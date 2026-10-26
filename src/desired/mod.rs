//! What a push creates, as one list.
//!
//! Phase 2 of the managed-object ownership plan (`plans/Managed-Object-Ownership-Plan.md`, D6).
//! Prisma, Drizzle and Atlas each build the declared schema and the introspected database into the
//! same model and compare model to model. This is the declared side of that: every object a push
//! will create, keyed the way [`crate::introspector::fingerprint`] keys the live side, with the
//! structural parts a push can predict exactly and the SQL that creates and drops it.
//!
//! Nothing emits from this list yet. Phase 2 proves it against what the generator emits (every
//! name in a migration is in the set, every object in the set exists after a push with matching
//! structure), and emission switches to it kind by kind as each moves onto the reconcile.
//!
//! Two things are deliberately not here. `drop_sql` never says `CASCADE`: a user object that
//! depends on one of ours must block the drop and be named, not vanish. And expression parts
//! (defaults, check expressions, policy quals) are not in `structure`: Postgres rewrites them on
//! the way in, so the ledger compares them live against recorded-live, never against our text.

pub mod identity;
pub mod statements;

use std::collections::BTreeMap;

use anyhow::Result;

use crate::differ::{
    column_diff::{expected_udt, field_is_primary_key},
    constraint_diff::expected_column_uniques,
    rls_diff::{expected_policies, intersect_access},
    table_diff::versions_record_id,
    Operation, Risk,
};
use crate::generator::sql::{
    constraints::constraint_to_expr,
    migration::{
        field_check_expression, implicit_model_indexes, normalize_fk_action, render_operation,
    },
    rls::membership_index_targets,
    type_checks,
    versions::{versions_record_index_name, versions_record_index_sql},
};
use crate::introspector::fingerprint::ObjectKind;
use crate::managed::{
    comment_on_constraint, comment_on_index, comment_on_table, comment_value,
    expected_check_constraint_name, expected_model_constraint_name, expected_model_index_name,
    expected_unique_constraint_name, foreign_key_name, managed_comment, primary_key_name,
    truncate_identifier, type_check_name,
};
use crate::parser::accessors::{
    column_names_for, db_foreign_key, default_foreign_key_column, versions_of, versions_table_name,
};
use crate::parser::ast::{AccessAst, FieldAst, ModelAst, RelationCardinality, SchemaAst};
use crate::parser::resolver::resolve_system_ref;

/// A check constraint the schema declares on a model: a field's bounds or a model-level rule.
pub(crate) struct ExpectedCheck {
    pub(crate) constraint: String,
    pub(crate) expression: String,
}

/// Every bounds and model-level check `model` asks for, named as the generator names them.
pub(crate) fn expected_checks(model: &ModelAst) -> Vec<ExpectedCheck> {
    let table = model.table_name();
    let mut out = Vec::new();

    // Field bounds: declared inline on the column, one constraint per column.
    for (field_name, field) in &model.fields {
        for col in column_names_for(field_name, field) {
            if col.is_empty() {
                continue;
            }
            let Some(expression) = field_check_expression(field, &col) else {
                continue;
            };
            out.push(ExpectedCheck {
                constraint: expected_check_constraint_name(table, &col),
                expression,
            });
        }
    }

    // Model-level constraints: named by position, because the author writes an expression and
    // not an identifier. Reordering therefore renames, which the ledger sees as a drop and a
    // create rather than a change.
    for (index, rule) in model.annotations.db.constraints.iter().enumerate() {
        let Ok(expression) = constraint_to_expr(rule) else {
            // A rule that cannot be rendered fails the migration, loudly, in the generator.
            continue;
        };
        out.push(ExpectedCheck {
            constraint: expected_model_constraint_name(table, index),
            expression,
        });
    }
    out
}

pub use crate::introspector::fingerprint::ObjectKey;

impl ObjectKey {
    /// The one drop for this object, derived from the key alone, so the desired set and the
    /// reconcile (which may hold only a ledger row) render the same statement. Never `CASCADE`:
    /// a user object that depends on one of ours must block the drop and be named, not vanish.
    /// `None` for a kind nothing drops yet; each kind gains its drop as it moves onto the reconcile.
    pub fn drop_sql(&self) -> Option<String> {
        let ObjectKey {
            kind,
            schema,
            parent,
            name,
        } = self;
        Some(match kind {
            ObjectKind::Table => format!("DROP TABLE IF EXISTS \"{schema}\".\"{name}\";"),
            ObjectKind::Column => {
                format!("ALTER TABLE \"{schema}\".\"{parent}\" DROP COLUMN IF EXISTS \"{name}\";")
            }
            ObjectKind::PrimaryKey
            | ObjectKind::ForeignKey
            | ObjectKind::Unique
            | ObjectKind::Check => format!(
                "ALTER TABLE \"{schema}\".\"{parent}\" DROP CONSTRAINT IF EXISTS \"{name}\";"
            ),
            ObjectKind::Index => format!("DROP INDEX IF EXISTS \"{schema}\".\"{name}\";"),
            ObjectKind::Policy => {
                format!("DROP POLICY IF EXISTS \"{name}\" ON \"{schema}\".\"{parent}\";")
            }
            ObjectKind::Trigger => {
                format!("DROP TRIGGER IF EXISTS \"{name}\" ON \"{schema}\".\"{parent}\";")
            }
            ObjectKind::View => format!("DROP VIEW IF EXISTS \"{schema}\".\"{name}\";"),
            ObjectKind::Schema
            | ObjectKind::Function
            | ObjectKind::RlsAttributes
            | ObjectKind::EnumType
            | ObjectKind::Sequence
            | ObjectKind::TableGrant
            | ObjectKind::ColumnGrant
            | ObjectKind::SecurityLabel
            | ObjectKind::CronJob => return None,
        })
    }

    /// `COMMENT ON <this object> IS <text>`, `NULL` when `text` is `None`, for the kinds whose
    /// comment Postgres keeps. Used to take an older engine's stamp out of a comment while keeping
    /// whatever the user wrote beside it (plan section 6). The table, constraint and index forms
    /// are the ones `managed.rs` writes stamps with, so writer and remover cannot disagree.
    pub fn comment_sql(&self, text: Option<&str>) -> Option<String> {
        let ObjectKey {
            kind,
            schema,
            parent,
            name,
        } = self;
        let value = comment_value(text);
        Some(match kind {
            ObjectKind::Table => comment_on_table(schema, name, text),
            ObjectKind::Column => {
                format!("COMMENT ON COLUMN \"{schema}\".\"{parent}\".\"{name}\" IS {value};")
            }
            ObjectKind::PrimaryKey
            | ObjectKind::ForeignKey
            | ObjectKind::Unique
            | ObjectKind::Check => comment_on_constraint(schema, parent, name, text),
            ObjectKind::Index => comment_on_index(schema, name, text),
            ObjectKind::Policy => {
                format!("COMMENT ON POLICY \"{name}\" ON \"{schema}\".\"{parent}\" IS {value};")
            }
            ObjectKind::Trigger => {
                format!("COMMENT ON TRIGGER \"{name}\" ON \"{schema}\".\"{parent}\" IS {value};")
            }
            ObjectKind::View => format!("COMMENT ON VIEW \"{schema}\".\"{name}\" IS {value};"),
            ObjectKind::Schema
            | ObjectKind::Function
            | ObjectKind::RlsAttributes
            | ObjectKind::EnumType
            | ObjectKind::Sequence
            | ObjectKind::TableGrant
            | ObjectKind::ColumnGrant
            | ObjectKind::SecurityLabel
            | ObjectKind::CronJob => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DesiredObject {
    pub key: ObjectKey,
    /// The labelled parts a push can predict exactly, a subset of [`ObjectKind::labels`]. These are
    /// what desired-versus-live comparison and auto-adopt (D2) are allowed to read.
    pub structure: BTreeMap<&'static str, String>,
    pub create_sql: String,
    /// Never `CASCADE`.
    pub drop_sql: String,
    pub depends_on: Vec<ObjectKey>,
    /// Policies, grants, labels and RLS attributes: drift on these fails a non-interactive push.
    pub security_relevant: bool,
}

/// Every object a push of `ast` creates in `schema`, sorted by key.
pub fn desired_objects(ast: &SchemaAst, schema: &str) -> Result<Vec<DesiredObject>> {
    let mut b = Builder {
        ast,
        schema,
        out: Vec::new(),
    };
    for model in &ast.models {
        b.model_table(model)?;
        b.model_columns(model)?;
        b.model_primary_key(model);
        b.model_uniques(model)?;
        b.model_foreign_keys(model)?;
        b.model_checks(model);
        b.model_indexes(model)?;
        b.model_policies(model)?;
        if versions_of(model).is_some() {
            b.versions_table(model)?;
        }
    }
    for junction in &ast.junction_tables {
        b.junction(junction)?;
    }
    let mut out = b.out;
    out.sort_by(|a, c| a.key.cmp(&c.key));
    Ok(out)
}

struct Builder<'a> {
    ast: &'a SchemaAst,
    schema: &'a str,
    out: Vec<DesiredObject>,
}

fn flag(b: bool) -> String {
    if b { "t" } else { "f" }.to_string()
}

impl<'a> Builder<'a> {
    fn key(&self, kind: ObjectKind, parent: &str, name: &str) -> ObjectKey {
        ObjectKey {
            kind,
            schema: self.schema.to_string(),
            parent: parent.to_string(),
            name: name.to_string(),
        }
    }

    fn table_key(&self, table: &str) -> ObjectKey {
        self.key(ObjectKind::Table, "", table)
    }

    fn push(
        &mut self,
        key: ObjectKey,
        structure: BTreeMap<&'static str, String>,
        create_sql: String,
        depends_on: Vec<ObjectKey>,
    ) {
        let security_relevant = matches!(key.kind, ObjectKind::Policy);
        // Every kind the builder emits has a drop; `desired_objects_tests` checks it per fixture.
        let drop_sql = key
            .drop_sql()
            .unwrap_or_else(|| panic!("{:?} has no drop statement", key.kind));
        // One object, however many rules or models ask for it: several access rules can read the
        // same join column, and each asks for the same membership index.
        if self.out.iter().any(|o| o.key == key) {
            return;
        }
        self.out.push(DesiredObject {
            key,
            structure,
            create_sql,
            drop_sql,
            depends_on,
            security_relevant,
        });
    }

    fn render(&self, op: Operation) -> Result<String> {
        render_operation(&op, self.schema, self.ast)
    }

    fn alter(&self, table: &str) -> String {
        format!("ALTER TABLE \"{}\".\"{table}\"", self.schema)
    }

    // --- tables and columns -------------------------------------------------------------------

    fn model_table(&mut self, model: &ModelAst) -> Result<()> {
        let table = model.table_name();
        let create = self.render(Operation::CreateTable {
            table: table.to_string(),
            model: Box::new(model.clone()),
            risk: Risk::Safe,
        })?;
        self.push(self.table_key(table), BTreeMap::new(), create, Vec::new());
        Ok(())
    }

    fn model_columns(&mut self, model: &ModelAst) -> Result<()> {
        let table = model.table_name();
        for (field_name, field) in &model.fields {
            for column in column_names_for(field_name, field) {
                if column.is_empty() {
                    continue;
                }
                let mut structure = BTreeMap::new();
                if let Some(udt) = expected_udt(field) {
                    structure.insert("udt", udt);
                }
                let create = self.render(Operation::AddColumn {
                    table: table.to_string(),
                    column: column.clone(),
                    field: Box::new(field.clone()),
                    risk: Risk::Safe,
                })?;
                self.push(
                    self.key(ObjectKind::Column, table, &column),
                    structure,
                    create,
                    vec![self.table_key(table)],
                );
            }
        }
        Ok(())
    }

    // --- constraints --------------------------------------------------------------------------

    fn primary_key(&mut self, table: &str, columns: &[String]) {
        let name = primary_key_name(table);
        let cols = columns
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let create = format!(
            "{} ADD CONSTRAINT \"{name}\" PRIMARY KEY ({cols});",
            self.alter(table)
        );
        let mut structure = BTreeMap::new();
        structure.insert("columns", columns.join(","));
        self.push(
            self.key(ObjectKind::PrimaryKey, table, &name),
            structure,
            create,
            vec![self.table_key(table)],
        );
    }

    fn model_primary_key(&mut self, model: &ModelAst) {
        let columns: Vec<String> = model
            .fields
            .iter()
            .filter(|(_, field)| field_is_primary_key(field))
            .flat_map(|(name, field)| column_names_for(name, field))
            .collect();
        if !columns.is_empty() {
            self.primary_key(model.table_name(), &columns);
        }
    }

    fn unique(&mut self, table: &str, name: &str, columns: &[String], create: String) {
        let mut structure = BTreeMap::new();
        structure.insert("columns", columns.join(","));
        self.push(
            self.key(ObjectKind::Unique, table, name),
            structure,
            create,
            vec![self.table_key(table)],
        );
    }

    fn model_uniques(&mut self, model: &ModelAst) -> Result<()> {
        let table = model.table_name();
        for exp in expected_column_uniques(self.ast)
            .into_iter()
            .filter(|e| e.table == table)
        {
            let create = self.render(Operation::AddUniqueConstraint {
                table: table.to_string(),
                column: exp.column.clone(),
                constraint: exp.constraint_name.clone(),
                risk: Risk::Safe,
            })?;
            self.unique(
                table,
                &exp.constraint_name,
                std::slice::from_ref(&exp.column),
                create,
            );
        }
        // A belongsTo declared one-to-one is unique on its column, which the generator writes
        // inline and `expected_column_uniques` leaves out because it skips relation fields.
        for (field_name, field) in &model.fields {
            if let FieldAst::Relation(rel) = field {
                if matches!(rel.cardinality, RelationCardinality::BelongsTo) && rel.unique_fk {
                    let column = db_foreign_key(field, field_name)
                        .unwrap_or_else(|| default_foreign_key_column(field_name));
                    let name = expected_unique_constraint_name(table, &column);
                    let create = format!(
                        "{} ADD CONSTRAINT \"{name}\" UNIQUE (\"{column}\");",
                        self.alter(table)
                    );
                    self.unique(table, &name, &[column], create);
                }
            }
        }
        Ok(())
    }

    fn foreign_key(&mut self, table: &str, name: &str, fk: ForeignKeyRef<'_>, create: String) {
        let mut structure = BTreeMap::new();
        structure.insert("columns", fk.column.to_string());
        structure.insert("references", fk.ref_table.to_string());
        structure.insert("referenced_columns", fk.ref_column.to_string());
        structure.insert("on_delete", fk.on_delete.to_string());
        let mut depends_on = vec![self.table_key(table)];
        if fk.ref_schema == self.schema {
            depends_on.push(self.table_key(fk.ref_table));
        }
        self.push(
            self.key(ObjectKind::ForeignKey, table, name),
            structure,
            create,
            depends_on,
        );
    }

    fn model_foreign_keys(&mut self, model: &ModelAst) -> Result<()> {
        let table = model.table_name();
        for (field_name, field) in &model.fields {
            let FieldAst::Relation(rel) = field else {
                continue;
            };
            if !matches!(rel.cardinality, RelationCardinality::BelongsTo) {
                continue;
            }
            let column = db_foreign_key(field, field_name)
                .unwrap_or_else(|| default_foreign_key_column(field_name));
            let (ref_table, ref_schema) = match resolve_system_ref(&rel.target) {
                Some((sys_schema, sys_table)) => {
                    (sys_table.to_string(), Some(sys_schema.to_string()))
                }
                None => (
                    self.ast
                        .models
                        .iter()
                        .find(|m| m.name == rel.target)
                        .map(|m| m.table_name().to_string())
                        .unwrap_or_else(|| crate::parser::resolver::to_snake_case(&rel.target)),
                    None,
                ),
            };
            let name = foreign_key_name(table, &column);
            let ref_column = rel.references.clone().unwrap_or_else(|| "id".to_string());
            let on_delete = normalize_fk_action(rel.on_delete.as_deref().unwrap_or("restrict"));
            let create = self.render(Operation::AddForeignKey {
                table: table.to_string(),
                field_name: field_name.clone(),
                relation: Box::new(rel.clone()),
                ref_table: ref_table.clone(),
                ref_schema: ref_schema.clone(),
                risk: Risk::Safe,
            })?;
            let schema_of_ref = ref_schema.as_deref().unwrap_or(self.schema).to_string();
            self.foreign_key(
                table,
                &name,
                ForeignKeyRef {
                    column: &column,
                    ref_schema: &schema_of_ref,
                    ref_table: &ref_table,
                    ref_column: &ref_column,
                    on_delete,
                },
                create,
            );
        }
        Ok(())
    }

    fn check(&mut self, table: &str, name: &str, create: String) {
        self.push(
            self.key(ObjectKind::Check, table, name),
            BTreeMap::new(),
            create,
            vec![self.table_key(table)],
        );
    }

    fn type_check(&mut self, table: &str, column: &str, expression: &str) {
        let name = type_check_name(table, column);
        let create = format!(
            "{} ADD CONSTRAINT \"{name}\" CHECK ({expression});",
            self.alter(table)
        );
        self.check(table, &name, create);
    }

    fn model_checks(&mut self, model: &ModelAst) {
        let table = model.table_name();
        for exp in expected_checks(model) {
            let create = format!(
                "{} ADD CONSTRAINT \"{}\" CHECK ({});",
                self.alter(table),
                exp.constraint,
                exp.expression
            );
            self.check(table, &exp.constraint, create);
        }
        // The checks a field type carries, which the generator writes inline on the column. These
        // follow the generator exactly, including a localized Email, where the regex is written
        // against a JSONB column and the migration fails: the set describes what a push emits.
        for (field_name, field) in &model.fields {
            for column in column_names_for(field_name, field) {
                match field {
                    FieldAst::Email(_) => {
                        self.type_check(table, &column, &type_checks::email_check_expr(&column))
                    }
                    FieldAst::Url(_) => {
                        self.type_check(table, &column, &type_checks::url_check_expr(&column))
                    }
                    FieldAst::Enum(f) => self.type_check(
                        table,
                        &column,
                        &type_checks::enum_check_expr(&column, &f.values),
                    ),
                    FieldAst::Publishable if column == "status" => self.type_check(
                        table,
                        &column,
                        type_checks::publishable_status_check_expr(),
                    ),
                    _ => {}
                }
            }
        }
    }

    // --- indexes ------------------------------------------------------------------------------

    fn index(
        &mut self,
        table: &str,
        name: &str,
        columns: &[String],
        method: &str,
        unique: bool,
        create: String,
    ) {
        let mut structure = BTreeMap::new();
        structure.insert("columns", columns.join(","));
        structure.insert("method", method.to_string());
        structure.insert("unique", flag(unique));
        structure.insert("primary", flag(false));
        self.push(
            self.key(ObjectKind::Index, table, name),
            structure,
            create,
            vec![self.table_key(table)],
        );
    }

    fn model_indexes(&mut self, model: &ModelAst) -> Result<()> {
        let table = model.table_name();
        for index in model
            .indexes()
            .iter()
            .cloned()
            .chain(implicit_model_indexes(model))
        {
            let name = index
                .name
                .clone()
                .unwrap_or_else(|| expected_model_index_name(table, &index.fields));
            let create = self.render(Operation::AddIndex {
                table: table.to_string(),
                index: Box::new(index.clone()),
                risk: Risk::Safe,
            })?;
            self.index(
                table,
                &name,
                &index.fields,
                index.using.as_sql(),
                index.unique,
                create,
            );
        }
        if model.options.singleton {
            let name = truncate_identifier(table, "_singleton_idx");
            let comment = managed_comment("unique_index", table, &[]);
            let create = format!(
                "CREATE UNIQUE INDEX IF NOT EXISTS \"{name}\" ON \"{}\".\"{table}\" ((TRUE));\n{}",
                self.schema,
                crate::managed::comment_on_index_sql(&name, &comment, self.schema)
            );
            // No column key: its structure is the expression, which is not predictable text.
            let mut structure = BTreeMap::new();
            structure.insert("method", "btree".to_string());
            structure.insert("unique", flag(true));
            structure.insert("primary", flag(false));
            self.push(
                self.key(ObjectKind::Index, table, &name),
                structure,
                create,
                vec![self.table_key(table)],
            );
        }
        Ok(())
    }

    // --- policies -----------------------------------------------------------------------------

    /// The policies `access` asks for on `table`, and the membership index each rule's join
    /// columns get beside them (`rls.rs` emits `idx_{table}_{column}_rls` with every policy whose
    /// rule reads another table; the name is built there without truncation, so it is here too).
    fn policies_for(&mut self, table: &str, access: &AccessAst) -> Result<()> {
        let mut policies: Vec<(String, &'static str)> = Vec::new();
        for (suffix, rule) in expected_policies(access) {
            if let Some(rule) = rule {
                for (target_table, column) in membership_index_targets(rule) {
                    let name = format!("idx_{target_table}_{column}_rls");
                    let create = format!(
                        "CREATE INDEX IF NOT EXISTS \"{name}\" ON \"{}\".\"{}\" (\"{}\");",
                        self.schema,
                        target_table.replace('"', "\"\""),
                        column.replace('"', "\"\"")
                    );
                    self.index(&target_table, &name, &[column], "btree", false, create);
                }
            }
            policies.push((suffix.clone(), polcmd(&suffix)));
        }
        for (suffix, command) in policies {
            let name = format!("{table}_{suffix}");
            let create = self.render(Operation::CreateRlsPolicy {
                table: table.to_string(),
                policy: name.clone(),
                risk: Risk::Safe,
            })?;
            let mut structure = BTreeMap::new();
            structure.insert("command", command.to_string());
            structure.insert("permissive", flag(true));
            structure.insert("roles", "public".to_string());
            self.push(
                self.key(ObjectKind::Policy, table, &name),
                structure,
                create,
                vec![self.table_key(table)],
            );
        }
        Ok(())
    }

    fn model_policies(&mut self, model: &ModelAst) -> Result<()> {
        self.policies_for(model.table_name(), model.access())
    }

    // --- versions tables ----------------------------------------------------------------------

    fn versions_table(&mut self, model: &ModelAst) -> Result<()> {
        let table = model.table_name();
        let vt = versions_table_name(table);
        let (primary_key, record_id_type) = versions_record_id(model);
        let create = self.render(Operation::CreateVersionsTable {
            table: table.to_string(),
            versions_table: vt.clone(),
            record_id_type,
            primary_key: primary_key.clone(),
            risk: Risk::Safe,
        })?;
        self.push(
            self.table_key(&vt),
            BTreeMap::new(),
            create,
            vec![self.table_key(table)],
        );

        self.primary_key(&vt, &["id".to_string()]);

        let fk = foreign_key_name(&vt, "record_id");
        let fk_create = format!(
            "{} ADD CONSTRAINT \"{fk}\" FOREIGN KEY (\"record_id\") REFERENCES \"{}\".\"{table}\" (\"{primary_key}\") ON DELETE CASCADE;",
            self.alter(&vt),
            self.schema
        );
        self.foreign_key(
            &vt,
            &fk,
            ForeignKeyRef {
                column: "record_id",
                ref_schema: self.schema,
                ref_table: table,
                ref_column: &primary_key,
                on_delete: "CASCADE",
            },
            fk_create,
        );

        self.type_check(&vt, "status", type_checks::versions_status_check_expr());

        let key = truncate_identifier(&format!("{vt}_record_id_version"), "_key");
        let key_create = format!(
            "{} ADD CONSTRAINT \"{key}\" UNIQUE (\"record_id\", \"version\");",
            self.alter(&vt)
        );
        self.unique(
            &vt,
            &key,
            &["record_id".to_string(), "version".to_string()],
            key_create,
        );

        let idx = versions_record_index_name(&vt);
        let idx_create = versions_record_index_sql(self.schema, &vt);
        self.index(
            &vt,
            &idx,
            &["record_id".to_string(), "version".to_string()],
            "btree",
            false,
            idx_create,
        );
        Ok(())
    }

    // --- junction tables ----------------------------------------------------------------------

    fn junction(&mut self, jt: &crate::parser::ast::JunctionTableAst) -> Result<()> {
        let table = jt.name.as_str();
        let create = self.render(Operation::CreateJunctionTable {
            table: table.to_string(),
            fk_a: jt.fk_a.clone(),
            table_a: jt.model_a.clone(),
            fk_b: jt.fk_b.clone(),
            table_b: jt.model_b.clone(),
            risk: Risk::Safe,
        })?;
        self.push(self.table_key(table), BTreeMap::new(), create, Vec::new());

        self.primary_key(table, &[jt.fk_a.clone(), jt.fk_b.clone()]);

        for (fk_col, model_name) in [(&jt.fk_a, &jt.model_a), (&jt.fk_b, &jt.model_b)] {
            let Some(parent) = self.ast.models.iter().find(|m| &m.name == model_name) else {
                continue;
            };
            let (pk, _) = versions_record_id(parent);
            let ref_table = parent.table_name().to_string();
            let name = foreign_key_name(table, fk_col);
            let create = format!(
                "{} ADD CONSTRAINT \"{name}\" FOREIGN KEY (\"{fk_col}\") REFERENCES \"{}\".\"{ref_table}\" (\"{pk}\") ON DELETE CASCADE;",
                self.alter(table),
                self.schema
            );
            self.foreign_key(
                table,
                &name,
                ForeignKeyRef {
                    column: fk_col,
                    ref_schema: self.schema,
                    ref_table: &ref_table,
                    ref_column: &pk,
                    on_delete: "CASCADE",
                },
                create,
            );
        }

        let (Some(a), Some(b)) = (
            self.ast.models.iter().find(|m| m.name == jt.model_a),
            self.ast.models.iter().find(|m| m.name == jt.model_b),
        ) else {
            return Ok(());
        };
        let derived = intersect_access(a.access(), b.access());
        self.policies_for(table, &derived)
    }
}

/// Where a foreign key points, and what happens on delete.
struct ForeignKeyRef<'a> {
    column: &'a str,
    ref_schema: &'a str,
    ref_table: &'a str,
    ref_column: &'a str,
    on_delete: &'a str,
}

/// `pg_policy.polcmd` for a policy suffix, which is how the live side reports the command.
fn polcmd(suffix: &str) -> &'static str {
    match suffix {
        "select" => "r",
        "insert" => "a",
        "update" => "w",
        "delete" => "d",
        _ => "*",
    }
}
