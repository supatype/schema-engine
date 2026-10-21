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

pub mod attributed;
pub mod identity;
pub mod statements;

use std::collections::BTreeMap;

use anyhow::Result;

use crate::differ::{
    column_diff::expected_udt, constraint_diff::expected_column_uniques,
    rls_diff::expected_policies, table_diff::versions_record_id, Operation, Risk,
};
use crate::generator::sql::triggers::{self, PLATFORM_SCHEMA};
use crate::generator::sql::{
    constraint_helpers,
    constraints::constraint_to_expr,
    field_views::{render_field_views, FieldViewTable},
    grants::{revoke_all_sql, table_grants},
    junction_access::{junction_access, policy_suffixes, JunctionAccess},
    migration::{
        field_check_expression, implicit_model_indexes, normalize_fk_action, option_columns,
        render_operation_named,
    },
    rls::{
        self, drop_field_label_sql, drop_table_label_sql, field_labels,
        membership_index_create_sql, membership_index_targets, MASK_PROVIDER,
    },
    type_checks,
    versions::{versions_record_index_name, versions_record_index_sql, versions_record_key_name},
};
use crate::introspector::constraints::ForeignKeyOptions;
use crate::introspector::fingerprint::{
    definition_value, normalise_sql, replica_identity_sql, rls_enable_sql, ObjectKind,
    REPLICA_IDENTITY, REPLICA_IDENTITY_FULL,
};
use crate::managed::{
    comment_on_constraint, comment_on_index, comment_on_table, comment_value,
    membership_index_name, policy_name, ObjectNames,
};
use crate::parser::accessors::{
    column_names_for, db_foreign_key, default_foreign_key_column, primary_key_columns, versions_of,
    versions_table_name,
};
use crate::parser::ast::{AccessAst, FieldAst, IndexAst, ModelAst, RelationCardinality, SchemaAst};
use crate::parser::resolver::resolve_system_ref;
use crate::sql_quote::{quote_ident, quote_literal, quote_qualified};

/// A check constraint the schema declares on a model: a field's bounds or a model-level rule.
pub(crate) struct ExpectedCheck {
    pub(crate) constraint: String,
    pub(crate) expression: String,
}

/// Every bounds and model-level check `model` asks for, named as the generator names them.
pub(crate) fn expected_checks(model: &ModelAst, names: &ObjectNames) -> Vec<ExpectedCheck> {
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
                constraint: names.bounds(table, &col),
                expression,
            });
        }
    }

    // Model-level constraints: named for what they check (CK1), never by position, so
    // reordering renames nothing.
    for (index, rule) in model.annotations.db.constraints.iter().enumerate() {
        let Ok(expression) = constraint_to_expr(rule) else {
            // A rule that cannot be rendered fails the migration, loudly, in the generator.
            continue;
        };
        out.push(ExpectedCheck {
            constraint: names.model_constraint(table, index, rule),
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
        let on_parent = quote_qualified(schema, parent);
        Some(match kind {
            ObjectKind::Table => format!("DROP TABLE IF EXISTS {};", quote_qualified(schema, name)),
            ObjectKind::Column => format!(
                "ALTER TABLE {on_parent} DROP COLUMN IF EXISTS {};",
                quote_ident(name)
            ),
            ObjectKind::PrimaryKey
            | ObjectKind::ForeignKey
            | ObjectKind::Unique
            | ObjectKind::Check => format!(
                "ALTER TABLE {on_parent} DROP CONSTRAINT IF EXISTS {};",
                quote_ident(name)
            ),
            ObjectKind::Index => format!("DROP INDEX IF EXISTS {};", quote_qualified(schema, name)),
            ObjectKind::Policy => format!(
                "DROP POLICY IF EXISTS {} ON {on_parent};",
                quote_ident(name)
            ),
            ObjectKind::Trigger => format!(
                "DROP TRIGGER IF EXISTS {} ON {on_parent};",
                quote_ident(name)
            ),
            ObjectKind::View => format!("DROP VIEW IF EXISTS {};", quote_qualified(schema, name)),
            // The name is `ident(types)`, the identity the ledger keys a function by.
            ObjectKind::Function => {
                let (ident, args) = name.split_once('(').unwrap_or((name, ")"));
                format!(
                    "DROP FUNCTION IF EXISTS {}({args};",
                    quote_qualified(schema, ident)
                )
            }
            // Guarded as the schedule is: a database without `pg_cron` has no job to unschedule.
            // Only this database's job, found as introspection finds them
            // ([`crate::generator::sql::versions::cron_job_database`]): `cron.job` is the cluster's.
            ObjectKind::CronJob => format!(
                "DO $cron$\nBEGIN\n  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN\n    PERFORM cron.unschedule(jobid) FROM cron.job WHERE jobname = {} AND database = {};\n  END IF;\nEND;\n$cron$;",
                quote_literal(name),
                crate::generator::sql::versions::cron_job_database()
            ),
            // The parent is `table.column`, or the table for a label on the table itself; only our
            // own provider's labels are ever desired or dropped.
            ObjectKind::SecurityLabel => match parent.split_once('.') {
                Some((table, column)) => drop_field_label_sql(schema, table, column),
                None => drop_table_label_sql(schema, parent),
            },
            // The parent is the table and the name the role: everything it holds there goes.
            ObjectKind::TableGrant => revoke_all_sql(schema, parent, name),
            ObjectKind::Schema
            | ObjectKind::RlsAttributes
            | ObjectKind::ReplicaIdentity
            | ObjectKind::EnumType
            | ObjectKind::Sequence => return None,
        })
    }

    /// The statement that renames this object to `to`, on the table its key names, for the kinds
    /// a push renames rather than drops and makes again (F2, F8): a constraint, an index and a
    /// trigger. A primary key's or unique constraint's index is renamed with it. `None` for any
    /// other kind.
    pub fn rename_sql(&self, to: &str) -> Option<String> {
        let ObjectKey {
            kind,
            schema,
            parent,
            name,
        } = self;
        let on_parent = quote_qualified(schema, parent);
        let (from, to) = (quote_ident(name), quote_ident(to));
        Some(match kind {
            ObjectKind::PrimaryKey
            | ObjectKind::ForeignKey
            | ObjectKind::Unique
            | ObjectKind::Check => {
                format!("ALTER TABLE {on_parent} RENAME CONSTRAINT {from} TO {to};")
            }
            ObjectKind::Index => format!(
                "ALTER INDEX {} RENAME TO {to};",
                quote_qualified(schema, name)
            ),
            ObjectKind::Trigger => format!("ALTER TRIGGER {from} ON {on_parent} RENAME TO {to};"),
            _ => return None,
        })
    }

    /// `COMMENT ON <this object> IS <text>`, `NULL` when `text` is `None`, for the kinds whose
    /// comment Postgres keeps. Used to take an older engine's stamp out of a comment while keeping
    /// whatever the user wrote beside it (plan section 6). The table, constraint and index forms
    /// are the ones an older engine wrote its stamps with.
    pub fn comment_sql(&self, text: Option<&str>) -> Option<String> {
        let ObjectKey {
            kind,
            schema,
            parent,
            name,
        } = self;
        let value = comment_value(text);
        let (on_parent, n) = (quote_qualified(schema, parent), quote_ident(name));
        Some(match kind {
            ObjectKind::Table => comment_on_table(schema, name, text),
            ObjectKind::Column => format!("COMMENT ON COLUMN {on_parent}.{n} IS {value};"),
            ObjectKind::PrimaryKey
            | ObjectKind::ForeignKey
            | ObjectKind::Unique
            | ObjectKind::Check => comment_on_constraint(schema, parent, name, text),
            ObjectKind::Index => comment_on_index(schema, name, text),
            ObjectKind::Policy => format!("COMMENT ON POLICY {n} ON {on_parent} IS {value};"),
            ObjectKind::Trigger => format!("COMMENT ON TRIGGER {n} ON {on_parent} IS {value};"),
            ObjectKind::View => format!(
                "COMMENT ON VIEW {} IS {value};",
                quote_qualified(schema, name)
            ),
            ObjectKind::Schema
            | ObjectKind::Function
            | ObjectKind::RlsAttributes
            | ObjectKind::ReplicaIdentity
            | ObjectKind::EnumType
            | ObjectKind::Sequence
            | ObjectKind::TableGrant
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

/// The statement a serial's sequence is recorded with: `ALTER SEQUENCE ... OWNED BY` its column.
pub fn sequence_owned_by_sql(schema: &str, name: &str, table: &str, column: &str) -> String {
    format!(
        "ALTER SEQUENCE {} OWNED BY {}.{};",
        quote_qualified(schema, name),
        quote_qualified(schema, table),
        quote_ident(column)
    )
}

/// The kinds the engine never removes (D9): row-level security on a table it owns is never turned
/// off automatically, because a table with RLS on and no policies denies everything and turning it
/// off is a decision no reconcile should make; and a schema or sequence (plan section 15: created if
/// missing, never dropped), since a schema may hold what is not ours and a sequence goes with its
/// column. A table's replica identity is not set back either: realtime may rely on it. A row nothing
/// desires any more is forgotten.
pub fn never_removed(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::RlsAttributes
            | ObjectKind::ReplicaIdentity
            | ObjectKind::Schema
            | ObjectKind::Sequence
    )
}

/// The objects whose drift fails a non-interactive push (plan 3.5): what decides who may read or
/// write what. Every policy, grant, security label and RLS attribute; every view, whose options
/// and owner decide whose rights it reads with, the engine's views being tier 2's whole API and the
/// drafts layer's (E19); and the functions access is decided by: the `can_*` predicates, which the
/// field masking labels, the tier 2 views and every caller asking "may I" run, and the claim
/// readers in the engine's helper schema that every generated rule reads the caller through
/// (F15 (f)), and the tier 2 set helpers (`rule_set_*`) a field rule reads another table
/// through. A hand edit to `can_read_note__secret` is as much a change to who may read a column
/// as an edit to its label. Any other function's callers are security relevant too when they
/// change (`ledger::reconcile`, F14), though its body is not. A table's replica identity is not:
/// it decides what the WAL carries, not who may read it.
pub fn security_relevant(key: &ObjectKey) -> bool {
    match key.kind {
        ObjectKind::Policy
        | ObjectKind::SecurityLabel
        | ObjectKind::TableGrant
        | ObjectKind::RlsAttributes
        | ObjectKind::View => true,
        ObjectKind::Function => {
            key.name.starts_with("can_")
                || (key.schema == crate::generator::sql::auth_functions::CLAIMS_SCHEMA
                    && key.name.starts_with("jwt_"))
                || (key.schema == crate::generator::sql::field_rules::RULE_SCHEMA
                    && key.name.starts_with("rule_set_"))
        }
        _ => false,
    }
}

/// How a database enforces the schema's field rules, which is the database's masking tier and not
/// the schema's: labels the masking extension reads, or `api` views for the tables in the plan a
/// push computed where the extension cannot load.
#[derive(Debug, Clone, Copy)]
pub enum FieldEnforcement<'a> {
    Labels,
    Views(&'a [FieldViewTable]),
}

/// Every object a push of `ast` creates in `schema` that the schema alone decides, sorted by key,
/// for a database that can load the masking extension. A push knows the database's actual tier:
/// [`desired_objects_for`].
pub fn desired_objects(ast: &SchemaAst, schema: &str) -> Result<Vec<DesiredObject>> {
    desired_objects_for(ast, schema, FieldEnforcement::Labels)
}

/// Every object a push of `ast` creates in `schema`, with the field rules enforced as `fields`
/// says, sorted by key.
pub fn desired_objects_for(
    ast: &SchemaAst,
    schema: &str,
    fields: FieldEnforcement<'_>,
) -> Result<Vec<DesiredObject>> {
    let mut b = Builder {
        ast,
        schema,
        names: ObjectNames::for_schema(ast),
        field_views: match fields {
            FieldEnforcement::Labels => &[],
            FieldEnforcement::Views(plan) => plan,
        },
        out: Vec::new(),
    };
    if matches!(fields, FieldEnforcement::Labels) {
        b.field_labels();
    }
    b.table_grants(matches!(fields, FieldEnforcement::Views(_)));
    b.engine_schemas(matches!(fields, FieldEnforcement::Views(_)));
    b.constraint_helpers();
    b.platform_functions();
    for model in &ast.models {
        b.model_table(model)?;
        b.model_columns(model)?;
        b.model_sequences(model);
        b.model_primary_key(model);
        b.model_uniques(model)?;
        b.model_foreign_keys(model)?;
        b.model_checks(model);
        b.model_indexes(model)?;
        b.model_policies(model)?;
        b.studio_policies(model.table_name());
        b.rls_enabled(model.table_name());
        b.replica_identity_full(model.table_name());
        b.model_triggers(model);
        if versions_of(model).is_some() {
            b.versions_table(model)?;
            b.studio_policies(&versions_table_name(model.table_name()));
        }
    }
    b.versions_layer()?;
    b.affordance_functions();
    b.api_views();
    b.bucket_policies()?;
    for junction in &ast.junction_tables {
        b.junction(junction)?;
        b.studio_policies(&junction.name);
        b.rls_enabled(&junction.name);
        b.replica_identity_full(&junction.name);
    }
    let mut out = b.out;
    out.sort_by(|a, c| a.key.cmp(&c.key));
    Ok(out)
}

struct Builder<'a> {
    ast: &'a SchemaAst,
    schema: &'a str,
    /// Every generated name, chosen once for the whole schema, as the generator chooses them.
    names: ObjectNames,
    field_views: &'a [FieldViewTable],
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
        let security_relevant = security_relevant(&key);
        // Every kind the builder emits has a drop, except what is never removed;
        // `desired_objects_tests` checks it per fixture.
        let drop_sql = key
            .drop_sql()
            .or_else(|| never_removed(key.kind).then(String::new))
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
        render_operation_named(&op, self.schema, self.ast, &self.names)
    }

    fn alter(&self, table: &str) -> String {
        format!("ALTER TABLE {}", quote_qualified(self.schema, table))
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
        // The columns the model's options add (`timestamps`, `softDelete`), which `CREATE TABLE`
        // writes beside the fields: without a row they could never be dropped when the option goes.
        for (column, definition) in option_columns(model) {
            let create = format!(
                "{} ADD COLUMN IF NOT EXISTS {} {definition};",
                self.alter(table),
                quote_ident(column)
            );
            let structure = BTreeMap::from([("udt", "timestamptz".to_string())]);
            self.push(
                self.key(ObjectKind::Column, table, column),
                structure,
                create,
                vec![self.table_key(table)],
            );
        }
        Ok(())
    }

    // --- constraints --------------------------------------------------------------------------

    fn primary_key(&mut self, table: &str, columns: &[String]) {
        let name = self.names.primary_key(table);
        let cols = columns
            .iter()
            .map(|c| quote_ident(c))
            .collect::<Vec<_>>()
            .join(", ");
        let create = format!(
            "{} ADD CONSTRAINT {} PRIMARY KEY ({cols});",
            self.alter(table),
            quote_ident(&name)
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
        let columns = primary_key_columns(model);
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
            let name = self.names.unique(table, &exp.column);
            let create = self.render(Operation::AddUniqueConstraint {
                table: table.to_string(),
                column: exp.column.clone(),
                constraint: name.clone(),
                risk: Risk::Safe,
            })?;
            self.unique(table, &name, std::slice::from_ref(&exp.column), create);
        }
        // A belongsTo declared one-to-one is unique on its column, which the generator writes
        // inline and `expected_column_uniques` leaves out because it skips relation fields.
        for (field_name, field) in &model.fields {
            if let FieldAst::Relation(rel) = field {
                if matches!(rel.cardinality, RelationCardinality::BelongsTo) && rel.unique_fk {
                    let column = db_foreign_key(field, field_name)
                        .unwrap_or_else(|| default_foreign_key_column(field_name));
                    let name = self.names.unique(table, &column);
                    let create = format!(
                        "{} ADD CONSTRAINT {} UNIQUE ({});",
                        self.alter(table),
                        quote_ident(&name),
                        quote_ident(&column)
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
        // Schema-qualified, as the live side reports it: a key to `auth.users` and one to a
        // `users` model are different keys.
        structure.insert("references", format!("{}.{}", fk.ref_schema, fk.ref_table));
        structure.insert("referenced_columns", fk.ref_column.to_string());
        structure.insert("on_delete", fk.on_delete.to_string());
        // The rest of what the key does, read off the statement that makes it.
        let options = foreign_key_options(&create);
        structure.insert("on_update", options.on_update);
        structure.insert("match_type", options.match_type);
        structure.insert("deferrable", flag(options.deferrable));
        structure.insert("initially_deferred", flag(options.initially_deferred));
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
            let name = self.names.foreign_key(table, &column);
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
        let name = self.names.type_check(table, column);
        let create = format!(
            "{} ADD CONSTRAINT {} CHECK ({expression});",
            self.alter(table),
            quote_ident(&name)
        );
        self.check(table, &name, create);
    }

    fn model_checks(&mut self, model: &ModelAst) {
        let table = model.table_name();
        for exp in expected_checks(model, &self.names) {
            let create = format!(
                "{} ADD CONSTRAINT {} CHECK ({});",
                self.alter(table),
                quote_ident(&exp.constraint),
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

    /// An index of plain column keys.
    fn index(
        &mut self,
        table: &str,
        name: &str,
        columns: &[String],
        method: &str,
        unique: bool,
        create: String,
    ) {
        let structure = index_structure(columns, method, unique, "");
        self.push(
            self.key(ObjectKind::Index, table, name),
            structure,
            create,
            vec![self.table_key(table)],
        );
    }

    /// An index of column keys some of which say more than their column (`version DESC`), as
    /// `options` in the form the live side reports (`DbIndex::options`).
    #[allow(clippy::too_many_arguments)]
    fn index_with_options(
        &mut self,
        table: &str,
        name: &str,
        columns: &[String],
        method: &str,
        unique: bool,
        options: &str,
        create: String,
    ) {
        let structure = index_structure(columns, method, unique, options);
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
            let name = self.names.index(table, &index);
            let create = self.render(Operation::AddIndex {
                table: table.to_string(),
                index: Box::new(index.clone()),
                risk: Risk::Safe,
            })?;
            self.index_with_options(
                table,
                &name,
                &index.fields,
                index.using.as_sql(),
                index.unique,
                &operator_class_options(&index),
                create,
            );
        }
        if model.options.singleton {
            let name = self.names.singleton_index(table);
            let create = format!(
                "CREATE UNIQUE INDEX IF NOT EXISTS {} ON {} ((TRUE));",
                quote_ident(&name),
                quote_qualified(self.schema, table)
            );
            // No column key, and one expression, which Postgres deparses as `true`.
            let mut structure = index_structure(&[], "btree", true, "");
            structure.insert("expressions", "true".to_string());
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
    /// rule reads another table, fitted to the identifier limit by the same rule as here).
    fn policies_for(&mut self, table: &str, access: &AccessAst) -> Result<()> {
        let mut suffixes = Vec::new();
        for (suffix, rule) in expected_policies(access) {
            if let Some(rule) = rule {
                for (target_table, column) in membership_index_targets(rule) {
                    let name = membership_index_name(&target_table, &column);
                    let create = membership_index_create_sql(self.schema, &target_table, &column);
                    self.index(&target_table, &name, &[column], "btree", false, create);
                }
            }
            suffixes.push(suffix);
        }
        self.policies_named(table, &suffixes)
    }

    /// `table`'s policies with these suffixes, each rendered by its `CreateRlsPolicy`.
    fn policies_named(&mut self, table: &str, suffixes: &[String]) -> Result<()> {
        for suffix in suffixes {
            let command = polcmd(suffix);
            let name = policy_name(table, suffix);
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

    /// Every object a rendered script creates, read off it statement by statement (`attributed`),
    /// for the scripts the push re-asserts whole: each object in them is the engine's.
    fn attributed_script(&mut self, sql: &str) {
        for object in attributed::objects(sql, self.schema) {
            if !self.out.iter().any(|o| o.key == object.key) {
                self.out.push(object);
            }
        }
    }

    /// The drafts, history and publishing layer (Phase 4.4): its functions, triggers, policies,
    /// views, tables and cron jobs.
    fn versions_layer(&mut self) -> Result<()> {
        let sql = crate::generator::sql::versions::render_versions_layer(self.ast, self.schema)?;
        self.attributed_script(&sql);
        Ok(())
    }

    /// The `can_*` affordance functions (Phase 4.4), one per model and verb, each taking its
    /// table's row type. Owned so a model's removal drops them before its table, which they depend
    /// on.
    fn affordance_functions(&mut self) {
        let sql = crate::generator::sql::rls::generate_can_functions(self.ast, self.schema);
        self.attributed_script(&sql);
    }

    /// The policies on `storage.objects` the buckets' rules and the models storing into them ask
    /// for (Phase 4.7b): ours by the ledger, created by the reconcile after the storage layer.
    /// Two buckets whose policies would share names are refused here, as the storage layer refuses
    /// them, so a plan that never renders that layer (`diff`, `doctor`) cannot keep one bucket's
    /// policies and silently lose the other's.
    fn bucket_policies(&mut self) -> Result<()> {
        crate::generator::sql::storage::refuse_colliding_policy_labels(self.ast)?;
        self.attributed_script(&crate::generator::sql::storage::bucket_policies_sql(
            self.ast,
        ));
        Ok(())
    }

    /// The `api` field views and their write triggers (Phase 4.6), for the tables the push's plan
    /// names: the tier a database without the masking extension gets. Owned so the last field
    /// rule's removal drops them. With them, each of their tables gets the policy admitting
    /// `service_role`, which the views' owner rights would otherwise shut out (F13).
    fn api_views(&mut self) {
        let sql = render_field_views(self.ast, self.field_views, self.schema);
        self.attributed_script(&sql);
        for entry in self.field_views {
            let create = rls::service_role_policy_sql(self.schema, &entry.table);
            self.engine_policy(&entry.table, rls::SERVICE_ROLE_POLICY, "*", create);
        }
    }

    /// The policies that admit a Studio user's request to every row of `table`
    /// (`rls::studio_policy_sql`), on each table the engine manages: models, their versions tables
    /// and junctions. Without them a Studio editor saving a draft was refused by the versions
    /// table's own rules, which are the app's rules, not Studio's.
    fn studio_policies(&mut self, table: &str) {
        for (suffix, command) in rls::STUDIO_POLICIES {
            let create = rls::studio_policy_sql(self.schema, table, suffix);
            self.engine_policy(table, suffix, command, create);
        }
    }

    /// One permissive policy on `table` that no access rule declares, named by `suffix`.
    fn engine_policy(&mut self, table: &str, suffix: &str, command: &str, create: String) {
        let name = policy_name(table, suffix);
        let structure = BTreeMap::from([
            ("command", command.to_string()),
            ("permissive", flag(true)),
            ("roles", "public".to_string()),
        ]);
        self.push(
            self.key(ObjectKind::Policy, table, &name),
            structure,
            create,
            vec![self.table_key(table)],
        );
    }

    /// Row-level security on for a model or junction table (Phase 4.8, D9): enablement only, never
    /// `FORCE`, and never turned off.
    fn rls_enabled(&mut self, table: &str) {
        let key = self.key(ObjectKind::RlsAttributes, table, "rls");
        let structure = BTreeMap::from([("enabled", flag(true))]);
        let create = rls_enable_sql(self.schema, table);
        self.push(key, structure, create, vec![self.table_key(table)]);
    }

    /// `REPLICA IDENTITY FULL` on a model or junction table (F68), so the WAL carries the whole
    /// old row of an `UPDATE` or `DELETE`: realtime delivers a `DELETE` only to a subscriber whose
    /// rules let them see that row, and without it delivers none. Never set back automatically.
    fn replica_identity_full(&mut self, table: &str) {
        let key = self.key(ObjectKind::ReplicaIdentity, table, REPLICA_IDENTITY);
        let structure = BTreeMap::from([("identity", REPLICA_IDENTITY_FULL.to_string())]);
        let create = replica_identity_sql(self.schema, table, REPLICA_IDENTITY_FULL)
            .expect("FULL has a statement");
        self.push(key, structure, create, vec![self.table_key(table)]);
    }

    /// The engine's own schemas a push creates (Phase 4.10): the platform and helper schemas and
    /// Studio's on every push, `draft` with any versioned model, and `api` under tier 2 masking.
    /// Ours by name and never dropped (plan section 15). `auth` and `storage` are shared, and the
    /// project schema is the user's.
    fn engine_schemas(&mut self, views: bool) {
        let mut schemas = vec![
            PLATFORM_SCHEMA,
            crate::generator::sql::versions::HELPER_SCHEMA,
            crate::generator::sql::versions::RPC_SCHEMA,
        ];
        if self.ast.models.iter().any(|m| versions_of(m).is_some()) {
            schemas.push(crate::generator::sql::versions::DRAFT_SCHEMA);
        }
        if views {
            schemas.push(crate::generator::sql::field_views::VIEW_SCHEMA);
        }
        for name in schemas {
            let key = ObjectKey {
                kind: ObjectKind::Schema,
                schema: name.to_string(),
                parent: String::new(),
                name: name.to_string(),
            };
            let create = format!("CREATE SCHEMA IF NOT EXISTS {};", quote_ident(name));
            self.push(key, BTreeMap::new(), create, Vec::new());
        }
    }

    /// The sequence a `SERIAL` or `BIGSERIAL` column owns (Phase 4.10), under the name Postgres
    /// gives it: `makeObjectName`'s, with a digit when another relation of the schema has it first.
    /// Made and kept by its column, so recorded only, and never dropped; a rename of its table or
    /// column renames it to match.
    fn model_sequences(&mut self, model: &ModelAst) {
        let table = model.table_name();
        for (field_name, field) in &model.fields {
            if !crate::parser::accessors::owns_sequence(field) {
                continue;
            }
            for column in column_names_for(field_name, field) {
                let name = self.names.sequence(table, &column);
                let structure = BTreeMap::from([("owned_by", format!("{table}.{column}"))]);
                let create = sequence_owned_by_sql(self.schema, &name, table, &column);
                let column_key = self.key(ObjectKind::Column, table, &column);
                let sequence_key = self.key(ObjectKind::Sequence, "", &name);
                self.push(sequence_key.clone(), structure, create, vec![column_key]);
                if matches!(field, FieldAst::Serial(_) | FieldAst::BigSerial(_)) {
                    self.sequence_grants(model, &name, sequence_key);
                }
            }
        }
    }

    /// What each API role may do with a serial column's sequence: `USAGE` where the model's create
    /// rule admits it (`grants::sequence_grant`), a ledger object like a table's grants, so a
    /// change by hand is drift that decides access.
    fn sequence_grants(&mut self, model: &ModelAst, sequence: &str, sequence_key: ObjectKey) {
        for role in crate::generator::sql::grants::GRANTED_ROLES {
            let grant = crate::generator::sql::grants::sequence_grant(model, sequence, role);
            let key = self.key(ObjectKind::TableGrant, sequence, role);
            let structure = BTreeMap::from([("privileges", grant.privilege_set())]);
            let create = grant.create_sql(self.schema);
            self.push(key, structure, create, vec![sequence_key.clone()]);
        }
    }

    /// What each API role may do on each model table (Phase 4.7c, D7): the exact privilege set,
    /// table and column privileges together. Under tier 2 masking (`views`) the base tables hold
    /// nothing for these roles; the `api` views' privileges are re-asserted with the views.
    fn table_grants(&mut self, views: bool) {
        for grant in table_grants(self.ast, views) {
            let key = self.key(ObjectKind::TableGrant, &grant.table, &grant.role);
            let structure = BTreeMap::from([("privileges", grant.privilege_set())]);
            let table = self.table_key(&grant.table);
            self.push(key, structure, grant.create_sql(self.schema), vec![table]);
        }
    }

    /// The security labels the masking extension reads (Phase 4.7), one per column with a field
    /// rule. Each depends on its column and on the predicates its text names.
    fn field_labels(&mut self) {
        for label in field_labels(self.ast, self.schema) {
            let key = self.key(
                ObjectKind::SecurityLabel,
                &format!("{}.{}", label.table, label.column),
                MASK_PROVIDER,
            );
            let structure = BTreeMap::from([("label", label.label.clone())]);
            let column = self.key(ObjectKind::Column, &label.table, &label.column);
            self.push(key, structure, label.create_sql(self.schema), vec![column]);
        }
    }

    /// The `_supatype` constraint helper functions (Phase 4.6), which the migration asserts before
    /// any table because a `CHECK` that calls one is validated at `CREATE TABLE`.
    fn constraint_helpers(&mut self) {
        self.attributed_script(&constraint_helpers::generate());
    }

    /// The `_platform` functions every push has (Phase 4.2).
    fn platform_functions(&mut self) {
        for function in triggers::shared_functions() {
            self.platform_function(&function);
        }
    }

    /// One `_platform` function, with the parts the catalog reports (`DbFunction`): the return
    /// type as `pg_get_function_result` spells it, the language, the volatility code, whether it
    /// is security definer, the body between the dollar quotes, whitespace-normalised as the
    /// fingerprint normalises it, and the options its statement declares.
    fn platform_function(&mut self, function: &triggers::TriggerFunction) {
        let mut structure = BTreeMap::new();
        structure.insert("returns", function.returns.to_string());
        structure.insert("language", "plpgsql".to_string());
        structure.insert("volatility", function.volatility.to_string());
        structure.insert("security_definer", flag(false));
        structure.insert("body", definition_value(&normalise_sql(&function.body)));
        // `SET`, `STRICT`, `PARALLEL`, cost and rows, as its statement declares them.
        structure.extend(attributed::function_options(&function.create_sql()));
        self.push(
            Self::platform_function_key(&function.key_name()),
            structure,
            function.create_sql(),
            Vec::new(),
        );
    }

    fn platform_function_key(key_name: &str) -> ObjectKey {
        ObjectKey {
            kind: ObjectKind::Function,
            schema: PLATFORM_SCHEMA.to_string(),
            parent: String::new(),
            name: key_name.to_string(),
        }
    }

    /// A model's triggers and the `_platform` functions of its own they run. The trigger's parts
    /// are the catalog's structural ones (`pg_trigger`), not its deparsed definition.
    fn model_triggers(&mut self, model: &ModelAst) {
        for function in triggers::model_functions(model, &self.names) {
            self.platform_function(&function);
        }
        for trigger in triggers::model_triggers(model, &self.names) {
            let mut structure = BTreeMap::new();
            structure.insert("timing", "BEFORE".to_string());
            structure.insert("events", trigger.events.join(","));
            structure.insert("columns", String::new());
            structure.insert("for_each_row", flag(true));
            structure.insert("function", trigger.qualified_function());
            structure.insert("enabled", flag(true));
            let depends_on = vec![
                self.table_key(&trigger.table),
                Self::platform_function_key(&format!("{}()", trigger.function)),
            ];
            self.push(
                self.key(ObjectKind::Trigger, &trigger.table, &trigger.name),
                structure,
                trigger.create_sql(self.schema),
                depends_on,
            );
        }
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

        let fk = self.names.foreign_key(&vt, "record_id");
        let fk_create = format!(
            "{} ADD CONSTRAINT {} FOREIGN KEY (\"record_id\") REFERENCES {} ({}) ON DELETE CASCADE;",
            self.alter(&vt),
            quote_ident(&fk),
            quote_qualified(self.schema, table),
            quote_ident(&primary_key)
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

        let key = versions_record_key_name(&vt);
        let key_create = format!(
            "{} ADD CONSTRAINT {} UNIQUE (\"record_id\", \"version\");",
            self.alter(&vt),
            quote_ident(&key)
        );
        self.unique(
            &vt,
            &key,
            &["record_id".to_string(), "version".to_string()],
            key_create,
        );

        let idx = versions_record_index_name(&vt);
        let idx_create = versions_record_index_sql(self.schema, &vt);
        self.index_with_options(
            &vt,
            &idx,
            &["record_id".to_string(), "version".to_string()],
            "btree",
            false,
            "2 DESC",
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
            let name = self.names.foreign_key(table, fk_col);
            let create = format!(
                "{} ADD CONSTRAINT {} FOREIGN KEY ({}) REFERENCES {} ({}) ON DELETE CASCADE;",
                self.alter(table),
                quote_ident(&name),
                quote_ident(fk_col),
                quote_qualified(self.schema, &ref_table),
                quote_ident(&pk)
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

        // An end missing from the schema leaves the intersection of nothing: no policies.
        match junction_access(self.ast, jt) {
            JunctionAccess::Intersected(derived) => self.policies_for(table, &derived),
            linked => self.policies_named(table, &policy_suffixes(&linked)),
        }
    }
}

/// What an index the engine creates is, in the labels the live fingerprint uses. Every part is
/// predicted, the empty ones included: a same-named index with a `WHERE`, an expression, an
/// `INCLUDE` or a `DESC` the engine never asked for is not the one it would create, and must not
/// be adopted as it (D2 compares only the labels the desired object has).
/// The `options` the catalog reports for `index`'s keys (`DbIndex::options`): for each key, the
/// operator class its method names, schema-qualified as the catalog qualifies a non-default class.
/// The class is pgvector's, so it is predicted where a push installs pgvector; empty for an index
/// whose method uses its keys' default classes.
fn operator_class_options(index: &IndexAst) -> String {
    let Some(class) = index.operator_class() else {
        return String::new();
    };
    let schema = crate::generator::sql::extensions::EXTENSIONS_SCHEMA;
    (1..=index.fields.len())
        .map(|key| format!("{key} {schema}.{class}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn index_structure(
    columns: &[String],
    method: &str,
    unique: bool,
    options: &str,
) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("columns", columns.join(",")),
        ("expressions", String::new()),
        ("predicate", String::new()),
        ("method", method.to_string()),
        ("unique", flag(unique)),
        ("primary", flag(false)),
        ("include", String::new()),
        ("options", options.to_string()),
    ])
}

/// Where a foreign key points, and what happens on delete.
struct ForeignKeyRef<'a> {
    column: &'a str,
    ref_schema: &'a str,
    ref_table: &'a str,
    ref_column: &'a str,
    on_delete: &'a str,
}

/// The `ON UPDATE`, `MATCH` and deferral a foreign key's `ADD CONSTRAINT` declares, spelled as the
/// catalog read spells them, each at its default when the statement leaves it out. Quoted names
/// are taken out first, so a table or column called `on update` reads as nothing.
fn foreign_key_options(create: &str) -> ForeignKeyOptions {
    let mut bare = String::new();
    for (i, part) in create.split('"').enumerate() {
        if i % 2 == 0 {
            bare.push_str(part);
        }
    }
    let sql = bare.to_ascii_uppercase();
    let sql = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    let tail = sql
        .rsplit_once("REFERENCES")
        .map(|(_, tail)| tail)
        .unwrap_or_default();
    let mut options = ForeignKeyOptions::default();
    if let Some((_, after)) = tail.split_once("ON UPDATE ") {
        if let Some(action) = [
            "NO ACTION",
            "RESTRICT",
            "CASCADE",
            "SET NULL",
            "SET DEFAULT",
        ]
        .into_iter()
        .find(|a| after.starts_with(a))
        {
            options.on_update = action.to_string();
        }
    }
    if tail.contains("MATCH FULL") {
        options.match_type = "FULL".into();
    } else if tail.contains("MATCH PARTIAL") {
        options.match_type = "PARTIAL".into();
    }
    options.deferrable = tail.contains("DEFERRABLE") && !tail.contains("NOT DEFERRABLE");
    options.initially_deferred = tail.contains("INITIALLY DEFERRED");
    options
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ast(json: &str) -> SchemaAst {
        crate::parser::parse(json).expect("fixture parses")
    }

    /// The desired side names the referenced table with its schema, as the live fingerprint does:
    /// a relation to `supatype:user` points at `auth.users`, and recorded as `users` alone it
    /// matched a live key to a `users` table in the project schema.
    #[test]
    fn a_foreign_key_references_its_table_with_its_schema() {
        let ast = ast(r#"{"astVersion":2,"models":[
              {"name":"Ticket","fields":{
                "id":{"kind":"uuid","required":true,"primaryKey":true,"annotations":{"db":{"pgType":"UUID","unique":true,"index":false}}},
                "owner":{"kind":"relation","cardinality":"belongsTo","target":"supatype:user","annotations":{"db":{"foreignKey":"owner_id"}}},
                "venue":{"kind":"relation","cardinality":"belongsTo","target":"Venue","annotations":{"db":{"foreignKey":"venue_id"}}}
              },"options":{},"annotations":{"db":{"tableName":"ticket","indexes":[]}}},
              {"name":"Venue","fields":{
                "id":{"kind":"uuid","required":true,"primaryKey":true,"annotations":{"db":{"pgType":"UUID","unique":true,"index":false}}}
              },"options":{},"annotations":{"db":{"tableName":"venue","indexes":[]}}}
            ]}"#);
        let set = desired_objects(&ast, "public").unwrap();
        let references = |name: &str| {
            set.iter()
                .find(|o| o.key.kind == ObjectKind::ForeignKey && o.key.name == name)
                .unwrap_or_else(|| panic!("{name} desired"))
                .structure["references"]
                .clone()
        };
        assert_eq!(references("ticket_owner_id_fkey"), "auth.users");
        assert_eq!(references("ticket_venue_id_fkey"), "public.venue");
    }

    /// A foreign key's `ON UPDATE`, `MATCH` and deferral are read off its statement, quoted names
    /// aside, each at its default when left out.
    #[test]
    fn a_foreign_keys_options_are_read_off_its_statement() {
        let base = r#"ALTER TABLE "public"."posts" ADD CONSTRAINT "posts_author_id_fkey" FOREIGN KEY ("author_id") REFERENCES "public"."on update cascade" ("id") ON DELETE RESTRICT"#;
        assert_eq!(
            foreign_key_options(&format!("{base};")),
            ForeignKeyOptions::default()
        );
        let all = foreign_key_options(&format!(
            "{base} ON UPDATE SET NULL MATCH FULL DEFERRABLE INITIALLY DEFERRED;"
        ));
        assert_eq!(
            all,
            ForeignKeyOptions {
                on_update: "SET NULL".into(),
                match_type: "FULL".into(),
                deferrable: true,
                initially_deferred: true,
            }
        );
        assert!(!foreign_key_options(&format!("{base} NOT DEFERRABLE;")).deferrable);
    }

    /// Every desired foreign key predicts `ON UPDATE`, `MATCH` and deferral, so a user's key of the
    /// same name that differs only in one of them does not match ours and is not adopted.
    #[test]
    fn a_desired_foreign_key_predicts_on_update_and_deferral() {
        use crate::introspector::{
            catalog::CatalogState,
            constraints::{DbConstraint, DbConstraintType},
            fingerprint::fingerprints,
        };
        use crate::ledger::reconcile::parse_definition;
        use crate::state::database_state::DatabaseState;

        let ast = ast(r#"{"astVersion":2,"models":[
              {"name":"User","fields":{
                "id":{"kind":"integer","required":true,"primaryKey":true,"annotations":{"db":{"pgType":"INTEGER","unique":false}}}
              },"options":{},"annotations":{"db":{"tableName":"users","indexes":[]}}},
              {"name":"Post","fields":{
                "id":{"kind":"integer","required":true,"primaryKey":true,"annotations":{"db":{"pgType":"INTEGER","unique":false}}},
                "author":{"kind":"relation","cardinality":"belongsTo","target":"User","annotations":{"db":{"foreignKey":"author_id"}}}
              },"options":{},"annotations":{"db":{"tableName":"posts","indexes":[]}}}
            ]}"#);
        let set = desired_objects(&ast, "public").unwrap();
        let fk = set
            .iter()
            .find(|o| o.key.kind == ObjectKind::ForeignKey)
            .expect("a foreign key");
        assert_eq!(fk.structure["on_update"], "CASCADE", "{:?}", fk.create_sql);
        assert_eq!(fk.structure["match_type"], "SIMPLE");
        assert_eq!(fk.structure["deferrable"], "f");
        assert_eq!(fk.structure["initially_deferred"], "f");

        let live = |options: ForeignKeyOptions| {
            let db = DatabaseState {
                schema: "public".into(),
                constraints: vec![DbConstraint {
                    table: "posts".into(),
                    name: fk.key.name.clone(),
                    constraint_type: DbConstraintType::ForeignKey,
                    columns: vec!["author_id".into()],
                    foreign_table: Some("users".into()),
                    foreign_schema: Some("public".into()),
                    foreign_columns: Some(vec!["id".into()]),
                    check_expression: None,
                    on_delete: Some(fk.structure["on_delete"].clone()),
                    definition: None,
                    comment: None,
                    foreign_key_options: Some(options),
                }],
                ..Default::default()
            };
            fingerprints(&db, &CatalogState::default()).remove(0)
        };
        let matches = |options: ForeignKeyOptions| {
            let live = live(options);
            let parts = parse_definition(&live.definition);
            fk.structure
                .iter()
                .all(|(label, want)| parts.get(label) == Some(&want.as_str()))
        };
        let ours = ForeignKeyOptions {
            on_update: "CASCADE".into(),
            ..Default::default()
        };
        assert!(matches(ours.clone()));
        assert!(
            !matches(ForeignKeyOptions::default()),
            "ON UPDATE NO ACTION"
        );
        assert!(!matches(ForeignKeyOptions {
            deferrable: true,
            ..ours.clone()
        }));
        assert!(!matches(ForeignKeyOptions {
            match_type: "FULL".into(),
            ..ours
        }));
    }

    /// Every desired index predicts every part a same-named live index could differ in, the empty
    /// ones included, so adoption (which compares only the parts predicted) cannot take a partial
    /// or expression index of the user's for ours. The singleton's has an empty `columns` too.
    #[test]
    fn a_desired_index_predicts_empty_expressions_predicate_and_include() {
        use crate::introspector::{
            catalog::CatalogState, fingerprint::fingerprints, indexes::DbIndex,
        };
        use crate::ledger::reconcile::parse_definition;
        use crate::state::database_state::DatabaseState;

        let ast = ast(r#"{"astVersion":2,"models":[
              {"name":"Post","fields":{
                "id":{"kind":"integer","required":true,"primaryKey":true,"annotations":{"db":{"pgType":"INTEGER","unique":false}}},
                "slug":{"kind":"text","required":false,"annotations":{"db":{"pgType":"TEXT","unique":false}}}
              },"options":{"singleton":true},"annotations":{"db":{"tableName":"posts","indexes":[
                {"fields":["slug"],"unique":true,"using":"btree"}
              ]}}}
            ]}"#);
        let set = desired_objects(&ast, "public").unwrap();
        let index = |name: &str| {
            set.iter()
                .find(|o| o.key.kind == ObjectKind::Index && o.key.name == name)
                .unwrap_or_else(|| panic!("{name} desired"))
        };
        let slug = index("posts_slug_idx");
        for (label, want) in [
            ("columns", "slug"),
            ("expressions", ""),
            ("predicate", ""),
            ("include", ""),
            ("options", ""),
            ("unique", "t"),
        ] {
            assert_eq!(slug.structure[label], want, "{label}");
        }
        let singleton = index("posts_singleton_idx");
        assert_eq!(singleton.structure["columns"], "");
        assert_eq!(singleton.structure["expressions"], "true");
        assert_eq!(singleton.structure["predicate"], "");

        // The same index live matches part for part; a partial one of the same name does not.
        let live = |predicate: Option<&str>| {
            let db = DatabaseState {
                schema: "public".into(),
                indexes: vec![DbIndex {
                    table: "posts".into(),
                    name: "posts_slug_idx".into(),
                    columns: vec!["slug".into()],
                    unique: true,
                    method: "btree".into(),
                    predicate: predicate.map(str::to_string),
                    ..Default::default()
                }],
                ..Default::default()
            };
            fingerprints(&db, &CatalogState::default()).remove(0)
        };
        let matches = |live: &crate::introspector::fingerprint::ObjectFingerprint| {
            let parts = parse_definition(&live.definition);
            slug.structure
                .iter()
                .all(|(label, want)| parts.get(label) == Some(&want.as_str()))
        };
        assert!(matches(&live(None)));
        assert!(!matches(&live(Some("(slug <> ''::text)"))));
    }
}
