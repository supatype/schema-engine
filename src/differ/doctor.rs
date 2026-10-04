//! `supatype doctor`: what a push would find, without applying anything.
//!
//! What the schema expects comes from the desired set (`crate::desired`), the same list a push
//! creates from, so every table (models, junctions, versions tables), unique constraint and index
//! the generator writes is known here too. Doctor used to derive its own expectations from the AST
//! and knew only the model tables and the declared indexes, so a push left generated objects
//! behind (membership indexes, versions tables) that doctor then reported as stale.
//!
//! A kind that has moved onto the ledger (checks, Phase 3d) is classified from the ledger rows;
//! the rest still from comment stamps, until each moves.

use anyhow::Result;

use crate::desired::{desired_objects, ObjectKey};
use crate::introspector::catalog::CatalogState;
use crate::introspector::constraints::{DbConstraint, DbConstraintType};
use crate::introspector::fingerprint::ObjectKind;
use crate::introspector::indexes::DbIndex;
use crate::ledger::LedgerRow;
use crate::managed::{is_managed_comment, managed_comment};
use crate::parser::ast::SchemaAst;
use crate::state::database_state::DatabaseState;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorReport {
    pub missing: Vec<DoctorItem>,
    pub stale_managed: Vec<DoctorItem>,
    pub unmanaged_drift: Vec<DoctorItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorItem {
    pub kind: String,
    pub table: String,
    pub name: String,
    pub fields: Vec<String>,
    pub message: String,
}

/// The tables, unique constraints and indexes a push of `ast` creates, read off the desired set.
struct Expected {
    /// Every table a push owns: models, junction tables and versions tables.
    tables: HashSet<String>,
    uniques: Vec<ExpectedConstraint>,
    indexes: Vec<ExpectedIndex>,
}

struct ExpectedConstraint {
    table: String,
    name: String,
    columns: Vec<String>,
}

struct ExpectedIndex {
    table: String,
    name: String,
    fields: Vec<String>,
    unique: bool,
}

fn expected(ast: &SchemaAst, schema: &str) -> Result<Expected> {
    let mut out = Expected {
        tables: HashSet::new(),
        uniques: Vec::new(),
        indexes: Vec::new(),
    };
    for object in desired_objects(ast, schema)? {
        let ObjectKey {
            kind, parent, name, ..
        } = object.key;
        let columns = |label: &str| -> Vec<String> {
            object
                .structure
                .get(label)
                .map(|c| c.split(',').map(str::to_string).collect())
                .unwrap_or_default()
        };
        match kind {
            ObjectKind::Table => {
                out.tables.insert(name);
            }
            ObjectKind::Unique => out.uniques.push(ExpectedConstraint {
                table: parent,
                name,
                columns: columns("columns"),
            }),
            ObjectKind::Index => out.indexes.push(ExpectedIndex {
                table: parent,
                name,
                fields: columns("columns"),
                unique: object.structure.get("unique").map(String::as_str) == Some("t"),
            }),
            _ => {}
        }
    }
    Ok(out)
}

/// `ledger` is what the push ledger owns (`_supatype.managed_objects`); a kind that has moved onto
/// it is classified from these rows rather than from comment stamps. Empty for a database no push
/// has bootstrapped.
pub fn report(
    ast: &SchemaAst,
    db: &DatabaseState,
    catalog: &CatalogState,
    ledger: &[LedgerRow],
) -> Result<DoctorReport> {
    let expected = expected(ast, &db.schema)?;
    let schema_tables = &expected.tables;
    // Columnar indexes from the differ's state, expression-only ones (a singleton's `((TRUE))`)
    // from the catalog: one list, as the fingerprints read them.
    let indexes: Vec<&DbIndex> = db
        .indexes
        .iter()
        .chain(&catalog.expression_indexes)
        .collect();
    // Every key the ledger owns, whatever the kind, so a kind that moves onto the ledger changes
    // nothing here: a filter asks `owned(kind, table, name)`.
    let owned: HashSet<(ObjectKind, &str, &str)> = ledger
        .iter()
        .map(|r| (r.key.kind, r.key.parent.as_str(), r.key.name.as_str()))
        .collect();

    let expected_unique_keys: HashSet<(&str, &str)> = expected
        .uniques
        .iter()
        .map(|e| (e.table.as_str(), e.name.as_str()))
        .collect();
    let expected_index_keys: HashSet<(&str, &str)> = expected
        .indexes
        .iter()
        .map(|e| (e.table.as_str(), e.name.as_str()))
        .collect();

    let mut missing = Vec::new();
    let mut stale_managed = Vec::new();
    let mut unmanaged_drift = Vec::new();

    for exp in &expected.uniques {
        let exists = db.constraints.iter().any(|c| {
            c.constraint_type == DbConstraintType::Unique
                && c.table == exp.table
                && c.columns == exp.columns
        });
        if !exists {
            missing.push(DoctorItem {
                kind: "unique_constraint".into(),
                table: exp.table.clone(),
                name: exp.name.clone(),
                fields: exp.columns.clone(),
                message: format!(
                    "AST expects unique on {}.{}: run `supatype push`",
                    exp.table,
                    exp.columns.join(", ")
                ),
            });
        }
    }

    for exp in &expected.indexes {
        let exists = indexes
            .iter()
            .any(|i| i.table == exp.table && i.name == exp.name);
        if !exists {
            missing.push(DoctorItem {
                kind: index_kind(exp.unique),
                table: exp.table.clone(),
                name: exp.name.clone(),
                fields: exp.fields.clone(),
                message: format!(
                    "AST expects index {} on {}: run `supatype push`",
                    exp.name, exp.table
                ),
            });
        }
    }

    for constraint in db.constraints.iter().filter(|c| {
        c.constraint_type == DbConstraintType::Unique && schema_tables.contains(&c.table)
    }) {
        if expected_unique_keys.contains(&(constraint.table.as_str(), constraint.name.as_str()))
            || expected
                .uniques
                .iter()
                .any(|e| e.table == constraint.table && e.columns == constraint.columns)
        {
            continue;
        }
        let item = doctor_constraint_item(constraint);
        if is_managed_comment(constraint.comment.as_deref()) {
            stale_managed.push(item);
        } else {
            unmanaged_drift.push(item);
        }
    }

    // Check constraints Supatype did not write, on tables it manages: no ledger row, and no stamp
    // from an engine older than the ledger.
    //
    // Doctor does not decide whether someone else's `CHECK` means what ours would: comparing
    // expressions needs the database (`ledger::probe`), and that is the push's job, which adopts
    // an equivalent one under our name and refuses a different one. Here the honest position is to
    // say the constraint is theirs. Push adds its own alongside, which is a duplicate rule rather
    // than a wrong one, and the operator is the one who can tell whether the two mean the same.
    let expected_checks = expected_check_constraint_count(ast);
    for constraint in db.constraints.iter().filter(|c| {
        c.constraint_type == DbConstraintType::Check
            && schema_tables.contains(&c.table)
            && !is_managed_comment(c.comment.as_deref())
            && !owned.contains(&(ObjectKind::Check, c.table.as_str(), c.name.as_str()))
    }) {
        // A column's own NOT NULL or an enum's value list are not rules anyone declared here.
        let expression = constraint.check_expression.as_deref().unwrap_or("");
        if expression.contains("IS NOT NULL") {
            continue;
        }
        let will_add = expected_checks
            .get(constraint.table.as_str())
            .copied()
            .unwrap_or(0);
        unmanaged_drift.push(DoctorItem {
            kind: "check_constraint".into(),
            table: constraint.table.clone(),
            name: constraint.name.clone(),
            fields: constraint.columns.clone(),
            message: if will_add > 0 {
                format!(
                    "Unmanaged check {} on {} was not created by Supatype and will not be adopted. \
                     Push adds {will_add} constraint(s) of its own to this table; if yours enforces \
                     the same rule, drop it to avoid enforcing it twice. Expression: {expression}",
                    constraint.name, constraint.table
                )
            } else {
                format!(
                    "Unmanaged check {} on {} was not created by Supatype and is left alone. \
                     Declare it in the schema if it should be managed. Expression: {expression}",
                    constraint.name, constraint.table
                )
            },
        });
    }

    for idx in indexes
        .iter()
        .filter(|i| !i.is_primary && schema_tables.contains(&i.table))
    {
        if expected_index_keys.contains(&(idx.table.as_str(), idx.name.as_str())) {
            continue;
        }
        // The index behind a unique constraint is the constraint's, reported above if at all.
        if idx.unique
            && db.constraints.iter().any(|c| {
                c.name == idx.name
                    && c.table == idx.table
                    && c.constraint_type == DbConstraintType::Unique
            })
        {
            continue;
        }
        let managed = is_managed_comment(idx.comment.as_deref());
        let item = DoctorItem {
            kind: index_kind(idx.unique),
            table: idx.table.clone(),
            name: idx.name.clone(),
            fields: idx.columns.clone(),
            message: if managed {
                format!(
                    "Managed index {} on {} is not in AST; review before push",
                    idx.name, idx.table
                )
            } else {
                format!(
                    "Unmanaged index {} on {}: push will not drop; manual decision required",
                    idx.name, idx.table
                )
            },
        };
        if managed {
            stale_managed.push(item);
        } else {
            unmanaged_drift.push(item);
        }
    }

    // Tables. The ownership gate declines to drop an unmarked table, and declines to drop a column
    // from one, so an operator seeing a clean report and a push that leaves a table behind would
    // conclude push is broken. Wording matches the constraint and index cases deliberately: the
    // mechanism is the same one.
    for table in &db.tables {
        let managed = is_managed_comment(table.comment.as_deref());
        let in_schema = schema_tables.contains(&table.name);

        // In the schema and unmarked: the table is diffed normally, but the gate declines to drop a
        // column the schema no longer declares. That is the difference `adopt` resolves.
        if in_schema && !managed {
            unmanaged_drift.push(DoctorItem {
                kind: "table".into(),
                table: table.name.clone(),
                name: table.name.clone(),
                fields: Vec::new(),
                message: format!(
                    "Table {} matches a model but is not managed: push will not drop its columns; \
                     run `supatype adopt` to bring it under management",
                    table.name
                ),
            });
            continue;
        }

        if in_schema {
            continue;
        }

        // Absent from the schema. Marked means push will drop it; unmarked means push will not.
        let item = DoctorItem {
            kind: "table".into(),
            table: table.name.clone(),
            name: table.name.clone(),
            fields: Vec::new(),
            message: if managed {
                format!(
                    "Managed table {} is not in AST; review before push",
                    table.name
                )
            } else {
                format!(
                    "Unmanaged table {}: push will not drop; manual decision required",
                    table.name
                )
            },
        };
        if managed {
            stale_managed.push(item);
        } else {
            unmanaged_drift.push(item);
        }
    }

    Ok(DoctorReport {
        missing,
        stale_managed,
        unmanaged_drift,
    })
}

fn index_kind(unique: bool) -> String {
    if unique { "unique_index" } else { "index" }.to_string()
}

pub fn has_strict_issues(report: &DoctorReport) -> bool {
    !report.missing.is_empty() || !report.stale_managed.is_empty()
}

/// How many `CHECK`s Supatype will create per table: column bounds plus model-level constraints.
///
/// A count rather than the expressions, because the message only needs to say "yours will sit
/// alongside ours". Whether two check expressions mean the same thing is a question for the
/// database (`ledger::probe`), which the push asks; doctor does not pretend to answer it.
fn expected_check_constraint_count(ast: &SchemaAst) -> HashMap<&str, usize> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for model in &ast.models {
        let total = crate::desired::expected_checks(model).len();
        if total > 0 {
            *counts.entry(model.table_name()).or_default() += total;
        }
    }
    counts
}

fn doctor_constraint_item(constraint: &DbConstraint) -> DoctorItem {
    DoctorItem {
        kind: "unique_constraint".into(),
        table: constraint.table.clone(),
        name: constraint.name.clone(),
        fields: constraint.columns.clone(),
        message: if is_managed_comment(constraint.comment.as_deref()) {
            format!(
                "Managed constraint {} on {} is not in AST; review before push",
                constraint.name, constraint.table
            )
        } else {
            format!(
                "Unmanaged constraint {} on {}: push will not drop; manual decision required",
                constraint.name, constraint.table
            )
        },
    }
}

/// SQL statements to stamp matching tables/constraints/indexes during adoption (comments only).
///
/// Tables are stamped **first**: the ownership gate is what makes an unmarked table safe from
/// `DropTable` and its columns safe from `DropColumn`, and until a table carries the marker, adopting
/// only its indexes leaves the confusing half-state where push manages the indexes on a table it
/// will not otherwise touch.
///
/// Only objects a push of this schema would create are stamped. Adoption is an opt-in ceremony for
/// objects the operator has decided belong to Supatype; stamping anything found in the schema
/// would make the gate meaningless on its first run, which is the one case it exists for.
pub fn adopt_stamp_sql(
    ast: &SchemaAst,
    db: &DatabaseState,
    catalog: &CatalogState,
    schema: &str,
) -> Result<Vec<String>> {
    let expected = expected(ast, schema)?;
    let mut lines = Vec::new();

    for db_table in &db.tables {
        if !expected.tables.contains(&db_table.name)
            || is_managed_comment(db_table.comment.as_deref())
        {
            continue;
        }
        // The same marker `CREATE TABLE` writes. A different shape would leave the table
        // permanently undroppable and the differ unable to converge.
        let comment = managed_comment("table", &db_table.name, &[]);
        lines.push(crate::managed::comment_on_table_sql(
            &db_table.name,
            &comment,
            schema,
        ));
    }

    for exp in &expected.uniques {
        let constraint = db.constraints.iter().find(|c| {
            c.constraint_type == DbConstraintType::Unique
                && c.table == exp.table
                && c.columns == exp.columns
        });
        if let Some(c) = constraint {
            if !is_managed_comment(c.comment.as_deref()) {
                let fields: Vec<&str> = exp.columns.iter().map(String::as_str).collect();
                let comment = managed_comment("unique_constraint", &exp.table, &fields);
                lines.push(crate::managed::comment_on_constraint_sql(
                    &exp.table, &c.name, &comment, schema,
                ));
            }
        }
    }

    for exp in &expected.indexes {
        let idx = db
            .indexes
            .iter()
            .chain(&catalog.expression_indexes)
            .find(|i| i.table == exp.table && i.name == exp.name);
        if let Some(i) = idx {
            if !is_managed_comment(i.comment.as_deref()) {
                let kind = if exp.unique { "unique_index" } else { "index" };
                let field_refs: Vec<&str> = exp.fields.iter().map(String::as_str).collect();
                let comment = managed_comment(kind, &exp.table, &field_refs);
                lines.push(crate::managed::comment_on_index_sql(
                    &exp.name, &comment, schema,
                ));
            }
        }
    }

    Ok(lines)
}
