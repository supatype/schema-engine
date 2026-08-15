use crate::differ::column_diff::column_names_for;
use crate::introspector::constraints::{DbConstraint, DbConstraintType};
use crate::managed::{
    expected_model_index_name, expected_unique_constraint_name, is_managed_comment, managed_comment,
};
use crate::parser::accessors::db_unique;
use crate::parser::ast::{FieldAst, SchemaAst};
use crate::state::database_state::DatabaseState;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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

pub fn report(ast: &SchemaAst, db: &DatabaseState) -> DoctorReport {
    let schema_tables: HashSet<&str> = ast.models.iter().map(|m| m.table_name()).collect();
    let expected_uniques = expected_column_uniques(ast);
    let expected_indexes = expected_model_indexes(ast);

    let expected_unique_keys: HashSet<(String, String)> = expected_uniques
        .iter()
        .map(|e| (e.table.clone(), e.constraint_name.clone()))
        .collect();
    let expected_index_keys: HashSet<(String, String)> = expected_indexes
        .iter()
        .map(|e| (e.table.clone(), e.index_name.clone()))
        .collect();

    let mut missing = Vec::new();
    let mut stale_managed = Vec::new();
    let mut unmanaged_drift = Vec::new();

    for exp in &expected_uniques {
        let exists = db.constraints.iter().any(|c| {
            c.constraint_type == DbConstraintType::Unique
                && c.table == exp.table
                && c.columns == vec![exp.column.clone()]
        });
        if !exists {
            missing.push(DoctorItem {
                kind: "unique_constraint".into(),
                table: exp.table.clone(),
                name: exp.constraint_name.clone(),
                fields: vec![exp.column.clone()],
                message: format!(
                    "AST expects unique on {}.{} — run `supatype push`",
                    exp.table, exp.column
                ),
            });
        }
    }

    for exp in &expected_indexes {
        let exists = db
            .indexes
            .iter()
            .any(|i| i.table == exp.table && i.name == exp.index_name);
        if !exists {
            missing.push(DoctorItem {
                kind: if exp.unique {
                    "unique_index".into()
                } else {
                    "index".into()
                },
                table: exp.table.clone(),
                name: exp.index_name.clone(),
                fields: exp.fields.clone(),
                message: format!(
                    "AST expects index {} on {} — run `supatype push`",
                    exp.index_name, exp.table
                ),
            });
        }
    }

    for constraint in db.constraints.iter().filter(|c| {
        c.constraint_type == DbConstraintType::Unique
            && c.columns.len() == 1
            && schema_tables.contains(c.table.as_str())
    }) {
        let key = (constraint.table.clone(), constraint.name.clone());
        if expected_unique_keys.contains(&key) {
            continue;
        }
        let col = constraint.columns.first().cloned().unwrap_or_default();
        if expected_uniques
            .iter()
            .any(|e| e.table == constraint.table && e.column == col)
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

    for idx in db
        .indexes
        .iter()
        .filter(|i| !i.is_primary && schema_tables.contains(i.table.as_str()))
    {
        let key = (idx.table.clone(), idx.name.clone());
        if expected_index_keys.contains(&key) {
            continue;
        }
        if idx.unique
            && idx.columns.len() == 1
            && db.constraints.iter().any(|c| {
                c.name == idx.name
                    && c.table == idx.table
                    && c.constraint_type == DbConstraintType::Unique
            })
        {
            continue;
        }
        let item = DoctorItem {
            kind: if idx.unique {
                "unique_index".into()
            } else {
                "index".into()
            },
            table: idx.table.clone(),
            name: idx.name.clone(),
            fields: idx.columns.clone(),
            message: if is_managed_comment(idx.comment.as_deref()) {
                format!(
                    "Managed index {} on {} is not in AST — review before push",
                    idx.name, idx.table
                )
            } else {
                format!(
                    "Unmanaged index {} on {} — push will not drop; manual decision required",
                    idx.name, idx.table
                )
            },
        };
        if is_managed_comment(idx.comment.as_deref()) {
            stale_managed.push(item);
        } else {
            unmanaged_drift.push(item);
        }
    }

    // Tables, which the report never covered.
    //
    // Indexes and constraints have been reported this way for a long time; tables were not, so the
    // ownership gate could silently decline to drop a table and `doctor` would say nothing. An
    // operator seeing a clean report and a push that leaves a table behind concludes push is broken.
    // Wording matches the constraint and index cases deliberately — the mechanism is the same one.
    let schema_owned: HashSet<&str> = ast
        .models
        .iter()
        .map(|m| m.table_name())
        .chain(ast.junction_tables.iter().map(|j| j.name.as_str()))
        .collect();

    for table in &db.tables {
        let managed = is_managed_comment(table.comment.as_deref());
        let in_schema = schema_owned.contains(table.name.as_str());

        // In the schema and unmarked: the table is diffed normally, but the gate declines to drop a
        // column the schema no longer declares. That is the difference `adopt` resolves.
        if in_schema && !managed {
            unmanaged_drift.push(DoctorItem {
                kind: "table".into(),
                table: table.name.clone(),
                name: table.name.clone(),
                fields: Vec::new(),
                message: format!(
                    "Table {} matches a model but is not managed — push will not drop its columns; \
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
                    "Managed table {} is not in AST — review before push",
                    table.name
                )
            } else {
                format!(
                    "Unmanaged table {} — push will not drop; manual decision required",
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

    DoctorReport {
        missing,
        stale_managed,
        unmanaged_drift,
    }
}

pub fn has_strict_issues(report: &DoctorReport) -> bool {
    !report.missing.is_empty() || !report.stale_managed.is_empty()
}

struct ExpectedUnique {
    table: String,
    column: String,
    constraint_name: String,
}

struct ExpectedIndex {
    table: String,
    index_name: String,
    fields: Vec<String>,
    unique: bool,
}

fn expected_column_uniques(ast: &SchemaAst) -> Vec<ExpectedUnique> {
    let mut out = Vec::new();
    for model in &ast.models {
        let table = model.table_name().to_string();
        for (field_name, field) in &model.fields {
            if !db_unique(field) || matches!(field, FieldAst::Relation(_)) {
                continue;
            }
            for col in column_names_for(field_name, field) {
                if col.is_empty() {
                    continue;
                }
                out.push(ExpectedUnique {
                    table: table.clone(),
                    column: col.clone(),
                    constraint_name: expected_unique_constraint_name(&table, &col),
                });
            }
        }
    }
    out
}

fn expected_model_indexes(ast: &SchemaAst) -> Vec<ExpectedIndex> {
    let mut out = Vec::new();
    for model in &ast.models {
        let table = model.table_name().to_string();
        for index in model.indexes() {
            let derived = expected_model_index_name(table.as_str(), &index.fields);
            let index_name = index
                .name
                .as_deref()
                .unwrap_or(derived.as_str())
                .to_string();
            out.push(ExpectedIndex {
                table: table.clone(),
                index_name,
                fields: index.fields.clone(),
                unique: index.unique,
            });
        }
    }
    out
}

fn doctor_constraint_item(constraint: &DbConstraint) -> DoctorItem {
    let fields = constraint.columns.clone();
    DoctorItem {
        kind: "unique_constraint".into(),
        table: constraint.table.clone(),
        name: constraint.name.clone(),
        fields: fields.clone(),
        message: if is_managed_comment(constraint.comment.as_deref()) {
            format!(
                "Managed constraint {} on {} is not in AST — review before push",
                constraint.name, constraint.table
            )
        } else {
            format!(
                "Unmanaged constraint {} on {} — push will not drop; manual decision required",
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
/// Only tables the schema actually declares are stamped. Adoption is an opt-in ceremony for objects
/// the operator has decided belong to Supatype — stamping anything found in the schema would make the
/// gate meaningless on its first run, which is the one case it exists for.
pub fn adopt_stamp_sql(ast: &SchemaAst, db: &DatabaseState, schema: &str) -> Vec<String> {
    let expected_uniques = expected_column_uniques(ast);
    let expected_indexes = expected_model_indexes(ast);
    let mut lines = Vec::new();

    for model in &ast.models {
        let table = model.table_name();
        let Some(db_table) = db.tables.iter().find(|t| t.name == table) else {
            continue;
        };
        if is_managed_comment(db_table.comment.as_deref()) {
            continue;
        }
        // The same marker `CREATE TABLE` writes. A different shape would leave the table
        // permanently undroppable and the differ unable to converge.
        let comment = managed_comment("table", table, &[]);
        lines.push(crate::managed::comment_on_table_sql(
            table, &comment, schema,
        ));
    }

    for junction in &ast.junction_tables {
        let Some(db_table) = db.tables.iter().find(|t| t.name == junction.name) else {
            continue;
        };
        if is_managed_comment(db_table.comment.as_deref()) {
            continue;
        }
        let comment = managed_comment("table", &junction.name, &[]);
        lines.push(crate::managed::comment_on_table_sql(
            &junction.name,
            &comment,
            schema,
        ));
    }

    for exp in &expected_uniques {
        let constraint = db.constraints.iter().find(|c| {
            c.constraint_type == DbConstraintType::Unique
                && c.table == exp.table
                && c.columns == vec![exp.column.clone()]
        });
        if let Some(c) = constraint {
            if !is_managed_comment(c.comment.as_deref()) {
                let comment = managed_comment("unique_constraint", &exp.table, &[&exp.column]);
                lines.push(crate::managed::comment_on_constraint_sql(
                    &exp.table, &c.name, &comment, schema,
                ));
            }
        }
    }

    for exp in &expected_indexes {
        let idx = db
            .indexes
            .iter()
            .find(|i| i.table == exp.table && i.name == exp.index_name);
        if let Some(i) = idx {
            if !is_managed_comment(i.comment.as_deref()) {
                let kind = if exp.unique { "unique_index" } else { "index" };
                let field_refs: Vec<&str> = exp.fields.iter().map(String::as_str).collect();
                let comment = managed_comment(kind, &exp.table, &field_refs);
                lines.push(crate::managed::comment_on_index_sql(
                    &exp.index_name,
                    &comment,
                    schema,
                ));
            }
        }
    }

    lines
}
