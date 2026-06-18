use super::{Operation, Risk};
use crate::differ::column_diff::column_names_for;
use crate::introspector::constraints::{DbConstraint, DbConstraintType};
use crate::managed::{expected_unique_constraint_name, is_managed_comment};
use crate::parser::accessors::db_unique;
use crate::parser::ast::{FieldAst, SchemaAst};
use crate::state::database_state::DatabaseState;
use anyhow::Result;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExpectedUnique {
    table: String,
    column: String,
    constraint_name: String,
}

fn expected_column_uniques(ast: &SchemaAst) -> Vec<ExpectedUnique> {
    let mut out = Vec::new();
    for model in &ast.models {
        let table = model.table_name().to_string();
        for (field_name, field) in &model.fields {
            if !db_unique(field) {
                continue;
            }
            if matches!(field, FieldAst::Relation(_)) {
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

fn db_unique_constraints(db: &DatabaseState) -> Vec<&DbConstraint> {
    db.constraints
        .iter()
        .filter(|c| c.constraint_type == DbConstraintType::Unique && c.columns.len() == 1)
        .collect()
}

pub fn diff(ast: &SchemaAst, db: &DatabaseState, ops: &mut Vec<Operation>) -> Result<()> {
    let expected = expected_column_uniques(ast);
    let expected_keys: HashSet<(String, String)> = expected
        .iter()
        .map(|e| (e.table.clone(), e.constraint_name.clone()))
        .collect();

    let schema_tables: HashSet<&str> = ast.models.iter().map(|m| m.table_name()).collect();

    for exp in &expected {
        // CREATE TABLE already declares inline UNIQUE for new tables.
        if table_being_created(ops, &exp.table) {
            continue;
        }
        let exists = db.constraints.iter().any(|c| {
            c.constraint_type == DbConstraintType::Unique
                && c.table == exp.table
                && c.columns == vec![exp.column.clone()]
        });
        if !exists {
            ops.push(Operation::AddUniqueConstraint {
                table: exp.table.clone(),
                column: exp.column.clone(),
                constraint: exp.constraint_name.clone(),
                risk: Risk::Safe,
            });
        }
    }

    for constraint in db_unique_constraints(db) {
        if !schema_tables.contains(constraint.table.as_str()) {
            continue;
        }
        let key = (constraint.table.clone(), constraint.name.clone());
        if expected_keys.contains(&key) {
            continue;
        }
        // Also skip if a matching expected unique exists under a different constraint name.
        let col = constraint.columns.first().map(String::as_str).unwrap_or("");
        if expected
            .iter()
            .any(|e| e.table == constraint.table && e.column == col)
        {
            continue;
        }
        if !is_managed_comment(constraint.comment.as_deref()) {
            continue;
        }
        ops.push(Operation::DropUniqueConstraint {
            table: constraint.table.clone(),
            constraint: constraint.name.clone(),
            risk: Risk::Safe,
        });
    }

    Ok(())
}

fn table_being_created(ops: &[Operation], table: &str) -> bool {
    ops.iter()
        .any(|op| matches!(op, Operation::CreateTable { table: t, .. } if t == table))
}
