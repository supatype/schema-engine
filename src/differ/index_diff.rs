use super::{Operation, Risk};
use crate::managed::{expected_model_index_name, is_managed_comment};
use crate::parser::ast::SchemaAst;
use crate::state::database_state::DatabaseState;
use anyhow::Result;
use std::collections::HashSet;

fn expected_index_names(ast: &SchemaAst) -> HashSet<(String, String)> {
    let mut names = HashSet::new();
    for model in &ast.models {
        let table = model.table_name();
        for index in model.indexes() {
            let derived = expected_model_index_name(table, &index.fields);
            let idx_name = index
                .name
                .as_deref()
                .unwrap_or(derived.as_str())
                .to_string();
            names.insert((table.to_string(), idx_name));
        }
    }
    names
}

pub fn diff(ast: &SchemaAst, db: &DatabaseState, ops: &mut Vec<Operation>) -> Result<()> {
    let db_index_names: HashSet<&str> = db
        .indexes
        .iter()
        .filter(|i| !i.is_primary)
        .map(|i| i.name.as_str())
        .collect();

    let expected = expected_index_names(ast);
    let schema_tables: HashSet<&str> = ast.models.iter().map(|m| m.table_name()).collect();

    for model in &ast.models {
        for index in model.indexes() {
            let derived = expected_model_index_name(model.table_name(), &index.fields);
            let idx_name = index.name.as_deref().unwrap_or(derived.as_str());
            if !db_index_names.contains(idx_name) {
                ops.push(Operation::AddIndex {
                    table: model.table_name().to_string(),
                    index: Box::new(index.clone()),
                    risk: Risk::Safe,
                });
            }
        }
    }

    for idx in &db.indexes {
        if idx.is_primary {
            continue;
        }
        if !schema_tables.contains(idx.table.as_str()) {
            continue;
        }
        let key = (idx.table.clone(), idx.name.clone());
        if expected.contains(&key) {
            continue;
        }
        // Skip constraint-backed single-column unique indexes (handled by constraint_diff).
        if idx.unique
            && idx.columns.len() == 1
            && db.constraints.iter().any(|c| {
                c.name == idx.name
                    && c.table == idx.table
                    && c.constraint_type == crate::introspector::constraints::DbConstraintType::Unique
            })
        {
            continue;
        }
        if !is_managed_comment(idx.comment.as_deref()) {
            continue;
        }
        ops.push(Operation::DropIndex {
            index_name: idx.name.clone(),
            risk: Risk::Safe,
        });
    }

    Ok(())
}
