use super::{Operation, Risk};
use crate::introspector::indexes::DbIndex;
use crate::managed::{expected_model_index_name, is_managed_comment};
use crate::parser::ast::{IndexAst, SchemaAst};
use crate::state::database_state::DatabaseState;
use anyhow::Result;
use std::collections::HashSet;

fn expected_index_names(ast: &SchemaAst) -> HashSet<(String, String)> {
    let mut names = HashSet::new();
    for model in &ast.models {
        // Declared and implicit together. The generator creates three kinds nobody declares, each
        // with a managed comment, so leaving them out of `expected` meant the differ saw a managed
        // index it could not account for and proposed dropping it, every single push.
        let implicit = crate::generator::sql::migration::implicit_model_indexes(model);
        for index in model.indexes().iter().chain(implicit.iter()) {
            let derived = expected_model_index_name(model.table_name(), &index.fields);
            let idx_name = index
                .name
                .as_deref()
                .unwrap_or(derived.as_str())
                .to_string();
            names.insert((model.table_name().to_string(), idx_name));
        }
    }
    names
}

/// Whether the index the database holds is the index the schema declares.
///
/// Compared on everything that changes what the index does: which columns, in what order, whether
/// it is unique, and which access method. Postgres has no `ALTER INDEX` for any of these, so a
/// difference means drop and recreate.
///
/// Matching on name alone was the whole check once, which made every one of those edits silent.
/// Adding `unique` to an index that already existed changed the admin config, changed what Studio
/// reported, and changed nothing in the database: the name was still there, so the differ planned
/// no work and the push reported success. The `CREATE INDEX IF NOT EXISTS` the generator emits
/// would not have helped even if an add had been planned.
fn index_matches(declared: &IndexAst, live: &DbIndex) -> bool {
    live.unique == declared.unique
        && live.method.eq_ignore_ascii_case(declared.using.as_sql())
        && live.columns == declared.fields
}

pub fn diff(ast: &SchemaAst, db: &DatabaseState, ops: &mut Vec<Operation>) -> Result<()> {
    let expected = expected_index_names(ast);
    let schema_tables: HashSet<&str> = ast.models.iter().map(|m| m.table_name()).collect();

    for model in &ast.models {
        for index in model.indexes() {
            let derived = expected_model_index_name(model.table_name(), &index.fields);
            let idx_name = index.name.as_deref().unwrap_or(derived.as_str());

            let live = db
                .indexes
                .iter()
                .find(|i| !i.is_primary && i.name == idx_name && i.table == model.table_name());

            // Same name but a different index is a rebuild, not a second index. The add carries
            // its own `DROP INDEX IF EXISTS`, so it is emitted the same way whether the index is
            // new or being replaced.
            if live.is_some_and(|existing| index_matches(index, existing)) {
                continue;
            }

            ops.push(Operation::AddIndex {
                table: model.table_name().to_string(),
                index: Box::new(index.clone()),
                risk: Risk::Safe,
            });
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
                    && c.constraint_type
                        == crate::introspector::constraints::DbConstraintType::Unique
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
