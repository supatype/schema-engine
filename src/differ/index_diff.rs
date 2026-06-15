use super::{Operation, Risk};
use crate::parser::ast::SchemaAst;
use crate::state::database_state::DatabaseState;
use anyhow::Result;

pub fn diff(ast: &SchemaAst, db: &DatabaseState, ops: &mut Vec<Operation>) -> Result<()> {
    let db_index_names: std::collections::HashSet<&str> = db
        .indexes
        .iter()
        .filter(|i| !i.is_primary)
        .map(|i| i.name.as_str())
        .collect();

    for model in &ast.models {
        for index in model.indexes() {
            let derived = format!("{}_{}_idx", model.table_name(), index.fields.join("_"));
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

    Ok(())
}
