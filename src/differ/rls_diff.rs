use anyhow::Result;
use crate::parser::ast::{AccessAst, SchemaAst};
use crate::state::database_state::DatabaseState;
use super::{Operation, Risk};

pub fn diff(ast: &SchemaAst, db: &DatabaseState, ops: &mut Vec<Operation>) -> Result<()> {
    let db_rls_tables: std::collections::HashSet<&str> =
        db.rls_policies.iter().map(|p| p.table.as_str()).collect();

    for model in &ast.models {
        let has_access_rules = model.access.read.is_some()
            || model.access.create.is_some()
            || model.access.update.is_some()
            || model.access.delete.is_some();

        if has_access_rules && !db_rls_tables.contains(model.table_name.as_str()) {
            ops.push(Operation::EnableRls {
                table: model.table_name.clone(),
                risk: Risk::Safe,
            });

            for (policy_name, _) in access_policy_names(&model.access) {
                ops.push(Operation::CreateRlsPolicy {
                    table: model.table_name.clone(),
                    policy: policy_name,
                    risk: Risk::Safe,
                });
            }
        }
    }

    Ok(())
}

fn access_policy_names(access: &AccessAst) -> Vec<(String, &str)> {
    let mut names = Vec::new();
    if access.read.is_some() { names.push(("select_policy".to_string(), "SELECT")); }
    if access.create.is_some() { names.push(("insert_policy".to_string(), "INSERT")); }
    if access.update.is_some() { names.push(("update_policy".to_string(), "UPDATE")); }
    if access.delete.is_some() { names.push(("delete_policy".to_string(), "DELETE")); }
    names
}
