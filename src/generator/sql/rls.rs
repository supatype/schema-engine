use anyhow::Result;
use crate::parser::ast::{AccessRule, SchemaAst};

pub fn generate(ast: &SchemaAst) -> Result<String> {
    let mut out = String::new();

    for model in &ast.models {
        let has_rules = model.access.read.is_some()
            || model.access.create.is_some()
            || model.access.update.is_some()
            || model.access.delete.is_some();

        if !has_rules { continue; }

        out.push_str(&format!(
            "-- RLS Policies for: {}\n-- Generated from schema access rules\n\n",
            model.name
        ));
        out.push_str(&format!(
            "ALTER TABLE \"public\".\"{table}\" ENABLE ROW LEVEL SECURITY;\n\n",
            table = model.table_name
        ));

        if let Some(rule) = &model.access.read {
            out.push_str(&render_policy(&model.table_name, "select_policy", "SELECT", "USING", rule));
        }
        if let Some(rule) = &model.access.create {
            out.push_str(&render_policy(&model.table_name, "insert_policy", "INSERT", "WITH CHECK", rule));
        }
        if let Some(rule) = &model.access.update {
            out.push_str(&render_policy(&model.table_name, "update_policy", "UPDATE", "USING", rule));
        }
        if let Some(rule) = &model.access.delete {
            out.push_str(&render_policy(&model.table_name, "delete_policy", "DELETE", "USING", rule));
        }
    }

    Ok(out)
}

fn render_policy(table: &str, name: &str, command: &str, clause: &str, rule: &AccessRule) -> String {
    let expr = access_rule_to_expr(rule);
    let full_name = format!("{table}_{name}");
    format!(
        "CREATE POLICY \"{full_name}\" ON \"public\".\"{table}\"\n  FOR {command}\n  {clause} (\n    {expr}\n  );\n\n"
    )
}

fn access_rule_to_expr(rule: &AccessRule) -> String {
    match rule {
        AccessRule::Public => "TRUE".to_string(),
        AccessRule::Private => "FALSE".to_string(),
        AccessRule::Owner { field } => format!("auth.uid() = {field}"),
        AccessRule::Role { roles } => {
            let list = roles.iter().map(|r| format!("'{r}'")).collect::<Vec<_>>().join(", ");
            format!("auth.role() IN ({list})")
        }
        AccessRule::Custom { expression } => expression.clone(),
    }
}
