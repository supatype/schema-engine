use crate::parser::accessors::{db_table_name, platform_access, resolve_owner_column};
use crate::parser::ast::{AccessRule, ModelAst, SchemaAst};
use anyhow::Result;

/// Generates RLS policy SQL for all models that have access rules.
/// Policy naming convention: `{table}_select`, `{table}_insert`, `{table}_update`, `{table}_delete`.
pub fn generate(ast: &SchemaAst) -> Result<String> {
    let mut out = String::new();

    for model in &ast.models {
        let access = platform_access(model);
        let has_rules = access.read.is_some()
            || access.create.is_some()
            || access.update.is_some()
            || access.delete.is_some();

        if !has_rules {
            continue;
        }

        let table = db_table_name(model);

        out.push_str(&format!(
            "-- RLS Policies for: {}\n-- Generated from schema access rules\n\n",
            model.name
        ));

        let schema = "public";
        out.push_str(&format!(
            "ALTER TABLE \"{schema}\".\"{table}\" ENABLE ROW LEVEL SECURITY;\n"
        ));
        out.push_str(&format!(
            "ALTER TABLE \"{schema}\".\"{table}\" FORCE ROW LEVEL SECURITY;\n\n"
        ));

        if let Some(rule) = &access.read {
            out.push_str(&render_select_policy_sql(schema, table, model, rule));
        }
        if let Some(rule) = &access.create {
            out.push_str(&render_insert_policy_sql(schema, table, model, rule));
        }
        if let Some(rule) = &access.update {
            out.push_str(&render_update_policy_sql(schema, table, model, rule));
        }
        if let Some(rule) = &access.delete {
            out.push_str(&render_delete_policy_sql(schema, table, model, rule));
        }
    }

    Ok(out)
}

/// Returns SQL DDL for auth helper functions (auth.uid, auth.role, auth.roles).
pub fn generate_auth_helpers() -> &'static str {
    r#"-- Auth helper functions for Supatype RLS policies.
-- Install once per database. Safe to run repeatedly (CREATE OR REPLACE).

CREATE SCHEMA IF NOT EXISTS auth;

CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid
  LANGUAGE sql STABLE AS $$
    SELECT NULLIF(
      current_setting('request.jwt.claims', true)::json->>'sub', ''
    )::uuid;
  $$;

CREATE OR REPLACE FUNCTION auth.role() RETURNS text
  LANGUAGE sql STABLE AS $$
    SELECT COALESCE(
      NULLIF(current_setting('request.jwt.claims', true)::json->>'role', ''),
      'anon'
    );
  $$;

CREATE OR REPLACE FUNCTION auth.roles() RETURNS text[]
  LANGUAGE sql STABLE AS $$
    SELECT ARRAY(
      SELECT jsonb_array_elements_text(
        current_setting('request.jwt.claims', true)::jsonb->'roles'
      )
    );
  $$;

"#
}

pub fn render_policy_migration_sql(
    schema: &str,
    table: &str,
    suffix: &str,
    model: &ModelAst,
    rule: &AccessRule,
) -> String {
    match suffix {
        "select" => render_select_policy_sql(schema, table, model, rule),
        "insert" => render_insert_policy_sql(schema, table, model, rule),
        "update" => render_update_policy_sql(schema, table, model, rule),
        "delete" => render_delete_policy_sql(schema, table, model, rule),
        other => format!("-- unknown RLS policy suffix: {other}\n"),
    }
}

pub(crate) fn render_select_policy_sql(
    schema: &str,
    table: &str,
    model: &ModelAst,
    rule: &AccessRule,
) -> String {
    let expr = access_rule_to_expr(model, rule);
    let name = format!("{table}_select");
    format!(
        "DROP POLICY IF EXISTS \"{name}\" ON \"{schema}\".\"{table}\";\n\
         CREATE POLICY \"{name}\" ON \"{schema}\".\"{table}\"\n\
           FOR SELECT USING (\n    {expr}\n  );\n\n"
    )
}

pub(crate) fn render_insert_policy_sql(
    schema: &str,
    table: &str,
    model: &ModelAst,
    rule: &AccessRule,
) -> String {
    let expr = access_rule_to_expr(model, rule);
    let name = format!("{table}_insert");
    format!(
        "DROP POLICY IF EXISTS \"{name}\" ON \"{schema}\".\"{table}\";\n\
         CREATE POLICY \"{name}\" ON \"{schema}\".\"{table}\"\n\
           FOR INSERT WITH CHECK (\n    {expr}\n  );\n\n"
    )
}

pub(crate) fn render_update_policy_sql(
    schema: &str,
    table: &str,
    model: &ModelAst,
    rule: &AccessRule,
) -> String {
    let expr = access_rule_to_expr(model, rule);
    let name = format!("{table}_update");
    format!(
        "DROP POLICY IF EXISTS \"{name}\" ON \"{schema}\".\"{table}\";\n\
         CREATE POLICY \"{name}\" ON \"{schema}\".\"{table}\"\n\
           FOR UPDATE USING (\n    {expr}\n  ) WITH CHECK (\n    {expr}\n  );\n\n"
    )
}

pub(crate) fn render_delete_policy_sql(
    schema: &str,
    table: &str,
    model: &ModelAst,
    rule: &AccessRule,
) -> String {
    let expr = access_rule_to_expr(model, rule);
    let name = format!("{table}_delete");
    format!(
        "DROP POLICY IF EXISTS \"{name}\" ON \"{schema}\".\"{table}\";\n\
         CREATE POLICY \"{name}\" ON \"{schema}\".\"{table}\"\n\
           FOR DELETE USING (\n    {expr}\n  );\n\n"
    )
}

/// Converts an AccessRule to a Postgres expression string for use in a USING / WITH CHECK clause.
pub fn access_rule_to_expr(model: &ModelAst, rule: &AccessRule) -> String {
    match rule {
        AccessRule::Public => "TRUE".to_string(),
        AccessRule::Private => "FALSE".to_string(),
        AccessRule::Authenticated => "auth.uid() IS NOT NULL".to_string(),
        AccessRule::Owner { field } => {
            let column = resolve_owner_column(model, field);
            format!("auth.uid() = {column}")
        }
        AccessRule::Role { roles } => {
            if roles.len() == 1 {
                format!("auth.role() = '{}'", roles[0])
            } else {
                let arr = roles
                    .iter()
                    .map(|r| format!("'{r}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("auth.role() = ANY(ARRAY[{arr}])")
            }
        }
        AccessRule::Custom { expression } => expression.clone(),
        AccessRule::Any { rules } => {
            let parts: Vec<String> = rules
                .iter()
                .map(|r| {
                    let expr = access_rule_to_expr(model, r);
                    if matches!(r, AccessRule::Any { .. }) {
                        format!("({expr})")
                    } else {
                        expr
                    }
                })
                .collect();
            parts.join("\n    OR\n    ")
        }
    }
}
