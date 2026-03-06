use anyhow::Result;
use crate::parser::ast::{AccessRule, SchemaAst};

/// Generates RLS policy SQL for all models that have access rules.
/// Policy naming convention: `{table}_select`, `{table}_insert`, `{table}_update`, `{table}_delete`.
pub fn generate(ast: &SchemaAst) -> Result<String> {
    let mut out = String::new();

    for model in &ast.models {
        let has_rules = model.access.read.is_some()
            || model.access.create.is_some()
            || model.access.update.is_some()
            || model.access.delete.is_some();

        if !has_rules { continue; }

        let table = &model.table_name;

        out.push_str(&format!(
            "-- RLS Policies for: {}\n-- Generated from schema access rules\n\n",
            model.name
        ));

        // Enable and force RLS so that even table owners are subject to policies.
        out.push_str(&format!(
            "ALTER TABLE \"public\".\"{table}\" ENABLE ROW LEVEL SECURITY;\n"
        ));
        out.push_str(&format!(
            "ALTER TABLE \"public\".\"{table}\" FORCE ROW LEVEL SECURITY;\n\n"
        ));

        if let Some(rule) = &model.access.read {
            out.push_str(&render_select_policy(table, rule));
        }
        if let Some(rule) = &model.access.create {
            out.push_str(&render_insert_policy(table, rule));
        }
        if let Some(rule) = &model.access.update {
            out.push_str(&render_update_policy(table, rule));
        }
        if let Some(rule) = &model.access.delete {
            out.push_str(&render_delete_policy(table, rule));
        }
    }

    Ok(out)
}

/// Returns SQL DDL for auth helper functions (auth.uid, auth.role, auth.roles).
/// These must be installed once per database before RLS policies can be applied.
/// The TypeScript CLI calls `definatype-engine rls` which includes this automatically.
pub fn generate_auth_helpers() -> &'static str {
    r#"-- Auth helper functions for Definatype RLS policies.
-- Install once per database. Safe to run repeatedly (CREATE OR REPLACE).

CREATE SCHEMA IF NOT EXISTS auth;

-- auth.uid() — returns the authenticated user's UUID from the JWT claims.
CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid
  LANGUAGE sql STABLE AS $$
    SELECT NULLIF(
      current_setting('request.jwt.claims', true)::json->>'sub', ''
    )::uuid;
  $$;

-- auth.role() — returns the primary role from the JWT claims.
CREATE OR REPLACE FUNCTION auth.role() RETURNS text
  LANGUAGE sql STABLE AS $$
    SELECT COALESCE(
      NULLIF(current_setting('request.jwt.claims', true)::json->>'role', ''),
      'anon'
    );
  $$;

-- auth.roles() — returns the array of roles from the JWT claims.
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

// ─── Policy rendering ─────────────────────────────────────────────────────────

fn render_select_policy(table: &str, rule: &AccessRule) -> String {
    let expr = access_rule_to_expr(rule);
    let name = format!("{table}_select");
    format!(
        "DROP POLICY IF EXISTS \"{name}\" ON \"public\".\"{table}\";\n\
         CREATE POLICY \"{name}\" ON \"public\".\"{table}\"\n\
           FOR SELECT USING (\n    {expr}\n  );\n\n"
    )
}

fn render_insert_policy(table: &str, rule: &AccessRule) -> String {
    let expr = access_rule_to_expr(rule);
    let name = format!("{table}_insert");
    format!(
        "DROP POLICY IF EXISTS \"{name}\" ON \"public\".\"{table}\";\n\
         CREATE POLICY \"{name}\" ON \"public\".\"{table}\"\n\
           FOR INSERT WITH CHECK (\n    {expr}\n  );\n\n"
    )
}

fn render_update_policy(table: &str, rule: &AccessRule) -> String {
    let expr = access_rule_to_expr(rule);
    let name = format!("{table}_update");
    // UPDATE policies benefit from both USING (filter rows) and WITH CHECK (validate new values)
    format!(
        "DROP POLICY IF EXISTS \"{name}\" ON \"public\".\"{table}\";\n\
         CREATE POLICY \"{name}\" ON \"public\".\"{table}\"\n\
           FOR UPDATE USING (\n    {expr}\n  ) WITH CHECK (\n    {expr}\n  );\n\n"
    )
}

fn render_delete_policy(table: &str, rule: &AccessRule) -> String {
    let expr = access_rule_to_expr(rule);
    let name = format!("{table}_delete");
    format!(
        "DROP POLICY IF EXISTS \"{name}\" ON \"public\".\"{table}\";\n\
         CREATE POLICY \"{name}\" ON \"public\".\"{table}\"\n\
           FOR DELETE USING (\n    {expr}\n  );\n\n"
    )
}

// ─── Expression generation ────────────────────────────────────────────────────

/// Converts an AccessRule to a Postgres expression string for use in a USING / WITH CHECK clause.
pub fn access_rule_to_expr(rule: &AccessRule) -> String {
    match rule {
        AccessRule::Public => "TRUE".to_string(),
        AccessRule::Private => "FALSE".to_string(),
        AccessRule::Authenticated => "auth.uid() IS NOT NULL".to_string(),
        AccessRule::Owner { field } => format!("auth.uid() = {field}"),
        AccessRule::Role { roles } => {
            if roles.len() == 1 {
                format!("auth.role() = '{}'", roles[0])
            } else {
                let arr = roles.iter().map(|r| format!("'{r}'")).collect::<Vec<_>>().join(", ");
                format!("auth.role() = ANY(ARRAY[{arr}])")
            }
        }
        AccessRule::Custom { expression } => expression.clone(),
        AccessRule::Any { rules } => {
            let parts: Vec<String> = rules.iter()
                .map(|r| {
                    let expr = access_rule_to_expr(r);
                    // Wrap sub-expressions in parens for clarity
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
