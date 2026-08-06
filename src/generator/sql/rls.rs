use crate::parser::accessors::{
    db_foreign_key, db_table_name, platform_access, resolve_owner_column,
};
use crate::parser::ast::{
    AccessRule, DefaultValueAst, FieldAst, LiteralValue, ModelAst, Operand, SchemaAst,
};
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
            out.push_str(&render_select_policy_sql(schema, table, ast, model, rule));
        }
        if let Some(rule) = &access.create {
            out.push_str(&render_insert_policy_sql(schema, table, ast, model, rule));
        }
        if let Some(rule) = &access.update {
            out.push_str(&render_update_policy_sql(schema, table, ast, model, rule));
        }
        if let Some(rule) = &access.delete {
            out.push_str(&render_delete_policy_sql(schema, table, ast, model, rule));
        }
    }

    Ok(out)
}

/// SQL DDL for the auth helper functions a policy may call.
///
/// Delegates to `auth_functions` rather than keeping a second copy. There were
/// two definitions of `auth.uid()` and `auth.role()` — this one, installed by a
/// migration, and the canonical one reinstalled by `reapply_auth_helpers` at
/// bootstrap. They had already diverged: this copy read only the top-level `role`
/// claim, so a fresh push installed a version that ignored `app_metadata.role`
/// until something else happened to overwrite it. Any helper added on one side
/// (`auth.claim`, say) was simply missing on the other.
///
/// Safe to run repeatedly — every function is `CREATE OR REPLACE`.
pub fn generate_auth_helpers() -> String {
    let config = crate::generator::sql::auth_functions::AuthFunctionConfig {
        project_ref: String::new(),
        auth_schema: "auth".to_string(),
    };
    let mut sql = crate::generator::sql::auth_functions::generate_auth_functions(&config);

    // `auth.roles()` has no equivalent in auth_functions and is referenced by
    // hand-written policies, so it stays here rather than disappearing.
    sql.push_str(
        r#"

-- auth.roles() -- the `roles` claim as a text array.
CREATE OR REPLACE FUNCTION auth.roles() RETURNS text[]
  LANGUAGE sql STABLE AS $$
    SELECT ARRAY(
      SELECT jsonb_array_elements_text(
        COALESCE(current_setting('request.jwt.claims', true)::jsonb->'roles', '[]'::jsonb)
      )
    );
  $$;

"#,
    );
    sql
}

pub fn render_policy_migration_sql(
    schema: &str,
    table: &str,
    suffix: &str,
    ast: &SchemaAst,
    model: &ModelAst,
    rule: &AccessRule,
) -> String {
    let sql = match suffix {
        "select" => render_select_policy_sql(schema, table, ast, model, rule),
        "insert" => render_insert_policy_sql(schema, table, ast, model, rule),
        "update" => render_update_policy_sql(schema, table, ast, model, rule),
        "delete" => render_delete_policy_sql(schema, table, ast, model, rule),
        other => return format!("-- unknown RLS policy suffix: {other}\n"),
    };

    // Stamp ownership so the differ can distinguish our policies from
    // hand-written ones instead of guessing from the name. Without this, a
    // user's own policy is dropped on the next push, and one that happens to
    // match our naming is silently replaced.
    let comment = crate::managed::managed_comment("rls_policy", table, &[suffix]);
    format!(
        "{sql}COMMENT ON POLICY \"{table}_{suffix}\" ON \"{schema}\".\"{table}\" IS '{comment}';\n"
    )
}

pub(crate) fn render_select_policy_sql(
    schema: &str,
    table: &str,
    ast: &SchemaAst,
    model: &ModelAst,
    rule: &AccessRule,
) -> String {
    let expr = access_rule_to_expr(ast, model, rule);
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
    ast: &SchemaAst,
    model: &ModelAst,
    rule: &AccessRule,
) -> String {
    let expr = access_rule_to_expr(ast, model, rule);
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
    ast: &SchemaAst,
    model: &ModelAst,
    rule: &AccessRule,
) -> String {
    let expr = access_rule_to_expr(ast, model, rule);
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
    ast: &SchemaAst,
    model: &ModelAst,
    rule: &AccessRule,
) -> String {
    let expr = access_rule_to_expr(ast, model, rule);
    let name = format!("{table}_delete");
    format!(
        "DROP POLICY IF EXISTS \"{name}\" ON \"{schema}\".\"{table}\";\n\
         CREATE POLICY \"{name}\" ON \"{schema}\".\"{table}\"\n\
           FOR DELETE USING (\n    {expr}\n  );\n\n"
    )
}

/// `auth.uid()` wrapped so Postgres evaluates it once per query, not once per row.
///
/// A bare `auth.uid()` in a policy is re-evaluated for every row the planner
/// tests, because the function reference sits inside a per-row filter. Wrapping it
/// in a scalar subquery makes the planner treat it as an InitPlan: computed once,
/// then compared as a constant. On a table of any size this is the difference
/// between a policy that scales and one that does not, and it costs nothing.
pub const AUTH_UID: &str = "(SELECT auth.uid())";

/// `auth.role()`, wrapped for the same reason as [`AUTH_UID`].
pub const AUTH_ROLE: &str = "(SELECT auth.role())";

/// Converts an AccessRule to a Postgres expression string for use in a USING / WITH CHECK clause.
pub fn access_rule_to_expr(ast: &SchemaAst, model: &ModelAst, rule: &AccessRule) -> String {
    match rule {
        AccessRule::Public => "TRUE".to_string(),
        AccessRule::Private => "FALSE".to_string(),
        AccessRule::Authenticated => format!("{AUTH_UID} IS NOT NULL"),
        AccessRule::Owner { field } => owner_access_expr(ast, model, field),
        AccessRule::Role { roles } => {
            if roles.len() == 1 {
                format!("{AUTH_ROLE} = '{}'", roles[0])
            } else {
                let arr = roles
                    .iter()
                    .map(|r| format!("'{r}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{AUTH_ROLE} = ANY(ARRAY[{arr}])")
            }
        }
        AccessRule::Custom { expression } => expression.clone(),
        AccessRule::Any { rules } => join_rules(ast, model, rules, "OR"),
        AccessRule::All { rules } => join_rules(ast, model, rules, "AND"),
        AccessRule::Not { rule } => {
            format!("NOT ({})", access_rule_to_expr(ast, model, rule))
        }
        AccessRule::Compare { left, op, right } => {
            format!(
                "{} {} {}",
                operand_to_expr(left),
                op.sql(),
                operand_to_expr(right)
            )
        }
        AccessRule::NullCheck { operand, is_null } => {
            let test = if *is_null { "IS NULL" } else { "IS NOT NULL" };
            format!("{} {test}", operand_to_expr(operand))
        }
    }
}

/// Joins composed rules, parenthesising any child that is itself a composition.
///
/// Without the parentheses `Any<[a, All<[b, c]>]>` would render as `a OR b AND c`,
/// which Postgres reads as `a OR (b AND c)` — correct by luck here, and wrong the
/// moment the nesting is the other way round. Precedence is never left to chance.
fn join_rules(ast: &SchemaAst, model: &ModelAst, rules: &[AccessRule], joiner: &str) -> String {
    let parts: Vec<String> = rules
        .iter()
        .map(|r| {
            let expr = access_rule_to_expr(ast, model, r);
            if matches!(
                r,
                AccessRule::Any { .. } | AccessRule::All { .. } | AccessRule::Custom { .. }
            ) {
                format!("({expr})")
            } else {
                expr
            }
        })
        .collect();
    parts.join(&format!("\n    {joiner}\n    "))
}

/// Renders one side of a comparison.
fn operand_to_expr(operand: &Operand) -> String {
    match operand {
        Operand::Column { name } => format!("\"{}\"", name.replace('"', "\"\"")),
        Operand::AuthUid => AUTH_UID.to_string(),
        Operand::AuthRole => AUTH_ROLE.to_string(),
        // Text, so it compares against a column or a string literal. A claim used
        // as a *set* goes through the membership path instead, which needs the
        // jsonb form.
        Operand::Claim { path } => format!("auth.claim_text({})", quote_literal(path)),
        Operand::Literal { value } => match value {
            LiteralValue::Bool(b) => if *b { "TRUE" } else { "FALSE" }.to_string(),
            // `{:?}` on f64 keeps integers as `1` rather than `1.0`, so a whole
            // number compares against an integer column without a cast.
            LiteralValue::Number(n) => format!("{n:?}").trim_end_matches(".0").to_string(),
            LiteralValue::Text(t) => quote_literal(t),
        },
    }
}

/// Single-quotes a string for SQL, doubling any embedded quote.
///
/// Schema authors control these strings, but a stray apostrophe in a claim path or
/// a literal would otherwise end the quoted string and change the meaning of the
/// policy around it.
fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Owner / OwnerFrom — compare auth.uid() to a row column or ownership via a related model.
fn owner_access_expr(ast: &SchemaAst, model: &ModelAst, kernel_field: &str) -> String {
    if kernel_field == "id" {
        return format!("{AUTH_UID} = id");
    }

    if let Some((field_name, field)) = model.fields.get_key_value(kernel_field) {
        if let FieldAst::Relation(rel) = field {
            let fk = db_foreign_key(field, field_name).unwrap_or_else(|| {
                crate::parser::accessors::default_foreign_key_column(field_name)
            });

            if let Some(target) = ast.models.iter().find(|m| m.name == rel.target) {
                if is_user_identity_model(target) {
                    return format!("{AUTH_UID} = {fk}");
                }
                if let Some(owner_col) = owner_column_on_model(target) {
                    let table = db_table_name(target);
                    return format!(
                        "EXISTS (SELECT 1 FROM \"{table}\" WHERE \"{table}\".id = {fk} AND {AUTH_UID} = \"{table}\".{owner_col})"
                    );
                }
            }

            return format!("{AUTH_UID} = {fk}");
        }

        let column = resolve_owner_column(model, kernel_field);
        return format!("{AUTH_UID} = {column}");
    }

    let column = resolve_owner_column(model, kernel_field);
    format!("{AUTH_UID} = {column}")
}

/// Models whose primary key is the auth user id (e.g. Profile), not a generated UUID.
fn is_user_identity_model(model: &ModelAst) -> bool {
    let Some(FieldAst::Uuid(id)) = model.fields.get("id") else {
        return false;
    };
    if !id.primary_key {
        return false;
    }
    !matches!(id.default, Some(DefaultValueAst::GenRandomUuid))
}

/// Owner column on a related model (from its read/update Owner rule).
fn owner_column_on_model(model: &ModelAst) -> Option<String> {
    let access = platform_access(model);
    let rule = access.read.as_ref().or(access.update.as_ref())?;
    let AccessRule::Owner { field } = rule else {
        return None;
    };
    if field == "id" {
        return Some("id".to_string());
    }
    Some(resolve_owner_column(model, field))
}
