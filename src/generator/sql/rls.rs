use crate::generator::sql::auth_functions::{API_ROLES, AUTH_SCHEMA};
use crate::parser::accessors::{
    db_foreign_key, db_table_name, platform_access, resolve_owner_column,
};
use crate::parser::ast::{
    AccessRule, DefaultValueAst, FieldAst, IntervalSpec, LiteralValue, MembershipSource, ModelAst,
    Operand, SchemaAst,
};
use anyhow::Result;

/// Generates RLS policy SQL for all models that have access rules.
/// Policy naming convention: `{table}_select`, `{table}_insert`, `{table}_update`, `{table}_delete`.
/// `schema` is the schema Supatype manages (`schema.pg_schema`). It used to be a literal `"public"`
/// here and in five other generators, which meant a project pointed at its own schema created its
/// tables in the right place and then attached its policies, grants, labels and membership
/// subqueries to `public`: either erroring, or silently reading a same-named table belonging to
/// whoever else is in that schema. The second case is the one this parameter exists for.
pub fn generate(ast: &SchemaAst, schema: &str) -> Result<String> {
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
            out.push_str(&render_update_policy_sql(
                schema,
                table,
                ast,
                model,
                rule,
                access.update_check.as_ref(),
            ));
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
/// two definitions of `auth.uid()` and `auth.role()`: this one, installed by a
/// migration, and the canonical one reinstalled by `reapply_auth_helpers` at
/// bootstrap. They had already diverged: this copy read only the top-level `role`
/// claim, so a fresh push installed a version that ignored `app_metadata.role`
/// until something else happened to overwrite it. Any helper added on one side
/// (`auth.claim`, say) was simply missing on the other.
///
/// Safe to run repeatedly, since every function is `CREATE OR REPLACE`.
pub fn generate_auth_helpers() -> String {
    let config = crate::generator::sql::auth_functions::AuthFunctionConfig {
        project_ref: String::new(),
        auth_schema: AUTH_SCHEMA.to_string(),
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
    // The update policy's WITH CHECK comes from the model rather than the caller:
    // the differ works one policy at a time and has only the USING rule to hand,
    // so reading the pair here keeps the two halves from drifting apart.
    let update_check = platform_access(model).update_check.clone();

    let sql = match suffix {
        "select" => render_select_policy_sql(schema, table, ast, model, rule),
        "insert" => render_insert_policy_sql(schema, table, ast, model, rule),
        "update" => {
            render_update_policy_sql(schema, table, ast, model, rule, update_check.as_ref())
        }
        "delete" => render_delete_policy_sql(schema, table, ast, model, rule),
        other => return format!("-- unknown RLS policy suffix: {other}\n"),
    };

    // Stamp ownership so the differ can distinguish our policies from
    // hand-written ones instead of guessing from the name. Without this, a
    // user's own policy is dropped on the next push, and one that happens to
    // match our naming is silently replaced.
    let comment = crate::managed::managed_comment("rls_policy", table, &[suffix]);

    // The membership indexes a rule's join columns need are the reconcile's (Phase 4.3), so one
    // dropped by hand comes back on the next push whether or not the policy changed.
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
    let expr = access_rule_to_expr(ast, model, rule, schema);
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
    let expr = access_rule_to_expr(ast, model, rule, schema);
    let name = format!("{table}_insert");
    format!(
        "DROP POLICY IF EXISTS \"{name}\" ON \"{schema}\".\"{table}\";\n\
         CREATE POLICY \"{name}\" ON \"{schema}\".\"{table}\"\n\
           FOR INSERT WITH CHECK (\n    {expr}\n  );\n\n"
    )
}

/// `check` splits the result constraint from the row selection. `None` uses the
/// same rule for both, which is what a schema written as a single rule means.
pub(crate) fn render_update_policy_sql(
    schema: &str,
    table: &str,
    ast: &SchemaAst,
    model: &ModelAst,
    rule: &AccessRule,
    check: Option<&AccessRule>,
) -> String {
    let using_expr = access_rule_to_expr(ast, model, rule, schema);
    let check_expr = match check {
        Some(c) => access_rule_to_expr(ast, model, c, schema),
        None => using_expr.clone(),
    };
    let name = format!("{table}_update");
    format!(
        "DROP POLICY IF EXISTS \"{name}\" ON \"{schema}\".\"{table}\";\n\
         CREATE POLICY \"{name}\" ON \"{schema}\".\"{table}\"\n\
           FOR UPDATE USING (\n    {using_expr}\n  ) WITH CHECK (\n    {check_expr}\n  );\n\n"
    )
}

pub(crate) fn render_delete_policy_sql(
    schema: &str,
    table: &str,
    ast: &SchemaAst,
    model: &ModelAst,
    rule: &AccessRule,
) -> String {
    let expr = access_rule_to_expr(ast, model, rule, schema);
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

/// Default schema for policies, affordance functions and grants.
///
/// A fallback, not the answer: the generators here take the managed schema as a parameter. This
/// covers callers with genuinely nothing to pass, an introspected `DatabaseState` whose `schema` is
/// empty, for instance.
pub const DEFAULT_POLICY_SCHEMA: &str = "public";

/// `auth.role()`, wrapped for the same reason as [`AUTH_UID`].
pub const AUTH_ROLE: &str = "(SELECT auth.role())";

/// Converts an AccessRule to a Postgres expression string for use in a USING / WITH CHECK clause.
pub fn access_rule_to_expr(
    ast: &SchemaAst,
    model: &ModelAst,
    rule: &AccessRule,
    schema: &str,
) -> String {
    match rule {
        // Constraint-only nodes. The CLI refuses them inside `access`, so reaching here means a
        // hand-written AST; rendering FALSE denies rather than silently granting.
        AccessRule::Matches { .. } => "FALSE".to_string(),
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
        AccessRule::Any { rules } => join_rules(ast, model, rules, "OR", schema),
        AccessRule::All { rules } => join_rules(ast, model, rules, "AND", schema),
        AccessRule::Not { rule } => {
            format!("NOT ({})", access_rule_to_expr(ast, model, rule, schema))
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
        AccessRule::In { column, source } => membership_to_expr(ast, model, column, source, schema),
        AccessRule::Exists { source } => set_exists_expr(ast, model, source, schema),
    }
}

/// "The source set is non-empty", with no column involved.
fn set_exists_expr(
    ast: &SchemaAst,
    model: &ModelAst,
    source: &MembershipSource,
    schema: &str,
) -> String {
    match source {
        MembershipSource::Claim { path } => format!(
            "EXISTS (SELECT 1 FROM jsonb_array_elements_text(\
             COALESCE(auth.claim({}), '[]'::jsonb)))",
            quote_literal(path)
        ),

        // A fixed set's emptiness is known at generation time, so it folds to a
        // constant rather than asking the database a question with one answer.
        MembershipSource::Literal { values } => {
            if values.is_empty() { "FALSE" } else { "TRUE" }.to_string()
        }

        MembershipSource::Rows { table, filter, .. } => {
            let table_esc = table.replace('"', "\"\"");
            let mut sql = format!("EXISTS (SELECT 1 FROM \"{schema}\".\"{table_esc}\"");
            if let Some(rule) = filter {
                let inner_model = ast.models.iter().find(|m| db_table_name(m) == table);
                let inner_expr = match inner_model {
                    Some(m) => access_rule_to_expr(ast, m, rule, schema),
                    None => access_rule_to_expr(ast, model, rule, schema),
                };
                sql.push_str(&format!(
                    " WHERE ({})",
                    qualify_bare_columns(&inner_expr, table)
                ));
            }
            sql.push(')');
            sql
        }
    }
}

/// Compiles a membership test.
///
/// Every form is a semi-join or an array test rather than `IN (SELECT …)`: the
/// planner can stop at the first match per row instead of materialising the whole
/// set, which is the difference between a policy that works on a large join table
/// and one that does not.
fn membership_to_expr(
    ast: &SchemaAst,
    model: &ModelAst,
    column: &str,
    source: &MembershipSource,
    schema: &str,
) -> String {
    let own_table = db_table_name(model);
    // Qualified so the correlated reference is unambiguous: the subquery's own
    // table may well have a column of the same name, and an unqualified reference
    // would silently bind to the *inner* one, making the test always true.
    let own_col = format!("\"{own_table}\".\"{}\"", column.replace('"', "\"\""));

    match source {
        MembershipSource::Claim { path } => format!(
            "EXISTS (SELECT 1 FROM jsonb_array_elements_text(\
             COALESCE(auth.claim({}), '[]'::jsonb)) AS claim_value \
             WHERE claim_value = {own_col}::text)",
            quote_literal(path)
        ),

        MembershipSource::Literal { values } => {
            if values.is_empty() {
                // An empty set matches nothing. Emitted as FALSE rather than
                // `= ANY(ARRAY[])`, which Postgres cannot type.
                return "FALSE".to_string();
            }
            let items = values
                .iter()
                .map(literal_to_sql)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{own_col} = ANY(ARRAY[{items}])")
        }

        MembershipSource::Rows {
            table,
            column: source_column,
            filter,
        } => {
            let table_esc = table.replace('"', "\"\"");
            let col_esc = source_column.replace('"', "\"\"");
            // Schema-qualified so the source is unambiguously the real table.
            // Inside a `can_*` function the row is a derived table aliased with the
            // model's own name, and a self-referential membership
            // (`In<"parent_id", Rows<"posts", "id", …>>`) would otherwise resolve
            // `FROM "posts"` to that single row instead of the table, quietly
            // answering about one row when it should have searched all of them.
            let mut sql = format!(
                "EXISTS (SELECT 1 FROM \"{schema}\".\"{table_esc}\" \
                 WHERE \"{table_esc}\".\"{col_esc}\" = {own_col}"
            );
            if let Some(rule) = filter {
                // The filter is evaluated against the *source* table, so resolve
                // its columns there rather than against the model the policy is
                // attached to.
                let inner_model = ast.models.iter().find(|m| db_table_name(m) == table);
                let inner_expr = match inner_model {
                    Some(m) => access_rule_to_expr(ast, m, rule, schema),
                    None => access_rule_to_expr(ast, model, rule, schema),
                };
                sql.push_str(&format!(
                    " AND ({})",
                    qualify_bare_columns(&inner_expr, table)
                ));
            }
            sql.push(')');
            sql
        }
    }
}

/// Qualifies unqualified quoted columns in a subquery predicate with its table.
///
/// A filter like `Eq<"user_id", AuthUid>` renders as `"user_id" = …`, which inside
/// the subquery would resolve against whichever table happens to have that column
/// and if both do, silently against the wrong one. Only already-unqualified
/// references are touched, so an explicit `"other"."col"` is left alone.
fn qualify_bare_columns(expr: &str, table: &str) -> String {
    let table_esc = table.replace('"', "\"\"");
    let mut out = String::with_capacity(expr.len());
    let mut rest = expr;

    while let Some(start) = rest.find('"') {
        out.push_str(&rest[..start]);
        let after_open = &rest[start + 1..];
        let Some(end) = after_open.find('"') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let ident = &after_open[..end];
        let tail = &after_open[end + 1..];

        // Already qualified (`"t"."c"`) if a dot follows, or if a dot preceded.
        let preceded_by_dot = out.ends_with('.');
        let followed_by_dot = tail.starts_with('.');
        // A quoted identifier straight after FROM or JOIN is a *table*, not a
        // column. Qualifying it produced `"categories"."posts"`, which Postgres
        // read as a schema-qualified relation that does not exist, so every
        // membership rule broke the moment its expression was reused here.
        let in_table_position = matches!(
            last_word(&out).to_ascii_uppercase().as_str(),
            "FROM" | "JOIN" | "INTO" | "UPDATE"
        );

        if preceded_by_dot || followed_by_dot || in_table_position {
            out.push('"');
            out.push_str(ident);
            out.push('"');
        } else {
            out.push_str(&format!("\"{table_esc}\".\"{ident}\""));
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// The last whitespace-delimited word emitted so far, for deciding whether the
/// identifier about to be written sits in table position.
fn last_word(out: &str) -> &str {
    let trimmed = out.trim_end();
    match trimmed.rfind(|c: char| c.is_whitespace() || c == '(') {
        Some(i) => &trimmed[i + 1..],
        None => trimmed,
    }
}

fn literal_to_sql(value: &LiteralValue) -> String {
    match value {
        LiteralValue::Bool(b) => if *b { "TRUE" } else { "FALSE" }.to_string(),
        LiteralValue::Number(n) => format!("{n:?}").trim_end_matches(".0").to_string(),
        LiteralValue::Text(t) => quote_literal(t),
    }
}

/// Columns a `Rows<>` source joins on, as `(table, column)` pairs.
///
/// The DSL names the join columns, so the classic RLS performance footgun (a
/// membership subquery scanning an unindexed join table for every row tested)
/// becomes generated infrastructure instead of something the developer has to
/// know about.
pub fn membership_index_targets(rule: &AccessRule) -> Vec<(String, String)> {
    let mut out = Vec::new();
    collect_membership_targets(rule, &mut out);
    out
}

fn collect_membership_targets(rule: &AccessRule, out: &mut Vec<(String, String)>) {
    match rule {
        AccessRule::In {
            source:
                MembershipSource::Rows {
                    table,
                    column,
                    filter,
                },
            ..
        } => {
            let pair = (table.clone(), column.clone());
            if !out.contains(&pair) {
                out.push(pair);
            }
            if let Some(inner) = filter {
                collect_membership_targets(inner, out);
            }
        }
        AccessRule::Any { rules } | AccessRule::All { rules } => {
            for r in rules {
                collect_membership_targets(r, out);
            }
        }
        AccessRule::Not { rule } => collect_membership_targets(rule, out),
        _ => {}
    }
}

/// `CREATE INDEX IF NOT EXISTS` for each join column a rule reads.
pub fn membership_index_sql(schema: &str, rule: &AccessRule) -> String {
    let mut sql = String::new();
    for (table, column) in membership_index_targets(rule) {
        let index = format!("idx_{table}_{column}_rls");
        let t = table.replace('"', "\"\"");
        let c = column.replace('"', "\"\"");
        sql.push_str(&format!(
            "CREATE INDEX IF NOT EXISTS \"{index}\" ON \"{schema}\".\"{t}\" (\"{c}\");\n"
        ));
    }
    sql
}

/// Joins composed rules, parenthesising any child that is itself a composition.
///
/// Without the parentheses `Any<[a, All<[b, c]>]>` would render as `a OR b AND c`,
/// which Postgres reads as `a OR (b AND c)`: correct by luck here, and wrong the
/// moment the nesting is the other way round. Precedence is never left to chance.
fn join_rules(
    ast: &SchemaAst,
    model: &ModelAst,
    rules: &[AccessRule],
    joiner: &str,
    schema: &str,
) -> String {
    let parts: Vec<String> = rules
        .iter()
        .map(|r| {
            let expr = access_rule_to_expr(ast, model, r, schema);
            if matches!(r, AccessRule::Any { .. } | AccessRule::All { .. }) {
                format!("({expr})")
            } else {
                expr
            }
        })
        .collect();
    parts.join(&format!("\n    {joiner}\n    "))
}

/// The bare SQL for a time base, without the scalar-subquery wrapper.
///
/// `After`/`Before` wrap the whole expression once rather than nesting a subquery inside
/// another: `(SELECT (SELECT now()) + INTERVAL '...')` is valid but gives the differ a
/// second shape to normalise for no gain.
///
/// Returns `None` for anything that is not a time base. Validation refuses those before
/// a policy is built, so the fallback in the caller is a backstop for an AST that did not
/// come through it, not a supported shape.
fn time_base_expr(operand: &Operand) -> Option<String> {
    match operand {
        Operand::Now => Some("now()".to_string()),
        Operand::StartOf { unit } => Some(format!("date_trunc('{}', now())", unit.sql())),
        _ => None,
    }
}

/// The text inside `INTERVAL '...'`, built from the spec's integers.
///
/// No author-supplied text reaches Postgres: every amount is a parsed integer and every
/// unit a keyword from the closed set, which is what keeps this from being a small
/// escape hatch. Components are emitted largest unit first so one spec always produces
/// one string.
///
/// An empty spec renders `0 seconds` rather than an empty literal. `INTERVAL ''` is a
/// syntax error, and emitting nothing at all would silently turn the operand into a bare
/// `now()`. Validation refuses an all-zero spec so the author hears about it; this keeps
/// the generated SQL honest and valid if one ever reaches here.
fn interval_literal(spec: &IntervalSpec) -> String {
    let components = spec.components();
    if components.is_empty() {
        return "0 seconds".to_string();
    }
    components
        .into_iter()
        .map(|(amount, unit)| format!("{amount} {}", unit.sql()))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Renders one side of a comparison.
/// Also used by the seed executor, so a seed and a policy cannot disagree about what an
/// operand means: `fromNow` renders once, here.
pub(crate) fn operand_to_expr(operand: &Operand) -> String {
    match operand {
        // Constraint-only operands, refused inside `access` by the CLI. Rendered so the match stays
        // exhaustive; a policy that reached one would be comparing against a measure, not a caller.
        Operand::Length { column, form } | Operand::ItemCount { column, form } => {
            crate::generator::sql::constraints::measure_expr(column, *form)
        }
        Operand::Column { name } => format!("\"{}\"", name.replace('"', "\"\"")),
        Operand::AuthUid => AUTH_UID.to_string(),
        Operand::AuthRole => AUTH_ROLE.to_string(),
        // Text, so it compares against a column or a string literal. A claim used
        // as a *set* goes through the membership path instead, which needs the
        // jsonb form.
        Operand::Claim { path } => format!("auth.claim_text({})", quote_literal(path)),
        Operand::Literal { value } => literal_to_sql(value),

        // Each temporal operand is one scalar subquery, so the planner evaluates it
        // once per query as an InitPlan rather than per row, the same reason
        // `auth.uid()` is wrapped.
        Operand::Now => "(SELECT now())".to_string(),
        Operand::StartOf { unit } => {
            format!("(SELECT date_trunc('{}', now()))", unit.sql())
        }
        // The interval is assembled from a parsed integer and a keyword from the
        // closed unit set. No author-supplied text reaches Postgres here, which is
        // what keeps this from being a small escape hatch.
        Operand::Ago { amount, unit } => {
            format!("(SELECT now() - INTERVAL '{amount} {}')", unit.sql())
        }
        Operand::FromNow { amount, unit } => {
            format!("(SELECT now() + INTERVAL '{amount} {}')", unit.sql())
        }
        // The base is rendered unwrapped and the whole expression wrapped once. The
        // fallback covers a base validation should already have refused.
        Operand::After { base, interval } => {
            let rendered = time_base_expr(base).unwrap_or_else(|| operand_to_expr(base));
            format!(
                "(SELECT {rendered} + INTERVAL '{}')",
                interval_literal(interval)
            )
        }
        Operand::Before { base, interval } => {
            let rendered = time_base_expr(base).unwrap_or_else(|| operand_to_expr(base));
            format!(
                "(SELECT {rendered} - INTERVAL '{}')",
                interval_literal(interval)
            )
        }
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

/// Owner / OwnerFrom: compare auth.uid() to a row column or ownership via a related model.
/// Quotes a column so it is unambiguous as an identifier.
///
/// Also what lets `qualify_bare_columns` find these references when the same
/// expression is reused inside a `can_*` function, where a bare column has no
/// `FROM` clause to resolve against. Quoting changes no meaning and the differ's
/// normaliser strips quotes, so no policy is recreated for it.
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn owner_access_expr(ast: &SchemaAst, model: &ModelAst, kernel_field: &str) -> String {
    if kernel_field == "id" {
        return format!("{AUTH_UID} = {}", quote_ident("id"));
    }

    if let Some((field_name, field)) = model.fields.get_key_value(kernel_field) {
        if let FieldAst::Relation(rel) = field {
            let fk = db_foreign_key(field, field_name).unwrap_or_else(|| {
                crate::parser::accessors::default_foreign_key_column(field_name)
            });

            if let Some(target) = ast.models.iter().find(|m| m.name == rel.target) {
                if is_user_identity_model(target) {
                    return format!("{AUTH_UID} = {}", quote_ident(&fk));
                }
                if let Some(owner_col) = owner_column_on_model(target) {
                    let table = db_table_name(target);
                    return format!(
                        "EXISTS (SELECT 1 FROM \"{table}\" WHERE \"{table}\".\"id\" = {fk_q} AND {AUTH_UID} = \"{table}\".\"{owner_col}\")",
                        fk_q = quote_ident(&fk)
                    );
                }
            }

            return format!("{AUTH_UID} = {}", quote_ident(&fk));
        }

        let column = resolve_owner_column(model, kernel_field);
        return format!("{AUTH_UID} = {}", quote_ident(&column));
    }

    let column = resolve_owner_column(model, kernel_field);
    format!("{AUTH_UID} = {}", quote_ident(&column))
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

// ─── Row-level affordances ───────────────────────────────────────────────────

/// `can_<op>_<table>(row) RETURNS boolean` for every operation a model declares.
///
/// Studio needs to know, per row, whether the delete button should be enabled.
/// The alternatives are all worse: a client-side SQL interpreter is a second
/// implementation of the rules that drifts from the enforced one; a round trip per
/// row does not scale; and an "unknown" state pushes the problem into the UI.
///
/// These functions are the answer, generated from the same AST as the policies, so
/// there is exactly one definition of what access means. PostgREST exposes them as
/// computed columns (`?select=*,can_delete_posts`) so Studio gets the affordance
/// from the query it was already running, with no extra request and no per-row call
/// from the client. They are also what `explain` and hand-written queries use.
///
/// The parameter is named after the table so the policy expression can be reused
/// verbatim: inside the body `posts.author_id` resolves against the composite
/// argument. Bare column references are qualified for the same reason: a function
/// body has no `FROM` clause for them to resolve against.
pub fn generate_can_functions(ast: &SchemaAst, schema: &str) -> String {
    let mut out = String::new();

    for model in &ast.models {
        let access = platform_access(model);
        let table = db_table_name(model);

        for (op, rule) in [
            ("read", access.read.as_ref()),
            ("create", access.create.as_ref()),
            ("update", access.update.as_ref()),
            ("delete", access.delete.as_ref()),
        ] {
            let Some(rule) = rule else {
                // An operation with no rule is denied, and a function that always
                // returns false is more useful to a UI than a missing one it has to
                // special-case.
                out.push_str(&render_can_function(schema, table, op, "FALSE"));
                continue;
            };

            // The expression is used exactly as the policy uses it. The function
            // body supplies a scope its column references resolve against, so
            // nothing has to be rewritten, which is what lets a `Custom` rule's
            // raw SQL answer definitively rather than "unknown".
            let expr = access_rule_to_expr(ast, model, rule, schema);
            out.push_str(&render_can_function(schema, table, op, &expr));
        }

        out.push_str(&render_field_can_functions(ast, model, schema, table));
    }

    out
}

/// Per-column affordance functions, one pair per field rule.
///
/// These are the functions the masking rewrite calls: `can_read_posts__salary(posts)`
/// decides whether a caller sees the column at all, `can_write_posts__salary(posts)`
/// whether they may change it. Studio calls the same functions to decide whether to
/// render a value, a lock, or a disabled input, so what the UI shows and what the
/// database enforces are one expression rather than two that drift.
///
/// **Write implies read, by construction.** The write body is conjoined with the read
/// rule rather than checked against it: "does this write rule imply this read rule" is
/// an implication between two arbitrary predicates and is not decidable in general.
/// Conjoining makes write-without-read unrepresentable, which in turn removes the
/// hazard that a caller who owns a row can hold write permission on a column they
/// cannot see -- round-tripping a value they were never shown and destroying it.
fn render_field_can_functions(
    ast: &SchemaAst,
    model: &ModelAst,
    schema: &str,
    table: &str,
) -> String {
    let mut out = String::new();

    for (column, rules) in &platform_access(model).fields {
        let read_expr = rules
            .read
            .as_ref()
            .map(|rule| access_rule_to_expr(ast, model, rule, schema));

        // No `read` rule means the column is as readable as the table, so the
        // affordance is unconditionally true rather than absent -- a UI should never
        // have to distinguish "allowed" from "no function".
        out.push_str(&render_field_can_function(
            schema,
            table,
            "read",
            column,
            read_expr.as_deref().unwrap_or("TRUE"),
        ));

        if let Some(rule) = rules.write.as_ref() {
            let write_expr = access_rule_to_expr(ast, model, rule, schema);
            let conjoined = match read_expr.as_deref() {
                Some(read) => format!("({write_expr}) AND ({read})"),
                None => write_expr,
            };
            out.push_str(&render_field_can_function(
                schema, table, "write", column, &conjoined,
            ));
        }
    }

    out
}

/// `can_<op>_<table>__<column>`.
///
/// Double underscore between table and column so a table named `posts_salary`
/// cannot collide with column `salary` of table `posts`.
fn render_field_can_function(
    schema: &str,
    table: &str,
    op: &str,
    column: &str,
    expr: &str,
) -> String {
    let name = format!("can_{op}_{table}__{column}");
    let alias = table.replace('"', "\"\"");
    format!(
        "CREATE OR REPLACE FUNCTION \"{schema}\".\"{name}\"(\"{table}\" \"{schema}\".\"{table}\")
           RETURNS boolean LANGUAGE sql STABLE AS $can$
             SELECT {expr}
               FROM (SELECT ($1).*) AS \"{alias}\";
           $can$;

"
    )
}

// ─── Field-level enforcement: security labels ────────────────────────────────

/// The extension that enforces field rules, and the label provider it registers.
pub const MASK_EXTENSION: &str = "supatype_mask";
pub const MASK_PROVIDER: &str = "supatype";

/// A qualified, quoted reference to a generated per-column predicate.
fn field_predicate_ref(schema: &str, op: &str, table: &str, column: &str) -> String {
    format!(
        "{schema}.\"can_{op}_{t}__{c}\"",
        t = table.replace('"', "\"\""),
        c = column.replace('"', "\"\"")
    )
}

/// `SECURITY LABEL FOR supatype` per field rule: what makes a `fields` rule actually
/// enforced rather than merely described.
///
/// The label points the extension at the predicates [`generate_can_functions`] already
/// emits, so the rule language stays here in Rust and the extension stays a rewrite.
/// `pg_dump` carries security labels, so a masked column stays masked across a
/// dump/restore without a push.
///
/// **A read rule is named only when one exists.** A `write`-only rule leaves reads
/// unrestricted, and labelling it with a trivially-true `READ` predicate would cost a
/// function call per row per read to answer a question nobody asked. The `can_read_*`
/// function is still generated (Studio wants a uniform affordance surface); it just
/// does not appear in the label.
/// `skip` names tables the schema declares but Supatype did not create; see
/// [`crate::differ::DiffOutput::unmanaged_model_tables`]. A `SECURITY LABEL` on their column is a
/// change to their table.
pub fn generate_security_labels(ast: &SchemaAst, schema: &str, skip: &[String]) -> String {
    let mut statements: Vec<String> = Vec::new();
    let mut keep: Vec<String> = Vec::new();

    for model in &ast.models {
        let table = db_table_name(model);
        if skip.iter().any(|t| t == table) {
            continue;
        }

        for (column, rules) in &platform_access(model).fields {
            let mut parts: Vec<String> = Vec::new();

            if rules.read.is_some() {
                parts.push(format!(
                    "READ {}",
                    field_predicate_ref(schema, "read", table, column)
                ));
            }
            if rules.write.is_some() {
                parts.push(format!(
                    "WRITE {}",
                    field_predicate_ref(schema, "write", table, column)
                ));
            }
            if parts.is_empty() {
                continue;
            }

            keep.push(format!("({}, {})", sql_string(table), sql_string(column)));
            statements.push(format!(
                "SECURITY LABEL FOR {MASK_PROVIDER} ON COLUMN \"{schema}\".\"{t}\".\"{c}\"\n  \
                 IS 'MASK {body}';",
                t = table.replace('"', "\"\""),
                c = column.replace('"', "\"\""),
                body = parts.join(" ")
            ));
        }
    }

    let mut out = String::new();

    // Refusing the push is the third tier in the field-access plan, and the only honest
    // answer: a schema that declares a column masked, applied to a database that cannot
    // mask it, is a database whose security posture silently differs from its source.
    // Never silently unmask.
    if !statements.is_empty() {
        out.push_str(&format!(
            "DO $mask_probe$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = '{MASK_EXTENSION}') THEN
    RAISE EXCEPTION 'field-level access requires the {MASK_EXTENSION} extension'
      USING ERRCODE = 'feature_not_supported',
            DETAIL  = '{n} column rule(s) in this schema would not be enforced.',
            HINT    = 'Use the supatype/postgres image, or: add {MASK_EXTENSION} to shared_preload_libraries, restart, then CREATE EXTENSION {MASK_EXTENSION};';
  END IF;
END
$mask_probe$;

",
            n = statements.len()
        ));
    }

    // Proof that the privilege those predicates need actually landed. The grant itself is in the
    // preamble, emitted on every push, so this no longer re-issues it: a grant can be a silent
    // no-op (see `render_auth_usage_probe`), and checking is the half worth doing twice.
    if !statements.is_empty() {
        out.push_str(&render_auth_usage_probe(statements.len()));
    }

    out.push_str(&render_stale_label_clear(&keep, schema));

    for statement in &statements {
        out.push_str(statement);
        out.push_str("\n\n");
    }

    out
}

/// Proof that the masking predicates can actually run, rather than a hope that they can.
///
/// [`grant_auth_schema_usage`] may have been a no-op: a role that does not own the schema cannot
/// grant on it, and Postgres reports that as `WARNING: no privileges were granted`, not an error.
/// So the grant alone proves nothing. Without this check a push to a database whose `auth` schema
/// belongs to another role reports success, and then every authenticated read of a masked column
/// fails with `42501 permission denied for schema auth`, the same class of fault as a privilege
/// that is generated and never applied.
///
/// Refuses rather than degrades, matching the extension probe: a schema that declares a masked
/// column, applied where the mask cannot be evaluated, is a database whose security posture
/// silently differs from its source.
fn render_auth_usage_probe(rule_count: usize) -> String {
    let roles = API_ROLES.join(", ");
    format!(
        r#"DO $auth_usage_probe$
DECLARE
  owner text;
BEGIN
  SELECT pg_get_userbyid(nspowner) INTO owner
    FROM pg_namespace WHERE nspname = '{AUTH_SCHEMA}';

  -- No auth schema: the field predicates could not have been created either, and the extension
  -- probe has already had its say about capability.
  IF owner IS NULL THEN
    RETURN;
  END IF;

  -- has_schema_privilege raises on an unknown role, so ask whether the role exists first. A
  -- database with no `authenticated` role has no authenticated caller to break.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    RETURN;
  END IF;

  IF NOT has_schema_privilege('authenticated', '{AUTH_SCHEMA}', 'USAGE') THEN
    RAISE EXCEPTION 'field-level access requires USAGE on schema {AUTH_SCHEMA}'
      USING ERRCODE = 'feature_not_supported',
            DETAIL  = format('%s column rule(s) would raise 42501 for every authenticated caller.',
                             {rule_count}),
            HINT    = format('Schema {AUTH_SCHEMA} is owned by %s, so this push could not grant on it. As that role: GRANT USAGE ON SCHEMA {AUTH_SCHEMA} TO {roles};',
                             owner);
  END IF;
END
$auth_usage_probe$;

"#
    )
}

/// Drop every label this push does not re-assert, so removing a field rule stops the
/// masking rather than leaving a column masked by a rule that no longer exists.
///
/// **Every label under our provider is ours.** Policies need a managed-object marker
/// because `pg_policy` is a shared namespace where a developer's hand-written policy has
/// to survive a push; a security label provider is a namespace this extension owns
/// outright, so there is no hand-written label under `supatype` to protect. Labels under
/// any other provider, and in any other schema, are untouched.
///
/// Emitted even when the schema has no field rules at all: that is exactly the case
/// where the last rule was just removed. Guarded on the extension existing, because
/// without the provider registered a `SECURITY LABEL` statement cannot even parse; and
/// without the provider there can be no labels to clear.
fn render_stale_label_clear(keep: &[String], schema: &str) -> String {
    let exclusion = if keep.is_empty() {
        String::new()
    } else {
        format!(
            "
         AND (c.relname, a.attname) NOT IN ({})",
            keep.join(", ")
        )
    };

    format!(
        "DO $mask_clear$
DECLARE
  stale record;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = '{MASK_EXTENSION}') THEN
    RETURN;
  END IF;

  FOR stale IN
    SELECT c.relname AS tbl, a.attname AS col
      FROM pg_seclabel l
      JOIN pg_class c ON c.oid = l.objoid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN pg_attribute a ON a.attrelid = l.objoid AND a.attnum = l.objsubid
     WHERE l.provider = '{MASK_PROVIDER}'
       AND l.classoid = 'pg_class'::regclass
       AND n.nspname = '{schema}'{exclusion}
  LOOP
    EXECUTE format('SECURITY LABEL FOR {MASK_PROVIDER} ON COLUMN %I.%I.%I IS NULL',
                   '{schema}', stale.tbl, stale.col);
  END LOOP;
END
$mask_clear$;

"
    )
}

fn sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// The row is expanded into a one-row derived table aliased with the table's own
/// name, so the policy expression works unchanged inside the function body.
///
/// This is why no rewriting of the expression is needed. Every reference resolves
/// the way it does in the policy: a bare `title` against the derived table, a
/// qualified `"posts"."site_id"` against the same alias. That includes the raw SQL
/// of a `Custom` rule, whose identifiers cannot be rewritten because there is no
/// way to know which of them are columns; the earlier approach rewrote the
/// expression instead and so had to answer "unknown" for those, which is precisely
/// the state these functions exist to eliminate.
fn render_can_function(schema: &str, table: &str, op: &str, expr: &str) -> String {
    let name = format!("can_{op}_{table}");
    let alias = table.replace('"', "\"\"");
    format!(
        "CREATE OR REPLACE FUNCTION \"{schema}\".\"{name}\"(\"{table}\" \"{schema}\".\"{table}\")\n  \
         RETURNS boolean LANGUAGE sql STABLE AS $can$\n    \
         SELECT {expr}\n      \
         FROM (SELECT ($1).*) AS \"{alias}\";\n  \
         $can$;\n\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ast::TruncUnit;

    #[test]
    fn after_now_renders_a_wrapped_addition() {
        let operand = Operand::After {
            base: Box::new(Operand::Now),
            interval: IntervalSpec {
                days: 30,
                ..IntervalSpec::default()
            },
        };
        assert_eq!(
            operand_to_expr(&operand),
            "(SELECT now() + INTERVAL '30 days')"
        );
    }

    #[test]
    fn before_now_renders_a_wrapped_subtraction() {
        let operand = Operand::Before {
            base: Box::new(Operand::Now),
            interval: IntervalSpec {
                days: 30,
                ..IntervalSpec::default()
            },
        };
        assert_eq!(
            operand_to_expr(&operand),
            "(SELECT now() - INTERVAL '30 days')"
        );
    }

    // The composition the single-unit operands could not express.
    #[test]
    fn after_a_truncation_base_composes_date_trunc_with_a_multi_unit_interval() {
        let operand = Operand::After {
            base: Box::new(Operand::StartOf {
                unit: TruncUnit::Day,
            }),
            interval: IntervalSpec {
                days: 30,
                hours: 9,
                ..IntervalSpec::default()
            },
        };
        assert_eq!(
            operand_to_expr(&operand),
            "(SELECT date_trunc('day', now()) + INTERVAL '30 days 9 hours')"
        );
    }

    // One subquery, not two. Nesting is valid SQL but hands the differ a second shape
    // to normalise for nothing.
    #[test]
    fn after_does_not_nest_a_subquery_inside_another() {
        let operand = Operand::After {
            base: Box::new(Operand::Now),
            interval: IntervalSpec {
                hours: 1,
                ..IntervalSpec::default()
            },
        };
        let rendered = operand_to_expr(&operand);
        assert_eq!(
            rendered.matches("SELECT").count(),
            1,
            "expected exactly one subquery, got: {rendered}"
        );
    }

    // Largest unit first, and always the same text for the same spec, so a policy does
    // not change shape because a field order did.
    #[test]
    fn interval_components_render_largest_unit_first() {
        let spec = IntervalSpec {
            seconds: 7,
            years: 1,
            days: 3,
            ..IntervalSpec::default()
        };
        assert_eq!(interval_literal(&spec), "1 years 3 days 7 seconds");
    }

    // An empty spec must not render `INTERVAL ''`, which is a syntax error, nor vanish
    // into a bare `now()`, which would silently mean something else. Validation refuses
    // it upstream; this keeps the generated SQL valid and honest if one reaches here.
    #[test]
    fn an_empty_interval_renders_zero_rather_than_nothing() {
        assert_eq!(interval_literal(&IntervalSpec::default()), "0 seconds");
    }

    #[test]
    fn an_empty_interval_spec_is_zero() {
        assert!(IntervalSpec::default().is_zero());
        assert!(!IntervalSpec {
            seconds: 1,
            ..IntervalSpec::default()
        }
        .is_zero());
    }

    // The clock stays STABLE. `clock_timestamp()` is VOLATILE and would make the
    // generated `can_*` functions' STABLE declaration a lie.
    #[test]
    fn after_never_reaches_for_a_volatile_clock() {
        let operand = Operand::After {
            base: Box::new(Operand::StartOf {
                unit: TruncUnit::Week,
            }),
            interval: IntervalSpec {
                days: 2,
                ..IntervalSpec::default()
            },
        };
        assert!(!operand_to_expr(&operand).contains("clock_timestamp"));
    }
}
