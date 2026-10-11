use crate::generator::sql::auth_functions::{API_ROLES, AUTH_SCHEMA, CLAIMS_SCHEMA};
use crate::parser::accessors::{db_table_name, platform_access, resolve_owner_column};
use crate::parser::ast::{
    AccessRule, DefaultValueAst, FieldAst, IntervalSpec, LiteralValue, MembershipSource, ModelAst,
    Operand, SchemaAst,
};
use crate::sql_quote::{comment_text, quote_ident, quote_literal, quote_qualified};
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
        let target = quote_qualified(schema, table);

        out.push_str(&format!(
            "-- RLS Policies for: {}\n-- Generated from schema access rules\n\n",
            comment_text(&model.name)
        ));

        out.push_str(&format!(
            "ALTER TABLE {target} ENABLE ROW LEVEL SECURITY;\n"
        ));
        out.push_str(&format!(
            "ALTER TABLE {target} FORCE ROW LEVEL SECURITY;\n\n"
        ));

        // A script of its own, so each policy is dropped before it is made and the script can run
        // twice. A push does not use it: there the reconcile drops and creates.
        let drop = |suffix: &str| {
            format!(
                "DROP POLICY IF EXISTS {} ON {target};\n",
                quote_ident(&format!("{table}_{suffix}"))
            )
        };
        if let Some(rule) = &access.read {
            out.push_str(&drop("select"));
            out.push_str(&render_select_policy_sql(schema, table, ast, model, rule));
        }
        if let Some(rule) = &access.create {
            out.push_str(&drop("insert"));
            out.push_str(&render_insert_policy_sql(schema, table, ast, model, rule));
        }
        if let Some(rule) = &access.update {
            out.push_str(&drop("update"));
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
            out.push_str(&drop("delete"));
            out.push_str(&render_delete_policy_sql(schema, table, ast, model, rule));
        }
    }

    Ok(out)
}

/// SQL DDL for the claim readers a policy calls, and the `auth.*` aliases of them.
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

    // `auth.roles()` has no reader of its own and is referenced by hand-written policies, so it
    // stays here rather than disappearing. It reads the claims through the guarded reader: its own
    // cast raised `22P02` on an empty claims setting instead of answering an empty array.
    sql.push_str(&format!(
        r#"

-- auth.roles(): the `roles` claim as a text array.
CREATE OR REPLACE FUNCTION auth.roles() RETURNS text[]
  LANGUAGE sql STABLE AS $$
    SELECT ARRAY(
      SELECT jsonb_array_elements_text(
        COALESCE({CLAIMS_SCHEMA}.jwt_claims() -> 'roles', '[]'::jsonb)
      )
    );
  $$;

"#
    ));
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
        other => return format!("-- unknown RLS policy suffix: {}\n", comment_text(other)),
    };

    // The `CREATE POLICY` alone. Which policies are ours is the ledger's record (Phase 4.7b), not
    // a comment, and the reconcile drops a policy before making it again. The membership indexes
    // a rule's join columns need are the reconcile's too (Phase 4.3).
    sql.trim_end().to_string()
}

/// `CREATE POLICY "<table>_<suffix>" ON "<schema>"."<table>"`, the head every model policy shares.
fn policy_head(schema: &str, table: &str, suffix: &str) -> String {
    format!(
        "CREATE POLICY {} ON {}",
        quote_ident(&crate::managed::policy_name(table, suffix)),
        quote_qualified(schema, table)
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
    let head = policy_head(schema, table, "select");
    format!("{head}\nFOR SELECT USING (\n    {expr}\n  );\n\n")
}

pub(crate) fn render_insert_policy_sql(
    schema: &str,
    table: &str,
    ast: &SchemaAst,
    model: &ModelAst,
    rule: &AccessRule,
) -> String {
    let expr = access_rule_to_expr(ast, model, rule, schema);
    let head = policy_head(schema, table, "insert");
    format!("{head}\nFOR INSERT WITH CHECK (\n    {expr}\n  );\n\n")
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
    let head = policy_head(schema, table, "update");
    format!(
        "{head}\nFOR UPDATE USING (\n    {using_expr}\n  ) WITH CHECK (\n    {check_expr}\n  );\n\n"
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
    let head = policy_head(schema, table, "delete");
    format!("{head}\nFOR DELETE USING (\n    {expr}\n  );\n\n")
}

/// The suffix of the policy admitting `service_role` to a tier 2 table.
pub const SERVICE_ROLE_POLICY: &str = "service_role";

/// Under tier 2, the permissive policy that lets `service_role` reach every row through the `api`
/// views (F13). The views run as their owner, which does not bypass row-level security, so
/// `service_role` would otherwise see only the rows its rules happen to allow it, where tier 1 and
/// every other channel give it all of them. Reachable only through the views: the API roles hold
/// nothing on the base table.
pub fn service_role_policy_sql(schema: &str, table: &str) -> String {
    let admitted = format!("{AUTH_ROLE} = 'service_role'");
    format!(
        "{}\nAS PERMISSIVE FOR ALL USING (\n    {admitted}\n  ) WITH CHECK (\n    {admitted}\n  );",
        policy_head(schema, table, SERVICE_ROLE_POLICY)
    )
}

/// The caller's user id, wrapped so Postgres evaluates it once per query, not once per row.
///
/// A bare function call in a policy is re-evaluated for every row the planner
/// tests, because the function reference sits inside a per-row filter. Wrapping it
/// in a scalar subquery makes the planner treat it as an InitPlan: computed once,
/// then compared as a constant. On a table of any size this is the difference
/// between a policy that scales and one that does not, and it costs nothing.
///
/// The engine's own reader, never `auth.uid()`: the auth server's migrations replace that one
/// (see `auth_functions`), and a generated rule must not change meaning when they do.
pub const AUTH_UID: &str = "(SELECT _supatype.jwt_uid())";

/// Default schema for policies, affordance functions and grants.
///
/// A fallback, not the answer: the generators here take the managed schema as a parameter. This
/// covers callers with genuinely nothing to pass, an introspected `DatabaseState` whose `schema` is
/// empty, for instance.
pub const DEFAULT_POLICY_SCHEMA: &str = "public";

/// The caller's application role, wrapped and read through the engine's own reader for the same
/// reasons as [`AUTH_UID`].
pub const AUTH_ROLE: &str = "(SELECT _supatype.jwt_role())";

/// A nested claim as `jsonb`, through the engine's own reader.
fn claim_json(path: &str) -> String {
    format!("{CLAIMS_SCHEMA}.jwt_claim({})", quote_literal(path))
}

/// `subject` equals one of `roles`: the check a `Role<...>` rule compiles to, for a model's policies
/// and a bucket's alike.
///
/// Each role is a literal. A role is a name the schema declares, and one holding a quote must
/// still compare as that name rather than end the string and add terms to the policy.
pub(crate) fn role_matches(subject: &str, roles: &[String]) -> String {
    match roles {
        [role] => format!("{subject} = {}", quote_literal(role)),
        _ => {
            let arr = roles
                .iter()
                .map(|r| quote_literal(r))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{subject} = ANY(ARRAY[{arr}])")
        }
    }
}

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
        AccessRule::Role { roles } => role_matches(AUTH_ROLE, roles),
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
             COALESCE({}, '[]'::jsonb)))",
            claim_json(path)
        ),

        // A fixed set's emptiness is known at generation time, so it folds to a
        // constant rather than asking the database a question with one answer.
        MembershipSource::Literal { values } => {
            if values.is_empty() { "FALSE" } else { "TRUE" }.to_string()
        }

        MembershipSource::Rows { table, filter, .. } => {
            let mut sql = format!("EXISTS (SELECT 1 FROM {}", quote_qualified(schema, table));
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
    let own_col = format!("{}.{}", quote_ident(own_table), quote_ident(column));

    match source {
        MembershipSource::Claim { path } => format!(
            "EXISTS (SELECT 1 FROM jsonb_array_elements_text(\
             COALESCE({}, '[]'::jsonb)) AS claim_value \
             WHERE claim_value = {own_col}::text)",
            claim_json(path)
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
            // Schema-qualified so the source is unambiguously the real table.
            // Inside a `can_*` function the row is a derived table aliased with the
            // model's own name, and a self-referential membership
            // (`In<"parent_id", Rows<"posts", "id", …>>`) would otherwise resolve
            // `FROM "posts"` to that single row instead of the table, quietly
            // answering about one row when it should have searched all of them.
            let mut sql = format!(
                "EXISTS (SELECT 1 FROM {} WHERE {}.{} = {own_col}",
                quote_qualified(schema, table),
                quote_ident(table),
                quote_ident(source_column)
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
    let qualifier = quote_ident(table);
    let mut out = String::with_capacity(expr.len());
    let mut rest = expr;

    while let Some(start) = rest.find(['"', '\'']) {
        out.push_str(&rest[..start]);
        let (token, tail) = split_quoted(&rest[start..]);
        rest = tail;

        // A string literal is a value, never a column, whatever it contains, and an unterminated
        // token is left exactly as it was written.
        let is_identifier = token.starts_with('"') && token.len() > 1 && token.ends_with('"');
        // Already qualified (`"t"."c"`) if a dot follows, or if a dot preceded.
        let qualified = out.ends_with('.') || tail.starts_with('.');
        // A quoted identifier straight after FROM or JOIN is a *table*, not a
        // column. Qualifying it produced `"categories"."posts"`, which Postgres
        // read as a schema-qualified relation that does not exist, so every
        // membership rule broke the moment its expression was reused here.
        let in_table_position = matches!(
            last_word(&out).to_ascii_uppercase().as_str(),
            "FROM" | "JOIN" | "INTO" | "UPDATE"
        );

        if is_identifier && !qualified && !in_table_position {
            out.push_str(&qualifier);
            out.push('.');
        }
        out.push_str(token);
    }
    out.push_str(rest);
    out
}

/// Splits the quoted token at the front of `s` (an identifier in `"`, a literal in `'`) from what
/// follows it. A doubled quote character is part of the token, as Postgres reads it: `"a""b"` is one
/// identifier and `'it''s'` one literal. An unterminated token runs to the end of `s`.
fn split_quoted(s: &str) -> (&str, &str) {
    let bytes = s.as_bytes();
    let quote = bytes[0];
    let mut i = 1;
    while i < bytes.len() {
        if bytes[i] == quote {
            if bytes.get(i + 1) == Some(&quote) {
                i += 2;
                continue;
            }
            return s.split_at(i + 1);
        }
        i += 1;
    }
    (s, "")
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
        sql.push_str(&membership_index_create_sql(schema, &table, &column));
        sql.push('\n');
    }
    sql
}

/// The `CREATE INDEX IF NOT EXISTS` for one join column, under the name the ledger records it by.
pub fn membership_index_create_sql(schema: &str, table: &str, column: &str) -> String {
    format!(
        "CREATE INDEX IF NOT EXISTS {} ON {} ({});",
        quote_ident(&crate::managed::membership_index_name(table, column)),
        quote_qualified(schema, table),
        quote_ident(column)
    )
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
        Operand::StartOf { unit } => {
            Some(format!("date_trunc({}, now())", quote_literal(unit.sql())))
        }
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
        Operand::Column { name } => quote_ident(name),
        Operand::AuthUid => AUTH_UID.to_string(),
        Operand::AuthRole => AUTH_ROLE.to_string(),
        // Text, so it compares against a column or a string literal. A claim used
        // as a *set* goes through the membership path instead, which needs the
        // jsonb form.
        Operand::Claim { path } => {
            format!("{CLAIMS_SCHEMA}.jwt_claim_text({})", quote_literal(path))
        }
        Operand::Literal { value } => literal_to_sql(value),

        // Each temporal operand is one scalar subquery, so the planner evaluates it
        // once per query as an InitPlan rather than per row, the same reason
        // the caller's user id is wrapped.
        Operand::Now => "(SELECT now())".to_string(),
        Operand::StartOf { unit } => {
            format!("(SELECT date_trunc({}, now()))", quote_literal(unit.sql()))
        }
        // The interval is assembled from a parsed integer and a keyword from the
        // closed unit set. No author-supplied text reaches Postgres here, which is
        // what keeps this from being a small escape hatch.
        Operand::Ago { amount, unit } => {
            format!(
                "(SELECT now() - {})",
                interval(&format!("{amount} {}", unit.sql()))
            )
        }
        Operand::FromNow { amount, unit } => {
            format!(
                "(SELECT now() + {})",
                interval(&format!("{amount} {}", unit.sql()))
            )
        }
        // The base is rendered unwrapped and the whole expression wrapped once. The
        // fallback covers a base validation should already have refused.
        Operand::After {
            base,
            interval: spec,
        } => {
            let rendered = time_base_expr(base).unwrap_or_else(|| operand_to_expr(base));
            format!(
                "(SELECT {rendered} + {})",
                interval(&interval_literal(spec))
            )
        }
        Operand::Before {
            base,
            interval: spec,
        } => {
            let rendered = time_base_expr(base).unwrap_or_else(|| operand_to_expr(base));
            format!(
                "(SELECT {rendered} - {})",
                interval(&interval_literal(spec))
            )
        }
    }
}

/// `INTERVAL '<text>'`.
fn interval(text: &str) -> String {
    format!("INTERVAL {}", quote_literal(text))
}

/// `Owner<"f">`: compare the caller's user id ([`AUTH_UID`]) with a column of the row, or look
/// ownership up through a related model.
///
/// `id` and a UUID field are compared directly, as is a relation's key when the related model is
/// keyed by the auth user id or declares no owner of its own. A related model with an `Owner`
/// rule is joined, and its owner column compared. The validator (`parser::owner_rules`) has
/// already refused every other kind of field.
///
/// Columns are always quoted, which is also what lets `qualify_bare_columns` find these references
/// when the same expression is reused inside a `can_*` function, where a bare column has no `FROM`
/// clause to resolve against. Quoting changes no meaning and the differ's normaliser strips quotes,
/// so no policy is recreated for it.
fn owner_access_expr(ast: &SchemaAst, model: &ModelAst, kernel_field: &str) -> String {
    let column = resolve_owner_column(model, kernel_field);
    let Some(FieldAst::Relation(rel)) = model.fields.get(kernel_field) else {
        return format!("{AUTH_UID} = {}", quote_ident(&column));
    };
    let owned_target = ast
        .models
        .iter()
        .find(|m| m.name == rel.target)
        .filter(|target| !is_user_identity_model(target))
        .and_then(|target| Some((target, owner_column_on_model(target)?)));
    match owned_target {
        Some((target, owner_col)) => {
            let table = quote_ident(db_table_name(target));
            format!(
                "EXISTS (SELECT 1 FROM {table} WHERE {table}.\"id\" = {fk_q} AND {AUTH_UID} = {table}.{owner_q})",
                fk_q = quote_ident(&column),
                owner_q = quote_ident(&owner_col)
            )
        }
        None => format!("{AUTH_UID} = {}", quote_ident(&column)),
    }
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
    let names = crate::managed::ObjectNames::for_schema(ast);

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
                out.push_str(&render_can_function(
                    schema,
                    table,
                    &names.can_function(table, op),
                    "FALSE",
                ));
                continue;
            };

            // The expression is used exactly as the policy uses it. The function
            // body supplies a scope its column references resolve against, so
            // nothing has to be rewritten, which is what lets a `Custom` rule's
            // raw SQL answer definitively rather than "unknown".
            let expr = access_rule_to_expr(ast, model, rule, schema);
            out.push_str(&render_can_function(
                schema,
                table,
                &names.can_function(table, op),
                &expr,
            ));
        }

        out.push_str(&render_field_can_functions(
            ast, model, schema, table, &names,
        ));
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
    names: &crate::managed::ObjectNames,
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
            &names.field_can_function(table, "read", column),
            read_expr.as_deref().unwrap_or("TRUE"),
        ));

        if let Some(rule) = rules.write.as_ref() {
            let write_expr = access_rule_to_expr(ast, model, rule, schema);
            let conjoined = match read_expr.as_deref() {
                Some(read) => format!("({write_expr}) AND ({read})"),
                None => write_expr,
            };
            out.push_str(&render_field_can_function(
                schema,
                table,
                &names.field_can_function(table, "write", column),
                &conjoined,
            ));
        }
    }

    out
}

/// `can_<op>_<table>__<column>`, named by [`crate::managed::ObjectNames::field_can_function`].
///
/// Double underscore between table and column so a table named `posts_salary`
/// cannot collide with column `salary` of table `posts`.
fn render_field_can_function(schema: &str, table: &str, name: &str, expr: &str) -> String {
    let (function, row, alias) = can_function_names(schema, table, name);
    format!(
        "CREATE OR REPLACE FUNCTION {function}({alias} {row})
           RETURNS boolean LANGUAGE sql STABLE AS $can$
             SELECT {expr}
               FROM (SELECT ($1).*) AS {alias};
           $can$;
{}
",
        can_function_grants(schema, table, name)
    )
}

// ─── Field-level enforcement: security labels ────────────────────────────────

/// The extension that enforces field rules, and the label provider it registers.
pub const MASK_EXTENSION: &str = "supatype_mask";
pub const MASK_PROVIDER: &str = "supatype";

/// A qualified reference to a generated per-column predicate.
///
/// The schema is written bare, as every label already in a database holds it: the label is
/// compared as text, so quoting it would relabel every masked column on the next push.
fn field_predicate_ref(
    names: &crate::managed::ObjectNames,
    schema: &str,
    op: &str,
    table: &str,
    column: &str,
) -> String {
    format!(
        "{schema}.{}",
        quote_ident(&names.field_can_function(table, op, column))
    )
}

/// One column's `SECURITY LABEL FOR supatype`, the object the ledger records under
/// (`schema`, `table.column`, provider).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldLabel {
    pub table: String,
    pub column: String,
    /// The label text, `MASK READ ... WRITE ...`, as `pg_seclabel` will hold it.
    pub label: String,
}

impl FieldLabel {
    /// The statement that sets the label.
    pub fn create_sql(&self, schema: &str) -> String {
        format!(
            "SECURITY LABEL FOR {MASK_PROVIDER} ON COLUMN {} IS {};",
            label_target(schema, &self.table, &self.column),
            quote_literal(&self.label)
        )
    }
}

/// `"schema"."table"."column"`, quoted as a `SECURITY LABEL` names its column.
fn label_target(schema: &str, table: &str, column: &str) -> String {
    format!("{}.{}", quote_qualified(schema, table), quote_ident(column))
}

/// The statement that takes a column's label off.
pub fn drop_field_label_sql(schema: &str, table: &str, column: &str) -> String {
    let target = quote_qualified(schema, table);
    guarded_label_drop(
        &format!(
            "SECURITY LABEL FOR {MASK_PROVIDER} ON COLUMN {} IS NULL",
            label_target(schema, table, column)
        ),
        &format!(
            "(SELECT attnum FROM pg_catalog.pg_attribute WHERE attrelid = {}::regclass AND attname = {})",
            quote_literal(&target),
            quote_literal(column)
        ),
        &target,
    )
}

/// [`drop_field_label_sql`] for a label on the table itself. The engine writes none, but one found
/// under its provider is its by location, so the reconcile drops it and needs the statement.
pub fn drop_table_label_sql(schema: &str, table: &str) -> String {
    let target = quote_qualified(schema, table);
    guarded_label_drop(
        &format!("SECURITY LABEL FOR {MASK_PROVIDER} ON TABLE {target} IS NULL"),
        "0",
        &target,
    )
}

/// Takes a label off whether or not the masking extension is installed (F17, A3-N6).
///
/// The provider is registered by the preloaded library, not the extension: `supatype/postgres` with
/// `supatype_mask` dropped still has it, and still acts on every label left behind, so every UPDATE
/// of a labelled column fails (T2-N7). A guard on `pg_extension` skipped the drop on exactly that
/// database while the plan said the label was dropped. So the statement is simply run. Where no
/// provider is loaded at all (`22023`, a database moved off the image) the label does nothing, a
/// `SECURITY LABEL` cannot name it, and a superuser removes the catalog row instead; anyone else
/// leaves it, inert.
fn guarded_label_drop(statement: &str, subid: &str, target: &str) -> String {
    format!(
        "DO $mask_label$\nBEGIN\n  EXECUTE {};\n\
         EXCEPTION WHEN invalid_parameter_value THEN\n\
         \x20 BEGIN\n\
         \x20   DELETE FROM pg_catalog.pg_seclabel\n\
         \x20    WHERE provider = {} AND classoid = 'pg_catalog.pg_class'::regclass\n\
         \x20      AND objoid = {}::regclass AND objsubid = {subid};\n\
         \x20 EXCEPTION WHEN insufficient_privilege THEN NULL;\n\
         \x20 END;\nEND\n$mask_label$;",
        quote_literal(statement),
        quote_literal(MASK_PROVIDER),
        quote_literal(target),
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
///
/// Each label is a ledger object (plan section 5): the reconcile sets it, and takes it off when
/// the rule goes, which the stale-label sweep used to do.
pub fn field_labels(ast: &SchemaAst, schema: &str) -> Vec<FieldLabel> {
    field_predicates(ast, schema)
        .into_iter()
        .map(|p| {
            let parts: Vec<String> = [("READ", &p.read), ("WRITE", &p.write)]
                .into_iter()
                .filter_map(|(word, predicate)| predicate.as_ref().map(|f| format!("{word} {f}")))
                .collect();
            FieldLabel {
                label: format!("MASK {}", parts.join(" ")),
                table: p.table,
                column: p.column,
            }
        })
        .collect()
}

/// Which `can_*` predicate decides each masked column, read and write, named as a label names it
/// (`schema."can_read_<t>__<col>"`). One entry per column with a field rule.
///
/// The names are chosen once for the whole schema, so one cut to the identifier limit, or given a
/// digit against another, is what the database holds: a reader rebuilding them from the naming rule
/// alone gets those wrong. Tier 1 carries this in the labels; under tier 2 there are none, so the
/// push records it beside the tier (`_supatype.schema_state.capabilities.fieldMasking.columns`).
pub fn field_predicates(ast: &SchemaAst, schema: &str) -> Vec<FieldPredicates> {
    let names = crate::managed::ObjectNames::for_schema(ast);
    let mut out = Vec::new();
    for model in &ast.models {
        let table = db_table_name(model);
        for (column, rules) in &platform_access(model).fields {
            let predicate = |op: &str, present: bool| {
                present.then(|| field_predicate_ref(&names, schema, op, table, column))
            };
            let read = predicate("read", rules.read.is_some());
            let write = predicate("write", rules.write.is_some());
            if read.is_none() && write.is_none() {
                continue;
            }
            out.push(FieldPredicates {
                table: table.to_string(),
                column: column.clone(),
                read,
                write,
            });
        }
    }
    out
}

/// One masked column's predicates: see [`field_predicates`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldPredicates {
    pub table: String,
    pub column: String,
    /// The read predicate, absent when only writes are ruled.
    pub read: Option<String>,
    /// The write predicate, absent when only reads are ruled.
    pub write: Option<String>,
}

/// The checks a push of field rules runs before any label is set: that the masking extension is
/// there, and that the predicates the labels name can be evaluated. Empty for a schema with no
/// field rules, which must not start requiring either.
///
/// Refusing the push is the third tier in the field-access plan, and the only honest answer: a
/// schema that declares a column masked, applied to a database that cannot mask it, is a database
/// whose security posture silently differs from its source. Never silently unmask.
pub fn generate_mask_probes(ast: &SchemaAst, schema: &str) -> String {
    let n = field_labels(ast, schema).len();
    if n == 0 {
        return String::new();
    }
    // Proof that the privilege those predicates need actually landed. The grant itself is in the
    // preamble, emitted on every push, so this does not re-issue it: a grant can be a silent no-op
    // (see `render_claims_usage_probe`), and checking is the half worth doing twice.
    format!(
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

{}",
        render_claims_usage_probe(n)
    )
}

/// The probes, then every label: what a schema's field rules apply as one script.
pub fn generate_security_labels(ast: &SchemaAst, schema: &str) -> String {
    let mut out = generate_mask_probes(ast, schema);
    for label in field_labels(ast, schema) {
        out.push_str(&label.create_sql(schema));
        out.push_str("\n\n");
    }
    out
}

/// Proof that the masking predicates can actually run, rather than a hope that they can.
///
/// The predicates call the claim readers in [`CLAIMS_SCHEMA`] as the caller, and the grant that
/// lets them may have been a no-op: a role that does not own the schema cannot grant on it, and
/// Postgres reports that as `WARNING: no privileges were granted`, not an error. So the grant alone
/// proves nothing. Without this check such a push reports success, and then every authenticated
/// read of a masked column fails with `42501 permission denied for schema`, the same class of fault
/// as a privilege that is generated and never applied.
///
/// Only the claims schema: no generated predicate calls into `auth` any more, so a database whose
/// `auth` schema belongs to another role masks correctly and is not refused for it.
///
/// Refuses rather than degrades, matching the extension probe: a schema that declares a masked
/// column, applied where the mask cannot be evaluated, is a database whose security posture
/// silently differs from its source.
fn render_claims_usage_probe(rule_count: usize) -> String {
    let roles = API_ROLES.join(", ");
    format!(
        r#"DO $claims_usage_probe$
DECLARE
  owner text;
BEGIN
  SELECT pg_get_userbyid(nspowner) INTO owner
    FROM pg_namespace WHERE nspname = '{CLAIMS_SCHEMA}';

  -- No claims schema: the field predicates could not have been created either, and the extension
  -- probe has already had its say about capability.
  IF owner IS NULL THEN
    RETURN;
  END IF;

  -- has_schema_privilege raises on an unknown role, so ask whether the role exists first. A
  -- database with no `authenticated` role has no authenticated caller to break.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    RETURN;
  END IF;

  IF NOT has_schema_privilege('authenticated', '{CLAIMS_SCHEMA}', 'USAGE') THEN
    RAISE EXCEPTION 'field-level access requires USAGE on schema {CLAIMS_SCHEMA}'
      USING ERRCODE = 'feature_not_supported',
            DETAIL  = format('%s column rule(s) would raise 42501 for every authenticated caller.',
                             {rule_count}),
            HINT    = format('Schema {CLAIMS_SCHEMA} is owned by %s, so this push could not grant on it. As that role: GRANT USAGE ON SCHEMA {CLAIMS_SCHEMA} TO {roles};',
                             owner);
  END IF;
END
$claims_usage_probe$;

"#
    )
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
fn render_can_function(schema: &str, table: &str, name: &str, expr: &str) -> String {
    let (function, row, alias) = can_function_names(schema, table, name);
    format!(
        "CREATE OR REPLACE FUNCTION {function}({alias} {row})\n  \
         RETURNS boolean LANGUAGE sql STABLE AS $can$\n    \
         SELECT {expr}\n      \
         FROM (SELECT ($1).*) AS {alias};\n  \
         $can$;\n{}\n",
        can_function_grants(schema, table, name)
    )
}

/// Who may call a `can_*` predicate: the API roles, which is everyone that legitimately does.
/// Policies, the `supatype_mask` rewrite, the tier 2 views and realtime all call them as the
/// querying role, and Studio reads them as computed columns through PostgREST.
///
/// They are `SECURITY INVOKER`, so `EXECUTE` decides nothing about rows; this only stops every
/// other role in the cluster calling them, which `PUBLIC`'s default `EXECUTE` allowed. Written as
/// `REVOKE ALL ... FROM PUBLIC` and `GRANT EXECUTE`, the two forms the statement attribution files
/// under the function, so they are part of what the ledger records for it, and the first push
/// after an engine that did not write them re-applies the function with them.
fn can_function_grants(schema: &str, table: &str, name: &str) -> String {
    let signature = format!(
        "{}({})",
        quote_qualified(schema, name),
        quote_qualified(schema, table)
    );
    format!(
        "REVOKE ALL ON FUNCTION {signature} FROM PUBLIC;\n\
         GRANT EXECUTE ON FUNCTION {signature} TO {};\n",
        API_ROLES.join(", ")
    )
}

/// The quoted names a `can_*` function is written with: the function, its row type, and the alias
/// the row is read under, which is also its argument's name.
fn can_function_names(schema: &str, table: &str, name: &str) -> (String, String, String) {
    (
        quote_qualified(schema, name),
        quote_qualified(schema, table),
        quote_ident(table),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ast::TruncUnit;

    #[test]
    fn qualifying_columns_leaves_literals_and_doubled_quotes_whole() {
        // A role holding a double quote is a literal, not a column, and an identifier holding a
        // doubled quote is one identifier.
        let expr = r#"(SELECT _supatype.jwt_role()) = 'o"brien' AND "a""b" = 1 AND "t"."c" = 2"#;
        assert_eq!(
            qualify_bare_columns(expr, "my\"t"),
            r#"(SELECT _supatype.jwt_role()) = 'o"brien' AND "my""t"."a""b" = 1 AND "t"."c" = 2"#
        );
    }

    #[test]
    fn a_role_rule_writes_each_role_as_a_literal() {
        let roles = vec!["o'brien".to_string(), "x' OR true OR 'a'='a".to_string()];
        assert_eq!(
            role_matches(AUTH_ROLE, &roles[..1]),
            "(SELECT _supatype.jwt_role()) = 'o''brien'"
        );
        assert_eq!(
            role_matches(AUTH_ROLE, &roles),
            "(SELECT _supatype.jwt_role()) = ANY(ARRAY['o''brien', 'x'' OR true OR ''a''=''a'])"
        );
    }

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
