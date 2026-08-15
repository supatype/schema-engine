//! Table privileges derived from the declared access rules.
//!
//! Provisioning grants `SELECT ON ALL TABLES` to `anon` and full CRUD to
//! `authenticated`, with matching default privileges so every future table inherits
//! them. RLS is then the only thing standing between an unauthenticated caller and
//! every row of every table -- a single layer, where a policy that fails to apply
//! (an unmarked table, a mistaken drop, a bug in this engine) has nothing behind it.
//!
//! The access rules already say which operations are reachable, so the privileges
//! can say the same thing. A model with no `read` rule denies every select, so
//! `anon` and `authenticated` do not need `SELECT` on it at all.
//!
//! **Conservative in one direction only.** A privilege is revoked only when the
//! rules prove it can never be used. Anything this analysis cannot decide keeps its
//! grant, because a wrong revoke breaks a working application while a missed one
//! merely leaves today's behaviour in place. `service_role` is never touched: it is
//! the escape hatch that has to keep working when everything else is locked down.

use crate::parser::accessors::{db_table_name, platform_access};
use crate::parser::ast::{AccessRule, MembershipSource, Operand, SchemaAst};

/// Whether an unauthenticated caller could ever satisfy a rule.
///
/// Only a proof of *unreachability* is acted on, so every uncertain case answers
/// true and the grant survives.
fn reachable_by_anon(rule: &AccessRule) -> bool {
    match rule {
        AccessRule::Public => true,
        AccessRule::Private => false,

        // `auth.uid()` is null for an unauthenticated caller.
        AccessRule::Authenticated => false,

        // Ownership compares against `auth.uid()`, which no anonymous caller has.
        AccessRule::Owner { .. } => false,

        // App roles come from the token's claims. Without one the caller's role is
        // `anon`, so only a rule naming it is reachable.
        AccessRule::Role { roles } => roles.iter().any(|r| r == "anon"),

        AccessRule::Any { rules } => rules.iter().any(reachable_by_anon),
        AccessRule::All { rules } => rules.iter().all(reachable_by_anon),

        // Negation of an unreachable rule is reachable, but proving that needs the
        // rule to be total; not worth the risk of a wrong revoke.
        AccessRule::Not { .. } => true,

        AccessRule::Compare { left, right, .. } => {
            operand_reachable_by_anon(left) && operand_reachable_by_anon(right)
        }
        AccessRule::NullCheck { operand, .. } => operand_reachable_by_anon(operand),

        // Membership is against the caller's own rows, so an anonymous caller
        // matches nothing -- unless the source is a fixed list, which is the same
        // for everyone.
        AccessRule::In { source, .. } | AccessRule::Exists { source } => {
            matches!(source, MembershipSource::Literal { .. })
        }
    }
}

fn operand_reachable_by_anon(operand: &Operand) -> bool {
    match operand {
        // Both are absent for an anonymous caller, so any comparison against them
        // is null and therefore false.
        Operand::AuthUid | Operand::Claim { .. } => false,
        // `auth.role()` falls back to 'anon', so a comparison can still match.
        Operand::AuthRole => true,
        _ => true,
    }
}

/// Privilege statements for what the rules prove usable, and revocations for what
/// they prove unusable.
///
/// Wrapped in a role-existence guard. `anon` / `authenticated` are created when a
/// project is provisioned, but a migration also runs against databases that have
/// never seen that step -- a bare Postgres in CI, a restored dump, a database whose
/// operator renamed the roles. A `GRANT` to a role that does not exist aborts the
/// whole transaction, so a defence-in-depth measure would take the migration down
/// with it.
///
/// Emitted on every push and idempotent: revoking a privilege that is not held is a
/// no-op, and the matching grant is what restores access when a rule is relaxed.
/// `skip` names tables the schema declares but Supatype did not create.
///
/// Their privileges are not ours to change: a `REVOKE` would take access away from whatever else
/// uses the table, and a `GRANT` would hand Supatype's API a table whose access rules were never
/// applied. Skipping leaves it inaccessible to the API, which is the safe direction.
/// `serve_from` is the schema the API actually reads. Under tier-2 field masking that is `api`, and
/// the privileges have to follow: schema exposure is PostgREST configuration, not a boundary, so a
/// mask that lives in a view is only as strong as the roles' inability to read the table behind it.
/// The base-table privileges are revoked from `anon` and `authenticated` in the same breath.
///
/// `service_role` keeps its base-table access, per this module's standing policy — it is the escape
/// hatch that has to keep working. One consequence to know: tier 1 masks a `service_role` caller like
/// any other (the read predicate simply fails for it), while under tier 2 that caller reads the table
/// directly and sees everything. Deliberate, and recorded rather than quietly true.
pub fn generate_table_grants(
    ast: &SchemaAst,
    schema: &str,
    skip: &[String],
    serve_from: Option<&str>,
) -> String {
    let mut anon_stmts: Vec<String> = Vec::new();
    let mut authed_stmts: Vec<String> = Vec::new();

    for model in &ast.models {
        let access = platform_access(model);
        let table = db_table_name(model);
        if skip.iter().any(|t| t == table) {
            continue;
        }
        let escaped = table.replace('"', "\"\"");
        let base = format!("\"{schema}\".\"{escaped}\"");
        let qualified = match serve_from {
            Some(view_schema) => format!("\"{view_schema}\".\"{escaped}\""),
            None => base.clone(),
        };
        // Tier 2 only: take the API roles off the table the view reads, so `Accept-Profile` cannot be
        // used to go round the mask and neither can a stray credential.
        if serve_from.is_some() {
            anon_stmts.push(format!("REVOKE ALL PRIVILEGES ON {base} FROM anon"));
            authed_stmts.push(format!(
                "REVOKE ALL PRIVILEGES ON {base} FROM authenticated"
            ));
        }

        let read_anon = access.read.as_ref().is_some_and(reachable_by_anon);
        anon_stmts.push(privilege_stmt("SELECT", &qualified, "anon", read_anon));
        authed_stmts.push(privilege_stmt(
            "SELECT",
            &qualified,
            "authenticated",
            access.read.is_some(),
        ));

        // `authenticated` keeps a write privilege whenever the operation is declared
        // at all; which *rows* it may touch is the policy's business, and revoking
        // here would stop the policy ever being consulted.
        for (op, rule) in [
            ("INSERT", access.create.as_ref()),
            ("UPDATE", access.update.as_ref()),
            ("DELETE", access.delete.as_ref()),
        ] {
            anon_stmts.push(privilege_stmt(
                op,
                &qualified,
                "anon",
                rule.is_some_and(reachable_by_anon),
            ));
            authed_stmts.push(privilege_stmt(
                op,
                &qualified,
                "authenticated",
                rule.is_some(),
            ));
        }
    }

    if anon_stmts.is_empty() && authed_stmts.is_empty() {
        return String::new();
    }

    let mut out = String::from(
        "DO $grants$
BEGIN
",
    );
    out.push_str(&guarded_block("anon", &anon_stmts));
    out.push_str(&guarded_block("authenticated", &authed_stmts));
    out.push_str(
        "END
$grants$;
",
    );
    out
}

fn guarded_block(role: &str, statements: &[String]) -> String {
    if statements.is_empty() {
        return String::new();
    }
    let body = statements
        .iter()
        .map(|s| format!("    EXECUTE '{}';\n", s.replace('\'', "''")))
        .collect::<String>();
    format!(
        "  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
{body}  END IF;
"
    )
}

fn privilege_stmt(privilege: &str, table: &str, role: &str, allowed: bool) -> String {
    if allowed {
        format!("GRANT {privilege} ON {table} TO {role}")
    } else {
        format!("REVOKE {privilege} ON {table} FROM {role}")
    }
}

// ─── Column privileges for field write rules (defence in depth) ──────────────

/// `fields.write` as column privileges, layered under the masking extension.
///
/// **Writes only.** A column `REVOKE` for reads makes `GET /table` with no `select` return
/// 403 for the whole table, which is the break the field-access design exists to avoid.
/// Writes have no such problem: `PATCH`/`POST` naming a column the role may not write is
/// *supposed* to fail.
///
/// This is a second layer, not the mechanism. Enforcement is the query rewrite, which can
/// express `Role<"admin">`; a column privilege cannot, because an application role is a JWT
/// claim and an admin still connects as `authenticated`. So only what a *database role*
/// provably can never write is revoked here.
pub fn generate_column_grants(ast: &SchemaAst, schema: &str, skip: &[String]) -> String {
    let mut blocks: Vec<String> = Vec::new();

    for model in &ast.models {
        let access = platform_access(model);
        if access.fields.is_empty() {
            continue;
        }
        if skip.iter().any(|t| t == db_table_name(model)) {
            continue;
        }
        let table = db_table_name(model);

        for (op, table_rule) in [
            ("INSERT", access.create.as_ref()),
            ("UPDATE", access.update.as_ref()),
        ] {
            // No table-level rule means `generate_table_grants` revoked the operation from
            // both roles. Granting a column complement back would *widen* what the table
            // rules just closed, so there is nothing to do.
            let Some(table_rule) = table_rule else {
                continue;
            };

            for role in ["anon", "authenticated"] {
                if role == "anon" && !reachable_by_anon(table_rule) {
                    // Same reason: `anon` does not hold the operation at table level.
                    continue;
                }

                let excluded: Vec<&str> = access
                    .fields
                    .iter()
                    .filter(|(_, rules)| {
                        rules
                            .write
                            .as_ref()
                            .is_some_and(|write| !write_satisfiable(op, role, write))
                    })
                    .map(|(column, _)| column.as_str())
                    .collect();

                if excluded.is_empty() {
                    continue;
                }

                blocks.push(render_column_grant(schema, table, op, role, &excluded));
            }
        }
    }

    if blocks.is_empty() {
        return String::new();
    }

    format!(
        "DO $colgrants$
DECLARE
  granted text;
BEGIN
{}END
$colgrants$;
",
        blocks.join("")
    )
}

/// Whether any caller connecting as `role` could ever satisfy this write rule for `op`.
///
/// Conservative in one direction only, like the table grants: a wrong revoke breaks a working
/// app, a missed one just leaves today's behaviour. So this answers true unless the rule
/// *proves* otherwise.
fn write_satisfiable(op: &str, role: &str, write: &AccessRule) -> bool {
    if role == "anon" {
        return reachable_by_anon(write);
    }

    // `authenticated` is every signed-in caller, so an application-role or ownership rule is
    // satisfiable by *some* of them and the column privilege must stay.
    if matches!(write, AccessRule::Private) {
        return false;
    }

    // On INSERT there is no row yet: the masking extension evaluates the write predicate
    // against `NULL::t`, so a rule that reads the row yields NULL for every caller. Nobody
    // can write the column on this path, which makes the privilege provably unusable —
    // whereas on UPDATE the same rule is satisfiable and the privilege must stay.
    if op == "INSERT" && crate::differ::field_access_diff::rule_is_row_dependent(write) {
        return false;
    }

    true
}

/// The complement is computed from `information_schema.columns` at apply time, not from the
/// AST.
///
/// A column this generator never saw — added out of band, or by a plugin — must still be
/// granted, or the layer meant to be defence in depth silently becomes the thing that breaks
/// writes. Reading the live column list also makes the statement converge on every push
/// without tracking what it granted last time.
fn render_column_grant(
    schema: &str,
    table: &str,
    op: &str,
    role: &str,
    excluded: &[&str],
) -> String {
    let quoted_table = table.replace('"', "\"\"");
    let exclusion_list = excluded
        .iter()
        .map(|column| format!("'{}'", column.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
    SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position)
      INTO granted
      FROM information_schema.columns
     WHERE table_schema = '{schema}'
       AND table_name = '{table_literal}'
       AND column_name NOT IN ({exclusion_list});
    EXECUTE 'REVOKE {op} ON \"{schema}\".\"{quoted_table}\" FROM {role}';
    IF granted IS NOT NULL THEN
      EXECUTE format('GRANT {op} (%s) ON \"{schema}\".\"{quoted_table}\" TO {role}', granted);
    END IF;
  END IF;
",
        table_literal = table.replace('\'', "''")
    )
}
