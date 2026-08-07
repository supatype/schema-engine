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
pub fn generate_table_grants(ast: &SchemaAst) -> String {
    let mut anon_stmts: Vec<String> = Vec::new();
    let mut authed_stmts: Vec<String> = Vec::new();
    let schema = super::rls::POLICY_SCHEMA;

    for model in &ast.models {
        let access = platform_access(model);
        let table = db_table_name(model);
        let qualified = format!("\"{schema}\".\"{}\"", table.replace('"', "\"\""));

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
            authed_stmts.push(privilege_stmt(op, &qualified, "authenticated", rule.is_some()));
        }
    }

    if anon_stmts.is_empty() && authed_stmts.is_empty() {
        return String::new();
    }

    let mut out = String::from("DO $grants$
BEGIN
");
    out.push_str(&guarded_block("anon", &anon_stmts));
    out.push_str(&guarded_block("authenticated", &authed_stmts));
    out.push_str("END
$grants$;
");
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
    format!("  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
{body}  END IF;
")
}

fn privilege_stmt(privilege: &str, table: &str, role: &str, allowed: bool) -> String {
    if allowed {
        format!("GRANT {privilege} ON {table} TO {role}")
    } else {
        format!("REVOKE {privilege} ON {table} FROM {role}")
    }
}
