//! Table privileges derived from the access rules.
//!
//! Provisioning grants `SELECT ON ALL TABLES` to `anon` and full CRUD to
//! `authenticated`, so RLS is the only thing standing between an unauthenticated
//! caller and every row of every table. These grants are the second layer: a policy
//! that fails to apply then meets a privilege that was never granted.

mod common;

use supatype_engine::{
    differ, generator::sql::migration, parser, state::database_state::DatabaseState,
};

const FIXTURE: &str = include_str!("fixtures/rls_access_rules.json");

fn forward_sql() -> String {
    let ast = parser::parse(FIXTURE).expect("fixture parses");
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    migration::forward_sql(&diff, false, "public", &ast).unwrap()
}

// `comments` is All<[Eq<"author_id", AuthUid>, …]> — every branch needs a caller,
// so no anonymous request can ever read a row and the privilege is dead weight.
#[test]
fn a_rule_that_needs_a_caller_revokes_anon_select() {
    let sql = forward_sql();
    assert!(
        sql.contains(r#"REVOKE SELECT ON "public"."comments" FROM anon"#),
        "anon kept SELECT on a table it can never read"
    );
}

// `users.read` contains a Public branch, so an anonymous caller genuinely can read
// it and revoking would break the application.
#[test]
fn a_publicly_readable_table_keeps_anon_select() {
    let sql = forward_sql();
    assert!(
        sql.contains(r#"GRANT SELECT ON "public"."users" TO anon"#),
        "a public table lost its anon SELECT"
    );
}

// An operation with no rule denies every row, so neither role needs the privilege.
#[test]
fn an_undeclared_operation_is_revoked_from_both_roles() {
    let sql = forward_sql();
    // Tag declares no delete rule.
    assert!(sql.contains(r#"REVOKE DELETE ON "public"."tags" FROM anon"#));
    assert!(sql.contains(r#"REVOKE DELETE ON "public"."tags" FROM authenticated"#));
}

// `authenticated` keeps a write privilege whenever the operation is declared at
// all — which rows it may touch is the policy's business, and revoking here would
// stop the policy ever being consulted.
#[test]
fn a_declared_write_keeps_the_authenticated_privilege() {
    let sql = forward_sql();
    assert!(sql.contains(r#"GRANT UPDATE ON "public"."posts" TO authenticated"#));
}

// service_role is the escape hatch that has to keep working when everything else is
// locked down, so nothing here may touch it.
#[test]
fn service_role_is_never_revoked() {
    let sql = forward_sql();
    assert!(
        !sql.contains("FROM service_role"),
        "a generated REVOKE targeted service_role"
    );
}

// A GRANT to a role that does not exist aborts the whole transaction, so a
// defence-in-depth measure would take the migration down with it on a bare Postgres,
// a restored dump, or a database whose operator renamed the roles.
#[test]
fn privileges_are_guarded_on_the_role_existing() {
    let sql = forward_sql();
    assert!(
        sql.contains("SELECT 1 FROM pg_roles WHERE rolname = 'anon'"),
        "grants are not guarded on the role existing"
    );
    assert!(sql.contains("SELECT 1 FROM pg_roles WHERE rolname = 'authenticated'"));
}

// The grants must land after the tables exist, like the affordance functions.
#[test]
fn grants_come_after_table_creation() {
    let sql = forward_sql();
    let first_create = sql.find("CREATE TABLE").expect("fixture creates tables");
    let first_grant = sql.find("DO $grants$").expect("fixture emits privileges");
    assert!(first_grant > first_create, "privileges emitted before the tables exist");
}

// Re-running a push must not need the previous state: REVOKE of a privilege that is
// not held is a no-op, and the matching GRANT restores access when a rule relaxes.
#[test]
fn every_privilege_is_stated_either_way() {
    let sql = forward_sql();
    for (table, privilege) in [
        ("posts", "SELECT"),
        ("posts", "INSERT"),
        ("posts", "UPDATE"),
        ("posts", "DELETE"),
    ] {
        let granted = sql.contains(&format!(r#"GRANT {privilege} ON "public"."{table}" TO anon"#));
        let revoked =
            sql.contains(&format!(r#"REVOKE {privilege} ON "public"."{table}" FROM anon"#));
        assert!(
            granted || revoked,
            "{table}.{privilege} for anon was left to whatever it was before"
        );
    }
}
