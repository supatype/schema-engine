//! Table privileges derived from the access rules.
//!
//! Provisioning grants every privilege on every table to `anon` and `authenticated`, so RLS is
//! the only thing standing between an unauthenticated caller and every row of every table. These
//! grants are the second layer: a policy that fails to apply then meets a privilege that was never
//! granted. Each role's privileges on a model table are one ledger object since Phase 4.7c (D7),
//! applied as the exact set: `tests/grant_ledger_tests.rs` proves them against Postgres.

use supatype_engine::{
    generator::sql::grants::{self, TableGrant},
    parser, push,
};

const FIXTURE: &str = include_str!("fixtures/rls_access_rules.json");

fn grant(table: &str, role: &str) -> TableGrant {
    let ast = parser::parse(FIXTURE).expect("fixture parses");
    grants::table_grants(&ast, false)
        .into_iter()
        .find(|g| g.table == table && g.role == role)
        .unwrap_or_else(|| panic!("no grant for {role} on {table}"))
}

fn migration() -> String {
    let ast = parser::parse(FIXTURE).expect("fixture parses");
    push::fresh_migration(&ast, "public", false)
        .expect("fixture renders")
        .up_script()
}

// `comments` is All<[Eq<"author_id", AuthUid>, ...]>: every branch needs a caller, so no
// anonymous request can ever read a row and the privilege is dead weight.
#[test]
fn a_rule_that_needs_a_caller_revokes_anon_select() {
    let anon = grant("comments", "anon");
    assert!(
        !anon.privileges.contains(&"SELECT"),
        "anon kept SELECT on a table it can never read: {anon:?}"
    );
}

// `users.read` contains a Public branch, so an anonymous caller genuinely can read it and
// revoking would break the application.
#[test]
fn a_publicly_readable_table_keeps_anon_select() {
    let anon = grant("users", "anon");
    assert!(anon.privileges.contains(&"SELECT"), "{anon:?}");
}

// An operation with no rule denies every row, so neither role needs the privilege.
#[test]
fn an_undeclared_operation_is_revoked_from_both_roles() {
    // Tag declares no delete rule.
    for role in grants::GRANTED_ROLES {
        let g = grant("tags", role);
        assert!(!g.privileges.contains(&"DELETE"), "{g:?}");
    }
}

// `authenticated` keeps a write privilege whenever the operation is declared at all: which rows
// it may touch is the policy's business, and revoking here would stop the policy ever being
// consulted.
#[test]
fn a_declared_write_keeps_the_authenticated_privilege() {
    let g = grant("posts", "authenticated");
    assert!(g.privileges.contains(&"UPDATE"), "{g:?}");
}

// service_role is the escape hatch that has to keep working when everything else is locked down,
// so nothing here may touch it.
#[test]
fn service_role_is_never_revoked() {
    assert!(!grants::GRANTED_ROLES.contains(&"service_role"));
    let sql = migration();
    assert!(
        !sql.contains("FROM service_role"),
        "a generated REVOKE targeted service_role"
    );
}

// A GRANT to a role that does not exist aborts the whole transaction, so a defence-in-depth
// measure would take the migration down with it on a bare Postgres, a restored dump, or a
// database whose operator renamed the roles.
#[test]
fn privileges_are_guarded_on_the_role_existing() {
    let sql = migration();
    assert!(
        sql.contains("SELECT 1 FROM pg_roles WHERE rolname = 'anon'"),
        "grants are not guarded on the role existing"
    );
    assert!(sql.contains("SELECT 1 FROM pg_roles WHERE rolname = 'authenticated'"));
}

// The grants must land after the tables exist.
#[test]
fn grants_come_after_table_creation() {
    let sql = migration();
    let first_create = sql.find("CREATE TABLE").expect("fixture creates tables");
    let first_grant = sql.find("DO $grants$").expect("fixture emits privileges");
    assert!(
        first_grant > first_create,
        "privileges emitted before the tables exist"
    );
}

// The exact set (D7): everything is revoked before the rules' privileges are granted, so no
// privilege survives that the rules do not allow, whatever the role held before. The image's
// default privileges had left TRUNCATE, which row-level security does not govern.
#[test]
fn each_role_holds_exactly_the_set_the_rules_allow() {
    let anon = grant("posts", "anon");
    let sql = anon.create_sql("public");
    let revoke = sql
        .find(r#"REVOKE ALL PRIVILEGES ON "public"."posts" FROM anon"#)
        .unwrap_or_else(|| panic!("{sql}"));
    if let Some(grant_at) = sql.find("GRANT ") {
        assert!(revoke < grant_at, "{sql}");
    }
    assert!(!sql.contains("TRUNCATE"), "{sql}");
}

// ─── Rules that read another table's rows (issue 16) ────────────────────────

const ROWS_FIXTURE: &str = include_str!("fixtures/rls_anon_rows.json");

fn rows_grant(table: &str, role: &str) -> TableGrant {
    let ast = parser::parse(ROWS_FIXTURE).expect("rows fixture parses");
    grants::table_grants(&ast, false)
        .into_iter()
        .find(|g| g.table == table && g.role == role)
        .unwrap_or_else(|| panic!("no grant for {role} on {table}"))
}

// `question.read` admits a question whose form is published. Nothing in that branch needs a
// caller, and anon may read a published form, so an anonymous visitor can read the questions of a
// published form and needs SELECT for the policy to be consulted at all.
#[test]
fn a_rows_source_anon_can_read_keeps_anon_select() {
    let anon = rows_grant("question", "anon");
    assert!(anon.privileges.contains(&"SELECT"), "{anon:?}");
}

// `response.create` is `In<"form_id", Rows<"form", "id", NotNull<"published_at">>>`: anyone may
// answer a published form.
#[test]
fn a_rows_source_anon_can_read_keeps_anon_insert() {
    let anon = rows_grant("response", "anon");
    assert!(anon.privileges.contains(&"INSERT"), "{anon:?}");
}

// `draft` reads `form` rows filtered to the caller's own, which no anonymous caller has.
#[test]
fn a_rows_filter_comparing_against_the_caller_revokes_anon() {
    let anon = rows_grant("draft", "anon");
    assert!(!anon.privileges.contains(&"SELECT"), "{anon:?}");
    assert!(!anon.privileges.contains(&"INSERT"), "{anon:?}");
}

// `secret_note` reads `secret` rows with a filter anon could pass, but `secret` itself is readable
// only when signed in: the policy's subquery runs as the caller, so anon finds no row.
#[test]
fn a_rows_source_anon_cannot_read_revokes_anon() {
    let anon = rows_grant("secret_note", "anon");
    assert!(!anon.privileges.contains(&"SELECT"), "{anon:?}");
}

// `node` reads its own table and `ping`/`pong` read each other: the analysis has to stop. A cycle
// cannot be proved unreachable, so the grant survives, as every undecided case does.
#[test]
fn a_rows_source_that_reads_itself_terminates() {
    for table in ["node", "ping", "pong"] {
        let anon = rows_grant(table, "anon");
        assert!(anon.privileges.contains(&"SELECT"), "{anon:?}");
    }
}
