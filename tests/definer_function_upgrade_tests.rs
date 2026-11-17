//! A database an earlier engine pushed to has its definer functions open to `PUBLIC`; the next
//! push closes them.
//!
//! Before the revokes, every definer function the engine made in `_supatype` kept the `EXECUTE`
//! Postgres hands `PUBLIC` to a new function: the draft and version helpers, the versions guard and
//! audit triggers, and the studio membership audit trigger. `definer_function_audit_tests` proves a
//! fresh push leaves none of that. This proves the push on top of an existing database does too, and
//! that it takes the privilege back from `PUBLIC` only: the API roles keep what they were granted.
//!
//! The old engine's database is reproduced, not built: after a push, `EXECUTE` is granted back to
//! `PUBLIC` on the functions the fix revokes it from. The old SQL differed from the new in nothing
//! else about these functions (the `acl` lines in the goldens are the whole diff), so the state is
//! the one a pre-fix push left, down to the ACL.

mod common;

use sqlx::PgPool;
use supatype_engine::introspector::fingerprint::ObjectKind;
use supatype_engine::parser::{self, ast::SchemaAst};

/// A fixture builder, so a scenario can make the schema afresh for each push.
type Fixture = fn() -> SchemaAst;

fn fixture(json: &str) -> SchemaAst {
    parser::parse(json).expect("fixture parses")
}

/// The API roles, as the database image makes them, holding `USAGE` on `_supatype`, and the
/// `auth.users` the auth server makes.
const GIVE_API_ROLES_USAGE: &str = "
    DO $$ BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN
        CREATE ROLE anon NOLOGIN; END IF;
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticated') THEN
        CREATE ROLE authenticated NOLOGIN; END IF;
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'service_role') THEN
        CREATE ROLE service_role NOLOGIN BYPASSRLS; END IF;
    END $$;
    CREATE SCHEMA IF NOT EXISTS auth;
    CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY);
    CREATE SCHEMA IF NOT EXISTS _supatype;
    GRANT USAGE ON SCHEMA _supatype TO anon, authenticated, service_role;";

/// What a pre-fix push left: `PUBLIC` holds `EXECUTE` on the functions the fix revokes it from. The other definer
/// functions were already revoked by that engine.
const REOPEN_TO_PUBLIC: &str = "
    DO $$ DECLARE f regprocedure; BEGIN
      FOR f IN SELECT p.oid::regprocedure FROM pg_proc p
                 JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = '_supatype'
                WHERE p.prosecdef
                  AND (p.proname LIKE 'sees_draft_%' OR p.proname LIKE '%_versions_guard'
                       OR p.proname LIKE '%_audit' OR p.proname IN
                          ('sees_all_drafts', 'preview_epoch', 'audit_studio_membership_change'))
      LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO PUBLIC', f);
      END LOOP;
    END $$;";

/// The definer functions in `_supatype` that `PUBLIC` can execute.
const PUBLIC_EXECUTABLE: &str = "
    SELECT p.oid::regprocedure::text FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = '_supatype'
      CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
     WHERE p.prosecdef AND a.privilege_type = 'EXECUTE' AND a.grantee = 0
     ORDER BY 1";

/// The draft helpers the API roles call from a policy, which the push must leave them able to run.
const API_ROLE_HELPERS: &str = "
    SELECT p.oid::regprocedure::text FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = '_supatype'
     WHERE p.proname LIKE 'sees\\_draft\\_%' OR p.proname IN ('sees_all_drafts', 'preview_epoch')
     ORDER BY 1";

async fn can_execute(pool: &PgPool, role: &str, function: &str) -> bool {
    sqlx::query_scalar(&format!(
        "SELECT has_function_privilege('{role}', '{function}'::regprocedure, 'EXECUTE')"
    ))
    .fetch_one(pool)
    .await
    .expect("read the privilege")
}

async fn names(pool: &PgPool, sql: &str) -> Vec<String> {
    sqlx::query_scalar(sql)
        .fetch_all(pool)
        .await
        .expect("read function names")
}

fn contains(list: &[String], needle: &str) -> bool {
    list.iter().any(|f| f.contains(needle))
}

/// Pushes `first`, reopens the definer functions to `PUBLIC` as the old engine left them, pushes
/// `second`, and returns what `PUBLIC` could execute before and after the second push.
async fn upgrade(
    pool: &PgPool,
    first: &SchemaAst,
    second: &SchemaAst,
) -> (Vec<String>, Vec<String>) {
    common::exec(pool, GIVE_API_ROLES_USAGE)
        .await
        .expect("make the API roles");
    common::push(pool, first).await.expect("first push");
    common::exec(pool, GIVE_API_ROLES_USAGE)
        .await
        .expect("grant usage");
    common::exec(pool, REOPEN_TO_PUBLIC).await.expect("reopen");
    record_as_the_old_engine_did(pool).await;
    let before = names(pool, PUBLIC_EXECUTABLE).await;
    common::push(pool, second).await.expect("second push");
    (before, names(pool, PUBLIC_EXECUTABLE).await)
}

/// The ledger as the old engine's push left it: the open functions recorded as they are live, and
/// their desired definition not the one this engine wants, and the bootstrap at the version before
/// the audit function was revoked. Without it the reopened `acl` reads as a
/// hand edit made after the push, which a push refuses to overwrite unprompted.
async fn record_as_the_old_engine_did(pool: &PgPool) {
    // The bootstrap that made the studio audit function ran once, and runs again only when its
    // statements changed: the recorded version is the old engine's.
    common::exec(
        pool,
        "UPDATE _supatype.engine_bootstrap SET version = 'sha256:pre-fix' WHERE id = 1",
    )
    .await
    .expect("record the old bootstrap");
    let state = common::live_state(pool).await;
    let open = state.fingerprints.iter().filter(|f| {
        f.kind == ObjectKind::Function
            && f.schema == "_supatype"
            && f.definition.contains("PUBLIC=EXECUTE")
    });
    for f in open {
        sqlx::query(
            "UPDATE _supatype.managed_objects SET live_fp = $1, live_def = $2, desired_fp = 'pre-fix'
              WHERE kind = $3 AND schema_name = $4 AND parent = $5 AND name = $6",
        )
        .bind(&f.fingerprint)
        .bind(&f.definition)
        .bind(f.kind.as_str())
        .bind(&f.schema)
        .bind(&f.parent)
        .bind(&f.name)
        .execute(pool)
        .await
        .expect("record the function as the old engine did");
    }
}

async fn assert_api_roles_keep_the_helpers(pool: &PgPool, name: &str) {
    let helpers = names(pool, API_ROLE_HELPERS).await;
    assert!(!helpers.is_empty(), "{name}: no helpers to check");
    for helper in &helpers {
        for role in ["anon", "authenticated", "service_role"] {
            assert!(
                can_execute(pool, role, helper).await,
                "{name}: {role} lost {helper}"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_closes_the_version_and_draft_helpers_an_older_engine_left_open() {
    let scenarios: [(&str, Fixture); 2] = [
        ("versions", || {
            fixture(include_str!("fixtures/versioned_blog.json"))
        }),
        ("drafts", || {
            fixture(include_str!("fixtures/drafts_content.json"))
        }),
    ];
    for (name, schema) in scenarios {
        common::with_integration_pool(|pool| async move {
            let (before, after) = upgrade(&pool, &schema(), &schema()).await;
            for helper in ["sees_draft_", "sees_all_drafts", "preview_epoch"] {
                assert!(
                    contains(&before, helper),
                    "{name}: {helper} should start open to PUBLIC: {before:?}"
                );
            }
            if name == "versions" {
                assert!(
                    contains(&before, "_versions_guard"),
                    "{name}: the guard should start open: {before:?}"
                );
                assert!(
                    contains(&before, "ledger_versions_audit"),
                    "{name}: the audit trigger should start open: {before:?}"
                );
            }
            assert!(
                after.is_empty(),
                "{name}: PUBLIC can still execute {after:?}"
            );
            assert_api_roles_keep_the_helpers(&pool, name).await;
        })
        .await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_closes_the_studio_membership_audit_trigger_an_older_engine_left_open() {
    common::with_integration_pool(|pool| async move {
        let schema = || fixture(include_str!("fixtures/rls_access_rules.json"));
        let (before, after) = upgrade(&pool, &schema(), &schema()).await;
        assert!(
            contains(&before, "audit_studio_membership_change"),
            "the trigger function should start open to PUBLIC: {before:?}"
        );
        assert!(after.is_empty(), "PUBLIC can still execute {after:?}");
    })
    .await;
}
