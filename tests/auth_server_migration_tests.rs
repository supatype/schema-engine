//! H9 (T1-N1): the auth server's own migrations must not change what a generated rule means.
//!
//! The auth server owns the `auth` schema, and on a fresh stack its migrations run about ten seconds
//! after the engine's first push. Three of them `CREATE OR REPLACE` `auth.uid()`, `auth.role()`,
//! `auth.email()` and `auth.jwt()`; its `auth.role()` reads only the top-level `role` claim, which
//! PostgREST pins to `authenticated`. Every generated rule that called `auth.role()` therefore
//! stopped matching an `app_metadata.role` until the next push put the engine's version back:
//! admins read masked columns as NULL and could not do what their role allowed.
//!
//! The generated rules now call the engine's own readers in `_supatype`, which nothing else
//! writes. These tests prove it two ways: no rendered statement calls an `auth.*` helper, and a
//! database whose `auth.*` helpers the auth server has replaced still honours `Role<...>` rules.

mod common;

use supatype_engine::{parser, parser::ast::SchemaAst, push};

/// The auth server's replacements, as `supatype-auth` ships them.
const AUTH_SERVER_FUNCTIONS: &str = include_str!("fixtures/auth_server_function_migrations.sql");

/// `users.email` is readable by `Role<"admin">` only, and a user row may be deleted by an admin.
const FIELD_FIXTURE: &str = include_str!("fixtures/rls_field_rules.json");

/// Every fixture the parser accepts, as `statement_attribution_tests` renders them.
const RENDERABLE: &[&str] = &[
    "awkward_names",
    "basic_blog",
    "cms_content",
    "conformance_matrix",
    "ecommerce",
    "five_model_blog",
    "geospatial",
    "kitchen_sink",
    "kitchen_sink_example",
    "many_to_many",
    "rls_access_rules",
    "rls_field_rules",
    "self_referential",
    "standup_relations",
    "vector_search",
    "versioned_blog",
];

/// The helpers the engine installs in `auth` for hand-written rules.
const AUTH_HELPERS: [&str; 7] = [
    "uid",
    "role",
    "jwt",
    "email",
    "claim",
    "claim_text",
    "roles",
];

fn fixture(name: &str) -> SchemaAst {
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    parser::parse(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

/// Each place in `sql` that calls an `auth.*` helper rather than defining it, as its line.
fn auth_helper_calls(sql: &str) -> Vec<String> {
    let mut calls = Vec::new();
    for line in sql.lines() {
        if line.trim_start().starts_with("--") {
            continue;
        }
        for (at, _) in line.match_indices("auth.") {
            let rest = &line[at + "auth.".len()..];
            let calls_helper = AUTH_HELPERS
                .iter()
                .any(|h| rest.starts_with(&format!("{h}(")));
            let defines_it = line[..at].trim_end().ends_with("FUNCTION");
            if calls_helper && !defines_it {
                calls.push(line.trim().to_string());
            }
        }
    }
    calls
}

// The rendered push of every fixture: policies, `can_*` predicates, field labels and views,
// storage policies and the drafts layer. The only `auth.*` left in it are the alias definitions.
#[test]
fn no_generated_statement_calls_an_auth_helper() {
    for name in RENDERABLE {
        let sql = push::fresh_migration(&fixture(name), "public", false)
            .unwrap()
            .up_script();
        let calls = auth_helper_calls(&sql);
        assert!(
            calls.is_empty(),
            "{name}: {} generated statement(s) call a helper the auth server replaces:\n  {}",
            calls.len(),
            calls.join("\n  ")
        );
    }
}

// The scan above has to be able to fail, or its silence proves nothing.
#[test]
fn the_scan_finds_a_call_and_ignores_a_definition() {
    let sql = "CREATE OR REPLACE FUNCTION auth.role() RETURNS text AS $$ SELECT 1 $$;\n\
               -- a comment naming auth.uid()\n\
               CREATE POLICY p ON t USING ((SELECT auth.role()) = 'admin');";
    assert_eq!(
        auth_helper_calls(sql),
        vec!["CREATE POLICY p ON t USING ((SELECT auth.role()) = 'admin');"]
    );
}

/// A transaction (rolled back by the caller) as a real signed-in user arrives: the database role
/// `authenticated`, and claims shaped as the auth server issues them, with the application role in
/// `app_metadata` and the top-level `role` pinned to `authenticated`.
async fn begin_as(
    pool: &sqlx::PgPool,
    app_role: &str,
) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut tx = pool.begin().await.expect("begin");
    let claims = format!(
        r#"{{"sub":"00000000-0000-4000-8000-00000000000a","role":"authenticated","app_metadata":{{"role":"{app_role}"}}}}"#
    );
    sqlx::raw_sql(&format!(
        "SET LOCAL request.jwt.claims = '{claims}'; SET LOCAL ROLE authenticated;"
    ))
    .execute(&mut *tx)
    .await
    .expect("assume the caller's identity");
    tx
}

async fn read_email(pool: &sqlx::PgPool, app_role: &str, id: &str) -> Option<String> {
    let mut tx = begin_as(pool, app_role).await;
    let email = sqlx::query_scalar("SELECT email FROM public.users WHERE id = $1::uuid")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .expect("the probe row is readable");
    tx.rollback().await.expect("rollback");
    email
}

async fn delete_count(pool: &sqlx::PgPool, app_role: &str, id: &str) -> u64 {
    let mut tx = begin_as(pool, app_role).await;
    let deleted = sqlx::query("DELETE FROM public.users WHERE id = $1::uuid")
        .bind(id)
        .execute(&mut *tx)
        .await
        .expect("the delete runs")
        .rows_affected();
    tx.rollback().await.expect("rollback");
    deleted
}

// The defect itself, on a real database: push, then let the auth server migrate, then read as an
// admin. Before the fix the admin's masked column read NULL and their delete matched no row.
#[tokio::test]
async fn role_rules_survive_the_auth_servers_function_migrations() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            return;
        }
        let ast = parser::parse(FIELD_FIXTURE).expect("fixture parses");
        common::push(&pool, &ast).await.expect("migration applies");

        let probe: String = sqlx::query_scalar(
            "INSERT INTO public.users (email, name) VALUES ('probe@example.com', 'probe') \
             RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .expect("seed a probe row");

        // What the auth server does on first boot, after the push.
        sqlx::raw_sql(AUTH_SERVER_FUNCTIONS)
            .execute(&pool)
            .await
            .expect("apply the auth server's function migrations");
        let replaced: String = sqlx::query_scalar(
            "SELECT prosrc FROM pg_proc WHERE oid = 'auth.role()'::regprocedure",
        )
        .fetch_one(&pool)
        .await
        .expect("auth.role() exists");
        assert!(
            !replaced.contains("app_metadata"),
            "the auth server's auth.role() was not installed, so this proves nothing: {replaced}"
        );

        assert_eq!(
            read_email(&pool, "admin", &probe).await.as_deref(),
            Some("probe@example.com"),
            "an admin's field rule stopped matching once the auth server replaced auth.role()"
        );
        assert_eq!(
            read_email(&pool, "member", &probe).await,
            None,
            "a non-admin read the column the field rule restricts"
        );
        assert_eq!(
            delete_count(&pool, "member", &probe).await,
            0,
            "a non-admin deleted a row only an admin may"
        );
        assert_eq!(
            delete_count(&pool, "admin", &probe).await,
            1,
            "an admin's row rule stopped matching once the auth server replaced auth.role()"
        );
    })
    .await;
}

// The aliases stay for hand-written rules, and a push puts back any the auth server replaced.
#[tokio::test]
async fn a_push_restores_the_auth_aliases() {
    common::with_integration_pool(|pool| async move {
        let ast = fixture("rls_access_rules");
        common::push(&pool, &ast).await.expect("first push");
        sqlx::raw_sql(AUTH_SERVER_FUNCTIONS)
            .execute(&pool)
            .await
            .expect("apply the auth server's function migrations");

        common::push(&pool, &ast).await.expect("second push");

        let role: String = sqlx::query_scalar(
            "SELECT prosrc FROM pg_proc WHERE oid = 'auth.role()'::regprocedure",
        )
        .fetch_one(&pool)
        .await
        .expect("auth.role() exists");
        assert!(
            role.contains("_supatype.jwt_role()"),
            "the push did not put the alias back: {role}"
        );
        for helper in AUTH_HELPERS {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                                 WHERE n.nspname = 'auth' AND p.proname = $1)",
            )
            .bind(helper)
            .fetch_one(&pool)
            .await
            .expect("read the catalog");
            assert!(exists, "auth.{helper}() is no longer installed");
        }
    })
    .await;
}

// The `_sso` script names its caller through the engine's reader too, and it has to apply at all:
// its policies were spelled `CREATE POLICY IF NOT EXISTS`, which Postgres does not have, so the
// script failed at the first one.
#[tokio::test]
async fn the_sso_schema_applies_twice_and_scopes_tokens_to_their_owner() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &fixture("rls_access_rules"))
            .await
            .expect("a push installs the claim readers");
        sqlx::raw_sql("CREATE TABLE IF NOT EXISTS auth.users (id uuid PRIMARY KEY)")
            .execute(&pool)
            .await
            .expect("the users table the script references");

        let sso = supatype_engine::generator::sql::sso::generate(
            &supatype_engine::parser::ast::SsoConfigAst {
                enabled: true,
                access_token_expiry_secs: 3600,
                refresh_token_expiry_days: 30,
                key_rotation_days: 90,
            },
        )
        .expect("render the sso schema");
        for attempt in ["first", "second"] {
            sqlx::raw_sql(&sso)
                .execute(&pool)
                .await
                .unwrap_or_else(|e| panic!("the sso schema did not apply a {attempt} time: {e}"));
        }

        let mine = "00000000-0000-4000-8000-00000000000a";
        let theirs = "00000000-0000-4000-8000-00000000000b";
        sqlx::raw_sql(&format!(
            "INSERT INTO auth.users (id) VALUES ('{mine}'), ('{theirs}') ON CONFLICT DO NOTHING;
             INSERT INTO _sso.oauth_clients (id, client_secret, name)
               VALUES ('00000000-0000-4000-8000-0000000000c1', 'secret', 'client');
             INSERT INTO _sso.oauth_access_tokens (client_id, user_id, expires_at)
               SELECT '00000000-0000-4000-8000-0000000000c1', u, now() + interval '1 hour'
                 FROM unnest(ARRAY['{mine}', '{theirs}']::uuid[]) AS u;
             GRANT USAGE ON SCHEMA _sso TO authenticated;
             GRANT SELECT ON _sso.oauth_access_tokens TO authenticated;"
        ))
        .execute(&pool)
        .await
        .expect("seed a token for each of two users");

        let mut tx = begin_as(&pool, "member").await;
        let owners: Vec<String> =
            sqlx::query_scalar("SELECT user_id::text FROM _sso.oauth_access_tokens")
                .fetch_all(&mut *tx)
                .await
                .expect("read the tokens as their owner");
        tx.rollback().await.expect("rollback");
        assert_eq!(
            owners,
            vec![mine.to_string()],
            "a user saw another user's tokens"
        );
    })
    .await;
}
