//! Who may reach what the engine creates for Studio, and for the affordance predicates.
//!
//! The Studio statistics functions run as their owner, so whatever they read they read past every
//! grant and policy: `daily_content_creates` used to count the rows of any table it was named, for
//! anon too. `dashboard_views` was writable by anon with no RLS. These tests take each caller in
//! turn (anon, a signed-in user who is not a Studio member, a member under either identity,
//! `service_role`) through the same switch PostgREST makes: the claims GUC and `SET LOCAL ROLE`.

mod common;

use supatype_engine::parser;

const FIXTURE: &str = include_str!("fixtures/rls_access_rules.json");

const MEMBER: &str = "a0000000-0000-0000-0000-00000000000a";
const STRANGER: &str = "b0000000-0000-0000-0000-00000000000b";
/// A Supatype Cloud account, admitted by a row keyed on `platform_user_id` rather than `user_id`.
const PLATFORM_MEMBER: &str = "c0000000-0000-0000-0000-00000000000c";

/// One API caller: the database role PostgREST switches to and the claims it would have verified.
#[derive(Clone, Copy, Debug)]
enum Caller {
    Anon,
    NonMember,
    Member,
    PlatformMember,
    ServiceRole,
}

impl Caller {
    fn role(self) -> &'static str {
        match self {
            Caller::Anon => "anon",
            Caller::NonMember | Caller::Member | Caller::PlatformMember => "authenticated",
            Caller::ServiceRole => "service_role",
        }
    }

    fn claims(self) -> String {
        let signed_in = |sub: &str| format!(r#"{{"role":"authenticated","sub":"{sub}"}}"#);
        match self {
            Caller::Anon => r#"{"role":"anon"}"#.to_string(),
            Caller::NonMember => signed_in(STRANGER),
            Caller::Member => signed_in(MEMBER),
            Caller::PlatformMember => signed_in(PLATFORM_MEMBER),
            Caller::ServiceRole => r#"{"role":"service_role"}"#.to_string(),
        }
    }
}

/// Every caller the Studio gate must admit: both identities a membership row can hold, and the
/// service role.
const ADMITTED: [Caller; 3] = [Caller::Member, Caller::PlatformMember, Caller::ServiceRole];

/// Run `sql` as `caller` and roll back. `Ok` with the number of rows, or the SQLSTATE it failed with.
async fn run_as(pool: &sqlx::PgPool, caller: Caller, sql: &str) -> Result<usize, String> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::raw_sql(&format!(
        "SET LOCAL request.jwt.claims = '{}'; SET LOCAL ROLE {};",
        caller.claims(),
        caller.role()
    ))
    .execute(&mut *tx)
    .await
    .expect("assume the caller's identity");
    let result = sqlx::query(sql).fetch_all(&mut *tx).await;
    tx.rollback().await.expect("rollback");
    match result {
        Ok(rows) => Ok(rows.len()),
        Err(sqlx::Error::Database(e)) => Err(e.code().map(|c| c.to_string()).unwrap_or_default()),
        Err(e) => panic!("{sql} as {caller:?}: {e}"),
    }
}

/// The fixture pushed, a Studio member under each identity, and a private table with rows nobody
/// but its owner reads.
async fn set_up(pool: &sqlx::PgPool) {
    let ast = parser::parse(FIXTURE).expect("fixture parses");
    common::push(pool, &ast).await.expect("migration applies");
    sqlx::raw_sql(&format!(
        "INSERT INTO _supatype.studio_members (user_id, role) VALUES ('{MEMBER}', 'developer');
         INSERT INTO _supatype.studio_members (platform_user_id, role)
              VALUES ('{PLATFORM_MEMBER}', 'developer');
         CREATE TABLE public.private_log (id serial PRIMARY KEY, created_at timestamptz DEFAULT now());
         ALTER TABLE public.private_log ENABLE ROW LEVEL SECURITY;
         REVOKE ALL ON public.private_log FROM PUBLIC, anon, authenticated;
         INSERT INTO public.private_log DEFAULT VALUES;
         INSERT INTO public.private_log DEFAULT VALUES;"
    ))
    .execute(pool)
    .await
    .expect("seed a member and a private table");
}

const STATS_CALLS: [&str; 4] = [
    "SELECT * FROM supatype.db_stats()",
    "SELECT * FROM supatype.daily_signups(30)",
    "SELECT * FROM supatype.storage_stats()",
    "SELECT * FROM supatype.daily_content_creates('posts', 30)",
];

const PERMISSION_DENIED: &str = "42501";

#[tokio::test]
async fn studio_statistics_answer_only_service_role_and_members() {
    common::with_integration_pool(|pool| async move {
        set_up(&pool).await;
        for sql in STATS_CALLS {
            for caller in [Caller::Anon, Caller::NonMember] {
                assert_eq!(
                    run_as(&pool, caller, sql).await,
                    Err(PERMISSION_DENIED.to_string()),
                    "{caller:?} reached {sql}"
                );
            }
            for caller in ADMITTED {
                assert!(
                    run_as(&pool, caller, sql).await.is_ok(),
                    "{caller:?} was refused {sql}"
                );
            }
        }
    })
    .await;
}

#[tokio::test]
async fn daily_content_creates_counts_only_declared_model_tables() {
    common::with_integration_pool(|pool| async move {
        set_up(&pool).await;
        for name in [
            "private_log",
            "studio_members",
            "posts\"; SELECT 1; --",
            "Posts",
        ] {
            let sql = format!(
                "SELECT * FROM supatype.daily_content_creates('{}', 30)",
                name.replace('\'', "''")
            );
            assert_eq!(
                run_as(&pool, Caller::ServiceRole, &sql).await,
                Err("22023".to_string()),
                "{name} is not a model table, yet it was counted"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn studio_functions_are_not_executable_by_public_and_pin_their_search_path() {
    common::with_integration_pool(|pool| async move {
        set_up(&pool).await;
        let rows: Vec<(String, bool, bool, Option<String>)> = sqlx::query_as(
            "SELECT p.oid::regprocedure::text,
                    has_function_privilege('anon', p.oid, 'EXECUTE'),
                    EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                             WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'),
                    array_to_string(p.proconfig, ',')
               FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'supatype'",
        )
        .fetch_all(&pool)
        .await
        .expect("read the supatype functions");
        assert!(rows.len() >= 4, "the Studio functions are missing: {rows:?}");
        for (name, anon, public, config) in rows {
            assert!(!anon, "anon may execute {name}");
            assert!(!public, "PUBLIC may execute {name}");
            assert!(
                config.as_deref().is_some_and(|c| c.contains("search_path=")),
                "{name} sets no search_path: {config:?}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn dashboard_views_are_for_service_role_and_members_only() {
    common::with_integration_pool(|pool| async move {
        set_up(&pool).await;
        sqlx::raw_sql("INSERT INTO supatype.dashboard_views (name) VALUES ('seeded')")
            .execute(&pool)
            .await
            .expect("seed a view");
        let read = "SELECT * FROM supatype.dashboard_views";
        let write = "INSERT INTO supatype.dashboard_views (name) VALUES ('mine') RETURNING id";
        // `WHERE true`: the image loads `safeupdate`, which refuses a DELETE with no WHERE.
        let wipe = "DELETE FROM supatype.dashboard_views WHERE true RETURNING id";

        for sql in [read, write, wipe] {
            assert_eq!(
                run_as(&pool, Caller::Anon, sql).await,
                Err(PERMISSION_DENIED.to_string()),
                "anon reached {sql}"
            );
        }
        assert_eq!(run_as(&pool, Caller::NonMember, read).await, Ok(0));
        assert_eq!(run_as(&pool, Caller::NonMember, wipe).await, Ok(0));
        assert_eq!(
            run_as(&pool, Caller::NonMember, write).await,
            Err(PERMISSION_DENIED.to_string()),
            "a non-member saved a dashboard view"
        );
        for caller in ADMITTED {
            assert_eq!(run_as(&pool, caller, read).await, Ok(1), "{caller:?}");
            assert_eq!(run_as(&pool, caller, write).await, Ok(1), "{caller:?}");
            assert_eq!(run_as(&pool, caller, wipe).await, Ok(1), "{caller:?}");
        }
    })
    .await;
}

/// A database bootstrapped by an earlier engine has the old grants on objects `CREATE OR REPLACE`
/// and `CREATE TABLE IF NOT EXISTS` leave alone. The next push has to take them away. That engine
/// recorded no bootstrap version (`_supatype.engine_bootstrap` came later), which is what makes
/// this engine run its bootstrap, Studio's objects included, on the first push after the upgrade.
#[tokio::test]
async fn a_push_takes_back_the_grants_an_earlier_engine_made() {
    common::with_integration_pool(|pool| async move {
        set_up(&pool).await;
        sqlx::raw_sql(
            "GRANT EXECUTE ON FUNCTION supatype.daily_content_creates(text, integer) TO PUBLIC, anon;
             GRANT SELECT, INSERT, UPDATE, DELETE ON supatype.dashboard_views TO anon;
             ALTER TABLE supatype.dashboard_views DISABLE ROW LEVEL SECURITY;
             DROP TABLE _supatype.engine_bootstrap;",
        )
        .execute(&pool)
        .await
        .expect("restore the old grants");

        let ast = parser::parse(FIXTURE).expect("fixture parses");
        common::push(&pool, &ast).await.expect("second push");

        assert_eq!(
            run_as(
                &pool,
                Caller::Anon,
                "SELECT * FROM supatype.daily_content_creates('posts', 30)"
            )
            .await,
            Err(PERMISSION_DENIED.to_string())
        );
        assert_eq!(
            run_as(&pool, Caller::Anon, "SELECT * FROM supatype.dashboard_views").await,
            Err(PERMISSION_DENIED.to_string())
        );
        assert_eq!(
            run_as(&pool, Caller::NonMember, "SELECT * FROM supatype.dashboard_views").await,
            Ok(0)
        );
    })
    .await;
}

/// The `can_*` predicates are `SECURITY INVOKER`, so `EXECUTE` decides nothing about rows; but a
/// role outside the API has no business calling them, and the API roles still must: policies and
/// the masking rewrite call them as the querying role.
#[tokio::test]
async fn can_predicates_are_executable_by_the_api_roles_only() {
    common::with_integration_pool(|pool| async move {
        set_up(&pool).await;
        let rows: Vec<(String, bool, bool, bool, bool)> = sqlx::query_as(
            "SELECT p.oid::regprocedure::text,
                    EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                             WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'),
                    has_function_privilege('anon', p.oid, 'EXECUTE'),
                    has_function_privilege('authenticated', p.oid, 'EXECUTE'),
                    has_function_privilege('service_role', p.oid, 'EXECUTE')
               FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'public' AND p.proname LIKE 'can\\_%'",
        )
        .fetch_all(&pool)
        .await
        .expect("read the predicates");
        assert!(!rows.is_empty(), "no can_* predicates were generated");
        for (name, public, anon, authenticated, service_role) in rows {
            assert!(!public, "PUBLIC may execute {name}");
            assert!(
                anon && authenticated && service_role,
                "an API role may not execute {name}"
            );
        }

        // And they still answer for the caller, through the row they are handed.
        assert_eq!(
            run_as(&pool, Caller::Anon, "SELECT can_read_users(u) FROM users u").await,
            Ok(0)
        );
    })
    .await;
}
