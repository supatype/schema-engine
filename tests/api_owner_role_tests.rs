//! Tier 2's view owner is one role per database (TI2).
//!
//! The `api` views and their write triggers run as their owner, which holds the rows of every base
//! table they read, and every pushing role is made a member of it. A role is the server's, not a
//! database's, so with one shared `supatype_api_owner` every project on a shared server granted its
//! base tables to the same role, and any project's pushing role, a member of it, could act as the
//! owner of every other project's views. Now each database has its own,
//! `supatype_api_owner_<hash of the database's name>`, and a database the shared role served is
//! moved to its own by the next push, leaving the shared role nothing here. A push never drops the
//! shared role, which other databases may still use.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst, push::Outcome};

use common::{exec, push};

const SHARED: &str = "supatype_api_owner";

fn uuid_pk() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" },
            "annotations": { "db": { "pgType": "UUID", "unique": false } } })
}

fn masked() -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": [{
        "name": "Staff",
        "fields": {
            "id": uuid_pk(),
            "salary": { "kind": "integer", "required": false,
                        "annotations": { "db": { "pgType": "INTEGER" } } }
        },
        "options": { "timestamps": false, "softDelete": false },
        "annotations": {
            "db": { "tableName": "staff", "indexes": [] },
            "platform": { "access": {
                "read": { "type": "authenticated" },
                "fields": { "salary": { "read": { "type": "role", "roles": ["admin"] } } }
            } }
        }
    }]});
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// The API roles and the auth helpers, without `supatype_mask`, so a push picks tier 2.
async fn tier_two(pool: &PgPool) {
    exec(
        pool,
        "CREATE SCHEMA IF NOT EXISTS auth;
         DO $$ BEGIN
           BEGIN CREATE ROLE anon NOLOGIN NOINHERIT;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
           BEGIN CREATE ROLE authenticated NOLOGIN NOINHERIT;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
           BEGIN CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
         END $$;",
    )
    .await
    .unwrap();
    exec(
        pool,
        &supatype_engine::generator::sql::rls::generate_auth_helpers(),
    )
    .await
    .unwrap();
}

/// The role this database's views should be owned by, worked out in SQL from its name.
async fn expected_owner(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT 'supatype_api_owner_' ||
                left(encode(sha256(convert_to(current_database(), 'UTF8')), 'hex'), 10)",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn view_owner(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT pg_get_userbyid(relowner)::text FROM pg_class WHERE oid = 'api.staff'::regclass",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// TI2: the views are owned by this database's own role, which alone holds the base table's rows,
/// and a second push changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn the_views_are_owned_by_this_databases_own_role() {
    common::with_integration_pool(|pool| async move {
        tier_two(&pool).await;
        push(&pool, &masked()).await.unwrap();
        let owner = expected_owner(&pool).await;
        assert_eq!(view_owner(&pool).await, owner);
        let holds: bool =
            sqlx::query_scalar("SELECT has_table_privilege($1, 'public.staff', 'SELECT')")
                .bind(&owner)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(holds, "{owner} reads the base table");
        let again = push(&pool, &masked()).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

/// TI2: a database whose views the shared role owns, as the last engine left it, is moved to its
/// own role by the next push: the views and the write trigger change owner, and the shared role's
/// privileges here are taken away.
#[tokio::test(flavor = "multi_thread")]
async fn a_database_on_the_shared_role_is_moved_to_its_own() {
    common::with_integration_pool(|pool| async move {
        tier_two(&pool).await;
        push(&pool, &masked()).await.unwrap();
        let owner = expected_owner(&pool).await;
        // As the last engine left it: everything of the role's owned by the shared one, which
        // holds the base table's rows. Made by moving this database back to it.
        exec(
            &pool,
            &format!(
                "DO $$ BEGIN
                   BEGIN CREATE ROLE {SHARED} NOLOGIN NOBYPASSRLS NOINHERIT;
                   EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
                 END $$;
                 GRANT {SHARED} TO current_user;
                 GRANT SELECT, INSERT, UPDATE, DELETE ON public.staff TO {SHARED};
                 REASSIGN OWNED BY {owner} TO {SHARED};"
            ),
        )
        .await
        .unwrap();
        assert_eq!(view_owner(&pool).await, SHARED);
        // Recorded so, as the last engine recorded it: what the push finds is the engine's own.
        supatype_engine::inspect::rebaseline(&pool, &masked(), "public", true)
            .await
            .expect("record the shared role's ownership as the baseline");
        exec(
            &pool,
            &format!(
                "UPDATE _supatype.managed_objects
                    SET desired_sql = replace(desired_sql, '{owner}', '{SHARED}'),
                        desired_fp = 'as the last engine recorded it'
                  WHERE desired_sql LIKE '%{owner}%'"
            ),
        )
        .await
        .unwrap();

        let outcome = push(&pool, &masked()).await.unwrap();
        eprintln!("{outcome:?}");
        assert_eq!(view_owner(&pool).await, owner);
        let shared_holds: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)
                AND has_table_privilege($1, 'public.staff', 'SELECT')",
        )
        .bind(SHARED)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            !shared_holds,
            "the shared role still reads this database's table"
        );
        let again = push(&pool, &masked()).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}
