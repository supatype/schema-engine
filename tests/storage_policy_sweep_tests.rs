//! The storage policy sweep, against Postgres.
//!
//! A push drops every storage policy it created on an earlier push that the schema no longer
//! names: a removed bucket, a renamed model, the last bucket gone. It also drops the unmarked
//! `storage_<label>_*` policies engines before the marker wrote, because the caller roles now hold
//! INSERT, UPDATE and DELETE and those old policies would take effect. A policy someone wrote by
//! hand is never touched.

mod common;

use supatype_engine::generator::sql::storage;
use supatype_engine::parser;

const MEDIA: &str = r#"{
  "astVersion": 2,
  "models": [],
  "storageBuckets": [{
    "id": "media", "public": false, "accessMode": "private",
    "access": { "read": { "type": "authenticated" }, "create": { "type": "authenticated" } }
  }]
}"#;

const NO_BUCKETS: &str = r#"{ "astVersion": 2, "models": [], "storageBuckets": [] }"#;

fn storage_sql(ast: &str) -> String {
    storage::generate(&parser::parse(ast).expect("schema parses")).expect("storage sql generates")
}

async fn policies(pool: &sqlx::PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT polname::text FROM pg_policy WHERE polrelid = 'storage.objects'::regclass ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .expect("list policies")
}

#[tokio::test]
async fn removing_the_last_bucket_drops_ours_and_keeps_a_hand_written_policy() {
    common::with_integration_pool(|pool| async move {
        // The policies call `auth.uid()`, which a push installs first. A fresh database (what CI
        // gives each test) has no `auth` schema until it does.
        sqlx::raw_sql(&supatype_engine::generator::sql::rls::generate_auth_helpers())
            .execute(&pool)
            .await
            .expect("auth helpers apply");
        sqlx::raw_sql(&storage_sql(MEDIA))
            .execute(&pool)
            .await
            .expect("first push applies");
        assert_eq!(
            policies(&pool).await,
            vec!["storage_media_ins", "storage_media_sel"]
        );

        // What an engine before the marker left behind, and one the developer wrote.
        sqlx::raw_sql(
            "CREATE POLICY storage_old_del ON storage.objects FOR DELETE USING (TRUE);
             CREATE POLICY team_rule ON storage.objects FOR SELECT USING (FALSE);",
        )
        .execute(&pool)
        .await
        .expect("fixture policies");

        sqlx::raw_sql(&storage_sql(NO_BUCKETS))
            .execute(&pool)
            .await
            .expect("push with no buckets applies");
        assert_eq!(policies(&pool).await, vec!["team_rule"]);
    })
    .await;
}

#[tokio::test]
async fn the_sweep_does_nothing_on_a_database_that_never_had_storage() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql("DROP SCHEMA IF EXISTS storage CASCADE")
            .execute(&pool)
            .await
            .expect("no storage schema");
        sqlx::raw_sql(&storage_sql(NO_BUCKETS))
            .execute(&pool)
            .await
            .expect("a schema with no buckets pushes cleanly where storage never existed");
    })
    .await;
}
