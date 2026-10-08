//! Rolling a push back puts the managed-object ledger back with the objects.
//!
//! A rollback runs the migration's `sql_down`, which restores the objects; until now the ledger
//! kept the rolled-back push's rows, so the next push read rows for objects that were gone and
//! none for ones that were back. Each push now records what it overwrote, and a rollback restores
//! it (`ledger::undo`).

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst, push, state::migration_history};

use common::{exec, push};

fn posts(index: &str) -> SchemaAst {
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Post",
            "fields": {
                "id": { "kind": "integer", "primaryKey": true, "required": true,
                        "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
                "title": { "kind": "text", "required": true,
                           "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
                "body": { "kind": "text", "required": true,
                          "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
            },
            "options": { "timestamps": false, "softDelete": false, "singleton": false },
            "annotations": { "db": { "tableName": "posts", "indexes": indexes(index) },
                             "platform": { "access": { "read": { "type": "public" } } } }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

fn indexes(field: &str) -> Value {
    json!([{ "fields": [field], "name": format!("posts_{field}_idx"), "unique": false, "using": "btree" }])
}

/// Every ledger row, in full but for its timestamps, in key order.
async fn ledger(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT concat_ws(' ', kind, schema_name, parent, name, desired_fp, live_fp, status,
                          coalesce(migration_id::text, '-'))
           FROM _supatype.managed_objects ORDER BY kind, schema_name, parent, name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn index_exists(pool: &PgPool, name: &str) -> bool {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("public.{name}"))
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn rolling_back_a_push_puts_the_ledger_back_as_it_was() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts("title")).await.unwrap();
        let before = ledger(&pool).await;

        // The second push drops the title index (removing its row) and adds the body index.
        push(&pool, &posts("body")).await.unwrap();
        assert_ne!(ledger(&pool).await, before);

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the second push rolls back");
        assert!(index_exists(&pool, "posts_title_idx").await);
        assert!(!index_exists(&pool, "posts_body_idx").await);
        assert_eq!(
            ledger(&pool).await,
            before,
            "the ledger kept the rolled-back push's rows"
        );

        // Ledger and database agree again, so the first schema has nothing left to do.
        let outcome = push(&pool, &posts("title")).await.unwrap();
        assert!(
            matches!(outcome, push::Outcome::UpToDate { .. }),
            "{outcome:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_migration_with_nothing_recorded_rolls_back_and_leaves_the_ledger_alone() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts("title")).await.unwrap();
        push(&pool, &posts("body")).await.unwrap();
        // As a migration an engine from before the undo record left it.
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects_undo WHERE true",
        )
        .await
        .unwrap();
        let after = ledger(&pool).await;

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("rolls back with nothing recorded");
        assert_eq!(ledger(&pool).await, after);
    })
    .await;
}

async fn table_comment(pool: &PgPool) -> Option<String> {
    sqlx::query_scalar("SELECT obj_description('public.posts'::regclass, 'pg_class')")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn rolling_back_the_push_that_took_over_a_stamped_table_puts_the_stamp_back() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts("title")).await.unwrap();
        // The upgrade: an older engine's stamped table, taken over by the push that takes the stamp
        // out of its comment.
        common::as_an_older_engine_left_it(&pool).await.unwrap();
        let stamp = table_comment(&pool).await;
        assert!(stamp
            .as_deref()
            .unwrap_or_default()
            .starts_with("supatype:managed"));
        push(&pool, &posts("title")).await.unwrap();
        assert_eq!(
            table_comment(&pool).await,
            None,
            "the stamp was not taken out"
        );

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the upgrade push rolls back");
        assert_eq!(
            table_comment(&pool).await,
            stamp,
            "the rollback removed the row and left the table with neither row nor stamp"
        );

        // Recognisably ours again, so the next push takes it over rather than refusing it.
        push(&pool, &posts("title"))
            .await
            .expect("the table is Supatype's after the rollback");
    })
    .await;
}

#[tokio::test]
async fn a_release_made_after_a_push_survives_rolling_that_push_back() {
    use supatype_engine::adopt;
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts("title")).await.unwrap();
        push(&pool, &posts("body")).await.unwrap();
        // Released after the push, outside any migration: not the push's to undo.
        let release = ["policy:posts.posts_select".to_string()];
        adopt::run(
            &pool,
            &posts("body"),
            "public",
            adopt::Request {
                release: &release,
                apply: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the second push rolls back");
        assert!(index_exists(&pool, "posts_title_idx").await);
        let status: String = sqlx::query_scalar(
            "SELECT status FROM _supatype.managed_objects
              WHERE kind = 'policy' AND parent = 'posts' AND name = 'posts_select'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(status, "released", "the rollback overwrote a later release");
    })
    .await;
}
