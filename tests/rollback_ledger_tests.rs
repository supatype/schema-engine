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

/// An engine from before Phase 4.0 stored `sql_down` as a script with its own `BEGIN`/`COMMIT`.
/// Run inside the rollback's transaction, its `COMMIT` ended that transaction after the objects
/// came back and before the history and the ledger were updated.
#[tokio::test]
async fn a_legacy_rollback_script_runs_inside_the_rollbacks_transaction() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts("title")).await.unwrap();
        push(&pool, &posts("body")).await.unwrap();
        exec(
            &pool,
            "UPDATE _supatype.migrations
                SET sql_down = E'-- ROLLBACK MIGRATION\\nBEGIN;\\n' || sql_down || E'\\nCOMMIT;\\n'
              WHERE id = (SELECT max(id) FROM _supatype.migrations)",
        )
        .await
        .unwrap();
        // The rollback's last step fails, after the legacy script's `COMMIT` would have run.
        exec(
            &pool,
            "CREATE FUNCTION public.refuse() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'refused'; END; $$;
             CREATE TRIGGER refuse BEFORE UPDATE ON _supatype.migrations
               FOR EACH ROW EXECUTE FUNCTION public.refuse();",
        )
        .await
        .unwrap();

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect_err("the history update is refused");
        assert!(
            index_exists(&pool, "posts_body_idx").await,
            "the objects' rollback went back with the failed history update"
        );
        assert!(!index_exists(&pool, "posts_title_idx").await);

        exec(&pool, "DROP TRIGGER refuse ON _supatype.migrations")
            .await
            .unwrap();
        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the legacy script rolls back");
        assert!(index_exists(&pool, "posts_title_idx").await);
        assert!(!index_exists(&pool, "posts_body_idx").await);
    })
    .await;
}
