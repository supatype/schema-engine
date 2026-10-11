//! Every model table a push manages has `REPLICA IDENTITY FULL` (F68).
//!
//! Realtime judges a `DELETE` from the whole old row: it delivers the event only to a subscriber
//! whose rules let them see that row. The WAL carries the whole old row only under `REPLICA
//! IDENTITY FULL`, so without it end users get no `DELETE` events at all. The push sets it on every
//! model and junction table, records it in the ledger so a change back by hand is reported and put
//! back, and leaves every other table as it is.

mod common;

use serde_json::json;
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst, push};

use common::{exec, push};

fn notes() -> SchemaAst {
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Note",
            "fields": {
                "id": { "kind": "uuid", "primaryKey": true, "required": true,
                        "annotations": { "db": { "pgType": "UUID", "unique": false } } },
                "body": { "kind": "text", "required": false,
                          "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
            },
            "options": { "timestamps": false, "softDelete": false, "singleton": false },
            "annotations": { "db": { "tableName": "notes" },
                             "platform": { "access": { "read": { "type": "public" } } } }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

async fn replica_identity(pool: &PgPool, table: &str) -> String {
    sqlx::query_scalar("SELECT relreplident::text FROM pg_class WHERE oid = $1::regclass")
        .bind(table)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_push_sets_full_on_model_tables_and_leaves_other_tables_alone() {
    common::with_integration_pool(|pool| async move {
        exec(&pool, "CREATE TABLE public.mine (id int PRIMARY KEY)")
            .await
            .unwrap();
        let ast = notes();
        push(&pool, &ast).await.unwrap();
        assert_eq!(replica_identity(&pool, "public.notes").await, "f");
        assert_eq!(
            replica_identity(&pool, "public.mine").await,
            "d",
            "a table that is not Supatype's was changed"
        );
        let again = push(&pool, &ast).await.unwrap();
        assert!(matches!(again, push::Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

#[tokio::test]
async fn a_replica_identity_set_back_by_hand_is_reported_and_put_back() {
    common::with_integration_pool(|pool| async move {
        let ast = notes();
        push(&pool, &ast).await.unwrap();
        exec(&pool, "ALTER TABLE public.notes REPLICA IDENTITY DEFAULT")
            .await
            .unwrap();

        let report = common::doctor(&pool, &ast).await;
        let drifted: Vec<String> = report
            .drifted
            .iter()
            .map(|i| format!("{} {}.{}", i.kind, i.table, i.name))
            .collect();
        assert_eq!(
            drifted,
            ["replica_identity notes.replica_identity"],
            "{report:#?}"
        );

        push(&pool, &ast).await.expect("the push puts it back");
        assert_eq!(replica_identity(&pool, "public.notes").await, "f");
        assert!(common::doctor(&pool, &ast).await.drifted.is_empty());
    })
    .await;
}

/// A database an engine before this one pushed: the first push after the upgrade sets `FULL`,
/// and records it, with nothing to ask.
#[tokio::test]
async fn the_first_push_after_an_upgrade_sets_full_on_existing_tables() {
    common::with_integration_pool(|pool| async move {
        let ast = notes();
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "ALTER TABLE public.notes REPLICA IDENTITY DEFAULT;
             DELETE FROM _supatype.managed_objects WHERE kind = 'replica_identity'",
        )
        .await
        .unwrap();

        push(&pool, &ast).await.expect("the upgrade push applies");
        assert_eq!(replica_identity(&pool, "public.notes").await, "f");
        let again = push(&pool, &ast).await.unwrap();
        assert!(matches!(again, push::Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}
