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

/// `notes` under `table`, declared renamed from `notes` when it is called anything else.
fn notes_as(table: &str) -> SchemaAst {
    let mut doc = serde_json::to_value(notes()).unwrap();
    let db = &mut doc["models"][0]["annotations"]["db"];
    db["tableName"] = json!(table);
    if table != "notes" {
        db["renamedFrom"] = json!("notes");
    }
    serde_json::from_value(doc).expect("the AST round-trips")
}

/// Each `replica_identity` ledger row, as `parent status`.
async fn replica_identity_rows(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT parent || ' ' || status FROM _supatype.managed_objects
          WHERE kind = 'replica_identity' ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// A declared table rename carries the table's replica identity with it, as Postgres does: the
/// reconcile renames its row to the new table, sets nothing again and leaves no row on the old
/// name, and the next push is up to date.
#[tokio::test]
async fn a_declared_table_rename_moves_the_replica_identity_row_with_it() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &notes_as("notes")).await.unwrap();
        assert_eq!(replica_identity_rows(&pool).await, ["notes managed"]);

        let renamed = notes_as("memos");
        let plan = push::prepare(&pool, &renamed, "public").await.unwrap();
        let moved: Vec<String> = plan
            .reconcile
            .actions
            .iter()
            .filter_map(|a| match a {
                supatype_engine::ledger::reconcile::Action::Rename { key, from, .. }
                    if key.kind.as_str() == "replica_identity" =>
                {
                    Some(format!("{} -> {}", from.parent, key.parent))
                }
                _ => None,
            })
            .collect();
        assert_eq!(moved, ["notes -> memos"], "{:?}", plan.reconcile.actions);
        let sql = plan.migration(false).unwrap().file();
        assert!(!sql.contains("REPLICA IDENTITY"), "{sql}");
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .expect("the rename applies");

        assert_eq!(replica_identity(&pool, "public.memos").await, "f");
        assert_eq!(replica_identity_rows(&pool).await, ["memos managed"]);
        let again = push(&pool, &renamed).await.unwrap();
        assert!(matches!(again, push::Outcome::UpToDate { .. }), "{again:?}");

        // Rolled back, the table takes its old name and the row goes back with it.
        supatype_engine::state::migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the rename rolls back");
        assert_eq!(replica_identity(&pool, "public.notes").await, "f");
        assert_eq!(replica_identity_rows(&pool).await, ["notes managed"]);
    })
    .await;
}
