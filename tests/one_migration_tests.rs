//! Phase 4.0 of the managed-object ownership plan: one migration, rendered once.
//!
//! `supatype migrate` printed the differ's file, the push applied the differ's body with the
//! reconcile's statements appended, and the history stored a third rendering with the reconcile's
//! rollback pasted in front of the file's `BEGIN`. The three are now one `Migration { up, down,
//! hash }`: what `migrate` prints is what the push applies and what the history records, and the
//! reconcile's statements sit inside the transaction in both directions.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    generator::sql::migration::migration_hash, parser, parser::ast::SchemaAst, push,
    state::migration_history,
};

fn schema(name_max: u32) -> SchemaAst {
    let doc = json!({
        "astVersion": 2,
        "locales": ["en"],
        "defaultLocale": "en",
        "publishing": {
            "draftVisibility": ["admin", "developer", "editor"],
            "previewDefaultTtl": 900,
            "previewMaxRecordTtl": 604800,
            "previewMaxProjectTtl": 86400,
            "previewAllowProjectScope": true
        },
        "models": [{
            "name": "Product",
            "fields": {
                "id": { "kind": "integer", "primaryKey": true, "required": true,
                        "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
                "name": { "kind": "text", "required": true,
                          "validation": { "maxLength": name_max },
                          "check": format!("char_length(\"{{name}}\") <= {name_max}"),
                          "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
            },
            "options": { "timestamps": false, "softDelete": false },
            "annotations": {
                "db": { "tableName": "products", "indexes": [], "constraints": Vec::<Value>::new() },
                "platform": {}
            }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

use common::{exec, push};

async fn name_bound(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'products_name_bounds'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// `(sql_up, sql_down)` of the latest migration the history holds.
async fn latest_history(pool: &PgPool) -> (String, Option<String>) {
    sqlx::query_as(
        "SELECT sql_up, sql_down FROM _supatype.migrations WHERE status = 'applied' \
         ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Every statement between `from` and `to` in `text` sits inside a `BEGIN;` ... `COMMIT;` pair.
fn inside_a_transaction(text: &str, needle: &str) -> bool {
    let at = text
        .find(needle)
        .unwrap_or_else(|| panic!("{needle} is in:\n{text}"));
    let begin = text[..at].rfind("BEGIN;");
    let commit = text[..at].rfind("COMMIT;");
    match (begin, commit) {
        (Some(b), Some(c)) => b > c,
        (Some(_), None) => true,
        _ => false,
    }
}

#[tokio::test]
async fn the_migration_file_carries_the_reconcile_inside_the_transaction_both_ways() {
    common::with_integration_pool(|pool| async move {
        let loose = schema(10);
        let tight = schema(3);
        push(&pool, &loose).await.unwrap();

        let plan = push::plan(&pool, &tight, "public").await.unwrap();
        assert!(
            plan.diff.operations.is_empty(),
            "the bound is the reconcile's, not the differ's: {:?}",
            plan.diff.operations
        );
        let migration = plan.migration(false).unwrap();
        let file = migration.file();

        let (up, down) = file
            .split_once("ROLLBACK MIGRATION")
            .expect("the file has a rollback section");
        assert!(
            up.contains("<= 3"),
            "the forward section carries the new bound:\n{up}"
        );
        assert!(
            inside_a_transaction(up, "<= 3"),
            "inside the forward transaction:\n{up}"
        );
        assert!(
            down.contains("<= 10"),
            "the rollback section restores the previous bound:\n{down}"
        );
        assert!(
            inside_a_transaction(down, "<= 10"),
            "inside the rollback transaction:\n{down}"
        );

        assert_eq!(migration.hash, migration_hash(&migration.up()));
        assert!(file.contains(&format!("-- Hash: {}", migration.hash)));
        let unchanged = push::plan(&pool, &loose, "public")
            .await
            .unwrap()
            .migration(false)
            .unwrap();
        assert_ne!(
            unchanged.hash, migration.hash,
            "a reconcile change is a different migration"
        );
    })
    .await;
}

#[tokio::test]
async fn the_history_holds_what_the_push_ran_and_rolling_back_restores_the_previous_check() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(10)).await.unwrap();
        let outcome = push(&pool, &schema(3)).await.unwrap();
        let push::Outcome::Applied { operations, .. } = outcome else {
            panic!("a tightened bound applies: {outcome:?}");
        };
        assert_eq!(operations, 2, "the drop and the add of the one check");
        assert!(name_bound(&pool).await.contains("<= 3"));

        let (sql_up, sql_down) = latest_history(&pool).await;
        assert!(sql_up.contains("<= 3"), "{sql_up}");
        let sql_down = sql_down.expect("a push that changed something can be rolled back");
        assert!(sql_down.contains("<= 10"), "{sql_down}");
        assert!(
            !sql_down.contains("BEGIN;"),
            "the statements only; the rollback owns its transaction:\n{sql_down}"
        );

        migration_history::apply_rollback(&pool, "public")
            .await
            .unwrap();
        assert!(
            name_bound(&pool).await.contains("<= 10"),
            "the previous check is back"
        );
        exec(&pool, "INSERT INTO public.products VALUES (1, 'five5')")
            .await
            .expect("the previous bound is what the database enforces");
    })
    .await;
}
