//! A table whose statistics are missing is analysed before a push decides about it (LK3).
//!
//! Whether a table has rows decides whether a new index is built concurrently, and its estimated
//! rows decide whether a rewrite needs consent. Both were read from statistics a table that was
//! never analysed does not have: such a table read as empty, so the index was built inside the
//! push's transaction under a lock that stops writes, and a rewrite of 120k rows ran without
//! asking. Now a table with no statistics is analysed first.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst};

use common::{exec, push};

fn items(qty_bigint: bool, label_index: bool) -> SchemaAst {
    let qty: Value = if qty_bigint {
        json!({ "kind": "bigInt", "required": false,
                "annotations": { "db": { "pgType": "BIGINT" } } })
    } else {
        json!({ "kind": "integer", "required": false,
                "annotations": { "db": { "pgType": "INTEGER" } } })
    };
    let indexes = if label_index {
        json!([{ "fields": ["label"], "unique": false, "using": "btree" }])
    } else {
        json!([])
    };
    let doc = json!({ "astVersion": 2, "models": [{
        "name": "Item",
        "fields": {
            "id": { "kind": "uuid", "primaryKey": true, "required": true,
                    "default": { "kind": "genRandomUuid" },
                    "annotations": { "db": { "pgType": "UUID", "unique": false } } },
            "label": { "kind": "text", "required": false,
                       "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
            "qty": qty
        },
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": { "tableName": "items", "indexes": indexes },
                         "platform": { "access": {} } } }]});
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// `rows` rows in `items`, with no statistics left for the push to read: never analysed or
/// vacuumed (`reltuples` is -1), autovacuum off, and the counters reset.
async fn fill_unanalysed(pool: &PgPool, rows: u32) {
    exec(
        pool,
        &format!(
            "ALTER TABLE public.items SET (autovacuum_enabled = false);
             INSERT INTO public.items (label, qty)
             SELECT md5(i::text), i FROM generate_series(1, {rows}) AS i;"
        ),
    )
    .await
    .unwrap();
    // Counted once the insert's statistics are flushed; reset after, so none are left.
    exec(
        pool,
        "SELECT pg_stat_force_next_flush();
         SELECT pg_stat_reset_single_table_counters('public.items'::regclass);",
    )
    .await
    .unwrap();
    let reltuples: f32 =
        sqlx::query_scalar("SELECT reltuples FROM pg_class WHERE oid = 'public.items'::regclass")
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(reltuples < 0.0, "never analysed: {reltuples}");
}

/// LK3: an index on a table with rows and no statistics is built concurrently after commit.
#[tokio::test(flavor = "multi_thread")]
async fn an_index_on_an_unanalysed_table_with_rows_is_built_concurrently() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &items(false, false)).await.unwrap();
        fill_unanalysed(&pool, 5_000).await;

        let target = items(false, true);
        let plan = supatype_engine::push::plan(&pool, &target, "public")
            .await
            .unwrap();
        assert!(
            plan.online.with_rows.contains("items"),
            "the table was read as empty: {:?}",
            plan.online.with_rows
        );
        let migration = plan.migration(false).unwrap();
        assert_eq!(
            migration.after_commit.indexes.len(),
            1,
            "the index is built after commit: {:?}",
            migration.after_commit
        );
    })
    .await;
}

/// LK3: a rewrite of an unanalysed table of 120k rows is flagged with its real size and needs
/// consent.
#[tokio::test(flavor = "multi_thread")]
async fn a_rewrite_of_a_large_unanalysed_table_needs_consent() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &items(false, false)).await.unwrap();
        fill_unanalysed(&pool, 120_000).await;

        let err = push(&pool, &items(true, false))
            .await
            .expect_err("a rewrite of 120k rows needs consent");
        let message = format!("{err:#}");
        assert!(message.contains("rewrite"), "{message}");
        assert!(message.contains("items"), "{message}");
    })
    .await;
}
