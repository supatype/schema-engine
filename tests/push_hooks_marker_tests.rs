//! A push that rewrites rows in model tables tells the change-log listener to skip its after-hooks.
//!
//! Converting a column's kind rewrites every row through an `UPDATE`, and the server's listener would
//! otherwise run each table's after-hooks once per rewritten row. A schema change is not a change
//! anyone's hooks should act on, so the push's transaction opens with the skip marker, unless the
//! push is run with `run_hooks`.

mod common;

use serde_json::{json, Value};
use supatype_engine::parser::{self, ast::SchemaAst};
use supatype_engine::push::ApplyOptions;

/// One `hm_note` table whose `body` field is `body`.
fn note(body: Value) -> SchemaAst {
    let model = json!({
        "name": "Note",
        "fields": {
            "id": { "kind": "uuid", "primaryKey": true, "required": true,
                    "default": { "kind": "genRandomUuid" },
                    "annotations": { "db": { "pgType": "UUID", "unique": false } } },
            "body": body
        },
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": { "tableName": "hm_note", "indexes": [] },
                         "platform": { "access": { "read": { "type": "public" } } } }
    });
    let doc = json!({ "astVersion": 2, "models": [model] });
    parser::parse(&doc.to_string()).expect("the fixture parses")
}

fn json_body() -> Value {
    json!({ "kind": "json", "required": false,
            "annotations": { "db": { "pgType": "JSONB", "unique": false } } })
}

fn rich_text_body() -> Value {
    json!({ "kind": "richText", "required": false,
            "annotations": { "db": { "pgType": "JSONB", "unique": false } } })
}

const INSERT_NOTE: &str = "INSERT INTO hm_note (body) VALUES ('\"hello\"'::jsonb)";

/// A write to `hm_note` in a transaction that opens with the skip marker, as a seed's does: the
/// control that shows the slot decodes the marker and the probe recognises it.
async fn marked_insert(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("begins");
    supatype_engine::hooks_marker::skip_hooks(&mut tx)
        .await
        .expect("the marker is written");
    sqlx::query(INSERT_NOTE)
        .execute(&mut *tx)
        .await
        .expect("the control row is written");
    tx.commit().await.expect("commits");
}

/// The transaction a push converting `hm_note.body` from JSON to rich text writes its rows in, as
/// the change log decodes it, once the [`marked_insert`] control after it is seen to carry its
/// marker. The conversion rewrites the stored row through an `UPDATE`.
async fn conversion_transaction(pool: &sqlx::PgPool, options: ApplyOptions) -> Vec<Value> {
    common::push(pool, &note(json_body()))
        .await
        .expect("first push");
    common::exec(pool, INSERT_NOTE)
        .await
        .expect("a row to convert");
    let slot = common::open_slot(pool).await;
    common::push_with(pool, &note(rich_text_body()), options)
        .await
        .expect("the conversion pushes");
    marked_insert(pool).await;
    let changes = common::drain_slot(pool, &slot).await;
    let mut written = common::transactions_writing(&changes, "hm_note");
    assert_eq!(
        written.len(),
        2,
        "the conversion, then the control: {changes:#?}"
    );
    assert!(
        common::opens_with_one_skip_marker(&written[1]),
        "the control's marker is seen: {changes:#?}"
    );
    written.remove(0)
}

fn force() -> ApplyOptions {
    ApplyOptions {
        force: true,
        ..ApplyOptions::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_that_rewrites_rows_skips_after_hooks() {
    common::with_integration_pool(|pool| async move {
        let rewrite = conversion_transaction(&pool, force()).await;
        assert!(common::opens_with_one_skip_marker(&rewrite), "{rewrite:#?}");
    })
    .await;
}

/// `run_hooks` keeps them firing: the same rewrite carries no marker.
#[tokio::test(flavor = "multi_thread")]
async fn run_hooks_keeps_a_push_from_skipping_them() {
    common::with_integration_pool(|pool| async move {
        let options = ApplyOptions {
            run_hooks: true,
            ..force()
        };
        let rewrite = conversion_transaction(&pool, options).await;
        assert_eq!(common::hooks_markers(&rewrite), 0, "{rewrite:#?}");
    })
    .await;
}

/// Slot names are the cluster's, not the database's, and these tests run side by side against one
/// cluster in CI: two probes open at once must not take the same name.
#[tokio::test(flavor = "multi_thread")]
async fn two_probes_can_be_open_at_once() {
    common::with_integration_pool(|pool| async move {
        let first = common::open_slot(&pool).await;
        let second = common::open_slot(&pool).await;
        assert_ne!(first, second);
        common::drain_slot(&pool, &first).await;
        common::drain_slot(&pool, &second).await;
    })
    .await;
}
