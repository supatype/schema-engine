//! Phase 4.3 of the managed-object ownership plan: indexes on the ledger.
//!
//! The six live tests every kind gets (plan section 11): created and recorded; untouched on a
//! second push; replaced when the definition changes; recreated when dropped by hand; dropped when
//! the schema stops asking; never touched when it was never ours. Then what this kind adds: the
//! indexes nobody declares (an `index: true` field, `deleted_at` for a soft-deleting model, the
//! singleton's `((TRUE))`) are recorded beside the declared ones; adding `index: true` to a column
//! that already exists creates the index, which the differ never did; and an index an older engine
//! stamped moves into the ledger and out of its comment.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    introspector::fingerprint::ObjectKind,
    ledger::{self, LedgerRow, Status},
    parser,
    parser::ast::SchemaAst,
    push,
};

fn int_pk() -> Value {
    json!({ "kind": "integer", "primaryKey": true, "required": true,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } })
}

fn text(indexed: bool) -> Value {
    json!({ "kind": "text", "required": false,
            "annotations": { "db": { "pgType": "TEXT", "unique": false, "index": indexed } } })
}

fn declared(fields: &[&str], unique: bool) -> Value {
    json!({ "fields": fields, "unique": unique, "using": "btree" })
}

/// `posts` with `title` and `body`, `title` indexed or not, the given declared indexes, and the
/// options asked for.
fn posts(title_indexed: bool, indexes: Vec<Value>, soft_delete: bool, singleton: bool) -> Value {
    json!({
        "name": "Post",
        "fields": { "id": int_pk(), "title": text(title_indexed), "body": text(false) },
        "options": { "timestamps": false, "softDelete": soft_delete, "singleton": singleton },
        "annotations": { "db": { "tableName": "posts", "indexes": indexes }, "platform": {} }
    })
}

fn schema(models: Vec<Value>) -> SchemaAst {
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
        "models": models
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

use common::{exec, push, push_with};

async fn index_rows(pool: &PgPool) -> Vec<LedgerRow> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == ObjectKind::Index)
        .collect()
}

async fn index_names(pool: &PgPool) -> Vec<String> {
    index_rows(pool)
        .await
        .into_iter()
        .map(|r| r.key.name)
        .collect()
}

/// `(definition, comment)` of an index on `posts`, or None when it is gone.
async fn live_index(pool: &PgPool, name: &str) -> Option<(String, Option<String>)> {
    sqlx::query_as(
        "SELECT pg_get_indexdef(c.oid), obj_description(c.oid, 'pg_class') \
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind = 'i' AND c.relname = $1",
    )
    .bind(name)
    .fetch_optional(pool)
    .await
    .unwrap()
}

fn applied(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::Applied { .. })
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

async fn force_push(pool: &PgPool, ast: &SchemaAst) -> push::Outcome {
    push_with(
        pool,
        ast,
        push::ApplyOptions {
            force: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn declared_and_implicit_indexes_are_recorded_on_creation_and_left_alone_on_a_second_push() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![posts(
            true,
            vec![declared(&["body"], false)],
            true,
            true,
        )]);
        assert!(applied(&push(&pool, &ast).await.unwrap()));

        assert_eq!(
            index_names(&pool).await,
            [
                "posts_body_idx",
                "posts_deleted_at_idx",
                "posts_singleton_idx",
                "posts_title_idx"
            ],
            "the declared index, the soft-delete index, the singleton's and the indexed field's"
        );
        let rows = index_rows(&pool).await;
        assert!(rows.iter().all(|r| r.status == Status::Managed));
        assert!(rows.iter().all(|r| r.migration_id.is_some()));
        assert!(
            rows.iter().all(|r| r.live_def.contains("method=btree")),
            "{rows:#?}"
        );
        // Indexes carry no stamp any more: the comment is the user's.
        for name in index_names(&pool).await {
            let (_, comment) = live_index(&pool, &name).await.unwrap();
            assert_eq!(comment, None, "{name} is stamped");
        }

        let again = push(&pool, &ast).await.unwrap();
        assert!(up_to_date(&again), "{again:?}");
        assert_eq!(index_rows(&pool).await, rows);
    })
    .await;
}

#[tokio::test]
async fn an_index_that_becomes_unique_is_replaced_and_the_database_enforces_it() {
    common::with_integration_pool(|pool| async move {
        push(
            &pool,
            &schema(vec![posts(
                false,
                vec![declared(&["body"], false)],
                false,
                false,
            )]),
        )
        .await
        .unwrap();
        let before = index_rows(&pool).await;

        let outcome = push(
            &pool,
            &schema(vec![posts(
                false,
                vec![declared(&["body"], true)],
                false,
                false,
            )]),
        )
        .await
        .unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        let (definition, _) = live_index(&pool, "posts_body_idx").await.unwrap();
        assert!(definition.contains("UNIQUE"), "{definition}");
        exec(
            &pool,
            "INSERT INTO public.posts (id, body) VALUES (1, 'same'), (2, 'same')",
        )
        .await
        .expect_err("the unique index is enforced");

        let after = index_rows(&pool).await;
        assert_ne!(
            after[0].desired_fp, before[0].desired_fp,
            "the intent changed"
        );
        assert_ne!(
            after[0].live_fp, before[0].live_fp,
            "and so did the catalog"
        );
    })
    .await;
}

#[tokio::test]
async fn a_removed_index_is_dropped_and_a_hand_added_one_survives() {
    common::with_integration_pool(|pool| async move {
        push(
            &pool,
            &schema(vec![posts(
                false,
                vec![declared(&["body"], false)],
                false,
                false,
            )]),
        )
        .await
        .unwrap();
        exec(
            &pool,
            "CREATE INDEX posts_their_idx ON public.posts (title)",
        )
        .await
        .unwrap();

        let outcome = force_push(&pool, &schema(vec![posts(false, vec![], false, false)])).await;
        assert!(applied(&outcome), "{outcome:?}");
        assert!(
            live_index(&pool, "posts_body_idx").await.is_none(),
            "ours is gone"
        );
        assert!(
            live_index(&pool, "posts_their_idx").await.is_some(),
            "theirs is untouched"
        );
        assert!(index_rows(&pool).await.is_empty());
    })
    .await;
}

#[tokio::test]
async fn an_owned_index_dropped_by_hand_is_recreated() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![posts(
            false,
            vec![declared(&["body"], false)],
            false,
            false,
        )]);
        push(&pool, &ast).await.unwrap();
        exec(&pool, "DROP INDEX public.posts_body_idx")
            .await
            .unwrap();

        let outcome = push(&pool, &ast).await.unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        assert!(live_index(&pool, "posts_body_idx").await.is_some());
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

#[tokio::test]
async fn indexing_a_column_that_already_exists_creates_the_index() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(vec![posts(false, vec![], false, false)]))
            .await
            .unwrap();
        assert!(live_index(&pool, "posts_title_idx").await.is_none());

        let outcome = push(&pool, &schema(vec![posts(true, vec![], false, false)]))
            .await
            .unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        assert!(
            live_index(&pool, "posts_title_idx").await.is_some(),
            "the differ only created an indexed field's index with the column"
        );
        assert_eq!(index_names(&pool).await, ["posts_title_idx"]);
    })
    .await;
}

#[tokio::test]
async fn an_index_stamped_by_an_older_engine_moves_into_the_ledger_and_out_of_its_comment() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(vec![posts(false, vec![], false, false)]))
            .await
            .unwrap();
        exec(
            &pool,
            "CREATE INDEX posts_body_idx ON public.posts (body);
             COMMENT ON INDEX public.posts_body_idx IS 'supatype:managed;kind=index;table=posts;fields=body;v=1'",
        )
        .await
        .unwrap();

        let ast = schema(vec![posts(false, vec![declared(&["body"], false)], false, false)]);
        assert!(applied(&push(&pool, &ast).await.unwrap()));
        let rows = index_rows(&pool).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, Status::Managed, "stamped: ours by its own record");
        let (_, comment) = live_index(&pool, "posts_body_idx").await.unwrap();
        assert_eq!(comment, None, "the stamp left the comment");
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

#[tokio::test]
async fn a_same_named_index_of_the_users_over_other_columns_refuses_the_push() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(vec![posts(false, vec![], false, false)]))
            .await
            .unwrap();
        exec(&pool, "CREATE INDEX posts_body_idx ON public.posts (title)")
            .await
            .unwrap();

        let refused = push(
            &pool,
            &schema(vec![posts(
                false,
                vec![declared(&["body"], false)],
                false,
                false,
            )]),
        )
        .await
        .expect_err("a same-named index over other columns is not ours");
        let message = format!("{refused:#}");
        assert!(message.contains("posts_body_idx"), "{message}");
        let (definition, _) = live_index(&pool, "posts_body_idx").await.unwrap();
        assert!(definition.contains("(title)"), "left alone: {definition}");
    })
    .await;
}
