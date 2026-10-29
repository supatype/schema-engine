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

use common::{applied, exec, push, push_with, up_to_date};
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

/// A partial index of the user's under the name of one we declare is not ours: the desired index
/// predicts an empty predicate, and adoption compares every part it predicts. Before, the desired
/// index had no `predicate` part and this one was adopted as the declared full unique index.
#[tokio::test]
async fn a_same_named_partial_index_of_the_users_refuses_the_push() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(vec![posts(false, vec![], false, false)]))
            .await
            .unwrap();
        exec(
            &pool,
            "CREATE UNIQUE INDEX posts_body_idx ON public.posts (body) WHERE body <> ''",
        )
        .await
        .unwrap();

        let refused = push(
            &pool,
            &schema(vec![posts(
                false,
                vec![declared(&["body"], true)],
                false,
                false,
            )]),
        )
        .await
        .expect_err("a partial index is not the full unique index we declare");
        let message = format!("{refused:#}");
        assert!(message.contains("posts_body_idx"), "{message}");
        let (definition, _) = live_index(&pool, "posts_body_idx").await.unwrap();
        assert!(definition.contains("WHERE"), "left alone: {definition}");
    })
    .await;
}

/// Every index a push creates (declared, implicit, the singleton's expression, the versions
/// table's `version DESC`) is, live, exactly what its desired object predicts, part for part: the
/// fingerprint now reads key options, `INCLUDE` and the whole definition, and none of that may
/// make an index the engine made read as someone else's.
#[tokio::test]
async fn every_index_a_push_creates_matches_what_it_predicts() {
    common::with_integration_pool(|pool| async move {
        let mut model = posts(true, vec![declared(&["body", "title"], true)], true, true);
        model["options"]["versions"] = json!({ "drafts": true, "keep": 5 });
        let ast = schema(vec![model]);
        assert!(applied(&push(&pool, &ast).await.unwrap()));

        let mut conn = pool.acquire().await.unwrap();
        let state = push::read_state(&mut conn, "public").await.unwrap();
        drop(conn);
        let desired = supatype_engine::desired::desired_objects(&ast, "public").unwrap();
        let indexes: Vec<_> = desired
            .iter()
            .filter(|o| o.key.kind == ObjectKind::Index)
            .collect();
        assert!(
            indexes
                .iter()
                .any(|o| o.structure.get("options").map(String::as_str) == Some("2 DESC")),
            "the versions index is among them: {indexes:#?}"
        );
        let mut problems = Vec::new();
        for o in &indexes {
            let Some(live) = state.fingerprints.iter().find(|f| f.key() == o.key) else {
                problems.push(format!("{}: not live", o.key));
                continue;
            };
            let parts = supatype_engine::ledger::reconcile::parse_definition(&live.definition);
            // In the project schema, where a same-named index may be the user's, every part is
            // predicted. The engine's own schemas are ours by location, and a partial index there
            // (`preview_links_live_for_record`) predicts only what its statement says plainly.
            for label in ["columns", "expressions", "predicate", "include", "options"] {
                if o.key.schema == "public" && !o.structure.contains_key(label) {
                    problems.push(format!("{}: predicts no {label}", o.key));
                }
            }
            for (label, want) in &o.structure {
                if parts.get(label) != Some(&want.as_str()) {
                    problems.push(format!(
                        "{}: {label} predicted {want:?}, live {:?}",
                        o.key,
                        parts.get(label)
                    ));
                }
            }
        }
        assert!(problems.is_empty(), "{}", problems.join("\n"));

        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}
