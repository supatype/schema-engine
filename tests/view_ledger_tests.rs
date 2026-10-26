//! Phase 4.6 of the managed-object ownership plan: views and the remaining helper functions on
//! the ledger.
//!
//! The draft views, the `api` field views with their write triggers, and the constraint helper
//! functions were re-asserted by the push and never dropped: turning drafts off left `draft.posts`
//! behind, and removing the last field rule left the `api` layer behind. All of them are read off
//! their rendered scripts now (`desired::attributed`), recorded, and dropped when the schema stops
//! asking. A view is never replaced in place: `CREATE OR REPLACE VIEW` refuses most changes, so a
//! changed view is dropped and recreated.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    introspector::fingerprint::ObjectKind,
    ledger::{self, LedgerRow},
    parser,
    parser::ast::SchemaAst,
    push,
};

fn uuid_pk() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" },
            "annotations": { "db": { "pgType": "UUID", "unique": false, "index": false } } })
}

fn text() -> Value {
    json!({ "kind": "text", "required": true,
            "annotations": { "db": { "pgType": "TEXT", "unique": false, "index": false } } })
}

/// `posts`, publishing through drafts, keeping history only, or plain.
fn posts(versions: Option<bool>) -> Value {
    let mut options = json!({ "timestamps": false, "softDelete": false, "singleton": false });
    if let Some(drafts) = versions {
        options["versions"] = json!({ "drafts": drafts, "keep": 5 });
    }
    json!({
        "name": "Post",
        "fields": { "id": uuid_pk(), "title": text() },
        "options": options,
        "annotations": { "db": { "tableName": "posts", "indexes": [] }, "platform": {} }
    })
}

/// `employees`, with a read rule on `salary` or none: the field rule is what asks for an `api`
/// view on a database that cannot load the masking extension.
fn employees(salary_rule: bool) -> Value {
    let mut access = json!({ "read": { "type": "public" }, "update": { "type": "public" } });
    if salary_rule {
        access["fields"] = json!({
            "salary": { "read": { "type": "compare",
                                  "left": { "kind": "column", "name": "user_id" },
                                  "op": "eq",
                                  "right": { "kind": "claim", "path": "uid" } } }
        });
    }
    json!({
        "name": "Employee",
        "fields": {
            "id": { "kind": "integer", "primaryKey": true, "required": true,
                    "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
            "salary": { "kind": "decimal",
                        "annotations": { "db": { "pgType": "NUMERIC", "unique": false } } },
            "user_id": { "kind": "text", "required": true,
                         "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
        },
        "options": { "timestamps": false, "softDelete": false, "singleton": false },
        "annotations": { "db": { "tableName": "employees", "indexes": [] },
                         "platform": { "access": access } }
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

use common::{exec, push};

async fn rows(pool: &PgPool, kind: ObjectKind) -> Vec<LedgerRow> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == kind)
        .collect()
}

fn names(rows: &[LedgerRow]) -> Vec<String> {
    rows.iter()
        .map(|r| format!("{}.{}", r.key.schema, r.key.name))
        .collect()
}

async fn view_exists(pool: &PgPool, schema: &str, view: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_views WHERE schemaname = $1 AND viewname = $2)",
    )
    .bind(schema)
    .bind(view)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn applied(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::Applied { .. })
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

#[tokio::test]
async fn the_draft_view_is_recorded_and_turning_drafts_off_drops_it() {
    common::with_integration_pool(|pool| async move {
        let drafting = schema(vec![posts(Some(true))]);
        assert!(applied(&push(&pool, &drafting).await.unwrap()));
        assert!(view_exists(&pool, "draft", "posts").await);
        assert_eq!(names(&rows(&pool, ObjectKind::View).await), ["draft.posts"]);
        let again = push(&pool, &drafting).await.unwrap();
        assert!(up_to_date(&again), "{again:?}");

        // History without drafts has no pending version to preview, and so no view.
        let outcome = push(&pool, &schema(vec![posts(Some(false))]))
            .await
            .unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        assert!(
            !view_exists(&pool, "draft", "posts").await,
            "the draft view outlived drafts being turned off"
        );
        assert!(rows(&pool, ObjectKind::View).await.is_empty());
    })
    .await;
}

#[tokio::test]
async fn a_users_view_on_a_model_table_is_never_ours() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![posts(None)]);
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "CREATE VIEW public.post_titles AS SELECT title FROM public.posts",
        )
        .await
        .unwrap();

        let again = push(&pool, &ast).await.unwrap();
        assert!(up_to_date(&again), "{again:?}");
        assert!(view_exists(&pool, "public", "post_titles").await);
        assert!(
            rows(&pool, ObjectKind::View).await.is_empty(),
            "and never recorded"
        );
    })
    .await;
}

#[tokio::test]
async fn the_api_layer_follows_the_field_rules_where_the_masking_extension_is_absent() {
    common::with_integration_pool(|pool| async move {
        if common::mask_extension_available(&pool).await {
            // With the extension the rules are labels, not views: nothing of the `api` layer is
            // desired, and the test has nothing to show here.
            let ast = schema(vec![employees(true)]);
            push(&pool, &ast).await.unwrap();
            assert!(rows(&pool, ObjectKind::View).await.is_empty());
            return;
        }

        let masked = schema(vec![employees(true)]);
        assert!(applied(&push(&pool, &masked).await.unwrap()));
        assert!(view_exists(&pool, "api", "employees").await);
        assert_eq!(
            names(&rows(&pool, ObjectKind::View).await),
            ["api.employees"]
        );
        let triggers = names(&rows(&pool, ObjectKind::Trigger).await);
        assert!(
            triggers.contains(&"api.employees_write".to_string()),
            "the view's write trigger: {triggers:?}"
        );
        let again = push(&pool, &masked).await.unwrap();
        assert!(up_to_date(&again), "{again:?}");

        // No field rule, no masking to do: the view and its trigger go.
        let outcome = push(&pool, &schema(vec![employees(false)])).await.unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        assert!(
            !view_exists(&pool, "api", "employees").await,
            "the api view outlived the last field rule"
        );
        assert!(rows(&pool, ObjectKind::View).await.is_empty());
    })
    .await;
}

#[tokio::test]
async fn the_constraint_helper_functions_are_recorded() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![posts(None)]);
        push(&pool, &ast).await.unwrap();
        let functions = names(&rows(&pool, ObjectKind::Function).await);
        assert!(
            functions.contains(&"_supatype.richtext_text(jsonb)".to_string()),
            "{functions:?}"
        );
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}
