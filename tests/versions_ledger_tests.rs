//! Phase 4.4 of the managed-object ownership plan: the drafts, history and publishing layer on
//! the ledger.
//!
//! The layer is one script the push re-asserts (plan 2.1, mechanism (b)), so nothing ever dropped
//! what it made: the audit trigger outlived its versions table, and the global functions and cron
//! jobs outlived the last versioned model. Its objects are now read off the script statement by
//! statement (`desired::attributed`) and recorded by the ledger, while the script still creates
//! them (its policies name the functions it defines a line earlier), so the reconcile's work is
//! the drops, the recreations and the record.

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

fn uuid_pk() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" },
            "annotations": { "db": { "pgType": "UUID", "unique": false, "index": false } } })
}

fn text() -> Value {
    json!({ "kind": "text", "required": true,
            "annotations": { "db": { "pgType": "TEXT", "unique": false, "index": false } } })
}

/// `posts`, keeping history (`drafts: false`) or publishing through drafts, or plain.
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

async fn rows(pool: &PgPool) -> Vec<LedgerRow> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn).await.unwrap()
}

fn names(rows: &[LedgerRow], kind: ObjectKind) -> Vec<String> {
    rows.iter()
        .filter(|r| r.key.kind == kind)
        .map(|r| format!("{}.{}", r.key.schema, r.key.name))
        .collect()
}

async fn trigger_exists(pool: &PgPool, table: &str, trigger: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = $1 AND t.tgname = $2 AND NOT t.tgisinternal)",
    )
    .bind(table)
    .bind(trigger)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn function_exists(pool: &PgPool, schema: &str, name: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = $1 AND p.proname = $2)",
    )
    .bind(schema)
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn cron_available(pool: &PgPool) -> bool {
    exec(pool, "CREATE EXTENSION IF NOT EXISTS pg_cron")
        .await
        .is_ok()
}

async fn supatype_jobs(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar("SELECT jobname FROM cron.job WHERE jobname LIKE 'supatype-%' ORDER BY 1")
        .fetch_all(pool)
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
async fn the_layers_objects_are_recorded_on_creation_and_left_alone_on_a_second_push() {
    common::with_integration_pool(|pool| async move {
        let cron = cron_available(&pool).await;
        let ast = schema(vec![posts(Some(false))]);
        assert!(applied(&push(&pool, &ast).await.unwrap()));

        let recorded = rows(&pool).await;
        let triggers = names(&recorded, ObjectKind::Trigger);
        assert_eq!(
            triggers,
            ["public.posts_versions_audit"],
            "history without drafts: the audit trigger on the model table"
        );
        let functions = names(&recorded, ObjectKind::Function);
        for expected in [
            "_supatype.posts_versions_audit()",
            "supatype.publish(text, text, integer, text[])",
            "_supatype.run_due_publishes(timestamp with time zone)",
        ] {
            assert!(
                functions.contains(&expected.to_string()),
                "{expected} in {functions:?}"
            );
        }
        let jobs = names(&recorded, ObjectKind::CronJob);
        if cron {
            assert_eq!(
                jobs,
                [".supatype-prune-versions", ".supatype-scheduled-publish"]
            );
        } else {
            assert!(jobs.is_empty(), "no scheduler, nothing to record: {jobs:?}");
        }
        assert!(recorded.iter().all(|r| r.status == Status::Managed));
        assert!(recorded.iter().all(|r| r.migration_id.is_some()));

        let again = push(&pool, &ast).await.unwrap();
        assert!(up_to_date(&again), "{again:?}");
        assert_eq!(rows(&pool).await, recorded);
    })
    .await;
}

#[tokio::test]
async fn removing_versions_drops_the_audit_trigger_and_its_function_and_writes_keep_working() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(vec![posts(Some(false))]))
            .await
            .unwrap();
        assert!(trigger_exists(&pool, "posts", "posts_versions_audit").await);

        let outcome = force_push(&pool, &schema(vec![posts(None)])).await;
        assert!(applied(&outcome), "{outcome:?}");
        assert!(!trigger_exists(&pool, "posts", "posts_versions_audit").await);
        assert!(!function_exists(&pool, "_supatype", "posts_versions_audit").await);
        exec(&pool, "INSERT INTO public.posts (title) VALUES ('Hello')")
            .await
            .expect("a write must not fail on a trigger inserting into a dropped table");
        let left = rows(&pool).await;
        assert!(
            names(&left, ObjectKind::Trigger).is_empty()
                && !names(&left, ObjectKind::Function)
                    .iter()
                    .any(|f| f.contains("posts_versions")),
            "{left:#?}"
        );
    })
    .await;
}

#[tokio::test]
async fn removing_the_last_versioned_model_retires_the_global_layer() {
    common::with_integration_pool(|pool| async move {
        let cron = cron_available(&pool).await;
        push(&pool, &schema(vec![posts(Some(true))])).await.unwrap();
        assert!(function_exists(&pool, "supatype", "publish").await);
        if cron {
            assert_eq!(
                supatype_jobs(&pool).await.len(),
                2,
                "precondition: both jobs scheduled"
            );
        }

        let outcome = force_push(&pool, &schema(vec![posts(None)])).await;
        assert!(applied(&outcome), "{outcome:?}");
        assert!(
            !function_exists(&pool, "supatype", "publish").await,
            "the RPC functions are gone"
        );
        assert!(!function_exists(&pool, "_supatype", "run_due_publishes").await);
        if cron {
            assert!(
                supatype_jobs(&pool).await.is_empty(),
                "the jobs are unscheduled"
            );
        }
        let left = rows(&pool).await;
        assert!(names(&left, ObjectKind::CronJob).is_empty(), "{left:#?}");
        assert!(up_to_date(
            &push(&pool, &schema(vec![posts(None)])).await.unwrap()
        ));
    })
    .await;
}

#[tokio::test]
async fn a_layer_function_an_older_engine_wrote_is_taken_over_and_brought_up_to_date() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![posts(Some(true))]);
        push(&pool, &ast).await.unwrap();
        let again = push(&pool, &ast).await.unwrap();
        assert!(up_to_date(&again), "before anything is touched: {again:?}");
        let ours: String = sqlx::query_scalar(
            "SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
             WHERE n.nspname = '_supatype' AND p.proname = 'sees_all_drafts'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        // No rows, and a body from before: what an upgrade finds. The layer's own schemas are
        // the engine's, so this is ours by location, not a conflict.
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects WHERE true;
             CREATE OR REPLACE FUNCTION _supatype.sees_all_drafts() RETURNS boolean
             LANGUAGE sql AS $$ SELECT TRUE $$",
        )
        .await
        .unwrap();

        let outcome = push(&pool, &ast).await.unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        let now: String = sqlx::query_scalar(
            "SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
             WHERE n.nspname = '_supatype' AND p.proname = 'sees_all_drafts'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(now, ours, "brought up to date");
        // Ours by location: `managed`, not merely `adopted` as a matching object in the project
        // schema would be.
        let taken_over = rows(&pool)
            .await
            .into_iter()
            .find(|r| r.key.schema == "_supatype" && r.key.name == "sees_all_drafts()")
            .expect("the function has a row again");
        assert_eq!(taken_over.status, Status::Managed);
        let plan = push::plan(&pool, &ast, "public").await.unwrap();
        let changes: Vec<_> = plan
            .reconcile
            .actions
            .iter()
            .filter(|a| a.is_change())
            .collect();
        assert!(
            changes.is_empty(),
            "the next push changes nothing: {changes:#?}"
        );
        assert!(
            plan.diff.operations.is_empty(),
            "and plans no operation: {:#?}",
            plan.diff.operations
        );
    })
    .await;
}
