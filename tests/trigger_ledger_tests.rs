//! Phase 4.2 of the managed-object ownership plan: triggers and their `_platform` functions on
//! the ledger.
//!
//! The six live tests every kind gets (plan section 11): created and recorded; untouched on a
//! second push; replaced when the definition changes; recreated when dropped by hand; dropped when
//! the schema stops asking; never touched when it was never ours. Then what these kinds add: a
//! function is replaced in place (`CREATE OR REPLACE`), since a trigger depends on it; a model's
//! function is dropped after the model's table, since the table's trigger depends on it; and a
//! `_platform` function an older engine wrote is ours by location, taken over and brought up to
//! date rather than refused.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    introspector::fingerprint::ObjectKind,
    ledger::{self, LedgerRow, Status},
    parser,
    parser::ast::SchemaAst,
    push,
    state::migration_history,
};

fn int_pk() -> Value {
    json!({ "kind": "integer", "primaryKey": true, "required": true,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } })
}

fn text() -> Value {
    json!({ "kind": "text", "required": true,
            "annotations": { "db": { "pgType": "TEXT", "unique": false, "index": false } } })
}

fn slug(from: &str) -> Value {
    json!({ "kind": "slug", "required": true, "from": from,
            "annotations": { "db": { "pgType": "TEXT", "unique": false } } })
}

fn options(timestamps: bool) -> Value {
    json!({ "timestamps": timestamps, "softDelete": false, "singleton": false })
}

fn model(name: &str, table: &str, fields: Value, options: Value) -> Value {
    json!({
        "name": name,
        "fields": fields,
        "options": options,
        "annotations": { "db": { "tableName": table, "indexes": [] }, "platform": {} }
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

/// `posts` with a slug from `title` and timestamps: an `updated_at` trigger, a slug trigger and
/// the slug's own function.
fn posts(slug_from: Option<&str>, timestamps: bool) -> Value {
    let mut fields = json!({ "id": int_pk(), "title": text(), "subtitle": text() });
    if let Some(from) = slug_from {
        fields["slug"] = slug(from);
    }
    model("Post", "posts", fields, options(timestamps))
}

fn plain(name: &str, table: &str) -> Value {
    model(name, table, json!({ "id": int_pk() }), options(false))
}

use common::{exec, push, push_with};

async fn rows_of(pool: &PgPool, kind: ObjectKind) -> Vec<LedgerRow> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        // This suite is about the trigger layer: the `_platform` functions and the triggers on
        // model tables. The affordance functions (`can_*`, Phase 4.4) are recorded beside them
        // and are another suite's.
        .filter(|r| {
            r.key.kind == kind && (kind != ObjectKind::Function || r.key.schema == "_platform")
        })
        .collect()
}

async fn names_of(pool: &PgPool, kind: ObjectKind) -> Vec<String> {
    rows_of(pool, kind)
        .await
        .into_iter()
        .map(|r| r.key.name)
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

/// The body of a `_platform` function, or None when it is gone.
async fn platform_function_body(pool: &PgPool, name: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = '_platform' AND p.proname = $1",
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
async fn triggers_and_their_functions_are_recorded_on_creation_and_left_alone_on_a_second_push() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![posts(Some("title"), true)]);

        // Functions before the triggers that call them, both after the table.
        let plan = push::prepare(&pool, &ast, "public").await.unwrap();
        let file = plan.migration(false).unwrap().file();
        let table = file.find("CREATE TABLE").unwrap();
        let function = file
            .find("CREATE OR REPLACE FUNCTION _platform.set_posts_slug")
            .unwrap();
        let trigger = file
            .find("CREATE OR REPLACE TRIGGER \"posts_slug_trigger\"")
            .unwrap();
        assert!(table < function && function < trigger, "{file}");
        assert!(applied(
            &push::apply(&pool, plan, push::ApplyOptions::default())
                .await
                .unwrap()
        ));

        assert_eq!(
            names_of(&pool, ObjectKind::Function).await,
            ["set_posts_slug()", "set_updated_at()", "slugify(text)"]
        );
        assert_eq!(
            names_of(&pool, ObjectKind::Trigger).await,
            ["posts_slug_trigger", "posts_updated_at_trigger"]
        );
        let rows = rows_of(&pool, ObjectKind::Function).await;
        assert!(
            rows.iter().all(|r| r.key.schema == "_platform"),
            "{rows:#?}"
        );
        assert!(rows.iter().all(|r| r.status == Status::Managed));
        assert!(rows.iter().all(|r| r.migration_id.is_some()));
        assert!(
            rows.iter().all(|r| r.live_def.contains("language=plpgsql")),
            "{rows:#?}"
        );

        exec(
            &pool,
            "INSERT INTO public.posts (id, title, subtitle) VALUES (1, 'Hello World', 's')",
        )
        .await
        .unwrap();
        let slugged: String = sqlx::query_scalar("SELECT slug FROM public.posts WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(slugged, "hello-world", "the trigger fires");

        let again = push(&pool, &ast).await.unwrap();
        assert!(up_to_date(&again), "{again:?}");
        assert_eq!(rows_of(&pool, ObjectKind::Function).await, rows);
    })
    .await;
}

#[tokio::test]
async fn removing_a_slug_field_drops_its_trigger_and_function_and_the_shared_ones_stay() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(vec![posts(Some("title"), true)]))
            .await
            .unwrap();

        let outcome = force_push(&pool, &schema(vec![posts(None, true)])).await;
        assert!(applied(&outcome), "{outcome:?}");
        assert!(!trigger_exists(&pool, "posts", "posts_slug_trigger").await);
        assert!(platform_function_body(&pool, "set_posts_slug")
            .await
            .is_none());
        assert!(
            platform_function_body(&pool, "slugify").await.is_some(),
            "shared, stays"
        );
        assert!(trigger_exists(&pool, "posts", "posts_updated_at_trigger").await);
        exec(
            &pool,
            "INSERT INTO public.posts (id, title, subtitle) VALUES (2, 'Still writable', 's')",
        )
        .await
        .expect("a write after the field is gone must not fail on a trigger naming it");
        assert_eq!(
            names_of(&pool, ObjectKind::Function).await,
            ["set_updated_at()", "slugify(text)"]
        );
    })
    .await;
}

#[tokio::test]
async fn removing_timestamps_drops_the_updated_at_trigger() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(vec![posts(None, true)])).await.unwrap();
        let outcome = force_push(&pool, &schema(vec![posts(None, false)])).await;
        assert!(applied(&outcome), "{outcome:?}");
        assert!(!trigger_exists(&pool, "posts", "posts_updated_at_trigger").await);
        exec(
            &pool,
            "INSERT INTO public.posts (id, title, subtitle) VALUES (1, 'Hello', 's')",
        )
        .await
        .expect("a write must not fail on a trigger setting a dropped column");
        assert!(names_of(&pool, ObjectKind::Trigger).await.is_empty());
    })
    .await;
}

#[tokio::test]
async fn an_owned_trigger_dropped_by_hand_is_recreated_and_a_hand_added_one_survives() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![posts(None, true)]);
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "DROP TRIGGER posts_updated_at_trigger ON public.posts;
             CREATE FUNCTION public.their_audit() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RETURN NEW; END $$;
             CREATE TRIGGER posts_their_audit AFTER INSERT ON public.posts
             FOR EACH ROW EXECUTE FUNCTION public.their_audit()",
        )
        .await
        .unwrap();

        let outcome = push(&pool, &ast).await.unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        assert!(
            trigger_exists(&pool, "posts", "posts_updated_at_trigger").await,
            "ours is back"
        );
        assert!(
            trigger_exists(&pool, "posts", "posts_their_audit").await,
            "theirs is untouched"
        );
        assert_eq!(
            names_of(&pool, ObjectKind::Trigger).await,
            ["posts_updated_at_trigger"]
        );
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

#[tokio::test]
async fn changing_a_slug_source_replaces_the_function_in_place_and_rolling_back_restores_it() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(vec![posts(Some("title"), false)]))
            .await
            .unwrap();
        let trigger_before = rows_of(&pool, ObjectKind::Trigger).await;

        let outcome = push(&pool, &schema(vec![posts(Some("subtitle"), false)]))
            .await
            .unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        let body = platform_function_body(&pool, "set_posts_slug")
            .await
            .unwrap();
        assert!(
            body.contains("\"subtitle\"") && !body.contains("\"title\""),
            "{body}"
        );
        assert_eq!(
            rows_of(&pool, ObjectKind::Trigger).await,
            trigger_before,
            "the trigger that calls the function is untouched"
        );
        exec(
            &pool,
            "INSERT INTO public.posts (id, title, subtitle) VALUES (1, 'T', 'From Subtitle')",
        )
        .await
        .unwrap();
        let slugged: String = sqlx::query_scalar("SELECT slug FROM public.posts WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(slugged, "from-subtitle");

        migration_history::apply_rollback(&pool, "public")
            .await
            .unwrap();
        let body = platform_function_body(&pool, "set_posts_slug")
            .await
            .unwrap();
        assert!(
            body.contains("\"title\""),
            "rolling back restores the previous body: {body}"
        );
        assert!(trigger_exists(&pool, "posts", "posts_slug_trigger").await);
    })
    .await;
}

#[tokio::test]
async fn a_platform_function_an_older_engine_wrote_is_taken_over_and_brought_up_to_date() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![posts(Some("title"), false)]);
        push(&pool, &ast).await.unwrap();
        let ours = platform_function_body(&pool, "slugify").await.unwrap();

        // No ledger rows, and a body from before: what an upgrade finds.
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects WHERE kind IN ('function', 'trigger');
             CREATE OR REPLACE FUNCTION _platform.slugify(val TEXT) RETURNS TEXT AS $$
             BEGIN RETURN lower(val); END; $$ LANGUAGE plpgsql IMMUTABLE",
        )
        .await
        .unwrap();

        let outcome = push(&pool, &ast).await.unwrap();
        assert!(applied(&outcome), "{outcome:?}");
        assert_eq!(
            platform_function_body(&pool, "slugify").await.unwrap(),
            ours
        );
        let rows = rows_of(&pool, ObjectKind::Function).await;
        assert_eq!(rows.len(), 3, "{rows:#?}");
        assert!(
            rows.iter().all(|r| r.status == Status::Managed),
            "{rows:#?}"
        );
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));
    })
    .await;
}

#[tokio::test]
async fn a_same_named_trigger_of_the_users_refuses_the_push() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(vec![posts(None, false)]))
            .await
            .unwrap();
        exec(
            &pool,
            "CREATE FUNCTION public.their_stamp() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RETURN NEW; END $$;
             CREATE TRIGGER posts_updated_at_trigger AFTER UPDATE ON public.posts
             FOR EACH ROW EXECUTE FUNCTION public.their_stamp()",
        )
        .await
        .unwrap();

        let refused = push(&pool, &schema(vec![posts(None, true)]))
            .await
            .expect_err("a same-named trigger that is not ours refuses the push");
        let message = format!("{refused:#}");
        assert!(message.contains("posts_updated_at_trigger"), "{message}");
        assert!(message.contains("supatype adopt"), "{message}");
    })
    .await;
}

#[tokio::test]
async fn a_removed_model_takes_its_trigger_and_function_with_it() {
    common::with_integration_pool(|pool| async move {
        push(
            &pool,
            &schema(vec![posts(Some("title"), true), plain("Tag", "tags")]),
        )
        .await
        .unwrap();

        let outcome = force_push(&pool, &schema(vec![plain("Tag", "tags")])).await;
        assert!(applied(&outcome), "{outcome:?}");
        assert!(platform_function_body(&pool, "set_posts_slug")
            .await
            .is_none());
        assert_eq!(
            names_of(&pool, ObjectKind::Function).await,
            ["set_updated_at()", "slugify(text)"]
        );
        assert!(names_of(&pool, ObjectKind::Trigger).await.is_empty());
    })
    .await;
}
