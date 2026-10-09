//! Phase 0 of the managed-object ownership plan: the evidence.
//!
//! Each test states what a push should leave behind when the schema stops asking for something,
//! or what it must leave alone because Supatype never created it. They are written as the
//! behaviour we want, so most of them fail on today's engine. That is the point: they are the
//! acceptance tests for the ledger (`plans/Managed-Object-Ownership-Plan.md`), and each kind's PR
//! flips its own from failing to passing.
//!
//! Every test runs the push the CLI and the server run, through `supatype_engine::push`, so what
//! it proves about a push is true of the one a user gets.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst, push};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn int_pk() -> Value {
    json!({ "kind": "integer", "primaryKey": true, "required": true,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } })
}

fn uuid_pk() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" },
            "annotations": { "db": { "pgType": "UUID", "unique": false, "index": false } } })
}

fn text(required: bool) -> Value {
    json!({ "kind": "text", "required": required,
            "annotations": { "db": { "pgType": "TEXT", "unique": false, "index": false } } })
}

fn integer() -> Value {
    json!({ "kind": "integer", "required": false,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } })
}

fn model(name: &str, table: &str, fields: Value, options: Value) -> Value {
    json!({
        "name": name,
        "fields": fields,
        "options": options,
        "annotations": { "db": { "tableName": table, "indexes": [] }, "platform": {} }
    })
}

fn plain_options() -> Value {
    json!({ "timestamps": false, "softDelete": false, "singleton": false })
}

fn schema(models: Vec<Value>) -> SchemaAst {
    let doc = json!({
        "astVersion": 2,
        "locales": ["en"],
        "defaultLocale": "en",
        // The full shape the CLI emits; the parser accepts nothing less.
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

// ---------------------------------------------------------------------------------------------
// Push and introspection helpers
// ---------------------------------------------------------------------------------------------

/// The previous schema is history now: the orchestrator reads it from `_supatype.migrations`,
/// which the first push wrote.
async fn push(pool: &PgPool, ast: &SchemaAst, force: bool) -> anyhow::Result<()> {
    common::push_with(
        pool,
        ast,
        push::ApplyOptions {
            force,
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}

use common::exec;

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
    .expect("query pg_trigger")
}

async fn view_exists(pool: &PgPool, schema: &str, view: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_views WHERE schemaname = $1 AND viewname = $2)",
    )
    .bind(schema)
    .bind(view)
    .fetch_one(pool)
    .await
    .expect("query pg_views")
}

async fn constraint_exists(pool: &PgPool, table: &str, constraint: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = $1 AND k.conname = $2)",
    )
    .bind(table)
    .bind(constraint)
    .fetch_one(pool)
    .await
    .expect("query pg_constraint")
}

/// The table a foreign key points at, or None when the constraint is gone.
async fn fk_target(pool: &PgPool, table: &str, constraint: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT r.relname::text FROM pg_constraint k \
         JOIN pg_class c ON c.oid = k.conrelid JOIN pg_class r ON r.oid = k.confrelid \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relname = $1 AND k.conname = $2 AND k.contype = 'f'",
    )
    .bind(table)
    .bind(constraint)
    .fetch_optional(pool)
    .await
    .expect("query foreign key")
}

async fn type_exists(pool: &PgPool, name: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace \
         WHERE n.nspname = 'public' AND t.typname = $1)",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("query pg_type")
}

async fn table_comment(pool: &PgPool, table: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT obj_description(('public.' || quote_ident($1))::regclass, 'pg_class')",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .expect("query comment")
}

// ---------------------------------------------------------------------------------------------
// Objects the schema stopped asking for, which a push must take with it
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn removing_a_slug_field_removes_its_trigger_and_writes_keep_working() {
    common::with_integration_pool(|pool| async move {
        let slug = json!({ "kind": "slug", "required": true, "from": "title",
                           "annotations": { "db": { "pgType": "TEXT", "unique": false } } });
        let with_slug = schema(vec![model(
            "Post",
            "posts",
            json!({ "id": int_pk(), "title": text(true), "slug": slug }),
            plain_options(),
        )]);
        push(&pool, &with_slug, false)
            .await
            .expect("first push applies");
        exec(
            &pool,
            "INSERT INTO public.posts (id, title) VALUES (1, 'Hello')",
        )
        .await
        .expect("the slug trigger fills slug on insert");

        let without_slug = schema(vec![model(
            "Post",
            "posts",
            json!({ "id": int_pk(), "title": text(true) }),
            plain_options(),
        )]);
        push(&pool, &without_slug, true)
            .await
            .expect("second push applies");

        assert!(
            !trigger_exists(&pool, "posts", "posts_slug_trigger").await,
            "the slug trigger outlived the slug field"
        );
        exec(
            &pool,
            "INSERT INTO public.posts (id, title) VALUES (2, 'Still writable')",
        )
        .await
        .expect("a write after the field is gone must not fail on a trigger naming it");
    })
    .await;
}

#[tokio::test]
async fn removing_timestamps_removes_the_updated_at_trigger() {
    common::with_integration_pool(|pool| async move {
        let with_ts = schema(vec![model(
            "Post",
            "posts",
            json!({ "id": int_pk(), "title": text(true) }),
            json!({ "timestamps": true, "softDelete": false, "singleton": false }),
        )]);
        push(&pool, &with_ts, false)
            .await
            .expect("first push applies");

        let without_ts = schema(vec![model(
            "Post",
            "posts",
            json!({ "id": int_pk(), "title": text(true) }),
            plain_options(),
        )]);
        push(&pool, &without_ts, true)
            .await
            .expect("second push applies");

        assert!(
            !trigger_exists(&pool, "posts", "posts_updated_at_trigger").await,
            "the updated_at trigger outlived the timestamps option"
        );
        exec(
            &pool,
            "INSERT INTO public.posts (id, title) VALUES (1, 'Hello')",
        )
        .await
        .expect("a write must not fail on a trigger setting a dropped column");
    })
    .await;
}

#[tokio::test]
async fn removing_versions_removes_the_audit_trigger_from_the_model_table() {
    common::with_integration_pool(|pool| async move {
        let versioned = schema(vec![model(
            "Post",
            "posts",
            json!({ "id": uuid_pk(), "title": text(true) }),
            json!({ "timestamps": false, "softDelete": false, "singleton": false,
                    "versions": { "drafts": false, "keep": 5 } }),
        )]);
        push(&pool, &versioned, false)
            .await
            .expect("first push applies");
        assert!(
            trigger_exists(&pool, "posts", "posts_versions_audit").await,
            "precondition: drafts:false installs the audit trigger"
        );

        let plain = schema(vec![model(
            "Post",
            "posts",
            json!({ "id": uuid_pk(), "title": text(true) }),
            plain_options(),
        )]);
        push(&pool, &plain, true)
            .await
            .expect("second push applies");

        assert!(
            !trigger_exists(&pool, "posts", "posts_versions_audit").await,
            "the audit trigger outlived the versions table it writes to"
        );
        exec(&pool, "INSERT INTO public.posts (title) VALUES ('Hello')")
            .await
            .expect("a write must not fail on a trigger inserting into a dropped table");
    })
    .await;
}

#[tokio::test]
async fn changing_email_to_text_removes_the_email_check() {
    common::with_integration_pool(|pool| async move {
        let email = json!({ "kind": "email", "required": true,
                            "annotations": { "db": { "pgType": "TEXT", "unique": false } } });
        let as_email = schema(vec![model(
            "Contact",
            "contacts",
            json!({ "id": int_pk(), "email": email }),
            plain_options(),
        )]);
        push(&pool, &as_email, false)
            .await
            .expect("first push applies");
        assert!(
            exec(
                &pool,
                "INSERT INTO public.contacts VALUES (1, 'not-an-email')"
            )
            .await
            .is_err(),
            "precondition: the email check refuses a non-address"
        );

        let as_text = schema(vec![model(
            "Contact",
            "contacts",
            json!({ "id": int_pk(), "email": text(true) }),
            plain_options(),
        )]);
        push(&pool, &as_text, false)
            .await
            .expect("second push applies");

        exec(
            &pool,
            "INSERT INTO public.contacts VALUES (2, 'not-an-email')",
        )
        .await
        .expect("a plain text column must accept what the email check refused");
    })
    .await;
}

#[tokio::test]
async fn adding_a_text_enum_value_widens_its_check() {
    common::with_integration_pool(|pool| async move {
        let status = |values: &[&str]| {
            json!({ "kind": "enum", "required": true, "values": values, "localized": false,
                    "annotations": { "db": { "pgType": "TEXT", "unique": false } } })
        };
        let two = schema(vec![model(
            "Task",
            "tasks",
            json!({ "id": int_pk(), "status": status(&["open", "done"]) }),
            plain_options(),
        )]);
        push(&pool, &two, false).await.expect("first push applies");
        assert!(
            exec(&pool, "INSERT INTO public.tasks VALUES (1, 'blocked')")
                .await
                .is_err(),
            "precondition: the IN check refuses a value outside the list"
        );

        let three = schema(vec![model(
            "Task",
            "tasks",
            json!({ "id": int_pk(), "status": status(&["open", "done", "blocked"]) }),
            plain_options(),
        )]);
        push(&pool, &three, false)
            .await
            .expect("second push applies");

        exec(&pool, "INSERT INTO public.tasks VALUES (2, 'blocked')")
            .await
            .expect("a value added to the enum must be accepted after the push");
    })
    .await;
}

#[tokio::test]
async fn retargeting_a_relation_moves_the_foreign_key() {
    common::with_integration_pool(|pool| async move {
        let author = |target: &str| {
            json!({ "kind": "relation", "cardinality": "belongsTo", "target": target,
                    "annotations": { "db": { "foreignKey": "author_id" } } })
        };
        let users = model("User", "users", json!({ "id": int_pk() }), plain_options());
        let accounts = model(
            "Account",
            "accounts",
            json!({ "id": int_pk() }),
            plain_options(),
        );

        let to_users = schema(vec![
            users.clone(),
            accounts.clone(),
            model(
                "Post",
                "posts",
                json!({ "id": int_pk(), "authorId": author("User") }),
                plain_options(),
            ),
        ]);
        push(&pool, &to_users, false)
            .await
            .expect("first push applies");
        assert_eq!(
            fk_target(&pool, "posts", "posts_author_id_fkey")
                .await
                .as_deref(),
            Some("users"),
            "precondition: the FK points at users"
        );

        let to_accounts = schema(vec![
            users,
            accounts,
            model(
                "Post",
                "posts",
                json!({ "id": int_pk(), "authorId": author("Account") }),
                plain_options(),
            ),
        ]);
        push(&pool, &to_accounts, true)
            .await
            .expect("second push applies");

        assert_eq!(
            fk_target(&pool, "posts", "posts_author_id_fkey")
                .await
                .as_deref(),
            Some("accounts"),
            "the FK kept its old target because only its name was compared"
        );
    })
    .await;
}

#[tokio::test]
async fn turning_drafts_off_removes_the_draft_view() {
    common::with_integration_pool(|pool| async move {
        let versions = |drafts: bool| {
            json!({ "timestamps": false, "softDelete": false, "singleton": false,
                    "versions": { "drafts": drafts, "keep": 5 } })
        };
        let drafting = schema(vec![model(
            "Post",
            "posts",
            json!({ "id": uuid_pk(), "title": text(true) }),
            versions(true),
        )]);
        push(&pool, &drafting, false)
            .await
            .expect("first push applies");
        assert!(
            view_exists(&pool, "draft", "posts").await,
            "precondition: drafts create draft.posts"
        );

        let history_only = schema(vec![model(
            "Post",
            "posts",
            json!({ "id": uuid_pk(), "title": text(true) }),
            versions(false),
        )]);
        push(&pool, &history_only, false)
            .await
            .expect("second push applies");

        assert!(
            !view_exists(&pool, "draft", "posts").await,
            "the draft view outlived drafts being turned off"
        );
    })
    .await;
}

#[tokio::test]
async fn removing_the_last_versioned_model_retires_the_cron_jobs() {
    common::with_cron_database(|pool| async move {
        // `pg_cron` needs shared_preload_libraries, so it is available in the supatype image and
        // absent almost everywhere else; the same guard `versions_runtime_tests` uses.
        if let Err(e) = exec(&pool, "CREATE EXTENSION IF NOT EXISTS pg_cron").await {
            if common::force_integration_tests() {
                panic!(
                    "this image cannot load pg_cron ({e}); supatype/postgres preloads it. Point \
                     INTEGRATION_POSTGRES_IMAGE at a current image, or unset \
                     SUPATYPE_FORCE_INTEGRATION_TESTS to let this test skip."
                );
            }
            eprintln!("SKIP cron retirement: this image cannot load pg_cron ({e})");
            return;
        }
        let versioned = schema(vec![model(
            "Post",
            "posts",
            json!({ "id": uuid_pk(), "title": text(true) }),
            json!({ "timestamps": false, "softDelete": false, "singleton": false,
                    "versions": { "drafts": true, "keep": 5 } }),
        )]);
        push(&pool, &versioned, false)
            .await
            .expect("first push applies");
        let scheduled: i64 =
            sqlx::query_scalar("SELECT count(*) FROM cron.job WHERE jobname LIKE 'supatype-%'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            scheduled, 2,
            "precondition: a versioned model schedules both jobs"
        );

        let plain = schema(vec![model(
            "Post",
            "posts",
            json!({ "id": uuid_pk(), "title": text(true) }),
            plain_options(),
        )]);
        push(&pool, &plain, true)
            .await
            .expect("second push applies");

        let remaining: Vec<String> = sqlx::query_scalar(
            "SELECT jobname FROM cron.job WHERE jobname LIKE 'supatype-%' ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(
            remaining.is_empty(),
            "the publishing cron jobs outlived the last versioned model: {remaining:?}"
        );
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// Objects Supatype never created, which a push must leave alone
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_hand_added_foreign_key_survives_a_push() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![
            model(
                "Owner",
                "owners",
                json!({ "id": int_pk() }),
                plain_options(),
            ),
            model(
                "Widget",
                "widgets",
                json!({ "id": int_pk(), "owner_id": integer() }),
                plain_options(),
            ),
        ]);
        push(&pool, &ast, false).await.expect("first push applies");
        exec(
            &pool,
            "ALTER TABLE public.widgets ADD CONSTRAINT widgets_owner_id_fkey \
             FOREIGN KEY (owner_id) REFERENCES public.owners (id)",
        )
        .await
        .expect("the operator adds a foreign key of their own");

        push(&pool, &ast, false).await.expect("second push applies");

        assert!(
            constraint_exists(&pool, "widgets", "widgets_owner_id_fkey").await,
            "a foreign key Supatype did not create was dropped by name"
        );
    })
    .await;
}

#[tokio::test]
async fn a_user_enum_type_survives_a_push() {
    common::with_integration_pool(|pool| async move {
        exec(&pool, "CREATE TYPE public.mood AS ENUM ('ok', 'tired')")
            .await
            .expect("the operator creates a type of their own");
        let ast = schema(vec![model(
            "Widget",
            "widgets",
            json!({ "id": int_pk() }),
            plain_options(),
        )]);

        push(&pool, &ast, false).await.expect("push applies");

        assert!(
            type_exists(&pool, "mood").await,
            "an enum type Supatype did not create was dropped because the schema did not name it"
        );
    })
    .await;
}

#[tokio::test]
async fn a_user_grant_on_a_managed_table_survives_a_push() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(vec![model(
            "Widget",
            "widgets",
            json!({ "id": int_pk() }),
            plain_options(),
        )]);
        push(&pool, &ast, false).await.expect("first push applies");
        exec(
            &pool,
            "DO $$ BEGIN CREATE ROLE reporting; EXCEPTION WHEN duplicate_object THEN NULL; END $$; \
             GRANT SELECT ON public.widgets TO reporting",
        )
        .await
        .expect("the operator grants a role of their own");

        push(&pool, &ast, false).await.expect("second push applies");

        let held: bool = sqlx::query_scalar(
            "SELECT has_table_privilege('reporting', 'public.widgets', 'SELECT')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            held,
            "a grant Supatype did not make was revoked by the push"
        );
    })
    .await;
}

#[tokio::test]
async fn a_user_view_on_a_versions_table_survives_the_versions_being_removed() {
    common::with_integration_pool(|pool| async move {
        let versioned = schema(vec![model(
            "Post",
            "posts",
            json!({ "id": uuid_pk(), "title": text(true) }),
            json!({ "timestamps": false, "softDelete": false, "singleton": false,
                    "versions": { "drafts": true, "keep": 5 } }),
        )]);
        push(&pool, &versioned, false).await.expect("first push applies");
        exec(&pool, "CREATE VIEW public.post_history AS SELECT record_id, version FROM public.posts_versions")
            .await
            .expect("the operator builds a view on the history");

        let plain = schema(vec![model(
            "Post",
            "posts",
            json!({ "id": uuid_pk(), "title": text(true) }),
            plain_options(),
        )]);
        // The push may refuse rather than proceed, and that is acceptable: what is not acceptable
        // is the view disappearing because a drop cascaded into it.
        let _ = push(&pool, &plain, true).await;

        assert!(
            view_exists(&pool, "public", "post_history").await,
            "a view Supatype did not create was taken by a CASCADE"
        );
    })
    .await;
}

#[tokio::test]
async fn adopting_a_table_keeps_the_comment_its_owner_wrote() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE TABLE public.widgets (id integer PRIMARY KEY); \
             COMMENT ON TABLE public.widgets IS 'Widgets we sell.'",
        )
        .await
        .expect("fixture applies");
        let ast = schema(vec![model(
            "Widget",
            "widgets",
            json!({ "id": int_pk() }),
            plain_options(),
        )]);
        supatype_engine::adopt::run(
            &pool,
            &ast,
            "public",
            supatype_engine::adopt::Request {
                apply: true,
                ..Default::default()
            },
        )
        .await
        .expect("adopt applies");
        let comment = table_comment(&pool, "widgets").await.unwrap_or_default();
        assert!(
            comment.contains("Widgets we sell."),
            "adopt replaced the owner's comment instead of keeping it; now: {comment:?}"
        );

        // Nor does the push that then manages it.
        let _ = push(&pool, &ast, false).await;
        let comment = table_comment(&pool, "widgets").await.unwrap_or_default();
        assert!(
            comment.contains("Widgets we sell."),
            "the push after adoption replaced the owner's comment; now: {comment:?}"
        );
    })
    .await;
}
