//! Every record of a drafts model has a version 1, so its publication is read from version rows
//! whichever way the record was written.
//!
//! Studio and the publish functions read a record's state from `<table>_versions` only, so a record
//! with none read as never published while the public was reading it: kitchen-sink's seeded talks,
//! live under `published_at <= now()` with no version row. Two halves, both against a real
//! database:
//!
//! * a push gives each record already there with no version row its version 1, live for what the
//!   row shows, and a second push changes nothing;
//! * a row inserted from then on gets its version 1 as it is inserted, exactly once, while
//!   `create_record` still writes exactly one.

mod common;

use common::{exec, with_integration_pool};
use serde_json::Value;
use sqlx::{Executor, PgConnection};
use supatype_engine::parser::{self, ast::SchemaAst};
use supatype_engine::push::Outcome;

const EDITOR: &str = "11111111-1111-1111-1111-111111111111";
const PUBLISHED: &str = "a0000000-0000-0000-0000-000000000001";
const SCHEDULED: &str = "a0000000-0000-0000-0000-000000000002";
const DRAFT: &str = "a0000000-0000-0000-0000-000000000003";
const PARTIAL: &str = "a0000000-0000-0000-0000-000000000004";

/// The versioned blog with `posts` hidden until published and written by editors, as
/// kitchen-sink's talks are.
fn schema() -> SchemaAst {
    let mut doc: Value =
        serde_json::from_str(include_str!("fixtures/versioned_blog.json")).unwrap();
    doc["models"][0]["annotations"]["platform"]["access"] = serde_json::json!({
        "read": {
            "type": "compare", "op": "lte",
            "left": { "kind": "column", "name": "published_at" },
            "right": { "kind": "now" }
        },
        "create": { "type": "role", "roles": ["editor"] },
        "update": { "type": "role", "roles": ["editor"] }
    });
    parser::parse(&doc.to_string()).unwrap()
}

/// Rows as a seed or an older engine left them: inserted with the session's triggers off, so no
/// version row is written for them whatever the engine does on insert.
const UNVERSIONED_ROWS: &str = r#"
BEGIN;
SET LOCAL session_replication_role = replica;
INSERT INTO posts (id, title, body, published_at) VALUES
  ('a0000000-0000-0000-0000-000000000001', 'Published', '{"en": "Hello", "fr": "Bonjour"}', now() - interval '1 day'),
  ('a0000000-0000-0000-0000-000000000002', 'Scheduled', '{"en": "Soon"}', now() + interval '1 day'),
  ('a0000000-0000-0000-0000-000000000003', 'Draft', '{"en": "Not yet"}', NULL),
  ('a0000000-0000-0000-0000-000000000004', 'Partial', '{"en": "English only", "fr": null}', now() - interval '1 day');
COMMIT;
"#;

/// One record's version rows, oldest first, as `(version, status, created_by, published locales,
/// scheduled locales, title)`.
type VersionRow = (i32, String, Option<String>, Value, Value, Option<String>);

async fn versions_of(pool: &sqlx::PgPool, id: &str) -> Vec<VersionRow> {
    sqlx::query_as(
        "SELECT version, status, created_by::text, \
         (SELECT COALESCE(jsonb_agg(k ORDER BY k), '[]') FROM jsonb_object_keys(published_locales) k), \
         (SELECT COALESCE(jsonb_agg(k ORDER BY k), '[]') FROM jsonb_object_keys(scheduled_locales) k), \
         data ->> 'title' \
         FROM posts_versions WHERE record_id = $1::uuid ORDER BY version",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .expect("read the record's versions")
}

fn warnings(outcome: &Outcome) -> Vec<String> {
    serde_json::from_value(outcome.to_json()["warnings"].clone()).expect("warnings are strings")
}

async fn last_sql_up(pool: &sqlx::PgPool) -> String {
    sqlx::query_scalar("SELECT sql_up FROM _supatype.migrations ORDER BY id DESC LIMIT 1")
        .fetch_one(pool)
        .await
        .expect("read the history")
}

fn row(version: i32, status: &str, published: Value, scheduled: Value, title: &str) -> VersionRow {
    (
        version,
        status.to_string(),
        None,
        published,
        scheduled,
        Some(title.to_string()),
    )
}

/// Published, scheduled, draft and one locale of two: each record gets version 1 holding its live
/// row, live or scheduled for the locales the row holds content in, with no author.
#[tokio::test]
async fn a_push_gives_each_unversioned_record_its_version_1() {
    with_integration_pool(|pool| async move {
        common::push(&pool, &schema()).await.expect("first push");
        exec(&pool, UNVERSIONED_ROWS).await.expect("seed rows");

        let outcome = common::push(&pool, &schema()).await.expect("second push");

        let none = serde_json::json!([]);
        let both = serde_json::json!(["en", "fr"]);
        let en = serde_json::json!(["en"]);
        let expect = [
            (
                PUBLISHED,
                row(1, "published", both, none.clone(), "Published"),
            ),
            (
                SCHEDULED,
                row(1, "draft", none.clone(), en.clone(), "Scheduled"),
            ),
            (DRAFT, row(1, "draft", none.clone(), none.clone(), "Draft")),
            (PARTIAL, row(1, "published", en, none, "Partial")),
        ];
        for (id, want) in expect {
            assert_eq!(versions_of(&pool, id).await, vec![want], "record {id}");
        }
        let said = "Created 4 baseline versions for posts";
        assert!(
            warnings(&outcome).iter().any(|w| w == said),
            "{:?}",
            warnings(&outcome)
        );
        let recorded = last_sql_up(&pool).await;
        assert!(recorded.contains(&format!("-- {said}")), "{recorded}");
        assert!(
            recorded.contains("INSERT INTO \"public\".\"posts_versions\""),
            "{recorded}"
        );
    })
    .await;
}

/// Once every record has a version the next push has nothing to add, and writes nothing.
#[tokio::test]
async fn a_second_push_creates_no_more_versions() {
    with_integration_pool(|pool| async move {
        common::push(&pool, &schema()).await.expect("first push");
        exec(&pool, UNVERSIONED_ROWS).await.expect("seed rows");
        common::push(&pool, &schema()).await.expect("backfill push");

        let outcome = common::push(&pool, &schema()).await.expect("third push");

        assert!(
            matches!(outcome, Outcome::UpToDate { .. }),
            "{}",
            outcome.to_json()
        );
        let total: i64 = sqlx::query_scalar("SELECT count(*) FROM posts_versions")
            .fetch_one(&pool)
            .await
            .expect("count versions");
        assert_eq!(total, 4);
    })
    .await;
}

/// The snapshot table's guard is back on after the backfill: an update of a version's `data`
/// still changes nothing.
#[tokio::test]
async fn the_guard_is_on_again_after_the_backfill() {
    with_integration_pool(|pool| async move {
        common::push(&pool, &schema()).await.expect("first push");
        exec(&pool, UNVERSIONED_ROWS).await.expect("seed rows");
        common::push(&pool, &schema()).await.expect("backfill push");

        exec(
            &pool,
            "UPDATE posts_versions SET data = '{\"title\": \"Rewritten\"}' WHERE TRUE",
        )
        .await
        .expect("update versions");
        let rewritten: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM posts_versions WHERE data ->> 'title' = 'Rewritten'",
        )
        .fetch_one(&pool)
        .await
        .expect("count rewritten");
        assert_eq!(rewritten, 0);
    })
    .await;
}

/// An editor's connection: `authenticated`, with an editor's claims as the auth server issues them.
async fn become_api_editor(db: &mut PgConnection) {
    let claims = serde_json::json!({
        "sub": EDITOR, "role": "authenticated", "app_metadata": { "role": "editor" }
    });
    sqlx::query("SELECT set_config('request.jwt.claims', $1, false)")
        .bind(claims.to_string())
        .execute(&mut *db)
        .await
        .expect("set claims");
    db.execute("SET ROLE authenticated")
        .await
        .expect("become authenticated");
}

/// A row inserted through the API gets version 1 at once, exactly one, by its author: live when
/// it came with a `published_at` in the past, a draft without one.
#[tokio::test]
async fn an_api_insert_gets_its_version_1_exactly_once() {
    with_integration_pool(|pool| async move {
        common::push(&pool, &schema()).await.expect("push");
        let mut db = pool.acquire().await.expect("acquire");
        become_api_editor(&mut db).await;
        db.execute(
            "INSERT INTO posts (id, title, body, published_at) VALUES \
             ('a0000000-0000-0000-0000-000000000001', 'Published', '{\"en\": \"Hi\"}', now() - interval '1 minute'), \
             ('a0000000-0000-0000-0000-000000000003', 'Draft', '{\"en\": \"Later\"}', NULL)",
        )
        .await
        .expect("an editor inserts two rows");

        let by_editor = |v: VersionRow| (v.0, v.1, v.2, v.3, v.4);
        let published = versions_of(&pool, PUBLISHED).await;
        let draft = versions_of(&pool, DRAFT).await;
        let editor = Some(EDITOR.to_string());
        let (none, en) = (serde_json::json!([]), serde_json::json!(["en"]));
        assert_eq!(
            published.into_iter().map(by_editor).collect::<Vec<_>>(),
            vec![(1, "published".to_string(), editor.clone(), en, none.clone())]
        );
        assert_eq!(
            draft.into_iter().map(by_editor).collect::<Vec<_>>(),
            vec![(1, "draft".to_string(), editor, none.clone(), none)]
        );
    })
    .await;
}

/// `create_record` still writes exactly one version, holding what the caller typed, and the row
/// it made is visible to its author afterwards through it.
#[tokio::test]
async fn create_record_still_writes_one_version() {
    with_integration_pool(|pool| async move {
        common::push(&pool, &schema()).await.expect("push");
        let mut db = pool.acquire().await.expect("acquire");
        become_api_editor(&mut db).await;
        let created: Value = sqlx::query_scalar(
            r#"SELECT supatype.create_record('posts', '{"title": "Mine", "body": {"en": "Typed"}}')"#,
        )
        .fetch_one(&mut *db)
        .await
        .expect("create_record");
        let id = created["record_id"].as_str().expect("record id").to_string();

        let versions = versions_of(&pool, &id).await;
        assert_eq!(versions.len(), 1, "{versions:?}");
        assert_eq!(versions[0].0, 1);
        let body: Value =
            sqlx::query_scalar("SELECT data -> 'body' FROM posts_versions WHERE record_id = $1::uuid")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .expect("read version 1's body");
        assert_eq!(body, serde_json::json!({"en": "Typed"}), "version 1 is what was typed");
    })
    .await;
}
