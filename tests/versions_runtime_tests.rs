//! Publishing against a real database.
//!
//! The rendering tests in `versions_tests.rs` assert what the SQL says. These assert what it does,
//! which is a different question and the one that found the defects. Three of them, none of which
//! reading the SQL would have caught:
//!
//! * `DELETE FROM …` with no `WHERE` is refused outright by the safe-update guard that the
//!   `supatype/postgres` image preloads.
//! * `auth.uid()` answers the nil UUID rather than NULL when a request has no subject, and a
//!   `service_role` write has none, so a draft saved through Studio was stamped with it and every
//!   other subject-less caller then satisfied `created_by = auth.uid()`.
//! * `publish` selected the newest version whose status was `draft`. An older version that was
//!   never published keeps that status for ever, quite correctly, so a second publish found it and
//!   put stale content live: not a refusal but a silent revert.
//!
//! **Everything runs in one transaction.** `request.jwt.claims` is a session setting, and a pool
//! hands successive queries to different connections, so a caller set on one and read on another is
//! no caller at all. That cost an hour of a false failure; a transaction is one connection by
//! construction, and rolling back leaves the database clean for the next test.

mod common;

use std::future::Future;

use sqlx::{Executor, PgConnection};
use supatype_engine::{
    differ, generator::sql::migration, parser, state::database_state::DatabaseState,
};

/// The migration for the versioned fixture, as a push would apply it.
fn forward_migration() -> String {
    let ast = parser::parse(include_str!("fixtures/versioned_blog.json")).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    migration::forward_sql(&diff, false, "public", &ast).unwrap()
}

const EDITOR: &str = "11111111-1111-1111-1111-111111111111";
const POST: &str = "22222222-2222-2222-2222-222222222222";
const LEDGER: &str = "33333333-3333-3333-3333-333333333333";

/// Impersonate a caller the way PostgREST does, for the rest of the connection's session.
///
/// Session scope, not transaction scope, and that is not a shortcut. The generated migration carries
/// its own `BEGIN`/`COMMIT`, so applying it inside a transaction ends that transaction: a
/// transaction-local setting made afterwards is discarded by the very next statement, and every
/// `created_by` assertion then failed against a NULL that looked like a product bug. One connection
/// plus a session setting is the shape that actually holds.
async fn become_caller(db: &mut PgConnection, subject: Option<&str>) {
    let claims = match subject {
        Some(sub) => {
            serde_json::json!({ "sub": sub, "role": "authenticated", "roles": ["editor"] })
        }
        None => serde_json::json!({ "role": "authenticated", "roles": ["editor"] }),
    };
    sqlx::query("SELECT set_config('request.jwt.claims', $1, false)")
        .bind(claims.to_string())
        .execute(db)
        .await
        .expect("set claims");
}

/// Apply the migration, become an editor, and seed one post.
///
/// The fixture rows are cleared first. With `DATABASE_URL` set each test gets its own database, but
/// under testcontainers they share one, and a seed that assumed an empty table would fail on the
/// second test for a reason that had nothing to do with the feature.
async fn apply_and_seed(db: &mut PgConnection) {
    db.execute(sqlx::raw_sql(&forward_migration()))
        .await
        .expect("the whole forward migration must apply to a real database");
    become_caller(db, Some(EDITOR)).await;
    for (table, id) in [("posts", POST), ("ledger", LEDGER)] {
        sqlx::query(&format!("DELETE FROM public.{table} WHERE id = $1::uuid"))
            .bind(id)
            .execute(&mut *db)
            .await
            .expect("clear the fixture row");
    }
    sqlx::query("INSERT INTO public.posts (id, title) VALUES ($1::uuid, 'First cut')")
        .bind(POST)
        .execute(db)
        .await
        .expect("seed a post");
}

async fn live_title(db: &mut PgConnection) -> String {
    sqlx::query_scalar("SELECT title FROM public.posts WHERE id = $1::uuid")
        .bind(POST)
        .fetch_one(db)
        .await
        .expect("read the live row")
}

async fn draft_title(db: &mut PgConnection) -> Option<String> {
    sqlx::query_scalar("SELECT title FROM draft.posts WHERE id = $1::uuid")
        .bind(POST)
        .fetch_optional(db)
        .await
        .expect("read the draft view")
}

async fn save_draft(db: &mut PgConnection, patch: &str) {
    sqlx::query("SELECT supatype.create_draft('posts', $1, $2::jsonb)")
        .bind(POST)
        .bind(patch)
        .execute(db)
        .await
        .expect("create_draft");
}

async fn publish(db: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT supatype.publish('posts', $1)")
        .bind(POST)
        .execute(db)
        .await
        .map(|_| ())
}

/// One connection, migration applied and one post seeded.
///
/// **Serialised.** With `DATABASE_URL` set the harness gives each test its own database, but under
/// testcontainers they share one, and cargo runs tests on parallel threads: two of them seeding and
/// publishing the same record is a failure about nothing. The lock costs the wall-clock time of ten
/// fast tests and buys a suite that means the same thing in both modes.
static FIXTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn with_seeded<F>(f: F)
where
    F: for<'a> FnOnce(
            &'a mut PgConnection,
        ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'a>>
        + Send,
{
    common::with_integration_pool(|pool| async move {
        let _guard = FIXTURE_LOCK.lock().await;
        // One connection for the whole test: `request.jwt.claims` is a session setting, and a pool
        // hands successive queries to different connections, so a caller set on one and read on
        // another is no caller at all.
        let mut conn = pool.acquire().await.expect("acquire one connection");
        apply_and_seed(&mut conn).await;
        f(&mut conn).await;
    })
    .await;
}

#[tokio::test]
async fn editing_writes_a_draft_and_publishing_moves_it_live() {
    with_seeded(|tx| {
        Box::pin(async move {
            // The whole point of the design: the live row does not move when a draft is saved.
            save_draft(tx, r#"{"title": "Edited in draft"}"#).await;
            assert_eq!(live_title(tx).await, "First cut");
            assert_eq!(draft_title(tx).await.as_deref(), Some("Edited in draft"));

            publish(tx).await.expect("publish");
            assert_eq!(live_title(tx).await, "Edited in draft");

            let stamped: bool = sqlx::query_scalar(
                "SELECT published_at IS NOT NULL FROM public.posts WHERE id = $1::uuid",
            )
            .bind(POST)
            .fetch_one(&mut *tx)
            .await
            .expect("read published_at");
            assert!(stamped, "publishing must stamp published_at");
        })
    })
    .await;
}

#[tokio::test]
async fn successive_drafts_accumulate_rather_than_restarting_from_what_is_live() {
    with_seeded(|tx| {
        Box::pin(async move {
            save_draft(tx, r#"{"title": "Second thoughts"}"#).await;
            // A patch that does not mention `title` must not lose the pending change: the merge
            // base is the newest snapshot, not the published row.
            save_draft(tx, r#"{"published_at": null}"#).await;

            assert_eq!(draft_title(tx).await.as_deref(), Some("Second thoughts"));
            assert_eq!(live_title(tx).await, "First cut");
        })
    })
    .await;
}

#[tokio::test]
async fn a_second_publish_with_nothing_pending_is_refused_not_reverted() {
    with_seeded(|tx| {
        Box::pin(async move {
            // Two drafts, so an older never-published version is left behind. That is the trap:
            // "the newest row whose status is draft" finds v1 once v2 has been published.
            save_draft(tx, r#"{"title": "One"}"#).await;
            save_draft(tx, r#"{"title": "Two"}"#).await;
            publish(tx).await.expect("first publish");
            assert_eq!(live_title(tx).await, "Two");

            let err = publish(tx)
                .await
                .expect_err("a second publish with nothing pending must be refused");
            assert!(
                format!("{err}").contains("no pending draft"),
                "expected a refusal naming the reason; got {err}"
            );
        })
    })
    .await;
}

#[tokio::test]
async fn restoring_a_version_creates_a_draft_and_does_not_go_live() {
    with_seeded(|tx| {
        Box::pin(async move {
            save_draft(tx, r#"{"title": "Version one"}"#).await;
            save_draft(tx, r#"{"title": "Version two"}"#).await;
            publish(tx).await.expect("publish");
            assert_eq!(live_title(tx).await, "Version two");

            sqlx::query("SELECT supatype.restore_version('posts', $1, 1)")
                .bind(POST)
                .execute(&mut *tx)
                .await
                .expect("restore");

            assert_eq!(
                live_title(tx).await,
                "Version two",
                "restoring must not change what the world sees"
            );
            assert_eq!(draft_title(tx).await.as_deref(), Some("Version one"));
        })
    })
    .await;
}

#[tokio::test]
async fn unpublishing_leaves_the_content_in_place() {
    with_seeded(|tx| {
        Box::pin(async move {
            save_draft(tx, r#"{"title": "Live copy"}"#).await;
            publish(tx).await.expect("publish");
            sqlx::query("SELECT supatype.unpublish('posts', $1)")
                .bind(POST)
                .execute(&mut *tx)
                .await
                .expect("unpublish");

            // Withdrawing publication is not reverting an edit. Blanking the row would lose the
            // thing a later publish would put back.
            assert_eq!(live_title(tx).await, "Live copy");
            let hidden: bool = sqlx::query_scalar(
                "SELECT published_at IS NULL FROM public.posts WHERE id = $1::uuid",
            )
            .bind(POST)
            .fetch_one(&mut *tx)
            .await
            .expect("read published_at");
            assert!(hidden);
        })
    })
    .await;
}

#[tokio::test]
async fn an_unregistered_table_is_refused_before_any_dynamic_sql_runs() {
    with_seeded(|tx| {
        Box::pin(async move {
            // The functions take a table name, so the registry is what stands between that
            // parameter and `format()`. A catalog table is the case worth naming.
            let err = sqlx::query("SELECT supatype.create_draft('pg_authid', $1, '{}'::jsonb)")
                .bind(POST)
                .execute(&mut *tx)
                .await
                .expect_err("an unregistered table must be refused");
            assert!(
                format!("{err}").contains("no versioned model for table"),
                "got {err}"
            );
        })
    })
    .await;
}

#[tokio::test]
async fn a_direct_insert_cannot_forge_a_published_version_or_another_author() {
    with_seeded(|tx| {
        Box::pin(async move {
            save_draft(tx, r#"{"title": "Real"}"#).await;

            // PostgREST exposes the snapshot table like any other in the managed schema, so this is
            // reachable. The guard trigger makes it a draft save and nothing more.
            sqlx::query(
                "INSERT INTO public.posts_versions (record_id, version, status, data, created_by)
                 VALUES ($1::uuid, 999, 'published', '{\"title\": \"Smuggled\"}'::jsonb,
                         '99999999-9999-9999-9999-999999999999'::uuid)",
            )
            .bind(POST)
            .execute(&mut *tx)
            .await
            .expect("the insert itself is permitted; what it claims is not");

            let row: (i32, String, Option<String>) = sqlx::query_as(
                "SELECT version, status, created_by::text FROM public.posts_versions
                  WHERE record_id = $1::uuid ORDER BY version DESC LIMIT 1",
            )
            .bind(POST)
            .fetch_one(&mut *tx)
            .await
            .expect("read the version back");

            assert_eq!(row.0, 2, "the submitted version number must be discarded");
            assert_eq!(row.1, "draft", "a version is born a draft");
            assert_eq!(
                row.2.as_deref(),
                Some(EDITOR),
                "authorship must be the caller's, not whatever was submitted"
            );
        })
    })
    .await;
}

#[tokio::test]
async fn history_cannot_be_rewritten_by_someone_who_may_still_edit_the_record() {
    with_seeded(|tx| {
        Box::pin(async move {
            save_draft(tx, r#"{"title": "As written"}"#).await;

            sqlx::query(
                "UPDATE public.posts_versions
                    SET data = '{\"title\": \"Rewritten\"}'::jsonb, created_by = NULL
                  WHERE record_id = $1::uuid AND version = 1",
            )
            .bind(POST)
            .execute(&mut *tx)
            .await
            .expect("the update is permitted; what it changes is not");

            let row: (String, bool) = sqlx::query_as(
                "SELECT data->>'title', created_by IS NOT NULL FROM public.posts_versions
                  WHERE record_id = $1::uuid AND version = 1",
            )
            .bind(POST)
            .fetch_one(&mut *tx)
            .await
            .expect("read the version back");

            assert_eq!(row.0, "As written", "a stored snapshot must be immutable");
            assert!(row.1, "authorship must survive an attempt to clear it");
        })
    })
    .await;
}

#[tokio::test]
async fn a_request_with_no_subject_records_no_creator() {
    with_seeded(|tx| {
        Box::pin(async move {
            // What a `service_role` write looks like: Studio's path. `auth.uid()` answers the nil
            // UUID for it, so storing that would make every other subject-less caller the creator
            // of this draft and hand them every draft Studio ever saved.
            become_caller(tx, None).await;
            save_draft(tx, r#"{"title": "Saved without a subject"}"#).await;

            let creator: Option<String> = sqlx::query_scalar(
                "SELECT created_by::text FROM public.posts_versions WHERE record_id = $1::uuid",
            )
            .bind(POST)
            .fetch_one(&mut *tx)
            .await
            .expect("read created_by");

            assert!(
                creator.is_none(),
                "no subject means no creator, not the nil UUID: got {creator:?}"
            );
        })
    })
    .await;
}

#[tokio::test]
async fn an_audit_model_records_every_write_and_refuses_drafts() {
    with_seeded(|tx| {
        Box::pin(async move {
            sqlx::query("INSERT INTO public.ledger (id, note) VALUES ($1::uuid, 'opened')")
                .bind(LEDGER)
                .execute(&mut *tx)
                .await
                .expect("insert");
            sqlx::query("UPDATE public.ledger SET note = 'amended' WHERE id = $1::uuid")
                .bind(LEDGER)
                .execute(&mut *tx)
                .await
                .expect("update");

            let notes: Vec<String> = sqlx::query_scalar(
                "SELECT data->>'note' FROM public.ledger_versions
                  WHERE record_id = $1::uuid ORDER BY version",
            )
            .bind(LEDGER)
            .fetch_all(&mut *tx)
            .await
            .expect("read history");
            assert_eq!(notes, vec!["opened", "amended"]);

            let err = sqlx::query("SELECT supatype.create_draft('ledger', $1, '{}'::jsonb)")
                .bind(LEDGER)
                .execute(&mut *tx)
                .await
                .expect_err("an audit-only model has no drafts to create");
            assert!(
                format!("{err}").contains("does not withhold writes"),
                "got {err}"
            );
        })
    })
    .await;
}
