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
use supatype_engine::{parser, push};

/// The migration for the versioned fixture, as a push to an empty database applies it: the
/// differ's operations and the reconcile's creations, the grants among them.
fn forward_migration() -> String {
    let ast = parser::parse(include_str!("fixtures/versioned_blog.json")).unwrap();
    push::fresh_migration(&ast, "public", false)
        .unwrap()
        .up_script()
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
                format!("{err}").contains("already live for"),
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

#[tokio::test]
async fn a_localized_field_survives_the_snapshot_round_trip_and_defaults_to_every_locale() {
    with_seeded(|db| {
        Box::pin(async move {
            // A localized field is one JSONB column holding every locale, so a snapshot is JSONB
            // inside JSONB. That is where a round trip goes wrong: `to_jsonb` then
            // `jsonb_populate_record` can double-encode, and the column comes back as a string
            // containing JSON rather than as the locale record.
            sqlx::query(
                "UPDATE public.posts SET body = '{\"en\": \"English\", \"fr\": \"Francais\"}'::jsonb
                  WHERE id = $1::uuid",
            )
            .bind(POST)
            .execute(&mut *db)
            .await
            .expect("seed both locales");

            // Edit one locale only. The other must survive, because the merge base is the whole row.
            save_draft(
                db,
                r#"{"body": {"en": "Edited English", "fr": "Francais"}}"#,
            )
            .await;

            let drafted: (Option<String>, Option<String>) = sqlx::query_as(
                "SELECT coalesce(nullif(_supatype.richtext_text(body->'en'), ''), body->>'en'), coalesce(nullif(_supatype.richtext_text(body->'fr'), ''), body->>'fr') FROM draft.posts WHERE id = $1::uuid",
            )
            .bind(POST)
            .fetch_one(&mut *db)
            .await
            .expect("read the draft view");
            assert_eq!(
                drafted,
                (Some("Edited English".into()), Some("Francais".into())),
                "the locale record must come back as an object, not as a string of JSON"
            );

            publish(db).await.expect("publish");

            // Publication is per record, not per locale: both locales go live together, because
            // they share one column and `published_at` is one column on the row.
            let live: (Option<String>, Option<String>) = sqlx::query_as(
                "SELECT coalesce(nullif(_supatype.richtext_text(body->'en'), ''), body->>'en'), coalesce(nullif(_supatype.richtext_text(body->'fr'), ''), body->>'fr') FROM public.posts WHERE id = $1::uuid",
            )
            .bind(POST)
            .fetch_one(&mut *db)
            .await
            .expect("read the live row");
            assert_eq!(
                live,
                (Some("Edited English".into()), Some("Francais".into())),
                "publishing must move every locale, and must not stringify the record"
            );
        })
    })
    .await;
}

#[tokio::test]
async fn any_version_can_be_restored_including_one_from_the_middle_of_a_history() {
    with_seeded(|db| {
        Box::pin(async move {
            for title in ["One", "Two", "Three", "Four", "Five"] {
                save_draft(db, &format!(r#"{{"title": "{title}"}}"#)).await;
            }
            publish(db).await.expect("publish the newest");
            assert_eq!(live_title(db).await, "Five");

            // Not just the first or the last: a version from the middle, while a later one is live.
            sqlx::query("SELECT supatype.restore_version('posts', $1, 2)")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect("restore version 2");

            assert_eq!(
                draft_title(db).await.as_deref(),
                Some("Two"),
                "the restored version becomes the working draft"
            );
            assert_eq!(
                live_title(db).await,
                "Five",
                "and nothing has gone live without a publish"
            );

            // Publishing then promotes exactly what was restored, so "publish version 2" is
            // restore-then-publish rather than a version argument on publish: the newest version
            // stays the one that says what the state is.
            publish(db).await.expect("publish the restored draft");
            assert_eq!(live_title(db).await, "Two");

            let history: Vec<(i32, String)> = sqlx::query_as(
                "SELECT version, status FROM public.posts_versions
                  WHERE record_id = $1::uuid ORDER BY version",
            )
            .bind(POST)
            .fetch_all(&mut *db)
            .await
            .expect("read history");
            assert_eq!(
                history.len(),
                6,
                "restoring appends rather than rewriting, so the act is in the history too"
            );
            assert_eq!(history[5].1, "published");

            // And a version that was never written is refused rather than silently doing nothing.
            let err = sqlx::query("SELECT supatype.restore_version('posts', $1, 99)")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect_err("a version that does not exist must be refused");
            assert!(format!("{err}").contains("no version"), "got {err}");
        })
    })
    .await;
}

#[tokio::test]
async fn one_locale_can_go_live_while_another_stays_in_draft() {
    with_seeded(|db| {
        Box::pin(async move {
            save_draft(
                db,
                r#"{"body": {"en": "English copy", "fr": "Copie francaise"}}"#,
            )
            .await;

            sqlx::query("SELECT supatype.publish('posts', $1, NULL, ARRAY['en'])")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect("publish English only");

            // The unpublished translation is *absent* from the live row rather than hidden by a
            // policy. That is the whole reason this is enforceable: row level security cannot hide
            // one key of a column, and nothing has to, because the value was never written.
            let live: (Option<String>, Option<String>, bool) = sqlx::query_as(
                "SELECT coalesce(nullif(_supatype.richtext_text(body->'en'), ''), body->>'en'), coalesce(nullif(_supatype.richtext_text(body->'fr'), ''), body->>'fr'), body ? 'fr' FROM public.posts
                  WHERE id = $1::uuid",
            )
            .bind(POST)
            .fetch_one(&mut *db)
            .await
            .expect("read the live row");
            assert_eq!(live.0.as_deref(), Some("English copy"));
            assert_eq!(live.1, None, "the French copy must not be live");
            assert!(!live.2, "the key must be absent, not present and empty");

            // The draft still holds both, so the translation is not lost, just unpublished.
            let drafted: (Option<String>, Option<String>) = sqlx::query_as(
                "SELECT coalesce(nullif(_supatype.richtext_text(body->'en'), ''), body->>'en'), coalesce(nullif(_supatype.richtext_text(body->'fr'), ''), body->>'fr') FROM draft.posts WHERE id = $1::uuid",
            )
            .bind(POST)
            .fetch_one(&mut *db)
            .await
            .expect("read the draft view");
            assert_eq!(drafted.0.as_deref(), Some("English copy"));
            assert_eq!(drafted.1.as_deref(), Some("Copie francaise"));

            // And the version records which locales it is live for.
            let published: serde_json::Value = sqlx::query_scalar(
                "SELECT published_locales FROM public.posts_versions
                  WHERE record_id = $1::uuid ORDER BY version DESC LIMIT 1",
            )
            .bind(POST)
            .fetch_one(&mut *db)
            .await
            .expect("read published_locales");
            assert!(published.get("en").is_some(), "en must be recorded live");
            assert!(published.get("fr").is_none(), "fr must not be");

            // Publishing the translation later brings it live without touching English.
            sqlx::query("SELECT supatype.publish('posts', $1, NULL, ARRAY['fr'])")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect("publish French");
            let both: (Option<String>, Option<String>) = sqlx::query_as(
                "SELECT coalesce(nullif(_supatype.richtext_text(body->'en'), ''), body->>'en'), coalesce(nullif(_supatype.richtext_text(body->'fr'), ''), body->>'fr') FROM public.posts WHERE id = $1::uuid",
            )
            .bind(POST)
            .fetch_one(&mut *db)
            .await
            .expect("read the live row");
            assert_eq!(both.0.as_deref(), Some("English copy"));
            assert_eq!(both.1.as_deref(), Some("Copie francaise"));
        })
    })
    .await;
}

#[tokio::test]
async fn unpublishing_one_locale_leaves_the_others_live() {
    with_seeded(|db| {
        Box::pin(async move {
            save_draft(db, r#"{"body": {"en": "Live", "fr": "En ligne"}}"#).await;
            publish(db).await.expect("publish both");

            sqlx::query("SELECT supatype.unpublish('posts', $1, ARRAY['fr'])")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect("unpublish French");

            let live: (Option<String>, Option<String>, bool) = sqlx::query_as(
                "SELECT coalesce(nullif(_supatype.richtext_text(body->'en'), ''), body->>'en'), coalesce(nullif(_supatype.richtext_text(body->'fr'), ''), body->>'fr'), published_at IS NOT NULL FROM public.posts
                  WHERE id = $1::uuid",
            )
            .bind(POST)
            .fetch_one(&mut *db)
            .await
            .expect("read the live row");
            assert_eq!(live.0.as_deref(), Some("Live"), "English stays live");
            assert_eq!(live.1, None, "French is withdrawn");
            assert!(
                live.2,
                "published_at must survive while any locale is live, or a rule comparing it would \
                 hide the locales that are still published"
            );

            // Withdrawing the last locale clears `published_at`, so the record reads as unpublished
            // to a rule that compares it.
            sqlx::query("SELECT supatype.unpublish('posts', $1, ARRAY['en'])")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect("unpublish English");
            let hidden: bool = sqlx::query_scalar(
                "SELECT published_at IS NULL FROM public.posts WHERE id = $1::uuid",
            )
            .bind(POST)
            .fetch_one(&mut *db)
            .await
            .expect("read published_at");
            assert!(hidden);
        })
    })
    .await;
}

#[tokio::test]
async fn a_named_version_can_be_published_directly() {
    with_seeded(|db| {
        Box::pin(async move {
            save_draft(db, r#"{"title": "One"}"#).await;
            save_draft(db, r#"{"title": "Two"}"#).await;
            save_draft(db, r#"{"title": "Three"}"#).await;

            // Straight to version 1, with two newer drafts above it.
            sqlx::query("SELECT supatype.publish('posts', $1, 1)")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect("publish version 1");
            assert_eq!(live_title(db).await, "One");

            // Exactly one version claims a locale, so publishing another moves the claim rather
            // than leaving two versions both saying they are live.
            sqlx::query("SELECT supatype.publish('posts', $1, 3)")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect("publish version 3");
            assert_eq!(live_title(db).await, "Three");

            let claims: Vec<(i32, bool)> = sqlx::query_as(
                "SELECT version, published_locales <> '{}'::jsonb FROM public.posts_versions
                  WHERE record_id = $1::uuid ORDER BY version",
            )
            .bind(POST)
            .fetch_all(&mut *db)
            .await
            .expect("read the claims");
            assert_eq!(
                claims,
                vec![(1, false), (2, false), (3, true)],
                "only the published version may claim a locale"
            );
        })
    })
    .await;
}

#[tokio::test]
async fn publishing_a_version_that_was_never_written_is_refused() {
    with_seeded(|db| {
        Box::pin(async move {
            save_draft(db, r#"{"title": "Only one"}"#).await;
            let err = sqlx::query("SELECT supatype.publish('posts', $1, 42)")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect_err("a version that does not exist must be refused");
            assert!(
                format!("{err}").contains("no version to publish"),
                "got {err}"
            );
        })
    })
    .await;
}

#[tokio::test]
async fn a_scheduled_publish_waits_and_then_fires() {
    with_seeded(|db| {
        Box::pin(async move {
            save_draft(db, r#"{"title": "Goes live at nine"}"#).await;

            sqlx::query("SELECT supatype.schedule_publish('posts', $1, now() + interval '1 hour')")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect("schedule");

            // Scheduling publishes nothing: it records an intent that the job acts on.
            assert_eq!(live_title(db).await, "First cut");

            // Nothing is due yet, so a run does nothing rather than publishing early.
            let fired: i32 = sqlx::query_scalar("SELECT _supatype.run_due_publishes()")
                .fetch_one(&mut *db)
                .await
                .expect("run the job");
            assert_eq!(fired, 0);
            assert_eq!(live_title(db).await, "First cut");

            // Ask the job what it would do an hour from now. Passing the clock in is what makes the
            // job testable at all: waiting an hour is not a test.
            let fired: i32 = sqlx::query_scalar(
                "SELECT _supatype.run_due_publishes(now() + interval '2 hours')",
            )
            .fetch_one(&mut *db)
            .await
            .expect("run the job");
            assert_eq!(fired, 1);
            assert_eq!(live_title(db).await, "Goes live at nine");

            // The schedule is consumed, so a second run does not publish it again.
            let again: i32 = sqlx::query_scalar(
                "SELECT _supatype.run_due_publishes(now() + interval '2 hours')",
            )
            .fetch_one(&mut *db)
            .await
            .expect("run the job again");
            assert_eq!(again, 0);
        })
    })
    .await;
}

#[tokio::test]
async fn one_locale_can_be_scheduled_while_another_is_already_live() {
    with_seeded(|db| {
        Box::pin(async move {
            save_draft(db, r#"{"body": {"en": "Now", "fr": "Plus tard"}}"#).await;
            sqlx::query("SELECT supatype.publish('posts', $1, NULL, ARRAY['en'])")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect("publish English now");

            sqlx::query(
                "SELECT supatype.schedule_publish('posts', $1, now() + interval '1 hour', NULL,
                                                  ARRAY['fr'])",
            )
            .bind(POST)
            .execute(&mut *db)
            .await
            .expect("schedule French");

            let before: (Option<String>, Option<String>) = sqlx::query_as(
                "SELECT coalesce(nullif(_supatype.richtext_text(body->'en'), ''), body->>'en'), coalesce(nullif(_supatype.richtext_text(body->'fr'), ''), body->>'fr') FROM public.posts WHERE id = $1::uuid",
            )
            .bind(POST)
            .fetch_one(&mut *db)
            .await
            .expect("read the live row");
            assert_eq!(before.0.as_deref(), Some("Now"));
            assert_eq!(before.1, None, "the translation is scheduled, not live");

            sqlx::query("SELECT _supatype.run_due_publishes(now() + interval '2 hours')")
                .execute(&mut *db)
                .await
                .expect("run the job");

            let after: (Option<String>, Option<String>) = sqlx::query_as(
                "SELECT coalesce(nullif(_supatype.richtext_text(body->'en'), ''), body->>'en'), coalesce(nullif(_supatype.richtext_text(body->'fr'), ''), body->>'fr') FROM public.posts WHERE id = $1::uuid",
            )
            .bind(POST)
            .fetch_one(&mut *db)
            .await
            .expect("read the live row");
            assert_eq!(after.0.as_deref(), Some("Now"), "English is untouched");
            assert_eq!(after.1.as_deref(), Some("Plus tard"));
        })
    })
    .await;
}

#[tokio::test]
async fn a_schedule_can_be_withdrawn_without_publishing() {
    with_seeded(|db| {
        Box::pin(async move {
            save_draft(db, r#"{"title": "Not yet"}"#).await;
            sqlx::query("SELECT supatype.schedule_publish('posts', $1, now() + interval '1 hour')")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect("schedule");
            sqlx::query("SELECT supatype.unschedule_publish('posts', $1)")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect("unschedule");

            let fired: i32 = sqlx::query_scalar(
                "SELECT _supatype.run_due_publishes(now() + interval '2 hours')",
            )
            .fetch_one(&mut *db)
            .await
            .expect("run the job");
            assert_eq!(fired, 0);
            assert_eq!(live_title(db).await, "First cut");
        })
    })
    .await;
}

#[tokio::test]
async fn retention_prunes_old_versions_but_never_the_newest_or_the_live_one() {
    with_seeded(|db| {
        Box::pin(async move {
            // The fixture keeps 5.
            for n in 1..=8 {
                save_draft(db, &format!(r#"{{"title": "v{n}"}}"#)).await;
            }
            // Publish version 2, so an *old* version is the live one and must survive pruning even
            // though retention would otherwise reach it.
            sqlx::query("SELECT supatype.publish('posts', $1, 2)")
                .bind(POST)
                .execute(&mut *db)
                .await
                .expect("publish version 2");

            sqlx::query("SELECT _supatype.prune_versions()")
                .execute(&mut *db)
                .await
                .expect("prune");

            let kept: Vec<i32> = sqlx::query_scalar(
                "SELECT version FROM public.posts_versions WHERE record_id = $1::uuid
                  ORDER BY version",
            )
            .bind(POST)
            .fetch_all(&mut *db)
            .await
            .expect("read the surviving versions");

            assert!(
                kept.contains(&8),
                "the newest must survive: a draft read and a publish both work from it"
            );
            assert!(
                kept.contains(&2),
                "the live version must survive: it is the only record of what the world is seeing"
            );
            assert!(
                !kept.contains(&1),
                "retention of 5 over 8 versions must actually remove something; kept {kept:?}"
            );
        })
    })
    .await;
}

#[tokio::test]
async fn the_scheduler_is_wired_up_when_the_database_has_one() {
    common::with_cron_database(|pool| async move {
        let mut conn = pool.acquire().await.expect("acquire");
        // `pg_cron` needs shared_preload_libraries, so it is available in the supatype image and
        // absent almost everywhere else. Install it here and assert the push schedules the jobs;
        // the degrade path is the same code with the `pg_extension` check failing.
        if let Err(e) = sqlx::raw_sql("CREATE EXTENSION IF NOT EXISTS pg_cron")
            .execute(&mut *conn)
            .await
        {
            if common::force_integration_tests() {
                panic!(
                    "this image cannot load pg_cron ({e}); supatype/postgres preloads it. Point \
                     INTEGRATION_POSTGRES_IMAGE at a current image, or unset \
                     SUPATYPE_FORCE_INTEGRATION_TESTS to let this test skip."
                );
            }
            eprintln!("SKIP scheduler wiring: this image cannot load pg_cron ({e})");
            return;
        }

        let _guard = FIXTURE_LOCK.lock().await;
        apply_and_seed(&mut conn).await;

        let jobs: Vec<String> = sqlx::query_scalar(
            "SELECT jobname FROM cron.job WHERE jobname LIKE 'supatype-%' ORDER BY jobname",
        )
        .fetch_all(&mut *conn)
        .await
        .expect("read cron.job");
        assert_eq!(
            jobs,
            vec!["supatype-prune-versions", "supatype-scheduled-publish"],
            "a push must register both jobs when the database can run them"
        );

        // Re-emitted on every push by the versions layer, and it has to converge rather than stack
        // a second copy.
        let ast = parser::parse(include_str!("fixtures/versioned_blog.json")).unwrap();
        let layer =
            supatype_engine::generator::sql::versions::render_versions_layer(&ast, "public")
                .expect("the layer renders");
        conn.execute(sqlx::raw_sql(&layer))
            .await
            .expect("re-apply the versions layer");
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM cron.job WHERE jobname LIKE 'supatype-%'")
                .fetch_one(&mut *conn)
                .await
                .expect("count jobs");
        assert_eq!(
            count, 2,
            "a second push must not add a second copy of each job"
        );
    })
    .await;
}

/// The claims a preview link carries, as `supatype-auth` mints them.
///
/// Built here rather than imported, because the point is to check that the shape
/// the Go service signs is the shape the generated policy reads. Two repos have to
/// agree on this, and nothing but a test that speaks both can say whether they do.
fn preview_claims(scope: &str, model: &str, record: &str, epoch: i32) -> String {
    let preview = if scope == "record" {
        serde_json::json!({
            "scope": "record", "model": model, "record_id": record, "epoch": epoch
        })
    } else {
        serde_json::json!({ "scope": "project", "epoch": epoch })
    };
    // No `sub`: `auth.uid()` is then null and the bearer inherits nothing from
    // looking logged in.
    serde_json::json!({ "role": "authenticated", "preview": preview }).to_string()
}

async fn become_preview_bearer(db: &mut PgConnection, claims: &str) {
    sqlx::query("SELECT set_config('request.jwt.claims', $1, false)")
        .bind(claims)
        .execute(db)
        .await
        .expect("set preview claims");
}

#[tokio::test]
async fn a_record_preview_link_opens_that_record_and_no_other() {
    with_seeded(|db| {
        Box::pin(async move {
            let other = "44444444-4444-4444-4444-444444444444";
            sqlx::query("INSERT INTO public.posts (id, title) VALUES ($1::uuid, 'Other post')")
                .bind(other)
                .execute(&mut *db)
                .await
                .expect("seed a second post");

            save_draft(db, r#"{"title": "Shared with a reviewer"}"#).await;
            sqlx::query("SELECT supatype.create_draft('posts', $1, '{\"title\": \"Private\"}')")
                .bind(other)
                .execute(&mut *db)
                .await
                .expect("draft the second post");

            let epoch: i32 = sqlx::query_scalar("SELECT _supatype.preview_epoch()")
                .fetch_one(&mut *db)
                .await
                .expect("read the epoch");

            become_preview_bearer(db, &preview_claims("record", "posts", POST, epoch)).await;

            let visible: Vec<String> = sqlx::query_scalar(
                "SELECT title FROM draft.posts ORDER BY title",
            )
            .fetch_all(&mut *db)
            .await
            .expect("read drafts as the bearer");

            // The table owner is not subject to RLS here, so this asserts the
            // policy's own arithmetic through the helper rather than through
            // privilege: what the bearer's claim entitles them to.
            let entitled: (bool, bool) = sqlx::query_as(
                "SELECT _supatype.preview_allows('posts', $1), _supatype.preview_allows('posts', $2)",
            )
            .bind(POST)
            .bind(other)
            .fetch_one(&mut *db)
            .await
            .expect("evaluate the preview clause");

            assert!(entitled.0, "the link must open the record it names");
            assert!(!entitled.1, "and must not open any other");
            assert_eq!(visible.len(), 2, "the owner sees both; the claim is what differs");
        })
    })
    .await;
}

#[tokio::test]
async fn a_project_preview_link_opens_every_record() {
    with_seeded(|db| {
        Box::pin(async move {
            let epoch: i32 = sqlx::query_scalar("SELECT _supatype.preview_epoch()")
                .fetch_one(&mut *db)
                .await
                .expect("read the epoch");
            become_preview_bearer(db, &preview_claims("project", "", "", epoch)).await;

            let entitled: bool = sqlx::query_scalar(
                "SELECT _supatype.preview_allows('posts', $1) AND _supatype.preview_allows('ledger', $2)",
            )
            .bind(POST)
            .bind(LEDGER)
            .fetch_one(&mut *db)
            .await
            .expect("evaluate the preview clause");
            assert!(entitled, "a project link covers every model and every record");
        })
    })
    .await;
}

#[tokio::test]
async fn bumping_the_epoch_withdraws_every_outstanding_link() {
    with_seeded(|db| {
        Box::pin(async move {
            let epoch: i32 = sqlx::query_scalar("SELECT _supatype.preview_epoch()")
                .fetch_one(&mut *db)
                .await
                .expect("read the epoch");
            become_preview_bearer(db, &preview_claims("record", "posts", POST, epoch)).await;

            let before: bool = sqlx::query_scalar("SELECT _supatype.preview_allows('posts', $1)")
                .bind(POST)
                .fetch_one(&mut *db)
                .await
                .expect("evaluate before");
            assert!(before);

            // What `POST /admin/preview-links/revoke` does. A signed token cannot
            // be recalled, only outwaited, so this is the only thing that pulls
            // one early.
            sqlx::query(
                "UPDATE _supatype.publishing_settings SET preview_epoch = preview_epoch + 1
                  WHERE singleton",
            )
            .execute(&mut *db)
            .await
            .expect("bump the epoch");

            let after: bool = sqlx::query_scalar("SELECT _supatype.preview_allows('posts', $1)")
                .bind(POST)
                .fetch_one(&mut *db)
                .await
                .expect("evaluate after");
            assert!(
                !after,
                "a link minted under an older epoch must stop working"
            );
        })
    })
    .await;
}

#[tokio::test]
async fn a_request_with_no_preview_claim_is_entitled_to_nothing() {
    with_seeded(|db| {
        Box::pin(async move {
            let entitled: bool = sqlx::query_scalar("SELECT _supatype.preview_allows('posts', $1)")
                .bind(POST)
                .fetch_one(&mut *db)
                .await
                .expect("evaluate with an ordinary caller");
            assert!(
                !entitled,
                "an ordinary signed-in caller holds no preview link"
            );

            // And an empty claims setting must read as anonymous rather than raise:
            // `current_setting(…)::jsonb` errors on '' and that is not the same as
            // unset.
            sqlx::query("SELECT set_config('request.jwt.claims', '', false)")
                .execute(&mut *db)
                .await
                .expect("clear the claims");
            let empty: bool = sqlx::query_scalar("SELECT _supatype.preview_allows('posts', $1)")
                .bind(POST)
                .fetch_one(&mut *db)
                .await
                .expect("an empty claims setting must not raise");
            assert!(!empty);
        })
    })
    .await;
}

// ─── auth.uid() ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn auth_uid_is_null_for_a_request_with_no_subject() {
    with_seeded(|db| {
        Box::pin(async move {
            // It used to answer the nil UUID, and that is a hole rather than a convenience: a
            // `service_role` write has no subject, so it stamped ownership columns with the nil
            // UUID, and every *other* subject-less caller then satisfied `column = auth.uid()`.
            become_caller(db, None).await;
            let uid: Option<String> = sqlx::query_scalar("SELECT auth.uid()::text")
                .fetch_one(&mut *db)
                .await
                .expect("read auth.uid()");
            assert_eq!(uid, None, "no subject means no user, not user zero");
        })
    })
    .await;
}

#[tokio::test]
async fn auth_uid_reads_the_subject_when_there_is_one() {
    with_seeded(|db| {
        Box::pin(async move {
            let uid: Option<String> = sqlx::query_scalar("SELECT auth.uid()::text")
                .fetch_one(&mut *db)
                .await
                .expect("read auth.uid()");
            assert_eq!(uid.as_deref(), Some(EDITOR));
        })
    })
    .await;
}

#[tokio::test]
async fn the_auth_helpers_survive_an_empty_claims_setting() {
    with_seeded(|db| {
        Box::pin(async move {
            // `current_setting(…, true)` answers NULL when unset and the empty string when
            // something has set it to one, and `''::jsonb` raises `22P02`. Seven helpers each
            // carried their own unguarded cast, so such a request failed with a JSON syntax error
            // rather than reading as anonymous.
            sqlx::query("SELECT set_config('request.jwt.claims', '', false)")
                .execute(&mut *db)
                .await
                .expect("clear the claims");

            let row: (Option<String>, String, String, Option<String>) = sqlx::query_as(
                "SELECT auth.uid()::text, auth.role(), auth.email(),
                        auth.claim_text('app_metadata.tier')",
            )
            .fetch_one(&mut *db)
            .await
            .expect("every helper must read an empty claims setting as anonymous");

            assert_eq!(row.0, None);
            assert_eq!(row.1, "anon");
            assert_eq!(row.2, "");
            assert_eq!(row.3, None);
        })
    })
    .await;
}

#[tokio::test]
async fn a_subject_less_caller_does_not_match_a_row_owned_by_the_nil_uuid() {
    with_seeded(|db| {
        Box::pin(async move {
            // The shape of the old hole, written as the thing it must not do. A row whose owner
            // column literally holds the nil UUID must not belong to everyone who has no subject.
            become_caller(db, None).await;
            let matches: bool = sqlx::query_scalar(
                "SELECT '00000000-0000-0000-0000-000000000000'::uuid = auth.uid()",
            )
            .fetch_one(&mut *db)
            .await
            .map(|v: Option<bool>| v.unwrap_or(false))
            .expect("compare");
            assert!(!matches, "the nil UUID must not be everybody");
        })
    })
    .await;
}

#[tokio::test]
async fn an_anonymous_reader_can_still_read_a_versioned_model() {
    with_seeded(|db| {
        Box::pin(async move {
            save_draft(db, r#"{"title": "Public post"}"#).await;
            publish(db).await.expect("publish");

            // As `anon`, which is how the public reads a blog. Every other test here runs as the
            // table's owner, which holds privileges the public does not, so the suite passed
            // against a database no anonymous reader could use: the draft-aware policy was written
            // as an `EXISTS` over the snapshot table, and evaluating it needs a privilege `anon`
            // deliberately does not have. Ordinary reads of *published* content failed `42501`.
            sqlx::query("SET ROLE anon")
                .execute(&mut *db)
                .await
                .expect("become anon");

            let readable: Result<Option<String>, sqlx::Error> =
                sqlx::query_scalar("SELECT title FROM public.posts WHERE id = $1::uuid")
                    .bind(POST)
                    .fetch_optional(&mut *db)
                    .await;

            assert!(
                readable.is_ok(),
                "an anonymous read of a versioned model must not fail: {:?}",
                readable.err()
            );
        })
    })
    .await;
}

#[tokio::test]
async fn an_anonymous_reader_is_told_nothing_about_a_draft() {
    with_seeded(|db| {
        Box::pin(async move {
            save_draft(db, r#"{"title": "Not for the public"}"#).await;

            // Both halves of being anonymous. `SET ROLE anon` changes only the Postgres role; the
            // session keeps whatever claims were set, so a test that switched role alone would
            // still be the editor as far as every policy is concerned. It would pass while asserting
            // nothing.
            sqlx::query("SELECT set_config('request.jwt.claims', '', false)")
                .execute(&mut *db)
                .await
                .expect("drop the claims");
            sqlx::query("SET ROLE anon")
                .execute(&mut *db)
                .await
                .expect("become anon");

            // The helper the policy calls is SECURITY DEFINER, so it reads the snapshot table on the
            // caller's behalf. That is safe only because the predicate inside it is what withholds
            // the draft, not the privilege: this asserts the predicate still says no.
            let sees: bool = sqlx::query_scalar("SELECT _supatype.sees_draft_posts($1)")
                .bind(POST)
                .fetch_one(&mut *db)
                .await
                .expect("evaluate the draft clause as anon");
            assert!(!sees, "anonymous must never be shown a draft");
        })
    })
    .await;
}

#[tokio::test]
async fn usage_on_the_helper_schema_does_not_hand_anyone_the_maintenance_functions() {
    with_seeded(|db| {
        Box::pin(async move {
            // The API roles need USAGE here so a draft policy can resolve the helper it calls.
            // Postgres grants EXECUTE on a new function to PUBLIC, so without the revokes that
            // USAGE also hands every role `prune_versions`, which is SECURITY DEFINER and deletes
            // history.
            sqlx::query("SET ROLE anon")
                .execute(&mut *db)
                .await
                .expect("become anon");

            let pruning = sqlx::query("SELECT _supatype.prune_versions()")
                .execute(&mut *db)
                .await;
            assert!(
                pruning.is_err(),
                "anonymous must not be able to delete version history"
            );

            let publishing = sqlx::query("SELECT _supatype.run_due_publishes()")
                .execute(&mut *db)
                .await;
            assert!(
                publishing.is_err(),
                "anonymous must not be able to run the publishing job"
            );

            sqlx::query("RESET ROLE")
                .execute(&mut *db)
                .await
                .expect("reset");
        })
    })
    .await;
}

/// A link row, minted the way the server does.
async fn insert_link(
    db: &mut PgConnection,
    id: &str,
    expires: &str,
    revoked: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO _supatype.preview_links
           (id, secret_hash, scope, model, record_id, epoch, expires_at, revoked_at)
         VALUES ($1, 'not-a-real-hash', 'record', 'posts', $2, 1,
                 now() + $3::interval, CASE WHEN $4 = '' THEN NULL ELSE now() + $4::interval END)",
    )
    .bind(id)
    .bind(POST)
    .bind(expires)
    .bind(revoked.unwrap_or(""))
    .execute(db)
    .await
    .map(|_| ())
}

#[tokio::test]
async fn a_record_link_must_name_the_record_it_covers() {
    with_seeded(|db| {
        Box::pin(async move {
            // A record-scoped row with no record resolves to a claim that matches nothing, so the
            // holder is told the draft does not exist rather than that their link is malformed.
            let bad = sqlx::query(
                "INSERT INTO _supatype.preview_links
                   (id, secret_hash, scope, epoch, expires_at)
                 VALUES ('pl_bad', 'h', 'record', 1, now() + interval '1 hour')",
            )
            .execute(&mut *db)
            .await;
            assert!(bad.is_err(), "a record link with no record must be refused");

            // The same row as a project link is fine: it covers everything by construction.
            sqlx::query(
                "INSERT INTO _supatype.preview_links
                   (id, secret_hash, scope, epoch, expires_at)
                 VALUES ('pl_project', 'h', 'project', 1, now() + interval '1 hour')",
            )
            .execute(&mut *db)
            .await
            .expect("a project link needs no record");
        })
    })
    .await;
}

#[tokio::test]
async fn the_api_roles_cannot_read_the_link_table() {
    with_seeded(|db| {
        Box::pin(async move {
            insert_link(db, "pl_secret", "1 hour", None)
                .await
                .expect("seed a link");

            // The schema grants USAGE so draft policies can resolve their helpers. That must not
            // carry the table with it: these rows are what a link is checked against.
            for role in ["anon", "authenticated", "service_role"] {
                sqlx::query(&format!("SET ROLE {role}"))
                    .execute(&mut *db)
                    .await
                    .unwrap_or_else(|_| panic!("become {role}"));
                let read = sqlx::query("SELECT secret_hash FROM _supatype.preview_links")
                    .fetch_all(&mut *db)
                    .await;
                assert!(read.is_err(), "{role} must not read preview link hashes");
                sqlx::query("RESET ROLE")
                    .execute(&mut *db)
                    .await
                    .expect("reset");
            }
        })
    })
    .await;
}

#[tokio::test]
async fn pruning_keeps_a_dead_link_long_enough_to_explain_itself() {
    with_seeded(|db| {
        Box::pin(async move {
            sqlx::query("DELETE FROM _supatype.preview_links WHERE TRUE")
                .execute(&mut *db)
                .await
                .expect("clear links");

            insert_link(db, "pl_live", "1 hour", None)
                .await
                .expect("live");
            insert_link(db, "pl_recent", "-1 hour", None)
                .await
                .expect("just expired");
            insert_link(db, "pl_ancient", "-30 days", None)
                .await
                .expect("long dead");
            insert_link(db, "pl_revoked", "30 days", Some("-30 days"))
                .await
                .expect("revoked long ago");

            let removed: i32 = sqlx::query_scalar("SELECT _supatype.prune_preview_links()")
                .fetch_one(&mut *db)
                .await
                .expect("prune");
            assert_eq!(removed, 2, "only links dead more than a week go");

            let left: Vec<String> =
                sqlx::query_scalar("SELECT id FROM _supatype.preview_links ORDER BY id")
                    .fetch_all(&mut *db)
                    .await
                    .expect("list");
            // The recently expired one stays on purpose: "why did that link stop working" is asked
            // after the fact, and a missing row cannot tell it apart from a link that never was.
            assert_eq!(left, vec!["pl_live".to_string(), "pl_recent".to_string()]);
        })
    })
    .await;
}

#[tokio::test]
async fn a_blanket_grant_does_not_survive_the_next_push() {
    with_seeded(|db| {
        Box::pin(async move {
            // Postgres grants nothing on a new table, so the previous test passes with or without
            // the explicit revoke. This is the case the revoke is actually for: a project that has
            // run `GRANT ALL ON ALL TABLES IN SCHEMA` for its own reasons, which sweeps up a table
            // holding the material every preview link is checked against.
            sqlx::query("GRANT SELECT ON ALL TABLES IN SCHEMA _supatype TO anon")
                .execute(&mut *db)
                .await
                .expect("a project may grant broadly in its own database");

            sqlx::query("SET ROLE anon")
                .execute(&mut *db)
                .await
                .expect("become anon");
            let granted = sqlx::query("SELECT id FROM _supatype.preview_links")
                .fetch_all(&mut *db)
                .await;
            sqlx::query("RESET ROLE")
                .execute(&mut *db)
                .await
                .expect("reset");
            assert!(
                granted.is_ok(),
                "the blanket grant must really have applied"
            );

            // Pushing again takes it back, so the exposure lasts until the next deploy rather than
            // for ever: the versions layer, which every push re-asserts, revokes it.
            let ast = parser::parse(include_str!("fixtures/versioned_blog.json")).unwrap();
            let layer =
                supatype_engine::generator::sql::versions::render_versions_layer(&ast, "public")
                    .expect("the layer renders");
            db.execute(sqlx::raw_sql(&layer))
                .await
                .expect("re-apply the versions layer");

            sqlx::query("SET ROLE anon")
                .execute(&mut *db)
                .await
                .expect("become anon");
            let after = sqlx::query("SELECT id FROM _supatype.preview_links")
                .fetch_all(&mut *db)
                .await;
            sqlx::query("RESET ROLE")
                .execute(&mut *db)
                .await
                .expect("reset");
            assert!(
                after.is_err(),
                "the push must revoke the blanket grant again"
            );
        })
    })
    .await;
}
