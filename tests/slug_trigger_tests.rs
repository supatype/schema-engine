//! A slug column holds a slug, whoever writes the row and however.
//!
//! The trigger used to fill an empty slug from its source on `INSERT` only. An `UPDATE` that set
//! the slug to NULL or to an empty string wrote exactly that, so a required slug refused the write
//! with `null value in column "slug"`, and an optional one kept an empty string. `publish` copies a
//! version into the live row with an `UPDATE`, so a draft saved with an empty slug (a client that
//! does not fill it, or a draft older than the client that does) could not be published at all.
//!
//! These run against a real database: the claim is about what Postgres does with the write, and a
//! test of the emitted SQL would prove the text of a trigger and nothing else.

mod common;

use std::future::Future;

use sqlx::PgConnection;
use supatype_engine::parser::{self, ast::SchemaAst};

const SCHEMA: &str = r#"{
    "astVersion": 2,
    "publishing": {
        "draftVisibility": ["admin", "developer", "editor"],
        "previewDefaultTtl": 900,
        "previewMaxRecordTtl": 604800,
        "previewMaxProjectTtl": 86400,
        "previewAllowProjectScope": true
    },
    "models": [
        {
            "name": "Speaker",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"},
                       "annotations": {"db": {"pgType": "UUID"}}},
                "name": {"kind": "text", "required": true,
                         "annotations": {"db": {"pgType": "TEXT"}}},
                "slug": {"kind": "slug", "required": true, "from": "name",
                         "annotations": {"db": {"pgType": "TEXT", "unique": true}}},
                "published_at": {"kind": "timestamp", "required": false,
                                 "annotations": {"db": {"pgType": "TIMESTAMPTZ"}}}
            },
            "options": {
                "timestamps": true,
                "softDelete": false,
                "versions": {"drafts": true, "keep": 5}
            },
            "annotations": {
                "db": {"tableName": "speakers", "indexes": []},
                "platform": {
                    "access": {
                        "read": {"type": "public"},
                        "update": {"type": "role", "roles": ["editor"]}
                    }
                }
            }
        }
    ]
}"#;

const EDITOR: &str = "11111111-1111-1111-1111-111111111111";
const SPEAKER: &str = "44444444-4444-4444-4444-444444444444";

fn schema() -> SchemaAst {
    parser::parse(SCHEMA).expect("the schema fixture parses")
}

/// Under testcontainers the tests share one database, and cargo runs them on parallel threads.
static FIXTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Push the schema, become an editor on one connection and seed one speaker named "Ada Lovelace".
///
/// One connection because `request.jwt.claims` is a session setting: a pool hands successive
/// queries to different connections, and a caller set on one is no caller on another.
async fn with_speaker<F>(f: F)
where
    F: for<'a> FnOnce(
            &'a mut PgConnection,
        ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'a>>
        + Send,
{
    common::with_integration_pool(|pool| async move {
        let _guard = FIXTURE_LOCK.lock().await;
        common::push(&pool, &schema())
            .await
            .expect("the schema pushes, triggers included");
        let mut conn = pool.acquire().await.expect("acquire one connection");
        let claims =
            serde_json::json!({ "sub": EDITOR, "role": "authenticated", "roles": ["editor"] });
        sqlx::query("SELECT set_config('request.jwt.claims', $1, false)")
            .bind(claims.to_string())
            .execute(&mut *conn)
            .await
            .expect("set claims");
        sqlx::query("DELETE FROM public.speakers WHERE id = $1::uuid")
            .bind(SPEAKER)
            .execute(&mut *conn)
            .await
            .expect("clear the fixture row");
        sqlx::query("INSERT INTO public.speakers (id, name) VALUES ($1::uuid, 'Ada Lovelace')")
            .bind(SPEAKER)
            .execute(&mut *conn)
            .await
            .expect("seed a speaker");
        f(&mut conn).await;
    })
    .await;
}

async fn live_slug(db: &mut PgConnection) -> Option<String> {
    sqlx::query_scalar("SELECT slug FROM public.speakers WHERE id = $1::uuid")
        .bind(SPEAKER)
        .fetch_one(db)
        .await
        .expect("read the live row")
}

async fn update(db: &mut PgConnection, set: &str) -> Result<(), sqlx::Error> {
    sqlx::query(&format!(
        "UPDATE public.speakers SET {set} WHERE id = $1::uuid"
    ))
    .bind(SPEAKER)
    .execute(db)
    .await
    .map(|_| ())
}

async fn save_draft(db: &mut PgConnection, patch: &str) {
    sqlx::query("SELECT supatype.create_draft('speakers', $1, $2::jsonb)")
        .bind(SPEAKER)
        .bind(patch)
        .execute(db)
        .await
        .expect("create_draft");
}

async fn publish(db: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT supatype.publish('speakers', $1)")
        .bind(SPEAKER)
        .execute(db)
        .await
        .map(|_| ())
}

#[tokio::test]
async fn an_update_that_empties_the_slug_refills_it_from_the_source() {
    with_speaker(|db| {
        Box::pin(async move {
            assert_eq!(live_slug(db).await.as_deref(), Some("ada-lovelace"));

            update(db, "slug = NULL")
                .await
                .expect("a NULL slug on update is filled, not refused by NOT NULL");
            assert_eq!(live_slug(db).await.as_deref(), Some("ada-lovelace"));

            update(db, "slug = '   '")
                .await
                .expect("a blank slug on update is filled");
            assert_eq!(live_slug(db).await.as_deref(), Some("ada-lovelace"));

            // Emptied in the same write that renames: the slug follows the new source.
            update(db, "slug = '', name = 'Grace Hopper'")
                .await
                .expect("an emptied slug with a new source is filled");
            assert_eq!(live_slug(db).await.as_deref(), Some("grace-hopper"));
        })
    })
    .await;
}

#[tokio::test]
async fn a_slug_that_is_set_is_left_alone() {
    with_speaker(|db| {
        Box::pin(async move {
            update(db, "slug = 'the-countess'")
                .await
                .expect("set a slug by hand");
            assert_eq!(live_slug(db).await.as_deref(), Some("the-countess"));

            // A hand-set slug no longer matches its source, so a rename must not overwrite it.
            update(db, "name = 'Augusta Ada King'")
                .await
                .expect("rename");
            assert_eq!(live_slug(db).await.as_deref(), Some("the-countess"));
        })
    })
    .await;
}

#[tokio::test]
async fn publishing_a_version_with_an_empty_slug_gives_the_live_row_one() {
    with_speaker(|db| {
        Box::pin(async move {
            // Empty string: the NOT NULL constraint accepts it, so without the trigger the live
            // row would silently carry an empty slug.
            save_draft(db, r#"{"slug": ""}"#).await;
            publish(db)
                .await
                .expect("a version with an empty slug publishes");
            assert_eq!(live_slug(db).await.as_deref(), Some("ada-lovelace"));

            // NULL: the case seen live, refused with `null value in column "slug"`.
            save_draft(db, r#"{"slug": null, "name": "Grace Hopper"}"#).await;
            publish(db)
                .await
                .expect("a version with a NULL slug publishes");
            assert_eq!(live_slug(db).await.as_deref(), Some("grace-hopper"));
        })
    })
    .await;
}
