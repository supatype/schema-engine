//! A bucket rule can bind the first folder of an object's path to the caller, and can keep guests
//! out, against a real `storage.objects` with row-level security on.
//!
//! `BucketOwner` alone does not do this: the storage service writes `owner` as the caller on every
//! upload, so `owner = caller` is true on insert whatever the path says, and any signed-in user
//! could upload under another user's folder. `Eq<Folder<1>, AuthUid>` is the rule that names the
//! path, and on update it is checked against the old name and the new one.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst};

use common::{exec, push};

const USER_A: &str = "8517c5e3-067d-4327-9dfc-ba8f8b4bc4f7";
const USER_B: &str = "0b1f4e7a-5c1d-4a52-9d3a-2f6f4f1a9e10";

fn folder_is_caller() -> Value {
    json!({ "type": "compare", "op": "eq",
            "left": { "kind": "folder", "index": 1 }, "right": { "kind": "authUid" } })
}

fn registered_only() -> Value {
    json!({ "type": "all", "rules": [
        { "type": "authenticated" },
        { "type": "compare", "op": "eq",
          "left":  { "kind": "claim", "path": "is_anonymous" },
          "right": { "kind": "literal", "value": false } } ] })
}

/// `docs` binds the folder, `members` admits registered users only, `loose` is `BucketOwner` alone.
fn schema() -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": [], "storageBuckets": [
        { "id": "docs", "public": false, "accessMode": "private", "access": {
            "read": folder_is_caller(), "create": folder_is_caller(),
            "update": folder_is_caller(), "delete": folder_is_caller() } },
        { "id": "members", "public": false, "accessMode": "private", "access": {
            "read": { "type": "authenticated" }, "create": registered_only() } },
        { "id": "loose", "public": false, "accessMode": "private", "access": {
            "read": { "type": "owner", "field": "owner_id" },
            "create": { "type": "owner", "field": "owner_id" } } },
    ]});
    parser::parse(&doc.to_string()).expect("fixture parses")
}

async fn api_roles(pool: &PgPool) {
    exec(
        pool,
        "CREATE SCHEMA IF NOT EXISTS auth;
         DO $$ BEGIN
           BEGIN CREATE ROLE anon NOLOGIN NOINHERIT;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
           BEGIN CREATE ROLE authenticated NOLOGIN NOINHERIT;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
           BEGIN CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
         END $$;",
    )
    .await
    .unwrap();
    exec(
        pool,
        &supatype_engine::generator::sql::rls::generate_auth_helpers(),
    )
    .await
    .unwrap();
}

/// Runs `sql` as `authenticated` carrying a token for `sub` (and `is_anonymous` when given),
/// rolled back. The error text is the database's, so a refusal can be told from a bad query.
async fn as_caller(
    pool: &PgPool,
    sub: &str,
    anonymous: Option<bool>,
    sql: &str,
) -> Result<u64, String> {
    let mut claims = json!({ "role": "authenticated", "sub": sub });
    if let Some(flag) = anonymous {
        claims["is_anonymous"] = json!(flag);
    }
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(claims.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::raw_sql("SET LOCAL ROLE authenticated")
        .execute(&mut *tx)
        .await
        .unwrap();
    let result = sqlx::raw_sql(sql)
        .execute(&mut *tx)
        .await
        .map(|done| done.rows_affected())
        .map_err(|e| e.to_string());
    let _ = tx.rollback().await;
    result
}

fn upload(bucket: &str, name: &str, owner: &str) -> String {
    format!("INSERT INTO storage.objects (bucket_id, name, owner) VALUES ('{bucket}', '{name}', '{owner}')")
}

fn assert_refused(result: Result<u64, String>, what: &str) {
    let message = result.expect_err(&format!("{what} is refused"));
    assert!(message.contains("row-level security"), "{what}: {message}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_user_uploads_under_their_own_folder_and_no_other() {
    common::with_integration_pool(|pool| async move {
        api_roles(&pool).await;
        push(&pool, &schema()).await.unwrap();

        as_caller(
            &pool,
            USER_A,
            Some(false),
            &upload("docs", &format!("{USER_A}/x"), USER_A),
        )
        .await
        .expect("a user uploads under their own folder");
        assert_refused(
            as_caller(
                &pool,
                USER_A,
                Some(false),
                &upload("docs", &format!("{USER_B}/x"), USER_A),
            )
            .await,
            "uploading under another user's folder",
        );
        assert_refused(
            as_caller(&pool, USER_A, Some(false), &upload("docs", "x", USER_A)).await,
            "uploading at the root, which has no first folder",
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rename_cannot_move_an_object_into_another_users_folder() {
    common::with_integration_pool(|pool| async move {
        api_roles(&pool).await;
        push(&pool, &schema()).await.unwrap();
        exec(&pool, &upload("docs", &format!("{USER_A}/x"), USER_A)).await.unwrap();

        let rename = |to: &str| {
            format!("UPDATE storage.objects SET name = '{to}' WHERE bucket_id = 'docs' AND name = '{USER_A}/x'")
        };
        let moved = as_caller(&pool, USER_A, Some(false), &rename(&format!("{USER_A}/y")))
            .await
            .expect("a rename inside the folder is allowed");
        assert_eq!(moved, 1, "the rename inside the folder changed the row");
        assert_refused(
            as_caller(&pool, USER_A, Some(false), &rename(&format!("{USER_B}/x"))).await,
            "renaming into another user's folder",
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_guest_cannot_upload_under_the_registered_rule() {
    common::with_integration_pool(|pool| async move {
        api_roles(&pool).await;
        push(&pool, &schema()).await.unwrap();

        let insert = upload("members", "x", USER_A);
        as_caller(&pool, USER_A, Some(false), &insert)
            .await
            .expect("a registered user uploads");
        assert_refused(
            as_caller(&pool, USER_A, Some(true), &insert).await,
            "a guest",
        );
        assert_refused(
            as_caller(&pool, USER_A, None, &insert).await,
            "a token with no is_anonymous claim",
        );
    })
    .await;
}

/// The gap the docs warn about: `BucketOwner` alone lets a user create under any path.
#[tokio::test(flavor = "multi_thread")]
async fn owner_alone_does_not_bind_the_path() {
    common::with_integration_pool(|pool| async move {
        api_roles(&pool).await;
        push(&pool, &schema()).await.unwrap();

        as_caller(
            &pool,
            USER_A,
            Some(false),
            &upload("loose", &format!("{USER_B}/x"), USER_A),
        )
        .await
        .expect("owner = caller is true on insert whatever the path says");
    })
    .await;
}
