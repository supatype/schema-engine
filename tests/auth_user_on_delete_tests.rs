//! A `SupatypeAuthUserId` field linked to `auth.users` with a delete behaviour.
//!
//! An auth user id has no foreign key by default. `SupatypeAuthUserId<{ onDelete }>` opts one field
//! in: the CLI writes `annotations.db.authUserOnDelete`, and the push adds
//! `FOREIGN KEY (col) REFERENCES auth.users (id) ON DELETE <action>` as a key on the ledger, so a
//! later push adds, changes and drops it with the schema. A push refuses, before it applies
//! anything, when `auth.users` is missing or when rows already name a user that does not exist.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    introspector::fingerprint::ObjectKind,
    ledger::{self, Status},
    parser,
    parser::ast::SchemaAst,
    push,
};

use common::{exec, push};

const FK: &str = "comments_user_id_fkey";
const ADA: &str = "00000000-0000-0000-0000-00000000000a";
const NOBODY: &str = "00000000-0000-0000-0000-0000000000ff";

fn int_pk() -> Value {
    json!({ "kind": "integer", "primaryKey": true, "required": true,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } })
}

/// `user_id: SupatypeAuthUserId`, with `onDelete` when given, `Optional<>` when not `required`.
fn user_id(required: bool, on_delete: Option<&str>) -> Value {
    let mut db = json!({ "pgType": "UUID", "unique": false, "authUserId": true });
    if let Some(action) = on_delete {
        db["authUserOnDelete"] = action.into();
    }
    json!({ "kind": "uuid", "required": required, "annotations": { "db": db } })
}

fn document(user_id: Value) -> String {
    json!({
        "astVersion": 2,
        "models": [{
            "name": "Comment",
            "fields": { "id": int_pk(), "user_id": user_id },
            "options": { "timestamps": false, "softDelete": false, "singleton": false },
            "annotations": { "db": { "tableName": "comments", "indexes": [] }, "platform": {} }
        }]
    })
    .to_string()
}

fn comments(required: bool, on_delete: Option<&str>) -> SchemaAst {
    parser::parse(&document(user_id(required, on_delete))).expect("fixture parses")
}

fn parse_err(required: bool, on_delete: &str) -> String {
    let err = parser::parse(&document(user_id(required, Some(on_delete))))
        .expect_err("the schema is refused");
    format!("{err:#}")
}

async fn create_auth_users(pool: &PgPool) {
    exec(
        pool,
        "CREATE SCHEMA IF NOT EXISTS auth;
         CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY);",
    )
    .await
    .unwrap();
}

/// `pg_constraint.confdeltype` of the key (`c` cascade, `r` restrict, `n` set null), and the
/// schema-qualified table it points at; `None` when there is no such key.
async fn fk_shape(pool: &PgPool) -> Option<(String, String)> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT k.confdeltype::text, n.nspname || '.' || r.relname FROM pg_constraint k \
         JOIN pg_class r ON r.oid = k.confrelid JOIN pg_namespace n ON n.oid = r.relnamespace \
         WHERE k.conrelid = 'public.comments'::regclass AND k.conname = $1",
    )
    .bind(FK)
    .fetch_optional(pool)
    .await
    .unwrap()
}

async fn fk_rows(pool: &PgPool) -> Vec<ledger::LedgerRow> {
    let mut conn = pool.acquire().await.unwrap();
    ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == ObjectKind::ForeignKey)
        .collect()
}

async fn applied(pool: &PgPool, ast: &SchemaAst) {
    let outcome = push(pool, ast).await.unwrap();
    assert!(
        matches!(outcome, push::Outcome::Applied { .. }),
        "{outcome:?}"
    );
}

async fn up_to_date(pool: &PgPool, ast: &SchemaAst) {
    let outcome = push(pool, ast).await.unwrap();
    assert!(
        matches!(outcome, push::Outcome::UpToDate { .. }),
        "no perpetual diff: {outcome:?}"
    );
}

/// Ada, with one comment, then Ada deleted: what is left of her comment, if the delete went
/// through.
async fn delete_ada_with_a_comment(pool: &PgPool) -> Result<Option<Option<String>>, sqlx::Error> {
    exec(
        pool,
        &format!(
            "INSERT INTO auth.users (id) VALUES ('{ADA}');
             INSERT INTO public.comments (id, user_id) VALUES (1, '{ADA}');"
        ),
    )
    .await
    .unwrap();
    exec(pool, &format!("DELETE FROM auth.users WHERE id = '{ADA}'")).await?;
    Ok(sqlx::query_scalar::<_, Option<String>>(
        "SELECT user_id::text FROM public.comments WHERE id = 1",
    )
    .fetch_optional(pool)
    .await
    .unwrap())
}

#[tokio::test]
async fn cascade_deletes_the_rows_with_their_user_and_is_kept_on_the_ledger() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        let ast = comments(true, Some("cascade"));
        applied(&pool, &ast).await;
        assert_eq!(
            fk_shape(&pool).await,
            Some(("c".into(), "auth.users".into()))
        );
        let rows = fk_rows(&pool).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].key.name, FK);
        assert_eq!(rows[0].status, Status::Managed);
        assert!(
            rows[0].live_def.contains("references=auth.users\n"),
            "{}",
            rows[0].live_def
        );
        up_to_date(&pool, &ast).await;

        assert_eq!(delete_ada_with_a_comment(&pool).await.unwrap(), None);
    })
    .await;
}

#[tokio::test]
async fn restrict_refuses_to_delete_a_user_who_still_owns_rows() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        let ast = comments(true, Some("restrict"));
        applied(&pool, &ast).await;
        assert_eq!(
            fk_shape(&pool).await,
            Some(("r".into(), "auth.users".into()))
        );
        up_to_date(&pool, &ast).await;

        let refused = delete_ada_with_a_comment(&pool)
            .await
            .expect_err("the user still owns a comment");
        let code = refused
            .as_database_error()
            .and_then(|e| e.code())
            .map(|c| c.to_string());
        assert_eq!(code.as_deref(), Some("23503"), "{refused}");
        assert!(refused.to_string().contains(FK), "{refused}");
    })
    .await;
}

#[tokio::test]
async fn set_null_keeps_the_rows_without_their_user() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        let ast = comments(false, Some("setNull"));
        applied(&pool, &ast).await;
        assert_eq!(
            fk_shape(&pool).await,
            Some(("n".into(), "auth.users".into()))
        );
        up_to_date(&pool, &ast).await;

        assert_eq!(delete_ada_with_a_comment(&pool).await.unwrap(), Some(None));
    })
    .await;
}

#[test]
fn set_null_on_a_required_field_is_a_schema_error() {
    let message = parse_err(true, "setNull");
    assert!(message.contains("Comment"), "{message}");
    assert!(message.contains("user_id"), "{message}");
    assert!(message.contains("Optional<"), "{message}");
    assert!(
        message.contains("cascade") && message.contains("restrict"),
        "{message}"
    );
}

#[test]
fn an_unknown_delete_behaviour_is_a_schema_error() {
    let message = parse_err(false, "noAction");
    assert!(message.contains("noAction"), "{message}");
    assert!(message.contains("setNull"), "{message}");
}

#[test]
fn on_delete_on_a_field_that_is_not_an_auth_user_id_is_a_schema_error() {
    let mut field = user_id(false, Some("cascade"));
    field["annotations"]["db"]
        .as_object_mut()
        .unwrap()
        .remove("authUserId");
    let err = parser::parse(&document(field)).expect_err("only an auth user id links to a user");
    let message = format!("{err:#}");
    assert!(message.contains("user_id"), "{message}");
    assert!(message.contains("SupatypeAuthUserId"), "{message}");
}

#[test]
fn no_option_means_no_foreign_key() {
    let ast = comments(true, None);
    let desired = supatype_engine::desired::desired_objects(&ast, "public").unwrap();
    assert!(
        desired.iter().all(|o| o.key.kind != ObjectKind::ForeignKey),
        "an auth user id has no key unless it asks for one"
    );
}

#[tokio::test]
async fn a_push_refuses_when_auth_users_does_not_exist() {
    common::with_integration_pool(|pool| async move {
        let refused = push(&pool, &comments(true, Some("cascade")))
            .await
            .expect_err("there is no auth.users to point at");
        let message = format!("{refused:#}");
        assert!(message.contains("auth.users"), "{message}");
        assert!(message.contains("comments.user_id"), "{message}");
        assert!(message.contains("onDelete"), "{message}");
        let exists: bool = sqlx::query_scalar("SELECT to_regclass('public.comments') IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!exists, "nothing was applied");
    })
    .await;
}

#[tokio::test]
async fn a_push_refuses_to_link_rows_that_name_a_missing_user_and_says_how_many() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        applied(&pool, &comments(false, None)).await;
        exec(
            &pool,
            &format!(
                "INSERT INTO auth.users (id) VALUES ('{ADA}');
                 INSERT INTO public.comments (id, user_id) VALUES
                   (1, '{ADA}'), (2, '{NOBODY}'), (3, '{NOBODY}'), (4, NULL);"
            ),
        )
        .await
        .unwrap();

        let refused = push(&pool, &comments(false, Some("cascade")))
            .await
            .expect_err("two comments name a user that does not exist");
        let message = format!("{refused:#}");
        assert!(message.contains("2 row(s)"), "{message}");
        assert!(message.contains("comments.user_id"), "{message}");
        assert!(message.contains("auth.users"), "{message}");
        assert!(
            message.contains("DELETE FROM"),
            "how to fix them: {message}"
        );
        assert_eq!(fk_shape(&pool).await, None, "nothing was applied");

        exec(
            &pool,
            &format!("DELETE FROM public.comments WHERE user_id = '{NOBODY}'"),
        )
        .await
        .unwrap();
        applied(&pool, &comments(false, Some("cascade"))).await;
        assert_eq!(
            fk_shape(&pool).await,
            Some(("c".into(), "auth.users".into()))
        );
    })
    .await;
}

#[tokio::test]
async fn the_key_follows_the_option_as_it_is_added_changed_and_removed() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        let plain = comments(false, None);
        applied(&pool, &plain).await;
        assert_eq!(fk_shape(&pool).await, None);

        for (action, deltype) in [("cascade", "c"), ("restrict", "r"), ("setNull", "n")] {
            let ast = comments(false, Some(action));
            applied(&pool, &ast).await;
            assert_eq!(
                fk_shape(&pool).await,
                Some((deltype.into(), "auth.users".into())),
                "{action}"
            );
            assert_eq!(fk_rows(&pool).await.len(), 1, "{action}");
            up_to_date(&pool, &ast).await;
        }

        applied(&pool, &plain).await;
        assert_eq!(
            fk_shape(&pool).await,
            None,
            "removing the option drops the key"
        );
        assert!(fk_rows(&pool).await.is_empty());
        up_to_date(&pool, &plain).await;
    })
    .await;
}
