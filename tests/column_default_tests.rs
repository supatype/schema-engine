//! A push converges a column's DEFAULT on a table that already exists.
//!
//! The column differ compared types, nullability, identity and generation, never the default, so a
//! default declared, changed or removed after a table was created stayed as the first push left it.
//! That is how an existing project never received the owner default (`_supatype.jwt_uid()`) added
//! for C7. A default is now set, changed and dropped like any other column property, as a safe
//! change, and a second push plans nothing.

mod common;

use serde_json::{json, Value};
use supatype_engine::differ::Operation;
use supatype_engine::parser::{self, ast::SchemaAst};

fn note(default: Option<Value>) -> SchemaAst {
    let mut label = json!({ "kind": "text", "required": false,
                            "annotations": { "db": { "pgType": "TEXT", "unique": false } } });
    if let Some(default) = default {
        label["default"] = default;
    }
    let model = json!({
        "name": "Note",
        "fields": {
            "id": { "kind": "uuid", "primaryKey": true, "required": true,
                    "default": { "kind": "genRandomUuid" },
                    "annotations": { "db": { "pgType": "UUID", "unique": false } } },
            "label": label
        },
        "options": { "timestamps": true, "softDelete": false },
        "annotations": { "db": { "tableName": "cd_note", "indexes": [] },
                         "platform": { "access": { "read": { "type": "public" } } } }
    });
    let doc = json!({ "astVersion": 2, "models": [model] });
    parser::parse(&doc.to_string()).expect("the fixture parses")
}

fn literal(text: &str) -> Option<Value> {
    Some(json!({ "kind": "value", "value": text }))
}

async fn label_default(pool: &sqlx::PgPool) -> Option<String> {
    sqlx::query_scalar(
        "SELECT column_default::text FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = 'cd_note' AND column_name = 'label'",
    )
    .fetch_one(pool)
    .await
    .expect("the column exists")
}

/// The column operations a push of `ast` would plan now.
async fn planned_column_ops(pool: &sqlx::PgPool, ast: &SchemaAst) -> Vec<String> {
    let plan = supatype_engine::push::prepare(pool, ast, "public")
        .await
        .expect("plans");
    plan.diff
        .operations
        .iter()
        .filter(|op| {
            matches!(
                op,
                Operation::AlterColumn { .. } | Operation::AddColumn { .. }
            )
        })
        .map(|op| format!("{op:?}"))
        .collect()
}

async fn push_and_settle(pool: &sqlx::PgPool, ast: &SchemaAst) {
    common::push(pool, ast).await.expect("push");
    assert_eq!(planned_column_ops(pool, ast).await, Vec::<String>::new());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_default_is_added_changed_and_dropped_on_an_existing_column() {
    common::with_integration_pool(|pool| async move {
        push_and_settle(&pool, &note(None)).await;
        assert_eq!(label_default(&pool).await, None);

        push_and_settle(&pool, &note(literal("hello"))).await;
        assert_eq!(label_default(&pool).await.as_deref(), Some("'hello'::text"));

        push_and_settle(&pool, &note(literal("bye"))).await;
        assert_eq!(label_default(&pool).await.as_deref(), Some("'bye'::text"));

        push_and_settle(&pool, &note(None)).await;
        assert_eq!(label_default(&pool).await, None);
    })
    .await;
}

/// The owner default reaches a project whose comment table predates it.
#[tokio::test(flavor = "multi_thread")]
async fn an_expression_default_converges_and_settles() {
    common::with_integration_pool(|pool| async move {
        push_and_settle(&pool, &note(None)).await;
        let now = Some(json!({ "kind": "expression", "expr": "upper('x')" }));
        push_and_settle(&pool, &note(now)).await;
        assert_eq!(
            label_default(&pool).await.as_deref(),
            Some("upper('x'::text)")
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_existing_owner_column_gains_the_caller_default() {
    common::with_integration_pool(|pool| async move {
        common::exec(
            &pool,
            &supatype_engine::generator::sql::rls::generate_auth_helpers(),
        )
        .await
        .expect("auth helpers");
        let comment = |create: Value| {
            let model = json!({
                "name": "Comment",
                "fields": {
                    "id": { "kind": "uuid", "primaryKey": true, "required": true,
                            "default": { "kind": "genRandomUuid" },
                            "annotations": { "db": { "pgType": "UUID", "unique": false } } },
                    "user_id": { "kind": "uuid", "required": true,
                                 "annotations": { "db": { "pgType": "UUID", "unique": false,
                                                          "authUserId": true } } }
                },
                "options": { "timestamps": false, "softDelete": false },
                "annotations": { "db": { "tableName": "cd_comment", "indexes": [] },
                                 "platform": { "access": { "read": { "type": "public" },
                                                           "create": create } } }
            });
            let doc = json!({ "astVersion": 2, "models": [model] });
            parser::parse(&doc.to_string()).expect("the fixture parses")
        };
        let before = comment(json!({ "type": "role", "roles": ["admin"] }));
        push_and_settle(&pool, &before).await;
        let after = comment(json!({ "type": "owner", "field": "user_id" }));
        push_and_settle(&pool, &after).await;
        let default: Option<String> = sqlx::query_scalar(
            "SELECT column_default::text FROM information_schema.columns
              WHERE table_name = 'cd_comment' AND column_name = 'user_id'",
        )
        .fetch_one(&pool)
        .await
        .expect("the column exists");
        assert_eq!(default.as_deref(), Some("_supatype.jwt_uid()"));
    })
    .await;
}
