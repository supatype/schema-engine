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

/// The model of each fixture: its name, table and whether it carries timestamps.
struct Model {
    name: &'static str,
    table: &'static str,
    timestamps: bool,
}

/// A one-model schema of `model`: a uuid `id` and the one field `name`, declared by `field`, with
/// `default` when one is given.
fn one_field(model: &Model, name: &str, mut field: Value, default: Option<Value>) -> SchemaAst {
    if let Some(default) = default {
        field["default"] = default;
    }
    let mut fields = json!({
        "id": { "kind": "uuid", "primaryKey": true, "required": true,
                "default": { "kind": "genRandomUuid" },
                "annotations": { "db": { "pgType": "UUID", "unique": false } } }
    });
    fields[name] = field;
    let model = json!({
        "name": model.name,
        "fields": fields,
        "options": { "timestamps": model.timestamps, "softDelete": false },
        "annotations": { "db": { "tableName": model.table, "indexes": [] },
                         "platform": { "access": { "read": { "type": "public" } } } }
    });
    let doc = json!({ "astVersion": 2, "models": [model] });
    parser::parse(&doc.to_string()).expect("the fixture parses")
}

fn note(default: Option<Value>) -> SchemaAst {
    let label = json!({ "kind": "text", "required": false,
                        "annotations": { "db": { "pgType": "TEXT", "unique": false } } });
    let model = Model {
        name: "Note",
        table: "cd_note",
        timestamps: true,
    };
    one_field(&model, "label", label, default)
}

fn literal(text: &str) -> Option<Value> {
    Some(json!({ "kind": "value", "value": text }))
}

/// The DEFAULT of `column` on `table`, as Postgres deparses it.
async fn column_default(pool: &sqlx::PgPool, table: &str, column: &str) -> Option<String> {
    sqlx::query_scalar(
        "SELECT column_default::text FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await
    .expect("the column exists")
}

async fn label_default(pool: &sqlx::PgPool) -> Option<String> {
    column_default(pool, "cd_note", "label").await
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

fn settings(default: Option<Value>) -> SchemaAst {
    let settings = json!({ "kind": "json", "required": false,
                           "annotations": { "db": { "pgType": "JSONB", "unique": false } } });
    let model = Model {
        name: "Profile",
        table: "cd_profile",
        timestamps: false,
    };
    one_field(&model, "settings", settings, default)
}

async fn settings_default(pool: &sqlx::PgPool) -> Option<String> {
    column_default(pool, "cd_profile", "settings").await
}

/// A JSON column's default converges like a scalar's (issue 17). Postgres stores `jsonb` with its
/// keys reordered and spaced, so `{"bb":1,"a":2}` reads back as `{"a": 2, "bb": 1}`: the same
/// value, which must not be planned again on every push.
#[tokio::test(flavor = "multi_thread")]
async fn a_json_default_is_added_changed_and_dropped_on_an_existing_column() {
    common::with_integration_pool(|pool| async move {
        push_and_settle(&pool, &settings(None)).await;
        assert_eq!(settings_default(&pool).await, None);

        push_and_settle(&pool, &settings(literal("[]"))).await;
        assert_eq!(
            settings_default(&pool).await.as_deref(),
            Some("'[]'::jsonb")
        );

        push_and_settle(&pool, &settings(literal(r#"{"bb":1,"a":"it's"}"#))).await;
        assert_eq!(
            settings_default(&pool).await.as_deref(),
            Some(r#"'{"a": "it''s", "bb": 1}'::jsonb"#)
        );

        push_and_settle(&pool, &settings(None)).await;
        assert_eq!(settings_default(&pool).await, None);
    })
    .await;
}

/// `options: Default<JSON<string[]>, "[]">` as the CLI sends it: required, so `NOT NULL`, and
/// optional in the generated `Insert` type because of its default.
fn question(default: Option<Value>) -> SchemaAst {
    let options = json!({ "kind": "json", "required": true, "jsonArray": true,
                          "tsType": "string[]",
                          "annotations": { "db": { "pgType": "JSONB", "unique": false,
                                                    "index": false } } });
    let model = Model {
        name: "Question",
        table: "cd_question",
        timestamps: false,
    };
    one_field(&model, "options", options, default)
}

/// What an insert that leaves `options` out stores there, or how it fails.
async fn insert_without_options(pool: &sqlx::PgPool) -> Result<String, String> {
    sqlx::query_scalar("INSERT INTO public.cd_question DEFAULT VALUES RETURNING options::text")
        .fetch_one(pool)
        .await
        .map_err(|e| match e.as_database_error() {
            Some(db) => format!("{} {}", db.code().unwrap_or_default(), db.message()),
            None => e.to_string(),
        })
}

/// The insert the generated types allow, leaving the required JSON column out, succeeds on a
/// table the push creates (issue 17): it was `23502` while the default was dropped.
#[tokio::test(flavor = "multi_thread")]
async fn an_insert_leaving_out_a_required_json_column_takes_its_default() {
    common::with_integration_pool(|pool| async move {
        push_and_settle(&pool, &question(literal("[]"))).await;
        assert_eq!(insert_without_options(&pool).await, Ok("[]".to_string()));
    })
    .await;
}

/// The same insert on a table an earlier push created without the default: the next push sets
/// it with `ALTER COLUMN ... SET DEFAULT`, and the insert then succeeds.
#[tokio::test(flavor = "multi_thread")]
async fn a_json_default_added_to_an_existing_table_lets_the_insert_through() {
    common::with_integration_pool(|pool| async move {
        push_and_settle(&pool, &question(None)).await;
        let refused = insert_without_options(&pool).await;
        assert!(
            refused.as_ref().is_err_and(|e| e.starts_with("23502")),
            "{refused:?}"
        );

        let ast = question(literal("[]"));
        let planned = planned_column_ops(&pool, &ast).await;
        assert!(
            planned.len() == 1 && planned[0].contains("'[]'::jsonb"),
            "expected one ALTER COLUMN setting the default, planned: {planned:?}"
        );
        push_and_settle(&pool, &ast).await;
        assert_eq!(insert_without_options(&pool).await, Ok("[]".to_string()));
    })
    .await;
}

fn place(default: Option<Value>) -> SchemaAst {
    let location = json!({ "kind": "geo", "required": false, "geoType": "point",
                           "annotations": { "db": { "pgType": "GEOGRAPHY", "unique": false } } });
    let model = Model {
        name: "Place",
        table: "cd_place",
        timestamps: false,
    };
    one_field(&model, "location", location, default)
}

/// The point a new row of `cd_place` defaults to, as Postgres reads the stored default back.
async fn location_default(pool: &sqlx::PgPool) -> Option<String> {
    sqlx::query_scalar(
        "WITH added AS (INSERT INTO cd_place DEFAULT VALUES RETURNING location) \
         SELECT ST_AsEWKT(location) FROM added",
    )
    .fetch_one(pool)
    .await
    .expect("a row is added")
}

/// A geography default converges too. Postgres keeps a geography literal in its binary form, which
/// reads back as nothing like the declared text, so it must still settle after one push and move
/// when the declared point does.
#[tokio::test(flavor = "multi_thread")]
async fn a_geography_default_is_added_changed_and_dropped_on_an_existing_column() {
    common::with_integration_pool(|pool| async move {
        push_and_settle(&pool, &place(None)).await;
        assert_eq!(location_default(&pool).await, None);

        push_and_settle(&pool, &place(literal("SRID=4326;POINT(1 2)"))).await;
        assert_eq!(
            location_default(&pool).await.as_deref(),
            Some("SRID=4326;POINT(1 2)")
        );

        push_and_settle(&pool, &place(literal("SRID=4326;POINT(3 4)"))).await;
        assert_eq!(
            location_default(&pool).await.as_deref(),
            Some("SRID=4326;POINT(3 4)")
        );

        push_and_settle(&pool, &place(None)).await;
        assert_eq!(location_default(&pool).await, None);
    })
    .await;
}
