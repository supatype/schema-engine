//! A seed may write array columns (0.9.1 release test, FF5).
//!
//! The seed builder types a `string[]` column as `string[]`, and the IR carries the value as a
//! JSON array. The executor cast every array column to `text`, because an array field has no
//! `pgType` of its own, and bound the value as its JSON text. So `tags: ["a", "b"]`, and even
//! `tags: []`, failed with `column "tags" is of type text[] but expression is of type text`
//! and rolled the seed back. The column is now cast to its own array type and the value bound as
//! a Postgres array literal, through a create, a `createMany`, both halves of an upsert and a
//! nested create that is matched before it is written.

mod common;

use supatype_engine::parser;
use supatype_engine::seed::errors::constraint_index_for;
use supatype_engine::seed::execute::{execute, Context, Report};
use supatype_engine::seed::plan::plan;
use supatype_engine::seed::SeedIr;

const SCHEMA: &str = r#"{
    "astVersion": 2,
    "models": [
        {
            "name": "Board",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"}},
                "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}},
                "notes": {"kind": "relation", "cardinality": "hasMany", "target": "Note"}
            },
            "annotations": {"db": {"tableName": "arr_board"}}
        },
        {
            "name": "Note",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"}},
                "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}},
                "tags": {"kind": "array", "required": false,
                         "annotations": {"db": {"elementType": "TEXT"}}},
                "scores": {"kind": "array", "required": false,
                           "annotations": {"db": {"elementType": "INTEGER"}}},
                "links": {"kind": "array", "required": false,
                          "annotations": {"db": {"elementType": "UUID"}}},
                "extras": {"kind": "array", "required": false,
                           "annotations": {"db": {"elementType": "JSONB"}}},
                "meta": {"kind": "json", "required": false},
                "board": {"kind": "relation", "cardinality": "belongsTo", "target": "Board",
                          "required": false, "annotations": {"db": {"foreignKey": "board_id"}}}
            },
            "annotations": {"db": {"tableName": "arr_note"}}
        }
    ]
}"#;

const LINK: &str = "00000000-0000-0000-0000-00000000000a";

async fn seed(pool: &sqlx::PgPool, ast: &parser::ast::SchemaAst, operations: &str) -> Report {
    let document =
        format!(r#"{{"irVersion":1,"schemaFingerprint":"sha256:x","operations":{operations}}}"#);
    let ir: SeedIr = serde_json::from_str(&document).expect("the IR fixture parses");
    let planned = plan(&ir, ast).expect("plans");
    let cx = Context {
        ast,
        constraints: &constraint_index_for(ast),
        schema: "public",
        environment: None,
    };
    execute(pool, &planned, cx)
        .await
        .expect("the array seed runs")
}

/// One column of the note `slug`, read back as text so every array type compares the same way.
async fn column(pool: &sqlx::PgPool, slug: &str, name: &str) -> Option<String> {
    sqlx::query_scalar(&format!(
        "SELECT \"{name}\"::text FROM arr_note WHERE slug = $1"
    ))
    .bind(slug)
    .fetch_one(pool)
    .await
    .expect("the note exists")
}

async fn notes(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM arr_note")
        .fetch_one(pool)
        .await
        .expect("counts")
}

async fn with_schema<F, Fut>(f: F)
where
    F: FnOnce(sqlx::PgPool, parser::ast::SchemaAst) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(SCHEMA).expect("the schema fixture parses");
        common::push(&pool, &ast).await.expect("the schema pushes");
        f(pool, ast).await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_create_writes_every_array_element_type() {
    with_schema(|pool, ast| async move {
        let ops = format!(
            r#"[{{"op":"create","model":"Note","data":{{"slug":"a",
                "tags":["a","has \"quotes\"","back\\slash",null,"{{braces}}","comma, here"],
                "scores":[1,-2,3],"links":["{LINK}"],"extras":[{{"k":1}},"text"]}}}}]"#
        );
        seed(&pool, &ast, &ops).await;
        assert_eq!(
            column(&pool, "a", "tags").await.as_deref(),
            Some(r#"{a,"has \"quotes\"","back\\slash",NULL,"{braces}","comma, here"}"#)
        );
        assert_eq!(
            column(&pool, "a", "scores").await.as_deref(),
            Some("{1,-2,3}")
        );
        assert_eq!(
            column(&pool, "a", "links").await,
            Some(format!("{{{LINK}}}"))
        );
        assert_eq!(
            column(&pool, "a", "extras").await.as_deref(),
            Some(r#"{"{\"k\": 1}","\"text\""}"#)
        );
    })
    .await;
}

/// The release test's own shapes: a `createMany` of one row, and an empty list.
#[tokio::test(flavor = "multi_thread")]
async fn create_many_writes_lists_empty_lists_and_nulls() {
    with_schema(|pool, ast| async move {
        let ops = r#"[{"op":"createMany","model":"Note","rows":[
            {"slug":"b","tags":["x","y"]},
            {"slug":"c","tags":[]},
            {"slug":"d","tags":null}
        ]}]"#;
        seed(&pool, &ast, ops).await;
        assert_eq!(column(&pool, "b", "tags").await.as_deref(), Some("{x,y}"));
        assert_eq!(column(&pool, "c", "tags").await.as_deref(), Some("{}"));
        assert_eq!(column(&pool, "d", "tags").await, None);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upsert_writes_a_list_on_insert_and_on_update() {
    with_schema(|pool, ast| async move {
        let first = r#"[{"op":"upsert","model":"Note","where":{"slug":"e"},
            "data":{"tags":["one"],"scores":[1]}}]"#;
        seed(&pool, &ast, first).await;
        assert_eq!(column(&pool, "e", "tags").await.as_deref(), Some("{one}"));
        let second = r#"[{"op":"upsert","model":"Note","where":{"slug":"e"},
            "data":{"tags":["two","three"],"scores":[]}}]"#;
        seed(&pool, &ast, second).await;
        assert_eq!(
            column(&pool, "e", "tags").await.as_deref(),
            Some("{two,three}")
        );
        assert_eq!(column(&pool, "e", "scores").await.as_deref(), Some("{}"));
    })
    .await;
}

/// A child nested under an upsert is matched against the rows already there, column by column,
/// so its list has to compare as a list: a re-run must not add it again.
#[tokio::test(flavor = "multi_thread")]
async fn a_nested_child_with_a_list_is_matched_on_a_rerun() {
    with_schema(|pool, ast| async move {
        let ops = r#"[{"op":"upsert","model":"Board","where":{"slug":"main"},"data":{
            "notes":{"create":[{"slug":"f","tags":["n1","n2"],"scores":[7]}]}}}]"#;
        seed(&pool, &ast, ops).await;
        seed(&pool, &ast, ops).await;
        assert_eq!(
            notes(&pool).await,
            1,
            "the re-run matched the child it wrote"
        );
        assert_eq!(column(&pool, "f", "tags").await.as_deref(), Some("{n1,n2}"));
    })
    .await;
}

/// A `json` column holding a list is not an array column: its value stays JSON.
#[tokio::test(flavor = "multi_thread")]
async fn a_json_column_holding_a_list_is_left_as_json() {
    with_schema(|pool, ast| async move {
        let ops = r#"[{"op":"create","model":"Note","data":{"slug":"g","meta":["a",1]}}]"#;
        seed(&pool, &ast, ops).await;
        assert_eq!(
            column(&pool, "g", "meta").await.as_deref(),
            Some(r#"["a", 1]"#)
        );
    })
    .await;
}
