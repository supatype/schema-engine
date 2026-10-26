//! A seed may write rich text as prose (B4).
//!
//! The seed builder types a rich text column as `SeedRichText | string`, and says a trigger
//! normalises the string into a document. The executor bound the string as it was and cast it to
//! `jsonb`, so `body: "The first published post."` failed with `invalid input syntax for type json`
//! and rolled the seed back. Prose now reaches the column as a JSON string, which the trigger
//! wraps, through a create, both halves of an upsert and a nested create.

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
            "name": "Author",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"}},
                "name": {"kind": "text", "required": true},
                "posts": {"kind": "relation", "cardinality": "hasMany", "target": "Post"}
            },
            "annotations": {"db": {"tableName": "rt_author"}}
        },
        {
            "name": "Post",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"}},
                "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}},
                "body": {"kind": "richText", "required": true},
                "author": {"kind": "relation", "cardinality": "belongsTo", "target": "Author",
                           "required": false, "annotations": {"db": {"foreignKey": "author_id"}}}
            },
            "annotations": {"db": {"tableName": "rt_post"}}
        }
    ]
}"#;

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
        .expect("the prose seed runs")
}

/// The text of the one paragraph the trigger wrapped the body of `slug` in.
async fn body_text(pool: &sqlx::PgPool, slug: &str) -> String {
    sqlx::query_scalar(
        "SELECT body #>> '{root,children,0,children,0,text}' FROM rt_post WHERE slug = $1",
    )
    .bind(slug)
    .fetch_one(pool)
    .await
    .expect("the post exists and its body is a document")
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
async fn a_create_writes_prose_into_a_rich_text_column() {
    with_schema(|pool, ast| async move {
        let ops =
            r#"[{"op":"create","model":"Post","data":{"slug":"a","body":"The first post."}}]"#;
        seed(&pool, &ast, ops).await;
        assert_eq!(body_text(&pool, "a").await, "The first post.");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_upsert_writes_prose_on_insert_and_on_update() {
    with_schema(|pool, ast| async move {
        let first =
            r#"[{"op":"upsert","model":"Post","where":{"slug":"b"},"data":{"body":"One"}}]"#;
        seed(&pool, &ast, first).await;
        assert_eq!(body_text(&pool, "b").await, "One");
        let second =
            r#"[{"op":"upsert","model":"Post","where":{"slug":"b"},"data":{"body":"Two"}}]"#;
        seed(&pool, &ast, second).await;
        assert_eq!(body_text(&pool, "b").await, "Two");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_nested_create_writes_prose_into_a_rich_text_column() {
    with_schema(|pool, ast| async move {
        let ops = r#"[{"op":"create","model":"Author","data":{"name":"Ann",
            "posts":{"create":[{"slug":"c","body":"Nested prose."}]}}}]"#;
        seed(&pool, &ast, ops).await;
        assert_eq!(body_text(&pool, "c").await, "Nested prose.");
    })
    .await;
}

/// A document is still written as it is: the prose path must not wrap one twice.
#[tokio::test(flavor = "multi_thread")]
async fn a_document_is_still_written_as_it_is() {
    with_schema(|pool, ast| async move {
        let ops = r#"[{"op":"create","model":"Post","data":{"slug":"d","body":
            {"root":{"type":"root","children":[{"type":"paragraph","children":
                [{"type":"text","text":"Already a document."}]}]}}}}]"#;
        seed(&pool, &ast, ops).await;
        assert_eq!(body_text(&pool, "d").await, "Already a document.");
    })
    .await;
}
