//! A seed casts every column to the type the migration created it with.
//!
//! The executor read a column's type from the field's `pgType`, falling back to `text`. That
//! is not the column's type for every field: a `blocks` field has no `pgType` and is a JSONB
//! column, and a localized field keeps its base `pgType` (`TEXT` for a localized title) while
//! the migration stores it as a JSONB locale map. Both were cast to the wrong type and failed
//! with 42804, the same error the 0.9.1 release test hit for arrays (FF5). The cast now comes
//! from `field_pg_type`, which the migration itself renders columns from.

mod common;

use supatype_engine::parser;
use supatype_engine::seed::errors::constraint_index_for;
use supatype_engine::seed::execute::{execute, Context};
use supatype_engine::seed::plan::plan;
use supatype_engine::seed::SeedIr;

const SCHEMA: &str = r#"{
    "astVersion": 2,
    "models": [
        {
            "name": "Site",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"}},
                "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}},
                "pages": {"kind": "relation", "cardinality": "hasMany", "target": "Page"}
            },
            "annotations": {"db": {"tableName": "ct_site"}}
        },
        {
            "name": "Page",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"}},
                "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}},
                "title": {"kind": "text", "required": false, "localized": true},
                "content": {"kind": "blocks", "required": false, "blocks": [
                    {"name": "hero", "label": null, "icon": null,
                     "fields": {"heading": {"kind": "text", "pgType": "TEXT", "required": true,
                                             "unique": false, "localized": false}}}
                ]},
                "cta": {"kind": "button", "required": false},
                "site": {"kind": "relation", "cardinality": "belongsTo", "target": "Site",
                         "required": false, "annotations": {"db": {"foreignKey": "site_id"}}}
            },
            "annotations": {"db": {"tableName": "ct_page"}}
        }
    ]
}"#;

const TITLE: &str = r#"{"en": "Hello", "de": "Hallo"}"#;
const CONTENT: &str = r#"[{"type": "hero", "data": {"heading": "Welcome"}}]"#;
const CTA: &str = r#"{"label": "Go", "href": "/go"}"#;

async fn seed(pool: &sqlx::PgPool, ast: &parser::ast::SchemaAst, operations: &str) {
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
    if let Err(e) = execute(pool, &planned, cx).await {
        panic!("the seed runs: {e:#}");
    }
}

/// Whether the page `slug`'s JSONB column `name` holds `expected`, compared as JSON values.
async fn holds(pool: &sqlx::PgPool, slug: &str, name: &str, expected: &str) -> bool {
    sqlx::query_scalar(&format!(
        "SELECT \"{name}\" = $2::jsonb FROM ct_page WHERE slug = $1"
    ))
    .bind(slug)
    .bind(expected)
    .fetch_one(pool)
    .await
    .expect("the page exists")
}

async fn pages(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM ct_page")
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
async fn a_create_writes_a_blocks_column() {
    with_schema(|pool, ast| async move {
        let ops = format!(
            r#"[{{"op":"create","model":"Page","data":{{"slug":"a","content":{CONTENT}}}}}]"#
        );
        seed(&pool, &ast, &ops).await;
        assert!(holds(&pool, "a", "content", CONTENT).await);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_create_writes_a_localized_column() {
    with_schema(|pool, ast| async move {
        let ops =
            format!(r#"[{{"op":"create","model":"Page","data":{{"slug":"b","title":{TITLE}}}}}]"#);
        seed(&pool, &ast, &ops).await;
        assert!(holds(&pool, "b", "title", TITLE).await);
    })
    .await;
}

/// A `button` is a JSONB column like `json`, and kept working through the change of source.
#[tokio::test(flavor = "multi_thread")]
async fn a_create_writes_a_button_column() {
    with_schema(|pool, ast| async move {
        let ops =
            format!(r#"[{{"op":"create","model":"Page","data":{{"slug":"c","cta":{CTA}}}}}]"#);
        seed(&pool, &ast, &ops).await;
        assert!(holds(&pool, "c", "cta", CTA).await);
    })
    .await;
}

/// A child nested under an upsert is matched column by column before it is written, so each of
/// these columns has to compare as its own type for a re-run to find the row it wrote.
#[tokio::test(flavor = "multi_thread")]
async fn a_nested_child_with_json_columns_is_matched_on_a_rerun() {
    with_schema(|pool, ast| async move {
        let ops = format!(
            r#"[{{"op":"upsert","model":"Site","where":{{"slug":"main"}},"data":{{
                "pages":{{"create":[{{"slug":"d","title":{TITLE},"content":{CONTENT},
                "cta":{CTA}}}]}}}}}}]"#
        );
        seed(&pool, &ast, &ops).await;
        seed(&pool, &ast, &ops).await;
        assert_eq!(
            pages(&pool).await,
            1,
            "the re-run matched the child it wrote"
        );
        assert!(holds(&pool, "d", "title", TITLE).await);
        assert!(holds(&pool, "d", "content", CONTENT).await);
    })
    .await;
}
