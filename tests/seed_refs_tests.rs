//! A `$ref` to any column of a row the seed wrote earlier, against a real Postgres.
//!
//! The builder hands back a reference for every column of a row, but the executor only ever
//! read the row's `id` back. A write referencing `alex.slug` passed validation and then wrote
//! NULL, because nothing had produced a slug to put there. Each test here references a column
//! other than `id`, in each place a reference can appear.

mod common;

use supatype_engine::parser;
use supatype_engine::parser::ast::SchemaAst;
use supatype_engine::seed::errors::{constraint_index_for, SeedError};
use supatype_engine::seed::execute::{execute, Context, Report};
use supatype_engine::seed::fingerprint::fingerprint;
use supatype_engine::seed::plan::plan;
use supatype_engine::seed::validate::validate;
use supatype_engine::seed::SeedIr;

/// A column name past the 63 bytes Postgres keeps of one.
const LONG: &str = "the_number_of_years_this_author_has_been_writing_for_the_publication";

/// The name Postgres keeps of [`LONG`].
fn kept_long() -> &'static str {
    &LONG[..63]
}

/// An author, whose columns are referenced, and a post, whose columns receive them.
fn schema() -> String {
    format!(
        r#"{{
    "astVersion": 2,
    "models": [
        {{
            "name": "Author",
            "fields": {{
                "id": {{"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {{"kind": "genRandomUuid"}},
                       "annotations": {{"db": {{"unique": true}}}}}},
                "slug": {{"kind": "text", "required": true, "annotations": {{"db": {{"unique": true}}}}}},
                "name": {{"kind": "text", "required": false}},
                "joined_at": {{"kind": "datetime", "required": false, "default": {{"kind": "now"}}}},
                "{LONG}": {{"kind": "text", "required": false}},
                "posts": {{"kind": "relation", "cardinality": "hasMany", "target": "Post"}}
            }},
            "annotations": {{"db": {{"tableName": "author"}}}}
        }},
        {{
            "name": "Post",
            "fields": {{
                "id": {{"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {{"kind": "genRandomUuid"}},
                       "annotations": {{"db": {{"unique": true}}}}}},
                "title": {{"kind": "text", "required": true}},
                "byline": {{"kind": "text", "required": false}},
                "since": {{"kind": "datetime", "required": false}},
                "motto": {{"kind": "text", "required": false}},
                "author": {{"kind": "relation", "cardinality": "belongsTo", "target": "Author",
                           "required": false,
                           "annotations": {{"db": {{"foreignKey": "author_id"}}}}}}
            }},
            "annotations": {{"db": {{"tableName": "post"}}}}
        }}
    ]
}}"#
    )
}

fn ir(operations: &serde_json::Value) -> SeedIr {
    serde_json::from_value(serde_json::json!({
        "irVersion": 1,
        "schemaFingerprint": "sha256:x",
        "operations": operations,
    }))
    .expect("the IR fixture parses")
}

/// Push the schema, then run the body against it.
macro_rules! with_schema {
    (|$pool:ident, $ast:ident| $body:block) => {
        common::with_integration_pool(|$pool| async move {
            let $ast = parser::parse(&schema()).expect("the schema fixture parses");
            common::push(&$pool, &$ast)
                .await
                .expect("the schema pushes");
            $body
        })
        .await;
    };
}

/// Validate, plan and execute, in the order `supatype seed` does.
async fn run(
    pool: &sqlx::PgPool,
    ast: &SchemaAst,
    operations: serde_json::Value,
) -> Result<Report, String> {
    let document = checked(ast, operations)?;
    let planned = plan(&document, ast).expect("plans");
    let context = Context {
        ast,
        constraints: &constraint_index_for(ast),
        schema: "public",
        environment: None,
    };
    execute(pool, &planned, context)
        .await
        .map_err(|e: SeedError| e.to_string())
}

/// The document, stamped with the schema's fingerprint and validated.
fn checked(ast: &SchemaAst, operations: serde_json::Value) -> Result<SeedIr, String> {
    let mut document = ir(&operations);
    document.schema_fingerprint = fingerprint(ast);
    validate(&document, ast, &document.schema_fingerprint).map_err(|e| e.to_string())?;
    Ok(document)
}

fn reference(to: &str) -> serde_json::Value {
    serde_json::json!({ "$ref": to })
}

/// Alex, labelled `alex`, with a name and the long column set.
fn alex() -> serde_json::Value {
    serde_json::json!({"op": "create", "model": "Author", "id": "alex", "data": {
        "slug": "alex-rivera", "name": "Alex Rivera", kept_long(): "twelve"
    }})
}

fn post(data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"op": "create", "model": "Post", "data": data})
}

/// One text column of the only post, read back.
async fn post_text(pool: &sqlx::PgPool, column: &str) -> Option<String> {
    sqlx::query_scalar(&format!("SELECT {column}::text FROM post"))
        .fetch_one(pool)
        .await
        .expect("reads the post")
}

#[tokio::test]
async fn a_typed_write_stores_the_referenced_slug() {
    with_schema!(|pool, ast| {
        let operations = serde_json::json!([
            alex(),
            post(serde_json::json!({"title": "Hello", "byline": reference("alex.slug")})),
        ]);
        run(&pool, &ast, operations)
            .await
            .expect("the seed applies");
        assert_eq!(
            post_text(&pool, "byline").await.as_deref(),
            Some("alex-rivera")
        );
    });
}

#[tokio::test]
async fn a_sql_param_binds_the_referenced_slug() {
    with_schema!(|pool, ast| {
        let operations = serde_json::json!([
            alex(),
            {"op": "sql", "text": "INSERT INTO post (title, byline) VALUES ($1, $2)",
             "params": ["Hello", reference("alex.slug")]},
        ]);
        run(&pool, &ast, operations)
            .await
            .expect("the seed applies");
        assert_eq!(
            post_text(&pool, "byline").await.as_deref(),
            Some("alex-rivera")
        );
    });
}

/// `joined_at` is never written by the seed: the database fills it with its default, and the
/// reference still finds the value that was stored.
#[tokio::test]
async fn a_ref_to_a_defaulted_column_resolves_to_the_stored_value() {
    with_schema!(|pool, ast| {
        let operations = serde_json::json!([
            alex(),
            post(serde_json::json!({"title": "Hello", "since": reference("alex.joined_at")})),
        ]);
        run(&pool, &ast, operations)
            .await
            .expect("the seed applies");
        let same: bool = sqlx::query_scalar(
            "SELECT p.since IS NOT NULL AND p.since = a.joined_at FROM post p, author a",
        )
        .fetch_one(&pool)
        .await
        .expect("compares the times");
        assert!(same, "the post holds the author's stored joined_at");
    });
}

/// Referenced by its full name, past what Postgres keeps, and by the name Postgres keeps.
#[tokio::test]
async fn a_ref_to_a_long_column_name_resolves() {
    for name in [LONG, kept_long()] {
        with_schema!(|pool, ast| {
            let to = format!("alex.{name}");
            let operations = serde_json::json!([
                alex(),
                post(serde_json::json!({"title": "Hello", "motto": reference(&to)})),
            ]);
            run(&pool, &ast, operations)
                .await
                .expect("the seed applies");
            assert_eq!(post_text(&pool, "motto").await.as_deref(), Some("twelve"));
        });
    }
}

/// A reference inside a nested write, and one inside a `connect` by natural key.
#[tokio::test]
async fn refs_resolve_in_nested_writes_and_connects() {
    with_schema!(|pool, ast| {
        let operations = serde_json::json!([
            alex(),
            {"op": "create", "model": "Author", "data": {"slug": "bea", "posts": {"create": [
                {"title": "Nested", "byline": reference("alex.name")}
            ]}}},
            post(serde_json::json!({"title": "Linked",
                "author": {"connect": {"slug": reference("alex.slug")}}})),
        ]);
        run(&pool, &ast, operations)
            .await
            .expect("the seed applies");
        let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT p.title, p.byline, a.slug FROM post p \
             LEFT JOIN author a ON a.id = p.author_id ORDER BY p.title",
        )
        .fetch_all(&pool)
        .await
        .expect("reads the posts");
        assert_eq!(
            rows,
            vec![
                ("Linked".into(), None, Some("alex-rivera".into())),
                (
                    "Nested".into(),
                    Some("Alex Rivera".into()),
                    Some("bea".into())
                ),
            ]
        );
    });
}

/// An upsert naming only its key does nothing on a conflict, so on a re-run the row comes
/// back from no `RETURNING`. Its columns are still found, and the second post is linked too.
#[tokio::test]
async fn a_ref_to_a_key_only_upsert_resolves_on_a_rerun() {
    with_schema!(|pool, ast| {
        let operations = serde_json::json!([
            {"op": "upsert", "model": "Author", "id": "alex",
             "where": {"slug": "alex-rivera"}, "data": {}},
            post(serde_json::json!({"title": "Hello", "byline": reference("alex.slug"),
                "author_id": reference("alex.id")})),
        ]);
        for attempt in ["first run", "second run"] {
            run(&pool, &ast, operations.clone())
                .await
                .unwrap_or_else(|e| panic!("the seed applies on the {attempt}: {e}"));
        }
        let unlinked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM post WHERE byline IS NULL OR author_id IS NULL",
        )
        .fetch_one(&pool)
        .await
        .expect("counts");
        assert_eq!(unlinked, 0, "both runs resolved the slug and the id");
    });
}

/// A model's relation is not a column, and neither is a name the model does not have.
#[test]
fn a_ref_to_a_field_the_model_does_not_have_is_refused() {
    let ast = parser::parse(&schema()).expect("the schema fixture parses");
    for field in ["nickname", "posts"] {
        let operations = serde_json::json!([
            alex(),
            post(
                serde_json::json!({"title": "Hello", "byline": reference(&format!("alex.{field}"))})
            ),
        ]);
        let message = checked(&ast, operations).expect_err("the reference is refused");
        assert!(message.contains("`Author`"), "{message}");
        assert!(message.contains(&format!("`{field}`")), "{message}");
    }
}
