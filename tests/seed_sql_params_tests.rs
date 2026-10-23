//! A raw `$sql` statement's parameters, against a real Postgres.
//!
//! The CLI sends `params` beside the text and the planner carries them, so a statement
//! that names `$1` has to receive them. It did not: the executor ran the text alone, and
//! Postgres refused with `bind message supplies 0 parameters`. The many-to-many example in
//! the seeding docs is exactly that shape, so it is run here end to end.

mod common;

use supatype_engine::parser;
use supatype_engine::parser::ast::SchemaAst;
use supatype_engine::seed::errors::{constraint_index_for, SeedError};
use supatype_engine::seed::execute::{execute, Context, Report};
use supatype_engine::seed::fingerprint::fingerprint;
use supatype_engine::seed::plan::plan;
use supatype_engine::seed::validate::validate;
use supatype_engine::seed::SeedIr;

/// A post and a tag, joined many-to-many through the default `post_tag` junction.
const SCHEMA: &str = r#"{
    "astVersion": 2,
    "models": [
        {
            "name": "Post",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"},
                       "annotations": {"db": {"unique": true}}},
                "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}},
                "title": {"kind": "text", "required": false},
                "views": {"kind": "integer", "required": false},
                "featured": {"kind": "boolean", "required": false},
                "tags": {"kind": "relation", "cardinality": "manyToMany", "target": "Tag"}
            },
            "annotations": {"db": {"tableName": "post"}}
        },
        {
            "name": "Tag",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"},
                       "annotations": {"db": {"unique": true}}},
                "name": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}}
            },
            "annotations": {"db": {"tableName": "tag"}}
        }
    ]
}"#;

/// The statement from the "Many-to-many rows" section of the seeding docs, verbatim.
const DOCS_JUNCTION_SQL: &str = "insert into post_tag (post_id, tag_id)\n   \
     select p.id, t.id from post p, tag t\n   \
     where p.slug = $1 and t.name = $2\n   \
     on conflict do nothing";

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
            let $ast = parser::parse(SCHEMA).expect("the schema fixture parses");
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
    let mut document = ir(&operations);
    document.schema_fingerprint = fingerprint(ast);
    validate(&document, ast, &document.schema_fingerprint).map_err(|e| e.to_string())?;
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

fn sql(text: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"op": "sql", "text": text, "params": params})
}

async fn count(pool: &sqlx::PgPool, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(pool)
        .await
        .expect("counts")
}

/// The seed from the docs: two typed upserts, then the junction row through `$sql`.
fn docs_example() -> serde_json::Value {
    serde_json::json!([
        {"op": "upsert", "model": "Post", "where": {"slug": "hello-world"},
         "data": {"slug": "hello-world", "title": "Hello world"}},
        {"op": "upsert", "model": "Tag", "where": {"name": "news"}, "data": {"name": "news"}},
        sql(DOCS_JUNCTION_SQL, serde_json::json!(["hello-world", "news"])),
    ])
}

/// A post's slug, title, views and featured flag, as read back.
type PostRow = (String, Option<String>, Option<i32>, Option<bool>);

#[tokio::test]
async fn text_numeric_and_boolean_params_are_bound() {
    with_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            serde_json::json!([
                sql(
                    "INSERT INTO post (slug, title, views, featured) VALUES ($1, $2, $3, $4)",
                    serde_json::json!(["first", "First post", 42, true]),
                ),
                sql(
                    "INSERT INTO post (slug, title, views, featured) VALUES ($1, $2, $3, $4)",
                    serde_json::json!(["second", null, null, false]),
                ),
            ]),
        )
        .await
        .expect("the parameterised statements apply");

        let rows: Vec<PostRow> =
            sqlx::query_as("SELECT slug, title, views, featured FROM post ORDER BY slug")
                .fetch_all(&pool)
                .await
                .expect("reads the posts");
        assert_eq!(
            rows,
            vec![
                (
                    "first".into(),
                    Some("First post".into()),
                    Some(42),
                    Some(true)
                ),
                ("second".into(), None, None, Some(false)),
            ]
        );
    });
}

/// A float binds as a double and an object as `jsonb`, so the statement can read into it.
#[tokio::test]
async fn float_and_json_params_are_bound_with_their_types() {
    with_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            serde_json::json!([sql(
                "INSERT INTO post (slug, views) SELECT $1 ->> 'slug', round($2)::int",
                serde_json::json!([{"slug": "from-json"}, 2.6]),
            )]),
        )
        .await
        .expect("the statement reads the jsonb and float params");

        let views: Option<i32> =
            sqlx::query_scalar("SELECT views FROM post WHERE slug = 'from-json'")
                .fetch_one(&pool)
                .await
                .expect("the row exists");
        assert_eq!(views, Some(3));
    });
}

/// The docs' many-to-many example, end to end, and again to prove it is re-runnable.
///
/// The junction statement reads rows the two upserts before it write. The executor ran
/// every raw statement before any typed write, so even with its parameters bound the
/// select found nothing and the link was silently never made on a fresh database.
#[tokio::test]
async fn the_docs_many_to_many_example_links_the_rows() {
    with_schema!(|pool, ast| {
        for attempt in ["first run", "second run"] {
            run(&pool, &ast, docs_example())
                .await
                .unwrap_or_else(|e| panic!("the docs example applies on the {attempt}: {e}"));
            assert_eq!(
                count(&pool, "post_tag").await,
                1,
                "one link after the {attempt}"
            );
        }

        let linked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM post_tag j JOIN post p ON p.id = j.post_id \
             JOIN tag t ON t.id = j.tag_id WHERE p.slug = 'hello-world' AND t.name = 'news')",
        )
        .fetch_one(&pool)
        .await
        .expect("reads the link");
        assert!(linked, "the link joins the post and the tag the seed named");
    });
}

/// A `$ref` param carries the id an earlier write produced.
#[tokio::test]
async fn a_ref_param_binds_the_id_an_earlier_write_returned() {
    with_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            serde_json::json!([
                {"op": "create", "model": "Post", "id": "post", "data": {"slug": "p"}},
                {"op": "create", "model": "Tag", "id": "tag", "data": {"name": "t"}},
                sql(
                    "INSERT INTO post_tag (post_id, tag_id) VALUES ($1::uuid, $2::uuid)",
                    serde_json::json!([{"$ref": "post.id"}, {"$ref": "tag.id"}]),
                ),
            ]),
        )
        .await
        .expect("the referenced ids bind");

        assert_eq!(count(&pool, "post_tag").await, 1);
    });
}

#[tokio::test]
async fn a_statement_with_no_params_still_runs() {
    with_schema!(|pool, ast| {
        run(
            &pool,
            &ast,
            serde_json::json!([sql(
                "INSERT INTO tag (name) VALUES ('plain')",
                serde_json::json!([])
            )]),
        )
        .await
        .expect("a statement without params applies");

        assert_eq!(count(&pool, "tag").await, 1);
    });
}

/// Too few params is what the docs example hit; too many is silently accepted by Postgres,
/// so both are checked before the statement runs, and the error names the statement.
#[tokio::test]
async fn a_wrong_param_count_names_the_statement() {
    with_schema!(|pool, ast| {
        for (params, given) in [
            (serde_json::json!(["hello-world"]), "given 1"),
            (serde_json::json!(["a", "b", "c"]), "given 3"),
            (serde_json::json!([]), "given 0"),
        ] {
            let operations = serde_json::json!([sql(DOCS_JUNCTION_SQL, params)]);
            let message = run(&pool, &ast, operations)
                .await
                .expect_err("a mismatched count fails");
            assert!(message.starts_with("operations[0]: "), "{message}");
            assert!(message.contains("2 parameters"), "{message}");
            assert!(message.contains(given), "{message}");
            assert!(message.contains("insert into post_tag"), "{message}");
        }
        assert_eq!(count(&pool, "post_tag").await, 0, "nothing was written");
    });
}
