//! A rich text column holds a Lexical document, whoever wrote to it.
//!
//! The column is JSONB with no check constraint, so `'"hello"'::jsonb` is accepted, while the
//! generated types say a rich text column is a document. That made the type a claim the database
//! did not keep, and the most reachable way to break it was a seed: the generated builder typed
//! the column loosely enough to accept a string, and the next read returned something the types
//! say is impossible.
//!
//! These run against a real database because that is the only place the claim can be tested. A
//! unit test of the emitted SQL would prove the text of a trigger, not that Postgres applies it.

mod common;

use supatype_engine::generator::sql::{migration, triggers};
use supatype_engine::parser;
use supatype_engine::state::database_state::DatabaseState;

const SCHEMA: &str = r#"{
    "astVersion": 2,
    "models": [
        {
            "name": "Article",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"}},
                "title": {"kind": "text", "required": true},
                "body": {"kind": "richText", "required": false},
                "notes": {"kind": "richText", "required": false},
                "summary": {"kind": "richText", "required": false, "localized": true}
            },
            "annotations": {"db": {"tableName": "article"}}
        },
        {
            "name": "Plain",
            "fields": {
                "id": {"kind": "uuid", "required": true, "primaryKey": true,
                       "default": {"kind": "genRandomUuid"}},
                "title": {"kind": "text", "required": true}
            },
            "annotations": {"db": {"tableName": "plain"}}
        }
    ]
}"#;

/// Apply the schema, triggers included, exactly as a push would.
macro_rules! with_schema {
    (|$pool:ident| $body:block) => {
        common::with_integration_pool(|$pool| async move {
            let ast = parser::parse(SCHEMA).expect("the schema fixture parses");
            let diff =
                supatype_engine::differ::diff(&ast, &DatabaseState::default()).expect("diffs");
            let sql = migration::forward_sql(&diff, false, "public", &ast).expect("renders");
            sqlx::raw_sql(&sql)
                .execute(&$pool)
                .await
                .expect("the schema applies");
            // `forward_sql` renders the DDL; the trigger SQL is applied beside it, which is
            // what `push` does. Applying only the first would test a table with no trigger on
            // it and pass for the wrong reason.
            let trigger_sql = triggers::generate(&ast, "public").expect("renders triggers");
            sqlx::raw_sql(&trigger_sql)
                .execute(&$pool)
                .await
                .expect("the triggers apply");
            $body
        })
        .await;
    };
}

async fn body_of(pool: &sqlx::PgPool, title: &str) -> serde_json::Value {
    sqlx::query_scalar::<_, serde_json::Value>("SELECT body FROM article WHERE title = $1")
        .bind(title)
        .fetch_one(pool)
        .await
        .expect("reads the row back")
}

/// The text a Lexical document carries, so a test can say what survived rather than compare
/// the whole shape.
async fn summary_of(pool: &sqlx::PgPool, title: &str) -> serde_json::Value {
    sqlx::query_scalar::<_, Option<serde_json::Value>>(
        "SELECT summary FROM article WHERE title = $1",
    )
    .bind(title)
    .fetch_one(pool)
    .await
    .expect("the row is there")
    .unwrap_or(serde_json::Value::Null)
}

fn text_in(document: &serde_json::Value) -> String {
    document["root"]["children"][0]["children"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// The case this exists for: something writes a bare string, and a read still returns a
/// document.
#[tokio::test]
async fn a_string_written_straight_into_the_column_comes_back_as_a_document() {
    with_schema!(|pool| {
        sqlx::query("INSERT INTO article (title, body) VALUES ($1, to_jsonb($2::text))")
            .bind("direct")
            .bind("Hello world")
            .execute(&pool)
            .await
            .expect("Postgres accepts a bare string, which is the whole problem");

        let document = body_of(&pool, "direct").await;
        assert_eq!(document["root"]["type"], "root", "{document}");
        assert_eq!(text_in(&document), "Hello world");
    });
}

/// A document is left exactly as it was. A trigger that rewrapped one would corrupt every
/// write from a real editor.
#[tokio::test]
async fn a_document_is_stored_untouched() {
    with_schema!(|pool| {
        let original = serde_json::json!({
            "root": {
                "type": "root", "version": 1, "direction": "ltr", "format": "", "indent": 0,
                "children": [{
                    "type": "paragraph", "version": 1, "direction": "ltr", "format": "", "indent": 0,
                    "children": [{
                        "type": "text", "version": 1, "detail": 0, "format": 0,
                        "mode": "normal", "style": "", "text": "Already a document"
                    }]
                }]
            }
        });

        sqlx::query("INSERT INTO article (title, body) VALUES ($1, $2)")
            .bind("document")
            .bind(&original)
            .execute(&pool)
            .await
            .expect("inserts");

        assert_eq!(body_of(&pool, "document").await, original);
    });
}

/// An update is a write too, and the first version of this trigger could easily have covered
/// only inserts.
#[tokio::test]
async fn a_string_written_by_an_update_is_normalised_too() {
    with_schema!(|pool| {
        sqlx::query("INSERT INTO article (title) VALUES ($1)")
            .bind("later")
            .execute(&pool)
            .await
            .expect("inserts");

        sqlx::query("UPDATE article SET body = to_jsonb($1::text) WHERE title = $2")
            .bind("Edited afterwards")
            .bind("later")
            .execute(&pool)
            .await
            .expect("updates");

        assert_eq!(text_in(&body_of(&pool, "later").await), "Edited afterwards");
    });
}

/// Null is absence, not empty prose. Wrapping it would turn every unset column into a document
/// containing nothing, which reads as content.
#[tokio::test]
async fn null_stays_null() {
    with_schema!(|pool| {
        sqlx::query("INSERT INTO article (title) VALUES ($1)")
            .bind("empty")
            .execute(&pool)
            .await
            .expect("inserts");

        let body: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT body FROM article WHERE title = 'empty'")
                .fetch_one(&pool)
                .await
                .expect("reads");
        assert!(body.is_none(), "got {body:?}");
    });
}

/// Every rich text column on the table, not just the first one found.
#[tokio::test]
async fn every_rich_text_column_on_the_table_is_covered() {
    with_schema!(|pool| {
        sqlx::query(
            "INSERT INTO article (title, body, notes) \
             VALUES ($1, to_jsonb($2::text), to_jsonb($3::text))",
        )
        .bind("both")
        .bind("The body")
        .bind("The notes")
        .execute(&pool)
        .await
        .expect("inserts");

        let notes: serde_json::Value =
            sqlx::query_scalar("SELECT notes FROM article WHERE title = 'both'")
                .fetch_one(&pool)
                .await
                .expect("reads");
        assert_eq!(text_in(&body_of(&pool, "both").await), "The body");
        assert_eq!(text_in(&notes), "The notes");
    });
}

/// Trigger SQL is re-applied on every push rather than diffed, so it has to be safe to apply
/// twice. `CREATE OR REPLACE` makes it so, and this is what says so.
#[tokio::test]
async fn applying_the_triggers_twice_is_safe() {
    with_schema!(|pool| {
        let ast = parser::parse(SCHEMA).expect("parses");
        let sql = triggers::generate(&ast, "public").expect("renders");
        sqlx::raw_sql(&sql)
            .execute(&pool)
            .await
            .expect("a second application is accepted");

        sqlx::query("INSERT INTO article (title, body) VALUES ($1, to_jsonb($2::text))")
            .bind("after")
            .bind("Still wrapped")
            .execute(&pool)
            .await
            .expect("inserts");
        assert_eq!(text_in(&body_of(&pool, "after").await), "Still wrapped");

        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_trigger WHERE tgname = 'article_rich_text_trigger'",
        )
        .fetch_one(&pool)
        .await
        .expect("counts");
        assert_eq!(count, 1, "replaced rather than duplicated");
    });
}

/// A model with no rich text column gets no trigger, so a schema that never uses the feature
/// pays nothing for it.
#[tokio::test]
async fn a_table_without_rich_text_gets_no_trigger() {
    with_schema!(|pool| {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_trigger WHERE tgname = 'plain_rich_text_trigger'",
        )
        .fetch_one(&pool)
        .await
        .expect("counts");
        assert_eq!(count, 0);
    });
}

/// And the emitted SQL says so before any database is involved.
#[test]
fn the_trigger_is_emitted_only_for_models_that_need_it() {
    let ast = parser::parse(SCHEMA).expect("parses");
    let sql = triggers::generate(&ast, "public").expect("renders");
    assert!(sql.contains("article_rich_text_trigger"), "{sql}");
    assert!(!sql.contains("plain_rich_text_trigger"), "{sql}");
    assert!(
        sql.contains("_platform.normalise_article_rich_text"),
        "one function per table: {sql}"
    );
}

/// The conversion the parenthesising fix was really about.
///
/// `jsonb_to_lexical_migrate_expr` is what the `json -> richText` migration runs, and it
/// produced `col #>> '{}'::text`, which Postgres reads as `jsonb #>> text` and refuses. The
/// trigger surfaced it; nothing had tested that migration, so it had been broken since it was
/// written. Covered here so it stays fixed for both callers.
/// A localized column holds one value per locale, and each of those is the document.
///
/// `{"en": "...", "fr": "..."}` has no top-level `root`, is not a string and is not an array, so
/// a wrap that only knows those shapes falls through to its catch-all and stringifies the whole
/// locale map into one text node. That loses every locale at once, and the column still type
/// checks, because the result is a valid document.
#[tokio::test]
async fn each_locale_of_a_localised_column_becomes_its_own_document() {
    with_schema!(|pool| {
        sqlx::query(
            r#"INSERT INTO article (title, summary)
               VALUES ('localised', '{"en": "Hello there", "fr": "Bonjour"}'::jsonb)"#,
        )
        .execute(&pool)
        .await
        .expect("the insert succeeds");

        let stored = summary_of(&pool, "localised").await;
        let map = stored.as_object().expect("a locale map, not a document");

        assert_eq!(
            map.keys().collect::<Vec<_>>(),
            vec!["en", "fr"],
            "both locales survive: {stored}"
        );
        assert_eq!(text_in(&map["en"]), "Hello there", "en: {stored}");
        assert_eq!(text_in(&map["fr"]), "Bonjour", "fr: {stored}");
        assert!(
            map["en"].get("root").is_some(),
            "each locale holds a document: {stored}"
        );
    });
}

/// The half that would hide the bug: a locale map already holding documents must not be re-wrapped.
#[tokio::test]
async fn a_localised_column_already_holding_documents_is_untouched() {
    with_schema!(|pool| {
        let document = r#"{"en": {"root": {"type": "root", "format": "", "indent": 0,
            "version": 1, "direction": "ltr", "children": [{"type": "paragraph", "format": "",
            "indent": 0, "version": 1, "direction": "ltr", "children": [{"mode": "normal",
            "text": "Already a document", "type": "text", "style": "", "detail": 0,
            "format": 0, "version": 1}]}]}}}"#;
        sqlx::query("INSERT INTO article (title, summary) VALUES ('kept', $1::jsonb)")
            .bind(document)
            .execute(&pool)
            .await
            .expect("the insert succeeds");

        let stored = summary_of(&pool, "kept").await;
        assert_eq!(
            text_in(&stored["en"]),
            "Already a document",
            "not re-wrapped: {stored}"
        );
    });
}

#[tokio::test]
async fn a_null_localised_column_stays_null() {
    with_schema!(|pool| {
        sqlx::query("INSERT INTO article (title, summary) VALUES ('empty', NULL)")
            .execute(&pool)
            .await
            .expect("the insert succeeds");
        assert!(summary_of(&pool, "empty").await.is_null());
    });
}

#[tokio::test]
async fn a_json_column_holding_a_string_converts_to_a_document() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(
            "CREATE TABLE note (id INTEGER PRIMARY KEY, body JSONB);              INSERT INTO note (id, body) VALUES (1, to_jsonb('Plain prose'::text)),                                                 (2, '[\"one\", \"two\"]'::jsonb),                                                 (3, NULL);",
        )
        .execute(&pool)
        .await
        .expect("seeds a json column with the shapes the migration has to handle");

        let expr = supatype_engine::generator::sql::column_conversion::jsonb_to_lexical_migrate_expr(
            "\"body\"",
        );
        sqlx::raw_sql(&format!(
            "UPDATE note SET body = {expr} WHERE body IS NOT NULL AND NOT (body ? 'root');"
        ))
        .execute(&pool)
        .await
        .expect("the migration expression is SQL Postgres accepts");

        let one: serde_json::Value = sqlx::query_scalar("SELECT body FROM note WHERE id = 1")
            .fetch_one(&pool)
            .await
            .expect("reads");
        assert_eq!(text_in(&one), "Plain prose");

        let two: serde_json::Value = sqlx::query_scalar("SELECT body FROM note WHERE id = 2")
            .fetch_one(&pool)
            .await
            .expect("reads");
        assert_eq!(two["root"]["type"], "root", "an array becomes a document too");

        let three: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT body FROM note WHERE id = 3")
                .fetch_one(&pool)
                .await
                .expect("reads");
        assert!(three.is_none(), "null is left alone");
    })
    .await;
}
