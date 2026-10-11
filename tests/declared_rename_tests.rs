//! Renames are declared, never guessed (decision D1).
//!
//! The column and table differs paired a dropped name with an added one by name similarity
//! (Jaro-Winkler 0.7), marked the pair safe and renamed it unasked, with no type check: two
//! different columns with similar names (`first_name`, `last_name`) were merged, and an integer
//! column was renamed into a declared text one. A real rename below the threshold (`title`,
//! `headline`) was a drop and an add, and lost its data under `--force`.
//!
//! Now a rename is applied only where the schema declares it (`annotations.db.renamedFrom` on the
//! field or on the model), only from a source that exists and is Supatype's, and only when the
//! source's type is the declared one or widens to it. An undeclared drop plus add is exactly that,
//! refused as destructive without `--force`. A declaration whose source is gone (already applied)
//! is a no-op, so it can stay in the schema.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::differ::Operation;
use supatype_engine::parser::{self, ast::SchemaAst};
use supatype_engine::push;

use common::{exec, push, push_with};

fn scalar(kind: &str, pg_type: &str, required: bool) -> Value {
    json!({ "kind": kind, "required": required,
            "annotations": { "db": { "pgType": pg_type, "unique": false } } })
}

fn text() -> Value {
    scalar("text", "TEXT", false)
}

/// `field`, declared as renamed from `from`.
fn renamed(mut field: Value, from: &str) -> Value {
    field["annotations"]["db"]["renamedFrom"] = json!(from);
    field
}

/// One model on `table`, keyed by a uuid `id`, with `fields`, and `renamed_from` on the model when
/// given.
fn model(table: &str, fields: Value, renamed_from: Option<&str>) -> Value {
    let mut all = json!({
        "id": { "kind": "uuid", "primaryKey": true, "required": true,
                "default": { "kind": "genRandomUuid" },
                "annotations": { "db": { "pgType": "UUID", "unique": false } } }
    });
    for (name, field) in fields.as_object().unwrap() {
        all[name] = field.clone();
    }
    let mut db = json!({ "tableName": table, "indexes": [] });
    if let Some(from) = renamed_from {
        db["renamedFrom"] = json!(from);
    }
    json!({
        "name": table,
        "fields": all,
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": db, "platform": { "access": { "read": { "type": "public" } } } }
    })
}

fn schema(models: Vec<Value>) -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": models });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

fn forced() -> push::ApplyOptions {
    push::ApplyOptions {
        force: true,
        ..Default::default()
    }
}

async fn rows(pool: &PgPool, sql: &str) -> Vec<String> {
    sqlx::query_scalar(sql).fetch_all(pool).await.unwrap()
}

async fn column_type(pool: &PgPool, table: &str, column: &str) -> Option<(String, String)> {
    sqlx::query_as(
        "SELECT udt_name::text, is_nullable::text FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_optional(pool)
    .await
    .unwrap()
}

fn renames(plan: &push::Plan<'_>) -> Vec<String> {
    plan.diff
        .operations
        .iter()
        .filter_map(|op| match op {
            Operation::RenameColumn { from, to, .. } => Some(format!("column {from} -> {to}")),
            Operation::RenameTable { from, to, .. } => Some(format!("table {from} -> {to}")),
            _ => None,
        })
        .collect()
}

/// E01: `first_name` and `last_name` are different columns, as are integer `count` and text
/// `county`. Similar names are never merged: the push is a drop and an add, refused without
/// `--force`, and the data stays where it was.
#[tokio::test]
async fn similar_names_are_never_merged() {
    common::with_integration_pool(|pool| async move {
        let v1 = json!({ "first_name": text(), "count": scalar("integer", "INTEGER", false) });
        push(&pool, &schema(vec![model("people", v1, None)]))
            .await
            .unwrap();
        exec(
            &pool,
            "INSERT INTO public.people (first_name, count) VALUES ('Alice', 42), ('Bob', 7)",
        )
        .await
        .unwrap();

        let v2 = schema(vec![model(
            "people",
            json!({ "last_name": text(), "county": text() }),
            None,
        )]);
        let plan = push::prepare(&pool, &v2, "public").await.unwrap();
        assert!(renames(&plan).is_empty(), "{:?}", plan.diff.operations);
        assert!(
            !plan
                .diff
                .warnings
                .iter()
                .any(|w| w.contains("renames.json")),
            "{:?}",
            plan.diff.warnings
        );
        let refused = push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .expect_err("an undeclared drop plus add is destructive");
        assert!(
            refused
                .to_string()
                .contains("destructive operation(s) detected"),
            "{refused:#}"
        );
        assert_eq!(
            rows(
                &pool,
                "SELECT first_name || ':' || count FROM public.people ORDER BY 1"
            )
            .await,
            ["Alice:42", "Bob:7"]
        );
    })
    .await;
}

/// E02: a real rename below any similarity threshold (`title` to `headline`) keeps its data once
/// it is declared, and the declaration left in the schema is a no-op on the next push.
#[tokio::test]
async fn a_declared_rename_keeps_the_data_and_stays_harmless() {
    common::with_integration_pool(|pool| async move {
        push(
            &pool,
            &schema(vec![model("articles", json!({ "title": text() }), None)]),
        )
        .await
        .unwrap();
        exec(
            &pool,
            "INSERT INTO public.articles (title) VALUES ('Hello'), ('World')",
        )
        .await
        .unwrap();

        let declared = schema(vec![model(
            "articles",
            json!({ "headline": renamed(text(), "title") }),
            None,
        )]);
        let plan = push::prepare(&pool, &declared, "public").await.unwrap();
        assert_eq!(renames(&plan), ["column title -> headline"]);
        assert!(!plan.diff.summary.is_destructive, "{:?}", plan.diff);
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert_eq!(
            rows(&pool, "SELECT headline FROM public.articles ORDER BY 1").await,
            ["Hello", "World"]
        );
        assert_eq!(column_type(&pool, "articles", "title").await, None);

        let again = push(&pool, &declared).await.unwrap();
        assert!(matches!(again, push::Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

/// E01, declared: an integer column renamed into a declared text field is refused, naming both,
/// and nothing is applied. A rename never changes a type behind the declaration's back.
#[tokio::test]
async fn a_declared_rename_with_an_incompatible_type_is_refused() {
    common::with_integration_pool(|pool| async move {
        let v1 = json!({ "count": scalar("integer", "INTEGER", false) });
        push(&pool, &schema(vec![model("people", v1, None)]))
            .await
            .unwrap();
        exec(&pool, "INSERT INTO public.people (count) VALUES (42)")
            .await
            .unwrap();

        let declared = schema(vec![model(
            "people",
            json!({ "county": renamed(text(), "count") }),
            None,
        )]);
        let refused = match push::prepare(&pool, &declared, "public").await {
            Ok(plan) => push::apply(&pool, plan, forced()).await.map(|_| ()),
            Err(e) => Err(e),
        }
        .expect_err("int4 is not text");
        let message = format!("{refused:#}");
        assert!(
            message.contains("\"people\".\"count\"") && message.contains("\"county\""),
            "{message}"
        );
        assert_eq!(
            column_type(&pool, "people", "count").await,
            Some(("int4".into(), "YES".into()))
        );

        // A type the source widens to is a rename and then the widening.
        let widened = schema(vec![model(
            "people",
            json!({ "total": renamed(scalar("bigInt", "BIGINT", false), "count") }),
            None,
        )]);
        push(&pool, &widened).await.unwrap();
        assert_eq!(
            column_type(&pool, "people", "total").await,
            Some(("int8".into(), "YES".into()))
        );
        assert_eq!(
            rows(&pool, "SELECT total::text FROM public.people").await,
            ["42"]
        );
    })
    .await;
}

/// E02 without a declaration: a drop plus an add is refused without `--force`; with it, it is the
/// drop and the add the schema describes.
#[tokio::test]
async fn an_undeclared_drop_plus_add_is_refused_without_force() {
    common::with_integration_pool(|pool| async move {
        push(
            &pool,
            &schema(vec![model("articles", json!({ "title": text() }), None)]),
        )
        .await
        .unwrap();
        exec(
            &pool,
            "INSERT INTO public.articles (title) VALUES ('Hello')",
        )
        .await
        .unwrap();
        let undeclared = schema(vec![model("articles", json!({ "headline": text() }), None)]);

        let refused = push(&pool, &undeclared).await.expect_err("destructive");
        assert!(
            refused.to_string().contains("1 destructive operation(s)"),
            "{refused:#}"
        );
        assert_eq!(
            rows(&pool, "SELECT title FROM public.articles").await,
            ["Hello"]
        );

        push_with(&pool, &undeclared, forced()).await.unwrap();
        assert_eq!(column_type(&pool, "articles", "title").await, None);
        assert!(column_type(&pool, "articles", "headline").await.is_some());
    })
    .await;
}

/// The engine names the pairs a person might mean as renames, for the CLI to offer: a dropped
/// column of ours and an added one on the same table whose types agree. Only offered, never
/// applied.
#[tokio::test]
async fn an_undeclared_drop_plus_add_is_offered_as_a_rename_candidate() {
    common::with_integration_pool(|pool| async move {
        let v1 = json!({ "title": text(), "count": scalar("integer", "INTEGER", false) });
        push(&pool, &schema(vec![model("articles", v1, None)]))
            .await
            .unwrap();
        let v2 = schema(vec![model(
            "articles",
            json!({ "headline": text(), "county": text() }),
            None,
        )]);
        let plan = push::prepare(&pool, &v2, "public").await.unwrap();
        let offered: Vec<String> = plan
            .diff
            .rename_candidates
            .iter()
            .map(|c| format!("{}.{} -> {}", c.table, c.from, c.to))
            .collect();
        // `count` is an integer: renaming it into a text field would be refused, so it is not
        // offered.
        assert_eq!(
            offered,
            ["articles.title -> county", "articles.title -> headline"]
        );
        assert!(renames(&plan).is_empty());
    })
    .await;
}

/// E08: a declared rename keeps the declared type and its `NOT NULL`. Declining a guessed rename
/// used to add the new column as nullable TEXT.
#[tokio::test]
async fn a_declared_rename_keeps_the_declared_type() {
    common::with_integration_pool(|pool| async move {
        let score = scalar("integer", "INTEGER", true);
        push(
            &pool,
            &schema(vec![model(
                "games",
                json!({ "score": score.clone() }),
                None,
            )]),
        )
        .await
        .unwrap();
        exec(&pool, "INSERT INTO public.games (score) VALUES (3)")
            .await
            .unwrap();

        let declared = schema(vec![model(
            "games",
            json!({ "scores": renamed(score, "score") }),
            None,
        )]);
        push(&pool, &declared).await.unwrap();
        assert_eq!(
            column_type(&pool, "games", "scores").await,
            Some(("int4".into(), "NO".into()))
        );
        assert_eq!(
            rows(&pool, "SELECT scores::text FROM public.games").await,
            ["3"]
        );
    })
    .await;
}

/// E07: a declared table rename keeps the rows, and the push builds everything for the new name
/// (it used to fail `type public.postings does not exist` when a guessed one was declined). An
/// undeclared one is a drop and a create, refused without `--force`.
#[tokio::test]
async fn a_table_rename_is_applied_only_when_declared() {
    common::with_integration_pool(|pool| async move {
        let fields = json!({ "title": text() });
        push(&pool, &schema(vec![model("posts", fields.clone(), None)]))
            .await
            .unwrap();
        exec(&pool, "INSERT INTO public.posts (title) VALUES ('P1')")
            .await
            .unwrap();

        let undeclared = schema(vec![model("postings", fields.clone(), None)]);
        let plan = push::prepare(&pool, &undeclared, "public").await.unwrap();
        assert!(renames(&plan).is_empty(), "{:?}", plan.diff.operations);
        let refused = push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .expect_err("dropping posts is destructive");
        assert!(refused.to_string().contains("destructive"), "{refused:#}");

        let declared = schema(vec![model("postings", fields, Some("posts"))]);
        let plan = push::prepare(&pool, &declared, "public").await.unwrap();
        assert_eq!(renames(&plan), ["table posts -> postings"]);
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert_eq!(
            rows(&pool, "SELECT title FROM public.postings").await,
            ["P1"]
        );
        let again = push(&pool, &declared).await.unwrap();
        assert!(matches!(again, push::Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

/// A declaration on a database that never had the source (a fresh one, or a later environment
/// that started from the renamed schema) is a no-op: the column and table are simply created.
#[tokio::test]
async fn a_declaration_without_its_source_is_a_no_op() {
    common::with_integration_pool(|pool| async move {
        let declared = schema(vec![model(
            "postings",
            json!({ "headline": renamed(text(), "title") }),
            Some("posts"),
        )]);
        let plan = push::prepare(&pool, &declared, "public").await.unwrap();
        assert!(renames(&plan).is_empty(), "{:?}", plan.diff.operations);
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        assert!(column_type(&pool, "postings", "headline").await.is_some());
    })
    .await;
}

/// A declaration whose source and target both exist cannot be a rename: the push is refused,
/// naming both, rather than guessing which one the schema means.
#[tokio::test]
async fn a_rename_onto_an_existing_column_is_refused() {
    common::with_integration_pool(|pool| async move {
        push(
            &pool,
            &schema(vec![model(
                "articles",
                json!({ "title": text(), "headline": text() }),
                None,
            )]),
        )
        .await
        .unwrap();
        let declared = schema(vec![model(
            "articles",
            json!({ "headline": renamed(text(), "title") }),
            None,
        )]);
        let refused = push::prepare(&pool, &declared, "public")
            .await
            .err()
            .expect("both columns exist");
        let message = format!("{refused:#}");
        assert!(
            message.contains("\"articles\".\"title\"") && message.contains("\"headline\""),
            "{message}"
        );
    })
    .await;
}
