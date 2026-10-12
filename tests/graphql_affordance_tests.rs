//! The `can_*` affordance functions stay out of GraphQL and stay callable through REST (CT3).
//!
//! Each model's `can_read_<table>`, `can_create_<table>`, `can_update_<table>` and
//! `can_delete_<table>` takes the table's row, which is exactly what pg_graphql reflects as a
//! computed field, so every model's GraphQL type listed four fields nobody asked for. pg_graphql
//! 1.5.9 has no directive that leaves a function out (its function directives are `name` and
//! `description`), but it reflects only functions that take the row alone, while PostgREST calls a
//! function whose other parameters have defaults as a computed column too. So each takes a second
//! parameter with a default: Studio's `select=*,can_update_posts` keeps working, and GraphQL no
//! longer lists them.

mod common;

use serde_json::json;
use supatype_engine::{parser, parser::ast::SchemaAst};

use common::{exec, push};

fn schema() -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": [{
        "name": "Note",
        "fields": {
            "id": { "kind": "uuid", "primaryKey": true, "required": true,
                    "default": { "kind": "genRandomUuid" },
                    "annotations": { "db": { "pgType": "UUID", "unique": false } } },
            "body": { "kind": "text", "required": false,
                      "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
        },
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": { "tableName": "ct_note", "indexes": [] },
                         "platform": { "access": {
                             "read": { "type": "public" },
                             "update": { "type": "authenticated" } } } } }]});
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// CT3: GraphQL's type for a model lists its columns and no `can_*` function.
#[tokio::test(flavor = "multi_thread")]
async fn graphql_lists_no_affordance_function() {
    common::with_integration_pool(|pool| async move {
        if exec(&pool, "CREATE EXTENSION IF NOT EXISTS pg_graphql")
            .await
            .is_err()
        {
            assert!(!common::force_integration_tests(), "pg_graphql is missing");
            return;
        }
        push(&pool, &schema()).await.unwrap();
        let fields: serde_json::Value = sqlx::query_scalar(
            "SELECT graphql.resolve($q$ { __type(name: \"ct_note\") { fields { name } } } $q$)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let names: Vec<&str> = fields["data"]["__type"]["fields"]
            .as_array()
            .unwrap_or_else(|| panic!("no type for ct_note: {fields}"))
            .iter()
            .filter_map(|f| f["name"].as_str())
            .collect();
        assert!(names.contains(&"body"), "{names:?}");
        assert!(
            !names.iter().any(|n| n.starts_with("can_")),
            "GraphQL lists affordance functions: {names:?}"
        );
    })
    .await;
}

/// CT3: each is still called with the row alone, as PostgREST calls a computed column.
#[tokio::test(flavor = "multi_thread")]
async fn each_affordance_function_is_called_with_the_row_alone() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema()).await.unwrap();
        exec(&pool, "INSERT INTO public.ct_note (body) VALUES ('x')")
            .await
            .unwrap();
        let (read, update): (bool, bool) = sqlx::query_as(
            "SELECT public.can_read_ct_note(n), public.can_update_ct_note(n) FROM public.ct_note n",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(read, "read is public");
        assert!(!update, "not signed in");
        let again = push(&pool, &schema()).await.unwrap();
        assert!(
            matches!(again, supatype_engine::push::Outcome::UpToDate { .. }),
            "{again:?}"
        );
    })
    .await;
}
