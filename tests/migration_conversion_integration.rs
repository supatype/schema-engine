//! Integration tests for column type conversion SQL against real Postgres.
//!
//! Uses the shared integration pool helper (ephemeral DB per test when `DATABASE_URL`
//! is set, or testcontainers locally).

mod common;

use common::with_integration_pool;
use supatype_engine::{differ, generator::sql::migration, introspector, parser, push};

/// A retype is destructive, so the push that makes one is forced.
fn forced() -> push::ApplyOptions {
    push::ApplyOptions {
        force: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn integer_to_jsonb_preserves_numeric_json() {
    with_integration_pool(|pool| async move {
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS conv_test (id serial PRIMARY KEY, value integer); \
             COMMENT ON TABLE conv_test IS 'supatype:managed;kind=table;table=conv_test;fields=;v=1'; \
             TRUNCATE conv_test; \
             INSERT INTO conv_test (value) VALUES (42);",
        )
        .execute(&pool)
        .await
        .expect("seed");

        let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "ConvTest",
      "fields": {
        "id": {
          "kind": "integer",
          "primaryKey": true,
          "required": true,
          "annotations": {
            "db": {
              "pgType": "INTEGER",
              "unique": false
            }
          }
        },
        "value": {
          "kind": "json",
          "required": false,
          "annotations": {
            "db": {
              "pgType": "JSONB",
              "unique": false
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false
      },
      "annotations": {
        "db": {
          "tableName": "conv_test",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

        let ast = parser::parse(ast_json).unwrap();
        common::push_with(&pool, &ast, forced())
            .await
            .expect("migrate");

        let row: (serde_json::Value,) = sqlx::query_as("SELECT value FROM conv_test WHERE id = 1")
            .fetch_one(&pool)
            .await
            .expect("read row");

        assert_eq!(row.0, serde_json::json!(42));
    })
    .await;
}

#[tokio::test]
async fn text_to_richtext_wraps_lexical_document() {
    with_integration_pool(|pool| async move {
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS rt_test (id serial PRIMARY KEY, body text); \
             COMMENT ON TABLE rt_test IS 'supatype:managed;kind=table;table=rt_test;fields=;v=1'; \
             TRUNCATE rt_test; \
             INSERT INTO rt_test (body) VALUES ('Hello world');",
        )
        .execute(&pool)
        .await
        .expect("seed");

        let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "RtTest",
      "fields": {
        "id": {
          "kind": "integer",
          "primaryKey": true,
          "required": true,
          "annotations": {
            "db": {
              "pgType": "INTEGER",
              "unique": false
            }
          }
        },
        "body": {
          "kind": "richText",
          "required": false,
          "annotations": {
            "db": {
              "pgType": "JSONB",
              "unique": false
            },
            "platform": {
              "editor": "rich"
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false
      },
      "annotations": {
        "db": {
          "tableName": "rt_test",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

        let ast = parser::parse(ast_json).unwrap();
        common::push_with(&pool, &ast, forced())
            .await
            .expect("migrate");

        let row: (serde_json::Value,) = sqlx::query_as("SELECT body FROM rt_test WHERE id = 1")
            .fetch_one(&pool)
            .await
            .expect("read row");

        assert_eq!(row.0["root"]["type"], "root");
        let text = row.0["root"]["children"][0]["children"][0]["text"]
            .as_str()
            .unwrap();
        assert_eq!(text, "Hello world");
    })
    .await;
}

#[tokio::test]
async fn richtext_to_text_extracts_plain_text() {
    with_integration_pool(|pool| async move {
        let lexical = serde_json::json!({
            "root": {
                "type": "root",
                "version": 1,
                "children": [{
                    "type": "paragraph",
                    "version": 1,
                    "children": [{
                        "type": "text",
                        "version": 1,
                        "text": "Retreat copy"
                    }]
                }]
            }
        });

        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS rt_back_test (id serial PRIMARY KEY, body jsonb); \
             COMMENT ON TABLE rt_back_test IS 'supatype:managed;kind=table;table=rt_back_test;fields=;v=1'; \
             TRUNCATE rt_back_test;",
        )
        .execute(&pool)
        .await
        .expect("create");

        sqlx::query("INSERT INTO rt_back_test (body) VALUES ($1)")
            .bind(lexical)
            .execute(&pool)
            .await
            .expect("seed");

        let previous_json = r#"{
  "astVersion": 2,
  "models": [{
    "name": "RtBackTest",
    "fields": {
      "id": {
        "kind": "integer",
        "primaryKey": true,
        "required": true,
        "annotations": { "db": { "pgType": "INTEGER", "unique": false } }
      },
      "body": {
        "kind": "richText",
        "required": false,
        "annotations": {
          "db": { "pgType": "JSONB", "unique": false },
          "platform": { "editor": "rich" }
        }
      }
    },
    "options": { "timestamps": false, "softDelete": false },
    "annotations": {
      "db": { "tableName": "rt_back_test", "indexes": [] },
      "platform": { "access": {} }
    }
  }]
}"#;

        let ast_json = r#"{
  "astVersion": 2,
  "models": [{
    "name": "RtBackTest",
    "fields": {
      "id": {
        "kind": "integer",
        "primaryKey": true,
        "required": true,
        "annotations": { "db": { "pgType": "INTEGER", "unique": false } }
      },
      "body": {
        "kind": "text",
        "required": false,
        "annotations": { "db": { "pgType": "TEXT", "unique": false } }
      }
    },
    "options": { "timestamps": false, "softDelete": false },
    "annotations": {
      "db": { "tableName": "rt_back_test", "indexes": [] },
      "platform": { "access": {} }
    }
  }]
}"#;

        let previous = parser::parse(previous_json).unwrap();
        let ast = parser::parse(ast_json).unwrap();
        let db = introspector::introspect(&pool, "public").await.unwrap();
        let diff = differ::diff_with_previous(&ast, &db, Some(&previous)).unwrap();
        let sql = migration::forward_sql(&diff, true, "public", &ast).unwrap();

        sqlx::raw_sql(&sql).execute(&pool).await.expect("migrate");

        let row: (String,) = sqlx::query_as("SELECT body FROM rt_back_test WHERE id = 1")
            .fetch_one(&pool)
            .await
            .expect("read row");

        assert_eq!(row.0, "Retreat copy");
    })
    .await;
}

/// The `links` column of `blk_test`, first as JSON and then as blocks of one declared kind.
fn links_ast(kind_json: &str) -> parser::ast::SchemaAst {
    let ast_json = format!(
        r#"{{
  "astVersion": 2,
  "models": [{{
    "name": "BlkTest",
    "fields": {{
      "id": {{
        "kind": "integer",
        "primaryKey": true,
        "required": true,
        "annotations": {{ "db": {{ "pgType": "INTEGER", "unique": false }} }}
      }},
      "links": {kind_json}
    }},
    "options": {{ "timestamps": false, "softDelete": false }},
    "annotations": {{
      "db": {{ "tableName": "blk_test", "indexes": [] }},
      "platform": {{ "access": {{}} }}
    }}
  }}]
}}"#
    );
    parser::parse(&ast_json).unwrap()
}

const LINKS_AS_JSON: &str = r#"{
  "kind": "json",
  "required": false,
  "annotations": { "db": { "pgType": "JSONB", "unique": false } }
}"#;

const LINKS_AS_BLOCKS: &str = r#"{
  "kind": "blocks",
  "required": false,
  "blocks": [{
    "name": "link",
    "label": null,
    "icon": null,
    "fields": {
      "label": { "kind": "text", "pgType": "TEXT", "required": true, "unique": false, "localized": false },
      "href": { "kind": "text", "pgType": "TEXT", "required": true, "unique": false, "localized": false }
    }
  }],
  "annotations": { "db": { "pgType": "JSONB", "unique": false } }
}"#;

/// Seeds `blk_test` with one row per value, then retypes `links` from JSON to blocks.
async fn json_to_blocks(pool: &sqlx::PgPool, seeds: &[&str]) -> Result<(), sqlx::Error> {
    seed_links(pool, seeds).await;
    let previous = links_ast(LINKS_AS_JSON);
    let ast = links_ast(LINKS_AS_BLOCKS);
    let db = introspector::introspect(pool, "public").await.unwrap();
    let diff = differ::diff_with_previous(&ast, &db, Some(&previous)).unwrap();
    let sql = migration::forward_sql(&diff, true, "public", &ast).unwrap();
    // One connection, so a refused script's open transaction is rolled back where it was opened.
    let mut conn = pool.acquire().await.expect("acquire");
    let applied = sqlx::raw_sql(&sql).execute(&mut *conn).await.map(|_| ());
    if applied.is_err() {
        sqlx::raw_sql("ROLLBACK")
            .execute(&mut *conn)
            .await
            .expect("rollback");
    }
    applied
}

/// A fresh `blk_test` holding one row per seed, as JSON.
async fn seed_links(pool: &sqlx::PgPool, seeds: &[&str]) {
    sqlx::raw_sql(
        "DROP TABLE IF EXISTS blk_test; \
         CREATE TABLE blk_test (id integer PRIMARY KEY, links jsonb); \
         COMMENT ON TABLE blk_test IS 'supatype:managed;kind=table;table=blk_test;fields=;v=1';",
    )
    .execute(pool)
    .await
    .expect("create");
    for (i, seed) in seeds.iter().enumerate() {
        sqlx::query("INSERT INTO blk_test (id, links) VALUES ($1, $2::jsonb)")
            .bind(i32::try_from(i + 1).expect("few seeds"))
            .bind(*seed)
            .execute(pool)
            .await
            .expect("seed");
    }
}

async fn links_by_id(pool: &sqlx::PgPool) -> Vec<Option<serde_json::Value>> {
    let rows: Vec<(Option<serde_json::Value>,)> =
        sqlx::query_as("SELECT links FROM blk_test ORDER BY id")
            .fetch_all(pool)
            .await
            .expect("read rows");
    rows.into_iter().map(|(links,)| links).collect()
}

/// Each object in a JSON array becomes its own block, an empty array stays empty, a lone object is
/// one block, and a column already holding blocks is left alone.
#[tokio::test]
async fn json_to_blocks_makes_one_block_per_object() {
    with_integration_pool(|pool| async move {
        json_to_blocks(
            &pool,
            &[
                r#"[{"label":"Go","href":"/x"},{"label":"Docs","href":"/d"}]"#,
                "[]",
                r#"{"label":"One","href":"/1"}"#,
                r#"[{"type":"link","data":{"label":"Kept","href":"/k"}}]"#,
                "null",
            ],
        )
        .await
        .expect("migrate");

        let link = |label: &str, href: &str| {
            serde_json::json!({ "type": "link", "data": { "label": label, "href": href } })
        };
        assert_eq!(
            links_by_id(&pool).await,
            vec![
                Some(serde_json::json!([link("Go", "/x"), link("Docs", "/d")])),
                Some(serde_json::json!([])),
                Some(serde_json::json!([link("One", "/1")])),
                Some(serde_json::json!([link("Kept", "/k")])),
                Some(serde_json::Value::Null),
            ]
        );
    })
    .await;
}

/// A value that is not an object has no fields to put under `data`, so the retype is refused and
/// every row keeps what it held.
#[tokio::test]
async fn json_to_blocks_refuses_values_that_are_not_objects() {
    with_integration_pool(|pool| async move {
        for seeds in [
            [r#"[{"label":"Go","href":"/x"}]"#, r#"["Go", 1]"#],
            [r#"[{"label":"Go","href":"/x"}]"#, r#""hello""#],
        ] {
            let refused = json_to_blocks(&pool, &seeds)
                .await
                .expect_err("a value that is not an object is refused");
            let message = refused.to_string();
            assert!(
                message.contains("blk_test.links") && message.contains("not an object"),
                "the refusal names the column and the reason: {message}"
            );
            let kept: Vec<Option<serde_json::Value>> = seeds
                .iter()
                .map(|s| Some(serde_json::from_str(s).unwrap()))
                .collect();
            assert_eq!(links_by_id(&pool).await, kept, "no row changed");
        }
    })
    .await;
}
