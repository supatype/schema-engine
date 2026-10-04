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
