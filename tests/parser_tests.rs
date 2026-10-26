use supatype_engine::generator::sql::storage;
use supatype_engine::generator::typescript::admin;
use supatype_engine::parser;

#[test]
fn test_parse_empty_schema() {
    let input = r#"{
  "astVersion": 2,
  "models": []
}"#;
    let ast = parser::parse(input).unwrap();
    assert!(ast.models.is_empty());
}

#[test]
fn test_parse_basic_model() {
    let input = include_str!("fixtures/basic_blog.json");
    let ast = parser::parse(input).unwrap();
    assert!(!ast.models.is_empty());
}

#[test]
fn test_storage_buckets_merge_and_declarative_rls() {
    let input = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Post",
      "fields": {
        "id": {
          "kind": "uuid",
          "primaryKey": true,
          "required": true,
          "default": {
            "kind": "genRandomUuid"
          },
          "annotations": {
            "db": {
              "pgType": "UUID",
              "unique": false
            }
          }
        },
        "manual": {
          "kind": "file",
          "required": false,
          "bucket": "docs",
          "annotations": {
            "db": {
              "pgType": "TEXT"
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
          "tableName": "posts",
          "indexes": []
        },
        "platform": {
          "access": {
            "read": {
              "type": "authenticated"
            }
          }
        }
      }
    }
  ],
  "storageBuckets": [
    {
      "id": "docs",
      "public": false,
      "accessMode": "private",
      "allowedMimeTypes": [
        "application/pdf"
      ],
      "fileSizeLimit": 52428800,
      "access": {
        "read": {
          "type": "public"
        },
        "create": {
          "type": "authenticated"
        },
        "delete": {
          "type": "authenticated"
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(input).unwrap();
    let b = ast
        .storage_buckets
        .iter()
        .find(|x| x.id == "docs")
        .expect("docs bucket");
    assert_eq!(
        b.allowed_mime_types.as_deref(),
        Some(&["application/pdf".to_string()][..])
    );
    assert_eq!(b.file_size_limit, Some(52428800));
    assert!(b.access.is_some());

    let sql = storage::bucket_policies_sql(&ast);
    assert!(sql.contains("storage_docs_sel"));
    // Not desired, so a model policy left from before the bucket declared rules is dropped: it
    // would be ORed with them.
    assert!(
        !sql.contains("CREATE POLICY \"posts_docs_sel\""),
        "declarative bucket RLS should suppress model/table-prefixed policies for that bucket"
    );
}

#[test]
fn test_storage_custom_mode_and_s3_policy_roundtrip() {
    let input = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Doc",
      "fields": {
        "id": {
          "kind": "uuid",
          "primaryKey": true,
          "required": true,
          "default": {
            "kind": "genRandomUuid"
          },
          "annotations": {
            "db": {
              "pgType": "UUID",
              "unique": false
            }
          }
        },
        "file": {
          "kind": "file",
          "required": false,
          "bucket": "private_docs",
          "annotations": {
            "db": {
              "pgType": "TEXT"
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
          "tableName": "docs",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ],
  "storageBuckets": [
    {
      "id": "private_docs",
      "public": false,
      "accessMode": "custom",
      "s3BucketPolicy": "{\"Version\":\"2012-10-17\"}"
    }
  ]
}"#;

    let ast = parser::parse(input).unwrap();
    let b = ast
        .storage_buckets
        .iter()
        .find(|x| x.id == "private_docs")
        .expect("private_docs bucket");
    assert_eq!(
        b.access_mode.as_ref().map(|m| format!("{m:?}")),
        Some("Custom".to_string())
    );
    assert_eq!(
        b.s3_bucket_policy.as_deref(),
        Some("{\"Version\":\"2012-10-17\"}")
    );

    let sql = storage::generate(&ast).unwrap();
    assert!(
        sql.contains("access_mode"),
        "storage SQL should include access_mode upsert/ddl fields"
    );
    assert!(
        sql.contains("s3_bucket_policy"),
        "storage SQL should include s3_bucket_policy upsert/ddl fields"
    );
    assert!(
        sql.contains("'custom'"),
        "custom access mode should be serialized in SQL"
    );
}

#[test]
fn test_admin_output_includes_storage_buckets() {
    let input = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "User",
      "fields": {
        "id": {
          "kind": "uuid",
          "primaryKey": true,
          "required": true,
          "default": {
            "kind": "genRandomUuid"
          },
          "annotations": {
            "db": {
              "pgType": "UUID",
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
          "tableName": "users",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ],
  "storageBuckets": [
    {
      "id": "avatars",
      "public": true,
      "accessMode": "public",
      "allowedMimeTypes": [
        "image/png"
      ]
    }
  ]
}"#;

    let ast = parser::parse(input).unwrap();
    let admin_json = admin::generate(&ast).unwrap();
    let buckets = admin_json
        .get("storageBuckets")
        .and_then(|v| v.as_array())
        .expect("storageBuckets array in admin output");
    assert_eq!(buckets.len(), 1);
    let first = &buckets[0];
    assert_eq!(first.get("id").and_then(|v| v.as_str()), Some("avatars"));
    assert_eq!(first.get("public").and_then(|v| v.as_bool()), Some(true));
}
