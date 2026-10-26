/// Tests for normaliser behaviours discovered during local dev that were previously untested.
use supatype_engine::{
    differ,
    generator::sql::migration,
    introspector::tables::{DbColumn, DbTable},
    parser, push,
    state::database_state::DatabaseState,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn col(name: &str, data_type: &str) -> DbColumn {
    DbColumn {
        name: name.into(),
        data_type: data_type.into(),
        udt_name: data_type.into(),
        nullable: true,
        default: None,
        ordinal_position: 0,
        ..Default::default()
    }
}

fn col_pk(name: &str, data_type: &str, default: &str) -> DbColumn {
    DbColumn {
        name: name.into(),
        data_type: data_type.into(),
        udt_name: data_type.into(),
        nullable: false,
        default: Some(default.into()),
        ordinal_position: 0,
        ..Default::default()
    }
}

// ── 1. Auto-injected `id` primary key ─────────────────────────────────────────

/// A model with no explicit primary key should get `id UUID PRIMARY KEY DEFAULT gen_random_uuid()`
/// injected by the normaliser, and the CREATE TABLE SQL must contain it.
#[test]
fn test_auto_pk_injected_into_model_without_explicit_pk() {
    let schema = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Article",
      "fields": {
        "title": {
          "kind": "text",
          "required": true,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        }
      },
      "options": {},
      "annotations": {
        "db": {
          "tableName": "article",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(schema).unwrap();
    let model = &ast.models[0];

    // Normaliser must have injected "id"
    assert!(
        model.fields.contains_key("id"),
        "normaliser should inject 'id' field when no explicit PK exists"
    );

    // The CREATE TABLE SQL must contain the id column as primary key
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::generate(&diff, false, "public", &ast).unwrap();

    assert!(
        sql.contains("\"id\" UUID") && sql.contains("PRIMARY KEY"),
        "CREATE TABLE SQL must contain '\"id\" UUID ... PRIMARY KEY'; got:\n{sql}"
    );
    assert!(
        sql.contains("gen_random_uuid()"),
        "CREATE TABLE SQL must contain gen_random_uuid() default for id; got:\n{sql}"
    );
}

/// A model that already has an explicit PK must NOT receive a duplicate `id` from the normaliser.
#[test]
fn test_no_duplicate_id_when_explicit_pk_exists() {
    let schema = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Article",
      "fields": {
        "articleId": {
          "kind": "uuid",
          "required": true,
          "primaryKey": true,
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
        "title": {
          "kind": "text",
          "required": true,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        }
      },
      "options": {},
      "annotations": {
        "db": {
          "tableName": "article",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(schema).unwrap();
    let model = &ast.models[0];

    assert!(
        !model.fields.contains_key("id"),
        "normaliser must NOT inject 'id' when model already has an explicit primary key"
    );
}

/// After a fresh push the differ must NOT produce a DropColumn for the auto-injected `id`
/// when the DB already has that column (no-op diff scenario).
#[test]
fn test_no_drop_id_on_noop_diff() {
    let schema = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Article",
      "fields": {
        "title": {
          "kind": "text",
          "required": true,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        }
      },
      "options": {},
      "annotations": {
        "db": {
          "tableName": "article",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(schema).unwrap();

    // Simulate DB state as if the first migration already ran: article has id + title.
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "article".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![
                col_pk("id", "uuid", "gen_random_uuid()"),
                col("title", "text"),
            ],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let sql = migration::generate(&diff, false, "public", &ast).unwrap();

    assert!(
        !sql.to_lowercase().contains("drop column"),
        "no-op diff must not generate any DROP COLUMN; got SQL:\n{sql}"
    );
}

// ── 2. Field insertion order preserved ────────────────────────────────────────

/// Fields in the generated CREATE TABLE SQL must appear in the same order as
/// defined in the input JSON, not alphabetically or HashMap-randomised.
#[test]
fn test_field_order_preserved_in_create_table_sql() {
    // Fields deliberately in non-alphabetical order: z_field, a_field, m_field
    let schema = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Ordered",
      "fields": {
        "z_field": {
          "kind": "text",
          "required": false,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        },
        "a_field": {
          "kind": "text",
          "required": false,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        },
        "m_field": {
          "kind": "text",
          "required": false,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        }
      },
      "options": {},
      "annotations": {
        "db": {
          "tableName": "ordered",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(schema).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::generate(&diff, false, "public", &ast).unwrap();

    let z_pos = sql.find("\"z_field\"").expect("z_field not found in SQL");
    let a_pos = sql.find("\"a_field\"").expect("a_field not found in SQL");
    let m_pos = sql.find("\"m_field\"").expect("m_field not found in SQL");

    assert!(
        z_pos < a_pos && a_pos < m_pos,
        "fields must appear in definition order (z < a < m), got positions: z={z_pos}, a={a_pos}, m={m_pos}\nSQL:\n{sql}"
    );
}

// ── 3. belongsTo FK column name derived from field name ───────────────────────

/// When a belongsTo relation omits `foreignKey`, the engine must derive the FK
/// column name as `{fieldName}_id` (e.g. field "author" → column "author_id").
#[test]
fn test_belongs_to_fk_derived_from_field_name() {
    let schema = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "User",
      "fields": {
        "name": {
          "kind": "text",
          "required": true,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        }
      },
      "options": {},
      "annotations": {
        "db": {
          "tableName": "user",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    },
    {
      "name": "Post",
      "fields": {
        "title": {
          "kind": "text",
          "required": true,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        },
        "author": {
          "kind": "relation",
          "cardinality": "belongsTo",
          "target": "User",
          "onDelete": "cascade"
        }
      },
      "options": {},
      "annotations": {
        "db": {
          "tableName": "post",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(schema).unwrap();
    // The whole first push, foreign keys included: they are the reconcile's since Phase 4.1.
    let sql = push::fresh_migration(&ast, "public", false).unwrap().up();

    assert!(
        sql.contains("\"author_id\""),
        "derived FK column must be 'author_id' when field is named 'author'; SQL:\n{sql}"
    );
    assert!(
        sql.contains("FOREIGN KEY (\"author_id\")"),
        "FK constraint must reference derived column 'author_id'; SQL:\n{sql}"
    );
    assert!(
        sql.contains("REFERENCES \"public\".\"user\""),
        "FK constraint must reference target table 'user'; SQL:\n{sql}"
    );
}

// ── 4. ASCII-only SQL comments ─────────────────────────────────────────────────

/// Migration SQL comments must not contain non-ASCII characters.
/// Unicode arrows (→, U+2192) in comments cause WIN1252 encoding failures on Windows.
#[test]
fn test_migration_comments_are_ascii_only() {
    let schema = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "User",
      "fields": {
        "name": {
          "kind": "text",
          "required": true,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        }
      },
      "options": {},
      "annotations": {
        "db": {
          "tableName": "user",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    },
    {
      "name": "Post",
      "fields": {
        "title": {
          "kind": "text",
          "required": true,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        },
        "author": {
          "kind": "relation",
          "cardinality": "belongsTo",
          "target": "User",
          "onDelete": "cascade"
        }
      },
      "options": {},
      "annotations": {
        "db": {
          "tableName": "post",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(schema).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::generate(&diff, false, "public", &ast).unwrap();

    for line in sql.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("--") {
            assert!(
                trimmed.is_ascii(),
                "migration comment contains non-ASCII character (e.g. Unicode arrow →): {trimmed:?}"
            );
        }
    }
}

/// Rename-column migration comment must use ASCII arrow `->`, not Unicode `→`.
#[test]
fn test_rename_column_comment_uses_ascii_arrow() {
    // Schema now has "new_name", declared as renamed from "old_name", which the DB still has.
    let schema = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Thing",
      "fields": {
        "new_name": {
          "kind": "text",
          "required": false,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false,
              "renamedFrom": "old_name"
            }
          }
        }
      },
      "options": {},
      "annotations": {
        "db": {
          "tableName": "thing",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(schema).unwrap();

    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "thing".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![
                col_pk("id", "uuid", "gen_random_uuid()"),
                col("old_name", "text"),
            ],
        }],
        // Only a column the ledger records as ours is renamed.
        column_ownership: [(("thing".to_string(), "old_name".to_string()), true)].into(),
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let sql = migration::generate(&diff, false, "public", &ast).unwrap();
    assert!(
        sql.contains("RENAME COLUMN \"old_name\" TO \"new_name\""),
        "{sql}"
    );

    for line in sql.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("--") {
            assert!(
                trimmed.is_ascii(),
                "migration comment contains non-ASCII character: {trimmed:?}"
            );
        }
    }
}

// ── Column names past Postgres's identifier limit ─────────────────────────────

/// `posts` with `fields` besides its id, and `rule` as its read rule.
fn posts_doc(fields: serde_json::Value, rule: serde_json::Value) -> String {
    let mut all = serde_json::json!({ "id": { "kind": "uuid", "primaryKey": true,
                                              "required": true } });
    all.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    serde_json::json!({
        "astVersion": 2,
        "models": [{
            "name": "Post",
            "fields": all,
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": { "tableName": "posts", "indexes": [] },
                             "platform": { "access": { "read": rule } } }
        }]
    })
    .to_string()
}

/// A field named past 63 bytes is the column Postgres keeps, its first 63 bytes, and a rule that
/// names it names that column.
#[test]
fn a_column_name_past_the_identifier_limit_is_kept_as_postgres_keeps_it() {
    let long = "registration_dietary_requirements_and_preferences_free_text_notes";
    assert!(long.len() > 63);
    let rule = serde_json::json!({ "type": "nullCheck", "isNull": false,
                                   "operand": { "kind": "column", "name": long } });
    let doc = posts_doc(serde_json::json!({ long: { "kind": "text" } }), rule);
    let ast = parser::parse(&doc).expect("parses");
    let model = &ast.models[0];
    assert!(
        model.fields.contains_key(&long[..63]),
        "{:?}",
        model.fields.keys()
    );
    let read = format!("{:?}", model.access().read);
    assert!(read.contains(&format!("\"{}\"", &long[..63])), "{read}");
}

/// Two columns whose names agree for their first 63 bytes would be one column to Postgres: the
/// schema is refused, naming both, rather than one silently taking the other's place.
#[test]
fn two_column_names_postgres_would_cut_to_one_are_refused() {
    let stem = "registration_dietary_requirements_and_preferences_free_text_not";
    assert_eq!(stem.len(), 63);
    let (a, b) = (format!("{stem}es_a"), format!("{stem}es_b"));
    let doc = posts_doc(
        serde_json::json!({ &a: { "kind": "text" }, &b: { "kind": "text" } }),
        serde_json::json!({ "type": "public" }),
    );
    let refused = parser::parse(&doc).expect_err("refused").to_string();
    assert!(refused.contains(&a) && refused.contains(&b), "{refused}");
    assert!(refused.contains("63"), "{refused}");
}

/// A relation's key column derived from a long field name is written out as Postgres keeps it.
#[test]
fn a_derived_foreign_key_column_past_the_limit_is_kept_as_postgres_keeps_it() {
    let field = "conference_attendee_registration_preferences_and_requirements";
    let doc = serde_json::json!({
        "astVersion": 2,
        "models": [{
            "name": "Prefs", "fields": { "id": { "kind": "uuid", "primaryKey": true } },
            "annotations": { "db": { "tableName": "prefs" } }
        }, {
            "name": "Diet",
            "fields": {
                "id": { "kind": "uuid", "primaryKey": true },
                field: { "kind": "relation", "cardinality": "belongsTo", "target": "Prefs" }
            },
            "annotations": { "db": { "tableName": "diets" } }
        }]
    });
    let ast = parser::parse(&doc.to_string()).expect("parses");
    let diet = ast.models.iter().find(|m| m.name == "Diet").unwrap();
    let Some(supatype_engine::parser::ast::FieldAst::Relation(rel)) = diet.fields.get(field) else {
        panic!("the relation");
    };
    let derived = format!("{field}_id");
    assert_eq!(rel.foreign_key.as_deref(), Some(&derived[..63]));
}
