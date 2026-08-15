//! Evolution scenario tests — Phase 1 requirement.
//!
//! Each test follows the pattern:
//!   1. Base DB state (simulates already-applied schema)
//!   2. New schema AST (simulates the desired change)
//!   3. Compute the diff
//!   4. Assert expected operations
//!
//! These are pure unit tests — no DB required.

use supatype_engine::{
    differ::{self, Operation, Risk},
    generator::typescript::admin,
    introspector::{
        constraints::{DbConstraint, DbConstraintType},
        enums::DbEnum,
        rls::DbRlsPolicy,
        tables::{DbColumn, DbTable},
    },
    parser,
    state::database_state::DatabaseState,
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn col(name: &str, data_type: &str) -> DbColumn {
    DbColumn {
        name: name.into(),
        data_type: data_type.into(),
        udt_name: data_type.into(),
        nullable: true,
        default: None,
        ordinal_position: 0,
    }
}

fn fk(table: &str, col_name: &str, ftable: &str) -> DbConstraint {
    DbConstraint {
        table: table.into(),
        name: format!("{table}_{col_name}_fkey"),
        constraint_type: DbConstraintType::ForeignKey,
        columns: vec![col_name.into()],
        foreign_table: Some(ftable.into()),
        foreign_columns: Some(vec!["id".into()]),
        check_expression: None,
        on_delete: Some("RESTRICT".into()),
        comment: None,
    }
}

// ─── Scenario 1: add_column_nullable ─────────────────────────────────────────

#[test]
fn test_add_column_nullable() {
    let ast_json = r#"{
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
        "excerpt": {
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("title", "text")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let add_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::AddColumn { column, .. } if column == "excerpt"))
        .collect();
    assert_eq!(add_ops.len(), 1, "should add excerpt column");
    assert!(
        !diff.summary.is_destructive,
        "adding nullable column is safe"
    );
}

// ─── Scenario 2: drop_column ─────────────────────────────────────────────────

#[test]
fn test_drop_column() {
    let ast_json = r#"{
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![
                col("id", "uuid"),
                col("title", "text"),
                col("legacy_field", "text"),
            ],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let drop_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::DropColumn { column, .. } if column == "legacy_field"))
        .collect();
    assert_eq!(drop_ops.len(), 1, "should detect dropped column");
    assert!(
        diff.summary.is_destructive,
        "dropping a column is destructive"
    );
}

// ─── Scenario 3: rename_column ───────────────────────────────────────────────

#[test]
fn test_rename_column_detected() {
    let ast_json = r#"{
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
        "body_content": {
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("body_text", "text")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let rename_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| {
            matches!(op, Operation::RenameColumn { from, to, .. }
            if from == "body_text" && to == "body_content")
        })
        .collect();
    assert_eq!(
        rename_ops.len(),
        1,
        "should detect rename via string similarity"
    );

    let drop_of_old: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::DropColumn { column, .. } if column == "body_text"))
        .collect();
    let add_of_new: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::AddColumn { column, .. } if column == "body_content"))
        .collect();
    assert!(
        drop_of_old.is_empty(),
        "must not emit DropColumn for the renamed column"
    );
    assert!(
        add_of_new.is_empty(),
        "must not emit AddColumn for the renamed column"
    );
}

// ─── Scenario 4: add FK on existing table ────────────────────────────────────

#[test]
fn test_add_fk_on_existing_table() {
    let ast_json = r#"{
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
    },
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
        "authorId": {
          "kind": "relation",
          "cardinality": "belongsTo",
          "target": "User",
          "onDelete": "cascade",
          "annotations": {
            "db": {
              "foreignKey": "author_id"
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![
            DbTable {
                schema: "public".into(),
                name: "users".into(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col("id", "uuid")],
            },
            DbTable {
                schema: "public".into(),
                name: "posts".into(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col("id", "uuid"), col("author_id", "uuid")],
            },
        ],
        constraints: vec![], // FK not yet present
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let fk_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::AddForeignKey { table, .. } if table == "posts"))
        .collect();
    assert_eq!(
        fk_ops.len(),
        1,
        "should emit AddForeignKey for posts.author_id"
    );
}

// ─── Scenario 5: FK already exists — no-op ───────────────────────────────────

#[test]
fn test_fk_already_exists_no_op() {
    let ast_json = r#"{
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
    },
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
        "authorId": {
          "kind": "relation",
          "cardinality": "belongsTo",
          "target": "User",
          "onDelete": "cascade",
          "annotations": {
            "db": {
              "foreignKey": "author_id"
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![
            // Use col_nn for PK — a real DB would never have a nullable PK
            DbTable {
                schema: "public".into(),
                name: "users".into(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col_nn("id", "uuid")],
            },
            DbTable {
                schema: "public".into(),
                name: "posts".into(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col_nn("id", "uuid"), col("author_id", "uuid")],
            },
        ],
        constraints: vec![fk("posts", "author_id", "users")], // already applied
        // These models declare no access rules, so a fully-applied schema now
        // also has RLS enabled on them (deny-all default).
        rls_enabled_tables: vec!["users".into(), "posts".into()],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let fk_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::AddForeignKey { .. }))
        .collect();
    assert!(
        fk_ops.is_empty(),
        "FK already exists — must not emit AddForeignKey (idempotency)"
    );
    assert_eq!(
        diff.operations.len(),
        0,
        "fully-applied schema must produce empty diff"
    );
}

// ─── Scenario 6: drop FK when relation removed ────────────────────────────────

#[test]
fn test_drop_fk_when_relation_removed() {
    // Schema: plain UUID column (relation was removed)
    let ast_json = r#"{
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
        "author_id": {
          "kind": "uuid",
          "required": false,
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
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("author_id", "uuid")],
        }],
        constraints: vec![fk("posts", "author_id", "users")], // stale FK
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let drop_fk: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| {
            matches!(op, Operation::DropForeignKey { constraint, .. }
            if constraint == "posts_author_id_fkey")
        })
        .collect();
    assert_eq!(
        drop_fk.len(),
        1,
        "should drop stale FK when relation removed from schema"
    );
}

// ─── Scenario 7: new table with FK ───────────────────────────────────────────

#[test]
fn test_new_table_added() {
    let ast_json = r#"{
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
    },
    {
      "name": "Profile",
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
        "userId": {
          "kind": "relation",
          "cardinality": "belongsTo",
          "target": "User",
          "onDelete": "cascade",
          "annotations": {
            "db": {
              "foreignKey": "user_id"
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
          "tableName": "profiles",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "users".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let create_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::CreateTable { table, .. } if table == "profiles"))
        .collect();
    assert_eq!(create_ops.len(), 1, "should create profiles table");

    // CreateTable should come before AddForeignKey
    let last_create = diff
        .operations
        .iter()
        .rposition(|op| matches!(op, Operation::CreateTable { .. }));
    let first_fk = diff
        .operations
        .iter()
        .position(|op| matches!(op, Operation::AddForeignKey { .. }));
    if let (Some(lc), Some(ffk)) = (last_create, first_fk) {
        assert!(lc < ffk, "CreateTable must precede AddForeignKey");
    }
}

// ─── Scenario 8: drop table ───────────────────────────────────────────────────

#[test]
fn test_drop_table_when_model_removed() {
    let ast_json = r#"{
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
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![
            DbTable {
                schema: "public".into(),
                name: "users".into(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col("id", "uuid")],
            },
            DbTable {
                schema: "public".into(),
                name: "legacy_sessions".into(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col("id", "uuid")],
            },
        ],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let drop_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::DropTable { table, .. } if table == "legacy_sessions"))
        .collect();
    assert_eq!(drop_ops.len(), 1, "should emit DropTable for removed model");
    assert!(
        diff.summary.is_destructive,
        "dropping a table is destructive"
    );
}

// ─── Scenario 9: junction table idempotency ──────────────────────────────────

#[test]
fn test_junction_table_not_recreated() {
    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Student",
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
        "courses": {
          "kind": "relation",
          "cardinality": "manyToMany",
          "target": "Course",
          "through": "enrollments"
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false
      },
      "annotations": {
        "db": {
          "tableName": "students",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    },
    {
      "name": "Course",
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
          "tableName": "courses",
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
    let db = DatabaseState {
        tables: vec![
            DbTable {
                schema: "public".into(),
                name: "students".into(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col("id", "uuid")],
            },
            DbTable {
                schema: "public".into(),
                name: "courses".into(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col("id", "uuid")],
            },
            DbTable {
                schema: "public".into(),
                name: "enrollments".into(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col("student_id", "uuid"), col("course_id", "uuid")],
            },
        ],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let jt_ops: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::CreateJunctionTable { table, .. } if table == "enrollments"))
        .collect();
    assert!(
        jt_ops.is_empty(),
        "junction table already exists — must not recreate"
    );
}

#[test]
fn test_junction_table_not_dropped_as_orphan() {
    // Junction tables are not models; the removed-table pass must not treat them
    // as orphans when they are present in ast.junction_tables.
    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Student",
      "fields": {
        "id": {
          "kind": "uuid",
          "primaryKey": true,
          "required": true,
          "default": { "kind": "genRandomUuid" },
          "annotations": { "db": { "pgType": "UUID", "unique": false } }
        },
        "courses": {
          "kind": "relation",
          "cardinality": "manyToMany",
          "target": "Course",
          "through": "enrollments"
        }
      },
      "options": { "timestamps": false, "softDelete": false },
      "annotations": {
        "db": { "tableName": "students", "indexes": [] },
        "platform": { "access": {} }
      }
    },
    {
      "name": "Course",
      "fields": {
        "id": {
          "kind": "uuid",
          "primaryKey": true,
          "required": true,
          "default": { "kind": "genRandomUuid" },
          "annotations": { "db": { "pgType": "UUID", "unique": false } }
        }
      },
      "options": { "timestamps": false, "softDelete": false },
      "annotations": {
        "db": { "tableName": "courses", "indexes": [] },
        "platform": { "access": {} }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![
            DbTable {
                schema: "public".into(),
                name: "students".into(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col("id", "uuid")],
            },
            DbTable {
                schema: "public".into(),
                name: "courses".into(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col("id", "uuid")],
            },
            DbTable {
                schema: "public".into(),
                name: "enrollments".into(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col("student_id", "uuid"), col("course_id", "uuid")],
            },
        ],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let drops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::DropTable { table, .. } if table == "enrollments"))
        .collect();
    assert!(
        drops.is_empty(),
        "existing junction must not be dropped as an orphan table: {:?}",
        diff.operations
    );
}

// ─── Scenario 10: timestamps option idempotency ───────────────────────────────

#[test]
fn test_timestamps_option_idempotency() {
    let ast_json = r#"{
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
      "options": {
        "timestamps": true,
        "softDelete": false
      },
      "annotations": {
        "db": {
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![
                col("id", "uuid"),
                col("title", "text"),
                col("created_at", "timestamp with time zone"),
                col("updated_at", "timestamp with time zone"),
            ],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let ts_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| {
            matches!(op, Operation::AddColumn { column, .. }
            if column == "created_at" || column == "updated_at")
        })
        .collect();
    assert!(
        ts_ops.is_empty(),
        "timestamps already exist — must not add them again"
    );
}

// ─── Scenario 11: softDelete option idempotency ───────────────────────────────

#[test]
fn test_soft_delete_option_idempotency() {
    let ast_json = r#"{
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
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": true
      },
      "annotations": {
        "db": {
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![
                col("id", "uuid"),
                col("deleted_at", "timestamp with time zone"),
            ],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::AddColumn { column, .. } if column == "deleted_at"))
        .collect();
    assert!(
        ops.is_empty(),
        "deleted_at already exists — must not add again"
    );
}

// ─── Scenario 12: auto-index on new column ───────────────────────────────────

#[test]
fn test_auto_index_emitted_with_new_indexed_column() {
    let ast_json = r#"{
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
        "authorId": {
          "kind": "uuid",
          "required": true,
          "annotations": {
            "db": {
              "pgType": "UUID",
              "unique": false,
              "index": true
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid")], // authorId not yet present
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let add_col: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::AddColumn { column, .. } if column == "authorId"))
        .collect();
    let add_idx: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::AddIndex { table, .. } if table == "posts"))
        .collect();
    assert_eq!(add_col.len(), 1, "should add authorId column");
    assert_eq!(
        add_idx.len(),
        1,
        "should add btree index for authorId with index:true"
    );
}

// ─── Scenario 13: rollback reverses CreateTable ───────────────────────────────

#[test]
fn test_rollback_reverses_create_table() {
    use supatype_engine::generator::sql::rollback;

    let ast_json = r#"{
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let rollback_sql = rollback::generate(&diff, "public").unwrap();

    assert!(
        rollback_sql.contains("DROP TABLE IF EXISTS"),
        "rollback must drop the created table"
    );
    assert!(
        rollback_sql.contains("BEGIN;"),
        "rollback must be wrapped in transaction"
    );
    assert!(rollback_sql.contains("COMMIT;"), "rollback must commit");
}

// ─── Helpers (extended) ───────────────────────────────────────────────────────

fn col_nn(name: &str, udt: &str) -> DbColumn {
    DbColumn {
        name: name.into(),
        data_type: udt.into(),
        udt_name: udt.into(),
        nullable: false,
        default: None,
        ordinal_position: 0,
    }
}

// ─── Scenario 14: rollback reverses AddForeignKey ────────────────────────────

#[test]
fn test_rollback_reverses_add_fk() {
    use supatype_engine::generator::sql::rollback;

    let ast_json = r#"{
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
    },
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
        "authorId": {
          "kind": "relation",
          "cardinality": "belongsTo",
          "target": "User",
          "onDelete": "cascade",
          "annotations": {
            "db": {
              "foreignKey": "author_id"
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let rollback_sql = rollback::generate(&diff, "public").unwrap();

    assert!(
        rollback_sql.contains("DROP CONSTRAINT"),
        "rollback must drop the FK constraint"
    );
}

// ─── Scenario 15: add_column_not_null_with_default ───────────────────────────

#[test]
fn test_add_column_not_null_with_default() {
    // Adding a NOT NULL column with a DEFAULT is safe — Postgres fills existing rows.
    let ast_json = r#"{
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
        "published": {
          "kind": "boolean",
          "required": true,
          "default": {
            "kind": "value",
            "value": false
          },
          "annotations": {
            "db": {
              "pgType": "BOOLEAN",
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
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let add_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::AddColumn { column, .. } if column == "published"))
        .collect();
    assert_eq!(add_ops.len(), 1, "should add NOT NULL column with default");
    assert!(
        !diff.summary.is_destructive,
        "adding column with default is safe"
    );
}

#[test]
fn test_add_required_richtext_column_backfills_empty_lexical() {
    use supatype_engine::generator::sql::migration;

    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Homepage",
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
        "someField": {
          "kind": "richText",
          "required": true,
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
        "softDelete": false,
        "singleton": true
      },
      "annotations": {
        "db": {
          "tableName": "_global_homepage",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "_global_homepage".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let sql = migration::generate(&diff, true, "public", &ast).unwrap();

    assert!(
        sql.contains("ADD COLUMN \"someField\" JSONB NOT NULL DEFAULT"),
        "must backfill existing rows when adding required JSONB column"
    );
    assert!(
        sql.contains("'type', 'root'"),
        "richText backfill must use empty Lexical document"
    );
    assert!(
        sql.contains("ALTER COLUMN \"someField\" DROP DEFAULT"),
        "must drop transient DEFAULT after backfill"
    );
}

#[test]
fn test_alter_nullable_richtext_to_required_has_preflight_guard() {
    use supatype_engine::generator::sql::migration;

    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Homepage",
      "fields": {
        "id": {
          "kind": "uuid",
          "primaryKey": true,
          "required": true,
          "default": { "kind": "genRandomUuid" },
          "annotations": { "db": { "pgType": "UUID", "unique": false } }
        },
        "someField": {
          "kind": "richText",
          "required": true,
          "annotations": {
            "db": { "pgType": "JSONB", "unique": false },
            "platform": { "editor": "rich" }
          }
        }
      },
      "options": { "timestamps": false, "softDelete": false, "singleton": true },
      "annotations": {
        "db": { "tableName": "_global_homepage", "indexes": [] },
        "platform": { "access": {} }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "_global_homepage".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("someField", "jsonb")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let sql = migration::generate(&diff, true, "public", &ast).unwrap();

    assert!(
        sql.contains("RAISE EXCEPTION"),
        "must guard against NULL rows before SET NOT NULL"
    );
    assert!(
        sql.contains("ALTER COLUMN \"someField\" SET NOT NULL"),
        "must tighten nullability after preflight guard"
    );
}

#[test]
fn test_add_required_richtext_column_with_string_default() {
    use supatype_engine::generator::sql::migration;

    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Homepage",
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
        "someField": {
          "kind": "richText",
          "required": true,
          "default": {
            "kind": "value",
            "value": "Welcome to Elmside."
          },
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
        "softDelete": false,
        "singleton": true
      },
      "annotations": {
        "db": {
          "tableName": "_global_homepage",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "_global_homepage".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let sql = migration::generate(&diff, true, "public", &ast).unwrap();

    assert!(
        sql.contains("ADD COLUMN \"someField\" JSONB NOT NULL DEFAULT"),
        "required RichText with schema default must emit DEFAULT on ADD COLUMN"
    );
    assert!(
        sql.contains("'text', 'Welcome to Elmside.'"),
        "plain string default must become Lexical paragraph text, not raw TEXT default"
    );
    assert!(
        !sql.contains("DROP DEFAULT"),
        "persistent schema default must not be dropped after backfill"
    );
}

#[test]
fn test_richtext_lexical_object_default_sql() {
    use supatype_engine::generator::sql::column_conversion::rich_text_default_sql;
    use supatype_engine::parser::ast::DefaultValueAst;

    let lexical = serde_json::json!({
        "root": {
            "type": "root",
            "version": 1,
            "children": []
        }
    });
    let sql = rich_text_default_sql(&DefaultValueAst::Value { value: lexical }).unwrap();
    assert!(sql.ends_with("::jsonb"));
    assert!(sql.contains("\"root\""));
}

// ─── Scenario 16: change_column_type_safe ────────────────────────────────────

#[test]
fn test_change_column_type_safe_widening() {
    // Widening int2 → BIGINT is a safe AlterColumn.
    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Counter",
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
        "value": {
          "kind": "bigInt",
          "required": false,
          "annotations": {
            "db": {
              "pgType": "BIGINT",
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
          "tableName": "counters",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "counters".into(),
            comment: Some("supatype:managed;kind=table".into()),
            // DB has value as SMALLINT (int2); id is PK so NOT NULL
            columns: vec![col_nn("id", "uuid"), col("value", "int2")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let alter_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::AlterColumn { column, .. } if column == "value"))
        .collect();
    assert_eq!(
        alter_ops.len(),
        1,
        "should emit AlterColumn for type widening"
    );

    // Safe widening must not be destructive
    assert!(
        !diff.summary.is_destructive,
        "safe type widening must not be destructive"
    );
}

// ─── Scenario 17: change_column_type_lossy ───────────────────────────────────

#[test]
fn test_change_column_type_lossy() {
    // Narrowing bigint → integer is a cautious type change (may lose data).
    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Counter",
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
        "value": {
          "kind": "integer",
          "required": false,
          "annotations": {
            "db": {
              "pgType": "INTEGER",
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
          "tableName": "counters",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "counters".into(),
            comment: Some("supatype:managed;kind=table".into()),
            // DB has value as BIGINT (int8) — narrowing to int4; id is PK so NOT NULL
            columns: vec![col_nn("id", "uuid"), col("value", "int8")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let alter_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::AlterColumn { column, .. } if column == "value"))
        .collect();
    assert_eq!(
        alter_ops.len(),
        1,
        "should emit AlterColumn for lossy type change"
    );
    assert_eq!(
        diff.summary.cautious, 1,
        "lossy type change must be classified cautious"
    );
}

// ─── Scenario 18: add_not_null to existing column ────────────────────────────

#[test]
fn test_add_not_null_to_existing_nullable_column() {
    // Making an existing nullable column NOT NULL is cautious (pre-flight guard needed).
    let ast_json = r#"{
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            // id is PK (NOT NULL); title is currently nullable
            columns: vec![col_nn("id", "uuid"), col("title", "text")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let alter_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| {
            matches!(op, Operation::AlterColumn { column, changes, .. }
            if column == "title" && changes.get("nullability").is_some())
        })
        .collect();
    assert_eq!(
        alter_ops.len(),
        1,
        "should emit AlterColumn for NULL → NOT NULL change"
    );
    assert_eq!(diff.summary.cautious, 1, "NULL → NOT NULL must be cautious");
}

// ─── Scenario 19: drop_not_null from existing column ─────────────────────────

#[test]
fn test_drop_not_null_from_existing_column() {
    // Making an existing NOT NULL column nullable is safe.
    let ast_json = r#"{
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
        "title": {
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            // id is PK (NOT NULL); title is NOT NULL in DB, schema wants nullable
            columns: vec![col_nn("id", "uuid"), col_nn("title", "text")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let alter_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| {
            matches!(op, Operation::AlterColumn { column, changes, .. }
            if column == "title" && changes.get("nullability").is_some())
        })
        .collect();
    assert_eq!(
        alter_ops.len(),
        1,
        "should emit AlterColumn to drop NOT NULL"
    );
    // Dropping NOT NULL is safe
    assert!(!diff.summary.is_destructive, "dropping NOT NULL is safe");
    assert_eq!(
        diff.summary.cautious, 0,
        "dropping NOT NULL must not be cautious"
    );
}

// ─── Scenario 20: alter_column SQL includes pre-flight NULL guard ─────────────

#[test]
fn test_alter_column_not_null_sql_has_preflight_guard() {
    use supatype_engine::generator::sql::migration;

    // Schema wants title to be NOT NULL
    let ast_json = r#"{
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            // id is PK (NOT NULL); title is nullable → schema wants NOT NULL
            columns: vec![col_nn("id", "uuid"), col("title", "text")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    // Use force=true so the cautious op passes the guard in migration::generate
    let sql = migration::generate(&diff, true, "public", &ast).unwrap();

    assert!(
        sql.contains("RAISE EXCEPTION"),
        "SQL must include pre-flight NULL check guard"
    );
    assert!(
        sql.contains("SET NOT NULL"),
        "SQL must contain SET NOT NULL"
    );
}

// ─── Scenario 21: alter_column rollback reverses nullability ──────────────────

#[test]
fn test_alter_column_rollback_reverses_nullability() {
    use supatype_engine::generator::sql::rollback;

    let ast_json = r#"{
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            // id is PK (NOT NULL); title is nullable → schema wants NOT NULL → rollback drops NOT NULL
            columns: vec![col_nn("id", "uuid"), col("title", "text")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let rollback_sql = rollback::generate(&diff, "public").unwrap();

    // Rollback of NOT NULL should emit DROP NOT NULL
    assert!(
        rollback_sql.contains("DROP NOT NULL"),
        "rollback must restore nullable state"
    );
}

// ─── Scenario 22: fresh model with access.authenticated ──────────────────────

#[test]
fn test_rls_fresh_model_authenticated() {
    // A brand-new model with read access.authenticated → EnableRls + CreateRlsPolicy
    let ast_json = r#"{
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
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    let enable_rls = diff
        .operations
        .iter()
        .any(|op| matches!(op, Operation::EnableRls { table, .. } if table == "posts"));
    assert!(enable_rls, "should emit EnableRls for posts");

    let create_policy = diff.operations.iter().any(|op| {
        matches!(op, Operation::CreateRlsPolicy { table, policy, .. }
            if table == "posts" && policy == "posts_select")
    });
    assert!(
        create_policy,
        "should emit CreateRlsPolicy for posts_select"
    );

    assert!(!diff.summary.is_destructive, "RLS enable is safe");
}

// ─── Scenario 23: access.any([owner, role]) OR expression ────────────────────

#[test]
fn test_rls_any_rule_generates_or_expression() {
    use supatype_engine::generator::sql::rls::access_rule_to_expr;
    use supatype_engine::parser::ast::AccessRule;

    // access.any([owner("user_id"), role(["admin"])]) should produce an OR-joined expression.
    let rule = AccessRule::Any {
        rules: vec![
            AccessRule::Owner {
                field: "user_id".to_string(),
            },
            AccessRule::Role {
                roles: vec!["admin".to_string()],
            },
        ],
    };

    let model = supatype_engine::parser::ast::ModelAst {
        name: "Test".to_string(),
        fields: indexmap::IndexMap::new(),
        options: Default::default(),
        annotations: Default::default(),
    };
    let ast = supatype_engine::parser::ast::SchemaAst {
        ast_version: 2,
        models: vec![model.clone()],
        junction_tables: vec![],
        storage_buckets: vec![],
        locales: vec![],
        default_locale: None,
        plugins: vec![],
        sso: None,
        warnings: vec![],
    };
    let expr = access_rule_to_expr(&ast, &model, &rule, "public");
    assert!(expr.contains("OR"), "any() rule must produce OR expression");
    assert!(
        expr.contains("auth.uid()"),
        "owner clause must reference auth.uid()"
    );
    assert!(
        expr.contains("auth.role()"),
        "role clause must reference auth.role()"
    );
    assert!(expr.contains("admin"), "role clause must include role name");
}

// ─── Scenario 24: access rule changed → drop + recreate policy ───────────────

#[test]
fn test_rls_changed_expression_triggers_recreate() {
    // DB has posts_select with expression for 'public'; schema now says 'authenticated'.
    // Differ emits CreateRlsPolicy only (idempotent DROP IF EXISTS + CREATE in SQL).
    let ast_json = r#"{
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
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid")],
        }],
        rls_policies: vec![DbRlsPolicy {
            table: "posts".into(),
            name: "posts_select".into(),
            command: "r".into(),
            permissive: true,
            // Old expression: true (public access)
            using_expr: Some("true".into()),
            check_expr: None,
            managed: true,
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    let drop_policy = diff.operations.iter().any(
        |op| matches!(op, Operation::DropRlsPolicy { policy, .. } if policy == "posts_select"),
    );
    assert!(
        !drop_policy,
        "must not emit separate DropRlsPolicy — CreateRlsPolicy SQL is idempotent"
    );

    let create_policy = diff.operations.iter().any(
        |op| matches!(op, Operation::CreateRlsPolicy { policy, .. } if policy == "posts_select"),
    );
    assert!(
        create_policy,
        "should emit CreateRlsPolicy when expression changed"
    );
}

// ─── Scenario 25: model loses access rules → all policies dropped + warning ───

#[test]
fn test_rls_removed_access_rules_drops_policies_and_warns() {
    // Schema no longer has access rules; DB has existing policy.
    // Differ must drop all policies and emit a warning.
    let ast_json = r#"{
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid")],
        }],
        rls_policies: vec![DbRlsPolicy {
            table: "posts".into(),
            name: "posts_select".into(),
            command: "r".into(),
            permissive: true,
            using_expr: Some("auth.uid() IS NOT NULL".into()),
            check_expr: None,
            managed: true,
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    let drop_policy = diff.operations.iter().any(
        |op| matches!(op, Operation::DropRlsPolicy { policy, .. } if policy == "posts_select"),
    );
    assert!(
        drop_policy,
        "should drop orphaned policy when access rules removed"
    );

    assert!(
        !diff.warnings.is_empty(),
        "should emit warning when RLS policies removed"
    );
    assert!(
        diff.warnings.iter().any(|w| w.contains("posts")),
        "warning must mention the affected table"
    );
}

// ─── Scenario 26: RLS generator output — FORCE RLS + correct naming ───────────

#[test]
fn test_rls_generator_output_force_rls_and_policy_naming() {
    use supatype_engine::generator::sql::rls;

    let ast_json = r#"{
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
          "access": {
            "read": {
              "type": "authenticated"
            },
            "create": {
              "type": "authenticated"
            },
            "update": {
              "type": "authenticated"
            },
            "delete": {
              "type": "authenticated"
            }
          }
        }
      }
    },
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
        "userId": {
          "kind": "relation",
          "cardinality": "belongsTo",
          "target": "User",
          "onDelete": "cascade",
          "annotations": {
            "db": {
              "foreignKey": "user_id"
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
            },
            "create": {
              "type": "authenticated"
            },
            "update": {
              "type": "owner",
              "field": "userId"
            },
            "delete": {
              "type": "owner",
              "field": "userId"
            }
          }
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let sql = rls::generate(&ast, "public").unwrap();

    assert!(sql.contains("ENABLE ROW LEVEL SECURITY"), "must enable RLS");
    assert!(sql.contains("FORCE ROW LEVEL SECURITY"), "must force RLS");

    // Policy naming: {table}_{operation}, no _policy suffix
    assert!(
        sql.contains("\"posts_select\""),
        "select policy must be named posts_select"
    );
    assert!(
        sql.contains("\"posts_insert\""),
        "insert policy must be named posts_insert"
    );
    assert!(
        sql.contains("\"posts_update\""),
        "update policy must be named posts_update"
    );
    assert!(
        sql.contains("\"posts_delete\""),
        "delete policy must be named posts_delete"
    );

    // INSERT uses WITH CHECK, not USING
    assert!(sql.contains("FOR INSERT"), "must have INSERT policy");
    assert!(
        sql.contains("WITH CHECK"),
        "INSERT policy must use WITH CHECK"
    );

    // UPDATE uses both USING and WITH CHECK
    assert!(sql.contains("FOR UPDATE"), "must have UPDATE policy");
}

// ─── Scenario 27: image field → resolver infers storage bucket ────────────────

#[test]
fn test_storage_resolver_infers_bucket_from_image_field() {
    // An image field with bucket "posts_avatar" should produce one StorageBucketAst.
    let ast_json = r#"{
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
        "avatar": {
          "kind": "image",
          "required": false,
          "bucket": "posts_avatar",
          "annotations": {
            "db": {
              "pgType": "JSONB"
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    assert_eq!(
        ast.storage_buckets.len(),
        1,
        "should infer one storage bucket"
    );
    assert_eq!(
        ast.storage_buckets[0].id, "posts_avatar",
        "bucket id must match field declaration"
    );
}

// ─── Scenario 28: storage generator emits schema DDL + bucket upsert ─────────

#[test]
fn test_storage_generator_emits_ddl_and_bucket_upsert() {
    use supatype_engine::generator::sql::storage;

    let ast_json = r#"{
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
        "avatar": {
          "kind": "image",
          "required": false,
          "bucket": "posts_avatar",
          "annotations": {
            "db": {
              "pgType": "JSONB"
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let sql = storage::generate(&ast).unwrap();

    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS storage.buckets"),
        "must create storage.buckets"
    );
    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS storage.objects"),
        "must create storage.objects"
    );
    assert!(sql.contains("posts_avatar"), "must upsert the bucket by id");
    assert!(
        sql.contains("ON CONFLICT (id) DO UPDATE"),
        "upsert must handle existing bucket"
    );
}

// ─── Scenario 29: storage RLS inherits model read access rule ────────────────

#[test]
fn test_storage_rls_inherits_model_read_access_rule() {
    use supatype_engine::generator::sql::storage;

    let ast_json = r#"{
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
        "avatar": {
          "kind": "image",
          "required": false,
          "bucket": "posts_avatar",
          "annotations": {
            "db": {
              "pgType": "JSONB"
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
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let sql = storage::generate(&ast).unwrap();

    assert!(
        sql.contains("ENABLE ROW LEVEL SECURITY"),
        "must enable RLS on storage.objects"
    );
    assert!(
        sql.contains("auth.uid() IS NOT NULL"),
        "select policy must inherit authenticated rule"
    );
    assert!(
        sql.contains("posts_avatar_sel"),
        "select policy must be named table_bucket_sel"
    );
    assert!(
        sql.contains("posts_avatar_ins"),
        "insert policy must be named table_bucket_ins"
    );
    assert!(
        sql.contains("posts_avatar_del"),
        "delete policy must be named table_bucket_del"
    );
}

// ─── Scenario 30: two fields with same bucket name → deduplicated ─────────────

#[test]
fn test_storage_resolver_deduplicates_same_bucket() {
    // Two image fields pointing to the same bucket should produce only one StorageBucketAst.
    let ast_json = r#"{
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
        "cover": {
          "kind": "image",
          "required": false,
          "bucket": "posts_images",
          "annotations": {
            "db": {
              "pgType": "JSONB"
            }
          }
        },
        "thumb": {
          "kind": "image",
          "required": false,
          "bucket": "posts_images",
          "annotations": {
            "db": {
              "pgType": "JSONB"
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
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    assert_eq!(
        ast.storage_buckets.len(),
        1,
        "duplicate bucket name must be deduplicated to one entry"
    );
    assert_eq!(ast.storage_buckets[0].id, "posts_images");
}

// ─── Scenario 31: singleton model appears in globals, not models ──────────────

#[test]
fn test_admin_singleton_in_globals() {
    let ast_json = r#"{
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
        "title": {
          "kind": "text",
          "required": true,
          "localized": false,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "posts",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    },
    {
      "name": "SiteSettings",
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
        "siteName": {
          "kind": "text",
          "required": true,
          "localized": false,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": true
      },
      "annotations": {
        "db": {
          "tableName": "site_settings",
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
    let config = admin::generate(&ast).unwrap();

    let models = config["models"].as_array().unwrap();
    let globals = config["globals"].as_array().unwrap();

    assert_eq!(models.len(), 1, "only non-singleton models in models array");
    assert_eq!(models[0]["name"], "Post");

    assert_eq!(globals.len(), 1, "singleton model appears in globals array");
    assert_eq!(globals[0]["name"], "SiteSettings");
    assert_eq!(globals[0]["singleton"], true);
}

// ─── Scenario 32: enum field has widget "select" and enumValues ───────────────

#[test]
fn test_admin_enum_field_widget() {
    let ast_json = r#"{
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
        "status": {
          "kind": "enum",
          "required": true,
          "values": [
            "draft",
            "published",
            "archived"
          ],
          "localized": false,
          "annotations": {
            "db": {
              "pgType": "ENUM",
              "unique": false
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "posts",
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
    let config = admin::generate(&ast).unwrap();

    let fields = config["models"][0]["fields"].as_array().unwrap();
    let status_field = fields.iter().find(|f| f["name"] == "status").unwrap();

    assert_eq!(
        status_field["widget"], "select",
        "enum fields must use select widget"
    );
    let enum_values = status_field["options"]["values"].as_array().unwrap();
    assert_eq!(enum_values.len(), 3);
    assert!(enum_values.iter().any(|v| v == "draft"));
    assert!(enum_values.iter().any(|v| v == "published"));
}

// ─── Scenario 33: belongsTo relation has widget "relationPicker" with target ──

#[test]
fn test_admin_belongs_to_relation_picker() {
    let ast_json = r#"{
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
        "softDelete": false,
        "singleton": false
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
    },
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
        "author": {
          "kind": "relation",
          "cardinality": "belongsTo",
          "target": "User",
          "onDelete": "RESTRICT",
          "annotations": {
            "db": {
              "foreignKey": "author_id"
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "posts",
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
    let config = admin::generate(&ast).unwrap();

    let post_model = config["models"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == "Post")
        .unwrap();
    let fields = post_model["fields"].as_array().unwrap();
    let author_field = fields.iter().find(|f| f["name"] == "author_id").unwrap();

    assert_eq!(author_field["widget"], "relation");
    assert_eq!(author_field["options"]["target"], "users");
    assert_eq!(author_field["options"]["cardinality"], "belongsTo");
    assert_eq!(author_field["options"]["foreignKey"], "author_id");
    assert_eq!(
        author_field["showInList"], true,
        "belongsTo should show in list"
    );
}

// ─── Scenario 34: navigation has Content group with non-singleton models ──────

#[test]
fn test_admin_navigation_content_group() {
    let ast_json = r#"{
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
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "posts",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    },
    {
      "name": "Category",
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
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "categories",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    },
    {
      "name": "Config",
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
        "softDelete": false,
        "singleton": true
      },
      "annotations": {
        "db": {
          "tableName": "config",
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
    let config = admin::generate(&ast).unwrap();

    let nav = config["navigation"].as_array().unwrap();
    let content_group = nav.iter().find(|g| g["group"] == "Content").unwrap();
    let settings_group = nav.iter().find(|g| g["group"] == "Settings").unwrap();

    let content_items = content_group["items"].as_array().unwrap();
    assert_eq!(
        content_items.len(),
        2,
        "Content group has both non-singleton models"
    );
    assert!(content_items.iter().any(|i| i["model"] == "posts"));
    assert!(content_items.iter().any(|i| i["model"] == "categories"));

    let settings_items = settings_group["items"].as_array().unwrap();
    assert_eq!(settings_items.len(), 1);
    assert_eq!(settings_items[0]["global"], "config");
}

// ─── Scenario 35: localized field appears with localized:true in admin config ─

#[test]
fn test_admin_localized_field_in_config() {
    let ast_json = r#"{
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
        "title": {
          "kind": "text",
          "required": true,
          "localized": true,
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
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "posts",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ],
  "locales": [
    "en",
    "fr"
  ],
  "defaultLocale": "en"
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let config = admin::generate(&ast).unwrap();

    // Localization config should reflect schema locales
    assert_eq!(config["localization"]["defaultLocale"], "en");
    let locales = config["localization"]["locales"].as_array().unwrap();
    assert!(locales.iter().any(|l| l == "en"));
    assert!(locales.iter().any(|l| l == "fr"));

    let fields = config["models"][0]["fields"].as_array().unwrap();
    let title_field = fields.iter().find(|f| f["name"] == "title").unwrap();
    assert_eq!(
        title_field["localized"], true,
        "localized field must have localized:true in config"
    );
    assert_eq!(title_field["defaultLocale"], "en");
}

// ─── Scenario 36: blocks field has widget "blocks" with definitions ──────

#[test]
fn test_admin_blocks_field_widget() {
    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Page",
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
        "content": {
          "kind": "blocks",
          "required": false,
          "blocks": [
            {
              "name": "hero",
              "label": "Hero Banner",
              "icon": null,
              "fields": {
                "heading": {
                  "kind": "text",
                  "pgType": "TEXT",
                  "required": true,
                  "unique": false,
                  "localized": false
                },
                "subheading": {
                  "kind": "text",
                  "pgType": "TEXT",
                  "required": false,
                  "unique": false,
                  "localized": false
                }
              }
            },
            {
              "name": "richtext",
              "label": null,
              "icon": null,
              "fields": {
                "body": {
                  "kind": "richText",
                  "pgType": "JSONB",
                  "required": true,
                  "unique": false,
                  "localized": false
                }
              }
            }
          ],
          "annotations": {
            "db": {
              "index": true
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "pages",
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
    let config = admin::generate(&ast).unwrap();

    let fields = config["models"][0]["fields"].as_array().unwrap();
    let content_field = fields.iter().find(|f| f["name"] == "content").unwrap();

    assert_eq!(content_field["widget"], "blocks");
    assert_eq!(content_field["showInList"], false);

    let blocks = content_field["options"]["blockTypes"].as_array().unwrap();
    assert_eq!(blocks.len(), 2, "two block definitions");

    let hero = blocks.iter().find(|b| b["name"] == "hero").unwrap();
    assert_eq!(hero["label"], "Hero Banner");
    let hero_fields = hero["fields"].as_array().unwrap();
    assert!(hero_fields.iter().any(|f| f["name"] == "heading"));

    let richtext = blocks.iter().find(|b| b["name"] == "richtext").unwrap();
    let rt_fields = richtext["fields"].as_array().unwrap();
    assert!(rt_fields.iter().any(|f| f["widget"] == "richtext"));
}

// ─── Scenario 37: studio metadata basic model ────────────────────────────────

#[test]
fn test_studio_metadata_basic_model() {
    use supatype_engine::generator::studio;

    let ast_json = r#"{
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
        "title": {
          "kind": "text",
          "required": true,
          "localized": false,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "posts",
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
    let meta = studio::generate(&ast).unwrap();

    assert_eq!(meta["version"], 1);

    let models = meta["models"].as_array().unwrap();
    assert_eq!(models.len(), 1);
    assert_eq!(models[0]["name"], "Post");
    assert_eq!(models[0]["tableName"], "posts");
    assert_eq!(models[0]["singleton"], false);

    let fields = models[0]["fields"].as_array().unwrap();
    let id_field = fields.iter().find(|f| f["name"] == "id").unwrap();
    assert_eq!(id_field["kind"], "uuid");
    assert_eq!(id_field["primaryKey"], true);
    assert_eq!(id_field["required"], true);
}

// ─── Scenario 38: studio metadata stats ──────────────────────────────────────

#[test]
fn test_studio_metadata_stats() {
    use supatype_engine::generator::studio;

    let ast_json = r#"{
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
        "title": {
          "kind": "text",
          "required": true,
          "localized": false,
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
          "uniqueFk": false
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "posts",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    },
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
        },
        "email": {
          "kind": "email",
          "required": true,
          "localized": false,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": true
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
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
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let meta = studio::generate(&ast).unwrap();

    let stats = &meta["stats"];
    assert_eq!(stats["modelCount"], 2, "two models");
    assert_eq!(
        stats["fieldCount"], 5,
        "total field count across all models"
    );
    assert_eq!(stats["relationCount"], 1, "one relation field");
    assert_eq!(stats["junctionTableCount"], 0);
    assert_eq!(stats["bucketCount"], 0);
}

// ─── Scenario 39: studio metadata relation field ──────────────────────────────

#[test]
fn test_studio_metadata_relation_field() {
    use supatype_engine::generator::studio;

    let ast_json = r#"{
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
        "softDelete": false,
        "singleton": false
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
    },
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
        "author": {
          "kind": "relation",
          "cardinality": "belongsTo",
          "target": "User",
          "uniqueFk": false
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "posts",
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
    let meta = studio::generate(&ast).unwrap();

    let post_model = meta["models"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == "Post")
        .unwrap();
    let fields = post_model["fields"].as_array().unwrap();
    let author = fields.iter().find(|f| f["name"] == "author").unwrap();

    assert_eq!(author["kind"], "relation");
    assert_eq!(author["cardinality"], "belongsTo");
    assert_eq!(author["target"], "User");
}

// ─── Scenario 40: OpenAPI paths for basic model ───────────────────────────────

#[test]
fn test_openapi_paths_for_model() {
    use supatype_engine::generator::openapi;

    let ast_json = r#"{
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
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "posts",
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
    let spec = openapi::generate(&ast).unwrap();

    assert_eq!(spec["openapi"], "3.0.0");

    let paths = spec["paths"].as_object().unwrap();
    assert!(
        paths.contains_key("/posts"),
        "collection path /posts must exist"
    );
    assert!(
        paths.contains_key("/posts/{id}"),
        "item path /posts/{{id}} must exist"
    );

    let collection = &spec["paths"]["/posts"];
    assert!(collection["get"].is_object(), "GET /posts must exist");
    assert!(collection["post"].is_object(), "POST /posts must exist");

    let item = &spec["paths"]["/posts/{id}"];
    assert!(item["get"].is_object(), "GET /posts/{{id}} must exist");
    assert!(item["patch"].is_object(), "PATCH /posts/{{id}} must exist");
    assert!(
        item["delete"].is_object(),
        "DELETE /posts/{{id}} must exist"
    );
}

// ─── Scenario 41: OpenAPI schema field type mapping ──────────────────────────

#[test]
fn test_openapi_schema_field_types() {
    use supatype_engine::generator::openapi;

    let ast_json = r#"{
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
        "title": {
          "kind": "text",
          "required": true,
          "localized": false,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false
            }
          }
        },
        "views": {
          "kind": "integer",
          "required": false,
          "localized": false,
          "annotations": {
            "db": {
              "pgType": "INTEGER",
              "unique": false
            }
          }
        },
        "active": {
          "kind": "boolean",
          "required": false,
          "localized": false,
          "annotations": {
            "db": {
              "pgType": "BOOLEAN",
              "unique": false
            }
          }
        },
        "createdAt": {
          "kind": "datetime",
          "required": false,
          "localized": false,
          "annotations": {
            "db": {
              "pgType": "TIMESTAMPTZ",
              "unique": false
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "posts",
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
    let spec = openapi::generate(&ast).unwrap();

    let schema_props = &spec["components"]["schemas"]["Post"]["properties"];

    assert_eq!(schema_props["id"]["type"], "string");
    assert_eq!(schema_props["id"]["format"], "uuid");

    assert_eq!(schema_props["title"]["type"], "string");

    assert_eq!(schema_props["views"]["type"], "integer");
    assert_eq!(schema_props["views"]["format"], "int32");

    assert_eq!(schema_props["active"]["type"], "boolean");

    assert_eq!(schema_props["createdAt"]["type"], "string");
    assert_eq!(schema_props["createdAt"]["format"], "date-time");
}

// ─── Scenario 42: OpenAPI schema enum field ───────────────────────────────────

#[test]
fn test_openapi_schema_enum_field() {
    use supatype_engine::generator::openapi;

    let ast_json = r#"{
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
        "status": {
          "kind": "enum",
          "required": true,
          "values": [
            "draft",
            "published",
            "archived"
          ],
          "localized": false,
          "annotations": {
            "db": {
              "pgType": "ENUM",
              "unique": false
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "posts",
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
    let spec = openapi::generate(&ast).unwrap();

    let schema_props = &spec["components"]["schemas"]["Post"]["properties"];

    assert_eq!(
        schema_props["status"]["type"], "string",
        "enum field must be type string"
    );

    let enum_values = schema_props["status"]["enum"].as_array().unwrap();
    assert_eq!(enum_values.len(), 3);
    assert!(enum_values.iter().any(|v| v == "draft"));
    assert!(enum_values.iter().any(|v| v == "published"));
    assert!(enum_values.iter().any(|v| v == "archived"));

    // status is required → must appear in required array
    let required = spec["components"]["schemas"]["Post"]["required"]
        .as_array()
        .unwrap();
    assert!(
        required.iter().any(|r| r == "status"),
        "required enum field must be in required array"
    );
}

// ─── Scenario 43: custom field type uses declared pgType in SQL migration ─────

#[test]
fn test_plugin_custom_field_sql() {
    use supatype_engine::generator::sql::migration;

    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Contact",
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
        "phone": {
          "kind": "custom",
          "plugin": "@supatype/plugin-phone-field",
          "fieldType": "phone",
          "tsType": "string",
          "required": true,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false,
              "index": false
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "contacts",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ],
  "plugins": [
    {
      "name": "@supatype/plugin-phone-field",
      "version": "1.0.0",
      "pluginApi": 1,
      "pluginType": "fieldType"
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        ..DatabaseState::default()
    };
    let diff = differ::diff(&ast, &db).unwrap();

    let create_op = diff
        .operations
        .iter()
        .find(|op| matches!(op, Operation::CreateTable { table, .. } if table == "contacts"));
    assert!(
        create_op.is_some(),
        "CreateTable for contacts must be emitted"
    );

    let sql = migration::generate(&diff, false, "public", &ast).unwrap();
    // Custom field uses declared pgType (TEXT), not a built-in name
    assert!(
        sql.contains("\"phone\" TEXT NOT NULL"),
        "custom field must render with declared pgType"
    );
}

// ─── Scenario 44: custom field type uses declared tsType in TypeScript gen ────

#[test]
fn test_plugin_custom_field_typescript() {
    use supatype_engine::generator::typescript::types;

    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Contact",
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
        "phone": {
          "kind": "custom",
          "plugin": "@supatype/plugin-phone-field",
          "fieldType": "phone",
          "tsType": "PhoneNumber",
          "required": true,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false,
              "index": false
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "contacts",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ],
  "plugins": [
    {
      "name": "@supatype/plugin-phone-field",
      "version": "1.0.0",
      "pluginApi": 1,
      "pluginType": "fieldType"
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let ts = types::generate(&ast).unwrap();

    assert!(
        ts.contains("phone: PhoneNumber"),
        "custom field must use declared tsType in generated TypeScript"
    );
}

// ─── Scenario 45: plugin with incompatible pluginApi emits warning ────────────

#[test]
fn test_plugin_version_mismatch_warning() {
    use supatype_engine::parser::resolver::SUPPORTED_PLUGIN_API;

    let api_version = SUPPORTED_PLUGIN_API + 1; // intentionally wrong
    let ast_json = format!(
        r#"{{
        "astVersion": 2,
        "models": [],
        "plugins": [
            {{ "name": "@community/supatype-paddle", "version": "2.0.0", "pluginApi": {api_version}, "pluginType": "provider" }}
        ]
    }}"#
    );

    let ast = parser::parse(&ast_json).unwrap();

    assert!(
        !ast.warnings.is_empty(),
        "incompatible pluginApi must produce a warning"
    );
    assert!(
        ast.warnings
            .iter()
            .any(|w| w.contains("@community/supatype-paddle")),
        "warning must reference the plugin name"
    );
    assert!(
        ast.warnings
            .iter()
            .any(|w| w.contains(&api_version.to_string())),
        "warning must include the declared incompatible version"
    );
}

// ─── Scenario 46: compatible plugin produces no version warning ───────────────

#[test]
fn test_plugin_compatible_version_no_warning() {
    let ast_json = r#"{
  "astVersion": 2,
  "models": [],
  "plugins": [
    {
      "name": "@supatype/plugin-phone-field",
      "version": "1.0.0",
      "pluginApi": 1,
      "pluginType": "fieldType"
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();

    let version_warnings: Vec<_> = ast
        .warnings
        .iter()
        .filter(|w| w.contains("pluginApi"))
        .collect();
    assert!(
        version_warnings.is_empty(),
        "compatible plugin must not produce version warnings"
    );
}

// ─── Scenario 47: custom field diff emits AddColumn with correct pgType ───────

#[test]
fn test_plugin_custom_field_diff() {
    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Contact",
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
        "phone": {
          "kind": "custom",
          "plugin": "@supatype/plugin-phone-field",
          "fieldType": "phone",
          "tsType": "string",
          "required": false,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false,
              "index": false
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "contacts",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ],
  "plugins": [
    {
      "name": "@supatype/plugin-phone-field",
      "version": "1.0.0",
      "pluginApi": 1,
      "pluginType": "fieldType"
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "contacts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    let add_phone = diff
        .operations
        .iter()
        .find(|op| matches!(op, Operation::AddColumn { column, .. } if column == "phone"));
    assert!(
        add_phone.is_some(),
        "should emit AddColumn for custom phone field"
    );
    assert!(!diff.summary.is_destructive, "adding custom field is safe");
}

// ─── Scenario 48: custom field in studio metadata has kind=custom ─────────────

#[test]
fn test_plugin_custom_field_studio_metadata() {
    use supatype_engine::generator::studio;

    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Contact",
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
        "phone": {
          "kind": "custom",
          "plugin": "@supatype/plugin-phone-field",
          "fieldType": "phone",
          "tsType": "PhoneNumber",
          "required": false,
          "annotations": {
            "db": {
              "pgType": "TEXT",
              "unique": false,
              "index": false
            }
          }
        }
      },
      "options": {
        "timestamps": false,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "contacts",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ],
  "plugins": [
    {
      "name": "@supatype/plugin-phone-field",
      "version": "1.0.0",
      "pluginApi": 1,
      "pluginType": "fieldType"
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let meta = studio::generate(&ast).unwrap();

    let fields = meta["models"][0]["fields"].as_array().unwrap();
    let phone_field = fields.iter().find(|f| f["name"] == "phone").unwrap();

    assert_eq!(phone_field["kind"], "custom");
    assert_eq!(phone_field["fieldType"], "phone");
    assert_eq!(phone_field["plugin"], "@supatype/plugin-phone-field");
    assert_eq!(phone_field["pgType"], "TEXT");
    assert_eq!(phone_field["tsType"], "PhoneNumber");
}

// ─── Phase 10: Multi-Language SDK & WASM ─────────────────────────────────────

fn simple_post_ast() -> &'static str {
    r#"{
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
        "score": {
          "kind": "integer",
          "required": false,
          "annotations": {
            "db": {
              "pgType": "INTEGER",
              "unique": false
            }
          }
        },
        "active": {
          "kind": "boolean",
          "required": true,
          "annotations": {
            "db": {
              "pgType": "BOOLEAN",
              "unique": false
            }
          }
        },
        "_timestamps": {
          "kind": "timestamps"
        }
      },
      "options": {
        "timestamps": true,
        "softDelete": false,
        "singleton": false
      },
      "annotations": {
        "db": {
          "tableName": "posts",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#
}

// ─── Scenario 49: Python @dataclass with correct type annotations ─────────────

#[test]
fn test_sdk_python_dataclass() {
    use supatype_engine::generator::sdk;

    let ast = parser::parse(simple_post_ast()).unwrap();
    let out = sdk::generate(&ast, "python").unwrap();

    assert!(
        out.contains("@dataclass"),
        "Python output must use @dataclass decorator"
    );
    assert!(
        out.contains("class Post:"),
        "Python output must define class Post"
    );
    assert!(
        out.contains("from dataclasses import dataclass"),
        "Python output must import dataclass"
    );
    assert!(
        out.contains(": str"),
        "required text field must use str type"
    );
    assert!(
        out.contains(": bool"),
        "required boolean field must use bool type"
    );
    assert!(
        out.contains("Optional[int]"),
        "optional integer field must use Optional[int]"
    );
    assert!(
        out.contains("Optional[datetime]"),
        "timestamp composite must emit Optional[datetime] fields"
    );
}

// ─── Scenario 50: Go struct with json tags ────────────────────────────────────

#[test]
fn test_sdk_go_struct_json_tags() {
    use supatype_engine::generator::sdk;

    let ast = parser::parse(simple_post_ast()).unwrap();
    let out = sdk::generate(&ast, "go").unwrap();

    assert!(
        out.contains("type Post struct {"),
        "Go output must define Post struct"
    );
    assert!(
        out.contains("package supatype"),
        "Go output must declare package"
    );
    assert!(
        out.contains("`json:\"title\"`"),
        "required field must have json tag without omitempty"
    );
    assert!(
        out.contains("`json:\"score,omitempty\"`"),
        "optional field must have omitempty json tag"
    );
    assert!(
        out.contains("Active bool"),
        "required boolean field must be bool"
    );
    assert!(
        out.contains("CreatedAt *time.Time"),
        "timestamps composite must add CreatedAt *time.Time"
    );
}

// ─── Scenario 51: PHP class with typed constructor properties ─────────────────

#[test]
fn test_sdk_php_typed_class() {
    use supatype_engine::generator::sdk;

    let ast = parser::parse(simple_post_ast()).unwrap();
    let out = sdk::generate(&ast, "php").unwrap();

    assert!(out.contains("<?php"), "PHP output must start with <?php");
    assert!(
        out.contains("class Post {"),
        "PHP output must define class Post"
    );
    assert!(
        out.contains("declare(strict_types=1)"),
        "PHP output must declare strict types"
    );
    assert!(
        out.contains("public readonly string $title"),
        "required string field must be typed string"
    );
    assert!(
        out.contains("public readonly ?int $score = null"),
        "optional int field must be ?int with null default"
    );
    assert!(
        out.contains("public readonly bool $active"),
        "required bool field must be typed bool"
    );
}

// ─── Scenario 52: Swift struct with Codable conformance ───────────────────────

#[test]
fn test_sdk_swift_codable_struct() {
    use supatype_engine::generator::sdk;

    let ast = parser::parse(simple_post_ast()).unwrap();
    let out = sdk::generate(&ast, "swift").unwrap();

    assert!(
        out.contains("import Foundation"),
        "Swift output must import Foundation"
    );
    assert!(
        out.contains("struct Post: Codable {"),
        "Swift output must define Post as Codable struct"
    );
    assert!(
        out.contains("var title: String"),
        "required String field must not be optional"
    );
    assert!(
        out.contains("var score: Int?"),
        "optional Int field must use optional type suffix"
    );
    assert!(
        out.contains("var active: Bool"),
        "required Bool field must not be optional"
    );
    assert!(
        out.contains("enum CodingKeys: String, CodingKey"),
        "Swift output must include CodingKeys enum"
    );
    assert!(
        out.contains("var createdAt: Date?"),
        "timestamps composite must add createdAt Date? field"
    );
}

// ─── Scenario 53: Kotlin data class with @Serializable ────────────────────────

#[test]
fn test_sdk_kotlin_data_class() {
    use supatype_engine::generator::sdk;

    let ast = parser::parse(simple_post_ast()).unwrap();
    let out = sdk::generate(&ast, "kotlin").unwrap();

    assert!(
        out.contains("package supatype.generated"),
        "Kotlin output must declare package"
    );
    assert!(
        out.contains("data class Post("),
        "Kotlin output must define Post as data class"
    );
    assert!(
        out.contains("val title: String"),
        "required String field must not be nullable"
    );
    assert!(
        out.contains("val score: Int? = null"),
        "optional Int field must be Int? with null default"
    );
    assert!(
        out.contains("val active: Boolean"),
        "required Boolean field must not be nullable"
    );
    assert!(
        out.contains("val createdAt: String? = null"),
        "timestamps composite must emit createdAt String?"
    );
}

// ─── Scenario 54: Dart class with fromJson/toJson ────────────────────────────

#[test]
fn test_sdk_dart_class_from_to_json() {
    use supatype_engine::generator::sdk;

    let ast = parser::parse(simple_post_ast()).unwrap();
    let out = sdk::generate(&ast, "dart").unwrap();

    assert!(
        out.contains("class Post {"),
        "Dart output must define class Post"
    );
    assert!(
        out.contains("factory Post.fromJson(Map<String, dynamic> json)"),
        "Dart output must have fromJson factory"
    );
    assert!(
        out.contains("Map<String, dynamic> toJson()"),
        "Dart output must have toJson method"
    );
    assert!(
        out.contains("final String title;"),
        "required String field must be final String"
    );
    assert!(
        out.contains("final int? score;"),
        "optional int field must be final int?"
    );
    assert!(
        out.contains("final bool active;"),
        "required bool field must be final bool"
    );
    assert!(
        out.contains("final DateTime? createdAt;"),
        "timestamps composite must add createdAt DateTime?"
    );
}

// ─── Scenario 55: Unknown language returns an error ──────────────────────────

#[test]
fn test_sdk_unknown_language_error() {
    use supatype_engine::generator::sdk;

    let ast = parser::parse(simple_post_ast()).unwrap();
    let result = sdk::generate(&ast, "brainfuck");

    assert!(result.is_err(), "unsupported language must return an Err");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("brainfuck"),
        "error message must include the unknown language name"
    );
}

// ─── Scenario 56: wasm_parse returns valid resolved AST JSON ─────────────────

#[test]
fn test_wasm_parse_returns_ast_json() {
    use supatype_engine::wasm;

    let result = wasm::wasm_parse(simple_post_ast());

    let parsed: serde_json::Value =
        serde_json::from_str(&result).expect("wasm_parse must return valid JSON");
    assert!(
        parsed.get("error").is_none(),
        "wasm_parse must not return an error for valid input"
    );
    assert!(
        parsed["models"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["name"] == "Post"),
        "wasm_parse AST must contain the Post model"
    );
}

// ─── Scenario 57: wasm_generate_typescript returns TypeScript interface ───────

#[test]
fn test_wasm_generate_typescript_interface() {
    use supatype_engine::wasm;

    let result = wasm::wasm_generate_typescript(simple_post_ast());

    assert!(
        !result.contains("\"error\""),
        "wasm_generate_typescript must not return an error JSON"
    );
    assert!(
        result.contains("export type Database"),
        "wasm_generate_typescript must emit Database root type"
    );
    assert!(
        result.contains("title: string"),
        "must include the title field typed as string"
    );
}

// ─── Scenario 58: SSO disabled → empty output ────────────────────────────────

#[test]
fn test_sso_disabled_produces_empty_output() {
    use supatype_engine::generator::sql::sso;
    use supatype_engine::parser::ast::SsoConfigAst;

    let cfg = SsoConfigAst {
        enabled: false,
        access_token_expiry_secs: 3600,
        refresh_token_expiry_days: 30,
        key_rotation_days: 90,
    };
    let sql = sso::generate(&cfg).unwrap();
    assert!(sql.is_empty(), "disabled SSO must produce no SQL");
}

// ─── Scenario 59: SSO enabled → creates _sso schema ─────────────────────────

#[test]
fn test_sso_enabled_creates_schema() {
    use supatype_engine::generator::sql::sso;
    use supatype_engine::parser::ast::SsoConfigAst;

    let cfg = SsoConfigAst {
        enabled: true,
        access_token_expiry_secs: 3600,
        refresh_token_expiry_days: 30,
        key_rotation_days: 90,
    };
    let sql = sso::generate(&cfg).unwrap();
    assert!(
        sql.contains("CREATE SCHEMA IF NOT EXISTS _sso"),
        "must create the _sso schema"
    );
}

// ─── Scenario 60: SSO enabled → creates oauth_clients table ──────────────────

#[test]
fn test_sso_enabled_creates_oauth_clients() {
    use supatype_engine::generator::sql::sso;
    use supatype_engine::parser::ast::SsoConfigAst;

    let cfg = SsoConfigAst {
        enabled: true,
        access_token_expiry_secs: 3600,
        refresh_token_expiry_days: 30,
        key_rotation_days: 90,
    };
    let sql = sso::generate(&cfg).unwrap();
    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS _sso.oauth_clients"),
        "must create oauth_clients table"
    );
    assert!(
        sql.contains("client_secret"),
        "oauth_clients must have client_secret column"
    );
    assert!(
        sql.contains("redirect_uris"),
        "oauth_clients must have redirect_uris column"
    );
    assert!(
        sql.contains("eligible_rules"),
        "oauth_clients must have eligible_rules JSONB column"
    );
}

// ─── Scenario 61: SSO enabled → creates oauth_consents table ─────────────────

#[test]
fn test_sso_enabled_creates_oauth_consents() {
    use supatype_engine::generator::sql::sso;
    use supatype_engine::parser::ast::SsoConfigAst;

    let cfg = SsoConfigAst {
        enabled: true,
        access_token_expiry_secs: 3600,
        refresh_token_expiry_days: 30,
        key_rotation_days: 90,
    };
    let sql = sso::generate(&cfg).unwrap();
    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS _sso.oauth_consents"),
        "must create oauth_consents table"
    );
    assert!(
        sql.contains("granted_at"),
        "oauth_consents must have granted_at column"
    );
    assert!(
        sql.contains("oauth_consents_user_client_unique"),
        "oauth_consents must have (user_id, client_id) unique constraint"
    );
}

// ─── Scenario 62: SSO enabled → RLS policies for user token ownership ────────

#[test]
fn test_sso_enabled_rls_policies() {
    use supatype_engine::generator::sql::sso;
    use supatype_engine::parser::ast::SsoConfigAst;

    let cfg = SsoConfigAst {
        enabled: true,
        access_token_expiry_secs: 3600,
        refresh_token_expiry_days: 30,
        key_rotation_days: 90,
    };
    let sql = sso::generate(&cfg).unwrap();
    assert!(
        sql.contains("ENABLE ROW LEVEL SECURITY"),
        "must enable RLS on user-facing tables"
    );
    assert!(
        sql.contains("oauth_access_tokens_select"),
        "must create select policy for access tokens"
    );
    assert!(
        sql.contains("oauth_consents_delete"),
        "must create delete policy for consents (revocation)"
    );
    assert!(
        sql.contains("user_id = auth.uid()"),
        "RLS policies must scope to the authenticated user"
    );
}

// ─── Scenario 63: SSO config round-trips through JSON parse ──────────────────

#[test]
fn test_sso_config_parses_from_schema_json() {
    let ast_json = r#"{
  "astVersion": 2,
  "models": [],
  "sso": {
    "enabled": true,
    "accessTokenExpirySecs": 1800,
    "refreshTokenExpiryDays": 14,
    "keyRotationDays": 60
  }
}"#;

    let ast = parser::parse(ast_json).expect("schema with sso block must parse");
    let sso = ast.sso.expect("sso field must be present");
    assert!(sso.enabled, "sso.enabled must be true");
    assert_eq!(sso.access_token_expiry_secs, 1800);
    assert_eq!(sso.refresh_token_expiry_days, 14);
    assert_eq!(sso.key_rotation_days, 60);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ─── Enum migration strategy (Gap Appendices tasks 67–70) ───────────────────
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Task 67: Add enum value ─────────────────────────────────────────────────

#[test]
fn test_enum_add_value_safe() {
    let ast_json = r#"{
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
        "status": {
          "kind": "enum",
          "values": [
            "draft",
            "published",
            "archived"
          ],
          "required": true,
          "annotations": {
            "db": {
              "pgType": "ENUM",
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
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("status", "text")],
        }],
        enums: vec![DbEnum {
            name: "posts_status".into(),
            values: vec!["draft".into(), "published".into()],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    let add_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::AddEnumValue { value, .. } if value == "archived"))
        .collect();
    assert_eq!(add_ops.len(), 1, "should emit AddEnumValue for 'archived'");

    // AddEnumValue must be classified as safe
    if let Operation::AddEnumValue { risk, .. } = &add_ops[0] {
        assert!(matches!(risk, Risk::Safe), "AddEnumValue must be safe");
    }
}

#[test]
fn test_enum_add_value_generates_alter_type_sql() {
    let ast_json = r#"{
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
        "status": {
          "kind": "enum",
          "values": [
            "draft",
            "published",
            "archived"
          ],
          "required": true,
          "annotations": {
            "db": {
              "pgType": "ENUM",
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
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("status", "text")],
        }],
        enums: vec![DbEnum {
            name: "posts_status".into(),
            values: vec!["draft".into(), "published".into()],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let sql = supatype_engine::generator::sql::migration::forward_sql(&diff, false, "public", &ast)
        .unwrap();
    assert!(
        sql.contains("ALTER TYPE \"posts_status\" ADD VALUE 'archived'"),
        "forward SQL must contain ALTER TYPE ... ADD VALUE; got:\n{sql}"
    );
}

// ─── Task 68: Remove enum value ─────────────────────────────────────────────

#[test]
fn test_enum_remove_value_destructive() {
    let ast_json = r#"{
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
        "status": {
          "kind": "enum",
          "values": [
            "draft",
            "published"
          ],
          "required": true,
          "annotations": {
            "db": {
              "pgType": "ENUM",
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
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("status", "text")],
        }],
        enums: vec![DbEnum {
            name: "posts_status".into(),
            values: vec!["draft".into(), "published".into(), "archived".into()],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    let remove_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::RemoveEnumValue { value, .. } if value == "archived"))
        .collect();
    assert_eq!(
        remove_ops.len(),
        1,
        "should emit RemoveEnumValue for 'archived'"
    );

    // Must be destructive
    if let Operation::RemoveEnumValue { risk, .. } = &remove_ops[0] {
        assert!(
            matches!(risk, Risk::Destructive),
            "RemoveEnumValue must be destructive"
        );
    }

    // Must require --force
    assert!(
        diff.summary.is_destructive,
        "removing an enum value must flag the migration as destructive"
    );
}

#[test]
fn test_enum_remove_value_requires_force() {
    let ast_json = r#"{
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
        "status": {
          "kind": "enum",
          "values": [
            "draft",
            "published"
          ],
          "required": true,
          "annotations": {
            "db": {
              "pgType": "ENUM",
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
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("status", "text")],
        }],
        enums: vec![DbEnum {
            name: "posts_status".into(),
            values: vec!["draft".into(), "published".into(), "archived".into()],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    // Without --force, migration generation should fail
    let result =
        supatype_engine::generator::sql::migration::forward_sql(&diff, false, "public", &ast);
    assert!(result.is_err(), "enum value removal must require --force");

    // With --force, it should succeed
    let sql = supatype_engine::generator::sql::migration::forward_sql(&diff, true, "public", &ast)
        .unwrap();
    assert!(
        sql.contains("RENAME TO \"posts_status_old\""),
        "remove enum value SQL must rename old type; got:\n{sql}"
    );
    assert!(
        sql.contains("DROP TYPE \"posts_status_old\""),
        "remove enum value SQL must drop old type; got:\n{sql}"
    );
}

#[test]
fn test_enum_remove_value_warning_message() {
    let ast_json = r#"{
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
        "status": {
          "kind": "enum",
          "values": [
            "draft",
            "published"
          ],
          "required": true,
          "annotations": {
            "db": {
              "pgType": "ENUM",
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
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("status", "text")],
        }],
        enums: vec![DbEnum {
            name: "posts_status".into(),
            values: vec!["draft".into(), "published".into(), "archived".into()],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    assert!(
        diff.warnings
            .iter()
            .any(|w| w.contains("archived") && w.contains("posts_status")),
        "should warn about removing enum value 'archived' from 'posts_status'"
    );
}

// ─── Task 69: Rename enum value ─────────────────────────────────────────────

#[test]
fn test_enum_rename_value_detected_via_similarity() {
    // "draft" → "drft" looks like a rename (high similarity).
    // "published" stays the same.
    let ast_json = r#"{
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
        "status": {
          "kind": "enum",
          "values": [
            "drafts",
            "published"
          ],
          "required": true,
          "annotations": {
            "db": {
              "pgType": "ENUM",
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
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("status", "text")],
        }],
        enums: vec![DbEnum {
            name: "posts_status".into(),
            values: vec!["draft".into(), "published".into()],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    let rename_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::RenameEnumValue { .. }))
        .collect();
    assert_eq!(rename_ops.len(), 1, "should detect one enum value rename");

    if let Operation::RenameEnumValue {
        enum_name,
        from,
        to,
        risk,
    } = &rename_ops[0]
    {
        assert_eq!(enum_name, "posts_status");
        assert_eq!(from, "draft");
        assert_eq!(to, "drafts");
        assert!(
            matches!(risk, Risk::Cautious),
            "RenameEnumValue must be cautious"
        );
    }
}

#[test]
fn test_enum_rename_value_generates_alter_type_rename_sql() {
    let ast_json = r#"{
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
        "status": {
          "kind": "enum",
          "values": [
            "drafts",
            "published"
          ],
          "required": true,
          "annotations": {
            "db": {
              "pgType": "ENUM",
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
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("status", "text")],
        }],
        enums: vec![DbEnum {
            name: "posts_status".into(),
            values: vec!["draft".into(), "published".into()],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let sql = supatype_engine::generator::sql::migration::forward_sql(&diff, false, "public", &ast)
        .unwrap();
    assert!(
        sql.contains("ALTER TYPE \"posts_status\" RENAME VALUE 'draft' TO 'drafts'"),
        "forward SQL must contain RENAME VALUE; got:\n{sql}"
    );
}

// ─── Task 70: Reorder enum values ───────────────────────────────────────────

#[test]
fn test_enum_reorder_values_detected() {
    // Same values, different order: schema says [published, draft], DB has [draft, published].
    let ast_json = r#"{
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
        "status": {
          "kind": "enum",
          "values": [
            "published",
            "draft"
          ],
          "required": true,
          "annotations": {
            "db": {
              "pgType": "ENUM",
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
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("status", "text")],
        }],
        enums: vec![DbEnum {
            name: "posts_status".into(),
            values: vec!["draft".into(), "published".into()],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    let reorder_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, Operation::ReorderEnumValues { .. }))
        .collect();
    assert_eq!(
        reorder_ops.len(),
        1,
        "should detect reorder when values are the same but order differs"
    );

    if let Operation::ReorderEnumValues {
        enum_name, risk, ..
    } = &reorder_ops[0]
    {
        assert_eq!(enum_name, "posts_status");
        assert!(
            matches!(risk, Risk::Cautious),
            "ReorderEnumValues must be cautious"
        );
    }
}

#[test]
fn test_enum_reorder_values_generates_recreate_sql() {
    let ast_json = r#"{
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
        "status": {
          "kind": "enum",
          "values": [
            "published",
            "draft"
          ],
          "required": true,
          "annotations": {
            "db": {
              "pgType": "ENUM",
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
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("status", "text")],
        }],
        enums: vec![DbEnum {
            name: "posts_status".into(),
            values: vec!["draft".into(), "published".into()],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let sql = supatype_engine::generator::sql::migration::forward_sql(&diff, false, "public", &ast)
        .unwrap();

    // Must rename old → create new → alter columns → drop old
    assert!(
        sql.contains("RENAME TO \"posts_status_old\""),
        "reorder SQL must rename old type; got:\n{sql}"
    );
    assert!(
        sql.contains("CREATE TYPE \"posts_status\" AS ENUM ('published', 'draft')"),
        "reorder SQL must create type with new order; got:\n{sql}"
    );
    assert!(
        sql.contains("DROP TYPE \"posts_status_old\""),
        "reorder SQL must drop old type; got:\n{sql}"
    );
}

// ─── No-op: unchanged enum produces no operations ───────────────────────────

#[test]
fn test_enum_no_change_produces_no_ops() {
    let ast_json = r#"{
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
        "status": {
          "kind": "enum",
          "values": [
            "draft",
            "published"
          ],
          "required": true,
          "annotations": {
            "db": {
              "pgType": "ENUM",
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
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("status", "text")],
        }],
        enums: vec![DbEnum {
            name: "posts_status".into(),
            values: vec!["draft".into(), "published".into()],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    let enum_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| {
            matches!(
                op,
                Operation::CreateEnum { .. }
                    | Operation::DropEnum { .. }
                    | Operation::AddEnumValue { .. }
                    | Operation::RemoveEnumValue { .. }
                    | Operation::RenameEnumValue { .. }
                    | Operation::ReorderEnumValues { .. }
            )
        })
        .collect();

    assert!(
        enum_ops.is_empty(),
        "unchanged enum should produce no enum operations; got: {enum_ops:?}"
    );
}

// ─── Scenario: text → richText (plain TEXT to Lexical JSONB) ─────────────────

#[test]
fn test_alter_column_text_to_richtext_uses_lexical_wrap() {
    use supatype_engine::generator::sql::migration;

    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Homepage",
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
        "story1_para1": {
          "kind": "richText",
          "required": true,
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
          "tableName": "homepage",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "homepage".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("story1_para1", "text")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let sql = migration::generate(&diff, true, "public", &ast).unwrap();

    assert!(
        sql.contains("TYPE JSONB USING"),
        "must alter column type to JSONB with USING"
    );
    assert!(
        sql.contains("'type', 'root'"),
        "must wrap plain text as Lexical root document"
    );
    assert!(
        sql.contains("'text', \"story1_para1\"::text"),
        "must preserve existing plain text in Lexical text node"
    );
    assert!(
        !sql.contains("story1_para1\"::jsonb"),
        "must not use raw ::jsonb cast on plain text"
    );
}

// ─── Scenario: richText → text (Lexical JSONB back to plain TEXT) ─────────────

#[test]
fn test_alter_column_richtext_to_text_extracts_lexical_plain_text() {
    use supatype_engine::generator::sql::migration;

    let previous_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Homepage",
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
        "story1_para1": {
          "kind": "richText",
          "required": true,
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
          "tableName": "_global_homepage",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Homepage",
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
        "story1_para1": {
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
      "options": {
        "timestamps": false,
        "softDelete": false
      },
      "annotations": {
        "db": {
          "tableName": "_global_homepage",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let previous = parser::parse(previous_json).unwrap();
    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "_global_homepage".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![
                col("id", "uuid"),
                DbColumn {
                    name: "story1_para1".into(),
                    data_type: "jsonb".into(),
                    udt_name: "jsonb".into(),
                    nullable: false,
                    default: None,
                    ordinal_position: 1,
                },
            ],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff_with_previous(&ast, &db, Some(&previous)).unwrap();
    let sql = migration::generate(&diff, true, "public", &ast).unwrap();

    assert!(
        sql.contains("TYPE TEXT USING"),
        "must alter JSONB column to TEXT with USING"
    );
    assert!(
        sql.contains("jsonb_path_query"),
        "must extract Lexical text nodes in a pre-update, got:\n{sql}"
    );
    assert!(
        sql.contains("to_jsonb("),
        "pre-update must materialise plain text before ALTER TYPE"
    );
    assert!(
        !sql.contains("TYPE TEXT USING COALESCE((SELECT"),
        "subqueries are not allowed in ALTER COLUMN USING"
    );
    assert!(
        !sql.contains("->>'en'"),
        "must not treat Lexical JSONB as localized map"
    );
}

// ─── Scenario: json → richText (JSONB kind change, same PG type) ─────────────

#[test]
fn test_alter_column_json_to_richtext_migrates_jsonb_data() {
    use supatype_engine::generator::sql::migration;

    let previous_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Homepage",
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
        "story1_para1": {
          "kind": "json",
          "required": true,
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
          "tableName": "homepage",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Homepage",
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
        "story1_para1": {
          "kind": "richText",
          "required": true,
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
          "tableName": "homepage",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let previous = parser::parse(previous_json).unwrap();
    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "homepage".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("story1_para1", "jsonb")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff_with_previous(&ast, &db, Some(&previous)).unwrap();
    let sql = migration::generate(&diff, true, "public", &ast).unwrap();

    assert!(
        sql.contains("UPDATE \"public\".\"homepage\""),
        "must UPDATE rows when PG type unchanged but kind changed"
    );
    assert!(
        sql.contains("'type', 'root'"),
        "must convert JSONB values to Lexical documents"
    );
    assert!(
        !sql.contains("TYPE JSONB"),
        "must not ALTER TYPE when column is already JSONB"
    );
}

// ─── Scenario: integer → richText (scalar to Lexical JSONB) ────────────────

#[test]
fn test_alter_column_integer_to_richtext_uses_lexical_wrap() {
    use supatype_engine::generator::sql::migration;

    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Counter",
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
        "value": {
          "kind": "richText",
          "required": true,
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
          "tableName": "counter",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "counter".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("value", "int4")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let sql = migration::generate(&diff, true, "public", &ast).unwrap();

    assert!(sql.contains("TYPE JSONB USING"));
    assert!(sql.contains("'type', 'root'"));
    assert!(sql.contains("\"value\"::text"));
    assert!(!sql.contains("\"value\"::jsonb"));
}

// ─── Column conversion: integer → json (typed to_jsonb) ─────────────────────

#[test]
fn test_alter_column_integer_to_json_uses_to_jsonb() {
    use supatype_engine::generator::sql::migration;

    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Counter",
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
        "value": {
          "kind": "json",
          "required": true,
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
          "tableName": "counter",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "counter".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("value", "int4")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let sql = migration::generate(&diff, true, "public", &ast).unwrap();

    assert!(sql.contains("TYPE JSONB USING to_jsonb(\"value\")"));
}

// ─── Column conversion: localization add ─────────────────────────────────────

#[test]
fn test_alter_column_localization_add_wraps_default_locale() {
    use supatype_engine::generator::sql::migration;

    let ast_json = r#"{
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
        "title": {
          "kind": "text",
          "required": true,
          "localized": true,
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
          "tableName": "posts",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("title", "text")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let sql = migration::generate(&diff, true, "public", &ast).unwrap();

    assert!(sql.contains("jsonb_build_object('en'"));
}

// ─── Column conversion: unc castable → recreate column ───────────────────────

#[test]
fn test_geo_to_json_emits_recreate_column() {
    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Place",
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
        "loc": {
          "kind": "geo",
          "required": false,
          "geoType": "point",
          "srid": 4326,
          "annotations": {
            "db": {
              "pgType": "GEOGRAPHY",
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
          "tableName": "places",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let previous_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Place",
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
        "loc": {
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
          "tableName": "places",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let previous = parser::parse(previous_json).unwrap();
    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "places".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![
                col("id", "uuid"),
                DbColumn {
                    name: "loc".into(),
                    data_type: "jsonb".into(),
                    udt_name: "jsonb".into(),
                    nullable: true,
                    default: None,
                    ordinal_position: 2,
                },
            ],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff_with_previous(&ast, &db, Some(&previous)).unwrap();
    let recreate = diff
        .operations
        .iter()
        .any(|op| matches!(op, Operation::RecreateColumn { column, .. } if column == "loc"));
    assert!(
        recreate,
        "geo from jsonb should recreate column; got {:?}",
        diff.operations
    );
}

// ─── Array element type change detected ──────────────────────────────────────

#[test]
fn test_array_element_type_change_detected() {
    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Tag",
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
        "names": {
          "kind": "array",
          "required": false,
          "annotations": {
            "db": {
              "elementType": "INTEGER",
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
          "tableName": "tags",
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
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "tags".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("names", "_text")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let alter = diff
        .operations
        .iter()
        .any(|op| matches!(op, Operation::AlterColumn { column, .. } if column == "names"));
    assert!(alter, "text[] → integer[] should emit AlterColumn");
}

// ─── Managed objects: Keepsake slug unique regression ───────────────────────

fn managed_unique_constraint(table: &str, column: &str) -> DbConstraint {
    DbConstraint {
        table: table.into(),
        name: format!("{table}_{column}_key"),
        constraint_type: DbConstraintType::Unique,
        columns: vec![column.into()],
        foreign_table: None,
        foreign_columns: None,
        check_expression: None,
        on_delete: None,
        comment: Some(format!(
            "supatype:managed;kind=unique_constraint;table={table};fields={column};v=1"
        )),
    }
}

#[test]
fn test_drop_managed_slug_unique_when_removed_from_ast() {
    let ast_json = r#"{
  "astVersion": 2,
  "models": [{
    "name": "Album",
    "fields": {
      "id": { "kind": "uuid", "primaryKey": true, "required": true,
        "annotations": { "db": { "pgType": "UUID" } } },
      "owner_id": { "kind": "uuid", "required": true,
        "annotations": { "db": { "pgType": "UUID" } } },
      "slug": { "kind": "slug", "required": true, "from": "title",
        "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
      "title": { "kind": "text", "required": true,
        "annotations": { "db": { "pgType": "TEXT" } } }
    },
    "options": {},
    "annotations": {
      "db": {
        "tableName": "album",
        "indexes": [{ "fields": ["owner_id", "slug"], "unique": true, "using": "btree" }]
      },
      "platform": { "access": {} }
    }
  }]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "album".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![
                col("id", "uuid"),
                col("owner_id", "uuid"),
                col("slug", "text"),
                col("title", "text"),
            ],
        }],
        constraints: vec![managed_unique_constraint("album", "slug")],
        indexes: vec![supatype_engine::introspector::indexes::DbIndex {
            table: "album".into(),
            name: "album_owner_id_slug_idx".into(),
            columns: vec!["owner_id".into(), "slug".into()],
            unique: true,
            method: "btree".into(),
            is_primary: false,
            comment: Some(
                "supatype:managed;kind=unique_index;table=album;fields=owner_id,slug;v=1".into(),
            ),
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    assert!(
        diff.operations.iter().any(|op| {
            matches!(
                op,
                Operation::DropUniqueConstraint {
                    constraint,
                    table,
                    ..
                } if table == "album" && constraint == "album_slug_key"
            )
        }),
        "expected DropUniqueConstraint for managed album_slug_key; got {:?}",
        diff.operations
    );
}

#[test]
fn test_unmanaged_slug_unique_never_auto_dropped() {
    let ast_json = r#"{
  "astVersion": 2,
  "models": [{
    "name": "Album",
    "fields": {
      "id": { "kind": "uuid", "primaryKey": true, "required": true,
        "annotations": { "db": { "pgType": "UUID" } } },
      "title": { "kind": "text", "required": true,
        "annotations": { "db": { "pgType": "TEXT" } } },
      "slug": { "kind": "slug", "required": true, "from": "title",
        "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
    },
    "options": {},
    "annotations": {
      "db": { "tableName": "album", "indexes": [] },
      "platform": { "access": {} }
    }
  }]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let mut constraint = managed_unique_constraint("album", "slug");
    constraint.comment = None;
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "album".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![col("id", "uuid"), col("title", "text"), col("slug", "text")],
        }],
        constraints: vec![constraint],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    assert!(
        !diff
            .operations
            .iter()
            .any(|op| matches!(op, Operation::DropUniqueConstraint { .. })),
        "unmanaged constraint must not be auto-dropped"
    );

    let report = supatype_engine::differ::doctor::report(&ast, &db);
    assert!(
        report
            .unmanaged_drift
            .iter()
            .any(|i| i.name == "album_slug_key"),
        "doctor should flag unmanaged album_slug_key"
    );
}

#[test]
fn test_drop_managed_model_index_removed_from_ast() {
    let ast_json = r#"{
  "astVersion": 2,
  "models": [{
    "name": "Album",
    "fields": {
      "id": { "kind": "uuid", "primaryKey": true, "required": true,
        "annotations": { "db": { "pgType": "UUID" } } },
      "owner_id": { "kind": "uuid", "required": true,
        "annotations": { "db": { "pgType": "UUID" } } },
      "title": { "kind": "text", "required": true,
        "annotations": { "db": { "pgType": "TEXT" } } },
      "slug": { "kind": "slug", "required": true, "from": "title",
        "annotations": { "db": { "pgType": "TEXT" } } }
    },
    "options": {},
    "annotations": {
      "db": { "tableName": "album", "indexes": [] },
      "platform": { "access": {} }
    }
  }]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "album".into(),
            comment: Some("supatype:managed;kind=table".into()),
            columns: vec![
                col("id", "uuid"),
                col("owner_id", "uuid"),
                col("title", "text"),
                col("slug", "text"),
            ],
        }],
        indexes: vec![supatype_engine::introspector::indexes::DbIndex {
            table: "album".into(),
            name: "album_owner_id_slug_idx".into(),
            columns: vec!["owner_id".into(), "slug".into()],
            unique: true,
            method: "btree".into(),
            is_primary: false,
            comment: Some(
                "supatype:managed;kind=unique_index;table=album;fields=owner_id,slug;v=1".into(),
            ),
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    assert!(
        diff.operations.iter().any(|op| {
            matches!(
                op,
                Operation::DropIndex { index_name, .. } if index_name == "album_owner_id_slug_idx"
            )
        }),
        "expected DropIndex for stale managed index; got {:?}",
        diff.operations
    );
}

/// `Code<"sql">` and `Currency<"USD">` reach the engine as `kind: "json"` carrying an extra
/// `tsType` — a fact only the TypeScript generator needs. The engine must ignore it and still emit
/// `JSONB`; if serde ever rejected the unknown field instead, every schema using either type would
/// fail to parse rather than to compile, which is a much worse error to debug.
#[test]
fn test_json_field_with_ts_type_annotation_is_parsed_as_jsonb() {
    use supatype_engine::generator::sql::migration;

    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Snippet",
      "fields": {
        "id": {
          "kind": "uuid",
          "primaryKey": true,
          "required": true,
          "default": { "kind": "genRandomUuid" },
          "annotations": { "db": { "pgType": "UUID", "unique": false } }
        },
        "body": {
          "kind": "json",
          "required": true,
          "tsType": "{ lang: \"sql\"; source: string }",
          "annotations": { "db": { "pgType": "JSONB", "unique": false } }
        },
        "price": {
          "kind": "json",
          "required": false,
          "tsType": "{ amount: string; code: \"USD\" }",
          "annotations": { "db": { "pgType": "JSONB", "unique": false } }
        }
      },
      "options": { "timestamps": false, "softDelete": false },
      "annotations": {
        "db": { "tableName": "snippets", "indexes": [] },
        "platform": { "access": {} }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).expect("tsType must not break parsing");
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::generate(&diff, true, "public", &ast).unwrap();

    assert!(
        sql.contains("\"body\" JSONB NOT NULL"),
        "Code<> must become a required JSONB column, got:\n{sql}"
    );
    assert!(
        sql.contains("\"price\" JSONB"),
        "Currency<> must become a JSONB column, got:\n{sql}"
    );
}

/// The OpenAPI document must agree with the migration generator about who owns a foreign key.
///
/// `HasOne` is the *inverse* side: the column (and its UNIQUE) belongs to whichever model declares
/// the `RelatedTo`, and `generator/sql/migration.rs` emits nothing for `hasOne`. The spec generator
/// used to emit an `<name>_id` property for it anyway, so a client generated from the document sent
/// a column PostgREST rejects — and the document described a table that does not exist.
#[test]
fn test_openapi_omits_column_for_inverse_relations() {
    use supatype_engine::generator::openapi;

    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Post",
      "fields": {
        "id": {
          "kind": "uuid",
          "primaryKey": true,
          "required": true,
          "default": { "kind": "genRandomUuid" },
          "annotations": { "db": { "pgType": "UUID", "unique": false } }
        },
        "settings": { "kind": "relation", "cardinality": "hasOne", "target": "Settings" },
        "comments": { "kind": "relation", "cardinality": "hasMany", "target": "Comment" }
      },
      "options": { "timestamps": false, "softDelete": false },
      "annotations": {
        "db": { "tableName": "posts", "indexes": [] },
        "platform": { "access": {} }
      }
    },
    {
      "name": "Settings",
      "fields": {
        "id": {
          "kind": "uuid",
          "primaryKey": true,
          "required": true,
          "default": { "kind": "genRandomUuid" },
          "annotations": { "db": { "pgType": "UUID", "unique": false } }
        },
        "post": { "kind": "relation", "cardinality": "belongsTo", "target": "Post" }
      },
      "options": { "timestamps": false, "softDelete": false },
      "annotations": {
        "db": { "tableName": "settings", "indexes": [] },
        "platform": { "access": {} }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let spec = openapi::generate(&ast).unwrap();

    let post_props = spec["components"]["schemas"]["Post"]["properties"]
        .as_object()
        .expect("Post schema must have properties");
    assert!(
        !post_props.contains_key("settings_id"),
        "hasOne owns no column, so the spec must not advertise settings_id: {post_props:?}"
    );
    assert!(
        !post_props.contains_key("comments_id"),
        "hasMany owns no column: {post_props:?}"
    );

    // The owning side still carries its foreign key, or the fix would have removed real columns.
    let settings_props = spec["components"]["schemas"]["Settings"]["properties"]
        .as_object()
        .expect("Settings schema must have properties");
    assert!(
        settings_props.contains_key("post_id"),
        "belongsTo owns the column and must still appear: {settings_props:?}"
    );
}

/// A field can name its Studio widget, and an unknown name is ignored rather than trusted.
///
/// `Code<"sql">`, `Currency<"USD">` and `Duration` are all stored as JSONB, so a widget chosen from
/// the column kind alone gives all three the raw JSON editor. `annotations.platform.editor` was
/// parsed by this engine and read by nothing; this is what makes it mean something.
#[test]
fn test_admin_config_honours_declared_editor_widget() {
    let ast_json = r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Snippet",
      "fields": {
        "id": {
          "kind": "uuid",
          "primaryKey": true,
          "required": true,
          "default": { "kind": "genRandomUuid" },
          "annotations": { "db": { "pgType": "UUID", "unique": false } }
        },
        "body": {
          "kind": "json",
          "required": true,
          "annotations": { "db": { "pgType": "JSONB" }, "platform": { "editor": "code" } }
        },
        "price": {
          "kind": "json",
          "required": false,
          "annotations": { "db": { "pgType": "JSONB" }, "platform": { "editor": "currency" } }
        },
        "payload": {
          "kind": "json",
          "required": false,
          "annotations": { "db": { "pgType": "JSONB" } }
        },
        "unknown_widget": {
          "kind": "json",
          "required": false,
          "annotations": { "db": { "pgType": "JSONB" }, "platform": { "editor": "hologram" } }
        }
      },
      "options": { "timestamps": false, "softDelete": false },
      "annotations": {
        "db": { "tableName": "snippets", "indexes": [] },
        "platform": { "access": {} }
      }
    }
  ]
}"#;

    let ast = parser::parse(ast_json).unwrap();
    let config = admin::generate(&ast).unwrap();

    let fields = config["models"][0]["fields"].as_array().unwrap();
    let widget_of = |name: &str| -> String {
        fields
            .iter()
            .find(|f| f["name"] == name)
            .unwrap_or_else(|| panic!("field {name} missing from admin config"))["widget"]
            .as_str()
            .unwrap()
            .to_string()
    };

    assert_eq!(widget_of("body"), "code");
    assert_eq!(widget_of("price"), "currency");
    // No declaration: the kind still decides.
    assert_eq!(widget_of("payload"), "json");
    // A widget Studio cannot render would leave the field with no editor, so it falls back.
    assert_eq!(widget_of("unknown_widget"), "json");
}
