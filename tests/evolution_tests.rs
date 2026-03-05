//! Evolution scenario tests — Phase 1 requirement.
//!
//! Each test follows the pattern:
//!   1. Base DB state (simulates already-applied schema)
//!   2. New schema AST (simulates the desired change)
//!   3. Compute the diff
//!   4. Assert expected operations
//!
//! These are pure unit tests — no DB required.

use definatype_engine::{
    differ::{self, Operation},
    introspector::{
        constraints::{DbConstraint, DbConstraintType},
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
    }
}

// ─── Scenario 1: add_column_nullable ─────────────────────────────────────────

#[test]
fn test_add_column_nullable() {
    let ast_json = r#"{
        "models": [{
            "name": "Post", "tableName": "posts",
            "fields": {
                "id":      { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } },
                "title":   { "kind": "text", "pgType": "TEXT", "required": true,  "unique": false },
                "excerpt": { "kind": "text", "pgType": "TEXT", "required": false, "unique": false }
            },
            "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
        }]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            columns: vec![col("id", "uuid"), col("title", "text")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let add_ops: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::AddColumn { column, .. } if column == "excerpt"))
        .collect();
    assert_eq!(add_ops.len(), 1, "should add excerpt column");
    assert!(!diff.summary.is_destructive, "adding nullable column is safe");
}

// ─── Scenario 2: drop_column ─────────────────────────────────────────────────

#[test]
fn test_drop_column() {
    let ast_json = r#"{
        "models": [{
            "name": "Post", "tableName": "posts",
            "fields": {
                "id":    { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } },
                "title": { "kind": "text", "pgType": "TEXT", "required": true, "unique": false }
            },
            "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
        }]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            columns: vec![col("id", "uuid"), col("title", "text"), col("legacy_field", "text")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let drop_ops: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::DropColumn { column, .. } if column == "legacy_field"))
        .collect();
    assert_eq!(drop_ops.len(), 1, "should detect dropped column");
    assert!(diff.summary.is_destructive, "dropping a column is destructive");
}

// ─── Scenario 3: rename_column ───────────────────────────────────────────────

#[test]
fn test_rename_column_detected() {
    let ast_json = r#"{
        "models": [{
            "name": "Post", "tableName": "posts",
            "fields": {
                "id":          { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } },
                "body_content": { "kind": "text", "pgType": "TEXT", "required": true, "unique": false }
            },
            "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
        }]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "posts".into(),
            columns: vec![col("id", "uuid"), col("body_text", "text")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let rename_ops: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::RenameColumn { from, to, .. }
            if from == "body_text" && to == "body_content"))
        .collect();
    assert_eq!(rename_ops.len(), 1, "should detect rename via string similarity");

    let drop_of_old: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::DropColumn { column, .. } if column == "body_text"))
        .collect();
    let add_of_new: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::AddColumn { column, .. } if column == "body_content"))
        .collect();
    assert!(drop_of_old.is_empty(), "must not emit DropColumn for the renamed column");
    assert!(add_of_new.is_empty(),  "must not emit AddColumn for the renamed column");
}

// ─── Scenario 4: add FK on existing table ────────────────────────────────────

#[test]
fn test_add_fk_on_existing_table() {
    let ast_json = r#"{
        "models": [
            {
                "name": "User", "tableName": "users",
                "fields": {
                    "id": { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } }
                },
                "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
            },
            {
                "name": "Post", "tableName": "posts",
                "fields": {
                    "id":       { "kind": "uuid",    "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } },
                    "authorId": { "kind": "relation","cardinality": "belongsTo","target": "User","foreignKey": "author_id","onDelete": "cascade" }
                },
                "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
            }
        ]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![
            DbTable { schema: "public".into(), name: "users".into(), columns: vec![col("id", "uuid")] },
            DbTable { schema: "public".into(), name: "posts".into(), columns: vec![col("id", "uuid"), col("author_id", "uuid")] },
        ],
        constraints: vec![], // FK not yet present
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let fk_ops: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::AddForeignKey { table, .. } if table == "posts"))
        .collect();
    assert_eq!(fk_ops.len(), 1, "should emit AddForeignKey for posts.author_id");
}

// ─── Scenario 5: FK already exists — no-op ───────────────────────────────────

#[test]
fn test_fk_already_exists_no_op() {
    let ast_json = r#"{
        "models": [
            {
                "name": "User", "tableName": "users",
                "fields": {
                    "id": { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } }
                },
                "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
            },
            {
                "name": "Post", "tableName": "posts",
                "fields": {
                    "id":       { "kind": "uuid",    "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } },
                    "authorId": { "kind": "relation","cardinality": "belongsTo","target": "User","foreignKey": "author_id","onDelete": "cascade" }
                },
                "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
            }
        ]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![
            DbTable { schema: "public".into(), name: "users".into(), columns: vec![col("id", "uuid")] },
            DbTable { schema: "public".into(), name: "posts".into(), columns: vec![col("id", "uuid"), col("author_id", "uuid")] },
        ],
        constraints: vec![fk("posts", "author_id", "users")], // already applied
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let fk_ops: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::AddForeignKey { .. }))
        .collect();
    assert!(fk_ops.is_empty(), "FK already exists — must not emit AddForeignKey (idempotency)");
    assert_eq!(diff.operations.len(), 0, "fully-applied schema must produce empty diff");
}

// ─── Scenario 6: drop FK when relation removed ────────────────────────────────

#[test]
fn test_drop_fk_when_relation_removed() {
    // Schema: plain UUID column (relation was removed)
    let ast_json = r#"{
        "models": [{
            "name": "Post", "tableName": "posts",
            "fields": {
                "id":        { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } },
                "author_id": { "kind": "uuid", "pgType": "UUID", "required": false, "unique": false }
            },
            "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
        }]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(), name: "posts".into(),
            columns: vec![col("id", "uuid"), col("author_id", "uuid")],
        }],
        constraints: vec![fk("posts", "author_id", "users")], // stale FK
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let drop_fk: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::DropForeignKey { constraint, .. }
            if constraint == "posts_author_id_fkey"))
        .collect();
    assert_eq!(drop_fk.len(), 1, "should drop stale FK when relation removed from schema");
}

// ─── Scenario 7: new table with FK ───────────────────────────────────────────

#[test]
fn test_new_table_added() {
    let ast_json = r#"{
        "models": [
            {
                "name": "User", "tableName": "users",
                "fields": { "id": { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } } },
                "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
            },
            {
                "name": "Profile", "tableName": "profiles",
                "fields": {
                    "id":     { "kind": "uuid",    "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } },
                    "userId": { "kind": "relation","cardinality": "belongsTo","target": "User","foreignKey": "user_id","onDelete": "cascade" }
                },
                "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
            }
        ]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable { schema: "public".into(), name: "users".into(), columns: vec![col("id", "uuid")] }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let create_ops: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::CreateTable { table, .. } if table == "profiles"))
        .collect();
    assert_eq!(create_ops.len(), 1, "should create profiles table");

    // CreateTable should come before AddForeignKey
    let last_create = diff.operations.iter().rposition(|op| matches!(op, Operation::CreateTable { .. }));
    let first_fk    = diff.operations.iter().position(|op| matches!(op, Operation::AddForeignKey { .. }));
    if let (Some(lc), Some(ffk)) = (last_create, first_fk) {
        assert!(lc < ffk, "CreateTable must precede AddForeignKey");
    }
}

// ─── Scenario 8: drop table ───────────────────────────────────────────────────

#[test]
fn test_drop_table_when_model_removed() {
    let ast_json = r#"{
        "models": [{
            "name": "User", "tableName": "users",
            "fields": { "id": { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } } },
            "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
        }]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![
            DbTable { schema: "public".into(), name: "users".into(),           columns: vec![col("id", "uuid")] },
            DbTable { schema: "public".into(), name: "legacy_sessions".into(), columns: vec![col("id", "uuid")] },
        ],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let drop_ops: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::DropTable { table, .. } if table == "legacy_sessions"))
        .collect();
    assert_eq!(drop_ops.len(), 1, "should emit DropTable for removed model");
    assert!(diff.summary.is_destructive, "dropping a table is destructive");
}

// ─── Scenario 9: junction table idempotency ──────────────────────────────────

#[test]
fn test_junction_table_not_recreated() {
    let ast_json = r#"{
        "models": [
            {
                "name": "Student", "tableName": "students",
                "fields": {
                    "id": { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } },
                    "courses": { "kind": "relation", "cardinality": "manyToMany", "target": "Course", "through": "enrollments" }
                },
                "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
            },
            {
                "name": "Course", "tableName": "courses",
                "fields": {
                    "id": { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } }
                },
                "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
            }
        ]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![
            DbTable { schema: "public".into(), name: "students".into(),    columns: vec![col("id", "uuid")] },
            DbTable { schema: "public".into(), name: "courses".into(),     columns: vec![col("id", "uuid")] },
            DbTable { schema: "public".into(), name: "enrollments".into(), columns: vec![
                col("student_id", "uuid"), col("course_id", "uuid"),
            ]},
        ],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let jt_ops: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::CreateJunctionTable { table, .. } if table == "enrollments"))
        .collect();
    assert!(jt_ops.is_empty(), "junction table already exists — must not recreate");
}

// ─── Scenario 10: timestamps option idempotency ───────────────────────────────

#[test]
fn test_timestamps_option_idempotency() {
    let ast_json = r#"{
        "models": [{
            "name": "Post", "tableName": "posts",
            "fields": {
                "id":    { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } },
                "title": { "kind": "text", "pgType": "TEXT", "required": true, "unique": false }
            },
            "access": {}, "indexes": [], "options": { "timestamps": true, "softDelete": false }
        }]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(), name: "posts".into(),
            columns: vec![
                col("id", "uuid"), col("title", "text"),
                col("created_at", "timestamp with time zone"),
                col("updated_at", "timestamp with time zone"),
            ],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let ts_ops: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::AddColumn { column, .. }
            if column == "created_at" || column == "updated_at"))
        .collect();
    assert!(ts_ops.is_empty(), "timestamps already exist — must not add them again");
}

// ─── Scenario 11: softDelete option idempotency ───────────────────────────────

#[test]
fn test_soft_delete_option_idempotency() {
    let ast_json = r#"{
        "models": [{
            "name": "Post", "tableName": "posts",
            "fields": {
                "id": { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } }
            },
            "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": true }
        }]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(), name: "posts".into(),
            columns: vec![col("id", "uuid"), col("deleted_at", "timestamp with time zone")],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let ops: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::AddColumn { column, .. } if column == "deleted_at"))
        .collect();
    assert!(ops.is_empty(), "deleted_at already exists — must not add again");
}

// ─── Scenario 12: auto-index on new column ───────────────────────────────────

#[test]
fn test_auto_index_emitted_with_new_indexed_column() {
    let ast_json = r#"{
        "models": [{
            "name": "Post", "tableName": "posts",
            "fields": {
                "id":       { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } },
                "authorId": { "kind": "uuid", "pgType": "UUID", "required": true, "unique": false, "index": true }
            },
            "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
        }]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(), name: "posts".into(),
            columns: vec![col("id", "uuid")], // authorId not yet present
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let add_col: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::AddColumn { column, .. } if column == "authorId"))
        .collect();
    let add_idx: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, Operation::AddIndex { table, .. } if table == "posts"))
        .collect();
    assert_eq!(add_col.len(), 1, "should add authorId column");
    assert_eq!(add_idx.len(), 1, "should add btree index for authorId with index:true");
}

// ─── Scenario 13: rollback reverses CreateTable ───────────────────────────────

#[test]
fn test_rollback_reverses_create_table() {
    use definatype_engine::generator::sql::rollback;

    let ast_json = r#"{
        "models": [{
            "name": "Post", "tableName": "posts",
            "fields": {
                "id": { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } }
            },
            "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
        }]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let rollback_sql = rollback::generate(&diff).unwrap();

    assert!(rollback_sql.contains("DROP TABLE IF EXISTS"), "rollback must drop the created table");
    assert!(rollback_sql.contains("BEGIN;"), "rollback must be wrapped in transaction");
    assert!(rollback_sql.contains("COMMIT;"), "rollback must commit");
}

// ─── Scenario 14: rollback reverses AddForeignKey ────────────────────────────

#[test]
fn test_rollback_reverses_add_fk() {
    use definatype_engine::generator::sql::rollback;

    let ast_json = r#"{
        "models": [
            {
                "name": "User", "tableName": "users",
                "fields": { "id": { "kind": "uuid", "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } } },
                "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
            },
            {
                "name": "Post", "tableName": "posts",
                "fields": {
                    "id":       { "kind": "uuid",    "pgType": "UUID", "primaryKey": true, "required": true, "unique": false, "default": { "kind": "genRandomUuid" } },
                    "authorId": { "kind": "relation","cardinality": "belongsTo","target": "User","foreignKey": "author_id","onDelete": "cascade" }
                },
                "access": {}, "indexes": [], "options": { "timestamps": false, "softDelete": false }
            }
        ]
    }"#;

    let ast = parser::parse(ast_json).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let rollback_sql = rollback::generate(&diff).unwrap();

    assert!(rollback_sql.contains("DROP CONSTRAINT"), "rollback must drop the FK constraint");
}
