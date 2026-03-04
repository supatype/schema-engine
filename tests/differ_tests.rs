use definatype_engine::{
    differ,
    introspector::{indexes::DbIndex, tables::{DbColumn, DbTable}},
    parser,
    state::database_state::DatabaseState,
};

#[test]
fn test_diff_empty_db_creates_all_tables() {
    let input = include_str!("fixtures/basic_blog.json");
    let ast = parser::parse(input).unwrap();
    let empty_db = DatabaseState::default();
    let diff = differ::diff(&ast, &empty_db).unwrap();

    let create_ops: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, differ::Operation::CreateTable { .. }))
        .collect();

    assert_eq!(create_ops.len(), ast.models.len());
    assert!(!diff.summary.is_destructive);
}

// Fix: options.timestamps columns (created_at, updated_at) must not be treated as
// dropped when they exist in the DB but are not explicit fields in the schema.
#[test]
fn test_timestamp_option_columns_not_treated_as_dropped() {
    let input = include_str!("fixtures/basic_blog.json");
    let ast = parser::parse(input).unwrap();

    // Simulate DB state after migration: tables include created_at/updated_at.
    let db = DatabaseState {
        tables: vec![
            DbTable {
                schema: "public".into(),
                name: "users".into(),
                columns: vec![
                    col("id", "uuid"),
                    col("email", "text"),
                    col("name", "text"),
                    col("created_at", "timestamp with time zone"),
                    col("updated_at", "timestamp with time zone"),
                ],
            },
            DbTable {
                schema: "public".into(),
                name: "posts".into(),
                columns: vec![
                    col("id", "uuid"),
                    col("title", "text"),
                    col("slug", "text"),
                    col("content", "jsonb"),
                    col("author_id", "uuid"),
                    col("created_at", "timestamp with time zone"),
                    col("updated_at", "timestamp with time zone"),
                ],
            },
        ],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    let drop_ops: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, differ::Operation::DropColumn { .. }))
        .collect();

    assert!(
        drop_ops.is_empty(),
        "options.timestamps columns must not be treated as dropped; got: {drop_ops:?}"
    );
}

// Fix: options.soft_delete column (deleted_at) must not be treated as dropped.
#[test]
fn test_soft_delete_option_column_not_treated_as_dropped() {
    let schema_json = r#"{
        "models": [{
            "name": "Article",
            "tableName": "articles",
            "fields": {
                "id": { "kind": "uuid", "pgType": "UUID", "primaryKey": true,
                        "required": true, "unique": false,
                        "default": { "kind": "genRandomUuid" } }
            },
            "access": {},
            "indexes": [],
            "options": { "timestamps": false, "softDelete": true }
        }]
    }"#;

    let ast = parser::parse(schema_json).unwrap();

    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "articles".into(),
            columns: vec![
                col("id", "uuid"),
                col("deleted_at", "timestamp with time zone"),
            ],
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    let drops_deleted_at: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, differ::Operation::DropColumn { column, .. } if column == "deleted_at"))
        .collect();

    assert!(
        drops_deleted_at.is_empty(),
        "options.softDelete 'deleted_at' must not be treated as a dropped column"
    );
}

// Fix: index_diff must derive the same default name as the SQL generator
// ({table}_{fields}_idx) so an already-applied index is not re-created on re-diff.
#[test]
fn test_existing_index_not_regenerated_when_name_matches() {
    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).unwrap();

    // posts has an index on ["author_id"]; derived name = "posts_author_id_idx".
    let db = DatabaseState {
        tables: ast.models.iter().map(|m| DbTable {
            schema: "public".into(),
            name: m.table_name.clone(),
            columns: vec![col("id", "uuid")],
        }).collect(),
        indexes: vec![DbIndex {
            table: "posts".into(),
            name: "posts_author_id_idx".into(),
            columns: vec!["author_id".into()],
            unique: false,
            method: "btree".into(),
            is_primary: false,
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    let add_index_for_posts: Vec<_> = diff.operations.iter()
        .filter(|op| matches!(op, differ::Operation::AddIndex { table, .. } if table == "posts"))
        .collect();

    assert!(
        add_index_for_posts.is_empty(),
        "index 'posts_author_id_idx' already exists — must not generate AddIndex op"
    );
}

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
