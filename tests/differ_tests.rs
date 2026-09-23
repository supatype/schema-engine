use supatype_engine::{
    differ,
    generator::sql::migration,
    introspector::{
        indexes::DbIndex,
        tables::{DbColumn, DbTable},
    },
    parser,
    state::database_state::DatabaseState,
};

#[test]
fn test_diff_empty_db_creates_all_tables() {
    let input = include_str!("fixtures/basic_blog.json");
    let ast = parser::parse(input).unwrap();
    let empty_db = DatabaseState::default();
    let diff = differ::diff(&ast, &empty_db).unwrap();

    let create_ops: Vec<_> = diff
        .operations
        .iter()
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
                comment: Some("supatype:managed;kind=table".into()),
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
                comment: Some("supatype:managed;kind=table".into()),
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

    let drop_ops: Vec<_> = diff
        .operations
        .iter()
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
  "astVersion": 2,
  "models": [
    {
      "name": "Article",
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
          "tableName": "articles",
          "indexes": []
        },
        "platform": {
          "access": {}
        }
      }
    }
  ]
}"#;

    let ast = parser::parse(schema_json).unwrap();

    let db = DatabaseState {
        tables: vec![DbTable {
            schema: "public".into(),
            name: "articles".into(),
            comment: Some("supatype:managed;kind=table".into()),
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
        tables: ast
            .models
            .iter()
            .map(|m| DbTable {
                schema: "public".into(),
                name: m.table_name().to_string(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col("id", "uuid")],
            })
            .collect(),
        indexes: vec![DbIndex {
            table: "posts".into(),
            name: "posts_author_id_idx".into(),
            columns: vec!["author_id".into()],
            unique: false,
            method: "btree".into(),
            is_primary: false,
            comment: None,
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    let add_index_for_posts: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, differ::Operation::AddIndex { table, .. } if table == "posts"))
        .collect();

    assert!(
        add_index_for_posts.is_empty(),
        "index 'posts_author_id_idx' already exists — must not generate AddIndex op"
    );
}

/// An index whose *shape* changed has to be rebuilt, not matched by name and skipped.
///
/// The declared-index check was a name lookup, so adding `unique: true` to an index that already
/// existed planned no work at all. The schema said unique, the admin config said unique, Studio
/// showed a "unique" badge, and the database went on accepting duplicates. The generator would not
/// have saved it either: it emits `CREATE INDEX IF NOT EXISTS`, so even a planned add is a no-op
/// while the old index still holds the name.
#[test]
fn test_index_rebuilt_when_uniqueness_changes() {
    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).unwrap();

    // Same name and columns as the declared index, but not unique.
    let db = DatabaseState {
        tables: ast
            .models
            .iter()
            .map(|m| DbTable {
                schema: "public".into(),
                name: m.table_name().to_string(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col("id", "uuid")],
            })
            .collect(),
        indexes: vec![DbIndex {
            table: "posts".into(),
            name: "posts_author_id_idx".into(),
            columns: vec!["author_id".into()],
            unique: true,
            method: "btree".into(),
            is_primary: false,
            comment: None,
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    assert!(
        diff.operations
            .iter()
            .any(|op| matches!(op, differ::Operation::AddIndex { table, .. } if table == "posts")),
        "a mismatched index must be rebuilt: {:?}",
        diff.operations
    );

    // And the rebuild has to remove the old index on the way. A separate drop operation would not
    // do: adds are ordered before drops, so the pair would create nothing and then delete what was
    // there, leaving the table with no index at all.
    let sql = migration::forward_sql(&diff, true, "public", &ast).unwrap();
    let drop_at = sql
        .find(r#"DROP INDEX IF EXISTS "public"."posts_author_id_idx""#)
        .expect(&format!(
            "rebuild must drop the old index:
{sql}"
        ));
    let create_at = sql
        .find(r#"INDEX IF NOT EXISTS "posts_author_id_idx""#)
        .expect("rebuild must create the new index");
    assert!(
        drop_at < create_at,
        "the drop has to come first:
{sql}"
    );
}

/// The same lookup, on the column list rather than uniqueness.
#[test]
fn test_index_rebuilt_when_columns_change() {
    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).unwrap();

    let db = DatabaseState {
        tables: ast
            .models
            .iter()
            .map(|m| DbTable {
                schema: "public".into(),
                name: m.table_name().to_string(),
                comment: Some("supatype:managed;kind=table".into()),
                columns: vec![col("id", "uuid")],
            })
            .collect(),
        indexes: vec![DbIndex {
            table: "posts".into(),
            name: "posts_author_id_idx".into(),
            columns: vec!["title".into()],
            unique: false,
            method: "btree".into(),
            is_primary: false,
            comment: None,
        }],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();

    assert!(
        diff.operations
            .iter()
            .any(|op| matches!(op, differ::Operation::AddIndex { table, .. } if table == "posts")),
        "an index over different columns is a different index: {:?}",
        diff.operations
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
        ..Default::default()
    }
}

// A model that declares no `access` used to be published with RLS off while
// anon/authenticated hold broad grants — world-readable, and writable by any
// signed-in user. The default is now deny: RLS on, no policies.
#[test]
fn test_models_without_access_get_rls_enabled_by_default() {
    let ast = parser::parse(&blog_ast_without_access()).unwrap();
    assert!(
        ast.models.iter().all(|m| m.access().read.is_none()),
        "access rules should have been stripped for this test",
    );

    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();

    let enabled: Vec<&str> = diff
        .operations
        .iter()
        .filter_map(|op| match op {
            differ::Operation::EnableRls { table, .. } => Some(table.as_str()),
            _ => None,
        })
        .collect();

    for model in &ast.models {
        assert!(
            enabled.contains(&model.table_name()),
            "expected RLS to be enabled for {}",
            model.table_name(),
        );
    }

    // No policies may be created for them — RLS with zero policies is the deny.
    assert!(
        !diff
            .operations
            .iter()
            .any(|op| matches!(op, differ::Operation::CreateRlsPolicy { .. })),
        "a model without access rules must not get policies",
    );

    assert!(
        diff.warnings.iter().any(|w| w.contains("no access rules")),
        "the deny-all must be reported, got: {:?}",
        diff.warnings,
    );
}

// Convergence: RLS-enabled state is introspected, so an already-denied table
// must not be re-enabled on every push.
#[test]
fn test_rls_not_re_enabled_when_already_on() {
    let ast = parser::parse(&blog_ast_without_access()).unwrap();

    let db = DatabaseState {
        rls_enabled_tables: ast
            .models
            .iter()
            .map(|m| m.table_name().to_string())
            .collect(),
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    assert!(
        !diff
            .operations
            .iter()
            .any(|op| matches!(op, differ::Operation::EnableRls { .. })),
        "RLS was already enabled; expected no EnableRls operations",
    );
}

/// The shared fixture declares access rules; strip them to exercise the
/// "model author wrote no access block" default.
fn blog_ast_without_access() -> String {
    let mut value: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/basic_blog.json")).unwrap();
    for model in value["models"].as_array_mut().unwrap() {
        if let Some(platform) = model["annotations"]["platform"].as_object_mut() {
            platform.remove("access");
        }
    }
    value.to_string()
}

// Ownership: only Supatype-marked policies may be dropped. A hand-written policy
// (SQL editor, psql) must survive a push, or we silently delete access control the
// operator added.
#[test]
fn test_unmanaged_policies_are_not_dropped() {
    use supatype_engine::introspector::rls::DbRlsPolicy;

    let ast = parser::parse(&blog_ast_without_access()).unwrap();
    let table = ast.models[0].table_name().to_string();

    let db = DatabaseState {
        rls_enabled_tables: vec![table.clone()],
        rls_policies: vec![
            DbRlsPolicy {
                table: table.clone(),
                name: "handwritten_extra".into(),
                command: "r".into(),
                permissive: true,
                using_expr: Some("true".into()),
                check_expr: None,
                managed: false,
            },
            DbRlsPolicy {
                table: table.clone(),
                name: format!("{table}_select"),
                command: "r".into(),
                permissive: true,
                using_expr: Some("true".into()),
                check_expr: None,
                managed: true,
            },
        ],
        ..DatabaseState::default()
    };

    let diff = differ::diff(&ast, &db).unwrap();
    let dropped: Vec<&str> = diff
        .operations
        .iter()
        .filter_map(|op| match op {
            differ::Operation::DropRlsPolicy { policy, .. } => Some(policy.as_str()),
            _ => None,
        })
        .collect();

    assert!(
        !dropped.contains(&"handwritten_extra"),
        "an unmanaged policy must never be dropped, got {dropped:?}",
    );
    assert!(
        dropped.contains(&format!("{table}_select").as_str()),
        "the managed policy should be dropped for a model with no access rules, got {dropped:?}",
    );
    assert!(
        diff.warnings.iter().any(|w| w.contains("hand-written")),
        "unmanaged policies must be reported, got {:?}",
        diff.warnings,
    );
}
