use supatype_engine::{
    differ,
    introspector::{
        fingerprint::ObjectKind,
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
// anon/authenticated hold broad grants: world-readable, and writable by any
// signed-in user. The default is now deny: RLS on, no policies.
#[test]
fn test_models_without_access_get_rls_enabled_by_default() {
    let ast = parser::parse(&blog_ast_without_access()).unwrap();
    assert!(
        ast.models.iter().all(|m| m.access().read.is_none()),
        "access rules should have been stripped for this test",
    );

    // RLS on and no app policy, both the desired set's since Phase 4.8 (D9). Convergence is the
    // ledger's: `rls_ledger_tests` proves a second push leaves it alone. The only policies are the
    // two that admit a Studio user, whose Studio role decides rather than the app's rules (owner
    // decision 2026-10-21); every app caller is still denied.
    let desired = supatype_engine::desired::desired_objects(&ast, "public").unwrap();
    for model in &ast.models {
        let on_table = |kind: ObjectKind| {
            desired
                .iter()
                .filter(|o| o.key.kind == kind && o.key.parent == model.table_name())
                .map(|o| o.key.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            on_table(ObjectKind::RlsAttributes).len(),
            1,
            "expected RLS to be enabled for {}",
            model.table_name(),
        );
        let studio = ["studio_read", "studio_write"]
            .map(|suffix| supatype_engine::managed::policy_name(model.table_name(), suffix));
        assert_eq!(
            on_table(ObjectKind::Policy),
            studio.to_vec(),
            "a model without access rules must get no policy but Studio's"
        );
    }

    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    assert!(
        diff.warnings.iter().any(|w| w.contains("no access rules")),
        "the deny-all must be reported, got: {:?}",
        diff.warnings,
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

// A hand-written policy (SQL editor, psql) on a managed table is reported, because Postgres ORs
// it with ours. Dropping policies is the reconcile's (Phase 4.7b, `policy_ledger_tests`): the
// differ emits no policy operation at all, so it cannot drop one.
#[test]
fn test_unmanaged_policies_are_reported_and_never_dropped() {
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
    let policy_ops: Vec<_> = diff
        .operations
        .iter()
        .filter(|op| matches!(op, differ::Operation::CreateRlsPolicy { .. }))
        .collect();
    assert!(policy_ops.is_empty(), "{policy_ops:?}");

    let reported = diff
        .warnings
        .iter()
        .find(|w| w.contains("hand-written"))
        .unwrap_or_else(|| {
            panic!(
                "unmanaged policies must be reported, got {:?}",
                diff.warnings
            )
        });
    assert!(reported.contains("handwritten_extra"), "{reported}");
    assert!(
        !reported.contains(&format!("{table}_select")),
        "a stamped policy is an older engine's, not hand-written: {reported}"
    );
}

// A policy the ledger records as ours that the schema no longer declares (an `update` rule taken
// out) is the reconcile's to drop in this same push. Reporting it as hand-written and left
// untouched said the opposite of what the push does.
#[test]
fn a_ledger_policy_the_reconcile_drops_is_not_reported_as_hand_written() {
    use supatype_engine::introspector::{fingerprint::ObjectKey, rls::DbRlsPolicy};
    use supatype_engine::ledger::{LedgerRow, Status};

    let ast = parser::parse(&blog_ast_without_access()).unwrap();
    let table = ast.models[0].table_name().to_string();
    let policy = |name: &str| DbRlsPolicy {
        table: table.clone(),
        name: name.into(),
        command: "w".into(),
        permissive: true,
        using_expr: Some("true".into()),
        check_expr: None,
        managed: false,
    };
    let row = |name: &str, status| LedgerRow {
        key: ObjectKey {
            kind: ObjectKind::Policy,
            schema: "public".into(),
            parent: table.clone(),
            name: name.into(),
        },
        desired_fp: String::new(),
        desired_sql: String::new(),
        live_fp: String::new(),
        live_def: String::new(),
        status,
        migration_id: None,
    };
    let mut db = DatabaseState {
        schema: "public".into(),
        rls_enabled_tables: vec![table.clone()],
        rls_policies: vec![
            policy(&format!("{table}_update")),
            policy("released_rule"),
            policy("handwritten_extra"),
        ],
        ..DatabaseState::default()
    };
    db.set_table_ownership(&[
        row(&format!("{table}_update"), Status::Managed),
        row("released_rule", Status::Released),
    ]);

    let diff = differ::diff(&ast, &db).unwrap();
    let reported = diff
        .warnings
        .iter()
        .find(|w| w.contains("hand-written"))
        .expect("the hand-written policy is still reported");
    assert!(reported.contains("handwritten_extra"), "{reported}");
    assert!(
        reported.contains("released_rule"),
        "a released policy is the user's again: {reported}"
    );
    assert!(
        !reported.contains(&format!("{table}_update")),
        "the reconcile drops this one: {reported}"
    );
}
