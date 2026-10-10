//! Phase 1d of the managed-object ownership plan: one project per database, enforced.
//!
//! `_supatype.migrations` has no project column, `schema_state` is a single row and the cron jobs
//! are named without a schema, so two projects in one database already share history they should
//! not. The engine now records the project schema on first push and refuses a push for a
//! different one, naming both, rather than letting the second project silently diff against the
//! first's snapshot.

mod common;

use serde_json::json;
use supatype_engine::{
    inspect, introspector, parser, parser::ast::SchemaAst, push, state::migration_history,
};

#[tokio::test]
async fn the_first_push_records_the_project_schema_and_the_same_schema_passes() {
    common::with_integration_pool(|pool| async move {
        migration_history::bootstrap_internal_state(&pool)
            .await
            .unwrap();

        // Nothing recorded yet: any schema may claim the database.
        migration_history::assert_project_schema(&pool, "public")
            .await
            .expect("fresh database");
        migration_history::assert_project_schema(&pool, "tenant")
            .await
            .expect("still unclaimed");

        let state = introspector::introspect(&pool, "public").await.unwrap();
        migration_history::save_schema_state(&pool, &state)
            .await
            .unwrap();

        migration_history::assert_project_schema(&pool, "public")
            .await
            .expect("the recorded schema");
    })
    .await;
}

#[tokio::test]
async fn a_push_for_a_different_schema_is_refused_naming_both() {
    common::with_integration_pool(|pool| async move {
        migration_history::bootstrap_internal_state(&pool)
            .await
            .unwrap();
        let state = introspector::introspect(&pool, "public").await.unwrap();
        migration_history::save_schema_state(&pool, &state)
            .await
            .unwrap();

        let err = migration_history::assert_project_schema(&pool, "tenant_b")
            .await
            .expect_err("a second project must not share this database");
        let message = err.to_string();
        assert!(message.contains("public"), "{message}");
        assert!(message.contains("tenant_b"), "{message}");
    })
    .await;
}

#[tokio::test]
async fn a_database_from_before_the_guard_is_claimed_by_its_next_push() {
    common::with_integration_pool(|pool| async move {
        migration_history::bootstrap_internal_state(&pool)
            .await
            .unwrap();
        let state = introspector::introspect(&pool, "public").await.unwrap();
        migration_history::save_schema_state(&pool, &state)
            .await
            .unwrap();
        // What an older engine left behind: a schema_state row with no project schema.
        sqlx::raw_sql("UPDATE _supatype.schema_state SET project_schema = NULL WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();

        migration_history::assert_project_schema(&pool, "public")
            .await
            .expect("legacy row passes");
        migration_history::save_schema_state(&pool, &state)
            .await
            .unwrap();

        let recorded: Option<String> =
            sqlx::query_scalar("SELECT project_schema FROM _supatype.schema_state WHERE id = 1")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(recorded.as_deref(), Some("public"));
    })
    .await;
}

#[tokio::test]
async fn a_legacy_row_is_claimed_by_the_schema_its_snapshot_names_not_by_the_next_push() {
    common::with_integration_pool(|pool| async move {
        migration_history::bootstrap_internal_state(&pool)
            .await
            .unwrap();
        let state = introspector::introspect(&pool, "public").await.unwrap();
        migration_history::save_schema_state(&pool, &state)
            .await
            .unwrap();
        // What an older engine left behind: a snapshot of `public`, no project schema.
        sqlx::raw_sql("UPDATE _supatype.schema_state SET project_schema = NULL WHERE id = 1")
            .execute(&pool)
            .await
            .unwrap();

        // Every push bootstraps before it checks.
        migration_history::bootstrap_internal_state(&pool)
            .await
            .unwrap();
        let err = migration_history::assert_project_schema(&pool, "tenant_b")
            .await
            .expect_err("the snapshot says this database is public's");
        assert!(err.to_string().contains("tenant_b"), "{err}");
        migration_history::assert_project_schema(&pool, "public")
            .await
            .expect("the project the snapshot names");
    })
    .await;
}

#[tokio::test]
async fn a_rollback_for_a_different_schema_is_refused() {
    common::with_integration_pool(|pool| async move {
        migration_history::bootstrap_internal_state(&pool)
            .await
            .unwrap();
        let state = introspector::introspect(&pool, "public").await.unwrap();
        migration_history::save_schema_state(&pool, &state)
            .await
            .unwrap();
        sqlx::raw_sql(
            "INSERT INTO _supatype.migrations (name, hash, engine_version, sql_up, sql_down)
             VALUES ('m1', 'sha256:x', 'test', 'SELECT 1;', 'SELECT 1;')",
        )
        .execute(&pool)
        .await
        .unwrap();

        let err = migration_history::apply_rollback(&pool, "tenant_b")
            .await
            .expect_err("another project's history is not this one's to roll back");
        assert!(err.to_string().contains("tenant_b"), "{err}");
        let rolled_back: bool =
            sqlx::query_scalar("SELECT rolled_back FROM _supatype.migrations WHERE name = 'm1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!rolled_back);
    })
    .await;
}

/// Two tables anyone may read and a signed-in user may write, as the verification scripts made
/// them: policies, grants and the `_platform` helpers to drift.
fn two_tables_with_access() -> SchemaAst {
    let table = |name: &str, model: &str, column: &str| {
        json!({
            "name": model,
            "fields": {
                "id": { "kind": "uuid", "required": true, "primaryKey": true,
                        "default": { "kind": "genRandomUuid" },
                        "annotations": { "db": { "pgType": "UUID", "unique": false } } },
                column: { "kind": "text", "required": false,
                          "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
            },
            "options": { "timestamps": false, "softDelete": false },
            "annotations": {
                "db": { "tableName": name, "indexes": [] },
                "platform": { "access": {
                    "read": { "type": "public" },
                    "create": { "type": "role", "roles": ["authenticated"] },
                    "update": { "type": "role", "roles": ["authenticated"] },
                    "delete": { "type": "role", "roles": ["authenticated"] } } }
            }
        })
    };
    let doc = json!({ "astVersion": 2,
                      "models": [table("t1", "T1", "a"), table("t2", "T2", "b")] });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// Every ledger row with its fingerprints, in key order.
async fn ledger(pool: &sqlx::PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT concat_ws(' ', kind, schema_name, parent, name, desired_fp, live_fp, status)
           FROM _supatype.managed_objects ORDER BY kind, schema_name, parent, name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// E14b: `doctor`, `doctor --rebaseline` (with and without consent for access drift), `diff` and
/// `migrate` all assert the project, as push and adopt do. A rebaseline for another schema
/// rewrote this project's ledger row for `_platform.slugify(text)`.
#[tokio::test]
async fn every_command_refuses_another_projects_database() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql("CREATE SCHEMA app1; CREATE SCHEMA app2")
            .execute(&pool)
            .await
            .unwrap();
        let ast = two_tables_with_access();
        let plan = push::prepare(&pool, &ast, "app1").await.unwrap();
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap();
        // Drift on a helper the project's ledger records, so a rebaseline has something to take.
        sqlx::raw_sql(
            "CREATE OR REPLACE FUNCTION _platform.slugify(val text) RETURNS text
               LANGUAGE sql IMMUTABLE AS $$ SELECT lower(val) $$",
        )
        .execute(&pool)
        .await
        .unwrap();
        let before = ledger(&pool).await;

        let refused = |what: &str, e: anyhow::Error| {
            let message = format!("{e:#}");
            assert!(
                message.contains("\"app1\"") && message.contains("\"app2\""),
                "{what} was not refused for the project: {message}"
            );
        };
        let doctor = inspect::doctor(&pool, &ast, "app2", false).await;
        refused("doctor", doctor.expect_err("doctor ran for app2"));
        for consent in [false, true] {
            let rebaseline = inspect::rebaseline(&pool, &ast, "app2", consent).await;
            refused("rebaseline", rebaseline.expect_err("rebaselined app2"));
        }
        // `diff` and `migrate` are both this plan.
        match push::plan(&pool, &ast, "app2").await {
            Ok(_) => panic!("diff and migrate planned app2 against app1's database"),
            Err(e) => refused("diff and migrate", e),
        }
        assert_eq!(ledger(&pool).await, before, "app1's ledger was rewritten");
    })
    .await;
}
