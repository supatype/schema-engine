//! Phase 1d of the managed-object ownership plan: one project per database, enforced.
//!
//! `_supatype.migrations` has no project column, `schema_state` is a single row and the cron jobs
//! are named without a schema, so two projects in one database already share history they should
//! not. The engine now records the project schema on first push and refuses a push for a
//! different one, naming both, rather than letting the second project silently diff against the
//! first's snapshot.

mod common;

use supatype_engine::{introspector, state::migration_history};

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
