/// Integration tests: the Postgres round trip and batch transaction semantics.
///
/// **Backends:**
/// - **`DATABASE_URL`** (CI / local): ephemeral database on that server, then `DROP DATABASE`.
/// - Otherwise **testcontainers** with **`supatype/postgres`** (PostGIS and pgvector, as in production).
mod common;

use common::with_integration_pool;
use supatype_engine::{differ, generator::sql::migration, introspector, parser};

// ─── Phase 1: Fresh schema application ───────────────────────────────────────

#[tokio::test]
async fn test_fresh_five_model_blog_schema() {
    with_integration_pool(|pool| async move {
        let input = include_str!("fixtures/five_model_blog.json");
        let ast = parser::parse(input).expect("schema must parse");
        assert_eq!(ast.models.len(), 5, "should have 5 models");

        let db_state = introspector::introspect(&pool, "public").await.unwrap();
        assert!(db_state.tables.is_empty(), "DB should be empty");

        let diff = differ::diff(&ast, &db_state).unwrap();
        assert!(
            !diff.summary.is_destructive,
            "fresh schema should have no destructive ops"
        );

        let create_table_count = diff
            .operations
            .iter()
            .filter(|op| matches!(op, differ::Operation::CreateTable { .. }))
            .count();
        assert_eq!(create_table_count, 5, "should create 5 tables");

        let sql = migration::generate(&diff, false, "public", &ast).unwrap();
        assert!(
            sql.contains("BEGIN;"),
            "migration must be wrapped in transaction"
        );
        assert!(sql.contains("COMMIT;"), "migration must commit");
        assert!(
            sql.contains("CREATE TABLE"),
            "migration must contain CREATE TABLE"
        );
        assert!(
            sql.contains("ROLLBACK MIGRATION"),
            "full migration file must contain rollback section"
        );

        common::push(&pool, &ast)
            .await
            .expect("migration must apply without error");

        let after = introspector::introspect(&pool, "public").await.unwrap();

        let table_names: Vec<&str> = after.tables.iter().map(|t| t.name.as_str()).collect();
        assert!(table_names.contains(&"users"), "users table must exist");
        assert!(
            table_names.contains(&"categories"),
            "categories table must exist"
        );
        assert!(table_names.contains(&"posts"), "posts table must exist");
        assert!(
            table_names.contains(&"comments"),
            "comments table must exist"
        );
        assert!(table_names.contains(&"tags"), "tags table must exist");

        let users = after.tables.iter().find(|t| t.name == "users").unwrap();
        let user_cols: Vec<&str> = users.columns.iter().map(|c| c.name.as_str()).collect();
        assert!(user_cols.contains(&"id"), "users.id must exist");
        assert!(user_cols.contains(&"email"), "users.email must exist");
        assert!(user_cols.contains(&"name"), "users.name must exist");
        assert!(
            user_cols.contains(&"created_at"),
            "users.created_at must exist"
        );
        assert!(
            user_cols.contains(&"updated_at"),
            "users.updated_at must exist"
        );

        let posts = after.tables.iter().find(|t| t.name == "posts").unwrap();
        let post_cols: Vec<&str> = posts.columns.iter().map(|c| c.name.as_str()).collect();
        assert!(
            post_cols.contains(&"author_id"),
            "posts.author_id FK must exist"
        );
        assert!(
            post_cols.contains(&"category_id"),
            "posts.category_id FK must exist"
        );
        assert!(post_cols.contains(&"slug"), "posts.slug must exist");
    })
    .await;
}

// ─── PostGIS / GeoPoint idempotency (regression for USER-DEFINED drift) ────────

fn is_type_drift_operation(op: &differ::Operation) -> bool {
    match op {
        differ::Operation::RecreateColumn { .. } => true,
        differ::Operation::AlterColumn { changes, .. } => changes.get("type").is_some(),
        _ => false,
    }
}

#[tokio::test]
async fn test_geospatial_schema_idempotent_after_push() {
    with_integration_pool(|pool| async move {
        let input = include_str!("fixtures/geospatial.json");
        let ast = parser::parse(input).expect("geospatial fixture parses");

        common::push(&pool, &ast)
            .await
            .expect("geospatial migration must apply");

        let after = introspector::introspect(&pool, "public").await.unwrap();
        let locations = after
            .tables
            .iter()
            .find(|t| t.name == "locations")
            .expect("locations table must exist");

        let point = locations
            .columns
            .iter()
            .find(|c| c.name == "point")
            .expect("point column must exist");
        assert_eq!(
            point.data_type.to_lowercase(),
            "user-defined",
            "PostGIS reports USER-DEFINED in information_schema"
        );
        assert_eq!(point.udt_name, "geography");

        let second_diff = differ::diff(&ast, &after).unwrap();
        let type_drift: Vec<_> = second_diff
            .operations
            .iter()
            .filter(|op| is_type_drift_operation(op))
            .collect();
        assert!(
            type_drift.is_empty(),
            "geospatial columns must not drift on second push, got: {type_drift:?}; all ops: {:?}; warnings: {:?}",
            second_diff.operations,
            second_diff.warnings
        );
        assert!(
            !second_diff
                .warnings
                .iter()
                .any(|w| w.contains("cannot cast geography")),
            "unexpected geo cast warning: {:?}",
            second_diff.warnings
        );
    })
    .await;
}

// ─── Phase 4: Idempotency + transaction batch semantics ─────────────────────

/// When `sqlx::raw_sql` sends a **BEGIN … COMMIT** script as one batch, PostgreSQL rolls back
/// the whole transaction if any statement fails. A push applies its migration the same way.
#[tokio::test]
async fn test_pg_batch_transaction_rollbacks_on_error() {
    with_integration_pool(|pool| async move {
        let sql = r#"
BEGIN;
CREATE TABLE supatype_engine_txn_probe (id int PRIMARY KEY);
CREATE TABLE supatype_engine_txn_probe (id int PRIMARY KEY);
COMMIT;
"#;

        let err = sqlx::raw_sql(sql).execute(&pool).await;
        assert!(
            err.is_err(),
            "duplicate CREATE should fail the batch, got Ok: {:?}",
            err
        );

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_name = 'supatype_engine_txn_probe'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(
            count, 0,
            "failed batch must not leave the first CREATE TABLE visible after rollback"
        );
    })
    .await;
}

#[tokio::test]
async fn test_idempotency_no_diff_after_apply() {
    with_integration_pool(|pool| async move {
        let input = include_str!("fixtures/five_model_blog.json");
        let ast = parser::parse(input).unwrap();

        common::push(&pool, &ast).await.unwrap();

        let second = supatype_engine::push::prepare(&pool, &ast, "public")
            .await
            .unwrap();
        assert_eq!(
            second.diff.operations.len(),
            0,
            "second push should produce zero operations (idempotency)"
        );
        let changes: Vec<_> = second
            .reconcile
            .actions
            .iter()
            .filter(|a| a.is_change())
            .collect();
        assert!(
            changes.is_empty(),
            "and change no owned object: {changes:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn test_up_to_date_push_records_initial_baseline_once() {
    use supatype_engine::generator::typescript::admin;
    use supatype_engine::state::migration_history;

    with_integration_pool(|pool| async move {
        let input = include_str!("fixtures/five_model_blog.json");
        let ast = parser::parse(input).unwrap();

        // The case under test is a database whose schema is current and whose history holds no
        // applied migration: a real first push, with every row it recorded then rolled back. The
        // `WHERE` is for the image's safe-update guard, which refuses an unqualified UPDATE.
        common::push(&pool, &ast).await.unwrap();
        sqlx::raw_sql("UPDATE _supatype.migrations SET rolled_back = true WHERE NOT rolled_back")
            .execute(&pool)
            .await
            .unwrap();

        let admin_cfg = admin::generate(&ast).unwrap();
        let schema_snap = serde_json::to_value(&ast).unwrap();

        let mut conn = pool.acquire().await.unwrap();
        migration_history::refresh_metadata_on_up_to_date_push(
            &mut conn,
            &admin_cfg,
            &schema_snap,
            &Default::default(),
        )
        .await
        .unwrap();
        migration_history::refresh_metadata_on_up_to_date_push(
            &mut conn,
            &admin_cfg,
            &schema_snap,
            &Default::default(),
        )
        .await
        .unwrap();
        drop(conn);

        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT FROM _supatype.migrations WHERE rolled_back = false",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count.0, 1, "noop push must not spam migration rows");

        let name: (String,) = sqlx::query_as(
            "SELECT name FROM _supatype.migrations WHERE rolled_back = false LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            name.0.starts_with("initial_"),
            "first noop push should record initial baseline, got {}",
            name.0
        );

        let admin_refresh_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT FROM _supatype.migrations WHERE name LIKE 'admin_refresh_%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(admin_refresh_count.0, 0);
    })
    .await;
}
