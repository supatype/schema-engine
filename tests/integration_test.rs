/// Integration tests — Postgres round-trip and batch transaction semantics.
///
/// **Two backends:**
/// - If **`DATABASE_URL`** is set (e.g. GitHub Actions service Postgres), each test creates an
///   ephemeral database on that server, runs, then **`DROP DATABASE`**. No Docker required.
/// - Otherwise uses **testcontainers** (Docker must be available).
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};

use supatype_engine::{differ, generator::sql::migration, introspector, parser};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

static EPHEMERAL_SEQ: AtomicU64 = AtomicU64::new(0);

fn database_url_with_name(admin_url: &str, db: &str) -> String {
    let (base, query) = match admin_url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (admin_url, None),
    };
    let prefix = base
        .rsplit_once('/')
        .expect("DATABASE_URL must include /dbname (e.g. …/postgres)")
        .0;
    match query {
        Some(q) => format!("{}/{}?{}", prefix, db, q),
        None => format!("{}/{}", prefix, db),
    }
}

async fn terminate_db_sessions(admin: &sqlx::PgPool, db_name: &str) {
    let safe = db_name.replace('\'', "''");
    let sql = format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE datname = '{safe}' AND pid <> pg_backend_pid()"
    );
    let _ = sqlx::raw_sql(&sql).execute(admin).await;
}

/// Runs `f` against an isolated Postgres (ephemeral DB or testcontainers).
/// Skips the test when `DATABASE_URL` is unset and Docker/testcontainers is unavailable.
async fn with_integration_pool<F, Fut>(f: F)
where
    F: FnOnce(sqlx::PgPool) -> Fut,
    Fut: Future<Output = ()>,
{
    if std::env::var("DATABASE_URL").is_ok() {
        with_ephemeral_database(f).await;
        return;
    }

    let container = match Postgres::default().start().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "SKIP integration_test: DATABASE_URL not set and Docker unavailable ({e})"
            );
            return;
        }
    };
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pool = sqlx::PgPool::connect(&url)
        .await
        .expect("connect testcontainers postgres");
    f(pool.clone()).await;
    pool.close().await;
    drop(container);
}

async fn with_ephemeral_database<F, Fut>(f: F)
where
    F: FnOnce(sqlx::PgPool) -> Fut,
    Fut: Future<Output = ()>,
{
    let admin_url =
        std::env::var("DATABASE_URL").expect("with_ephemeral_database requires DATABASE_URL");
    let admin = sqlx::PgPool::connect(&admin_url)
        .await
        .expect("DATABASE_URL: connect admin pool");
    let n = EPHEMERAL_SEQ.fetch_add(1, Ordering::SeqCst);
    let db_name = format!("st_engine_it_{}_{}", std::process::id(), n);
    assert!(
        db_name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
        "generated db name must be a safe identifier: {db_name}"
    );

    sqlx::raw_sql(&format!(r#"CREATE DATABASE "{db_name}""#))
        .execute(&admin)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "CREATE DATABASE {db_name} failed: {e} \
                 (DATABASE_URL user needs CREATEDB / superuser)"
            )
        });

    let child_url = database_url_with_name(&admin_url, &db_name);
    let pool = sqlx::PgPool::connect(&child_url)
        .await
        .unwrap_or_else(|e| panic!("connect ephemeral database {db_name}: {e}"));

    f(pool.clone()).await;
    pool.close().await;

    terminate_db_sessions(&admin, &db_name).await;
    let _ = sqlx::raw_sql(&format!(r#"DROP DATABASE IF EXISTS "{db_name}""#))
        .execute(&admin)
        .await;
    admin.close().await;
}

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
        let apply_sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
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

        sqlx::raw_sql(&apply_sql)
            .execute(&pool)
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

// ─── Phase 4: Idempotency + transaction batch semantics ─────────────────────

/// When `sqlx::raw_sql` sends a **BEGIN … COMMIT** script as one batch, PostgreSQL rolls back
/// the whole transaction if any statement fails — same mechanism used by `migration::forward_sql`.
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

        let empty = introspector::introspect(&pool, "public").await.unwrap();
        let diff = differ::diff(&ast, &empty).unwrap();
        let apply_sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&apply_sql).execute(&pool).await.unwrap();

        let after = introspector::introspect(&pool, "public").await.unwrap();
        let second_diff = differ::diff(&ast, &after).unwrap();

        assert_eq!(
            second_diff.operations.len(),
            0,
            "second push should produce zero operations (idempotency)"
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

        let empty = introspector::introspect(&pool, "public").await.unwrap();
        let diff = differ::diff(&ast, &empty).unwrap();
        let apply_sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&apply_sql).execute(&pool).await.unwrap();

        sqlx::raw_sql(migration_history::create_internal_schema_sql())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(&migration_history::create_migrations_table_sql())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(&migration_history::create_schema_state_table_sql())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(&migration_history::ensure_schema_state_studio_columns_sql())
            .execute(&pool)
            .await
            .unwrap();

        let admin_cfg = admin::generate(&ast).unwrap();
        let schema_snap = serde_json::to_value(&ast).unwrap();

        migration_history::refresh_metadata_on_up_to_date_push(&pool, &admin_cfg, &schema_snap)
            .await
            .unwrap();
        migration_history::refresh_metadata_on_up_to_date_push(&pool, &admin_cfg, &schema_snap)
            .await
            .unwrap();

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
