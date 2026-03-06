/// Phase 0 integration test — round-trip correctness.
///
/// Requires Docker to be running. Each test spins up a fresh Postgres 16
/// container via testcontainers, applies the generated migration, introspects
/// the resulting schema, and asserts the DB state matches the target AST.
use supatype_engine::{differ, generator::sql::migration, introspector, parser};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

// ─── Helper ──────────────────────────────────────────────────────────────────

async fn pg_url(port: u16) -> String {
    format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres")
}

// ─── Phase 1: Fresh schema application ───────────────────────────────────────

#[tokio::test]
async fn test_fresh_five_model_blog_schema() {
    let container = Postgres::default().start().await.expect("Docker must be running");
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = pg_url(port).await;

    let pool = sqlx::PgPool::connect(&url).await.unwrap();

    // Parse
    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).expect("schema must parse");
    assert_eq!(ast.models.len(), 5, "should have 5 models");

    // Diff against empty DB
    let db_state = introspector::introspect(&pool, "public").await.unwrap();
    assert!(db_state.tables.is_empty(), "DB should be empty");

    let diff = differ::diff(&ast, &db_state).unwrap();
    assert!(!diff.summary.is_destructive, "fresh schema should have no destructive ops");

    let create_table_count = diff.operations.iter()
        .filter(|op| matches!(op, differ::Operation::CreateTable { .. }))
        .count();
    assert_eq!(create_table_count, 5, "should create 5 tables");

    // Generate SQL
    let sql = migration::generate(&diff, false).unwrap();
    assert!(sql.contains("BEGIN;"), "migration must be wrapped in transaction");
    assert!(sql.contains("COMMIT;"), "migration must commit");
    assert!(sql.contains("CREATE TABLE"), "migration must contain CREATE TABLE");

    // Apply migration
    sqlx::raw_sql(&sql).execute(&pool).await
        .expect("migration must apply without error");

    // Introspect resulting DB state
    let after = introspector::introspect(&pool, "public").await.unwrap();

    // Assert all 5 tables were created
    let table_names: Vec<&str> = after.tables.iter().map(|t| t.name.as_str()).collect();
    assert!(table_names.contains(&"users"),      "users table must exist");
    assert!(table_names.contains(&"categories"), "categories table must exist");
    assert!(table_names.contains(&"posts"),      "posts table must exist");
    assert!(table_names.contains(&"comments"),   "comments table must exist");
    assert!(table_names.contains(&"tags"),       "tags table must exist");

    // Assert users has expected columns
    let users = after.tables.iter().find(|t| t.name == "users").unwrap();
    let user_cols: Vec<&str> = users.columns.iter().map(|c| c.name.as_str()).collect();
    assert!(user_cols.contains(&"id"),         "users.id must exist");
    assert!(user_cols.contains(&"email"),      "users.email must exist");
    assert!(user_cols.contains(&"name"),       "users.name must exist");
    assert!(user_cols.contains(&"created_at"), "users.created_at must exist");
    assert!(user_cols.contains(&"updated_at"), "users.updated_at must exist");

    // Assert posts has FK columns
    let posts = after.tables.iter().find(|t| t.name == "posts").unwrap();
    let post_cols: Vec<&str> = posts.columns.iter().map(|c| c.name.as_str()).collect();
    assert!(post_cols.contains(&"author_id"),   "posts.author_id FK must exist");
    assert!(post_cols.contains(&"category_id"), "posts.category_id FK must exist");
    assert!(post_cols.contains(&"slug"),        "posts.slug must exist");
}

// ─── Phase 4: Idempotency ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_idempotency_no_diff_after_apply() {
    let container = Postgres::default().start().await.expect("Docker must be running");
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = pg_url(port).await;
    let pool = sqlx::PgPool::connect(&url).await.unwrap();

    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).unwrap();

    // Apply once
    let empty = introspector::introspect(&pool, "public").await.unwrap();
    let diff = differ::diff(&ast, &empty).unwrap();
    let sql = migration::generate(&diff, false).unwrap();
    sqlx::raw_sql(&sql).execute(&pool).await.unwrap();

    // Diff again — should be empty
    let after = introspector::introspect(&pool, "public").await.unwrap();
    let second_diff = differ::diff(&ast, &after).unwrap();

    assert_eq!(
        second_diff.operations.len(), 0,
        "second push should produce zero operations (idempotency)"
    );
}
