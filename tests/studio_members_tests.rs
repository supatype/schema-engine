//! Studio membership bootstrap — `_supatype.studio_members` is the sole grant
//! for admin-UI access, so the SQL that creates and seeds it is load-bearing.

mod common;

use supatype_engine::state::migration_history;

#[test]
fn members_table_lives_outside_the_data_plane() {
    let sql = migration_history::create_studio_members_table_sql();

    // `_supatype` is absent from PGRST_DB_SCHEMAS. Putting this table anywhere
    // reachable through PostgREST would let the developer's own API surface hand
    // out Studio access.
    assert!(sql.contains("_supatype.studio_members"), "got: {sql}");
    assert!(sql.contains("CREATE TABLE IF NOT EXISTS"), "got: {sql}");
    assert!(sql.contains("user_id     UUID PRIMARY KEY"), "got: {sql}");
}

// Studio access moved out of JWT claims. Without a seed, the first push after
// that change locks every existing admin out of their own Studio.
#[test]
fn seed_carries_forward_existing_admin_claims() {
    let sql = migration_history::seed_studio_members_from_claims_sql();

    assert!(sql.contains("INSERT INTO _supatype.studio_members"), "got: {sql}");
    assert!(sql.contains("raw_app_meta_data->>'role'"), "got: {sql}");
}

// `authenticated` is GoTrue's default for every signed-in user, so treating it
// as a Studio role would admit the entire user base.
#[test]
fn seed_excludes_the_default_authenticated_role() {
    let sql = migration_history::seed_studio_members_from_claims_sql();
    assert!(sql.contains("<> 'authenticated'"), "got: {sql}");
}

// Runs only while the table is empty, so it cannot resurrect access that was
// deliberately revoked after the migration.
#[test]
fn seed_is_skipped_once_membership_exists() {
    let sql = migration_history::seed_studio_members_from_claims_sql();
    assert!(
        sql.contains("IF NOT EXISTS (SELECT 1 FROM _supatype.studio_members)"),
        "got: {sql}"
    );
}

// A project with no GoTrue schema (never pushed, or auth disabled) must not fail
// its push because the seed referenced a missing table.
#[test]
fn seed_tolerates_a_missing_auth_schema() {
    let sql = migration_history::seed_studio_members_from_claims_sql();
    assert!(sql.contains("table_schema = 'auth'"), "got: {sql}");
    assert!(sql.contains("table_name = 'users'"), "got: {sql}");
}

// ── Against a live Postgres ──────────────────────────────────────────────────

async fn seed_and_list(pool: &sqlx::PgPool) -> Vec<(String, String)> {
    sqlx::raw_sql(&migration_history::seed_studio_members_from_claims_sql())
        .execute(pool)
        .await
        .expect("seed runs");
    sqlx::query_as::<_, (String, String)>(
        "SELECT u.email, m.role
           FROM _supatype.studio_members m
           JOIN auth.users u ON u.id = m.user_id
          ORDER BY u.email",
    )
    .fetch_all(pool)
    .await
    .expect("list members")
}

#[tokio::test]
async fn seed_promotes_only_real_admin_claims() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(migration_history::create_internal_schema_sql())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(&migration_history::create_studio_members_table_sql())
            .execute(&pool)
            .await
            .unwrap();

        // A project with no auth schema at all: the seed must be a no-op, not an
        // error that aborts the push.
        sqlx::raw_sql(&migration_history::seed_studio_members_from_claims_sql())
            .execute(&pool)
            .await
            .expect("seed tolerates a missing auth.users");

        sqlx::raw_sql(
            r#"CREATE SCHEMA auth;
               CREATE TABLE auth.users (
                 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                 email TEXT UNIQUE,
                 raw_app_meta_data JSONB DEFAULT '{}'
               );
               INSERT INTO auth.users (email, raw_app_meta_data) VALUES
                 ('admin@example.com',  '{"role":"admin"}'),
                 ('editor@example.com', '{"role":"editor"}'),
                 ('user@example.com',   '{"role":"authenticated"}'),
                 ('blank@example.com',  '{"role":""}'),
                 ('none@example.com',   '{"provider":"email"}');"#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let members = seed_and_list(&pool).await;
        assert_eq!(
            members,
            vec![
                ("admin@example.com".to_string(), "admin".to_string()),
                ("editor@example.com".to_string(), "editor".to_string()),
            ],
            "only real admin-panel roles carry forward"
        );

        // Idempotent: a second push must not disturb the table.
        let again = seed_and_list(&pool).await;
        assert_eq!(again, members, "re-running the seed changes nothing");

        // Revocation must stick. Removing an admin leaves the table non-empty, so
        // the guard keeps the next push from handing the access back.
        sqlx::raw_sql(
            "DELETE FROM _supatype.studio_members m
              USING auth.users u
              WHERE u.id = m.user_id AND u.email = 'editor@example.com'",
        )
        .execute(&pool)
        .await
        .unwrap();

        let after_revoke = seed_and_list(&pool).await;
        assert_eq!(
            after_revoke,
            vec![("admin@example.com".to_string(), "admin".to_string())],
            "a revoked member must not be resurrected by the seed"
        );
    })
    .await;
}
