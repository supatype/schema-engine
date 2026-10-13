//! `_supatype.studio_identity_links`: which project user a Supatype Cloud account acts as in Studio.
//!
//! Cloud mints a short-lived project token for a member's linked project user, so RLS and field
//! masks apply to them as the app would apply them. The link is its own table, not a second id on a
//! `studio_members` row, so a membership row still names exactly one identity and self-host's
//! lookups by `user_id` mean what they always did.

mod common;

use supatype_engine::state::migration_history;

const PLATFORM_USER: &str = "aaaaaaaa-1111-2222-3333-444444444444";
const OTHER_PLATFORM_USER: &str = "bbbbbbbb-1111-2222-3333-444444444444";
const PROJECT_USER: &str = "cccccccc-1111-2222-3333-444444444444";

async fn create_auth_users(pool: &sqlx::PgPool) {
    sqlx::raw_sql(
        "CREATE SCHEMA IF NOT EXISTS auth;
         CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY, email TEXT);",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_link(pool: &sqlx::PgPool, platform: &str, user: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO _supatype.studio_identity_links (platform_user_id, user_id, email)
         VALUES ($1::uuid, $2::uuid, 'dev@example.com')",
    )
    .bind(platform)
    .bind(user)
    .execute(pool)
    .await
    .map(|_| ())
}

async fn link_count(pool: &sqlx::PgPool) -> i64 {
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM _supatype.studio_identity_links")
        .fetch_one(pool)
        .await
        .unwrap();
    count
}

// The table is created by every push's bootstrap, beside the membership table, and is keyed by the
// cloud account so one account links to one project user.
#[tokio::test]
async fn bootstrap_creates_the_link_table() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        sqlx::raw_sql(&format!(
            "INSERT INTO auth.users (id, email) VALUES ('{PROJECT_USER}', 'dev@example.com')"
        ))
        .execute(&pool)
        .await
        .unwrap();
        migration_history::bootstrap_internal_state(&pool)
            .await
            .unwrap();

        insert_link(&pool, PLATFORM_USER, PROJECT_USER)
            .await
            .expect("a cloud account links to a project user");
        assert!(
            insert_link(&pool, PLATFORM_USER, PROJECT_USER)
                .await
                .is_err(),
            "one link per cloud account"
        );
        assert!(
            insert_link(&pool, OTHER_PLATFORM_USER, PROJECT_USER)
                .await
                .is_err(),
            "two cloud accounts cannot act as the same project user"
        );
    })
    .await;
}

// A deleted project user takes their link with them, so the member fails closed instead of acting
// as an id that no longer exists.
#[tokio::test]
async fn deleting_the_project_user_removes_the_link() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        sqlx::raw_sql(&format!(
            "INSERT INTO auth.users (id, email) VALUES ('{PROJECT_USER}', 'dev@example.com')"
        ))
        .execute(&pool)
        .await
        .unwrap();
        migration_history::bootstrap_internal_state(&pool)
            .await
            .unwrap();
        insert_link(&pool, PLATFORM_USER, PROJECT_USER)
            .await
            .unwrap();

        sqlx::raw_sql(&format!(
            "DELETE FROM auth.users WHERE id = '{PROJECT_USER}'"
        ))
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(link_count(&pool).await, 0);
    })
    .await;
}

// A project with no auth schema still bootstraps; the link table then has no foreign key to add.
#[tokio::test]
async fn bootstrap_tolerates_a_missing_auth_schema() {
    common::with_integration_pool(|pool| async move {
        migration_history::bootstrap_internal_state(&pool)
            .await
            .expect("bootstrap runs without auth.users");
        assert_eq!(link_count(&pool).await, 0);
    })
    .await;
}

// The statements are idempotent, and a table made before auth existed gains the foreign key once
// auth.users is there.
#[tokio::test]
async fn link_statements_are_idempotent_and_add_the_foreign_key_later() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(migration_history::create_internal_schema_sql())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(&migration_history::create_studio_identity_links_table_sql())
            .execute(&pool)
            .await
            .unwrap();
        create_auth_users(&pool).await;
        for _ in 0..2 {
            sqlx::raw_sql(&migration_history::create_studio_identity_links_table_sql())
                .execute(&pool)
                .await
                .expect("idempotent");
        }
        assert!(
            insert_link(&pool, PLATFORM_USER, PROJECT_USER)
                .await
                .is_err(),
            "the foreign key refuses a link to a user who does not exist"
        );
    })
    .await;
}

// Self-host semantics are unchanged: a membership row still holds exactly one identity.
#[test]
fn membership_rows_still_hold_one_identity() {
    let sql = migration_history::create_studio_members_table_sql();
    assert!(
        sql.contains("CHECK (num_nonnulls(user_id, platform_user_id) = 1)"),
        "got: {sql}"
    );
}
