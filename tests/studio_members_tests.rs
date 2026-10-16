//! Studio membership bootstrap. `_supatype.studio_members` is the sole grant
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
}

// A row belongs to exactly one identity space, a project user or a cloud
// account, so neither lookup can match a row it was not meant to.
#[test]
fn members_table_tags_the_identity_space_of_every_row() {
    let sql = migration_history::create_studio_members_table_sql();
    assert!(sql.contains("user_id           UUID UNIQUE"), "got: {sql}");
    assert!(sql.contains("platform_user_id  UUID UNIQUE"), "got: {sql}");
    assert!(
        sql.contains("CHECK (num_nonnulls(user_id, platform_user_id) = 1)"),
        "got: {sql}"
    );
}

// Studio access moved out of JWT claims. Without a seed, the first push after
// that change locks every existing admin out of their own Studio.
#[test]
fn seed_carries_forward_existing_admin_claims() {
    let sql = migration_history::seed_studio_members_from_claims_sql();

    assert!(
        sql.contains("INSERT INTO _supatype.studio_members"),
        "got: {sql}"
    );
    assert!(sql.contains("raw_app_meta_data->>'role'"), "got: {sql}");
}

// `app_metadata.role` is the developer's own namespace, so it holds arbitrary
// application roles that never granted Studio access. Only the roles that
// actually admitted anyone may carry over, and `authenticated` is GoTrue's
// default for every signed-in user, so it would admit the entire user base.
#[test]
fn seed_only_promotes_roles_that_granted_access() {
    let sql = migration_history::seed_studio_members_from_claims_sql();
    assert!(
        sql.contains("IN ('admin', 'supatype_admin')"),
        "seed must be limited to the default STUDIO_ADMIN_ROLES: {sql}"
    );
    assert!(!sql.contains("'authenticated'"), "got: {sql}");
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

// "Who gave this person admin, and when" has to be answerable months later, so
// the trail is a table rather than a log line that rotates away, and it lives in
// `_supatype` for the same reason `studio_members` does.
#[test]
fn audit_trail_records_who_changed_what() {
    let sql = migration_history::create_studio_audit_table_sql();
    assert!(sql.contains("_supatype.studio_audit"), "got: {sql}");
    assert!(sql.contains("action      TEXT NOT NULL"), "got: {sql}");
    // Both ids are nullable: a change can come from the CLI with no signed-in
    // actor, and not every audited event is *about* someone: an elevated request
    // has an actor and no target.
    assert!(sql.contains("actor_id    UUID,"), "got: {sql}");
    assert!(sql.contains("target_id   UUID,"), "got: {sql}");
    assert!(sql.contains("detail      JSONB"), "got: {sql}");
}

// An audit table created for membership changes only must reach the shape that
// also records elevated access, or the first elevated write fails on a NOT NULL.
#[tokio::test]
async fn audit_table_migrates_to_record_elevated_access() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(migration_history::create_internal_schema_sql())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(
            r#"CREATE TABLE _supatype.studio_audit (
                 id BIGSERIAL PRIMARY KEY,
                 actor_id UUID,
                 target_id UUID NOT NULL,
                 action TEXT NOT NULL,
                 role TEXT,
                 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
               );
               INSERT INTO _supatype.studio_audit (actor_id, target_id, action, role)
               VALUES (NULL, '11111111-2222-3333-4444-555555555555', 'set_role', 'admin');"#,
        )
        .execute(&pool)
        .await
        .unwrap();

        for _ in 0..2 {
            sqlx::raw_sql(&migration_history::ensure_studio_audit_columns_sql())
                .execute(&pool)
                .await
                .expect("audit migration is idempotent");
        }

        sqlx::raw_sql(
            r#"INSERT INTO _supatype.studio_audit (actor_id, target_id, action, detail)
               VALUES ('99999999-8888-7777-6666-555555555555', NULL, 'elevated_request',
                       '{"method":"PATCH","path":"/rest/v1/posts"}')"#,
        )
        .execute(&pool)
        .await
        .expect("an elevated request has no target");

        let (kept,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM _supatype.studio_audit WHERE action = 'set_role'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(kept, 1, "existing audit records must survive the migration");
    })
    .await;
}

// The migration must be safe before the table exists: bootstrap order should not
// be load-bearing.
#[tokio::test]
async fn audit_migration_tolerates_a_missing_table() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(migration_history::create_internal_schema_sql())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(&migration_history::ensure_studio_audit_columns_sql())
            .execute(&pool)
            .await
            .expect("audit migration is a no-op with no table");
    })
    .await;
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

// The pre-cloud table had `user_id` as its primary key and no second identity.
// A push against it must reach the current shape without losing its rows.
#[tokio::test]
async fn existing_tables_migrate_to_the_two_identity_shape() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(migration_history::create_internal_schema_sql())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(
            r#"CREATE TABLE _supatype.studio_members (
                 user_id     UUID PRIMARY KEY,
                 role        TEXT NOT NULL,
                 created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                 updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
               );
               INSERT INTO _supatype.studio_members (user_id, role)
               VALUES ('11111111-2222-3333-4444-555555555555', 'admin');"#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::raw_sql(&migration_history::ensure_studio_members_platform_identity_sql())
            .execute(&pool)
            .await
            .expect("migration runs against the pre-cloud table");

        let (kept,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM _supatype.studio_members
              WHERE user_id = '11111111-2222-3333-4444-555555555555' AND role = 'admin'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(kept, 1, "existing grants must survive the migration");

        // A cloud account can now hold a membership.
        sqlx::raw_sql(
            "INSERT INTO _supatype.studio_members (platform_user_id, role)
             VALUES ('99999999-8888-7777-6666-555555555555', 'editor')",
        )
        .execute(&pool)
        .await
        .expect("platform identities are accepted after the migration");

        // Neither identity may be omitted, and a row may not claim both.
        for bad in [
            "INSERT INTO _supatype.studio_members (role) VALUES ('admin')",
            "INSERT INTO _supatype.studio_members (user_id, platform_user_id, role)
               VALUES ('22222222-2222-2222-2222-222222222222',
                       '33333333-3333-3333-3333-333333333333', 'admin')",
        ] {
            assert!(
                sqlx::raw_sql(bad).execute(&pool).await.is_err(),
                "expected the identity CHECK to reject: {bad}"
            );
        }

        // Idempotent: a second push must not fail on the migrated table.
        sqlx::raw_sql(&migration_history::ensure_studio_members_platform_identity_sql())
            .execute(&pool)
            .await
            .expect("migration is idempotent");
    })
    .await;
}

// A fresh table already has the target shape, so the migration must be a no-op
// rather than trying to move a primary key that is already where it belongs.
#[tokio::test]
async fn migration_is_a_no_op_on_a_fresh_table() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(migration_history::create_internal_schema_sql())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(&migration_history::create_studio_members_table_sql())
            .execute(&pool)
            .await
            .unwrap();

        for _ in 0..2 {
            sqlx::raw_sql(&migration_history::ensure_studio_members_platform_identity_sql())
                .execute(&pool)
                .await
                .expect("migration is safe on a fresh table");
        }

        let (pk_col,): (String,) = sqlx::query_as(
            "SELECT a.attname FROM pg_constraint c
               JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
              WHERE c.conrelid = '_supatype.studio_members'::regclass AND c.contype = 'p'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(pk_col, "id");
    })
    .await;
}

// The migration must also work when the table does not exist yet: bootstrap
// order should not be load-bearing.
#[tokio::test]
async fn migration_tolerates_a_missing_table() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(migration_history::create_internal_schema_sql())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(&migration_history::ensure_studio_members_platform_identity_sql())
            .execute(&pool)
            .await
            .expect("migration is a no-op with no table");
    })
    .await;
}

// The membership API writes here on every change, so a project that has been
// pushed must always have the table, and a second push must not disturb it.
#[tokio::test]
async fn audit_table_is_created_and_idempotent() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(migration_history::create_internal_schema_sql())
            .execute(&pool)
            .await
            .unwrap();
        for _ in 0..2 {
            sqlx::raw_sql(&migration_history::create_studio_audit_table_sql())
                .execute(&pool)
                .await
                .expect("audit table creation is idempotent");
        }

        sqlx::raw_sql(
            "INSERT INTO _supatype.studio_audit (actor_id, target_id, action, role)
             VALUES (NULL, '11111111-2222-3333-4444-555555555555', 'set_role', 'editor')",
        )
        .execute(&pool)
        .await
        .expect("an unattributed change is still recordable");

        let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM _supatype.studio_audit")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    })
    .await;
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
            // The integration database is shared, so this fixture must be able to
            // run after another test has already created the auth schema. Without
            // this the suite passes or fails on ordering, which is worse than a
            // failure -- it makes a real regression indistinguishable from a race.
            r#"CREATE SCHEMA IF NOT EXISTS auth;
               DROP TABLE IF EXISTS auth.users CASCADE;
               CREATE TABLE auth.users (
                 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                 email TEXT UNIQUE,
                 raw_app_meta_data JSONB DEFAULT '{}'
               );
               INSERT INTO auth.users (email, raw_app_meta_data) VALUES
                 ('admin@example.com',    '{"role":"admin"}'),
                 ('platform@example.com', '{"role":"supatype_admin"}'),
                 ('moderator@example.com','{"role":"moderator"}'),
                 ('user@example.com',     '{"role":"authenticated"}'),
                 ('blank@example.com',    '{"role":""}'),
                 ('none@example.com',     '{"provider":"email"}');"#,
        )
        .execute(&pool)
        .await
        .unwrap();

        let members = seed_and_list(&pool).await;
        assert_eq!(
            members,
            vec![
                ("admin@example.com".to_string(), "admin".to_string()),
                ("platform@example.com".to_string(), "admin".to_string()),
            ],
            "only the roles that actually granted Studio access carry forward, \
             and they become the Studio role `admin`"
        );

        // Idempotent: a second push must not disturb the table.
        let again = seed_and_list(&pool).await;
        assert_eq!(again, members, "re-running the seed changes nothing");

        // Revocation must stick. Removing an admin leaves the table non-empty, so
        // the guard keeps the next push from handing the access back.
        sqlx::raw_sql(
            "DELETE FROM _supatype.studio_members m
              USING auth.users u
              WHERE u.id = m.user_id AND u.email = 'platform@example.com'",
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

// ── A member's project user owns the membership ──────────────────────────────

const MEMBER_USER: &str = "aaaaaaaa-0000-0000-0000-000000000001";
const ORPHAN_USER: &str = "aaaaaaaa-0000-0000-0000-000000000002";
const CLOUD_ACCOUNT: &str = "bbbbbbbb-0000-0000-0000-000000000003";

async fn create_auth_users_with_member_user(pool: &sqlx::PgPool) {
    sqlx::raw_sql(&format!(
        "CREATE SCHEMA IF NOT EXISTS auth;
         CREATE TABLE IF NOT EXISTS auth.users (
           id UUID PRIMARY KEY, email TEXT, raw_app_meta_data JSONB DEFAULT '{{}}'
         );
         INSERT INTO auth.users (id, email) VALUES ('{MEMBER_USER}', 'member@example.com');"
    ))
    .execute(pool)
    .await
    .unwrap();
}

async fn member_ids(pool: &sqlx::PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT COALESCE(user_id, platform_user_id)::text FROM _supatype.studio_members ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn has_user_foreign_key(pool: &sqlx::PgPool) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_constraint
                         WHERE conrelid = '_supatype.studio_members'::regclass
                           AND conname = 'studio_members_user_id_fkey'
                           AND contype = 'f' AND confdeltype = 'c')",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

// Deleting a project user by any route, a raw SQL delete included, takes their membership with
// them, as it already takes their identity link. A row left behind kept a role for an id that no
// longer exists, and the members list showed a member nobody could sign in as.
#[tokio::test]
async fn deleting_the_project_user_removes_the_membership() {
    common::with_integration_pool(|pool| async move {
        create_auth_users_with_member_user(&pool).await;
        migration_history::bootstrap_internal_state(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(&format!(
            "INSERT INTO _supatype.studio_members (user_id, role) VALUES ('{MEMBER_USER}', 'admin');
             INSERT INTO _supatype.studio_members (platform_user_id, role)
             VALUES ('{CLOUD_ACCOUNT}', 'admin');"
        ))
        .execute(&pool)
        .await
        .unwrap();

        sqlx::raw_sql(&format!(
            "DELETE FROM auth.users WHERE id = '{MEMBER_USER}'"
        ))
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            member_ids(&pool).await,
            vec![CLOUD_ACCOUNT.to_string()],
            "the deleted user's membership goes with them; a cloud account's does not"
        );
    })
    .await;
}

// A database pushed before the foreign key existed may hold a membership whose user is already
// gone. The upgrade drops that row instead of failing to add the constraint, and keeps every row
// that still names someone: a live project user, or a cloud account, which has no project user.
#[tokio::test]
async fn an_existing_database_with_an_orphan_membership_upgrades() {
    common::with_integration_pool(|pool| async move {
        sqlx::raw_sql(migration_history::create_internal_schema_sql())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(&format!(
            r#"CREATE TABLE _supatype.studio_members (
                 id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                 user_id           UUID UNIQUE,
                 platform_user_id  UUID UNIQUE,
                 role              TEXT NOT NULL,
                 created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                 updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                 CONSTRAINT studio_members_one_identity
                     CHECK (num_nonnulls(user_id, platform_user_id) = 1)
               );
               INSERT INTO _supatype.studio_members (user_id, role) VALUES
                 ('{MEMBER_USER}', 'admin'), ('{ORPHAN_USER}', 'editor');
               INSERT INTO _supatype.studio_members (platform_user_id, role)
               VALUES ('{CLOUD_ACCOUNT}', 'admin');"#
        ))
        .execute(&pool)
        .await
        .unwrap();
        create_auth_users_with_member_user(&pool).await;

        migration_history::bootstrap_internal_state(&pool)
            .await
            .expect("the upgrade runs against a table holding an orphan");

        assert_eq!(
            member_ids(&pool).await,
            vec![MEMBER_USER.to_string(), CLOUD_ACCOUNT.to_string()],
            "only the orphan is dropped"
        );
        assert!(has_user_foreign_key(&pool).await);
    })
    .await;
}

// Running the bootstrap again over a database that already has the constraint changes nothing,
// and a project pushed before its auth schema existed gains the constraint once it does.
#[tokio::test]
async fn the_membership_foreign_key_is_idempotent_and_added_once_auth_exists() {
    common::with_integration_pool(|pool| async move {
        migration_history::bootstrap_internal_state(&pool)
            .await
            .expect("bootstrap runs without auth.users");
        assert!(!has_user_foreign_key(&pool).await);

        create_auth_users_with_member_user(&pool).await;
        for _ in 0..2 {
            // Forget the recorded bootstrap so the statements really run again.
            sqlx::raw_sql("DELETE FROM _supatype.engine_bootstrap WHERE id = 1")
                .execute(&pool)
                .await
                .unwrap();
            migration_history::bootstrap_internal_state(&pool)
                .await
                .expect("idempotent");
        }
        assert!(has_user_foreign_key(&pool).await);

        sqlx::raw_sql(&format!(
            "INSERT INTO _supatype.studio_members (user_id, role) VALUES ('{MEMBER_USER}', 'admin')"
        ))
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            sqlx::raw_sql(&format!(
                "INSERT INTO _supatype.studio_members (user_id, role) VALUES ('{ORPHAN_USER}', 'admin')"
            ))
            .execute(&pool)
            .await
            .is_err(),
            "the foreign key refuses a membership for a user who does not exist"
        );
        let (count,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM pg_constraint WHERE conname = 'studio_members_user_id_fkey'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1, "re-running adds no second constraint");
    })
    .await;
}
