use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::{Executor, PgPool, Postgres, Transaction};

// Internal bookkeeping lives in a dedicated schema so it never appears in the
// user's `public` schema and is never touched by introspection or diffs.
const SCHEMA: &str = "_supatype";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationListItem {
    pub id: i32,
    pub name: String,
    pub hash: String,
    pub applied_at: String,
    pub rolled_back: bool,
    pub engine_version: String,
    pub status: String,
    pub schema_sources_manifest: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RollbackResult {
    pub status: String,
    pub name: String,
    pub message: String,
    pub restored_migration_name: Option<String>,
    pub schema_sources_manifest: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_sources_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationRecord {
    pub id: i32,
    pub name: String,
    pub hash: String,
    pub applied_at: String,
    pub rolled_back: bool,
    pub engine_version: String,
    pub schema_snapshot: Option<serde_json::Value>,
    pub status: String,
    pub error_message: Option<String>,
}

pub fn create_internal_schema_sql() -> &'static str {
    "CREATE SCHEMA IF NOT EXISTS _supatype"
}

pub fn create_migrations_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.migrations (
    id                      SERIAL PRIMARY KEY,
    name                    TEXT NOT NULL UNIQUE,
    hash                    TEXT NOT NULL,
    applied_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rolled_back             BOOLEAN NOT NULL DEFAULT FALSE,
    rolled_back_at          TIMESTAMPTZ,
    engine_version          TEXT NOT NULL,
    schema_snapshot         JSONB,
    admin_config            JSONB,
    sql_up                  TEXT,
    sql_down                TEXT,
    schema_sources          BYTEA,
    schema_sources_manifest JSONB,
    status                  TEXT NOT NULL DEFAULT 'applied',
    error_message           TEXT
)"#
    )
}

pub fn create_schema_state_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.schema_state (
    id               INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    db_state         JSONB NOT NULL,
    captured_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    engine_version   TEXT NOT NULL
)"#
    )
}

/// Studio membership: who may use the admin UI, and with what capability set.
///
/// Deliberately NOT a JWT claim and NOT in the `public` schema: `_supatype` is
/// absent from PGRST_DB_SCHEMAS, so nothing the developer's app or API surface
/// does can read or write it. Studio roles are Supatype's namespace; the
/// developer's own app roles live in their claims/tables and are unrelated.
///
/// A row identifies its holder by exactly one of two identities:
///
/// * `user_id`: a project `auth.users` id. How self-host grants access, and how
///   a project's own users are admitted in either host.
/// * `platform_user_id`: a Supatype Cloud account. Cloud callers are platform
///   accounts, not project users, so they cannot be looked up by `user_id`.
///
/// Keeping both in one table means "who may use Studio for this project" has a
/// single answer wherever the project runs, and the grants survive an export from
/// cloud to self-host. The CHECK makes the identity space of every row explicit,
/// so neither lookup can ever match a row it was not meant to.
pub fn create_studio_members_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.studio_members (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID UNIQUE,
    platform_user_id  UUID UNIQUE,
    role              TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT studio_members_one_identity
        CHECK (num_nonnulls(user_id, platform_user_id) = 1)
)"#
    )
}

/// Audit trail for Studio membership changes and elevated data access.
///
/// Access-control changes need a durable record, not a log line that rotates
/// away: "who gave this person admin, and when" has to be answerable months
/// later. Lives in `_supatype` for the same reason `studio_members` does:
/// nothing reachable through the data plane can read or rewrite it.
///
/// `actor_id` is nullable because a change can come from the CLI against the
/// database directly, where there is no signed-in actor to attribute it to.
/// `target_id` is nullable because not every audited event is *about* someone:
/// an elevated request has an actor and no target. `detail` carries the shape of
/// whatever the action was: the method and path of an elevated request, say.
pub fn create_studio_audit_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.studio_audit (
    id          BIGSERIAL PRIMARY KEY,
    actor_id    UUID,
    target_id   UUID,
    action      TEXT NOT NULL,
    role        TEXT,
    detail      JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
)"#
    )
}

/// Bring an audit table created for membership changes only up to the shape that
/// also records elevated access.
pub fn ensure_studio_audit_columns_sql() -> String {
    format!(
        r#"DO $$
BEGIN
    IF to_regclass('{SCHEMA}.studio_audit') IS NULL THEN
        RETURN;
    END IF;
    ALTER TABLE {SCHEMA}.studio_audit ADD COLUMN IF NOT EXISTS detail JSONB;
    ALTER TABLE {SCHEMA}.studio_audit ALTER COLUMN target_id DROP NOT NULL;
END $$"#
    )
}

/// Migrate a `studio_members` table created before cloud accounts could hold a
/// membership: `user_id` was the primary key and the only identity.
///
/// Written as a guarded DO block rather than plain `ALTER`s because the target
/// shape has to be reached from either starting point (the pre-cloud table or
/// the current one), and a push must never fail on a table that is already right.
pub fn ensure_studio_members_platform_identity_sql() -> String {
    format!(
        r#"DO $$
BEGIN
    IF to_regclass('{SCHEMA}.studio_members') IS NULL THEN
        RETURN;
    END IF;

    ALTER TABLE {SCHEMA}.studio_members
        ADD COLUMN IF NOT EXISTS platform_user_id UUID;

    -- `user_id` becomes optional, so the primary key has to move off it.
    IF EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = '{SCHEMA}.studio_members'::regclass
           AND contype = 'p'
           AND conkey = ARRAY[(SELECT attnum FROM pg_attribute
                                WHERE attrelid = '{SCHEMA}.studio_members'::regclass
                                  AND attname = 'user_id')]::smallint[]
    ) THEN
        ALTER TABLE {SCHEMA}.studio_members DROP CONSTRAINT studio_members_pkey;
        ALTER TABLE {SCHEMA}.studio_members
            ADD COLUMN IF NOT EXISTS id UUID NOT NULL DEFAULT gen_random_uuid();
        ALTER TABLE {SCHEMA}.studio_members ADD PRIMARY KEY (id);
        ALTER TABLE {SCHEMA}.studio_members ALTER COLUMN user_id DROP NOT NULL;
        ALTER TABLE {SCHEMA}.studio_members ADD CONSTRAINT studio_members_user_id_key
            UNIQUE (user_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = '{SCHEMA}.studio_members'::regclass
           AND conname = 'studio_members_platform_user_id_key'
    ) THEN
        ALTER TABLE {SCHEMA}.studio_members
            ADD CONSTRAINT studio_members_platform_user_id_key UNIQUE (platform_user_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = '{SCHEMA}.studio_members'::regclass
           AND conname = 'studio_members_one_identity'
    ) THEN
        ALTER TABLE {SCHEMA}.studio_members
            ADD CONSTRAINT studio_members_one_identity
            CHECK (num_nonnulls(user_id, platform_user_id) = 1);
    END IF;
END $$"#
    )
}

/// Seed `studio_members` from the admin roles that used to live in
/// `app_metadata`.
///
/// Studio access moved out of JWT claims and into this table. Without a seed,
/// the first push after that change locks every existing admin out of their own
/// Studio: their claim no longer grants anything and they have no membership
/// row. Runs only while the table is empty, so it cannot resurrect access that
/// was deliberately revoked later.
///
/// Only the roles that actually admitted anyone are carried over, and they all
/// become the Studio role `admin`:
///
/// * `app_metadata.role` was the developer's own namespace, so it holds arbitrary
///   application roles: `moderator`, `staff`, whatever their app needed. Those
///   never granted Studio access (`STUDIO_ADMIN_ROLES` did, defaulting to `admin`
///   and `supatype_admin`), so seeding them would *hand out* access rather than
///   preserve it.
/// * A Studio role has to be one the deployment understands, or the capability
///   check refuses it. Copying claim strings verbatim would seed rows that deny.
///
/// A deployment that customised `STUDIO_ADMIN_ROLES` seeds nobody and falls
/// through to the CLI's first-admin prompt, which is the right recovery, better
/// than guessing which app roles were meant to be administrators.
pub fn seed_studio_members_from_claims_sql() -> String {
    format!(
        r#"DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM {SCHEMA}.studio_members) THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'auth' AND table_name = 'users'
        ) THEN
            INSERT INTO {SCHEMA}.studio_members (user_id, platform_user_id, role)
            SELECT id, NULL, 'admin'
              FROM auth.users
             WHERE raw_app_meta_data->>'role' IN ('admin', 'supatype_admin')
            ON CONFLICT (user_id) DO NOTHING;
        END IF;
    END IF;
END $$"#
    )
}

pub fn ensure_migrations_admin_config_column_sql() -> String {
    format!("ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS admin_config JSONB")
}

pub fn ensure_migrations_sql_down_column_sql() -> String {
    format!("ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS sql_down TEXT")
}

pub fn ensure_migrations_sql_up_column_sql() -> String {
    format!("ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS sql_up TEXT")
}

pub fn ensure_migrations_schema_sources_column_sql() -> String {
    format!(
        "ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS schema_sources BYTEA;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS schema_sources_manifest JSONB"
    )
}

/// Repair a `migrations` table that predates this engine's layout.
///
/// [`create_migrations_table_sql`] uses CREATE TABLE IF NOT EXISTS, so a table
/// created by anything else (e.g. an older engine, or a provisioner that
/// pre-created it) silently wins and every insert then fails on a missing
/// column. These columns are NOT NULL at creation time; added after the fact
/// they must be nullable, which is harmless because every insert supplies them.
pub fn ensure_migrations_core_columns_sql() -> String {
    format!(
        "ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS hash TEXT;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS engine_version TEXT;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW();\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS rolled_back BOOLEAN NOT NULL DEFAULT FALSE;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS rolled_back_at TIMESTAMPTZ;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS schema_snapshot JSONB"
    )
}

/// A foreign `migrations` table may carry NOT NULL columns this engine never
/// writes (a legacy layout used `version`, `sql`, `checksum`), and may lack the
/// UNIQUE constraint on `name` that failed-migration upserts rely on. Relax the
/// columns we don't own and restore the constraint so inserts can succeed.
pub fn ensure_migrations_writable_sql() -> String {
    format!(
        "DO $$
DECLARE
  col RECORD;
BEGIN
  FOR col IN
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema = '{SCHEMA}'
      AND table_name = 'migrations'
      AND is_nullable = 'NO'
      AND column_default IS NULL
      AND column_name <> ALL (ARRAY['id', 'name', 'hash', 'engine_version'])
  LOOP
    EXECUTE format('ALTER TABLE {SCHEMA}.migrations ALTER COLUMN %I DROP NOT NULL', col.column_name);
  END LOOP;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_index i
    JOIN pg_class c ON c.oid = i.indrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY (i.indkey)
    WHERE n.nspname = '{SCHEMA}'
      AND c.relname = 'migrations'
      AND i.indisunique
      AND i.indnatts = 1
      AND a.attname = 'name'
  ) THEN
    EXECUTE 'CREATE UNIQUE INDEX migrations_name_key ON {SCHEMA}.migrations (name)';
  END IF;
END $$"
    )
}

pub fn ensure_all_migration_columns_sql() -> Vec<String> {
    vec![
        ensure_migrations_core_columns_sql(),
        ensure_migrations_writable_sql(),
        ensure_migrations_admin_config_column_sql(),
        ensure_migrations_sql_up_column_sql(),
        ensure_migrations_status_columns_sql(),
        ensure_migrations_sql_down_column_sql(),
        ensure_migrations_schema_sources_column_sql(),
    ]
}

pub fn ensure_migrations_status_columns_sql() -> String {
    format!(
        "ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'applied';\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS error_message TEXT"
    )
}

pub fn ensure_schema_state_studio_columns_sql() -> String {
    format!(
        "ALTER TABLE {SCHEMA}.schema_state ADD COLUMN IF NOT EXISTS ast_snapshot JSONB;\
         ALTER TABLE {SCHEMA}.schema_state ADD COLUMN IF NOT EXISTS admin_config JSONB"
    )
}

/// What this database can actually enforce, as opposed to what the schema declares.
pub fn ensure_schema_state_capabilities_column_sql() -> String {
    format!("ALTER TABLE {SCHEMA}.schema_state ADD COLUMN IF NOT EXISTS capabilities JSONB")
}

/// Which project schema this database belongs to. See [`assert_project_schema`].
pub fn ensure_schema_state_project_schema_column_sql() -> String {
    format!("ALTER TABLE {SCHEMA}.schema_state ADD COLUMN IF NOT EXISTS project_schema TEXT")
}

/// Refuse to push a second project into a database that already holds one.
///
/// `_supatype.migrations` has no project column, `schema_state` is one row, and the publishing cron
/// jobs are named with no schema, so two projects in one database share a history they should not:
/// the second one's push loads the first one's snapshot as "the previous schema" and diffs against
/// it. Cloud runs one Postgres per project; this makes the same shape explicit for self-host rather
/// than letting it fail in a way that names nothing.
///
/// A database with no recorded schema (a fresh one, or one written by an engine from before this
/// column) passes, and [`save_schema_state`] records the schema at the end of that push.
pub async fn assert_project_schema(pool: &PgPool, schema: &str) -> Result<()> {
    let sql = format!("SELECT project_schema FROM {SCHEMA}.schema_state WHERE id = 1");
    let recorded: Option<Option<String>> = sqlx::query_scalar(&sql).fetch_optional(pool).await?;
    match recorded.flatten() {
        Some(existing) if existing != schema => anyhow::bail!(
            "This database already holds the project schema \"{existing}\", and this push is for \
             \"{schema}\". Supatype runs one project per database: point this project at a database \
             of its own, or set pg_schema back to \"{existing}\"."
        ),
        _ => Ok(()),
    }
}

/// Record how field-level access is enforced here, from a live probe rather than an
/// assumption.
///
/// Studio and `explain` need to state which mechanism is in force, and a value derived
/// on demand is a value that can disagree with the push that actually applied the
/// schema. Writing it makes the tier a recorded fact.
///
/// A database with field rules cannot reach here without the extension (the migration
/// refuses to apply first), so `unenforced` means only "no field rules in this schema".
/// That distinction is the point: a deployment that quietly stopped enforcing must be
/// visible, not inferred.
pub async fn record_field_enforcement(
    conn: &mut sqlx::PgConnection,
    labelled_columns: usize,
) -> Result<()> {
    let extension: Option<String> =
        sqlx::query_scalar("SELECT extversion FROM pg_extension WHERE extname = $1")
            .bind(crate::generator::sql::rls::MASK_EXTENSION)
            .fetch_optional(&mut *conn)
            .await?
            .flatten();

    // Tier 2 is real enforcement, not a failure, but only if the views are actually there. Asking
    // the database rather than assuming: a schema that *should* have views and does not is exactly
    // the state worth recording as broken.
    let views_present: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_class c            JOIN pg_namespace n ON n.oid = c.relnamespace           WHERE n.nspname = $1 AND c.relkind = 'v')",
    )
    .bind(crate::generator::sql::field_views::VIEW_SCHEMA)
    .fetch_one(&mut *conn)
    .await?;

    let tier = if labelled_columns == 0 {
        "unenforced"
    } else if extension.is_some() {
        "extension"
    } else if views_present {
        "views"
    } else {
        // The extension is gone and no views stand in for it. Reachable by dropping the extension
        // under a tier-1 database, and worth recording honestly rather than asserting.
        "broken"
    };

    let record = serde_json::json!({
        "fieldMasking": {
            "tier": tier,
            "extension": crate::generator::sql::rls::MASK_EXTENSION,
            "extensionVersion": extension,
            "labelledColumns": labelled_columns,
        }
    });

    // Merged rather than replaced, so a future capability recorded elsewhere survives.
    let sql = format!(
        "UPDATE {SCHEMA}.schema_state \
         SET capabilities = COALESCE(capabilities, '{{}}'::jsonb) || $1::jsonb \
         WHERE id = 1"
    );
    sqlx::query(&sql).bind(record).execute(&mut *conn).await?;

    Ok(())
}

/// How many columns the schema declares field rules for: the number recorded alongside
/// the tier, and what makes "no field rules" distinguishable from "rules that stopped
/// being enforced".
pub fn labelled_column_count(ast: &crate::parser::ast::SchemaAst) -> usize {
    ast.models
        .iter()
        .map(|model| {
            crate::parser::accessors::platform_access(model)
                .fields
                .values()
                .filter(|rules| rules.read.is_some() || rules.write.is_some())
                .count()
        })
        .sum()
}

fn snapshot_hash(schema_snapshot: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(schema_snapshot.to_string().as_bytes());
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// Latest applied schema AST snapshot (for kind-aware diffs when PG types are unchanged).
pub async fn load_latest_schema_snapshot(pool: &PgPool) -> Option<serde_json::Value> {
    let sql = format!(
        "SELECT schema_snapshot FROM {SCHEMA}.migrations \
         WHERE rolled_back = false AND schema_snapshot IS NOT NULL \
         ORDER BY applied_at DESC LIMIT 1"
    );
    if let Ok(Some((v,))) = sqlx::query_as::<_, (serde_json::Value,)>(&sql)
        .fetch_optional(pool)
        .await
    {
        return Some(v);
    }

    let fallback = format!(
        "SELECT ast_snapshot FROM {SCHEMA}.schema_state WHERE id = 1 AND ast_snapshot IS NOT NULL"
    );
    sqlx::query_as::<_, (serde_json::Value,)>(&fallback)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|(v,)| v)
}

/// Latest Studio admin config from migration history or schema_state fallback.
pub async fn load_latest_admin_config(pool: &PgPool) -> Option<serde_json::Value> {
    let sql = format!(
        "SELECT admin_config FROM {SCHEMA}.migrations \
         WHERE rolled_back = false AND admin_config IS NOT NULL \
         ORDER BY applied_at DESC LIMIT 1"
    );
    if let Ok(Some((v,))) = sqlx::query_as::<_, (serde_json::Value,)>(&sql)
        .fetch_optional(pool)
        .await
    {
        return Some(v);
    }

    let fallback = format!(
        "SELECT admin_config FROM {SCHEMA}.schema_state WHERE id = 1 AND admin_config IS NOT NULL"
    );
    sqlx::query_as::<_, (serde_json::Value,)>(&fallback)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|(v,)| v)
}

/// Printed when `--no-cache` is passed to push or adopt, which no longer read a cache at all.
///
/// Both used to diff against the snapshot the last push wrote, which cannot see anything changed
/// outside Supatype since: a table that lost its ownership marker, a column dropped by hand. They
/// read the database live now, so the flag has nothing left to bypass. It is still accepted, for
/// one release, so a script that passes it keeps working.
pub const NO_CACHE_NOTICE: &str = "--no-cache is no longer needed: push and adopt always read the \
     database live. The flag does nothing and will be removed in a future release.";

pub async fn list_migrations(pool: &PgPool) -> Result<Vec<MigrationRecord>> {
    let sql = format!(
        "SELECT id, name, hash, applied_at::TEXT, rolled_back, engine_version, schema_snapshot, \
         COALESCE(status, 'applied'), error_message \
         FROM {SCHEMA}.migrations ORDER BY applied_at ASC"
    );
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        i32,
        String,
        String,
        String,
        bool,
        String,
        Option<serde_json::Value>,
        String,
        Option<String>,
    )> = sqlx::query_as(&sql).fetch_all(pool).await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                name,
                hash,
                applied_at,
                rolled_back,
                engine_version,
                schema_snapshot,
                status,
                error_message,
            )| {
                MigrationRecord {
                    id,
                    name,
                    hash,
                    applied_at,
                    rolled_back,
                    engine_version,
                    schema_snapshot,
                    status,
                    error_message,
                }
            },
        )
        .collect())
}

/// Record what the database looks like after a push or an adoption.
///
/// Nothing diffs against `db_state` any more: push and adopt introspect live. It is still written
/// because this is the statement that creates the `schema_state` row, and the Studio metadata and
/// capability writers are all `UPDATE ... WHERE id = 1` against it.
pub async fn save_schema_state<'e, E>(
    executor: E,
    state: &crate::state::database_state::DatabaseState,
) -> Result<()>
where
    E: Executor<'e, Database = Postgres>,
{
    let sql = format!(
        "INSERT INTO {SCHEMA}.schema_state (id, db_state, engine_version, project_schema)
         VALUES (1, $1, $2, $3)
         ON CONFLICT (id) DO UPDATE SET db_state = EXCLUDED.db_state,
             captured_at = NOW(), engine_version = EXCLUDED.engine_version,
             project_schema = EXCLUDED.project_schema"
    );
    sqlx::query(&sql)
        .bind(serde_json::to_value(state)?)
        .bind(env!("ENGINE_VERSION"))
        .bind(&state.schema)
        .execute(executor)
        .await?;
    Ok(())
}

pub fn insert_migration_sql() -> String {
    format!(
        "INSERT INTO {SCHEMA}.migrations \
         (name, hash, engine_version, schema_snapshot, admin_config, sql_up, sql_down, schema_sources, schema_sources_manifest) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    )
}

#[derive(Default)]
pub struct AppliedMigrationSources {
    pub sql_down: Option<String>,
    pub schema_sources: Option<Vec<u8>>,
    pub schema_sources_manifest: Option<serde_json::Value>,
}

/// Record a successful migration row (same shape as [`insert_migration_sql`]).
pub async fn insert_applied_migration<'e, E>(
    executor: E,
    name: &str,
    hash: &str,
    schema_snapshot: Option<serde_json::Value>,
    admin_config: Option<serde_json::Value>,
    sql_up: &str,
    sources: &AppliedMigrationSources,
) -> Result<()>
where
    E: Executor<'e, Database = Postgres>,
{
    let sql = insert_migration_sql();
    sqlx::query(&sql)
        .bind(name)
        .bind(hash)
        .bind(env!("ENGINE_VERSION"))
        .bind(schema_snapshot)
        .bind(admin_config)
        .bind(sql_up)
        .bind(sources.sql_down.as_deref())
        .bind(sources.schema_sources.as_deref())
        .bind(sources.schema_sources_manifest.as_ref())
        .execute(executor)
        .await?;
    Ok(())
}

/// Updates `admin_config` and `schema_snapshot` on the latest non-rolled-back migration row.
/// Returns the number of rows updated (0 if there are no applicable migration records).
pub async fn update_latest_migration_admin(
    pool: &PgPool,
    admin_config: &serde_json::Value,
    schema_snapshot: &serde_json::Value,
) -> Result<u64> {
    let sql = format!(
        "UPDATE {SCHEMA}.migrations SET admin_config = $1, schema_snapshot = $2 \
         WHERE id = (SELECT MAX(id) FROM {SCHEMA}.migrations WHERE rolled_back = FALSE)"
    );
    let res = sqlx::query(&sql)
        .bind(admin_config)
        .bind(schema_snapshot)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// When push finds no DDL diff: refresh Studio metadata on the latest migration row, or
/// record a one-time `initial_*` baseline when no active migration exists yet.
pub async fn refresh_metadata_on_up_to_date_push(
    pool: &PgPool,
    admin_config: &serde_json::Value,
    schema_snapshot: &serde_json::Value,
) -> Result<()> {
    save_studio_metadata_if_present(pool, admin_config, schema_snapshot).await?;

    let n = update_latest_migration_admin(pool, admin_config, schema_snapshot).await?;
    if n > 0 {
        return Ok(());
    }

    let migration_name = format!("initial_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
    let hash = snapshot_hash(schema_snapshot);
    sqlx::query(&insert_migration_sql())
        .bind(&migration_name)
        .bind(&hash)
        .bind(env!("ENGINE_VERSION"))
        .bind(schema_snapshot)
        .bind(admin_config)
        .bind(None::<String>)
        .bind(None::<String>)
        .bind(None::<Vec<u8>>)
        .bind(None::<serde_json::Value>)
        .execute(pool)
        .await?;
    Ok(())
}

/// Persist Studio metadata on `schema_state` when a cached DB snapshot row already exists.
pub async fn save_studio_metadata_if_present(
    pool: &PgPool,
    admin_config: &serde_json::Value,
    schema_snapshot: &serde_json::Value,
) -> Result<()> {
    let sql = format!(
        "UPDATE {SCHEMA}.schema_state SET ast_snapshot = $1, admin_config = $2 WHERE id = 1"
    );
    sqlx::query(&sql)
        .bind(schema_snapshot)
        .bind(admin_config)
        .execute(pool)
        .await?;
    Ok(())
}

pub fn insert_failed_migration_sql() -> String {
    format!(
        "INSERT INTO {SCHEMA}.migrations \
         (name, hash, engine_version, sql_up, status, error_message) \
         VALUES ($1, $2, $3, $4, 'failed', $5) \
         ON CONFLICT (name) DO UPDATE SET status = 'failed', error_message = EXCLUDED.error_message"
    )
}

pub async fn record_failed_migration(
    pool: &PgPool,
    name: &str,
    hash: &str,
    sql_up: &str,
    error: &str,
) -> Result<()> {
    sqlx::query(&insert_failed_migration_sql())
        .bind(name)
        .bind(hash)
        .bind(env!("ENGINE_VERSION"))
        .bind(sql_up)
        .bind(error)
        .execute(pool)
        .await?;
    Ok(())
}

/// Roll back an in-flight push transaction and best-effort record a failed migration row.
pub async fn rollback_push_tx(
    tx: Transaction<'_, Postgres>,
    pool: &PgPool,
    migration_name: &str,
    hash: &str,
    apply_batch: &str,
    err: &str,
) {
    let _ = tx.rollback().await;
    if let Err(record_err) =
        record_failed_migration(pool, migration_name, hash, apply_batch, err).await
    {
        eprintln!("Warning: could not record failed migration: {record_err}");
    }
}

pub async fn list_migrations_summary(pool: &PgPool) -> Result<Vec<MigrationListItem>> {
    type MigrationSummaryRow = (
        i32,
        String,
        String,
        String,
        bool,
        String,
        String,
        Option<serde_json::Value>,
    );

    let sql = format!(
        "SELECT id, name, hash, applied_at::TEXT, rolled_back, engine_version, \
         COALESCE(status, 'applied'), schema_sources_manifest \
         FROM {SCHEMA}.migrations ORDER BY applied_at DESC"
    );
    let rows: Vec<MigrationSummaryRow> = sqlx::query_as(&sql).fetch_all(pool).await?;

    Ok(rows
        .into_iter()
        .map(
            |(id, name, hash, applied_at, rolled_back, engine_version, status, manifest)| {
                MigrationListItem {
                    id,
                    name,
                    hash,
                    applied_at,
                    rolled_back,
                    engine_version,
                    status,
                    schema_sources_manifest: manifest,
                }
            },
        )
        .collect())
}

struct LatestMigrationRow {
    id: i32,
    name: String,
    sql_down: Option<String>,
}

async fn load_latest_applied_migration(pool: &PgPool) -> Result<Option<LatestMigrationRow>> {
    let sql = format!(
        "SELECT id, name, sql_down FROM {SCHEMA}.migrations \
         WHERE rolled_back = false AND COALESCE(status, 'applied') = 'applied' \
         ORDER BY applied_at DESC LIMIT 1"
    );
    Ok(sqlx::query_as::<_, (i32, String, Option<String>)>(&sql)
        .fetch_optional(pool)
        .await?
        .map(|(id, name, sql_down)| LatestMigrationRow { id, name, sql_down }))
}

struct PriorMigrationRow {
    name: String,
    schema_snapshot: Option<serde_json::Value>,
    admin_config: Option<serde_json::Value>,
    schema_sources: Option<Vec<u8>>,
    schema_sources_manifest: Option<serde_json::Value>,
}

async fn load_prior_applied_migration(
    pool: &PgPool,
    exclude_id: i32,
) -> Result<Option<PriorMigrationRow>> {
    let sql = format!(
        "SELECT name, schema_snapshot, admin_config, schema_sources, schema_sources_manifest \
         FROM {SCHEMA}.migrations \
         WHERE rolled_back = false AND COALESCE(status, 'applied') = 'applied' AND id <> $1 \
         ORDER BY applied_at DESC LIMIT 1"
    );
    Ok(sqlx::query_as::<
        _,
        (
            String,
            Option<serde_json::Value>,
            Option<serde_json::Value>,
            Option<Vec<u8>>,
            Option<serde_json::Value>,
        ),
    >(&sql)
    .bind(exclude_id)
    .fetch_optional(pool)
    .await?
    .map(
        |(name, schema_snapshot, admin_config, schema_sources, schema_sources_manifest)| {
            PriorMigrationRow {
                name,
                schema_snapshot,
                admin_config,
                schema_sources,
                schema_sources_manifest,
            }
        },
    ))
}

pub async fn apply_rollback(pool: &PgPool, schema: &str) -> Result<RollbackResult> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    let latest = load_latest_applied_migration(pool).await?.ok_or_else(|| {
        anyhow::anyhow!("no_applied_migration: No applied migration to roll back")
    })?;

    let sql_down = latest
        .sql_down
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("no_rollback_sql: Migration has no rollback SQL (metadata-only push?)")
        })?;

    let prior = load_prior_applied_migration(pool, latest.id).await?;

    let mut tx = pool.begin().await?;

    (&mut *tx)
        .execute(sqlx::raw_sql(&sql_down))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to apply rollback SQL: {e}"))?;

    let mark_sql = format!(
        "UPDATE {SCHEMA}.migrations SET rolled_back = true, rolled_back_at = NOW() WHERE id = $1"
    );
    sqlx::query(&mark_sql)
        .bind(latest.id)
        .execute(&mut *tx)
        .await?;

    if let Some(ref prior) = prior {
        if let (Some(admin), Some(snap)) = (&prior.admin_config, &prior.schema_snapshot) {
            let studio_sql = format!(
                "UPDATE {SCHEMA}.schema_state SET ast_snapshot = $1, admin_config = $2 WHERE id = 1"
            );
            sqlx::query(&studio_sql)
                .bind(snap)
                .bind(admin)
                .execute(&mut *tx)
                .await?;
        }
    }

    let new_state = crate::introspector::introspect_connection(&mut tx, schema).await?;
    save_schema_state(&mut *tx, &new_state).await?;

    tx.commit().await?;

    let (restored_name, manifest, sources_b64) = prior
        .map(|p| {
            (
                Some(p.name),
                p.schema_sources_manifest,
                p.schema_sources.map(|b| B64.encode(b)),
            )
        })
        .unwrap_or((None, None, None));

    Ok(RollbackResult {
        status: "rolled_back".into(),
        name: latest.name.clone(),
        message: format!("Rolled back migration {}.", latest.name),
        restored_migration_name: restored_name,
        schema_sources_manifest: manifest,
        schema_sources_base64: sources_b64,
    })
}

pub async fn load_migration_sources(
    pool: &PgPool,
    name: &str,
) -> Result<Option<(Vec<u8>, Option<serde_json::Value>)>> {
    let sql = format!(
        "SELECT schema_sources, schema_sources_manifest FROM {SCHEMA}.migrations WHERE name = $1"
    );
    let row: Option<(Option<Vec<u8>>, Option<serde_json::Value>)> =
        sqlx::query_as(&sql).bind(name).fetch_optional(pool).await?;
    Ok(row.and_then(|(sources, manifest)| sources.map(|s| (s, manifest))))
}

/// Re-apply the `auth.*` helper functions used by RLS policies.
///
/// These were only ever written at provision time, so an engine change to
/// `auth.role()` (for example, resolving application roles from
/// `app_metadata.role`) never reached an existing project: its policies kept
/// calling the old definition indefinitely. They are CREATE OR REPLACE, so
/// re-applying on every push is cheap and idempotent.
///
/// Skipped when there is no `auth` schema (a plain Postgres target), rather than
/// failing a push that has nothing to do with auth.
pub async fn reapply_auth_helpers(pool: &PgPool, auth_schema: &str) -> Result<bool> {
    let exists: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM information_schema.schemata WHERE schema_name = $1")
            .bind(auth_schema)
            .fetch_optional(pool)
            .await?;
    if exists.is_none() {
        return Ok(false);
    }

    let config = crate::generator::sql::auth_functions::AuthFunctionConfig {
        project_ref: String::new(),
        auth_schema: auth_schema.to_string(),
    };
    let sql = crate::generator::sql::auth_functions::generate_auth_functions(&config);
    sqlx::raw_sql(&sql).execute(pool).await?;
    Ok(true)
}

/// Create and repair everything the engine owns inside `_supatype`, and re-apply
/// the auth helper functions.
///
/// Both push implementations (the CLI binary, `main.rs`, and the HTTP server,
/// `server/routes.rs`) call this. They previously each wrote out the same
/// sequence by hand, so every new internal object or repair had to be added
/// twice; forgetting one produced exactly the silent drift this engine has been
/// accumulating (a migrations table with no `hash`, RLS state that never
/// converged, Studio metadata written on only one code path).
pub async fn bootstrap_internal_state(pool: &PgPool) -> Result<()> {
    sqlx::raw_sql(create_internal_schema_sql())
        .execute(pool)
        .await?;
    sqlx::raw_sql(&create_migrations_table_sql())
        .execute(pool)
        .await?;
    // Created in the same bootstrap as `migrations`, so a seed run never has to create
    // its own table mid-transaction.
    sqlx::raw_sql(&crate::seed::ledger::create_seeds_table_sql())
        .execute(pool)
        .await?;
    sqlx::raw_sql(&crate::seed::ledger::create_seeds_index_sql())
        .execute(pool)
        .await?;
    sqlx::raw_sql(&create_studio_members_table_sql())
        .execute(pool)
        .await?;
    sqlx::raw_sql(&ensure_studio_members_platform_identity_sql())
        .execute(pool)
        .await?;
    sqlx::raw_sql(&create_studio_audit_table_sql())
        .execute(pool)
        .await?;
    sqlx::raw_sql(&ensure_studio_audit_columns_sql())
        .execute(pool)
        .await?;
    // Migrating an existing project: carry forward the admins who only have the
    // old `app_metadata.role` claim, before that claim stops meaning anything.
    if let Err(e) = sqlx::raw_sql(&seed_studio_members_from_claims_sql())
        .execute(pool)
        .await
    {
        eprintln!("Warning: failed to seed Studio membership from existing admin roles: {e}");
    }
    sqlx::raw_sql(&create_schema_state_table_sql())
        .execute(pool)
        .await?;
    sqlx::raw_sql(&ensure_schema_state_studio_columns_sql())
        .execute(pool)
        .await?;
    sqlx::raw_sql(&ensure_schema_state_capabilities_column_sql())
        .execute(pool)
        .await?;
    sqlx::raw_sql(&ensure_schema_state_project_schema_column_sql())
        .execute(pool)
        .await?;

    for sql in ensure_all_migration_columns_sql() {
        sqlx::raw_sql(&sql).execute(pool).await?;
    }
    // After `migrations`, which it references.
    sqlx::raw_sql(&crate::ledger::create_table_sql())
        .execute(pool)
        .await?;

    // Helper functions are cosmetic to a migration's success, so a failure here
    // must not abort the push.
    if let Err(e) = reapply_auth_helpers(pool, "auth").await {
        eprintln!("Warning: failed to reapply auth helper functions: {e}");
    }
    Ok(())
}
