use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::{Executor, PgPool, Postgres, Transaction};

// Internal bookkeeping lives in a dedicated schema so it never appears in the
// user's `public` schema and is never touched by introspection or diffs.
const SCHEMA: &str = "_supatype";

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
    id               SERIAL PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    hash             TEXT NOT NULL,
    applied_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rolled_back      BOOLEAN NOT NULL DEFAULT FALSE,
    rolled_back_at   TIMESTAMPTZ,
    engine_version   TEXT NOT NULL,
    schema_snapshot  JSONB,
    admin_config     JSONB,
    sql_up           TEXT,
    status           TEXT NOT NULL DEFAULT 'applied',
    error_message    TEXT
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

pub fn ensure_migrations_admin_config_column_sql() -> String {
    format!("ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS admin_config JSONB")
}

pub fn ensure_migrations_sql_up_column_sql() -> String {
    format!("ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS sql_up TEXT")
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

pub async fn load_schema_state(
    pool: &PgPool,
) -> Option<crate::state::database_state::DatabaseState> {
    let sql = format!("SELECT db_state FROM {SCHEMA}.schema_state WHERE id = 1");
    let row: Option<(serde_json::Value,)> = sqlx::query_as(&sql)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();

    row.and_then(|(val,)| serde_json::from_value(val).ok())
}

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

pub async fn save_schema_state<'e, E>(
    executor: E,
    state: &crate::state::database_state::DatabaseState,
) -> Result<()>
where
    E: Executor<'e, Database = Postgres>,
{
    let sql = format!(
        "INSERT INTO {SCHEMA}.schema_state (id, db_state, engine_version)
         VALUES (1, $1, $2)
         ON CONFLICT (id) DO UPDATE SET db_state = EXCLUDED.db_state,
             captured_at = NOW(), engine_version = EXCLUDED.engine_version"
    );
    sqlx::query(&sql)
        .bind(serde_json::to_value(state)?)
        .bind(env!("ENGINE_VERSION"))
        .execute(executor)
        .await?;
    Ok(())
}

pub fn insert_migration_sql() -> String {
    format!(
        "INSERT INTO {SCHEMA}.migrations \
         (name, hash, engine_version, schema_snapshot, admin_config, sql_up) \
         VALUES ($1, $2, $3, $4, $5, $6)"
    )
}

/// Record a successful migration row (same shape as [`insert_migration_sql`]).
pub async fn insert_applied_migration<'e, E>(
    executor: E,
    name: &str,
    hash: &str,
    schema_snapshot: Option<serde_json::Value>,
    admin_config: Option<serde_json::Value>,
    sql_up: &str,
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
