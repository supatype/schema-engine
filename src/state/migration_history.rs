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

pub fn ensure_all_migration_columns_sql() -> Vec<String> {
    vec![
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
