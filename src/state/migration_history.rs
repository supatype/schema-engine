use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

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
}

pub const MIGRATIONS_TABLE: &str = "_platform.migrations";

pub fn create_migrations_table_sql() -> &'static str {
    r#"
CREATE SCHEMA IF NOT EXISTS _platform;

CREATE TABLE IF NOT EXISTS _platform.migrations (
    id               SERIAL PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    hash             TEXT NOT NULL,
    applied_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rolled_back      BOOLEAN NOT NULL DEFAULT FALSE,
    rolled_back_at   TIMESTAMPTZ,
    engine_version   TEXT NOT NULL,
    schema_snapshot  JSONB
);

CREATE TABLE IF NOT EXISTS _platform.schema_state (
    id               INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    db_state         JSONB NOT NULL,
    captured_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    engine_version   TEXT NOT NULL
);
"#
}

/// Load the cached DB state from `_platform.schema_state`.
/// Returns None if the table doesn't exist yet or no row is stored.
pub async fn load_schema_state(pool: &PgPool) -> Option<crate::state::database_state::DatabaseState> {
    let row: Option<(serde_json::Value,)> = sqlx::query_as(
        "SELECT db_state FROM _platform.schema_state WHERE id = 1"
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    row.and_then(|(val,)| serde_json::from_value(val).ok())
}

/// Upsert the current DB state into `_platform.schema_state`.
pub async fn save_schema_state(
    pool: &PgPool,
    state: &crate::state::database_state::DatabaseState,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO _platform.schema_state (id, db_state, engine_version)
         VALUES (1, $1, $2)
         ON CONFLICT (id) DO UPDATE SET db_state = EXCLUDED.db_state,
             captured_at = NOW(), engine_version = EXCLUDED.engine_version"
    )
    .bind(serde_json::to_value(state)?)
    .bind(env!("ENGINE_VERSION"))
    .execute(pool)
    .await?;
    Ok(())
}
