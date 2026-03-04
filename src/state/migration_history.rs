use serde::{Deserialize, Serialize};

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
"#
}
