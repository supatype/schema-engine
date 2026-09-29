//! What has been seeded, and when.
//!
//! `_supatype.seeds` sits beside `_supatype.migrations` and answers the same kind of
//! question for a different kind of write.
//!
//! **It is a record, not a gate.** Seeds are idempotent upserts by design, so skipping a
//! file because it ran before would fight the whole model and turn every seed into a
//! one-shot migration. What it is for: knowing what was applied to an environment and when,
//! noticing that a file has changed since it was applied, and telling which run produced a
//! given set of rows.
//!
//! The one exception is `runOnce`, for a genuine backfill rather than a fixture, which
//! consults the ledger before running. Off by default.
//!
//! The row is written **inside the caller's transaction**. A ledger that could commit while
//! the writes it describes rolled back would be worse than no ledger, because it would be
//! confidently wrong about the one thing it exists to record.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};

const SCHEMA: &str = "_supatype";

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Committed,
    RolledBack,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RunStatus::Committed => "committed",
            RunStatus::RolledBack => "rolled_back",
        }
    }

    fn from_str(text: &str) -> Self {
        match text {
            "rolled_back" => RunStatus::RolledBack,
            _ => RunStatus::Committed,
        }
    }
}

/// One recorded run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeedRun {
    /// The seed file, relative to the project root. What links a row back to its source.
    pub file: String,
    pub ir_hash: String,
    pub schema_fingerprint: String,
    pub status: RunStatus,
    pub duration_ms: i64,
    /// Model name to rows written.
    pub rows_written: serde_json::Value,
    pub error_message: Option<String>,
    pub engine_version: String,
}

/// A row read back, with when it happened.
///
/// `applied_at` is an RFC 3339 string rather than a `DateTime`: sqlx is built here without
/// its chrono feature, and turning that on for one column would change decoding across the
/// whole engine. The query casts it, so the value is still Postgres's own rendering.
#[derive(Debug, Clone)]
pub struct SeedRunRecord {
    pub run: SeedRun,
    pub applied_at: String,
}

/// A stable hash of the IR document, for spotting a file that changed since it ran.
pub fn ir_hash(ir_json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ir_json.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

/// `CREATE TABLE IF NOT EXISTS _supatype.seeds`.
///
/// Columns follow `migrations`: the same names for the same meanings, so a reader who knows
/// one knows the other.
pub fn create_seeds_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.seeds (
    id                      BIGSERIAL PRIMARY KEY,
    file                    TEXT NOT NULL,
    ir_hash                 TEXT NOT NULL,
    schema_fingerprint      TEXT NOT NULL,
    applied_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_ms             BIGINT NOT NULL DEFAULT 0,
    status                  TEXT NOT NULL DEFAULT 'committed',
    rows_written            JSONB NOT NULL DEFAULT '{{}}'::jsonb,
    error_message           TEXT,
    engine_version          TEXT
)"#
    )
}

/// An index on `(file, applied_at DESC)`.
///
/// Every read of this table is "the latest runs of this file", for the history view and for
/// the drift check. Without it those scan the whole table, which grows by a row per file per
/// run and so is unbounded on a project that seeds in CI.
pub fn create_seeds_index_sql() -> String {
    format!(
        "CREATE INDEX IF NOT EXISTS seeds_file_applied_at_idx \
         ON {SCHEMA}.seeds (file, applied_at DESC)"
    )
}

/// Record a run, inside the caller's transaction.
///
/// Taking the transaction rather than the pool is the point: the row commits with the writes
/// it describes, or not at all.
pub async fn record(tx: &mut Transaction<'_, Postgres>, run: &SeedRun) -> Result<()> {
    let sql = format!(
        "INSERT INTO {SCHEMA}.seeds \
         (file, ir_hash, schema_fingerprint, duration_ms, status, rows_written, error_message, engine_version) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    );
    sqlx::query(&sql)
        .bind(&run.file)
        .bind(&run.ir_hash)
        .bind(&run.schema_fingerprint)
        .bind(run.duration_ms)
        .bind(run.status.as_str())
        .bind(&run.rows_written)
        .bind(&run.error_message)
        .bind(&run.engine_version)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Record a run that rolled back, on its own connection.
///
/// The transaction it described is gone, so this cannot ride along with it. Best effort: a
/// failure to record must not replace the failure that caused the rollback.
pub async fn record_rolled_back(pool: &PgPool, run: &SeedRun) {
    let sql = format!(
        "INSERT INTO {SCHEMA}.seeds \
         (file, ir_hash, schema_fingerprint, duration_ms, status, rows_written, error_message, engine_version) \
         VALUES ($1, $2, $3, $4, 'rolled_back', $5, $6, $7)"
    );
    if let Err(e) = sqlx::query(&sql)
        .bind(&run.file)
        .bind(&run.ir_hash)
        .bind(&run.schema_fingerprint)
        .bind(run.duration_ms)
        .bind(&run.rows_written)
        .bind(&run.error_message)
        .bind(&run.engine_version)
        .execute(pool)
        .await
    {
        eprintln!("Warning: could not record the failed seed run: {e}");
    }
}

/// Whether this exact document already committed for this file.
///
/// Only consulted for `runOnce`. The hash is part of the question on purpose: a file that
/// changed is a different backfill, and skipping it because an older version of it ran would
/// be the wrong answer.
pub async fn already_applied(pool: &PgPool, file: &str, ir_hash: &str) -> Result<bool> {
    let sql = format!(
        "SELECT EXISTS (SELECT 1 FROM {SCHEMA}.seeds \
         WHERE file = $1 AND ir_hash = $2 AND status = 'committed')"
    );
    let exists: bool = sqlx::query_scalar(&sql)
        .bind(file)
        .bind(ir_hash)
        .fetch_one(pool)
        .await?;
    Ok(exists)
}

/// Runs of one file, most recent first.
pub async fn history(pool: &PgPool, file: &str, limit: i64) -> Result<Vec<SeedRunRecord>> {
    let sql = format!(
        "SELECT file, ir_hash, schema_fingerprint, applied_at::text AS applied_at, duration_ms, status, \
                rows_written, error_message, engine_version \
         FROM {SCHEMA}.seeds WHERE file = $1 ORDER BY applied_at DESC LIMIT $2"
    );
    let rows = sqlx::query(&sql)
        .bind(file)
        .bind(limit)
        .fetch_all(pool)
        .await?;

    Ok(rows.into_iter().map(record_from_row).collect())
}

/// The most recent run of every file, for the history view.
pub async fn latest_per_file(pool: &PgPool) -> Result<Vec<SeedRunRecord>> {
    let sql = format!(
        "SELECT DISTINCT ON (file) \
                file, ir_hash, schema_fingerprint, applied_at::text AS applied_at, duration_ms, status, \
                rows_written, error_message, engine_version \
         FROM {SCHEMA}.seeds ORDER BY file, applied_at DESC"
    );
    let rows = sqlx::query(&sql).fetch_all(pool).await?;
    Ok(rows.into_iter().map(record_from_row).collect())
}

/// Whether a file's latest run used a different document than the one before it.
///
/// "This seed is not what ran" is the question the history view exists to answer, and it
/// cannot be answered from one row.
pub async fn has_drifted(pool: &PgPool, file: &str) -> Result<bool> {
    let recent = history(pool, file, 2).await?;
    Ok(match recent.as_slice() {
        [latest, previous] => latest.run.ir_hash != previous.run.ir_hash,
        _ => false,
    })
}

fn record_from_row(row: sqlx::postgres::PgRow) -> SeedRunRecord {
    SeedRunRecord {
        run: SeedRun {
            file: row.try_get("file").unwrap_or_default(),
            ir_hash: row.try_get("ir_hash").unwrap_or_default(),
            schema_fingerprint: row.try_get("schema_fingerprint").unwrap_or_default(),
            status: RunStatus::from_str(
                row.try_get::<String, _>("status")
                    .unwrap_or_default()
                    .as_str(),
            ),
            duration_ms: row.try_get("duration_ms").unwrap_or_default(),
            rows_written: row
                .try_get("rows_written")
                .unwrap_or(serde_json::Value::Null),
            error_message: row.try_get("error_message").ok(),
            engine_version: row.try_get("engine_version").unwrap_or_default(),
        },
        applied_at: row.try_get("applied_at").unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_follows_the_migrations_conventions() {
        let sql = create_seeds_table_sql();
        assert!(
            sql.contains("CREATE TABLE IF NOT EXISTS _supatype.seeds"),
            "{sql}"
        );
        for column in [
            "file",
            "ir_hash",
            "schema_fingerprint",
            "applied_at",
            "duration_ms",
            "status",
            "rows_written",
            "error_message",
            "engine_version",
        ] {
            assert!(sql.contains(column), "missing column {column}: {sql}");
        }
    }

    /// The table is keyed on nothing but its own id: a file appears once per run, not once.
    /// A unique key on `file` would make it a gate rather than a record.
    #[test]
    fn a_file_may_appear_more_than_once() {
        let sql = create_seeds_table_sql();
        assert!(
            !sql.contains("file                    TEXT NOT NULL UNIQUE"),
            "a unique file column would make the ledger a gate: {sql}"
        );
    }

    #[test]
    fn the_index_covers_how_the_table_is_read() {
        let sql = create_seeds_index_sql();
        assert!(sql.contains("(file, applied_at DESC)"), "{sql}");
    }

    #[test]
    fn the_hash_is_stable_and_names_its_algorithm() {
        let a = ir_hash(r#"{"irVersion":1}"#);
        assert_eq!(a, ir_hash(r#"{"irVersion":1}"#));
        assert_ne!(a, ir_hash(r#"{"irVersion":2}"#));
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn status_round_trips() {
        assert_eq!(RunStatus::from_str("rolled_back"), RunStatus::RolledBack);
        assert_eq!(RunStatus::from_str("committed"), RunStatus::Committed);
        assert_eq!(RunStatus::Committed.as_str(), "committed");
    }
}
