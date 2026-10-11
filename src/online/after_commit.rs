//! What runs once a push's transaction has committed: the keys and checks it added `NOT VALID`
//! are validated, and the indexes it left are built with `CREATE INDEX CONCURRENTLY`, each
//! recorded in the ledger once it is in place (IN-C 2).

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use sqlx::{Connection, Executor, PgConnection};

use super::EngineSession;
use crate::desired::ObjectKey;
use crate::generator::sql::online::{validate_sql, AfterCommit, ConcurrentIndex};
use crate::introspector::fingerprint::ObjectFingerprint;
use crate::ledger::{self, LedgerRow};
use crate::sql_quote::quote_qualified;

/// How long a statement that runs after commit waits for a lock. Validation and a concurrent build
/// take SHARE UPDATE EXCLUSIVE, which no read or write waits on, so a longer wait holds nobody up.
const AFTER_COMMIT_LOCK_TIMEOUT: &str = "30s";

/// What the steps after commit could not do. The migration itself is applied.
#[derive(Debug, Default)]
pub struct Unfinished {
    pub failures: Vec<String>,
}

/// Runs `after` on `session`, recording in the ledger what is put in place: validations first,
/// then the index builds. `migration_id` is the push's history row, which an index it builds is
/// recorded against. Returns what failed; an error is a failure to run them at all.
pub async fn run_after_commit(
    session: &mut EngineSession,
    after: &AfterCommit,
    schema: &str,
    migration_id: Option<i32>,
) -> Result<Unfinished> {
    let mut unfinished = Unfinished::default();
    if !after.validations.is_empty() {
        validate(session, &after.validations, schema, &mut unfinished).await?;
    }
    if !after.indexes.is_empty() {
        let built = build_indexes(session, &after.indexes, &mut unfinished).await?;
        record_indexes(session, &built, schema, migration_id).await?;
    }
    Ok(unfinished)
}

/// Validates each key and check in one transaction, each in a savepoint so one that fails leaves
/// the others validated, then rewrites the live fingerprint of each validated one's row.
async fn validate(
    session: &mut EngineSession,
    keys: &[ObjectKey],
    schema: &str,
    unfinished: &mut Unfinished,
) -> Result<()> {
    let mut tx = session.begin(AFTER_COMMIT_LOCK_TIMEOUT).await?;
    let mut validated = Vec::new();
    for key in keys {
        let sql = validate_sql(key);
        let mut savepoint = tx.begin().await?;
        let ran = (&mut *savepoint).execute(sqlx::raw_sql(&sql)).await;
        match ran {
            Ok(_) => {
                savepoint.commit().await?;
                validated.push(key.clone());
            }
            Err(e) => {
                savepoint.rollback().await?;
                unfinished.failures.push(format!(
                    "{key} was added NOT VALID and could not be validated: {e}. It holds for rows \
                     written from now on; fix the rows that break it and push again to validate it"
                ));
            }
        }
    }
    refresh_rows(&mut tx, &validated, schema).await?;
    tx.commit().await.context("commit the validations")
}

/// Rewrites the live fingerprint and definition of the rows for `keys` from the catalog.
async fn refresh_rows(conn: &mut PgConnection, keys: &[ObjectKey], schema: &str) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    let live = live_fingerprints(conn, schema).await?;
    let mut rows: Vec<LedgerRow> = ledger::load_if_present(conn).await?;
    rows.retain(|r| keys.contains(&r.key));
    for row in &mut rows {
        if let Some(fp) = live.get(&row.key) {
            row.live_fp = fp.fingerprint.clone();
            row.live_def = fp.definition.clone();
        }
    }
    ledger::upsert_after_commit(conn, &rows).await
}

async fn live_fingerprints(
    conn: &mut PgConnection,
    schema: &str,
) -> Result<BTreeMap<ObjectKey, ObjectFingerprint>> {
    let state = crate::push::read_state(conn, schema).await?;
    Ok(state
        .fingerprints
        .into_iter()
        .map(|f| (f.key(), f))
        .collect())
}

/// Builds each index concurrently, outside any transaction. An INVALID index left under its name
/// (by an earlier build) is dropped first, and one this build leaves is dropped after it, so the
/// next push starts clean. Returns the indexes built.
async fn build_indexes<'a>(
    session: &mut EngineSession,
    indexes: &'a [ConcurrentIndex],
    unfinished: &mut Unfinished,
) -> Result<Vec<&'a ConcurrentIndex>> {
    let conn = session.conn();
    let was = set_lock_timeout(conn, AFTER_COMMIT_LOCK_TIMEOUT).await?;
    let mut built = Vec::new();
    for index in indexes {
        drop_if_invalid(conn, &index.key).await?;
        let ran = (&mut *conn).execute(sqlx::raw_sql(&index.build_sql)).await;
        match ran {
            Ok(_) => built.push(index),
            Err(e) => {
                drop_if_invalid(conn, &index.key).await?;
                unfinished.failures.push(format!(
                    "index {} could not be built: {e}. Nothing of it was left behind; the next \
                     push builds it again",
                    index.key.name
                ));
            }
        }
    }
    set_lock_timeout(conn, &was).await?;
    Ok(built)
}

/// Sets the session's lock timeout to `timeout`, returning what it was.
async fn set_lock_timeout(conn: &mut PgConnection, timeout: &str) -> Result<String> {
    let was: String = sqlx::query_scalar("SELECT current_setting('lock_timeout')")
        .fetch_one(&mut *conn)
        .await
        .context("read the session's lock timeout")?;
    sqlx::query("SELECT set_config('lock_timeout', $1, false)")
        .bind(timeout)
        .execute(&mut *conn)
        .await
        .context("set the session's lock timeout")?;
    Ok(was)
}

/// Drops the index `key` names when it is INVALID, without blocking writes to its table.
async fn drop_if_invalid(conn: &mut PgConnection, key: &ObjectKey) -> Result<()> {
    let relation = quote_qualified(&key.schema, &key.name);
    let invalid: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_index WHERE indexrelid = to_regclass($1)
                         AND NOT indisvalid)",
    )
    .bind(&relation)
    .fetch_one(&mut *conn)
    .await?;
    if invalid {
        let drop = format!("DROP INDEX CONCURRENTLY IF EXISTS {relation}");
        (&mut *conn)
            .execute(sqlx::raw_sql(&drop))
            .await
            .with_context(|| format!("drop the INVALID index {relation}"))?;
    }
    Ok(())
}

/// Records each built index as a push records any object it made.
async fn record_indexes(
    session: &mut EngineSession,
    built: &[&ConcurrentIndex],
    schema: &str,
    migration_id: Option<i32>,
) -> Result<()> {
    if built.is_empty() {
        return Ok(());
    }
    let mut tx = session.begin(AFTER_COMMIT_LOCK_TIMEOUT).await?;
    let live = live_fingerprints(&mut tx, schema).await?;
    let rows: Vec<LedgerRow> = built
        .iter()
        .filter_map(|index| {
            let fp = live.get(&index.key)?;
            Some(LedgerRow {
                key: index.key.clone(),
                desired_fp: ledger::desired_fingerprint(index.key.kind, &index.create_sql),
                desired_sql: index.create_sql.clone(),
                live_fp: fp.fingerprint.clone(),
                live_def: fp.definition.clone(),
                status: index.status,
                migration_id,
            })
        })
        .collect();
    ledger::upsert_after_commit(&mut tx, &rows).await?;
    tx.commit().await.context("record the indexes built")
}

/// A push whose migration committed while something meant to run after it did not.
#[derive(Debug)]
pub struct AfterCommitFailed {
    /// The migration applied, or `None` for an up-to-date push.
    pub name: Option<String>,
    pub failures: Vec<String>,
}

impl std::fmt::Display for AfterCommitFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let applied = match &self.name {
            Some(name) => format!("Migration {name} was applied"),
            None => "The schema is up to date".to_string(),
        };
        write!(
            f,
            "{applied}, but {} step(s) that run after it did not finish: {}",
            self.failures.len(),
            self.failures.join("; ")
        )
    }
}

impl std::error::Error for AfterCommitFailed {}

/// `Ok` when everything after commit was done; otherwise [`AfterCommitFailed`] naming each step.
pub fn finished(unfinished: Unfinished, name: Option<&str>) -> Result<()> {
    if unfinished.failures.is_empty() {
        return Ok(());
    }
    Err(AfterCommitFailed {
        name: name.map(String::from),
        failures: unfinished.failures,
    }
    .into())
}
