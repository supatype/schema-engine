//! A column made `NOT NULL` after a push's transaction has committed (LK7): its helper check is
//! validated under SHARE UPDATE EXCLUSIVE, which lets reads and writes through, then `SET NOT NULL`
//! runs, which a validated check spares its scan, so its ACCESS EXCLUSIVE lasts a moment.

use anyhow::Result;
use sqlx::{Executor, PgConnection};

use super::after_commit::{refresh_rows, Unfinished, AFTER_COMMIT_LOCK_TIMEOUT};
use super::{EngineSession, PUSH_LOCK_TIMEOUT};
use crate::generator::sql::online::NotNull;

/// Makes each of `columns` `NOT NULL`, refreshing its ledger row; one that cannot be has its
/// helper check dropped and is reported, and stays nullable until the next push.
pub async fn make_not_null(
    session: &mut EngineSession,
    columns: &[NotNull],
    schema: &str,
    unfinished: &mut Unfinished,
) -> Result<()> {
    let mut done = Vec::new();
    for column in columns {
        let Err(e) = set_one(session, column).await else {
            done.push(column.key());
            continue;
        };
        let left = if drop_helper(session, column).await {
            String::new()
        } else {
            format!(
                ", and its helper check {} is left until the next push replaces it",
                column.check
            )
        };
        unfinished.failures.push(format!(
            "{}.{} could not be made NOT NULL: {e:#}. It stays nullable{left}; fix the rows that \
             are NULL and push again",
            column.table, column.column
        ));
    }
    if done.is_empty() {
        return Ok(());
    }
    let mut tx = session.begin(AFTER_COMMIT_LOCK_TIMEOUT).await?;
    refresh_rows(&mut tx, &done, schema).await?;
    tx.commit().await?;
    Ok(())
}

/// The check validated in one transaction, then `SET NOT NULL` and the check's drop in another,
/// which waits for its lock no longer than a push does.
async fn set_one(session: &mut EngineSession, column: &NotNull) -> Result<()> {
    let mut tx = session.begin(AFTER_COMMIT_LOCK_TIMEOUT).await?;
    run(&mut tx, &column.validate_sql()).await?;
    tx.commit().await?;
    let mut tx = session.begin(PUSH_LOCK_TIMEOUT).await?;
    for sql in column.set_sql() {
        run(&mut tx, &sql).await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn run(conn: &mut PgConnection, sql: &str) -> Result<()> {
    conn.execute(sqlx::raw_sql(sql)).await?;
    Ok(())
}

/// Drops the helper check, so nothing of a column that could not be made `NOT NULL` is left.
/// Whether it is gone.
async fn drop_helper(session: &mut EngineSession, column: &NotNull) -> bool {
    let Ok(mut tx) = session.begin(PUSH_LOCK_TIMEOUT).await else {
        return false;
    };
    run(&mut tx, &column.drop_sql()).await.is_ok() && tx.commit().await.is_ok()
}
