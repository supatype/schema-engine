//! A rollback's index drops, run concurrently once its transaction has committed (LK7).
//!
//! `DROP INDEX` takes ACCESS EXCLUSIVE on the index's table, held until the rollback commits, so
//! every read and write of the table queued behind it. `DROP INDEX CONCURRENTLY` takes SHARE
//! UPDATE EXCLUSIVE, which no read or write waits on, but cannot run in a transaction: so a drop
//! that nothing later in the rollback depends on runs after it.

use anyhow::{Context, Result};
use sqlx::{Executor, PgPool};

use crate::desired::statements::{head, split_statements};
use crate::generator::sql::online::drop_concurrently_sql;

const DROP_INDEX: &str = "DROP INDEX IF EXISTS ";

/// `sql` without the index drops that can run after its transaction, and those indexes, quoted and
/// qualified as `sql` names them. A drop stays where it is when a later statement names the index
/// again (made again under its name, say, or attached to a constraint).
pub fn concurrent_drops(sql: &str) -> (String, Vec<String>) {
    let statements = split_statements(sql);
    let mut kept = String::new();
    let mut later = Vec::new();
    for (i, statement) in statements.iter().enumerate() {
        let index = dropped_index(statement).filter(|index| {
            // Its name as a later statement may write it, with or without its schema.
            let bare = index.rsplit('.').next().unwrap_or(index);
            !statements[i + 1..].iter().any(|s| s.contains(bare))
        });
        match index {
            Some(index) => later.push(index),
            None => kept.push_str(statement),
        }
    }
    (kept, later)
}

/// The index a lone `DROP INDEX IF EXISTS <index>;` drops.
fn dropped_index(statement: &str) -> Option<String> {
    let index = head(statement)
        .strip_prefix(DROP_INDEX)?
        .trim_end()
        .strip_suffix(';')?
        .trim();
    let lone = !index.is_empty() && !index.contains([';', ',', ' ', '\n']);
    lone.then(|| index.to_string())
}

/// Drops each of `indexes` concurrently. The rollback has committed, so a drop that fails leaves
/// an index nothing records: the error names it.
pub async fn drop_concurrently(pool: &PgPool, indexes: &[String]) -> Result<()> {
    if indexes.is_empty() {
        return Ok(());
    }
    let mut conn = pool.acquire().await.context("acquire a connection")?;
    // One statement at a time: several sent together run as one transaction, which a concurrent
    // drop refuses.
    conn.execute("SET lock_timeout = '30s'").await?;
    let mut failed = None;
    for index in indexes {
        let dropped = conn
            .execute(sqlx::raw_sql(&drop_concurrently_sql(index)))
            .await;
        if let Err(e) = dropped {
            failed = Some(anyhow::Error::from(e).context(format!(
                "The rollback was applied, but the index {index} it removes could not be \
                 dropped; drop it with DROP INDEX CONCURRENTLY"
            )));
            break;
        }
    }
    conn.execute("RESET lock_timeout").await?;
    failed.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lone_index_drop_moves_after_the_transaction_unless_the_index_is_named_again() {
        let sql = "-- undo\nDROP INDEX IF EXISTS \"public\".\"a_idx\";\n\
                   DROP INDEX IF EXISTS \"public\".\"b_idx\";\n\
                   CREATE INDEX IF NOT EXISTS \"b_idx\" ON \"public\".\"t\" (\"x\");\n\
                   ALTER TABLE \"public\".\"t\" DROP COLUMN \"y\";\n";
        let (kept, later) = concurrent_drops(sql);
        assert_eq!(later, ["\"public\".\"a_idx\""]);
        assert!(!kept.contains("a_idx"), "{kept}");
        assert!(
            kept.contains("DROP INDEX IF EXISTS \"public\".\"b_idx\""),
            "{kept}"
        );
        assert!(kept.contains("DROP COLUMN"), "{kept}");
    }
}
