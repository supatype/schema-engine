//! Putting the ledger back when a push is rolled back.
//!
//! A rollback runs the migration's `sql_down`, which puts the objects back as they were; the ledger
//! has to go back with them, or the next push reads rows for objects that are gone, and none for
//! ones that are back. So before a push writes its rows it records, against its migration, each
//! touched row as it was (or that there was none), and rolling that migration back restores
//! exactly those. A rollback only ever undoes the latest applied migration, so what was recorded is
//! what the ledger held just before it.
//!
//! A migration from an engine before this has nothing recorded: rolling it back leaves the ledger
//! as it is, as every rollback did then, and the next push reconciles it.

use anyhow::{Context, Result};
use sqlx::PgConnection;

use super::{key_columns, ObjectKey, SCHEMA};

/// One row per (migration, object) the migration's push wrote or removed: the row as it was, or
/// `existed = false` when there was none.
pub fn create_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.managed_objects_undo (
    migration_id        INT NOT NULL REFERENCES {SCHEMA}.migrations (id),
    kind                TEXT NOT NULL,
    schema_name         TEXT NOT NULL,
    parent              TEXT NOT NULL,
    name                TEXT NOT NULL,
    existed             BOOLEAN NOT NULL,
    desired_fp          TEXT,
    desired_sql         TEXT,
    live_fp             TEXT,
    live_def            TEXT,
    status              TEXT,
    prior_migration_id  INT,
    created_at          TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ,
    PRIMARY KEY (migration_id, kind, schema_name, parent, name)
)"#
    )
}

/// Records, against `migration_id`, the rows for `keys` as they are now, before the push writes
/// them. Called once per push, in its transaction.
pub async fn remember(
    conn: &mut PgConnection,
    migration_id: i32,
    keys: &[ObjectKey],
) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    let keys = key_columns(keys.iter());
    sqlx::query(&format!(
        "INSERT INTO {SCHEMA}.managed_objects_undo
            (migration_id, kind, schema_name, parent, name, existed, desired_fp, desired_sql,
             live_fp, live_def, status, prior_migration_id, created_at, updated_at)
         SELECT $5, k.kind, k.schema_name, k.parent, k.name, m.kind IS NOT NULL, m.desired_fp,
                m.desired_sql, m.live_fp, m.live_def, m.status, m.migration_id, m.created_at,
                m.updated_at
           FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[])
                AS k(kind, schema_name, parent, name)
           LEFT JOIN {SCHEMA}.managed_objects m
             ON m.kind = k.kind AND m.schema_name = k.schema_name
            AND m.parent = k.parent AND m.name = k.name
         ON CONFLICT DO NOTHING"
    ))
    .bind(&keys.kinds)
    .bind(&keys.schemas)
    .bind(&keys.parents)
    .bind(&keys.names)
    .bind(migration_id)
    .execute(&mut *conn)
    .await
    .context("record the ledger as it was before the push")?;
    Ok(())
}

/// Puts the ledger back as it was before `migration_id`'s push: rows it added go, rows it changed
/// or removed come back as they were. In the rollback's transaction.
///
/// Only rows still as the push left them. The ledger is also written outside a migration (`adopt`,
/// `adopt --release`, `doctor --rebaseline`), and a write made after the push is not the push's to
/// undo: a release made since would otherwise be silently reverted. Every row a push writes carries
/// its transaction's `NOW()`, as does its migration's `applied_at`, so a row written since is one
/// updated after it.
pub async fn restore(conn: &mut PgConnection, migration_id: i32) -> Result<()> {
    let untouched_since = format!("(SELECT applied_at FROM {SCHEMA}.migrations WHERE id = $1)");
    let statements = [
        format!(
            "DELETE FROM {SCHEMA}.managed_objects m USING {SCHEMA}.managed_objects_undo u
              WHERE u.migration_id = $1 AND NOT u.existed
                AND m.kind = u.kind AND m.schema_name = u.schema_name
                AND m.parent = u.parent AND m.name = u.name
                AND m.updated_at <= {untouched_since}"
        ),
        format!(
            "INSERT INTO {SCHEMA}.managed_objects
                (kind, schema_name, parent, name, desired_fp, desired_sql, live_fp, live_def,
                 status, migration_id, created_at, updated_at)
             SELECT kind, schema_name, parent, name, desired_fp, desired_sql, live_fp, live_def,
                    status, prior_migration_id, created_at, updated_at
               FROM {SCHEMA}.managed_objects_undo
              WHERE migration_id = $1 AND existed
             ON CONFLICT (kind, schema_name, parent, name) DO UPDATE SET
                desired_fp = EXCLUDED.desired_fp,
                desired_sql = EXCLUDED.desired_sql,
                live_fp = EXCLUDED.live_fp,
                live_def = EXCLUDED.live_def,
                status = EXCLUDED.status,
                migration_id = EXCLUDED.migration_id,
                created_at = EXCLUDED.created_at,
                updated_at = EXCLUDED.updated_at
              WHERE {SCHEMA}.managed_objects.updated_at <= {untouched_since}"
        ),
        format!("DELETE FROM {SCHEMA}.managed_objects_undo WHERE migration_id = $1"),
    ];
    for sql in &statements {
        sqlx::query(sql)
            .bind(migration_id)
            .execute(&mut *conn)
            .await
            .context("put the ledger back as it was before the push")?;
    }
    Ok(())
}
