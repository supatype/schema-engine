//! How large each table a push changes is, read from the catalog without a lock: what decides
//! whether a statement runs online (IN-C 2) and whether a rewrite needs consent (IN-C 3).

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use sqlx::PgConnection;

use crate::desired::ObjectKey;
use crate::differ::{DiffOutput, Operation};
use crate::generator::sql::online::OnlineTables;
use crate::introspector::fingerprint::ObjectKind;
use crate::ledger::reconcile::{self, Action};
use crate::push::State;

/// What the catalog says of one table's size, read without taking a lock on it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TableSize {
    /// `pg_class.reltuples`, or the statistics' live row count where it has never been analysed.
    pub rows: i64,
    /// Whether it holds rows, or has: storage, an estimate, or an insert counted. A table that
    /// cannot be shown empty is taken to have rows, which only makes the push gentler.
    pub has_rows: bool,
}

/// `(table, reltuples, relpages, n_live_tup, n_tup_ins)`.
type SizeRow = (String, f64, i64, i64, i64);

impl TableSize {
    fn of(&(_, reltuples, relpages, live, inserted): &SizeRow) -> TableSize {
        TableSize {
            // A rounded estimate, far inside `i64`; -1 before the table was ever analysed.
            rows: if reltuples >= 0.0 {
                reltuples as i64
            } else {
                live
            },
            has_rows: reltuples > 0.0 || relpages > 0 || live > 0 || inserted > 0,
        }
    }
}

/// The size of each table of `schema`, by the name `diff` knows it by: a table it renames is read
/// under its old name. From `pg_class` and the statistics views, which take no lock, so planning a
/// push never waits on an application.
pub async fn table_sizes(
    conn: &mut PgConnection,
    schema: &str,
    diff: &DiffOutput,
) -> Result<BTreeMap<String, TableSize>> {
    let rows: Vec<SizeRow> = sqlx::query_as(
        "SELECT c.relname::text, c.reltuples::float8, c.relpages::int8,
                COALESCE(s.n_live_tup, 0)::int8, COALESCE(s.n_tup_ins, 0)::int8
           FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
          WHERE n.nspname = $1 AND c.relkind IN ('r', 'p')",
    )
    .bind(schema)
    .fetch_all(&mut *conn)
    .await
    .context("read the size of each table")?;
    let mut sizes: BTreeMap<String, TableSize> = rows
        .iter()
        .map(|row| (row.0.clone(), TableSize::of(row)))
        .collect();
    for op in &diff.operations {
        if let Operation::RenameTable { from, to, .. } = op {
            if let Some(size) = sizes.get(from).copied() {
                sizes.insert(to.clone(), size);
            }
        }
    }
    Ok(sizes)
}

/// What decides the statements that run online: the tables with rows, the INVALID indexes an
/// earlier build left, and the keys and checks of ours still `NOT VALID` that this push leaves as
/// they are, which it validates.
pub fn online_tables(
    state: &State,
    plan: &reconcile::Plan,
    sizes: &BTreeMap<String, TableSize>,
    schema: &str,
) -> OnlineTables {
    let (invalid, unvalidated): (Vec<ObjectKey>, Vec<ObjectKey>) = pending(state, schema)
        .into_iter()
        .partition(|k| k.kind == ObjectKind::Index);
    OnlineTables {
        with_rows: sizes
            .iter()
            .filter(|(_, s)| s.has_rows)
            .map(|(t, _)| t.clone())
            .collect(),
        invalid_indexes: invalid.into_iter().map(|k| k.name).collect(),
        unvalidated: unvalidated
            .into_iter()
            .filter(|key| left_as_it_is(plan, key))
            .collect(),
    }
}

/// The catalog's unfinished objects of `schema`, as keys.
fn pending(state: &State, schema: &str) -> Vec<ObjectKey> {
    state
        .catalog
        .pending
        .iter()
        .map(|p| ObjectKey {
            kind: p.kind,
            schema: schema.to_string(),
            parent: p.table.clone(),
            name: p.name.clone(),
        })
        .collect()
}

/// Whether the reconcile keeps `key` as it is: ours, wanted and unchanged.
fn left_as_it_is(plan: &reconcile::Plan, key: &ObjectKey) -> bool {
    plan.actions
        .iter()
        .any(|a| a.key() == key && matches!(a, Action::Keep { .. } | Action::Restate { .. }))
}
