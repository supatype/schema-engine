//! The file `supatype migrate` prints.
//!
//! Plain, it is the migration a push would apply, planned from a snapshot of the database without
//! taking any lock an application waits on (IN-A): nothing stronger than the ACCESS SHARE a read
//! takes. Applied by hand it changes the schema and records nothing, so its header says the next
//! push will find the tables unmanaged.
//!
//! With `--record` it is a push, written out so that applying it by hand is the push. A push writes
//! more than the migration: the engine's own tables, the history row and a ledger row for every
//! object it made, whose live fingerprint is read from the catalog after the migration ran. A file
//! that carried only the migration left a database with Supatype's tables and no record that they
//! were Supatype's, and the next push refused them as unmanaged (E17). The live fingerprints cannot
//! be known without running the migration, so the recorded file is made by running it: the
//! bootstrap, the plan and the push's own writes, in a transaction that is always rolled back, and
//! which takes the locks a push takes. What the push wrote is read back before the rollback and
//! rendered as statements that write the same rows, and the file carries them inside its own
//! transaction.

use anyhow::{Context, Result};
use serde_json::Value;
use sqlx::{PgConnection, PgPool};

use crate::generator::sql::migration::Recording;
use crate::parser::ast::SchemaAst;
use crate::sql_quote::{quote_ident, quote_literal};
use crate::state::migration_history;

const SCHEMA: &str = "_supatype";
const LEDGER_KEY: &[&str] = &["kind", "schema_name", "parent", "name"];

/// How `supatype migrate` was asked to write its file.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Allow destructive operations, and rewrites of large tables.
    pub force: bool,
    /// Rehearse the push, under its locks, so the file also records the history and the ledger.
    pub record: bool,
}

/// The header of a file that records nothing.
pub const UNRECORDED_HEADER: &str = "\
-- This file does not record what it does. Applied by hand, it changes the schema and writes no
-- migration history and no record of which objects are Supatype's, so the next `supatype push`
-- finds the tables it made unmanaged and refuses them until `supatype adopt` takes them over.
-- To write a file that records it as a push does, run `supatype migrate --record`, which
-- rehearses the push and takes the same table locks while it does.";

/// The migration file for pushing `ast` to the database at `pool`.
pub async fn render(
    pool: &PgPool,
    ast: &SchemaAst,
    schema: &str,
    options: Options,
) -> Result<String> {
    if options.record {
        return render_recorded(pool, ast, schema, options.force).await;
    }
    render_unrecorded(pool, ast, schema, options.force).await
}

/// The migration alone, planned in a transaction that only reads, under one snapshot, and is rolled
/// back: no bootstrap, no engine lock, nothing stronger than ACCESS SHARE on any table.
async fn render_unrecorded(
    pool: &PgPool,
    ast: &SchemaAst,
    schema: &str,
    force: bool,
) -> Result<String> {
    use sqlx::Connection;
    let mut conn = pool.acquire().await?;
    let mut tx = conn.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await
        .context("read the database under one snapshot")?;
    let plan = crate::push::plan_on(&mut tx, ast, schema).await;
    tx.rollback().await?;
    let plan = match plan {
        Ok(plan) => plan,
        Err(e) => return Err(crate::push::busy_if_waiting_on_a_writer(pool, e).await),
    };
    crate::push::refuse_conflicts(&plan)?;
    let file = plan.migration(force)?.file();
    Ok(format!("{UNRECORDED_HEADER}\n{file}"))
}

/// The migration file, with the bootstrap and the push's history and ledger writes in it. A plan
/// with nothing to apply writes nothing, as a push writes no migration, and its file records
/// nothing.
///
/// The rehearsal is a writer, under the engine's lock like a push, and runs the bootstrap whatever
/// version the database records: the file carries what a push runs on a database with no bootstrap
/// yet (the bootstrap, its version row, then the claim readers and `auth.*` aliases every push
/// reinstalls), so applied by hand to any database it leaves the next push nothing to bootstrap.
/// Every statement is in its transaction, as rehearsed: no index is built concurrently.
async fn render_recorded(
    pool: &PgPool,
    ast: &SchemaAst,
    schema: &str,
    force: bool,
) -> Result<String> {
    let mut tx = crate::push::begin_writer(pool).await?;
    migration_history::run_bootstrap(&mut tx, &migration_history::bootstrap_version())
        .await
        .context("rehearse the bootstrap")?;
    let plan = crate::push::plan_on(&mut tx, ast, schema).await?;
    if !plan.has_changes() {
        return Ok(plan.migration_in_transaction(force)?.file());
    }

    let mut bootstrap = migration_history::bootstrap_file_statements();
    bootstrap.extend(migration_history::auth_helper_statements(&mut tx, "auth").await?);
    let name = format!("migrate_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f"));
    let (migration, migration_id) = crate::push::rehearse(&mut tx, &plan, force, name.clone())
        .await
        .context("rehearse the migration, to record what a push would")?;
    let ledger = recorded(&mut tx, &name, migration_id).await?;
    tx.rollback().await?;
    Ok(migration.file_recording(&Recording { bootstrap, ledger }))
}

/// What the rehearsed push wrote, read back as JSON.
struct Written {
    /// The history row, without the columns its insert fills in.
    migration: Value,
    /// Each ledger row as it was before the push, without its migration.
    undo: Value,
    /// Each ledger row the push wrote, as it left it, without its timestamps.
    rows: Value,
    /// The key of each ledger row the push removed.
    removed: Value,
    /// The `schema_state` row, without its timestamp.
    state: Value,
}

/// The statements that write what the push wrote as migration `migration_id`, under `name`.
async fn recorded(conn: &mut PgConnection, name: &str, migration_id: i32) -> Result<Vec<String>> {
    let written = read_written(conn, migration_id).await?;
    let this_migration = format!(
        "(SELECT id FROM {SCHEMA}.migrations WHERE name = {})",
        quote_literal(name)
    );
    let migration_ref = format!(
        "CASE WHEN r.migration_id = {migration_id} THEN {this_migration} ELSE r.migration_id END"
    );
    let ledger_upsert = format!(
        "ON CONFLICT ({}) DO UPDATE SET {}, updated_at = NOW()",
        LEDGER_KEY.join(", "),
        excluded(&written.rows, LEDGER_KEY)
    );
    let state_upsert = format!(
        "ON CONFLICT (id) DO UPDATE SET {}, captured_at = NOW()",
        excluded(&written.state, &["id"])
    );
    Ok([
        insert("migrations", &written.migration, &[], ""),
        insert(
            "managed_objects_undo",
            &written.undo,
            &[("migration_id", &this_migration)],
            "",
        ),
        delete_ledger_rows(&written.removed),
        insert(
            "managed_objects",
            &written.rows,
            &[("migration_id", &migration_ref)],
            &ledger_upsert,
        ),
        insert("schema_state", &written.state, &[], &state_upsert),
    ]
    .into_iter()
    .flatten()
    .collect())
}

async fn read_written(conn: &mut PgConnection, migration_id: i32) -> Result<Written> {
    let key = LEDGER_KEY.join(", ");
    let (migration, undo, rows, removed, state): (Value, Value, Value, Value, Value) =
        sqlx::query_as(&format!(
            "WITH u AS (SELECT * FROM {SCHEMA}.managed_objects_undo WHERE migration_id = $1)
             SELECT
               (SELECT jsonb_agg(to_jsonb(m) - 'id' - 'applied_at')
                  FROM {SCHEMA}.migrations m WHERE m.id = $1),
               COALESCE((SELECT jsonb_agg(to_jsonb(u) - 'migration_id') FROM u), '[]'),
               COALESCE((SELECT jsonb_agg(to_jsonb(m) - 'created_at' - 'updated_at')
                           FROM {SCHEMA}.managed_objects m JOIN u USING ({key})), '[]'),
               COALESCE((SELECT jsonb_agg(jsonb_build_object(
                                  'kind', u.kind, 'schema_name', u.schema_name,
                                  'parent', u.parent, 'name', u.name))
                           FROM u
                          WHERE NOT EXISTS (SELECT 1 FROM {SCHEMA}.managed_objects m
                                             WHERE (m.kind, m.schema_name, m.parent, m.name)
                                                 = (u.kind, u.schema_name, u.parent, u.name))),
                        '[]'),
               COALESCE((SELECT jsonb_agg(to_jsonb(s) - 'captured_at')
                           FROM {SCHEMA}.schema_state s WHERE s.id = 1), '[]')"
        ))
        .bind(migration_id)
        .fetch_one(&mut *conn)
        .await
        .context("read back what the rehearsed push recorded")?;
    Ok(Written {
        migration,
        undo,
        rows,
        removed,
        state,
    })
}

/// The column names of `rows`, a JSON array of objects read from one table.
fn columns(rows: &Value) -> Vec<&str> {
    rows.as_array()
        .and_then(|rows| rows.first())
        .and_then(Value::as_object)
        .map(|row| row.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

/// `col = EXCLUDED.col` for every column of `rows` but `key`.
fn excluded(rows: &Value, key: &[&str]) -> String {
    columns(rows)
        .into_iter()
        .filter(|c| !key.contains(c))
        .map(|c| format!("{0} = EXCLUDED.{0}", quote_ident(c)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `rows` as JSON for the statement: a literal cast to `jsonb`.
fn json_literal(rows: &Value) -> String {
    format!("{}::jsonb", quote_literal(&rows.to_string()))
}

/// `INSERT INTO _supatype.<table>` of `rows` (a JSON array read from that table), each column taken
/// from its row unless `computed` gives it an expression over the row `r`, then `tail`. `None`
/// when there are no rows.
fn insert(table: &str, rows: &Value, computed: &[(&str, &str)], tail: &str) -> Option<String> {
    let mut names = columns(rows);
    if names.is_empty() {
        return None;
    }
    for (name, _) in computed {
        if !names.contains(name) {
            names.push(name);
        }
    }
    let values: Vec<String> = names
        .iter()
        .map(|name| match computed.iter().find(|(c, _)| c == name) {
            Some((_, expression)) => (*expression).to_string(),
            None => format!("r.{}", quote_ident(name)),
        })
        .collect();
    let names: Vec<String> = names.iter().map(|n| quote_ident(n)).collect();
    Some(format!(
        "INSERT INTO {SCHEMA}.{table} ({})\nSELECT {}\n  FROM jsonb_populate_recordset(NULL::{SCHEMA}.{table}, {}) AS r\n{tail}",
        names.join(", "),
        values.join(", "),
        json_literal(rows),
    ))
}

/// Removes the ledger rows keyed in `keys`; `None` when there are none.
fn delete_ledger_rows(keys: &Value) -> Option<String> {
    if columns(keys).is_empty() {
        return None;
    }
    let pairs: Vec<String> = LEDGER_KEY
        .iter()
        .map(|c| format!("m.{c} = k.{c}"))
        .collect();
    Some(format!(
        "DELETE FROM {SCHEMA}.managed_objects m\n USING jsonb_populate_recordset(NULL::{SCHEMA}.managed_objects, {}) AS k\n WHERE {}",
        json_literal(keys),
        pairs.join(" AND ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_are_inserted_by_column_with_computed_ones_in_place() {
        let rows = serde_json::json!([{ "kind": "table", "name": "it's", "migration_id": 7 }]);
        let sql = insert("managed_objects", &rows, &[("migration_id", "42")], "").unwrap();
        assert!(
            sql.starts_with(
                "INSERT INTO _supatype.managed_objects (\"kind\", \"name\", \"migration_id\")\n\
                 SELECT r.\"kind\", r.\"name\", 42"
            ),
            "{sql}"
        );
        assert!(
            sql.contains("'[{\"kind\":\"table\",\"name\":\"it''s\",\"migration_id\":7}]'::jsonb"),
            "{sql}"
        );
        assert_eq!(
            insert("managed_objects", &serde_json::json!([]), &[], ""),
            None
        );
    }

    #[test]
    fn an_upsert_sets_every_column_but_the_key() {
        let rows = serde_json::json!([{ "kind": "t", "name": "n", "status": "managed" }]);
        assert_eq!(
            excluded(&rows, &["kind", "name"]),
            "\"status\" = EXCLUDED.\"status\""
        );
        assert_eq!(delete_ledger_rows(&serde_json::json!([])), None);
    }
}
