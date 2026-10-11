//! The file `supatype migrate` prints: a push, written out so that applying it by hand is the push.
//!
//! A push writes more than the migration: the engine's own tables, the history row and a ledger row
//! for every object it made, whose live fingerprint is read from the catalog after the migration
//! ran. A file that carried only the migration left a database with Supatype's tables and no
//! record that they were Supatype's, and the next push refused them as unmanaged (E17).
//!
//! The live fingerprints cannot be known without running the migration, so the file is made by
//! running it: the bootstrap, the plan and the push's own writes, in a transaction that is always
//! rolled back. What the push wrote is read back before the rollback and rendered as statements
//! that write the same rows, and the file carries them inside its own transaction.

use anyhow::{Context, Result};
use serde_json::Value;
use sqlx::{Executor, PgConnection, PgPool};

use crate::generator::sql::migration::Recording;
use crate::parser::ast::SchemaAst;
use crate::sql_quote::{quote_ident, quote_literal};
use crate::state::{migration_history, studio_state};

const SCHEMA: &str = "_supatype";
const LEDGER_KEY: &[&str] = &["kind", "schema_name", "parent", "name"];

/// The migration file for pushing `ast` to the database at `pool`, with the bootstrap and the
/// push's history and ledger writes in it. A plan with nothing to apply writes nothing, as a push
/// writes no migration, and its file records nothing.
pub async fn render(pool: &PgPool, ast: &SchemaAst, schema: &str, force: bool) -> Result<String> {
    let mut tx = pool.begin().await?;
    crate::push::take_engine_lock(&mut tx).await?;
    let bootstrap = bootstrap_statements();
    for sql in &bootstrap {
        (&mut *tx)
            .execute(sqlx::raw_sql(sql))
            .await
            .context("rehearse the bootstrap")?;
    }
    migration_history::assert_project_schema(&mut *tx, schema).await?;
    let previous = migration_history::load_latest_schema_ast_on(&mut tx).await;
    let plan = crate::push::plan_on(&mut tx, ast, schema, previous.as_ref()).await?;
    if !plan.has_changes() {
        return Ok(plan.migration(force)?.file());
    }

    let name = format!("migrate_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f"));
    let (migration, migration_id) = crate::push::rehearse(&mut tx, &plan, force, name.clone())
        .await
        .context("rehearse the migration, to record what a push would")?;
    let ledger = recorded(&mut tx, &name, migration_id).await?;
    tx.rollback().await?;
    Ok(migration.file_recording(&Recording { bootstrap, ledger }))
}

/// The bootstrap a push runs before it plans: `_supatype`, then Studio's objects.
fn bootstrap_statements() -> Vec<String> {
    let mut statements = migration_history::bootstrap_statements();
    statements.push(migration_history::seed_studio_members_from_claims_sql());
    statements.extend(
        studio_state::bootstrap_statements()
            .into_iter()
            .map(|(_, sql)| sql),
    );
    statements
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
