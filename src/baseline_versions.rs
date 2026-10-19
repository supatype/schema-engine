//! A push gives each record of a drafts model that has no version rows its version 1.
//!
//! The plan counts, for each drafts model whose table the database already holds and this push
//! neither creates, renames nor drops, the live rows with no version row, with one read-only query
//! per model. A model with none adds nothing to the push, so a push after the backfill is up to
//! date. A model with some adds its statements to the push's migration, inside its transaction and
//! after the versions layer (which makes the snapshot table and its guard), and the push reports
//! what it created and records it in the migration history.
//!
//! The SQL is [`crate::generator::sql::baseline_versions`]'s.

use anyhow::{Context, Result};
use sqlx::PgConnection;

use crate::differ::DiffOutput;
use crate::flat_blocks::tables_named;
use crate::generator::sql::baseline_versions::{baseline_models, BaselineModel};
use crate::parser::ast::SchemaAst;
use crate::sql_quote::quote_qualified;

/// A drafts model with records lacking a version, and how many the plan counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baseline {
    pub model: BaselineModel,
    pub pending: i64,
}

impl Baseline {
    /// The statements that write the missing versions.
    pub fn statements(&self, schema: &str) -> Vec<String> {
        self.model.backfill_sql(schema)
    }

    /// What the plan says it will do.
    pub fn pending_message(&self) -> String {
        format!(
            "Will create {} for {}, from what each live row holds.",
            versions(self.pending),
            self.model.table
        )
    }

    /// What the push says it did, from the count taken in its own transaction.
    pub fn created_message(&self, done: i64) -> String {
        format!("Created {} for {}", versions(done), self.model.table)
    }

    /// How [`Plan::to_json`](crate::push::Plan::to_json) lists it.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "table": self.model.table, "records": self.pending })
    }
}

fn versions(n: i64) -> String {
    match n {
        1 => "1 baseline version".to_string(),
        n => format!("{n} baseline versions"),
    }
}

/// Live rows of `model` with no version row on `conn`, or `None` when its table is not there.
pub async fn count(
    conn: &mut PgConnection,
    model: &BaselineModel,
    schema: &str,
) -> Result<Option<i64>> {
    if !exists(conn, &quote_qualified(schema, &model.table)).await? {
        return Ok(None);
    }
    let versions_exist = exists(conn, &quote_qualified(schema, &model.versions_table)).await?;
    let n: i64 = sqlx::query_scalar(&model.count_sql(schema, versions_exist))
        .fetch_one(&mut *conn)
        .await
        .with_context(|| format!("Failed to count records with no version in {}", model.table))?;
    Ok(Some(n))
}

async fn exists(conn: &mut PgConnection, relation: &str) -> Result<bool> {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(relation)
        .fetch_one(&mut *conn)
        .await
        .with_context(|| format!("Failed to look up {relation}"))
}

/// The drafts models of `ast` with records lacking a version, each said in `diff`'s warnings.
pub async fn plan(
    conn: &mut PgConnection,
    ast: &SchemaAst,
    diff: &mut DiffOutput,
    schema: &str,
) -> Result<Vec<Baseline>> {
    let mut out = Vec::new();
    for model in baseline_models(ast) {
        if table_moves(diff, &model.table) {
            continue;
        }
        let pending = count(conn, &model, schema).await?.unwrap_or(0);
        if pending > 0 {
            out.push(Baseline { model, pending });
        }
    }
    diff.warnings
        .extend(out.iter().map(Baseline::pending_message));
    Ok(out)
}

/// What each of `baselines` will create, counted again on `conn` (the push's transaction), as
/// the push reports it.
pub async fn created(
    conn: &mut PgConnection,
    baselines: &[Baseline],
    schema: &str,
) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(baselines.len());
    for b in baselines {
        let done = count(conn, &b.model, schema).await?.unwrap_or(0);
        out.push(b.created_message(done));
    }
    Ok(out)
}

/// Whether `diff` creates, drops or renames `table`: a table this push makes has no rows, and one
/// it renames is backfilled by the next push, under its new name.
fn table_moves(diff: &DiffOutput, table: &str) -> bool {
    diff.operations
        .iter()
        .any(|op| tables_named(op).contains(&table))
}
