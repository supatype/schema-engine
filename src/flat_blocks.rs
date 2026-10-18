//! A push moves block entries still in the flat shape to `{ type, data, meta? }` (0.7.0).
//!
//! The plan counts, for each `Blocks` column the schema declares and the database already holds,
//! the entries still flat in the live table and in the model's snapshots, with one read-only query
//! per column. A column with none adds nothing to the push, so a push after the move is up to date.
//! A column with some adds its statements to the push's migration, inside its transaction, and
//! the push reports what it moved and records it in the migration history.
//!
//! The SQL is [`crate::generator::sql::flat_blocks`]'s.

use anyhow::{Context, Result};
use sqlx::PgConnection;

use crate::differ::{DiffOutput, Operation};
use crate::generator::sql::flat_blocks::{block_columns, BlockColumn, Site};
use crate::parser::ast::SchemaAst;
use crate::push::State;

/// What one count found at one site.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SiteCount {
    /// Flat entries naming a declared block: what the push moves.
    pub entries: i64,
    /// Rows holding at least one of them.
    pub rows: i64,
    /// Entries left as they are: not objects, or naming no declared block.
    pub left_alone: i64,
    /// Entries with `data` and fields beside it.
    pub mixed: i64,
}

/// The live table's count and, on a versioned model, its snapshots'.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub live: SiteCount,
    pub versions: Option<SiteCount>,
}

impl Counts {
    fn has_work(&self) -> bool {
        self.live.entries > 0 || self.versions.is_some_and(|v| v.entries > 0)
    }

    fn version_rows(&self) -> Option<i64> {
        self.versions.map(|v| v.rows)
    }
}

/// A column with flat entries to move, and where it reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMove {
    pub column: BlockColumn,
    pub sites: Vec<Site>,
    /// What the plan counted.
    pub pending: Counts,
}

impl BlockMove {
    /// The statements that move this column's entries, live table first.
    pub fn statements(&self, schema: &str) -> Vec<String> {
        self.sites
            .iter()
            .flat_map(|site| self.column.move_sql(schema, *site))
            .collect()
    }

    /// What the plan says it will do.
    pub fn pending_message(&self) -> String {
        format!(
            "Will convert {} in {}{} to the 0.7.0 shape {{ type, data }}.",
            entries(self.pending.live.entries),
            self.column.label(),
            versions_note(self.pending.version_rows()),
        )
    }

    /// What the push says it did, from the count taken in its own transaction.
    pub fn converted_message(&self, done: &Counts) -> String {
        format!(
            "Converted {} in {}{}",
            entries(done.live.entries),
            self.column.label(),
            versions_note(done.version_rows()),
        )
    }

    /// How [`Plan::to_json`](crate::push::Plan::to_json) lists it.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "table": self.column.table,
            "column": self.column.column,
            "entries": self.pending.live.entries,
            "versionRows": self.pending.version_rows(),
        })
    }
}

fn entries(n: i64) -> String {
    match n {
        1 => "1 block entry".to_string(),
        n => format!("{n} block entries"),
    }
}

fn versions_note(rows: Option<i64>) -> String {
    match rows {
        Some(1) => " (1 version row)".to_string(),
        Some(n) => format!(" ({n} version rows)"),
        None => String::new(),
    }
}

/// Counts `column` at `sites` on `conn`.
pub async fn count(
    conn: &mut PgConnection,
    column: &BlockColumn,
    sites: &[Site],
    schema: &str,
) -> Result<Counts> {
    let rows: Vec<(String, i64, i64, i64, i64)> = sqlx::query_as(&column.count_sql(schema, sites))
        .fetch_all(&mut *conn)
        .await
        .with_context(|| format!("Failed to count block entries in {}", column.label()))?;
    let mut counts = Counts::default();
    for (site, entries, rows, left_alone, mixed) in rows {
        let found = SiteCount {
            entries,
            rows,
            left_alone,
            mixed,
        };
        match site.as_str() {
            "versions" => counts.versions = Some(found),
            _ => counts.live = found,
        }
    }
    Ok(counts)
}

/// [`pending`], with what it found said in `diff`'s warnings: what the push leaves alone, then
/// what it will move.
pub async fn plan(
    conn: &mut PgConnection,
    ast: &SchemaAst,
    (state, diff): (&State, &mut DiffOutput),
    schema: &str,
) -> Result<Vec<BlockMove>> {
    let (moves, left_alone) = pending(conn, ast, (state, diff), schema).await?;
    diff.warnings.extend(left_alone);
    diff.warnings
        .extend(moves.iter().map(BlockMove::pending_message));
    Ok(moves)
}

/// What each of `moves` will move, counted again on `conn` (the push's transaction), as the push
/// reports it.
pub async fn converted(
    conn: &mut PgConnection,
    moves: &[BlockMove],
    schema: &str,
) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(moves.len());
    for m in moves {
        let done = count(conn, &m.column, &m.sites, schema).await?;
        out.push(m.converted_message(&done));
    }
    Ok(out)
}

/// The columns of `ast` with flat entries in the database `state` describes, and a warning for
/// each column holding entries the push leaves alone.
pub async fn pending(
    conn: &mut PgConnection,
    ast: &SchemaAst,
    (state, diff): (&State, &DiffOutput),
    schema: &str,
) -> Result<(Vec<BlockMove>, Vec<String>)> {
    let mut moves = Vec::new();
    let mut warnings = Vec::new();
    for column in block_columns(ast) {
        let Some(sites) = sites_in_place(&column, state, diff) else {
            continue;
        };
        let counts = count(conn, &column, &sites, schema).await?;
        warnings.extend(left_alone_warnings(&column, &counts));
        if counts.has_work() {
            moves.push(BlockMove {
                column,
                sites,
                pending: counts,
            });
        }
    }
    Ok((moves, warnings))
}

/// Where `column` can be read as it is now: the live table, when the database has it as `jsonb`
/// and this push neither creates, renames, retypes nor drops it, and the snapshot table when the
/// model keeps versions and the database already has one. `None` when the live column is not in
/// place, so a column this push changes is moved by the next one.
fn sites_in_place(column: &BlockColumn, state: &State, diff: &DiffOutput) -> Option<Vec<Site>> {
    let has_jsonb = |table: &str, name: &str| {
        state.db.tables.iter().any(|t| {
            t.name == table
                && t.columns
                    .iter()
                    .any(|c| c.name == name && c.udt_name == "jsonb")
        })
    };
    if !has_jsonb(&column.table, &column.column) || touched(diff, column) {
        return None;
    }
    let mut sites = vec![Site::Live];
    if let Some(versions) = &column.versions_table {
        if has_jsonb(versions, "data") {
            sites.push(Site::Versions);
        }
    }
    Some(sites)
}

/// Whether an operation of `diff` changes `column` or its table's name.
fn touched(diff: &DiffOutput, column: &BlockColumn) -> bool {
    let (table, name) = (column.table.as_str(), column.column.as_str());
    diff.operations
        .iter()
        .any(|op| tables_named(op).contains(&table) || columns_named(op).contains(&(table, name)))
}

/// The tables `op` creates, drops or renames, under each name it gives them.
fn tables_named(op: &Operation) -> Vec<&str> {
    match op {
        Operation::CreateTable { table, .. } | Operation::DropTable { table, .. } => vec![table],
        Operation::RenameTable { from, to, .. } => vec![from, to],
        _ => Vec::new(),
    }
}

/// The columns `op` adds, drops, retypes or renames, as `(table, column)`.
fn columns_named(op: &Operation) -> Vec<(&str, &str)> {
    match op {
        Operation::AddColumn { table, column, .. }
        | Operation::DropColumn { table, column, .. }
        | Operation::AlterColumn { table, column, .. }
        | Operation::RecreateColumn { table, column, .. } => vec![(table, column)],
        Operation::RenameColumn {
            table, from, to, ..
        } => vec![(table, from), (table, to)],
        _ => Vec::new(),
    }
}

/// What the push leaves alone in `column`, said so a person can look.
fn left_alone_warnings(column: &BlockColumn, counts: &Counts) -> Vec<String> {
    let versions = counts.versions.unwrap_or_default();
    let left_alone = counts.live.left_alone + versions.left_alone;
    let mixed = counts.live.mixed + versions.mixed;
    let mut out = Vec::new();
    if left_alone > 0 {
        out.push(format!(
            "Left as stored in {}: {}, each not an object or naming a block the schema does not \
             declare, so no definition says how to move its fields.",
            column.label(),
            entries(left_alone),
        ));
    }
    if mixed > 0 {
        out.push(format!(
            "Left as stored in {}: {} with `data` and fields beside it, from an edit in Studio \
             before the move. See UPGRADING.md, \"Moving rows saved in the old shape\".",
            column.label(),
            entries(mixed),
        ));
    }
    out
}
