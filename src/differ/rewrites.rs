//! The operations that hold a table's ACCESS EXCLUSIVE lock while Postgres reads or rewrites every
//! row (IN-C 3).
//!
//! Most changes a push makes take their lock for a moment: a column added with a constant default
//! (Postgres 11 and later), a dropped column, a rename. Some read or rewrite the whole table under
//! a lock that stops every read and write until the push commits: a type change that is not
//! binary-compatible, a column added with a volatile default or a generated value, `SET NOT NULL`
//! with no validated check to prove it. On a large table that is an outage, so the plan says so
//! with the table's estimated size, and a push of one on a table above [`CONSENT_ROWS`] needs the
//! same consent a destructive change does.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{DiffOutput, Operation};
use crate::parser::ast::{scalar_of, DefaultValueAst, FieldAst};

/// Above this many estimated rows, a rewrite needs consent.
pub const CONSENT_ROWS: i64 = 100_000;

/// What Postgres does to every row while it holds the lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Work {
    /// Writes the table again.
    Rewrites,
    /// Reads every row to check it.
    Checks,
}

/// One operation that locks its table while it reads or rewrites every row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TableRewrite {
    pub table: String,
    pub column: String,
    pub work: Work,
    /// Why, in a few words: "changes its type from int4 to BIGINT".
    pub reason: String,
    /// `pg_class.reltuples`, or an estimate from the table's size where Postgres has none.
    pub estimated_rows: i64,
    /// Above [`CONSENT_ROWS`]: a push refuses it without consent.
    pub needs_consent: bool,
}

impl TableRewrite {
    /// The line the plan prints: "items.qty changes its type from int4 to BIGINT: locks items
    /// while it rewrites ~120000 rows".
    pub fn message(&self) -> String {
        let verb = match self.work {
            Work::Rewrites => "rewrites",
            Work::Checks => "checks",
        };
        format!(
            "{}.{} {}: locks {} while it {verb} ~{} rows",
            self.table, self.column, self.reason, self.table, self.estimated_rows
        )
    }
}

/// The refusal of a push whose rewrites need consent it was not given.
pub fn refusal(rewrites: &[TableRewrite]) -> Option<String> {
    let large: Vec<String> = rewrites
        .iter()
        .filter(|r| r.needs_consent)
        .map(TableRewrite::message)
        .collect();
    if large.is_empty() {
        return None;
    }
    Some(format!(
        "{} operation(s) rewrite a large table, which stops every read and write on it until the \
         push commits: {}. Use --force to proceed.",
        large.len(),
        large.join("; ")
    ))
}

/// Every operation in `diff` that reads or rewrites its whole table, with each table's estimated
/// rows from `rows` (tables the push creates are not in it, and have none).
pub fn rewrites(diff: &DiffOutput, rows: &BTreeMap<String, i64>) -> Vec<TableRewrite> {
    diff.operations
        .iter()
        .flat_map(classify)
        .filter_map(|(table, column, work, reason)| {
            let estimated_rows = *rows.get(&table)?;
            Some(TableRewrite {
                needs_consent: estimated_rows > CONSENT_ROWS,
                table,
                column,
                work,
                reason,
                estimated_rows,
            })
        })
        .collect()
}

type Found = (String, String, Work, String);

/// What `op` reads or rewrites, if anything.
fn classify(op: &Operation) -> Vec<Found> {
    let found = |table: &str, column: &str, work: Work, reason: String| {
        (table.to_string(), column.to_string(), work, reason)
    };
    match op {
        Operation::AddColumn {
            table,
            column,
            field,
            ..
        } => filled_per_row(field)
            .map(|why| found(table, column, Work::Rewrites, format!("is added {why}")))
            .into_iter()
            .collect(),
        Operation::RecreateColumn {
            table,
            column,
            field,
            ..
        } => filled_per_row(field)
            .map(|why| {
                found(
                    table,
                    column,
                    Work::Rewrites,
                    format!("is added again {why}"),
                )
            })
            .into_iter()
            .collect(),
        Operation::AlterColumn {
            table,
            column,
            changes,
            ..
        } => altered(changes)
            .into_iter()
            .map(|(work, reason)| found(table, column, work, reason))
            .collect(),
        _ => Vec::new(),
    }
}

/// Why a column added with `field` gets a value computed for each existing row, if it does: a
/// constant default is stored once, in the catalog.
fn filled_per_row(field: &FieldAst) -> Option<&'static str> {
    if matches!(field, FieldAst::Serial(_) | FieldAst::BigSerial(_)) {
        return Some("as a serial, numbering every row");
    }
    let scalar = scalar_of(field)?;
    if scalar.generated.is_some() {
        return Some("as a generated column, computed for every row");
    }
    if scalar.identity.is_some() || scalar.auto_increment {
        return Some("as an identity column, numbering every row");
    }
    match &scalar.default {
        Some(DefaultValueAst::GenRandomUuid) => Some("with a volatile default (gen_random_uuid())"),
        Some(DefaultValueAst::Expression { expr }) if volatile(expr) => {
            Some("with a volatile default")
        }
        _ => None,
    }
}

/// Whether a default expression calls something Postgres evaluates per row.
fn volatile(expr: &str) -> bool {
    let lower = expr.to_ascii_lowercase();
    [
        "random(",
        "gen_random_uuid(",
        "uuid_generate_",
        "clock_timestamp(",
        "nextval(",
        "timeofday(",
    ]
    .iter()
    .any(|f| lower.contains(f))
}

/// What an `ALTER COLUMN` reads or rewrites, from the differ's `changes`.
fn altered(changes: &serde_json::Value) -> Vec<(Work, String)> {
    let mut out = Vec::new();
    if let Some(change) = changes.get("type") {
        let from = change
            .get("from_udt")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let to = change.get("to_pg").and_then(|v| v.as_str()).unwrap_or("?");
        if !binary_compatible(from, to) {
            out.push((
                Work::Rewrites,
                format!("changes its type from {from} to {to}"),
            ));
        }
    }
    let not_null = changes
        .get("nullability")
        .and_then(|c| c.get("to"))
        .and_then(|v| v.as_str())
        == Some("not_null");
    if not_null {
        out.push((Work::Checks, "becomes NOT NULL".to_string()));
    }
    let generated = changes
        .get("generated")
        .and_then(|g| g.get("action"))
        .and_then(|v| v.as_str());
    if matches!(generated, Some(action) if action != "drop_expression") {
        out.push((Work::Rewrites, "changes how it is generated".to_string()));
    }
    out
}

/// Whether Postgres changes a column from `from` (its `udt_name`) to `to` (the type the schema
/// asks for) without touching a row: text and an unbounded `varchar` are the same on disk.
fn binary_compatible(from: &str, to: &str) -> bool {
    let to = to.trim().to_ascii_lowercase();
    let textual = |t: &str| matches!(t, "text" | "varchar" | "character varying");
    textual(&from.to_ascii_lowercase()) && textual(&to)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_type_change_rewrites_unless_the_two_types_are_the_same_on_disk() {
        assert!(binary_compatible("varchar", "TEXT"));
        assert!(binary_compatible("varchar", "text"));
        assert!(!binary_compatible("int4", "BIGINT"));
        let changes = serde_json::json!({ "type": { "from_udt": "int4", "to_pg": "BIGINT" },
                                          "nullability": { "to": "not_null" } });
        assert_eq!(
            altered(&changes),
            vec![
                (
                    Work::Rewrites,
                    "changes its type from int4 to BIGINT".to_string()
                ),
                (Work::Checks, "becomes NOT NULL".to_string()),
            ]
        );
    }

    #[test]
    fn the_message_names_the_table_and_its_size() {
        let r = TableRewrite {
            table: "items".into(),
            column: "qty".into(),
            work: Work::Rewrites,
            reason: "changes its type from int4 to BIGINT".into(),
            estimated_rows: 120_000,
            needs_consent: true,
        };
        assert_eq!(
            r.message(),
            "items.qty changes its type from int4 to BIGINT: locks items while it rewrites \
             ~120000 rows"
        );
        assert!(refusal(&[r]).unwrap().contains("Use --force"));
    }
}
