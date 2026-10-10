//! Generates rollback (reverse) SQL for a forward DiffOutput.
//!
//! Each forward operation has a deterministic inverse. Operations that cannot be
//! perfectly reversed (e.g. DropTable, DropColumn) are annotated with a warning
//! rather than silently omitted.

use super::migration::{
    identity_change_sql, nullability_sql, rename_serial_sequence_sql, serial_columns,
};
use crate::differ::{DiffOutput, Operation};
use crate::managed::make_object_name;
use crate::parser::ast::SchemaAst;
use crate::sql_quote::{comment_text, quote_ident, quote_literal, quote_qualified};
use anyhow::Result;
use serde_json::json;

/// The rollback as a script of its own: the statements of [`statements`] inside one transaction.
pub fn generate(diff: &DiffOutput, schema: &str, ast: &SchemaAst) -> Result<String> {
    Ok(script(&statements(diff, schema, ast)?))
}

/// The inverse of each forward operation, newest first, each under a comment naming what it
/// undoes. Statements only: the caller owns the transaction. `ast` is the schema the forward
/// migration applies, which says which renamed columns own a sequence.
pub fn statements(diff: &DiffOutput, schema: &str, ast: &SchemaAst) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    for op in diff.operations.iter().rev() {
        if let Some(sql) = rollback_op(op, schema, ast, diff)? {
            lines.push(format!(
                "-- rollback: {}",
                comment_text(&forward_description(op))
            ));
            lines.push(sql);
            lines.push(String::new());
        }
    }
    Ok(lines)
}

/// `lines` as the rollback section of a migration file: headed, inside `BEGIN`/`COMMIT`.
pub fn script(lines: &[String]) -> String {
    let mut out = vec![
        "-- ============================================================".into(),
        "-- ROLLBACK MIGRATION".into(),
        "-- ============================================================".into(),
        String::new(),
        "BEGIN;".into(),
        String::new(),
    ];
    out.extend(lines.iter().cloned());
    out.push("COMMIT;".into());
    out.join("\n")
}

/// The sequence a serial column owns renamed back to Postgres's name for it under `table`, as the
/// forward rename renamed it on (`rename_serial_sequence_sql`).
fn sequence_back(schema: &str, table: &str, column: &str) -> String {
    rename_serial_sequence_sql(
        schema,
        table,
        column,
        &make_object_name(table, Some(column), "seq"),
    )
}

/// A `-- WARNING:` line for an operation no statement can undo.
fn warning(text: &str) -> String {
    format!("-- WARNING: {}", comment_text(text))
}

/// `"table"."column"`, as the warnings name a column.
fn column_label(table: &str, column: &str) -> String {
    format!("{}.{}", quote_ident(table), quote_ident(column))
}

fn rollback_op(
    op: &Operation,
    schema: &str,
    ast: &SchemaAst,
    diff: &DiffOutput,
) -> Result<Option<String>> {
    let sql = match op {
        // CreateTable → DROP TABLE, never `CASCADE` (plan 3.3): the reconcile's rollback, which runs
        // first, has already dropped what of ours depends on the table.
        Operation::CreateTable { table, .. } | Operation::CreateJunctionTable { table, .. } => {
            drop_table(schema, table)
        }
        // RenameTable → rename back, and its serials' sequences with it.
        Operation::RenameTable { from, to, .. } => rename_table_back(schema, ast, diff, from, to),
        // DropTable → cannot restore (need snapshot); emit a commented placeholder
        Operation::DropTable { table, .. } => warning(&format!(
            "Cannot automatically roll back DROP TABLE {}. Restore from backup or snapshot.",
            quote_ident(table)
        )),
        // AddColumn → DROP COLUMN
        Operation::AddColumn { table, column, .. } => format!(
            "ALTER TABLE {} DROP COLUMN IF EXISTS {};",
            quote_qualified(schema, table),
            quote_ident(column)
        ),
        // DropColumn → cannot restore without snapshot
        Operation::DropColumn { table, column, .. } => warning(&format!(
            "Cannot automatically roll back DROP COLUMN {}. Restore from backup or snapshot.",
            column_label(table, column)
        )),
        // RenameColumn → rename back
        Operation::RenameColumn {
            table, from, to, ..
        } => {
            let mut sql = format!(
                "ALTER TABLE {} RENAME COLUMN {} TO {};",
                quote_qualified(schema, table),
                quote_ident(to),
                quote_ident(from)
            );
            if serial_columns(ast, table).contains(to) {
                sql.push('\n');
                sql.push_str(&sequence_back(schema, table, from));
            }
            sql
        }
        // AlterColumn → reverse each change using stored metadata
        Operation::AlterColumn {
            table,
            column,
            changes,
            ..
        } => rollback_alter_column(table, column, changes, schema),
        Operation::RecreateColumn { table, column, .. } => warning(&format!(
            "Cannot automatically roll back RECREATE COLUMN {}. Original column data was discarded. \
             Restore from backup or snapshot.",
            column_label(table, column)
        )),
        // Never in a diff: the reconcile creates indexes, foreign keys and unique constraints from
        // the desired set (these operations only render its `CREATE`s), and its rollback drops them.
        Operation::AddIndex { .. }
        | Operation::AddForeignKey { .. }
        | Operation::AddUniqueConstraint { .. } => return Ok(None),
        // CreateRlsPolicy → DROP POLICY
        Operation::CreateRlsPolicy { table, policy, .. } => format!(
            "DROP POLICY IF EXISTS {} ON {};",
            quote_ident(policy),
            quote_qualified(schema, table)
        ),
        // CreateVersionsTable → DROP TABLE. Safe to roll back exactly because the operation only
        // ever *creates*: it runs when the table is absent, so a rollback removes a table this
        // migration made and no history that predates it.
        Operation::CreateVersionsTable { versions_table, .. } => {
            drop_table(schema, versions_table)
        }
        // EnableExtension → DROP EXTENSION (risky, so only emit a warning)
        Operation::EnableExtension { name, .. } => warning(&format!(
            "Rollback of CREATE EXTENSION {} would DROP it. Remove manually if safe to do so.",
            quote_ident(name)
        )),
    };
    Ok(Some(sql))
}

fn drop_table(schema: &str, table: &str) -> String {
    format!("DROP TABLE IF EXISTS {};", quote_qualified(schema, table))
}

/// A table renamed back, and its serials' sequences with it. The column renames of the same
/// migration are undone first, so each column has its old name again here.
fn rename_table_back(
    schema: &str,
    ast: &SchemaAst,
    diff: &DiffOutput,
    from: &str,
    to: &str,
) -> String {
    let mut sql = format!(
        "ALTER TABLE {} RENAME TO {};",
        quote_qualified(schema, to),
        quote_ident(from)
    );
    for column in serial_columns(ast, to) {
        let column = diff
            .operations
            .iter()
            .find_map(|op| match op {
                Operation::RenameColumn {
                    table,
                    from,
                    to: renamed,
                    ..
                } if table == to && *renamed == column => Some(from.clone()),
                _ => None,
            })
            .unwrap_or(column);
        sql.push('\n');
        sql.push_str(&sequence_back(schema, from, &column));
    }
    sql
}

fn rollback_alter_column(
    table: &str,
    column: &str,
    changes: &serde_json::Value,
    schema: &str,
) -> String {
    let mut stmts: Vec<String> = Vec::new();

    // Reverse type change: restore old type from from_udt
    if let Some(type_change) = changes.get("type") {
        stmts.extend(type_back(schema, table, column, changes, type_change));
    }

    // Reverse an identity change first: it was made after the nullability, and an identity column
    // cannot drop NOT NULL.
    if let Some(identity) = changes.get("identity") {
        stmts.extend(identity_back(schema, table, column, identity));
    }
    if changes.get("generated").is_some() {
        stmts.push(warning(&format!(
            "Cannot automatically make {} a generated column again.",
            column_label(table, column)
        )));
    }

    // Reverse nullability change: was NOT NULL, so apply it again, or was nullable, so drop it.
    if let Some(null_change) = changes.get("nullability") {
        let original_state = null_change
            .get("from")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        stmts.extend(nullability_sql(
            schema,
            table,
            column,
            (original_state == "not_null").then_some("restore"),
        ));
    }

    if stmts.is_empty() {
        warning(&format!(
            "Cannot automatically roll back ALTER COLUMN {}.",
            column_label(table, column)
        ))
    } else {
        stmts.join("\n")
    }
}

/// The column's type changed back to the one it had, from `from_udt`.
fn type_back(
    schema: &str,
    table: &str,
    column: &str,
    changes: &serde_json::Value,
    type_change: &serde_json::Value,
) -> Vec<String> {
    let mut stmts = Vec::new();
    if changes
        .get("conversion")
        .and_then(|c| c.get("strategy"))
        .and_then(|v| v.as_str())
        .is_some_and(|s| matches!(s, "transform_cast" | "kind_migrate"))
    {
        stmts.push(warning(&format!(
            "Transform/kind migration on {} is not automatically reversible.",
            column_label(table, column)
        )));
    }
    let from_udt = type_change
        .get("from_udt")
        .and_then(|v| v.as_str())
        .unwrap_or("text");
    // Map udt_name back to a castable type keyword
    let restore_type = udt_to_pg_type(from_udt);
    let col = quote_ident(column);
    stmts.push(format!(
        "ALTER TABLE {} ALTER COLUMN {col} TYPE {restore_type} USING {col}::{restore_type}; \
         -- restoring from {}",
        quote_qualified(schema, table),
        comment_text(from_udt)
    ));
    stmts
}

/// An identity change undone. A serial converted to an identity column is a serial again: its own
/// sequence, numbering on past the rows there, as its default.
fn identity_back(
    schema: &str,
    table: &str,
    column: &str,
    identity: &serde_json::Value,
) -> Vec<String> {
    let back = match identity.get("action").and_then(|v| v.as_str()) {
        Some("add") => json!({ "action": "drop" }),
        Some("drop") => json!({ "action": "add", "to": identity.get("from") }),
        _ => json!({ "action": "set", "to": identity.get("from") }),
    };
    let mut stmts = identity_change_sql(schema, table, column, &back);
    let Some(serial) = identity.get("serial") else {
        return stmts;
    };
    let as_type = serial
        .get("sequenceType")
        .and_then(|v| v.as_str())
        .unwrap_or("integer");
    let target = quote_qualified(schema, table);
    let sequence = quote_qualified(schema, &format!("{table}_{column}_seq"));
    let literal = quote_literal(&sequence);
    let col = quote_ident(column);
    stmts.push(format!(
        "CREATE SEQUENCE {sequence} AS {as_type} OWNED BY {target}.{col};"
    ));
    stmts.push(format!(
        "SELECT setval({literal}, COALESCE(MAX({col}), 0) + 1, false) FROM {target};"
    ));
    stmts.push(format!(
        "ALTER TABLE {target} ALTER COLUMN {col} SET DEFAULT nextval({literal}::regclass);"
    ));
    stmts
}

fn udt_to_pg_type(udt: &str) -> &'static str {
    match udt {
        "int2" => "SMALLINT",
        "int4" => "INTEGER",
        "int8" => "BIGINT",
        "float4" => "REAL",
        "float8" => "DOUBLE PRECISION",
        "bool" => "BOOLEAN",
        "uuid" => "UUID",
        "timestamptz" => "TIMESTAMPTZ",
        "timestamp" => "TIMESTAMP",
        "date" => "DATE",
        "bytea" => "BYTEA",
        "jsonb" => "JSONB",
        "inet" => "INET",
        "cidr" => "CIDR",
        "macaddr" => "MACADDR",
        "interval" => "INTERVAL",
        "tsquery" => "TSQUERY",
        "tsvector" => "TSVECTOR",
        _ => "TEXT",
    }
}

fn forward_description(op: &Operation) -> String {
    match op {
        Operation::CreateTable { table, .. } => format!("create table {table}"),
        Operation::DropTable { table, .. } => format!("drop table {table}"),
        Operation::RenameTable { from, to, .. } => format!("rename table {from} -> {to}"),
        Operation::AddColumn { table, column, .. } => format!("add column {table}.{column}"),
        Operation::DropColumn { table, column, .. } => format!("drop column {table}.{column}"),
        Operation::RenameColumn {
            table, from, to, ..
        } => format!("rename {table}.{from} -> {to}"),
        Operation::AlterColumn { table, column, .. } => format!("alter column {table}.{column}"),
        Operation::RecreateColumn { table, column, .. } => {
            format!("recreate column {table}.{column}")
        }
        Operation::AddIndex { table, index, .. } => {
            format!("add index on {table}({})", index.fields.join(","))
        }
        Operation::AddForeignKey {
            table, relation, ..
        } => format!("add fk {table} -> {}", relation.target),
        Operation::AddUniqueConstraint { table, column, .. } => {
            format!("add unique {table}.{column}")
        }
        Operation::CreateRlsPolicy { table, policy, .. } => {
            format!("create policy {table}.{policy}")
        }
        Operation::CreateJunctionTable { table, .. } => format!("create junction table {table}"),
        Operation::CreateVersionsTable { versions_table, .. } => {
            format!("create versions table {versions_table}")
        }
        Operation::EnableExtension { name, .. } => format!("enable extension {name}"),
    }
}
