//! Generates rollback (reverse) SQL for a forward DiffOutput.
//!
//! Each forward operation has a deterministic inverse. Operations that cannot be
//! perfectly reversed (e.g. DropTable, DropColumn) are annotated with a warning
//! rather than silently omitted.

use super::migration::{rename_serial_sequence_sql, serial_columns};
use crate::differ::{DiffOutput, Operation};
use crate::managed::make_object_name;
use crate::parser::ast::SchemaAst;
use anyhow::Result;

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
            lines.push(format!("-- rollback: {}", forward_description(op)));
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

fn rollback_op(
    op: &Operation,
    schema: &str,
    ast: &SchemaAst,
    diff: &DiffOutput,
) -> Result<Option<String>> {
    let sql = match op {
        // CreateTable → DROP TABLE, never `CASCADE` (plan 3.3): the reconcile's rollback, which runs
        // first, has already dropped what of ours depends on the table.
        Operation::CreateTable { table, .. } => {
            format!("DROP TABLE IF EXISTS \"{schema}\".\"{table}\";")
        }
        // RenameTable → rename back, and its serials' sequences with it. The column renames of
        // the same migration are undone first, so each column has its old name again here.
        Operation::RenameTable { from, to, .. } => {
            let mut sql = format!("ALTER TABLE \"{schema}\".\"{to}\" RENAME TO \"{from}\";");
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
        // DropTable → cannot restore (need snapshot); emit a commented placeholder
        Operation::DropTable { table, .. } => {
            format!(
                "-- WARNING: Cannot automatically roll back DROP TABLE \"{table}\". \
                     Restore from backup or snapshot."
            )
        }
        // AddColumn → DROP COLUMN
        Operation::AddColumn { table, column, .. } => {
            format!("ALTER TABLE \"{schema}\".\"{table}\" DROP COLUMN IF EXISTS \"{column}\";")
        }
        // DropColumn → cannot restore without snapshot
        Operation::DropColumn { table, column, .. } => {
            format!(
                "-- WARNING: Cannot automatically roll back DROP COLUMN \"{table}\".\"{column}\". \
                     Restore from backup or snapshot."
            )
        }
        // RenameColumn → rename back
        Operation::RenameColumn {
            table, from, to, ..
        } => {
            let mut sql = format!(
                "ALTER TABLE \"{schema}\".\"{table}\" RENAME COLUMN \"{to}\" TO \"{from}\";"
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
        Operation::RecreateColumn { table, column, .. } => {
            format!(
                "-- WARNING: Cannot automatically roll back RECREATE COLUMN \"{table}\".\"{column}\". \
                     Original column data was discarded. Restore from backup or snapshot."
            )
        }
        // Never in a diff: the reconcile creates indexes, foreign keys and unique constraints from
        // the desired set (these operations only render its `CREATE`s), and its rollback drops them.
        Operation::AddIndex { .. }
        | Operation::AddForeignKey { .. }
        | Operation::AddUniqueConstraint { .. } => return Ok(None),
        // CreateRlsPolicy → DROP POLICY
        Operation::CreateRlsPolicy { table, policy, .. } => {
            format!("DROP POLICY IF EXISTS \"{policy}\" ON \"{schema}\".\"{table}\";")
        }
        // CreateJunctionTable → DROP TABLE
        Operation::CreateJunctionTable { table, .. } => {
            format!("DROP TABLE IF EXISTS \"{schema}\".\"{table}\";")
        }
        // CreateVersionsTable → DROP TABLE. Safe to roll back exactly because the operation only
        // ever *creates*: it runs when the table is absent, so a rollback removes a table this
        // migration made and no history that predates it.
        Operation::CreateVersionsTable { versions_table, .. } => {
            format!("DROP TABLE IF EXISTS \"{schema}\".\"{versions_table}\";")
        }
        // EnableExtension → DROP EXTENSION (risky, so only emit a warning)
        Operation::EnableExtension { name, .. } => {
            format!(
                "-- WARNING: Rollback of CREATE EXTENSION \"{name}\" would DROP it. \
                     Remove manually if safe to do so."
            )
        }
    };
    Ok(Some(sql))
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
        if changes
            .get("conversion")
            .and_then(|c| c.get("strategy"))
            .and_then(|v| v.as_str())
            .is_some_and(|s| matches!(s, "transform_cast" | "kind_migrate"))
        {
            stmts.push(format!(
                "-- WARNING: Transform/kind migration on \"{table}\".\"{column}\" is not automatically reversible."
            ));
        }
        let from_udt = type_change
            .get("from_udt")
            .and_then(|v| v.as_str())
            .unwrap_or("text");
        // Map udt_name back to a castable type keyword
        let restore_type = udt_to_pg_type(from_udt);
        stmts.push(format!(
            "ALTER TABLE \"{schema}\".\"{table}\" ALTER COLUMN \"{column}\" \
             TYPE {restore_type} USING \"{column}\"::{restore_type}; \
             -- restoring from {from_udt}"
        ));
    }

    // Reverse nullability change
    if let Some(null_change) = changes.get("nullability") {
        let original_state = null_change
            .get("from")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if original_state == "not_null" {
            // Was NOT NULL, now re-apply NOT NULL constraint
            stmts.push(format!(
                "DO $$ BEGIN\n  \
                 IF EXISTS (SELECT 1 FROM \"{schema}\".\"{table}\" WHERE \"{column}\" IS NULL) THEN\n    \
                 RAISE EXCEPTION 'Cannot restore NOT NULL on {table}.{column}: NULL values exist.';\n  \
                 END IF;\n\
                 END $$;"
            ));
            stmts.push(format!(
                "ALTER TABLE \"{schema}\".\"{table}\" ALTER COLUMN \"{column}\" SET NOT NULL;"
            ));
        } else {
            // Was nullable: restore by dropping not null
            stmts.push(format!(
                "ALTER TABLE \"{schema}\".\"{table}\" ALTER COLUMN \"{column}\" DROP NOT NULL;"
            ));
        }
    }

    if stmts.is_empty() {
        format!("-- WARNING: Cannot automatically roll back ALTER COLUMN \"{table}\".\"{column}\".")
    } else {
        stmts.join("\n")
    }
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
