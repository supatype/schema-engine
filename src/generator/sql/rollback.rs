//! Generates rollback (reverse) SQL for a forward DiffOutput.
//!
//! Each forward operation has a deterministic inverse. Operations that cannot be
//! perfectly reversed (e.g. DropTable, DropColumn) are annotated with a warning
//! rather than silently omitted.

use crate::differ::{DiffOutput, Operation};
use anyhow::Result;

/// The rollback as a script of its own: the statements of [`statements`] inside one transaction.
pub fn generate(diff: &DiffOutput, schema: &str) -> Result<String> {
    Ok(script(&statements(diff, schema)?))
}

/// The inverse of each forward operation, newest first, each under a comment naming what it
/// undoes. Statements only: the caller owns the transaction.
pub fn statements(diff: &DiffOutput, schema: &str) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    for op in diff.operations.iter().rev() {
        if let Some(sql) = rollback_op(op, schema)? {
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

fn rollback_op(op: &Operation, schema: &str) -> Result<Option<String>> {
    let sql = match op {
        // CreateTable → DROP TABLE
        Operation::CreateTable { table, .. } => {
            format!("DROP TABLE IF EXISTS \"{schema}\".\"{table}\" CASCADE;")
        }
        // RenameTable → rename back
        Operation::RenameTable { from, to, .. } => {
            format!("ALTER TABLE \"{schema}\".\"{to}\" RENAME TO \"{from}\";")
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
            format!("ALTER TABLE \"{schema}\".\"{table}\" RENAME COLUMN \"{to}\" TO \"{from}\";")
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
        // AddIndex → DROP INDEX
        Operation::AddIndex { table, index, .. } => {
            let derived = format!("{}_{}_idx", table, index.fields.join("_"));
            let idx_name = index.name.as_deref().unwrap_or(&derived);
            format!("DROP INDEX IF EXISTS \"{idx_name}\";")
        }
        // AddForeignKey → DROP CONSTRAINT
        Operation::AddForeignKey {
            table,
            field_name,
            relation,
            ..
        } => {
            let derived;
            let fk_col = match relation.foreign_key.as_deref() {
                Some(fk) => fk,
                None => {
                    derived = format!("{field_name}_id");
                    &derived
                }
            };
            let constraint = format!("{table}_{fk_col}_fkey");
            format!(
                "ALTER TABLE \"{schema}\".\"{table}\" DROP CONSTRAINT IF EXISTS \"{constraint}\";"
            )
        }
        Operation::AddUniqueConstraint {
            table, constraint, ..
        } => {
            format!(
                "ALTER TABLE \"{schema}\".\"{table}\" DROP CONSTRAINT IF EXISTS \"{constraint}\";"
            )
        }
        Operation::DropUniqueConstraint {
            table, constraint, ..
        } => {
            format!("-- WARNING: Cannot automatically roll back DROP CONSTRAINT \"{table}\".\"{constraint}\". \
                     Recreate the unique constraint manually.")
        }
        // CreateEnum → DROP TYPE
        Operation::CreateEnum { name, .. } => {
            format!("DROP TYPE IF EXISTS \"{name}\";")
        }
        // DropEnum → cannot restore
        Operation::DropEnum { name, .. } => {
            format!("-- WARNING: Cannot automatically roll back DROP TYPE \"{name}\".")
        }
        // AddEnumValue → cannot remove a value from an enum directly; warn.
        Operation::AddEnumValue {
            enum_name, value, ..
        } => {
            format!(
                "-- WARNING: Cannot automatically roll back ADD VALUE '{value}' on \"{enum_name}\". \
                 Postgres does not support removing enum values without recreating the type."
            )
        }
        // RemoveEnumValue → re-add the removed value
        Operation::RemoveEnumValue {
            enum_name, value, ..
        } => {
            format!("ALTER TYPE \"{enum_name}\" ADD VALUE '{value}';")
        }
        // RenameEnumValue → rename back
        Operation::RenameEnumValue {
            enum_name,
            from,
            to,
            ..
        } => {
            format!("ALTER TYPE \"{enum_name}\" RENAME VALUE '{to}' TO '{from}';")
        }
        // ReorderEnumValues → recreate with old order
        Operation::ReorderEnumValues {
            enum_name,
            old_values,
            affected_columns,
            ..
        } => {
            let old_name = format!("{enum_name}_old");
            let vals = old_values
                .iter()
                .map(|v| format!("'{v}'"))
                .collect::<Vec<_>>()
                .join(", ");

            let mut stmts = Vec::new();
            stmts.push(format!(
                "ALTER TYPE \"{enum_name}\" RENAME TO \"{old_name}\";"
            ));
            stmts.push(format!("CREATE TYPE \"{enum_name}\" AS ENUM ({vals});"));
            for (table, column) in affected_columns {
                stmts.push(format!(
                    "ALTER TABLE \"{schema}\".\"{table}\" ALTER COLUMN \"{column}\" \
                     TYPE \"{enum_name}\" USING \"{column}\"::text::\"{enum_name}\";"
                ));
            }
            stmts.push(format!("DROP TYPE \"{old_name}\";"));
            stmts.join("\n")
        }
        // EnableRls → DISABLE ROW LEVEL SECURITY
        Operation::EnableRls { table, .. } => {
            format!("ALTER TABLE \"{schema}\".\"{table}\" DISABLE ROW LEVEL SECURITY;")
        }
        // CreateRlsPolicy → DROP POLICY
        Operation::CreateRlsPolicy { table, policy, .. } => {
            format!("DROP POLICY IF EXISTS \"{policy}\" ON \"{schema}\".\"{table}\";")
        }
        // DropRlsPolicy → cannot restore
        Operation::DropRlsPolicy { table, policy, .. } => {
            format!(
                "-- WARNING: Cannot automatically roll back DROP POLICY \"{table}\".\"{policy}\"."
            )
        }
        // CreateJunctionTable → DROP TABLE
        Operation::CreateJunctionTable { table, .. } => {
            format!("DROP TABLE IF EXISTS \"{schema}\".\"{table}\" CASCADE;")
        }
        // CreateVersionsTable → DROP TABLE. Safe to roll back exactly because the operation only
        // ever *creates*: it runs when the table is absent, so a rollback removes a table this
        // migration made and no history that predates it.
        Operation::CreateVersionsTable { versions_table, .. } => {
            format!("DROP TABLE IF EXISTS \"{schema}\".\"{versions_table}\" CASCADE;")
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
        Operation::DropUniqueConstraint {
            table, constraint, ..
        } => format!("drop unique {table}.{constraint}"),
        Operation::CreateEnum { name, .. } => format!("create enum {name}"),
        Operation::DropEnum { name, .. } => format!("drop enum {name}"),
        Operation::AddEnumValue {
            enum_name, value, ..
        } => format!("add enum value {enum_name}.'{value}'"),
        Operation::RemoveEnumValue {
            enum_name, value, ..
        } => format!("remove enum value {enum_name}.'{value}'"),
        Operation::RenameEnumValue {
            enum_name,
            from,
            to,
            ..
        } => format!("rename enum value {enum_name}.'{from}' -> '{to}'"),
        Operation::ReorderEnumValues { enum_name, .. } => {
            format!("reorder enum values {enum_name}")
        }
        Operation::EnableRls { table, .. } => format!("enable rls {table}"),
        Operation::CreateRlsPolicy { table, policy, .. } => {
            format!("create policy {table}.{policy}")
        }
        Operation::DropRlsPolicy { table, policy, .. } => format!("drop policy {table}.{policy}"),
        Operation::CreateJunctionTable { table, .. } => format!("create junction table {table}"),
        Operation::CreateVersionsTable { versions_table, .. } => {
            format!("create versions table {versions_table}")
        }
        Operation::EnableExtension { name, .. } => format!("enable extension {name}"),
    }
}
