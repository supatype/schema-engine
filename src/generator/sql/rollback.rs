//! Generates rollback (reverse) SQL for a forward DiffOutput.
//!
//! Each forward operation has a deterministic inverse. Operations that cannot be
//! perfectly reversed (e.g. DropTable, DropColumn) are annotated with a warning
//! rather than silently omitted.

use crate::differ::{DiffOutput, Operation};
use anyhow::Result;

pub fn generate(diff: &DiffOutput) -> Result<String> {
    let mut lines = vec![
        "-- ============================================================".into(),
        "-- ROLLBACK MIGRATION".into(),
        "-- ============================================================".into(),
        String::new(),
        "BEGIN;".into(),
        String::new(),
    ];

    // Apply rollback ops in reverse order of the forward migration
    for op in diff.operations.iter().rev() {
        if let Some(sql) = rollback_op(op)? {
            lines.push(format!("-- rollback: {}", forward_description(op)));
            lines.push(sql);
            lines.push(String::new());
        }
    }

    lines.push("COMMIT;".into());
    Ok(lines.join("\n"))
}

fn rollback_op(op: &Operation) -> Result<Option<String>> {
    let sql = match op {
        // CreateTable → DROP TABLE
        Operation::CreateTable { table, .. } => {
            format!("DROP TABLE IF EXISTS \"public\".\"{table}\" CASCADE;")
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
            format!("ALTER TABLE \"public\".\"{table}\" DROP COLUMN IF EXISTS \"{column}\";")
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
            format!("ALTER TABLE \"public\".\"{table}\" RENAME COLUMN \"{to}\" TO \"{from}\";")
        }
        // AlterColumn → reverse each change using stored metadata
        Operation::AlterColumn {
            table,
            column,
            changes,
            ..
        } => rollback_alter_column(table, column, changes),
        // AddIndex → DROP INDEX
        Operation::AddIndex { table, index, .. } => {
            let derived = format!("{}_{}_idx", table, index.fields.join("_"));
            let idx_name = index.name.as_deref().unwrap_or(&derived);
            format!("DROP INDEX IF EXISTS \"{idx_name}\";")
        }
        // DropIndex → cannot restore
        Operation::DropIndex { index_name, .. } => {
            format!(
                "-- WARNING: Cannot automatically roll back DROP INDEX \"{index_name}\". \
                     Recreate the index manually."
            )
        }
        // AddForeignKey → DROP CONSTRAINT
        Operation::AddForeignKey {
            table, relation, ..
        } => {
            let fk_col = relation.foreign_key.as_deref().unwrap_or("unknown_fk");
            let constraint = format!("{table}_{fk_col}_fkey");
            format!(
                "ALTER TABLE \"public\".\"{table}\" DROP CONSTRAINT IF EXISTS \"{constraint}\";"
            )
        }
        // DropForeignKey → cannot restore definition
        Operation::DropForeignKey {
            table, constraint, ..
        } => {
            format!("-- WARNING: Cannot automatically roll back DROP CONSTRAINT \"{table}\".\"{constraint}\". \
                     Restore from backup.")
        }
        // CreateEnum → DROP TYPE
        Operation::CreateEnum { name, .. } => {
            format!("DROP TYPE IF EXISTS \"{name}\";")
        }
        // DropEnum → cannot restore
        Operation::DropEnum { name, .. } => {
            format!("-- WARNING: Cannot automatically roll back DROP TYPE \"{name}\".")
        }
        // EnableRls → DISABLE ROW LEVEL SECURITY
        Operation::EnableRls { table, .. } => {
            format!("ALTER TABLE \"public\".\"{table}\" DISABLE ROW LEVEL SECURITY;")
        }
        // CreateRlsPolicy → DROP POLICY
        Operation::CreateRlsPolicy { table, policy, .. } => {
            format!("DROP POLICY IF EXISTS \"{table}_{policy}\" ON \"public\".\"{table}\";")
        }
        // DropRlsPolicy → cannot restore
        Operation::DropRlsPolicy { table, policy, .. } => {
            format!(
                "-- WARNING: Cannot automatically roll back DROP POLICY \"{table}\".\"{policy}\"."
            )
        }
        // CreateTrigger → DROP TRIGGER
        Operation::CreateTrigger { table, trigger, .. } => {
            format!("DROP TRIGGER IF EXISTS \"{trigger}\" ON \"public\".\"{table}\";")
        }
        // DropTrigger → cannot restore
        Operation::DropTrigger { table, trigger, .. } => {
            format!("-- WARNING: Cannot automatically roll back DROP TRIGGER \"{trigger}\" on \"{table}\".")
        }
        // CreateJunctionTable → DROP TABLE
        Operation::CreateJunctionTable { table, .. } => {
            format!("DROP TABLE IF EXISTS \"public\".\"{table}\" CASCADE;")
        }
        // EnableExtension → DROP EXTENSION (risky — only emit a warning)
        Operation::EnableExtension { name, .. } => {
            format!(
                "-- WARNING: Rollback of CREATE EXTENSION \"{name}\" would DROP it. \
                     Remove manually if safe to do so."
            )
        }
    };
    Ok(Some(sql))
}

fn rollback_alter_column(table: &str, column: &str, changes: &serde_json::Value) -> String {
    let mut stmts: Vec<String> = Vec::new();

    // Reverse type change: restore old type from from_udt
    if let Some(type_change) = changes.get("type") {
        let from_udt = type_change
            .get("from_udt")
            .and_then(|v| v.as_str())
            .unwrap_or("text");
        // Map udt_name back to a castable type keyword
        let restore_type = udt_to_pg_type(from_udt);
        stmts.push(format!(
            "ALTER TABLE \"public\".\"{table}\" ALTER COLUMN \"{column}\" \
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
                 IF EXISTS (SELECT 1 FROM \"public\".\"{table}\" WHERE \"{column}\" IS NULL) THEN\n    \
                 RAISE EXCEPTION 'Cannot restore NOT NULL on {table}.{column}: NULL values exist.';\n  \
                 END IF;\n\
                 END $$;"
            ));
            stmts.push(format!(
                "ALTER TABLE \"public\".\"{table}\" ALTER COLUMN \"{column}\" SET NOT NULL;"
            ));
        } else {
            // Was nullable — restore by dropping not null
            stmts.push(format!(
                "ALTER TABLE \"public\".\"{table}\" ALTER COLUMN \"{column}\" DROP NOT NULL;"
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
        "varchar" | "bpchar" | "text" | _ => "TEXT",
    }
}

fn forward_description(op: &Operation) -> String {
    match op {
        Operation::CreateTable { table, .. } => format!("create table {table}"),
        Operation::DropTable { table, .. } => format!("drop table {table}"),
        Operation::AddColumn { table, column, .. } => format!("add column {table}.{column}"),
        Operation::DropColumn { table, column, .. } => format!("drop column {table}.{column}"),
        Operation::RenameColumn {
            table, from, to, ..
        } => format!("rename {table}.{from} → {to}"),
        Operation::AlterColumn { table, column, .. } => format!("alter column {table}.{column}"),
        Operation::AddIndex { table, index, .. } => {
            format!("add index on {table}({})", index.fields.join(","))
        }
        Operation::DropIndex { index_name, .. } => format!("drop index {index_name}"),
        Operation::AddForeignKey {
            table, relation, ..
        } => format!("add fk {table} → {}", relation.target),
        Operation::DropForeignKey {
            table, constraint, ..
        } => format!("drop fk {table}.{constraint}"),
        Operation::CreateEnum { name, .. } => format!("create enum {name}"),
        Operation::DropEnum { name, .. } => format!("drop enum {name}"),
        Operation::EnableRls { table, .. } => format!("enable rls {table}"),
        Operation::CreateRlsPolicy { table, policy, .. } => {
            format!("create policy {table}.{policy}")
        }
        Operation::DropRlsPolicy { table, policy, .. } => format!("drop policy {table}.{policy}"),
        Operation::CreateTrigger { table, trigger, .. } => {
            format!("create trigger {table}.{trigger}")
        }
        Operation::DropTrigger { table, trigger, .. } => format!("drop trigger {table}.{trigger}"),
        Operation::CreateJunctionTable { table, .. } => format!("create junction table {table}"),
        Operation::EnableExtension { name, .. } => format!("enable extension {name}"),
    }
}
