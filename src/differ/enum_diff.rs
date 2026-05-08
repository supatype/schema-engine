//! Enum diff — detects changes between schema-declared enums and the database's
//! Postgres enum types. Generates operations for:
//!   - Add enum value (task 67, safe)
//!   - Remove enum value (task 68, destructive)
//!   - Rename enum value (task 69, cautious)
//!   - Reorder enum values (task 70, cautious)

use super::{Operation, Risk};
use crate::parser::ast::{FieldAst, SchemaAst};
use crate::state::database_state::DatabaseState;
use anyhow::Result;
use strsim::jaro_winkler;

/// Similarity threshold for detecting enum value renames (same as column rename).
const RENAME_THRESHOLD: f64 = 0.7;

/// Derives the Postgres enum type name from a model table name and field name.
/// Convention: `{table}_{field}` — e.g. table "posts", field "status" → "posts_status".
fn enum_type_name(table_name: &str, field_name: &str) -> String {
    format!("{table_name}_{field_name}")
}

/// Collects all (table, column) pairs from the schema that reference a given enum type name.
fn columns_using_enum(ast: &SchemaAst, enum_name: &str) -> Vec<(String, String)> {
    let mut cols = Vec::new();
    for model in &ast.models {
        for (field_name, field) in &model.fields {
            if let FieldAst::Enum(ef) = field {
                if ef.pg_type.to_uppercase() == "TEXT" {
                    continue; // TEXT+CHECK enum — no native Postgres type
                }
                let name = enum_type_name(&model.table_name, field_name);
                if name == enum_name {
                    cols.push((model.table_name.clone(), field_name.clone()));
                }
            }
        }
    }
    cols
}

/// Diff schema enums against database enums.
///
/// The schema doesn't declare enum types explicitly — they are inferred from
/// `Enum` fields. Each Enum field produces a named type `{table}_{field}`.
pub fn diff(
    ast: &SchemaAst,
    db: &DatabaseState,
    ops: &mut Vec<Operation>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    // Build a map of schema-desired enums: name → ordered values
    let mut schema_enums: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for model in &ast.models {
        for (field_name, field) in &model.fields {
            if let FieldAst::Enum(ef) = field {
                // TEXT+CHECK enums don't create a Postgres type — skip them.
                // Only native enums (pg_type != "TEXT") need type management.
                if ef.pg_type.to_uppercase() == "TEXT" {
                    continue;
                }
                let name = enum_type_name(&model.table_name, field_name);
                schema_enums.insert(name, ef.values.clone());
            }
        }
    }

    // Build a map of existing DB enums: name → ordered values
    let db_enums: std::collections::HashMap<&str, &Vec<String>> = db
        .enums
        .iter()
        .map(|e| (e.name.as_str(), &e.values))
        .collect();

    let schema_enum_names: std::collections::HashSet<&str> =
        schema_enums.keys().map(|s| s.as_str()).collect();
    let db_enum_names: std::collections::HashSet<&str> = db_enums.keys().copied().collect();

    // ─── New enums (CreateEnum) ──────────────────────────────────────────────
    for name in &schema_enum_names {
        if !db_enum_names.contains(name) {
            ops.push(Operation::CreateEnum {
                name: name.to_string(),
                values: schema_enums[*name].clone(),
                risk: Risk::Safe,
            });
        }
    }

    // ─── Dropped enums (DropEnum) ────────────────────────────────────────────
    for name in &db_enum_names {
        if !schema_enum_names.contains(name) {
            ops.push(Operation::DropEnum {
                name: name.to_string(),
                risk: Risk::Safe,
            });
        }
    }

    // ─── Changed enums ──────────────────────────────────────────────────────
    for name in schema_enum_names.intersection(&db_enum_names) {
        let schema_vals = &schema_enums[*name];
        let db_vals = db_enums[*name];

        if schema_vals == db_vals {
            continue; // No change
        }

        diff_enum_values(name, db_vals, schema_vals, ast, ops, warnings);
    }

    Ok(())
}

/// Diff the values of a single enum type. Detects:
///   - Renames (via string similarity)
///   - Additions
///   - Removals
///   - Reordering
fn diff_enum_values(
    enum_name: &str,
    db_vals: &[String],
    schema_vals: &[String],
    ast: &SchemaAst,
    ops: &mut Vec<Operation>,
    warnings: &mut Vec<String>,
) {
    let db_set: std::collections::HashSet<&str> = db_vals.iter().map(|s| s.as_str()).collect();
    let schema_set: std::collections::HashSet<&str> =
        schema_vals.iter().map(|s| s.as_str()).collect();

    let added: Vec<&str> = schema_vals
        .iter()
        .filter(|v| !db_set.contains(v.as_str()))
        .map(|s| s.as_str())
        .collect();

    let removed: Vec<&str> = db_vals
        .iter()
        .filter(|v| !schema_set.contains(v.as_str()))
        .map(|s| s.as_str())
        .collect();

    // ─── Rename detection ────────────────────────────────────────────────────
    let mut renamed_added: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut renamed_removed: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for &rm in &removed {
        if let Some(&best_add) = added
            .iter()
            .filter(|&&a| !renamed_added.contains(a))
            .max_by(|&&a, &&b| {
                jaro_winkler(rm, a)
                    .partial_cmp(&jaro_winkler(rm, b))
                    .unwrap()
            })
        {
            if jaro_winkler(rm, best_add) >= RENAME_THRESHOLD {
                ops.push(Operation::RenameEnumValue {
                    enum_name: enum_name.to_string(),
                    from: rm.to_string(),
                    to: best_add.to_string(),
                    risk: Risk::Cautious,
                });
                warnings.push(format!(
                    "Enum '{enum_name}': value '{rm}' removed and '{best_add}' added. \
                     Treating as rename (ALTER TYPE ... RENAME VALUE)."
                ));
                renamed_added.insert(best_add);
                renamed_removed.insert(rm);
            }
        }
    }

    // ─── Added values ────────────────────────────────────────────────────────
    for &val in &added {
        if !renamed_added.contains(val) {
            ops.push(Operation::AddEnumValue {
                enum_name: enum_name.to_string(),
                value: val.to_string(),
                risk: Risk::Safe,
            });
        }
    }

    // ─── Removed values ──────────────────────────────────────────────────────
    let affected_columns = columns_using_enum(ast, enum_name);
    for &val in &removed {
        if !renamed_removed.contains(val) {
            ops.push(Operation::RemoveEnumValue {
                enum_name: enum_name.to_string(),
                value: val.to_string(),
                affected_columns: affected_columns.clone(),
                risk: Risk::Destructive,
            });
            warnings.push(format!(
                "Removing enum value '{val}' from '{enum_name}'. \
                 Rows currently using this value will need to be updated. \
                 Use --force to proceed."
            ));
        }
    }

    // ─── Reorder detection ───────────────────────────────────────────────────
    // After accounting for renames/adds/removes, check if the common values
    // (those present in both DB and schema) have changed their relative order.
    let effective_db: Vec<&str> = db_vals
        .iter()
        .filter(|v| {
            // Map renamed values to their new names for ordering comparison
            if renamed_removed.contains(v.as_str()) {
                return false;
            }
            schema_set.contains(v.as_str())
        })
        .map(|s| s.as_str())
        .collect();

    let effective_schema: Vec<&str> = schema_vals
        .iter()
        .filter(|v| {
            if renamed_added.contains(v.as_str()) {
                return false;
            }
            db_set.contains(v.as_str())
        })
        .map(|s| s.as_str())
        .collect();

    if effective_db != effective_schema && !effective_db.is_empty() {
        ops.push(Operation::ReorderEnumValues {
            enum_name: enum_name.to_string(),
            old_values: db_vals.to_vec(),
            new_values: schema_vals.to_vec(),
            affected_columns,
            risk: Risk::Cautious,
        });
        warnings.push(format!(
            "Enum '{enum_name}': value order changed. The type will be recreated \
             to preserve the declared order (affects sort operations)."
        ));
    }
}
