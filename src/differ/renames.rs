//! Renames are declared, never guessed (decision D1).
//!
//! The column and table differs used to pair a dropped name with an added one by name similarity
//! (Jaro-Winkler at 0.7), mark the pair safe and rename it unasked, with no type check: two
//! different columns with similar names were merged, an integer column was renamed into a declared
//! text one, and a real rename below the threshold lost its data under `--force`. Now a rename is
//! applied only where the schema declares it (`annotations.db.renamedFrom` on a field or a model),
//! and everything else is the drop and the add the schema describes.
//!
//! A declaration is checked here before the differ uses it: its source must exist, be Supatype's
//! and not be declared again, and a column's source must hold the declared type or one that widens
//! to it. A declaration whose source is gone (already applied, or a database that never had it) is
//! a no-op, so it can stay in the schema.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use super::column_diff::{column_type_matches_introspected, expected_udt, field_pg_type};
use super::Operation;
use crate::generator::sql::column_conversion::is_safe_widening;
use crate::introspector::tables::DbColumn;
use crate::parser::accessors::{column_names_for, field_annotations};
use crate::parser::ast::{FieldAst, ModelAst};
use crate::state::database_state::DatabaseState;

/// A dropped table or column and an added one a person may have meant as a rename. Only offered
/// (the CLI asks, and writes the declaration on a yes), never applied: a rename is declared.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameCandidate {
    /// `table` or `column`.
    pub kind: String,
    /// The table, for a column; the old table's name, for a table.
    pub table: String,
    pub from: String,
    pub to: String,
}

/// One declared column rename: the old column, the new one, and the field that declares it.
pub(crate) struct DeclaredColumnRename<'a> {
    pub from: String,
    pub to: String,
    pub field: &'a FieldAst,
}

/// The column renames `model` declares, as old and new column pairs. The old columns are the ones
/// the previous push's field of that name made, when there was one, or the ones this field would
/// make under its old name (a relation's `<name>_id`).
pub(crate) fn declared_column_renames<'a>(
    model: &'a ModelAst,
    previous: Option<&ModelAst>,
) -> Vec<DeclaredColumnRename<'a>> {
    let mut out = Vec::new();
    for (name, field) in &model.fields {
        let Some(old) = field_annotations(field).db.renamed_from.as_deref() else {
            continue;
        };
        let old_columns = previous
            .and_then(|m| m.fields.get(old))
            .map(|f| column_names_for(old, f))
            .unwrap_or_else(|| column_names_for(old, field));
        for (from, to) in old_columns.into_iter().zip(column_names_for(name, field)) {
            if from != to {
                out.push(DeclaredColumnRename { from, to, field });
            }
        }
    }
    out
}

/// The facts a declared column rename is checked against.
pub(crate) struct ColumnRenameSite<'a> {
    pub table: &'a str,
    pub source: Option<&'a DbColumn>,
    pub target_exists: bool,
    pub source_declared: bool,
    pub source_ours: bool,
}

/// Checks one declared column rename, refusing anything that cannot be a rename, naming both
/// columns: a source and target that both exist, a source the schema still declares, a source
/// that is not Supatype's, or a source whose type is not the declared one and does not widen to it.
/// True when the source is to be renamed; false when it is gone (already applied, or never there),
/// so there is nothing to rename.
pub(crate) fn check_column_rename(
    rename: &DeclaredColumnRename<'_>,
    site: &ColumnRenameSite<'_>,
) -> Result<bool> {
    let (table, from, to) = (site.table, &rename.from, &rename.to);
    let Some(source) = site.source else {
        return Ok(false);
    };
    if site.target_exists {
        bail!(
            "\"{table}\".\"{to}\" is declared as renamed from \"{table}\".\"{from}\", but both \
             columns exist. Drop one of them, or remove the declaration."
        );
    }
    if site.source_declared {
        bail!(
            "\"{table}\".\"{to}\" is declared as renamed from \"{table}\".\"{from}\", but the schema \
             still declares \"{from}\". Remove one of them."
        );
    }
    if !site.source_ours {
        bail!(
            "\"{table}\".\"{to}\" is declared as renamed from \"{table}\".\"{from}\", but \
             \"{from}\" is not Supatype's to rename. Run `supatype adopt` to bring it under \
             management first, or remove the declaration."
        );
    }
    if !holds_declared_type(rename.field, source) {
        let declared = field_pg_type(rename.field);
        bail!(
            "\"{table}\".\"{to}\" is declared as renamed from \"{table}\".\"{from}\", but \
             \"{from}\" is {} and \"{to}\" is declared {declared}, which a rename cannot change. \
             Declare \"{to}\" with the column's type, rename first and change the type in a later \
             push, or remove the declaration to drop and add the column.",
            source.udt_name
        );
    }
    Ok(true)
}

/// Checks a model's declared table rename against the database, refusing anything that cannot be
/// a rename. `Some(source)` when the table is to be renamed from `source`; `None` when there is
/// nothing to rename (the source is gone).
pub(crate) fn check_table_rename<'a>(
    model: &'a ModelAst,
    db: &DatabaseState,
    declared_tables: &std::collections::HashSet<&str>,
) -> Result<Option<&'a str>> {
    let Some(from) = model.annotations.db.renamed_from.as_deref() else {
        return Ok(None);
    };
    let to = model.table_name();
    let Some(source) = db.tables.iter().find(|t| t.name == from && from != to) else {
        return Ok(None);
    };
    if db.tables.iter().any(|t| t.name == to) {
        bail!(
            "Table \"{to}\" is declared as renamed from \"{from}\", but both tables exist. Drop \
             one of them, or remove the declaration."
        );
    }
    if declared_tables.contains(from) {
        bail!(
            "Table \"{to}\" is declared as renamed from \"{from}\", but the schema still declares \
             \"{from}\". Remove one of them."
        );
    }
    if !db.owns_table(source) {
        bail!(
            "Table \"{to}\" is declared as renamed from \"{from}\", but \"{from}\" is not managed \
             by Supatype. Run `supatype adopt` to bring it under management first, or remove the \
             declaration."
        );
    }
    Ok(Some(from))
}

/// The renames a person may have meant in `ops`: on one table, a dropped column of ours and an
/// added one whose declared type the dropped one holds or widens to; and a dropped table and a
/// created one. Sorted, for a stable prompt.
pub(crate) fn rename_candidates(ops: &[Operation], db: &DatabaseState) -> Vec<RenameCandidate> {
    let mut out = Vec::new();
    for op in ops {
        match op {
            Operation::DropColumn { table, column, .. } => {
                out.extend(column_candidates(ops, db, table, column));
            }
            Operation::DropTable { table: from, .. } => {
                out.extend(ops.iter().filter_map(|other| match other {
                    Operation::CreateTable { table: to, .. } => Some(RenameCandidate {
                        kind: "table".into(),
                        table: from.clone(),
                        from: from.clone(),
                        to: to.clone(),
                    }),
                    _ => None,
                }));
            }
            _ => {}
        }
    }
    out.sort();
    out
}

fn column_candidates(
    ops: &[Operation],
    db: &DatabaseState,
    table: &str,
    dropped: &str,
) -> Vec<RenameCandidate> {
    let Some(source) = db
        .tables
        .iter()
        .find(|t| t.name == table)
        .and_then(|t| t.columns.iter().find(|c| c.name == dropped))
    else {
        return Vec::new();
    };
    ops.iter()
        .filter_map(|op| match op {
            Operation::AddColumn {
                table: t,
                column,
                field,
                ..
            } if t == table && holds_declared_type(field, source) => Some(RenameCandidate {
                kind: "column".into(),
                table: table.to_string(),
                from: dropped.to_string(),
                to: column.clone(),
            }),
            _ => None,
        })
        .collect()
}

/// Whether `source` can become `field` by a rename alone, or a rename and a widening cast: its
/// type is the declared one, or one that widens to it. A field with no column type of its own (a
/// composite) never can.
fn holds_declared_type(field: &FieldAst, source: &DbColumn) -> bool {
    expected_udt(field).is_some()
        && (column_type_matches_introspected(field, source)
            || is_safe_widening(&source.udt_name, &field_pg_type(field)))
}
