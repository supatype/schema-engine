//! Renames are declared, never guessed (decision D1).
//!
//! The column and table differs used to pair a dropped name with an added one by name similarity
//! (Jaro-Winkler at 0.7), mark the pair safe and rename it unasked, with no type check: two
//! different columns with similar names were merged, an integer column was renamed into a declared
//! text one, and a real rename below the threshold lost its data under `--force`. Now a rename is
//! applied only where it is declared, and everything else is the drop and the add the schema
//! describes. A rename is declared two ways, read together:
//!
//! - `annotations.db.renamedFrom` on a field or a model: one old name or a list, newest first;
//! - the project's rename journal (`renameJournal`, `supatype/renames.json`), each entry an old and
//!   a new column or table name, as a person confirmed it. Entries chain: `name` became `label`,
//!   then `label` became `title`, so a database still at `name` follows the chain back.
//!
//! Of the old names declared for a target, the first the database still has is the source. A
//! declaration is checked here before the differ uses it: its source must be Supatype's and not be
//! declared again, and a column's source must hold the declared type or one that widens to it. A
//! declaration whose sources are all gone (already applied, or a database that never had them) is
//! a no-op, so it can stay.

use anyhow::{bail, Result};

use super::column_diff::{column_type_matches_introspected, expected_udt, field_pg_type};
use super::Operation;
use crate::generator::sql::column_conversion::is_safe_widening;
use crate::introspector::tables::DbColumn;
use crate::parser::accessors::{column_names_for, field_annotations};
use crate::parser::annotations::DeclaredRename;
pub use crate::parser::annotations::RenameCandidate;
use crate::parser::ast::{FieldAst, ModelAst};
use crate::state::database_state::DatabaseState;

/// The longest chain of journal renames followed back from one name: far more than any project
/// has, and what stops a journal that loops from looping here.
const MAX_CHAIN: usize = 64;

/// The old names the journal records for `name`, newest first: the entry that renamed something
/// to `name`, then the one that renamed something to that, and so on. `kind` and `tables` say which
/// entries count: a column's on one of its table's names, or a table's.
fn journal_chain(
    journal: &[DeclaredRename],
    kind: &str,
    tables: &[&str],
    name: &str,
) -> Vec<String> {
    let mut chain: Vec<String> = Vec::new();
    let mut current = name.to_string();
    while chain.len() < MAX_CHAIN {
        let Some(entry) = journal.iter().rev().find(|e| {
            e.rename.kind == kind
                && e.rename.to == current
                && (kind == "table" || tables.contains(&e.rename.table.as_str()))
        }) else {
            break;
        };
        let from = entry.rename.from.clone();
        if from == name || chain.contains(&from) {
            break;
        }
        chain.push(from.clone());
        current = from;
    }
    chain
}

/// Every old name declared for one target, newest first and each once: the schema's own
/// `renamedFrom` before the journal's chain.
fn declared_sources(declared: Vec<String>, chained: Vec<String>) -> Vec<String> {
    let mut sources: Vec<String> = Vec::new();
    for name in declared.into_iter().chain(chained) {
        if !sources.contains(&name) {
            sources.push(name);
        }
    }
    sources
}

/// One declared column rename: the old columns it may come from (newest first), the new one, and
/// the field it renames to.
pub(crate) struct DeclaredColumnRename<'a> {
    pub sources: Vec<String>,
    pub to: String,
    pub field: &'a FieldAst,
}

impl DeclaredColumnRename<'_> {
    /// The source the database still has: the first of [`Self::sources`] it holds.
    pub fn present_source(&self, has: impl Fn(&str) -> bool) -> Option<&str> {
        self.sources
            .iter()
            .map(String::as_str)
            .find(|from| *from != self.to && has(from))
    }
}

/// The column renames `model` declares, on `tables` (its table's names, newest first): for each of
/// its columns, the old ones it may come from. A field's `renamedFrom` names old fields, whose
/// columns are the ones the previous push's field of that name made, when there was one, or the
/// ones this field would make under that name (a relation's `<name>_id`); the journal names old
/// columns.
pub(crate) fn declared_column_renames<'a>(
    model: &'a ModelAst,
    previous: Option<&ModelAst>,
    journal: &[DeclaredRename],
    tables: &[&str],
) -> Vec<DeclaredColumnRename<'a>> {
    let mut out = Vec::new();
    for (name, field) in &model.fields {
        let declared: Vec<Vec<String>> = field_annotations(field)
            .db
            .renamed_from
            .names()
            .map(|old| {
                previous
                    .and_then(|m| m.fields.get(old))
                    .map(|f| column_names_for(old, f))
                    .unwrap_or_else(|| column_names_for(old, field))
            })
            .collect();
        for (i, to) in column_names_for(name, field).into_iter().enumerate() {
            let from_field = declared
                .iter()
                .filter_map(|cols| cols.get(i).cloned())
                .collect();
            let sources =
                declared_sources(from_field, journal_chain(journal, "column", tables, &to));
            if !sources.is_empty() {
                out.push(DeclaredColumnRename { sources, to, field });
            }
        }
    }
    out
}

/// The facts a declared column rename is checked against.
pub(crate) struct ColumnRenameSite<'a> {
    pub table: &'a str,
    pub source: &'a DbColumn,
    pub target_exists: bool,
    pub source_declared: bool,
    pub source_ours: bool,
}

/// Checks one declared column rename from its present source, refusing anything that cannot be a
/// rename, naming both columns: a source and target that both exist, a source the schema still
/// declares, a source that is not Supatype's, or a source whose type is not the declared one and
/// does not widen to it.
pub(crate) fn check_column_rename(
    rename: &DeclaredColumnRename<'_>,
    site: &ColumnRenameSite<'_>,
) -> Result<()> {
    let (table, from, to) = (site.table, &site.source.name, &rename.to);
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
    if !holds_declared_type(rename.field, site.source) {
        let declared = field_pg_type(rename.field);
        bail!(
            "\"{table}\".\"{to}\" is declared as renamed from \"{table}\".\"{from}\", but \
             \"{from}\" is {udt} and \"{to}\" is declared {declared}, which a rename cannot change. \
             Declare \"{to}\" with the column's type, rename first and change the type in a later \
             push, or remove the declaration to drop and add the column.",
            udt = site.source.udt_name
        );
    }
    Ok(())
}

/// The old names declared for `model`'s table, newest first: its `renamedFrom`, then the journal's
/// chain back from its table.
pub(crate) fn declared_table_sources(model: &ModelAst, journal: &[DeclaredRename]) -> Vec<String> {
    let declared = model.annotations.db.renamed_from.0.clone();
    declared_sources(
        declared,
        journal_chain(journal, "table", &[], model.table_name()),
    )
}

/// Checks a model's declared table rename against the database, refusing anything that cannot be
/// a rename. `Some(source)` when the table is to be renamed from `source`, the first declared old
/// name the database has; `None` when there is nothing to rename (every source is gone).
pub(crate) fn check_table_rename(
    model: &ModelAst,
    db: &DatabaseState,
    declared_tables: &std::collections::HashSet<&str>,
    journal: &[DeclaredRename],
) -> Result<Option<String>> {
    let to = model.table_name();
    let Some(source) = declared_table_sources(model, journal)
        .into_iter()
        .filter(|from| from != to)
        .find_map(|from| db.tables.iter().find(|t| t.name == from))
    else {
        return Ok(None);
    };
    let from = &source.name;
    if db.tables.iter().any(|t| t.name == to) {
        bail!(
            "Table \"{to}\" is declared as renamed from \"{from}\", but both tables exist. Drop \
             one of them, or remove the declaration."
        );
    }
    if declared_tables.contains(from.as_str()) {
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
    Ok(Some(from.clone()))
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
