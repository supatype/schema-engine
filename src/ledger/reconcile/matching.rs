//! Recognising an owned object under a name other than the one this push gives it, so that it is
//! renamed rather than dropped and made again (F2 and F8).
//!
//! Two ways an object comes to have another name. Its table was renamed: Postgres keeps the names
//! of everything on a renamed table, while the schema names them after the new one. Or an older
//! engine named it differently: 0.6.0 let Postgres cut a long name to 63 bytes where this engine
//! fits it as Postgres fits the names it chooses itself. Either way the object is the one desired
//! when its structure is, and the push renames it in place.

use std::collections::{BTreeMap, BTreeSet};

use crate::desired::statements::check_expression;
use crate::desired::{DesiredObject, ObjectKey};
use crate::introspector::fingerprint::{ObjectFingerprint, ObjectKind};

use super::{
    changed_since_recorded, parse_definition, structure_matches, Action, AdoptReason, Inputs,
    LedgerRow, Location, Sides, Status,
};

/// What [`moved_with_their_tables`] found: the renames, the rows they retire and the desired keys
/// they take.
#[derive(Default)]
pub(super) struct Moved {
    pub(super) actions: Vec<Action>,
    pub(super) from: BTreeSet<ObjectKey>,
    pub(super) to: BTreeSet<ObjectKey>,
}

/// The kinds named after their table that a table rename carries along: the keys, checks, indexes
/// and triggers on it.
fn moves_with_its_table(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::PrimaryKey
            | ObjectKind::Unique
            | ObjectKind::ForeignKey
            | ObjectKind::Check
            | ObjectKind::Index
            | ObjectKind::Trigger
    )
}

/// F2(b): every owned object on a table this push renames, unchanged since the last apply, that is
/// the same object as one desired on the table's new name. Renamed to that name, its row moved.
pub(super) fn moved_with_their_tables(inputs: &Inputs<'_>, sides: &Sides<'_>) -> Moved {
    let mut moved = Moved::default();
    for (&key, row) in &sides.ledger {
        let Some(table) = new_table_name(inputs, key) else {
            continue;
        };
        if row.status == Status::Released || !moves_with_its_table(key.kind) {
            continue;
        }
        let Some(l) = sides
            .live
            .get(key)
            .filter(|l| !changed_since_recorded(row, l))
        else {
            continue;
        };
        let found = sides.desired.values().find(|d| {
            d.key.kind == key.kind
                && d.key.schema == key.schema
                && d.key.parent == table
                && !sides.ledger.contains_key(&d.key)
                && !moved.to.contains(&d.key)
                && same_object(inputs, d, row, l)
        });
        if let Some(d) = found {
            moved.from.insert(key.clone());
            moved.to.insert(d.key.clone());
            moved.actions.push(Action::Rename {
                key: d.key.clone(),
                from: key.clone(),
                create_sql: d.create_sql.clone(),
                status: row.status,
            });
        }
    }
    moved
}

/// The name a renamed table of `key`'s takes, when this push renames it.
fn new_table_name<'i>(inputs: &Inputs<'i>, key: &ObjectKey) -> Option<&'i str> {
    let table = ObjectKey {
        kind: ObjectKind::Table,
        schema: key.schema.clone(),
        parent: String::new(),
        name: key.parent.clone(),
    };
    inputs.renamed_tables.get(&table).map(String::as_str)
}

/// Whether the recorded object `row` (live as `l`) is the desired `d` under another name: the same
/// structure, or for a check, whose only part is an expression Postgres rewrites, the same
/// expression as recorded.
fn same_object(
    inputs: &Inputs<'_>,
    d: &DesiredObject,
    row: &LedgerRow,
    l: &ObjectFingerprint,
) -> bool {
    match d.key.kind {
        ObjectKind::Check => check_expression(&row.desired_sql)
            .is_some_and(|recorded| Some(recorded) == check_expression(&d.create_sql)),
        _ => structure_matches_renamed(d, l, inputs.renamed_tables),
    }
}

/// [`structure_matches`], with a foreign key's referenced table read under the name this push
/// gives it: a key to a table being renamed points at the renamed table once the push has run.
pub(super) fn structure_matches_renamed(
    d: &DesiredObject,
    l: &ObjectFingerprint,
    renamed: &BTreeMap<ObjectKey, String>,
) -> bool {
    if d.structure.is_empty() {
        return false;
    }
    let parts = parse_definition(&l.definition);
    d.structure.iter().all(|(label, want)| {
        let have = parts.get(*label).copied();
        have == Some(want.as_str())
            || (*label == "references"
                && have.and_then(|h| renamed_reference(h, renamed)).as_deref()
                    == Some(want.as_str()))
    })
}

/// `schema.table` under the name this push gives the table, when it renames it.
fn renamed_reference(reference: &str, renamed: &BTreeMap<ObjectKey, String>) -> Option<String> {
    let (schema, table) = reference.split_once('.')?;
    renamed
        .iter()
        .find(|(k, _)| k.schema == schema && k.name == table)
        .map(|(_, to)| format!("{schema}.{to}"))
}

/// The kinds a live object with no row is matched to a desired one by structure, under a name of
/// its own.
fn matched_by_structure(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::Unique
            | ObjectKind::PrimaryKey
            | ObjectKind::ForeignKey
            | ObjectKind::Index
            | ObjectKind::Trigger
    )
}

/// A live object of `d`'s kind on `d`'s table, under another name, that no row records, nothing
/// else desires and nothing has taken, with exactly `d`'s structure.
fn found_by_structure<'s>(
    sides: &Sides<'s>,
    d: &DesiredObject,
    taken: &BTreeSet<ObjectKey>,
) -> Option<(&'s ObjectFingerprint, ObjectKey)> {
    sides
        .live
        .iter()
        .find(|(k, l)| {
            k.kind == d.key.kind
                && k.schema == d.key.schema
                && k.parent == d.key.parent
                && !sides.ledger.contains_key(*k)
                && !sides.desired.contains_key(*k)
                && !taken.contains(*k)
                && structure_matches(d, l)
        })
        .map(|(k, l)| (*l, k.clone()))
}

/// Whether a live object found under another name is ours: stamped, in a place only the engine
/// writes, named as an engine names it (this one, or 0.6.0 before it), or recorded under that name
/// on a table since renamed. A row under the same name on another table is this object before its
/// table was renamed: a key's name is its index's, unique in the schema. Not a released row: that
/// one is the user's, wherever it is.
fn ours(inputs: &Inputs<'_>, sides: &Sides<'_>, from: &ObjectKey) -> bool {
    let recorded_elsewhere = sides.ledger.iter().any(|(k, row)| {
        row.status != Status::Released
            && k.kind == from.kind
            && k.schema == from.schema
            && k.name == from.name
    });
    recorded_elsewhere
        || (inputs.location)(from) != Location::Neutral
        || inputs.named_by_the_engine.contains(from)
}

/// A desired object with no row and nothing live under its name, found under a name of its own
/// (the differ this replaced matched a unique by its columns, and 0.6.0 named long keys,
/// indexes and triggers differently). Ours is taken over and renamed, so nothing is duplicated
/// or rebuilt. A user's unique constraint on the columns ours would cover is theirs: the push
/// refuses until `adopt` hands it over, keyed by its own name so adopt can record it, and the push
/// after that brings it to the schema. Any other object of the user's is left alone and ours is
/// created beside it. The live keys taken are added to `taken`.
pub(super) fn under_another_name(
    inputs: &Inputs<'_>,
    sides: &Sides<'_>,
    d: &DesiredObject,
    taken: &mut BTreeSet<ObjectKey>,
) -> Option<Action> {
    if !matched_by_structure(d.key.kind) {
        return None;
    }
    let (l, from) = found_by_structure(sides, d, taken)?;
    let reason = match (l.stamped(), ours(inputs, sides, &from)) {
        (true, _) => AdoptReason::Stamped,
        (false, true) => AdoptReason::OwnedSchema,
        (false, false) if d.key.kind == ObjectKind::Unique => {
            let conflict = Action::Conflict {
                key: from.clone(),
                create_sql: d.create_sql.clone(),
                live_def: l.definition.clone(),
            };
            taken.insert(from);
            return Some(conflict);
        }
        (false, false) => return None,
    };
    let adopt = Action::Adopt {
        key: d.key.clone(),
        reason,
        create_sql: d.create_sql.clone(),
        comment: l.comment.clone(),
        renamed_from: Some(from.name.clone()),
        status: Status::Managed,
    };
    taken.insert(from);
    Some(adopt)
}
