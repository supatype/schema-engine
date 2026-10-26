//! F2(a): a primary key or unique constraint a push drops and makes again takes the foreign keys
//! that depend on it down and back up with it, in one ordered plan.
//!
//! Postgres refuses to drop a key a foreign key references (`cannot drop constraint ... because
//! other objects depend on it`), and nothing here cascades. So each foreign key that references
//! the columns of a key being rebuilt, and is not already dropped by this push, is dropped before
//! the key and made again after it: from this push's statement when it is ours, from the
//! catalog's own definition when it is not. The removals run dependents first and the additions
//! dependencies first ([`super::creation_rank`]), so the order holds.

use crate::desired::ObjectKey;
use crate::introspector::fingerprint::{ObjectFingerprint, ObjectKind};
use crate::sql_quote::{quote_ident, quote_qualified};

use super::{goes_with_its_table, parse_definition, Action, Inputs, Sides};

/// A key this push drops and makes again, with the columns its live index covers, sorted.
fn rebuilt_key(sides: &Sides<'_>, action: &Action) -> Option<(ObjectKey, Vec<String>)> {
    let key = action.key();
    let rebuilt = matches!(action, Action::Replace { .. } | Action::Drift { .. })
        && matches!(key.kind, ObjectKind::PrimaryKey | ObjectKind::Unique)
        && action.removal_sql().is_some();
    if !rebuilt {
        return None;
    }
    let live = sides.live.get(key)?;
    Some((key.clone(), sorted_columns(&live.definition, "columns")))
}

fn sorted_columns(definition: &str, label: &str) -> Vec<String> {
    let mut columns: Vec<String> = parse_definition(definition)
        .get(label)
        .map(|c| c.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    columns.sort();
    columns
}

/// Whether the live foreign key `fk` references exactly the columns of `key`'s table that `columns`
/// names, which is what makes Postgres tie it to that key's index.
fn depends_on(fk: &ObjectFingerprint, key: &ObjectKey, columns: &[String]) -> bool {
    let parts = parse_definition(&fk.definition);
    parts.get("references").copied() == Some(&format!("{}.{}", key.schema, key.parent))
        && sorted_columns(&fk.definition, "referenced_columns") == columns
}

/// `ADD CONSTRAINT` for a foreign key as the catalog renders it, for one that is not ours: put
/// back exactly as it was. `None` when the rendering holds an escaped character, which this would
/// not put back faithfully.
fn as_it_is(key: &ObjectKey, fk: &ObjectFingerprint) -> Option<String> {
    let definition = parse_definition(&fk.definition)
        .get("definition")
        .copied()?;
    if definition.is_empty() || definition.contains('\\') {
        return None;
    }
    Some(format!(
        "ALTER TABLE {} ADD CONSTRAINT {} {definition};",
        quote_qualified(&key.schema, &key.parent),
        quote_ident(&key.name)
    ))
}

/// The rebuild of the foreign key `key` (live as `fk`) for `because`, given what the push
/// otherwise does about it, or `None` when it is already dropped or not this push's to touch.
fn rebuild(
    key: &ObjectKey,
    fk: &ObjectFingerprint,
    because: &ObjectKey,
    current: Option<&Action>,
) -> Option<Action> {
    let (create_sql, status) = match current {
        Some(Action::Keep {
            create_sql, status, ..
        })
        | Some(Action::Restate {
            create_sql, status, ..
        }) => (create_sql.clone(), Some(*status)),
        Some(Action::Released { .. }) | None => (as_it_is(key, fk)?, None),
        Some(_) => return None,
    };
    Some(Action::Rebuild {
        key: key.clone(),
        create_sql,
        status,
        because: because.clone(),
    })
}

/// Every foreign key on a key `changes` rebuilds, turned into (or added as) a [`Action::Rebuild`].
/// One `removals` already drops, one on a table the push drops, and one the push replaces anyway
/// are left as they are.
pub(super) fn dependents(
    inputs: &Inputs<'_>,
    sides: &Sides<'_>,
    removals: &[Action],
    changes: &mut Vec<Action>,
) {
    let rebuilt: Vec<(ObjectKey, Vec<String>)> = changes
        .iter()
        .filter_map(|a| rebuilt_key(sides, a))
        .collect();
    for (because, columns) in &rebuilt {
        for (key, fk) in &sides.live {
            if key.kind != ObjectKind::ForeignKey
                || !depends_on(fk, because, columns)
                || goes_with_its_table(inputs, key)
                || removals.iter().any(|a| a.key() == key)
            {
                continue;
            }
            let at = changes.iter().position(|a| a.key() == key);
            let Some(action) = rebuild(key, fk, because, at.map(|i| &changes[i])) else {
                continue;
            };
            match at {
                Some(i) => changes[i] = action,
                None => changes.push(action),
            }
        }
    }
}
