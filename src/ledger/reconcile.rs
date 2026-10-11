//! The reconcile: desired objects against the ledger against the catalog, into actions.
//!
//! Plan 3.3 (the table) and section 7 (objects with no ledger row), as one pure function. It takes
//! what a push wants (`desired`), what the ledger says we own, what the catalog holds now (each
//! live fingerprint carrying its comment, so an older engine's stamp is a property of the object),
//! and the one fact that depends on this push rather than on the objects: which desired objects
//! another statement of the push already creates. Nothing here touches a connection, so every row
//! of the table has a unit test.
//!
//! A same-named unstamped object whose structure cannot be compared (a check, whose only part is
//! an expression Postgres rewrites) comes out as a `Conflict`. The caller may then prove some of
//! those equivalent with the database itself (`super::probe`) and call [`Plan::adopt_equivalent`],
//! which turns exactly those conflicts into adoptions. The reconcile never compares our text to a
//! deparse.
//!
//! Only the kinds in `kinds` are reconciled. A kind moves onto the reconcile one PR at a time
//! (plan section 9); until it moves, its old differ stays authoritative and its rows do not exist.

mod matching;
mod rebuild;

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::desired::{never_removed, DesiredObject, ObjectKey};
use crate::introspector::fingerprint::{ObjectFingerprint, ObjectKind};
use crate::sql_quote::{quote_ident, quote_qualified};

use super::{LedgerRow, Status};

pub struct Inputs<'a> {
    pub desired: &'a [DesiredObject],
    pub ledger: &'a [LedgerRow],
    pub live: &'a [ObjectFingerprint],
    /// Desired objects this push already creates as part of another statement (a constraint
    /// declared inline in `CREATE TABLE` or `ADD COLUMN`). Their `Create` runs no SQL of its own.
    pub created_by_parent: &'a BTreeSet<ObjectKey>,
    /// Tables this push drops. An owned object on one goes with it (plan 3.3): its row is removed
    /// and no drop of its own is emitted, since the table will not be there to alter.
    pub dropped_tables: &'a BTreeSet<ObjectKey>,
    /// What an object's location says about whose it is, for a live object with no row (plan 3.4
    /// and section 5). The push knows the engine's schemas and names; the reconcile does not.
    pub location: fn(&ObjectKey) -> Location,
    /// Objects an older engine made under a name only the engine gives (section 7, by naming): a
    /// function, trigger or view in one of its own schemas, or an affordance function or trigger
    /// in the project schema, named exactly as the engine names it for a model the last push's
    /// schema declares. With no row and no stamp, such an object is ours: replaced when the
    /// schema asks for it and its definition differs, dropped when it no longer does. Nothing else
    /// is claimed this way.
    pub named_by_the_engine: &'a BTreeSet<ObjectKey>,
    /// Tables this push renames, keyed by the table's key under its old name, with its new name.
    /// An object the ledger records on one is the same object on the renamed table (F2): it is
    /// renamed with it, never dropped and made again.
    pub renamed_tables: &'a BTreeMap<ObjectKey, String>,
    pub kinds: &'a [ObjectKind],
}

/// What a live object's location says about whose it is when the ledger has no row for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// Nothing: whose it is rests on a stamp or on its structure (section 7).
    Neutral,
    /// In one of the engine's own schemas (plan 3.4): ours when the schema asks for it, brought up
    /// to date rather than refused, and otherwise left alone.
    Owned,
    /// Somewhere only the engine writes (a label under our provider, section 5): ours whether or
    /// not the schema asks for it, so taken off when it does not, as a stamped object is.
    Exclusive,
}

/// A location rule that knows no location, for callers with no engine schemas to name.
pub fn no_location(_: &ObjectKey) -> Location {
    Location::Neutral
}

/// The kinds the table and column differs create, alter and drop, because a table or column holds
/// data that a drop and re-create would lose: renames, type conversions and nullability are the
/// differ's, gated on the ledger (D4, Phase 4.11). A serial column's sequence is made and kept by its
/// column. The reconcile records them and runs no SQL of its own for them.
pub fn altered_by_the_differ(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::Table | ObjectKind::Column | ObjectKind::Sequence
    )
}

/// The differ-altered kinds that declaring takes over (D4): a column the schema declares on a table
/// that is ours, and its sequence. Not a table: one that exists and is not ours makes the push
/// refuse until `supatype adopt` hands it over, since attaching access rules to it changes what an
/// existing application can read.
fn adopted_by_declaring(kind: ObjectKind) -> bool {
    matches!(kind, ObjectKind::Column | ObjectKind::Sequence)
}

/// Kinds whose name says what they govern, so a same-named live object with no row is ours and
/// is replaced, whatever its comment or structure.
///
/// A policy is named by its table and the operation it covers; the policy differ rewrote any
/// policy on a name it owned, which is how an older engine's policies, stamped or not, are brought
/// up to date. Its expression is what a takeover would have to compare, and replacing it costs one
/// statement. A grant is named by its table and role, and only the API roles on model tables are
/// ever desired, whose privileges the engine always re-asserted (D7): an upgrade takes them over
/// and leaves them holding exactly what the rules allow. Row-level security is named by its table,
/// and only tables the schema owns ask for it. A schema is named by itself, and only the engine's
/// own schemas are desired.
fn claimed_by_name(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::Policy
            | ObjectKind::TableGrant
            | ObjectKind::RlsAttributes
            | ObjectKind::Schema
    )
}

/// The kinds whose `CREATE` replaces what is there, so a new definition needs no drop first:
/// functions and triggers (`CREATE OR REPLACE`; dropping first would fail anyway, as a trigger
/// depends on its function), and grants, whose statement revokes everything before it grants the
/// exact set, and RLS enablement and schemas, whose statements simply assert them. Not views: `CREATE OR REPLACE VIEW` refuses anything but appending columns, so a
/// changed view is dropped and made again.
fn replaced_in_place(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::Function
            | ObjectKind::Trigger
            | ObjectKind::TableGrant
            | ObjectKind::RlsAttributes
            | ObjectKind::Schema
    )
}

/// Whether a statement that creates an object of this kind as part of another (the versions
/// layer's script, a re-asserted function file) also replaces one that is there: its `Replace` and
/// `Drift` can then run no SQL of their own. Not an index: every index is made `IF NOT EXISTS`, so
/// a changed or hand-edited one would be left as it is while its row recorded it as put right. Its
/// own drop and create run instead, and the parent's then finds it made.
fn remade_by_its_parent(kind: ObjectKind) -> bool {
    kind != ObjectKind::Index
}

/// The order kinds are created in, dependencies first; drops run in reverse. A trigger needs its
/// function and its table, a foreign key its two tables, a column its type.
pub fn creation_rank(kind: ObjectKind) -> u8 {
    match kind {
        ObjectKind::Schema => 0,
        ObjectKind::EnumType => 1,
        ObjectKind::Sequence => 2,
        ObjectKind::Table => 3,
        ObjectKind::Column => 4,
        ObjectKind::PrimaryKey => 5,
        ObjectKind::Unique => 6,
        ObjectKind::ForeignKey => 7,
        ObjectKind::Check => 8,
        ObjectKind::Index => 9,
        ObjectKind::Function => 10,
        ObjectKind::Trigger => 11,
        ObjectKind::View => 12,
        ObjectKind::Policy => 13,
        ObjectKind::RlsAttributes => 14,
        ObjectKind::TableGrant => 15,
        ObjectKind::SecurityLabel => 16,
        ObjectKind::CronJob => 17,
    }
}

/// Why an object with no ledger row is taken as ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptReason {
    /// Stamped `supatype:managed` by an older engine: ours by its own record (section 7.1).
    Stamped,
    /// Unstamped, but its structural parts are exactly what we would create (D2, section 7.2).
    StructureMatches,
    /// Unstamped and not structurally comparable, but the database deparses it to what we would
    /// create (section 7.2, proved by `super::probe`).
    DeparsesEqual,
    /// In one of the engine's own schemas (plan 3.4), or a label under its own provider (section 5),
    /// where nothing else writes: ours by location, so `managed` rather than `adopted`.
    OwnedSchema,
    /// A column the schema declares on a table the schema owns (D4): declaring it is what adopts
    /// it. The column differ brings it to the declared type; the reconcile only records it.
    Declared,
    /// A column the schema no longer declares, on a table that is ours, that the last push's schema
    /// declared and no row records (the first push after an upgrade): an older engine made it. The
    /// push that removes it from the schema only records it, and the next push drops it.
    PreviouslyDeclared,
}

/// What a push does about one object. Every variant that leaves a row carries what the row needs:
/// the `CREATE` we intend (`create_sql`) and the status the reconcile decided for it. Drops are
/// rendered from the key (`ObjectKey::drop_sql`), never stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Action {
    /// No row, desired, absent. `inline` when the parent statement creates it, so no SQL runs.
    Create {
        key: ObjectKey,
        create_sql: String,
        inline: bool,
        status: Status,
    },
    /// No row, desired, present and recognisably ours. A row is added; for a stamped object the
    /// stamp is taken out of its comment (section 6), which is the only SQL this runs.
    Adopt {
        key: ObjectKey,
        reason: AdoptReason,
        create_sql: String,
        /// The live comment, so the stamp can be removed and any user text kept.
        comment: Option<String>,
        /// The name the object has now, when it is found under another than the one desired (a
        /// unique constraint is matched by its columns until it has a row): it is renamed to the
        /// desired name, so every later push matches it by name.
        #[serde(skip_serializing_if = "Option::is_none")]
        renamed_from: Option<String>,
        status: Status,
    },
    /// No row, desired, present and not ours. The push refuses; `adopt` or a rename resolves it.
    Conflict {
        key: ObjectKey,
        create_sql: String,
        live_def: String,
    },
    /// Owned, desired, absent: someone dropped it. Recreated and reported. `inline` as for
    /// `Create`: the parent statement (a re-asserted script) makes it, so no SQL of its own runs.
    Recreate {
        key: ObjectKey,
        create_sql: String,
        inline: bool,
        status: Status,
    },
    /// Owned, desired, present, and this push's `CREATE` differs from the one recorded. `inline`
    /// when the parent statement replaces it itself.
    Replace {
        key: ObjectKey,
        create_sql: String,
        previous_sql: String,
        inline: bool,
        status: Status,
        /// The object was also changed outside Supatype since the last apply: replacing it
        /// overwrites that change, so where it decides access a push asks first (plan 3.5).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        drifted: Option<HandEdit>,
    },
    /// Owned, desired, present, and the catalog no longer matches what was recorded after the last
    /// apply: changed outside Supatype. Shown as a diff, then re-asserted (O1, subject to 3.5).
    /// `inline` when the parent statement re-asserts it itself.
    Drift {
        key: ObjectKey,
        recorded_def: String,
        live_def: String,
        /// The live fingerprint, which `doctor --rebaseline` records as the new baseline.
        live_fp: String,
        create_sql: String,
        security_relevant: bool,
        inline: bool,
        status: Status,
    },
    /// Owned, desired, present, unchanged. The row is refreshed after apply, nothing is executed.
    Keep {
        key: ObjectKey,
        create_sql: String,
        status: Status,
    },
    /// Owned, desired, present and unchanged since the last apply, with exactly the structure this
    /// push wants, while the `CREATE` recorded for it is worded differently (an older engine's
    /// template). Nothing is executed: the row is rewritten to this push's statement.
    Restate {
        key: ObjectKey,
        create_sql: String,
        previous_sql: String,
        status: Status,
    },
    /// Owned, on a table this push renames, and the same object as the one desired on the table's
    /// new name: renamed in place to the name the schema now gives it, never dropped and made
    /// again. Its row moves from `from` to `key`.
    Rename {
        key: ObjectKey,
        from: ObjectKey,
        create_sql: String,
        status: Status,
    },
    /// A foreign key on a primary key or unique constraint this push drops and makes again.
    /// Postgres refuses to drop a key a foreign key depends on, so the foreign key is dropped
    /// before `because` and made again after it, unchanged. `status` is its row's, or `None` for
    /// one Supatype does not own, which is put back exactly as it was and gets no row.
    Rebuild {
        key: ObjectKey,
        create_sql: String,
        status: Option<Status>,
        because: ObjectKey,
    },
    /// Owned, no longer desired, present. `recorded_sql` is the `CREATE` the ledger held, which is
    /// what a rollback re-runs, or for an object with no row the live definition the catalog renders;
    /// `None` when neither has one (a stamped check).
    Drop {
        key: ObjectKey,
        recorded_sql: Option<String>,
    },
    /// Owned, no longer desired, already gone. The row goes.
    Forget { key: ObjectKey },
    /// `released`: the user took it back. Left alone whatever the schema says.
    Released { key: ObjectKey },
}

/// A change made outside Supatype to an object this push replaces anyway: what was recorded after
/// the last apply, beside what the catalog holds now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HandEdit {
    pub recorded_def: String,
    pub live_def: String,
    /// The live fingerprint, which `doctor --rebaseline` records as the new baseline.
    pub live_fp: String,
}

/// What an action leaves in the ledger once applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowAfter<'a> {
    /// A row with this `CREATE` and status, its live fingerprint read after apply.
    Write { create_sql: &'a str, status: Status },
    /// No row.
    Remove,
    /// Whatever row there was, untouched.
    Leave,
}

impl Action {
    pub fn key(&self) -> &ObjectKey {
        match self {
            Action::Create { key, .. }
            | Action::Adopt { key, .. }
            | Action::Conflict { key, .. }
            | Action::Recreate { key, .. }
            | Action::Replace { key, .. }
            | Action::Drift { key, .. }
            | Action::Keep { key, .. }
            | Action::Restate { key, .. }
            | Action::Rename { key, .. }
            | Action::Rebuild { key, .. }
            | Action::Drop { key, .. }
            | Action::Forget { key }
            | Action::Released { key } => key,
        }
    }

    /// The `CREATE` this action intends, where it intends one.
    pub fn create_sql(&self) -> Option<&str> {
        match self {
            Action::Create { create_sql, .. }
            | Action::Adopt { create_sql, .. }
            | Action::Conflict { create_sql, .. }
            | Action::Recreate { create_sql, .. }
            | Action::Replace { create_sql, .. }
            | Action::Drift { create_sql, .. }
            | Action::Keep { create_sql, .. }
            | Action::Restate { create_sql, .. }
            | Action::Rename { create_sql, .. }
            | Action::Rebuild { create_sql, .. } => Some(create_sql),
            Action::Drop { .. } | Action::Forget { .. } | Action::Released { .. } => None,
        }
    }

    /// The key of the live object this action takes over under another name: a renamed object's
    /// key before the rename, whose row (if it has one) goes when the action's own is written.
    pub fn found_as(&self) -> Option<ObjectKey> {
        match self {
            Action::Rename { from, .. } => Some(from.clone()),
            Action::Adopt {
                key,
                renamed_from: Some(from),
                ..
            } => Some(ObjectKey {
                name: from.clone(),
                ..key.clone()
            }),
            _ => None,
        }
    }

    /// The statement that takes the live object out of the way: the drop of an object being
    /// dropped, replaced, or put back after drift. The migration runs every removal before its
    /// own operations, so a drop they depend on has happened (plan 3.3: nothing cascades).
    pub fn removal_sql(&self) -> Option<String> {
        match self {
            Action::Replace { inline: true, .. } | Action::Drift { inline: true, .. } => None,
            Action::Replace { key, .. } | Action::Drift { key, .. }
                if replaced_in_place(key.kind) =>
            {
                None
            }
            Action::Replace { key, .. } | Action::Drift { key, .. } | Action::Drop { key, .. } => {
                Some(drop_for(key))
            }
            // Said in the migration itself, so whoever reads it sees why a key that did not
            // change is dropped.
            Action::Rebuild { key, because, .. } => Some(format!(
                "-- {key} depends on {because}, which this push drops and makes again: \
                 dropped first and made again after it, unchanged\n{}",
                drop_for(key)
            )),
            Action::Create { .. }
            | Action::Adopt { .. }
            | Action::Conflict { .. }
            | Action::Recreate { .. }
            | Action::Keep { .. }
            | Action::Restate { .. }
            | Action::Rename { .. }
            | Action::Forget { .. }
            | Action::Released { .. } => None,
        }
    }

    /// The statements that put the desired object in place. The migration runs every addition
    /// after its own operations, which may create the table or column the object needs.
    pub fn addition_sql(&self) -> Vec<String> {
        let mut out = self.placing_sql();
        out.extend(self.acl_restore_sql());
        out
    }

    /// Who may call a function, put back as recorded after a hand change to it (F14). Its parent
    /// script makes the function again with `CREATE OR REPLACE`, which keeps whatever privileges it
    /// finds, so a grant added by hand would survive the put-back and a revoke the script does not
    /// repeat would stand. Run after everything else, it leaves exactly the recorded callers.
    fn acl_restore_sql(&self) -> Option<String> {
        let Action::Drift {
            key,
            recorded_def,
            live_def,
            ..
        } = self
        else {
            return None;
        };
        if key.kind != ObjectKind::Function {
            return None;
        }
        let recorded = function_acl(recorded_def)?;
        let live = function_acl(live_def)?;
        (recorded != live).then(|| acl_statements(key, recorded, live))
    }

    fn placing_sql(&self) -> Vec<String> {
        match self {
            Action::Create {
                create_sql,
                inline: false,
                ..
            }
            | Action::Recreate {
                create_sql,
                inline: false,
                ..
            }
            | Action::Replace {
                create_sql,
                inline: false,
                ..
            }
            | Action::Drift {
                create_sql,
                inline: false,
                ..
            }
            | Action::Rebuild { create_sql, .. } => vec![create_sql.clone()],
            Action::Adopt {
                key,
                reason,
                comment,
                renamed_from,
                ..
            } => {
                let rename = renamed_from
                    .as_deref()
                    .and_then(|from| rename_sql(key, from, &key.name));
                let unstamp = (*reason == AdoptReason::Stamped).then(|| {
                    key.comment_sql(
                        crate::managed::comment_without_stamp(comment.as_deref()).as_deref(),
                    )
                });
                rename.into_iter().chain(unstamp.flatten()).collect()
            }
            Action::Rename { key, from, .. } => {
                rename_sql(key, &from.name, &key.name).into_iter().collect()
            }
            Action::Create { inline: true, .. }
            | Action::Recreate { inline: true, .. }
            | Action::Replace { inline: true, .. }
            | Action::Drift { inline: true, .. }
            | Action::Conflict { .. }
            | Action::Drop { .. }
            | Action::Keep { .. }
            | Action::Restate { .. }
            | Action::Forget { .. }
            | Action::Released { .. } => Vec::new(),
        }
    }

    /// Every statement this action runs, removal then addition. Empty for the bookkeeping-only
    /// actions.
    pub fn sql(&self) -> Vec<String> {
        let mut statements: Vec<String> = self.removal_sql().into_iter().collect();
        statements.extend(self.addition_sql());
        statements
    }

    /// Whether the removal runs after the migration's operations rather than before. A function's
    /// does, because the trigger that depends on it may sit on a table the operations drop and
    /// goes with the table; unless the function's own identity names the row type of a table
    /// being dropped or renamed (an affordance function takes its table), in which case the
    /// function must go first: or the table cannot, or the drop no longer finds it by that name.
    pub fn removal_is_late(&self, dropped_tables: &[String]) -> bool {
        let key = self.key();
        key.kind == ObjectKind::Function
            && !dropped_tables.iter().any(|table| {
                key.name.contains(&format!(".{table})")) || key.name.contains(&format!(".{table},"))
            })
    }

    /// Undoes the addition: drops what this action created. An inline `Create` has one too; its
    /// parent's rollback covers it, and the explicit drop is `IF EXISTS`. A replacement in place
    /// is undone by the previous definition alone ([`Action::undo_removal`]). Row-level security
    /// is never turned off, by a rollback either (D9). Taking over a stamped object is undone by
    /// putting its comment back, stamp and all: the rollback removes the row, and without the
    /// stamp the object would read as someone else's and the next push would refuse it. One taken
    /// over under another name gets that name back first, and its comment under it.
    pub fn undo_addition(&self) -> Option<String> {
        match self {
            Action::Adopt {
                key,
                reason: AdoptReason::Stamped,
                comment,
                renamed_from,
                ..
            } => match renamed_from {
                Some(from) => {
                    let old = ObjectKey {
                        name: from.clone(),
                        ..key.clone()
                    };
                    let rename = rename_sql(key, &key.name, from);
                    let comment = old.comment_sql(comment.as_deref());
                    let both: Vec<String> = rename.into_iter().chain(comment).collect();
                    (!both.is_empty()).then(|| both.join("\n"))
                }
                None => key.comment_sql(comment.as_deref()),
            },
            // Its old name back, on the table under its new name: the operations' rollback, which
            // renames the table back, runs after this.
            Action::Rename { key, from, .. } => rename_sql(key, &key.name, &from.name),
            action if never_removed(action.key().kind) => None,
            // The differ's rollback undoes what the differ did.
            action if altered_by_the_differ(action.key().kind) => None,
            Action::Replace { key, .. } | Action::Drift { key, .. }
                if replaced_in_place(key.kind) =>
            {
                None
            }
            Action::Create { key, .. }
            | Action::Recreate { key, .. }
            | Action::Replace { key, .. }
            | Action::Drift { key, .. }
            | Action::Rebuild { key, .. } => Some(drop_for(key)),
            // An adoption under another name is undone by giving the object its name back.
            Action::Adopt {
                key,
                renamed_from: Some(from),
                ..
            } => rename_sql(key, &key.name, from),
            Action::Adopt { .. }
            | Action::Conflict { .. }
            | Action::Keep { .. }
            | Action::Restate { .. }
            | Action::Drop { .. }
            | Action::Forget { .. }
            | Action::Released { .. } => None,
        }
    }

    /// Undoes the removal: re-creates what this action dropped. Rolling back a drift replacement
    /// restores Supatype's previous definition, which is this same `CREATE`; the hand edit is not
    /// recoverable (plan 3.5). `None` for a drop with no definition to restore.
    pub fn undo_removal(&self) -> Option<String> {
        match self {
            action if altered_by_the_differ(action.key().kind) => None,
            action if never_removed(action.key().kind) => None,
            Action::Replace { previous_sql, .. } => Some(previous_sql.clone()),
            Action::Drift { create_sql, .. } | Action::Rebuild { create_sql, .. } => {
                Some(create_sql.clone())
            }
            Action::Drop { recorded_sql, .. } => recorded_sql.clone(),
            Action::Create { .. }
            | Action::Adopt { .. }
            | Action::Conflict { .. }
            | Action::Recreate { .. }
            | Action::Keep { .. }
            | Action::Restate { .. }
            | Action::Rename { .. }
            | Action::Forget { .. }
            | Action::Released { .. } => None,
        }
    }

    /// Every statement that undoes this action, in order, for the migration's `sql_down`.
    pub fn rollback_sql(&self) -> Vec<String> {
        self.undo_addition()
            .into_iter()
            .chain(self.undo_removal())
            .collect()
    }

    /// Whether the action changes the database or the ledger. A restatement only rewrites a row's
    /// wording, which an up-to-date push records without a migration.
    pub fn is_change(&self) -> bool {
        !matches!(
            self,
            Action::Keep { .. } | Action::Restate { .. } | Action::Released { .. }
        )
    }

    pub fn row_after(&self) -> RowAfter<'_> {
        match self {
            Action::Create {
                create_sql, status, ..
            }
            | Action::Adopt {
                create_sql, status, ..
            }
            | Action::Recreate {
                create_sql, status, ..
            }
            | Action::Replace {
                create_sql, status, ..
            }
            | Action::Drift {
                create_sql, status, ..
            }
            | Action::Keep {
                create_sql, status, ..
            }
            | Action::Restate {
                create_sql, status, ..
            }
            | Action::Rename {
                create_sql, status, ..
            }
            | Action::Rebuild {
                create_sql,
                status: Some(status),
                ..
            } => RowAfter::Write {
                create_sql,
                status: *status,
            },
            Action::Drop { .. } | Action::Forget { .. } => RowAfter::Remove,
            Action::Conflict { .. }
            | Action::Released { .. }
            | Action::Rebuild { status: None, .. } => RowAfter::Leave,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    /// Forgets and drops first (dependents before what they depend on), then replacements,
    /// re-creations and creations (dependencies first), each group in key order within a kind.
    pub actions: Vec<Action>,
}

impl Plan {
    pub fn conflicts(&self) -> impl Iterator<Item = &Action> {
        self.actions
            .iter()
            .filter(|a| matches!(a, Action::Conflict { .. }))
    }

    pub fn has_changes(&self) -> bool {
        self.actions.iter().any(Action::is_change)
    }

    /// The second pass of section 7.2 for expression kinds: the caller has proved, with the
    /// database, that the live objects under `proven` deparse to what we would create. Those
    /// conflicts become adoptions; every other conflict stands.
    pub fn adopt_equivalent(&mut self, proven: &BTreeSet<ObjectKey>) {
        for action in &mut self.actions {
            if let Action::Conflict {
                key, create_sql, ..
            } = action
            {
                if proven.contains(key) {
                    *action = Action::Adopt {
                        key: key.clone(),
                        reason: AdoptReason::DeparsesEqual,
                        create_sql: std::mem::take(create_sql),
                        comment: None,
                        renamed_from: None,
                        status: Status::Adopted,
                    };
                }
            }
        }
    }
}

/// `label=value` lines back into a map, the inverse of `fingerprint::render_definition`.
pub fn parse_definition(def: &str) -> BTreeMap<&str, &str> {
    def.lines()
        .filter_map(|line| line.split_once('='))
        .collect()
}

/// D2: every structural part the desired object predicts equals the live part. A kind whose
/// structure is empty (an expression-only kind such as a check) is never matched this way.
fn structure_matches(desired: &DesiredObject, live: &ObjectFingerprint) -> bool {
    if desired.structure.is_empty() {
        return false;
    }
    let parts = parse_definition(&live.definition);
    desired
        .structure
        .iter()
        .all(|(label, want)| parts.get(*label) == Some(&want.as_str()))
}

/// The statement that renames the object `on` names from `from` to `to`, on its table as the
/// table is named when the statement runs. `None` when the names are the same, or for a kind with
/// no rename.
fn rename_sql(on: &ObjectKey, from: &str, to: &str) -> Option<String> {
    if from == to {
        return None;
    }
    ObjectKey {
        name: from.to_string(),
        ..on.clone()
    }
    .rename_sql(to)
}

fn drop_for(key: &ObjectKey) -> String {
    key.drop_sql()
        .unwrap_or_else(|| panic!("{key} is on the reconcile with no drop statement"))
}

/// Whether a same-named live object whose structure matches may be adopted on that alone (D2). Not
/// a view: the one part a view's statement predicts is that it is not materialized, which says
/// nothing about what it shows, so a user's view under our name is theirs until `adopt`.
fn adopted_on_structure(kind: ObjectKind) -> bool {
    kind != ObjectKind::View
}

/// A desired object found live with no ledger row (section 7). Ours when its name says so (a
/// policy), its stamp says so, or its location says so; adopted when its structure is exactly what
/// we would create; otherwise a conflict the push refuses. What is ours but made differently is
/// replaced, with its live definition kept for the rollback.
fn claim(inputs: &Inputs<'_>, key: ObjectKey, d: &DesiredObject, l: &ObjectFingerprint) -> Action {
    let ours_by_location =
        (inputs.location)(&key) != Location::Neutral || inputs.named_by_the_engine.contains(&key);
    let replace = |previous_sql: &str| Action::Replace {
        inline: inputs.created_by_parent.contains(&key) && remade_by_its_parent(key.kind),
        key: key.clone(),
        create_sql: d.create_sql.clone(),
        previous_sql: previous_sql.to_string(),
        status: Status::Managed,
        drifted: None,
    };
    let adopt = |reason, status| Action::Adopt {
        key: key.clone(),
        reason,
        create_sql: d.create_sql.clone(),
        comment: l.comment.clone(),
        renamed_from: None,
        status,
    };
    let conflict = || Action::Conflict {
        key: key.clone(),
        create_sql: d.create_sql.clone(),
        live_def: l.definition.clone(),
    };
    if adopted_by_declaring(key.kind) {
        return adopt(AdoptReason::Declared, Status::Managed);
    }
    if claimed_by_name(key.kind) {
        return replace(l.create_sql.as_deref().unwrap_or_default());
    }
    if l.stamped() {
        return adopt(AdoptReason::Stamped, Status::Managed);
    }
    // A table is never replaced: only its differ touches it, and only once it is ours.
    if altered_by_the_differ(key.kind) {
        return if ours_by_location {
            adopt(AdoptReason::OwnedSchema, Status::Managed)
        } else {
            conflict()
        };
    }
    if structure_matches(d, l) && (ours_by_location || adopted_on_structure(key.kind)) {
        return if ours_by_location {
            adopt(AdoptReason::OwnedSchema, Status::Managed)
        } else {
            adopt(AdoptReason::StructureMatches, Status::Adopted)
        };
    }
    match l.create_sql.as_deref() {
        Some(previous_sql) if ours_by_location => replace(previous_sql),
        _ => conflict(),
    }
}

/// The `acl` part of a function's definition: who may call it. `None` for a row an older engine
/// recorded before it was part of the fingerprint.
fn function_acl(definition: &str) -> Option<&str> {
    definition.lines().find_map(|l| l.strip_prefix("acl="))
}

/// Whether a function's callers changed since it was recorded, which decides access: an RPC
/// function an API role may call is part of the API (F14).
fn acl_changed(row: &LedgerRow, live: &ObjectFingerprint) -> bool {
    row.key.kind == ObjectKind::Function
        && matches!(
            (function_acl(&row.live_def), function_acl(&live.definition)),
            (Some(recorded), Some(now)) if recorded != now
        )
}

/// The roles an `acl` part names (`grantee=PRIVILEGE,...`).
fn acl_grantees(acl: &str) -> BTreeSet<&str> {
    acl.split(',')
        .filter_map(|entry| entry.rsplit_once('=').map(|(grantee, _)| grantee))
        .filter(|grantee| !grantee.is_empty())
        .collect()
}

/// Takes `EXECUTE` from every role the live `acl` names, and from `PUBLIC`, then gives it to exactly
/// the roles the recorded one names.
fn acl_statements(key: &ObjectKey, recorded: &str, live: &str) -> String {
    let (name, arguments) = key.name.split_once('(').unwrap_or((&key.name, ")"));
    let signature = format!("{}({arguments}", quote_qualified(&key.schema, name));
    let role = |grantee: &str| {
        if grantee == "PUBLIC" {
            "PUBLIC".to_string()
        } else {
            quote_ident(grantee)
        }
    };
    let mut revoked = acl_grantees(live);
    revoked.insert("PUBLIC");
    let revokes = revoked
        .into_iter()
        .map(|g| format!("REVOKE ALL ON FUNCTION {signature} FROM {};", role(g)));
    let grants = acl_grantees(recorded)
        .into_iter()
        .map(|g| format!("GRANT EXECUTE ON FUNCTION {signature} TO {};", role(g)));
    revokes.chain(grants).collect::<Vec<_>>().join("\n")
}

/// The labelled parts of a definition (`label=value` per line, as the fingerprint writes them), or
/// `None` when a line carries no label of `kind`'s.
fn labelled_parts(kind: ObjectKind, definition: &str) -> Option<BTreeMap<&str, &str>> {
    let labels = kind.labels();
    definition
        .lines()
        .map(|line| {
            let (label, value) = line.split_once('=')?;
            labels.contains(&label).then_some((label, value))
        })
        .collect()
}

/// Whether `live` was changed since the ledger recorded it.
///
/// A part the recorded definition does not carry was not fingerprinted when it was recorded: an
/// older engine wrote the row before that part entered the fingerprint (a view's options and owner,
/// say). Such a row is compared on the parts it does carry, so an upgrade is not taken for a hand
/// edit on every object of the kind; the push then records the whole fingerprint.
fn changed_since_recorded(row: &LedgerRow, live: &ObjectFingerprint) -> bool {
    if live.fingerprint == row.live_fp {
        return false;
    }
    let (Some(recorded), Some(now)) = (
        labelled_parts(row.key.kind, &row.live_def),
        labelled_parts(row.key.kind, &live.definition),
    ) else {
        return true;
    };
    let older = recorded.len() < now.len() && recorded.keys().all(|l| now.contains_key(l));
    !older
        || recorded
            .iter()
            .any(|(label, value)| now.get(label) != Some(value))
}

/// The reconcile's three sides, for the kinds it owns, each keyed the same way.
struct Sides<'a> {
    desired: BTreeMap<&'a ObjectKey, &'a DesiredObject>,
    ledger: BTreeMap<&'a ObjectKey, &'a LedgerRow>,
    live: BTreeMap<ObjectKey, &'a ObjectFingerprint>,
}

impl<'a> Sides<'a> {
    fn of(inputs: &Inputs<'a>) -> Sides<'a> {
        let kinds: BTreeSet<ObjectKind> = inputs.kinds.iter().copied().collect();
        Sides {
            desired: inputs
                .desired
                .iter()
                .filter(|d| kinds.contains(&d.key.kind))
                .map(|d| (&d.key, d))
                .collect(),
            ledger: inputs
                .ledger
                .iter()
                .filter(|r| kinds.contains(&r.key.kind))
                .map(|r| (&r.key, r))
                .collect(),
            live: inputs
                .live
                .iter()
                .filter(|f| kinds.contains(&f.kind))
                .map(|f| (f.key(), f))
                .collect(),
        }
    }
}

/// Whether `key` is on a table this push drops, and so goes with it.
fn goes_with_its_table(inputs: &Inputs<'_>, key: &ObjectKey) -> bool {
    inputs.dropped_tables.contains(&ObjectKey {
        kind: ObjectKind::Table,
        schema: key.schema.clone(),
        parent: String::new(),
        name: key.parent.clone(),
    })
}

/// What a push does about an object the ledger records (plan 3.3).
fn recorded(
    inputs: &Inputs<'_>,
    row: &LedgerRow,
    d: Option<&DesiredObject>,
    l: Option<&ObjectFingerprint>,
) -> Action {
    let key = row.key.clone();
    let status = row.status;
    if status == Status::Released {
        return Action::Released { key };
    }
    match (d, l) {
        (Some(d), None) => Action::Recreate {
            inline: inputs.created_by_parent.contains(&key) || altered_by_the_differ(key.kind),
            key,
            create_sql: d.create_sql.clone(),
            status,
        },
        (Some(d), Some(l)) => recorded_and_present(inputs, row, d, l),
        // A column adopted while the schema does not declare it stays recorded as long as it
        // is there: the push keeps it, and a narrowed write grant includes it (#63).
        (None, Some(_))
            if key.kind == ObjectKind::Column
                && status == Status::Adopted
                && !goes_with_its_table(inputs, &key) =>
        {
            Action::Keep {
                key,
                create_sql: row.desired_sql.clone(),
                status,
            }
        }
        // Never removed (D9): a row nothing desires any more is forgotten, not undone.
        (None, Some(_))
            if !goes_with_its_table(inputs, &key)
                && !never_removed(key.kind)
                && !altered_by_the_differ(key.kind) =>
        {
            Action::Drop {
                key,
                recorded_sql: Some(row.desired_sql.clone()),
            }
        }
        (None, _) => Action::Forget { key },
    }
}

/// An object the ledger records that the schema asks for and the catalog holds: kept, restated,
/// put back after drift, or replaced.
fn recorded_and_present(
    inputs: &Inputs<'_>,
    row: &LedgerRow,
    d: &DesiredObject,
    l: &ObjectFingerprint,
) -> Action {
    let key = row.key.clone();
    let status = row.status;
    let create_sql = d.create_sql.clone();
    let inline = (inputs.created_by_parent.contains(&key) || altered_by_the_differ(key.kind))
        && remade_by_its_parent(key.kind);
    // Compared on the parts the row carries, so a row an older engine wrote before a part entered
    // the fingerprint is neither drift nor a reason to refuse a restatement.
    let unchanged = !changed_since_recorded(row, l);
    if row.intends(&d.create_sql) {
        if unchanged {
            return Action::Keep {
                key,
                create_sql,
                status,
            };
        }
        return Action::Drift {
            key,
            recorded_def: row.live_def.clone(),
            live_def: l.definition.clone(),
            live_fp: l.fingerprint.clone(),
            create_sql,
            security_relevant: d.security_relevant || acl_changed(row, l),
            inline,
            status,
        };
    }
    if unchanged && restated(inputs, d, l) {
        return Action::Restate {
            key,
            create_sql,
            previous_sql: row.desired_sql.clone(),
            status,
        };
    }
    // Decided before drift, since the schema changed too; but a hand edit it would overwrite is
    // still one, and must not escape the consent drift needs.
    let drifted = (!unchanged).then(|| HandEdit {
        recorded_def: row.live_def.clone(),
        live_def: l.definition.clone(),
        live_fp: l.fingerprint.clone(),
    });
    Action::Replace {
        key,
        create_sql,
        previous_sql: row.desired_sql.clone(),
        inline,
        status,
        drifted,
    }
}

/// F2(c): a replacement is decided on structure, not on the wording of the `CREATE`. A key or
/// index whose structure says everything a statement can set about it, and that is already shaped
/// as this push wants it, needs no statement however differently this engine words its `CREATE`
/// (an upgrade whose template moved a space): only its row is rewritten. The catch-all
/// `definition` part is the catalog's own rendering, which no statement is compared with.
fn restated(inputs: &Inputs<'_>, d: &DesiredObject, l: &ObjectFingerprint) -> bool {
    let kind = d.key.kind;
    matches!(
        kind,
        ObjectKind::PrimaryKey | ObjectKind::Unique | ObjectKind::ForeignKey | ObjectKind::Index
    ) && kind
        .labels()
        .iter()
        .all(|label| *label == "definition" || d.structure.contains_key(label))
        && matching::structure_matches_renamed(d, l, inputs.renamed_tables)
}

/// The desired objects no row records: created, claimed (section 7), or found under a name of
/// their own. Returns the live keys found that way, which nothing may then drop as undeclared.
fn unrecorded(
    inputs: &Inputs<'_>,
    sides: &Sides<'_>,
    moved_to: &BTreeSet<ObjectKey>,
    changes: &mut Vec<Action>,
) -> BTreeSet<ObjectKey> {
    let mut found = BTreeSet::new();
    for (&key, d) in &sides.desired {
        if sides.ledger.contains_key(key) || moved_to.contains(key) {
            continue;
        }
        let action =
            match sides.live.get(key) {
                Some(l) => claim(inputs, key.clone(), d, l),
                None => matching::under_another_name(inputs, sides, d, &mut found).unwrap_or_else(
                    || Action::Create {
                        inline: inputs.created_by_parent.contains(key)
                            || altered_by_the_differ(key.kind),
                        key: key.clone(),
                        create_sql: d.create_sql.clone(),
                        status: Status::Managed,
                    },
                ),
            };
        changes.push(action);
    }
    found
}

/// Objects of a moved kind that nothing declares any more and that are ours by their own record
/// (an older engine's stamp, section 7, last paragraph) or by where they live (section 5): they
/// are dropped, as the stamp-reading differs and the sweeps dropped them. The live definition,
/// where the catalog renders one, is what a rollback restores.
fn undeclared(inputs: &Inputs<'_>, sides: &Sides<'_>, found: &BTreeSet<ObjectKey>) -> Vec<Action> {
    sides
        .live
        .iter()
        .filter(|(key, l)| {
            (l.stamped()
                || (inputs.location)(key) == Location::Exclusive
                || inputs.named_by_the_engine.contains(*key))
                && !sides.ledger.contains_key(*key)
                && !sides.desired.contains_key(*key)
                && !found.contains(*key)
                && !goes_with_its_table(inputs, key)
                // A stamped table nothing declares is the table differ's to drop, behind its gate.
                && !altered_by_the_differ(key.kind)
        })
        .map(|(key, l)| Action::Drop {
            key: key.clone(),
            recorded_sql: l.create_sql.clone(),
        })
        .collect()
}

pub fn reconcile(inputs: Inputs<'_>) -> Plan {
    let sides = Sides::of(&inputs);
    let moved = matching::moved_with_their_tables(&inputs, &sides);

    let mut removals = Vec::new();
    let mut changes = Vec::new();
    for (&key, row) in &sides.ledger {
        if moved.from.contains(key) {
            continue;
        }
        let action = recorded(
            &inputs,
            row,
            sides.desired.get(key).copied(),
            sides.live.get(key).copied(),
        );
        match action {
            Action::Drop { .. } | Action::Forget { .. } => removals.push(action),
            _ => changes.push(action),
        }
    }
    changes.extend(moved.actions);
    let found = unrecorded(&inputs, &sides, &moved.to, &mut changes);
    removals.extend(undeclared(&inputs, &sides, &found));
    rebuild::dependents(&inputs, &sides, &removals, &mut changes);

    // Dependencies first for the changes, dependents first for the removals, then key order.
    removals.sort_by_key(|a| (Reverse(creation_rank(a.key().kind)), a.key().clone()));
    changes.sort_by_key(|a| (creation_rank(a.key().kind), a.key().clone()));
    removals.extend(changes);
    Plan { actions: removals }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::introspector::fingerprint::hash;
    use crate::ledger::desired_fingerprint;

    fn key(name: &str) -> ObjectKey {
        ObjectKey {
            kind: ObjectKind::Check,
            schema: "public".into(),
            parent: "posts".into(),
            name: name.into(),
        }
    }

    fn desired(name: &str, expr: &str) -> DesiredObject {
        DesiredObject {
            key: key(name),
            structure: BTreeMap::new(),
            create_sql: format!(
                "ALTER TABLE \"public\".\"posts\" ADD CONSTRAINT \"{name}\" CHECK ({expr});"
            ),
            drop_sql: key(name).drop_sql().unwrap(),
            depends_on: Vec::new(),
            security_relevant: false,
        }
    }

    fn live(name: &str, expr: &str) -> ObjectFingerprint {
        let def = format!("expression=CHECK (({expr}))");
        ObjectFingerprint {
            kind: ObjectKind::Check,
            schema: "public".into(),
            parent: "posts".into(),
            name: name.into(),
            fingerprint: hash(ObjectKind::Check, &[&format!("CHECK (({expr}))")]),
            definition: def,
            comment: None,
            create_sql: None,
        }
    }

    fn stamped(mut l: ObjectFingerprint) -> ObjectFingerprint {
        l.comment = Some("supatype:managed;kind=check;table=posts;fields=title;v=1".into());
        l
    }

    fn row(d: &DesiredObject, l: &ObjectFingerprint, status: Status) -> LedgerRow {
        LedgerRow {
            key: d.key.clone(),
            desired_fp: desired_fingerprint(d.key.kind, &d.create_sql),
            desired_sql: d.create_sql.clone(),
            live_fp: l.fingerprint.clone(),
            live_def: l.definition.clone(),
            status,
            migration_id: None,
        }
    }

    fn run(
        desired: &[DesiredObject],
        ledger: &[LedgerRow],
        live: &[ObjectFingerprint],
        created_by_parent: &[ObjectKey],
    ) -> Vec<Action> {
        reconcile(Inputs {
            desired,
            ledger,
            live,
            created_by_parent: &created_by_parent.iter().cloned().collect(),
            dropped_tables: &BTreeSet::new(),
            location: no_location,
            named_by_the_engine: &BTreeSet::new(),
            renamed_tables: &BTreeMap::new(),
            kinds: &[ObjectKind::Check],
        })
        .actions
    }

    fn drop(name: &str) -> String {
        key(name).drop_sql().unwrap()
    }

    #[test]
    fn no_row_desired_absent_is_a_create_with_sql_unless_the_parent_creates_it() {
        let d = desired("posts_title_check", "length(title) > 0");
        let actions = run(std::slice::from_ref(&d), &[], &[], &[]);
        assert!(
            matches!(&actions[..], [Action::Create { inline: false, create_sql, .. }] if *create_sql == d.create_sql),
            "{actions:?}"
        );
        assert_eq!(actions[0].sql(), std::slice::from_ref(&d.create_sql));
        assert_eq!(
            actions[0].row_after(),
            RowAfter::Write {
                create_sql: &d.create_sql,
                status: Status::Managed
            }
        );

        let inline = run(
            std::slice::from_ref(&d),
            &[],
            &[],
            std::slice::from_ref(&d.key),
        );
        assert!(
            matches!(&inline[..], [Action::Create { inline: true, .. }]),
            "{inline:?}"
        );
        assert!(
            inline[0].sql().is_empty(),
            "the parent statement creates it"
        );
        assert_eq!(inline[0].rollback_sql(), [drop("posts_title_check")]);
    }

    #[test]
    fn no_row_and_a_same_named_live_object_is_adopted_only_when_stamped_or_proven_equivalent() {
        let d = desired("posts_title_check", "length(title) > 0");
        let l = live("posts_title_check", "length(title) > 0");

        let unproven = run(std::slice::from_ref(&d), &[], std::slice::from_ref(&l), &[]);
        assert!(
            matches!(&unproven[..], [Action::Conflict { key, live_def, .. }] if *key == d.key && *live_def == l.definition),
            "{unproven:?}"
        );
        assert_eq!(unproven[0].row_after(), RowAfter::Leave);

        let with_stamp = run(std::slice::from_ref(&d), &[], &[stamped(l.clone())], &[]);
        match &with_stamp[..] {
            [Action::Adopt {
                reason: AdoptReason::Stamped,
                comment,
                status,
                ..
            }] => {
                assert!(comment.is_some());
                assert_eq!(*status, Status::Managed, "stamped means ours by record");
                // Adopting a stamped object takes the stamp out of its comment, in the same push.
                assert_eq!(
                    with_stamp[0].sql(),
                    ["COMMENT ON CONSTRAINT \"posts_title_check\" ON \"public\".\"posts\" IS NULL;"]
                );
                // And a rollback puts the stamp back, so the object is still recognisably ours.
                let rollback = with_stamp[0].rollback_sql();
                assert_eq!(rollback.len(), 1, "{rollback:?}");
                assert!(
                    rollback[0].contains("'supatype:managed;kind=check"),
                    "{rollback:?}"
                );
            }
            other => panic!("{other:?}"),
        }

        let mut plan = Plan { actions: unproven };
        plan.adopt_equivalent(&[d.key.clone()].into_iter().collect());
        match &plan.actions[..] {
            [Action::Adopt {
                reason: AdoptReason::DeparsesEqual,
                create_sql,
                status,
                ..
            }] => {
                assert_eq!(*create_sql, d.create_sql);
                assert_eq!(*status, Status::Adopted);
                assert!(plan.actions[0].sql().is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_structural_kind_is_adopted_on_an_exact_part_match_and_refused_otherwise() {
        let mut d = desired("posts_slug_key", "");
        d.key.kind = ObjectKind::Unique;
        d.structure.insert("columns", "slug".into());
        let mut l = live("posts_slug_key", "");
        l.kind = ObjectKind::Unique;
        l.definition = "columns=slug".into();
        let kinds = [ObjectKind::Unique];
        let none = BTreeSet::new();
        let plan = reconcile(Inputs {
            desired: std::slice::from_ref(&d),
            ledger: &[],
            live: std::slice::from_ref(&l),
            created_by_parent: &none,
            dropped_tables: &none,
            location: no_location,
            named_by_the_engine: &none,
            renamed_tables: &BTreeMap::new(),
            kinds: &kinds,
        });
        assert!(
            matches!(
                &plan.actions[..],
                [Action::Adopt {
                    reason: AdoptReason::StructureMatches,
                    status: Status::Adopted,
                    ..
                }]
            ),
            "{plan:?}"
        );

        l.definition = "columns=slug,locale".into();
        let plan = reconcile(Inputs {
            desired: std::slice::from_ref(&d),
            ledger: &[],
            live: std::slice::from_ref(&l),
            created_by_parent: &none,
            dropped_tables: &none,
            location: no_location,
            named_by_the_engine: &none,
            renamed_tables: &BTreeMap::new(),
            kinds: &kinds,
        });
        assert!(
            matches!(&plan.actions[..], [Action::Conflict { .. }]),
            "{plan:?}"
        );
    }

    #[test]
    fn an_owned_object_is_kept_replaced_drifted_or_recreated() {
        let d = desired("posts_title_check", "length(title) > 0");
        let l = live("posts_title_check", "length(title) > 0");
        let r = row(&d, &l, Status::Adopted);

        let kept = run(
            std::slice::from_ref(&d),
            std::slice::from_ref(&r),
            std::slice::from_ref(&l),
            &[],
        );
        assert!(
            matches!(
                &kept[..],
                [Action::Keep {
                    status: Status::Adopted,
                    ..
                }]
            ),
            "{kept:?}"
        );
        assert!(!Plan { actions: kept }.has_changes());

        let tightened = desired("posts_title_check", "length(title) > 3");
        let replaced = run(
            std::slice::from_ref(&tightened),
            std::slice::from_ref(&r),
            std::slice::from_ref(&l),
            &[],
        );
        match &replaced[..] {
            [Action::Replace {
                previous_sql,
                create_sql,
                status,
                ..
            }] => {
                assert_eq!(*previous_sql, d.create_sql);
                assert_eq!(*create_sql, tightened.create_sql);
                assert_eq!(
                    *status,
                    Status::Adopted,
                    "a replacement keeps the row's status"
                );
                assert_eq!(
                    replaced[0].sql(),
                    [drop("posts_title_check"), tightened.create_sql.clone()]
                );
                assert_eq!(
                    replaced[0].rollback_sql(),
                    [drop("posts_title_check"), d.create_sql.clone()]
                );
            }
            other => panic!("{other:?}"),
        }

        let edited = live("posts_title_check", "length(title) > 1");
        let drifted = run(
            std::slice::from_ref(&d),
            std::slice::from_ref(&r),
            std::slice::from_ref(&edited),
            &[],
        );
        assert!(
            matches!(&drifted[..], [Action::Drift { recorded_def, live_def, .. }]
                if *recorded_def == l.definition && *live_def == edited.definition),
            "{drifted:?}"
        );

        let recreated = run(std::slice::from_ref(&d), std::slice::from_ref(&r), &[], &[]);
        assert!(
            matches!(&recreated[..], [Action::Recreate { create_sql, .. }] if *create_sql == d.create_sql),
            "{recreated:?}"
        );
    }

    #[test]
    fn an_owned_object_the_schema_dropped_is_dropped_or_forgotten_and_a_released_one_is_left() {
        let d = desired("posts_title_check", "length(title) > 0");
        let l = live("posts_title_check", "length(title) > 0");
        let r = row(&d, &l, Status::Managed);

        let dropped = run(&[], std::slice::from_ref(&r), std::slice::from_ref(&l), &[]);
        match &dropped[..] {
            [Action::Drop { recorded_sql, .. }] => {
                assert_eq!(dropped[0].sql(), [drop("posts_title_check")]);
                assert_eq!(recorded_sql.as_deref(), Some(d.create_sql.as_str()));
                assert_eq!(
                    dropped[0].rollback_sql(),
                    std::slice::from_ref(&d.create_sql)
                );
                assert_eq!(dropped[0].row_after(), RowAfter::Remove);
            }
            other => panic!("{other:?}"),
        }

        let forgotten = run(&[], std::slice::from_ref(&r), &[], &[]);
        assert_eq!(forgotten, [Action::Forget { key: d.key.clone() }]);

        let released = row(&d, &l, Status::Released);
        let tightened = desired("posts_title_check", "length(title) > 3");
        let left = run(
            std::slice::from_ref(&tightened),
            std::slice::from_ref(&released),
            std::slice::from_ref(&l),
            &[],
        );
        assert_eq!(left, [Action::Released { key: d.key.clone() }]);
        assert_eq!(left[0].row_after(), RowAfter::Leave);
    }

    #[test]
    fn a_stamped_object_nothing_declares_is_dropped_and_a_user_object_is_never_touched() {
        let l = live("posts_old_check", "true");
        let with_stamp = run(&[], &[], &[stamped(l.clone())], &[]);
        assert!(
            matches!(
                &with_stamp[..],
                [Action::Drop {
                    recorded_sql: None,
                    ..
                }]
            ),
            "{with_stamp:?}"
        );
        assert!(with_stamp[0].rollback_sql().is_empty());

        let user = run(&[], &[], std::slice::from_ref(&l), &[]);
        assert!(user.is_empty(), "{user:?}");
    }

    #[test]
    fn kinds_not_on_the_reconcile_are_ignored_and_removals_come_first() {
        let d = desired("posts_title_check", "length(title) > 0");
        let mut other = desired("posts_slug_key", "");
        other.key.kind = ObjectKind::Unique;
        let stale = live("posts_old_check", "true");
        let stale_row = LedgerRow {
            key: stale.key(),
            desired_fp: "x".into(),
            desired_sql: "x".into(),
            live_fp: stale.fingerprint.clone(),
            live_def: stale.definition.clone(),
            status: Status::Managed,
            migration_id: None,
        };
        let actions = run(
            &[d.clone(), other],
            std::slice::from_ref(&stale_row),
            std::slice::from_ref(&stale),
            &[],
        );
        assert!(
            matches!(&actions[..], [Action::Drop { .. }, Action::Create { .. }]),
            "{actions:?}"
        );
        assert!(actions.iter().all(|a| a.key().kind == ObjectKind::Check));
    }

    #[test]
    fn an_owned_object_on_a_table_the_push_drops_goes_with_it() {
        let d = desired("posts_title_check", "length(title) > 0");
        let l = live("posts_title_check", "length(title) > 0");
        let r = row(&d, &l, Status::Managed);
        let table = ObjectKey {
            kind: ObjectKind::Table,
            schema: "public".into(),
            parent: String::new(),
            name: "posts".into(),
        };
        let dropped: BTreeSet<ObjectKey> = [table].into_iter().collect();
        let none = BTreeSet::new();
        let plan = reconcile(Inputs {
            desired: &[],
            ledger: std::slice::from_ref(&r),
            live: &[stamped(l.clone())],
            created_by_parent: &none,
            dropped_tables: &dropped,
            location: no_location,
            named_by_the_engine: &none,
            renamed_tables: &BTreeMap::new(),
            kinds: &[ObjectKind::Check],
        });
        // The row goes; no `ALTER TABLE` is emitted against a table that will not be there.
        assert_eq!(plan.actions, [Action::Forget { key: d.key.clone() }]);
        assert!(plan.actions.iter().all(|a| a.sql().is_empty()));
    }

    #[test]
    fn rls_enablement_nothing_desires_is_forgotten_never_turned_off() {
        let key = ObjectKey {
            kind: ObjectKind::RlsAttributes,
            schema: "public".into(),
            parent: "posts".into(),
            name: "rls".into(),
        };
        let live = ObjectFingerprint {
            kind: key.kind,
            schema: key.schema.clone(),
            parent: key.parent.clone(),
            name: key.name.clone(),
            fingerprint: hash(ObjectKind::RlsAttributes, &["t"]),
            definition: "enabled=t".into(),
            comment: None,
            create_sql: None,
        };
        let row = LedgerRow {
            key: key.clone(),
            desired_fp: "fp".into(),
            desired_sql: "ALTER TABLE \"public\".\"posts\" ENABLE ROW LEVEL SECURITY;".into(),
            live_fp: live.fingerprint.clone(),
            live_def: live.definition.clone(),
            status: Status::Managed,
            migration_id: None,
        };
        let plan = reconcile(Inputs {
            desired: &[],
            ledger: &[row],
            live: &[live],
            created_by_parent: &BTreeSet::new(),
            dropped_tables: &BTreeSet::new(),
            location: no_location,
            named_by_the_engine: &BTreeSet::new(),
            renamed_tables: &BTreeMap::new(),
            kinds: &[ObjectKind::RlsAttributes],
        });
        assert_eq!(plan.actions, [Action::Forget { key }]);
        assert!(plan.actions.iter().all(|a| a.sql().is_empty()));
    }

    /// The versions layer makes its index `IF NOT EXISTS`, so an inline replacement would run
    /// nothing while the row recorded the hand-edited index as ours: an index is dropped and made
    /// again instead. A function, which its parent's `CREATE OR REPLACE` remakes, stays inline.
    #[test]
    fn an_index_its_parent_creates_is_still_dropped_and_made_again_when_it_changes() {
        let mut d = desired("preview_links_live_for_record", "");
        d.key = ObjectKey {
            kind: ObjectKind::Index,
            schema: "_supatype".into(),
            parent: "preview_links".into(),
            name: "preview_links_live_for_record".into(),
        };
        d.create_sql = "CREATE INDEX IF NOT EXISTS \"preview_links_live_for_record\" ON _supatype.preview_links (\"model\");".into();
        d.drop_sql = d.key.drop_sql().unwrap();
        let mut l = live("preview_links_live_for_record", "");
        l.kind = ObjectKind::Index;
        l.schema = "_supatype".into();
        l.parent = "preview_links".into();
        l.definition = "columns=model".into();
        l.fingerprint = hash(ObjectKind::Index, &["model"]);
        let r = row(&d, &l, Status::Managed);
        let mut edited = l.clone();
        edited.fingerprint = hash(ObjectKind::Index, &["model,record_id"]);
        let parent: BTreeSet<ObjectKey> = [d.key.clone()].into_iter().collect();
        let none = BTreeSet::new();
        let run = |live: &ObjectFingerprint, d: &DesiredObject| {
            reconcile(Inputs {
                desired: std::slice::from_ref(d),
                ledger: std::slice::from_ref(&r),
                live: std::slice::from_ref(live),
                created_by_parent: &parent,
                dropped_tables: &none,
                location: no_location,
                named_by_the_engine: &none,
                renamed_tables: &BTreeMap::new(),
                kinds: &[ObjectKind::Index, ObjectKind::Function],
            })
            .actions
        };

        let drifted = run(&edited, &d);
        assert!(
            matches!(&drifted[..], [Action::Drift { inline: false, .. }]),
            "{drifted:?}"
        );
        assert_eq!(
            drifted[0].sql(),
            [d.key.drop_sql().unwrap(), d.create_sql.clone()]
        );

        let mut changed = d.clone();
        changed.create_sql = changed
            .create_sql
            .replace("(\"model\")", "(\"model\", \"record_id\")");
        let replaced = run(&l, &changed);
        assert!(
            matches!(&replaced[..], [Action::Replace { inline: false, .. }]),
            "{replaced:?}"
        );
        assert_eq!(replaced[0].sql().len(), 2, "{replaced:?}");

        let mut f = d.clone();
        f.key = ObjectKey {
            kind: ObjectKind::Function,
            schema: "_supatype".into(),
            parent: String::new(),
            name: "caller_id()".into(),
        };
        f.create_sql = "CREATE OR REPLACE FUNCTION _supatype.caller_id() RETURNS uuid LANGUAGE sql AS $$ SELECT NULL $$;".into();
        let mut fl = l.clone();
        fl.kind = ObjectKind::Function;
        fl.parent = String::new();
        fl.name = "caller_id()".into();
        let fr = LedgerRow {
            key: f.key.clone(),
            ..row(&f, &fl, Status::Managed)
        };
        let mut fedited = fl.clone();
        fedited.fingerprint = "other".into();
        let fparent: BTreeSet<ObjectKey> = [f.key.clone()].into_iter().collect();
        let function = reconcile(Inputs {
            desired: std::slice::from_ref(&f),
            ledger: std::slice::from_ref(&fr),
            live: std::slice::from_ref(&fedited),
            created_by_parent: &fparent,
            dropped_tables: &none,
            location: no_location,
            named_by_the_engine: &none,
            renamed_tables: &BTreeMap::new(),
            kinds: &[ObjectKind::Function],
        })
        .actions;
        assert!(
            matches!(&function[..], [Action::Drift { inline: true, .. }]),
            "{function:?}"
        );
    }

    fn unique(name: &str, columns: &str) -> (DesiredObject, ObjectFingerprint) {
        let mut d = desired(name, "");
        d.key.kind = ObjectKind::Unique;
        d.structure.insert("columns", columns.into());
        d.create_sql = format!(
            "ALTER TABLE \"public\".\"posts\" ADD CONSTRAINT \"{name}\" UNIQUE (\"{columns}\");"
        );
        d.drop_sql = d.key.drop_sql().unwrap();
        let mut l = live(name, "");
        l.kind = ObjectKind::Unique;
        l.definition = format!("columns={columns}");
        l.fingerprint = hash(ObjectKind::Unique, &[columns]);
        (d, l)
    }

    fn run_uniques(
        desired: &[DesiredObject],
        ledger: &[LedgerRow],
        live: &[ObjectFingerprint],
    ) -> Vec<Action> {
        let none = BTreeSet::new();
        reconcile(Inputs {
            desired,
            ledger,
            live,
            created_by_parent: &none,
            dropped_tables: &none,
            location: no_location,
            named_by_the_engine: &none,
            renamed_tables: &BTreeMap::new(),
            kinds: &[ObjectKind::Unique],
        })
        .actions
    }

    /// A row under the live constraint's name on another table is that constraint before its
    /// table was renamed, so it is ours and renamed to our name; but not a released row, which is
    /// the user's: then the constraint is theirs, a conflict.
    #[test]
    fn a_released_row_on_another_table_does_not_make_a_unique_ours() {
        let (d, _) = unique("posts_slug_key", "slug");
        let (_, old) = unique("posts_slug_unique", "slug");
        let (mut elsewhere, _) = unique("posts_slug_unique", "slug");
        elsewhere.key.parent = "articles".into();
        for (status, ours) in [(Status::Managed, true), (Status::Released, false)] {
            let recorded = row(&elsewhere, &old, status);
            let actions = run_uniques(
                std::slice::from_ref(&d),
                std::slice::from_ref(&recorded),
                std::slice::from_ref(&old),
            );
            let adopted = actions.iter().any(|a| {
                matches!(a, Action::Adopt { renamed_from: Some(from), .. } if from == "posts_slug_unique")
            });
            let refused = actions
                .iter()
                .any(|a| matches!(a, Action::Conflict { key, .. } if *key == old.key()));
            assert_eq!((adopted, refused), (ours, !ours), "{status:?}: {actions:?}");
        }
    }

    /// With no row, a unique constraint is matched by its columns, as the differ it replaced
    /// matched it: an older engine's under a name of its own is renamed to ours and recorded, not
    /// dropped and made again. A user's unstamped one on the same columns is theirs: a conflict
    /// under its own name, for `adopt`, never renamed and never duplicated. Once a row exists, the
    /// name alone decides.
    #[test]
    fn a_unique_with_no_row_is_matched_by_its_columns() {
        let (d, _) = unique("posts_slug_key", "slug");
        let (_, old) = unique("posts_slug_unique", "slug");
        let rename =
            "ALTER TABLE \"public\".\"posts\" RENAME CONSTRAINT \"posts_slug_unique\" TO \"posts_slug_key\";";

        let stamped_old = stamped(old.clone());
        let actions = run_uniques(std::slice::from_ref(&d), &[], &[stamped_old]);
        match &actions[..] {
            [a @ Action::Adopt {
                reason: AdoptReason::Stamped,
                status: Status::Managed,
                renamed_from: Some(from),
                ..
            }] => {
                assert_eq!(from, "posts_slug_unique");
                assert_eq!(a.key(), &d.key);
                let sql = a.sql();
                assert_eq!(sql[0], rename);
                assert!(
                    sql[1].starts_with("COMMENT ON CONSTRAINT \"posts_slug_key\""),
                    "{sql:?}"
                );
                // Its name back, then its stamp under that name.
                let rollback = a.rollback_sql();
                assert_eq!(rollback.len(), 1, "{rollback:?}");
                let (back, stamp) = rollback[0].split_once('\n').expect("two statements");
                assert_eq!(
                    back,
                    "ALTER TABLE \"public\".\"posts\" RENAME CONSTRAINT \"posts_slug_key\" TO \"posts_slug_unique\";"
                );
                assert!(
                    stamp.starts_with("COMMENT ON CONSTRAINT \"posts_slug_unique\""),
                    "{stamp}"
                );
            }
            other => panic!("no drop and re-create: {other:?}"),
        }

        let user = run_uniques(std::slice::from_ref(&d), &[], std::slice::from_ref(&old));
        match &user[..] {
            [Action::Conflict { key, live_def, .. }] => {
                assert_eq!(key, &old.key(), "keyed by the user's name, for adopt");
                assert_eq!(live_def, &old.definition);
            }
            other => panic!("a user's constraint is refused, not renamed or duplicated: {other:?}"),
        }
        // Adopted, it has a row: the next push brings it to the schema, ours under our name.
        let (old_d, _) = unique("posts_slug_unique", "slug");
        let adopted = row(&old_d, &old, Status::Adopted);
        let next = run_uniques(
            std::slice::from_ref(&d),
            std::slice::from_ref(&adopted),
            std::slice::from_ref(&old),
        );
        assert!(
            matches!(&next[..], [Action::Drop { .. }, Action::Create { .. }]),
            "{next:?}"
        );

        // Ours by location or naming, unstamped: renamed as an older engine's.
        let none = BTreeSet::new();
        let named = BTreeSet::from([old.key()]);
        let ours = reconcile(Inputs {
            desired: std::slice::from_ref(&d),
            ledger: &[],
            live: std::slice::from_ref(&old),
            created_by_parent: &none,
            dropped_tables: &none,
            location: no_location,
            named_by_the_engine: &named,
            renamed_tables: &BTreeMap::new(),
            kinds: &[ObjectKind::Unique],
        })
        .actions;
        match &ours[..] {
            [a @ Action::Adopt {
                reason: AdoptReason::OwnedSchema,
                status: Status::Managed,
                ..
            }] => assert_eq!(a.sql(), [rename]),
            other => panic!("ours is renamed: {other:?}"),
        }

        // Other columns are another constraint.
        let (_, other) = unique("posts_title_key", "title");
        let created = run_uniques(std::slice::from_ref(&d), &[], &[other]);
        assert!(
            matches!(&created[..], [Action::Create { .. }]),
            "{created:?}"
        );

        // A row decides by name: the recorded constraint is dropped, ours made under its name.
        let (old_d, _) = unique("posts_slug_unique", "slug");
        let r = row(&old_d, &old, Status::Managed);
        let by_name = run_uniques(
            std::slice::from_ref(&d),
            std::slice::from_ref(&r),
            std::slice::from_ref(&old),
        );
        assert!(
            matches!(&by_name[..], [Action::Drop { .. }, Action::Create { .. }]),
            "{by_name:?}"
        );
    }

    /// An older engine stamped nothing, so an object it made is known by its name alone: with no
    /// row and no stamp, one named exactly as the engine names it is replaced when its definition
    /// differs (not refused) and dropped when the schema no longer asks for it. A user's function
    /// under any other name is never touched.
    #[test]
    fn an_object_named_by_the_engine_with_no_row_or_stamp_is_ours() {
        let function = |name: &str, body: &str| {
            let key = ObjectKey {
                kind: ObjectKind::Function,
                schema: "public".into(),
                parent: String::new(),
                name: format!("{name}(public.posts)"),
            };
            let create_sql = format!(
                "CREATE OR REPLACE FUNCTION \"public\".\"{name}\"(\"posts\" \"public\".\"posts\") RETURNS boolean LANGUAGE sql STABLE AS $can$ SELECT {body} $can$;"
            );
            let d = DesiredObject {
                key: key.clone(),
                structure: BTreeMap::new(),
                drop_sql: key.drop_sql().unwrap(),
                create_sql: create_sql.clone(),
                depends_on: Vec::new(),
                security_relevant: true,
            };
            let l = ObjectFingerprint {
                kind: key.kind,
                schema: key.schema.clone(),
                parent: String::new(),
                name: key.name.clone(),
                fingerprint: hash(ObjectKind::Function, &[body]),
                definition: format!("body={body}"),
                comment: None,
                create_sql: Some(create_sql),
            };
            (d, l)
        };
        let (d, _) = function("can_read_posts", "TRUE");
        let (_, old) = function("can_read_posts", "FALSE");
        let (_, gone) = function("can_update_posts", "TRUE");
        let (_, user) = function("can_do_things", "TRUE");
        let named: BTreeSet<ObjectKey> = [d.key.clone(), gone.key()].into_iter().collect();
        let none = BTreeSet::new();
        let run = |named: &BTreeSet<ObjectKey>| {
            reconcile(Inputs {
                desired: std::slice::from_ref(&d),
                ledger: &[],
                live: &[old.clone(), gone.clone(), user.clone()],
                created_by_parent: &none,
                dropped_tables: &none,
                location: no_location,
                named_by_the_engine: named,
                renamed_tables: &BTreeMap::new(),
                kinds: &[ObjectKind::Function],
            })
            .actions
        };

        // Without the naming rule: the differing body is a conflict, the stale one stays.
        let before = run(&none);
        assert!(
            matches!(&before[..], [Action::Conflict { .. }]),
            "{before:?}"
        );

        let actions = run(&named);
        assert!(
            matches!(&actions[..], [Action::Drop { key, .. }, Action::Replace { key: replaced, status: Status::Managed, .. }]
                if *key == gone.key() && *replaced == d.key),
            "{actions:?}"
        );
        assert!(
            actions.iter().all(|a| *a.key() != user.key()),
            "a user's function is left alone: {actions:?}"
        );
    }

    /// A key on `parent` with the given structure parts, desired as `create_sql` and live with
    /// exactly those parts.
    fn key_object(
        kind: ObjectKind,
        parent: &str,
        name: &str,
        parts: &[(&'static str, &str)],
        create_sql: &str,
    ) -> (DesiredObject, ObjectFingerprint) {
        let key = ObjectKey {
            kind,
            schema: "public".into(),
            parent: parent.into(),
            name: name.into(),
        };
        let d = DesiredObject {
            structure: parts.iter().map(|(l, v)| (*l, v.to_string())).collect(),
            create_sql: create_sql.into(),
            drop_sql: key.drop_sql().unwrap_or_default(),
            depends_on: Vec::new(),
            security_relevant: false,
            key: key.clone(),
        };
        let definition = parts
            .iter()
            .map(|(l, v)| format!("{l}={v}"))
            .collect::<Vec<_>>()
            .join("\n");
        let l = ObjectFingerprint {
            kind,
            schema: key.schema.clone(),
            parent: key.parent.clone(),
            name: key.name.clone(),
            fingerprint: hash(kind, &[&definition]),
            definition,
            comment: None,
            create_sql: None,
        };
        (d, l)
    }

    fn run_with(
        desired: &[DesiredObject],
        ledger: &[LedgerRow],
        live: &[ObjectFingerprint],
        named: &BTreeSet<ObjectKey>,
        renamed: &BTreeMap<ObjectKey, String>,
    ) -> Vec<Action> {
        let none = BTreeSet::new();
        reconcile(Inputs {
            desired,
            ledger,
            live,
            created_by_parent: &none,
            dropped_tables: &none,
            location: no_location,
            named_by_the_engine: named,
            renamed_tables: renamed,
            kinds: &[
                ObjectKind::PrimaryKey,
                ObjectKind::Unique,
                ObjectKind::ForeignKey,
                ObjectKind::Index,
                ObjectKind::Trigger,
                ObjectKind::View,
                ObjectKind::Function,
            ],
        })
        .actions
    }

    fn pk(table: &str) -> (DesiredObject, ObjectFingerprint) {
        key_object(
            ObjectKind::PrimaryKey,
            table,
            &format!("{table}_pkey"),
            &[("columns", "id")],
            &format!(
                "ALTER TABLE \"public\".\"{table}\" ADD CONSTRAINT \"{table}_pkey\" PRIMARY KEY (\"id\");"
            ),
        )
    }

    fn fk_to(target: &str) -> (DesiredObject, ObjectFingerprint) {
        let refs = format!("public.{target}");
        key_object(
            ObjectKind::ForeignKey,
            "comments",
            "comments_post_id_fkey",
            &[
                ("columns", "post_id"),
                ("references", refs.as_str()),
                ("referenced_columns", "id"),
                ("on_delete", "NO ACTION"),
                ("on_update", "NO ACTION"),
                ("match_type", "SIMPLE"),
                ("deferrable", "f"),
                ("initially_deferred", "f"),
            ],
            &format!(
                "ALTER TABLE \"public\".\"comments\" ADD CONSTRAINT \"comments_post_id_fkey\" FOREIGN KEY (\"post_id\") REFERENCES \"public\".\"{target}\" (\"id\");"
            ),
        )
    }

    fn table_key(name: &str) -> ObjectKey {
        ObjectKey {
            kind: ObjectKind::Table,
            schema: "public".into(),
            parent: String::new(),
            name: name.into(),
        }
    }

    /// F2(b): the primary key of a table this push renames is renamed after the table, and back
    /// before it on rollback; its row moves. A foreign key that references it, whose statement now
    /// names the new table, is only restated: once the table is renamed it points there.
    #[test]
    fn a_renamed_tables_key_is_renamed_and_the_key_on_it_restated() {
        let (old_pk, old_live) = pk("posts");
        let (new_pk, _) = pk("postings");
        let (old_fk, fk_live) = fk_to("posts");
        let (new_fk, _) = fk_to("postings");
        let ledger = [
            row(&old_pk, &old_live, Status::Managed),
            row(&old_fk, &fk_live, Status::Managed),
        ];
        let renamed = BTreeMap::from([(table_key("posts"), "postings".to_string())]);
        let actions = run_with(
            &[new_pk.clone(), new_fk.clone()],
            &ledger,
            &[old_live, fk_live],
            &BTreeSet::new(),
            &renamed,
        );
        match &actions[..] {
            [rename @ Action::Rename { key, from, .. }, Action::Restate { key: fk, .. }] => {
                assert_eq!((key, from, fk), (&new_pk.key, &old_pk.key, &new_fk.key));
                assert_eq!(
                    rename.sql(),
                    ["ALTER TABLE \"public\".\"postings\" RENAME CONSTRAINT \"posts_pkey\" TO \"postings_pkey\";"]
                );
                assert_eq!(
                    rename.rollback_sql(),
                    ["ALTER TABLE \"public\".\"postings\" RENAME CONSTRAINT \"postings_pkey\" TO \"posts_pkey\";"]
                );
                assert_eq!(rename.found_as().as_ref(), Some(&old_pk.key));
            }
            other => panic!("renamed and restated, never dropped: {other:?}"),
        }
        // Without the table rename the old key is dropped and the new one made, as before.
        let unrenamed = run_with(
            std::slice::from_ref(&new_pk),
            &ledger[..1],
            &[pk("posts").1],
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert!(
            matches!(&unrenamed[..], [Action::Drop { .. }, Action::Create { .. }]),
            "{unrenamed:?}"
        );
    }

    /// F2(c): a recorded statement worded differently from this push's, for an object unchanged
    /// since the last apply and shaped as desired, is restated: no SQL, the row rewritten. Changed
    /// by hand since, it is replaced, as before.
    #[test]
    fn a_reworded_statement_is_restated_unless_the_object_changed() {
        let (d, l) = pk("posts");
        let mut r = row(&d, &l, Status::Managed);
        r.desired_sql = d.create_sql.replace(" (", "(");
        r.desired_fp = desired_fingerprint(ObjectKind::PrimaryKey, &r.desired_sql);
        let none = BTreeSet::new();
        let restated = run_with(
            std::slice::from_ref(&d),
            std::slice::from_ref(&r),
            std::slice::from_ref(&l),
            &none,
            &BTreeMap::new(),
        );
        assert!(
            matches!(&restated[..], [Action::Restate { previous_sql, .. }] if *previous_sql == r.desired_sql),
            "{restated:?}"
        );
        assert!(restated[0].sql().is_empty() && !restated[0].is_change());
        assert_eq!(
            restated[0].row_after(),
            RowAfter::Write {
                create_sql: &d.create_sql,
                status: Status::Managed
            }
        );

        r.live_fp = "edited".into();
        let replaced = run_with(
            std::slice::from_ref(&d),
            std::slice::from_ref(&r),
            std::slice::from_ref(&l),
            &none,
            &BTreeMap::new(),
        );
        assert!(
            matches!(
                &replaced[..],
                [Action::Replace {
                    drifted: Some(_),
                    ..
                }]
            ),
            "{replaced:?}"
        );
    }

    /// F2(a): a primary key put back after drift takes the foreign keys on it with it: ours, kept
    /// otherwise, is rebuilt from its statement and keeps its row; a user's is rebuilt as the
    /// catalog renders it and gets none. Each is dropped before the key and made again after it.
    #[test]
    fn a_rebuilt_key_rebuilds_the_foreign_keys_on_it() {
        let (d, l) = pk("posts");
        let mut r = row(&d, &l, Status::Managed);
        r.live_fp = "edited".into();
        let (fk, fk_live) = fk_to("posts");
        let fk_row = row(&fk, &fk_live, Status::Managed);
        let mut theirs = fk_live.clone();
        theirs.name = "likes_post_fk".into();
        theirs.parent = "likes".into();
        theirs
            .definition
            .push_str("\ndefinition=FOREIGN KEY (post_id) REFERENCES public.posts(id)");
        let actions = run_with(
            &[d.clone(), fk.clone()],
            &[r, fk_row],
            &[l, fk_live, theirs.clone()],
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        let rebuilt: Vec<(&ObjectKey, Option<Status>)> = actions
            .iter()
            .filter_map(|a| match a {
                Action::Rebuild {
                    key,
                    status,
                    because,
                    ..
                } => {
                    assert_eq!(because, &d.key);
                    Some((key, *status))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            rebuilt,
            [(&fk.key, Some(Status::Managed)), (&theirs.key(), None)],
            "{actions:?}"
        );
        let user = actions.iter().find(|a| *a.key() == theirs.key()).unwrap();
        assert_eq!(
            user.addition_sql(),
            ["ALTER TABLE \"public\".\"likes\" ADD CONSTRAINT \"likes_post_fk\" FOREIGN KEY (post_id) REFERENCES public.posts(id);"]
        );
        assert!(user.removal_sql().unwrap().starts_with("-- "));
        assert_eq!(user.row_after(), RowAfter::Leave);
    }

    /// F8: a trigger 0.6.0 named, cut by Postgres, with no row: named by the engine and shaped as
    /// the desired one, so it is renamed, not left beside a second copy.
    #[test]
    fn an_older_engines_cut_name_is_renamed_to_ours() {
        let parts = [
            ("timing", "BEFORE"),
            ("events", "UPDATE"),
            ("function", "_platform.set_updated_at"),
        ];
        let (d, _) = key_object(
            ObjectKind::Trigger,
            "posts",
            "posts_upd_updated_at_trigger",
            &parts,
            "CREATE OR REPLACE TRIGGER \"posts_upd_updated_at_trigger\" BEFORE UPDATE ON \"public\".\"posts\" FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();",
        );
        let (_, old) = key_object(
            ObjectKind::Trigger,
            "posts",
            "posts_updated_at_tri",
            &parts,
            "",
        );
        let named = BTreeSet::from([old.key()]);
        let actions = run_with(
            std::slice::from_ref(&d),
            &[],
            std::slice::from_ref(&old),
            &named,
            &BTreeMap::new(),
        );
        match &actions[..] {
            [a @ Action::Adopt {
                renamed_from: Some(from),
                status: Status::Managed,
                ..
            }] => {
                assert_eq!(from, "posts_updated_at_tri");
                assert_eq!(
                    a.sql(),
                    ["ALTER TRIGGER \"posts_updated_at_tri\" ON \"public\".\"posts\" RENAME TO \"posts_upd_updated_at_trigger\";"]
                );
            }
            other => panic!("renamed, not duplicated: {other:?}"),
        }
        // Not the engine's name: a user's trigger, left alone, and ours made beside it.
        let user = run_with(
            std::slice::from_ref(&d),
            &[],
            std::slice::from_ref(&old),
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert!(matches!(&user[..], [Action::Create { .. }]), "{user:?}");
    }

    /// F12: a view's structure says only that it is not materialized, so a same-named view that is
    /// not ours by location or naming is a conflict, never adopted on that alone.
    #[test]
    fn a_users_view_under_our_name_is_a_conflict() {
        let (d, l) = key_object(
            ObjectKind::View,
            "",
            "users",
            &[("materialized", "f")],
            "CREATE VIEW \"api\".\"users\" AS SELECT 1;",
        );
        let none = BTreeSet::new();
        let refused = run_with(
            std::slice::from_ref(&d),
            &[],
            std::slice::from_ref(&l),
            &none,
            &BTreeMap::new(),
        );
        assert!(
            matches!(&refused[..], [Action::Conflict { .. }]),
            "{refused:?}"
        );
        let named = BTreeSet::from([d.key.clone()]);
        let ours = run_with(
            std::slice::from_ref(&d),
            &[],
            std::slice::from_ref(&l),
            &named,
            &BTreeMap::new(),
        );
        assert!(
            matches!(
                &ours[..],
                [Action::Adopt {
                    reason: AdoptReason::OwnedSchema,
                    ..
                }]
            ),
            "{ours:?}"
        );
    }

    /// A row as an older engine wrote it, fingerprinting only `parts` of the object.
    fn older_row(d: &DesiredObject, l: &ObjectFingerprint, parts: &[&str]) -> LedgerRow {
        let live_def = l
            .definition
            .lines()
            .filter(|line| parts.iter().any(|p| line.starts_with(&format!("{p}="))))
            .collect::<Vec<_>>()
            .join("\n");
        LedgerRow {
            live_fp: hash(d.key.kind, &[&live_def]),
            live_def,
            ..row(d, l, Status::Managed)
        }
    }

    /// ENG-TIER2 added a view's options and owner to its fingerprint. A row an older engine wrote
    /// without them is compared on the parts it carries, through every path the reconcile takes: an
    /// unchanged view is kept, a changed one is replaced with no hand edit to consent to, and a
    /// part the row does carry that changed is still drift.
    #[test]
    fn an_older_engines_view_row_is_compared_on_the_parts_it_carries() {
        let parts = [
            ("materialized", "f"),
            ("definition", "SELECT 1"),
            ("options", "security_barrier=true"),
            ("owner", "supatype_api"),
        ];
        let create = "CREATE VIEW \"public\".\"posts\" AS SELECT 1;";
        let (d, l) = key_object(ObjectKind::View, "", "posts", &parts, create);
        let older = older_row(&d, &l, &["materialized", "definition"]);
        let none = BTreeSet::new();
        let renamed = BTreeMap::new();
        let run = |d: &DesiredObject, l: &ObjectFingerprint| {
            run_with(
                std::slice::from_ref(d),
                std::slice::from_ref(&older),
                std::slice::from_ref(l),
                &none,
                &renamed,
            )
        };

        let kept = run(&d, &l);
        assert!(matches!(&kept[..], [Action::Keep { .. }]), "{kept:?}");

        let changed = DesiredObject {
            create_sql: "CREATE VIEW \"public\".\"posts\" AS SELECT 1 AS one;".into(),
            ..d.clone()
        };
        let replaced = run(&changed, &l);
        assert!(
            matches!(&replaced[..], [Action::Replace { drifted: None, .. }]),
            "{replaced:?}"
        );

        let (_, edited) = key_object(
            ObjectKind::View,
            "",
            "posts",
            &[parts[0], ("definition", "SELECT 2"), parts[2], parts[3]],
            create,
        );
        let drift = run(&d, &edited);
        assert!(matches!(&drift[..], [Action::Drift { .. }]), "{drift:?}");
    }

    /// The same for a function's `acl`: an older row without it is no hand edit, and so neither a
    /// drift nor a security-relevant one.
    #[test]
    fn an_older_engines_function_row_without_its_acl_is_kept() {
        let parts = [
            ("returns", "boolean"),
            ("body", "SELECT true"),
            ("acl", "authenticated=X"),
        ];
        let create = "CREATE FUNCTION \"public\".\"can_read\"() RETURNS boolean AS 'SELECT true';";
        let (d, l) = key_object(ObjectKind::Function, "", "can_read()", &parts, create);
        let older = older_row(&d, &l, &["returns", "body"]);
        let actions = run_with(
            std::slice::from_ref(&d),
            std::slice::from_ref(&older),
            std::slice::from_ref(&l),
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert!(matches!(&actions[..], [Action::Keep { .. }]), "{actions:?}");
    }
}
