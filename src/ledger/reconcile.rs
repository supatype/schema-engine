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

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::desired::{DesiredObject, ObjectKey};
use crate::introspector::fingerprint::{ObjectFingerprint, ObjectKind};

use super::{desired_fingerprint, LedgerRow, Status};

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
    /// The engine's own schemas (plan 3.4). A desired object found there with no row is ours by
    /// location, whatever an older engine made of it: brought up to date rather than refused.
    pub owned_schemas: &'a [&'a str],
    /// Security label providers the engine owns outright (plan section 5). A label under one is
    /// ours wherever it is: claimed when desired, and taken off when nothing desires it, as a
    /// stamped object is, since no one else writes under our provider.
    pub owned_label_providers: &'a [&'a str],
    pub kinds: &'a [ObjectKind],
}

impl Inputs<'_> {
    /// Ours by where it lives: one of the engine's schemas, or a label under our provider.
    fn ours_by_location(&self, key: &ObjectKey) -> bool {
        self.owned_schemas.contains(&key.schema.as_str()) || self.under_owned_provider(key)
    }

    fn under_owned_provider(&self, key: &ObjectKey) -> bool {
        key.kind == ObjectKind::SecurityLabel
            && self.owned_label_providers.contains(&key.name.as_str())
    }
}

/// The kinds Postgres replaces with `CREATE OR REPLACE`, so a new definition needs no drop first.
/// Dropping first would fail anyway: a trigger depends on its function. Not views: `CREATE OR
/// REPLACE VIEW` refuses anything but appending columns, so a changed view is dropped and made
/// again.
fn replaced_in_place(kind: ObjectKind) -> bool {
    matches!(kind, ObjectKind::Function | ObjectKind::Trigger)
}

/// The order kinds are created in, dependencies first; drops run in reverse. A trigger needs its
/// function and its table, a foreign key its two tables, a column its type.
fn creation_rank(kind: ObjectKind) -> u8 {
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
        ObjectKind::ColumnGrant => 16,
        ObjectKind::SecurityLabel => 17,
        ObjectKind::CronJob => 18,
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
    },
    /// Owned, desired, present, and the catalog no longer matches what was recorded after the last
    /// apply: changed outside Supatype. Shown as a diff, then re-asserted (O1, subject to 3.5).
    /// `inline` when the parent statement re-asserts it itself.
    Drift {
        key: ObjectKey,
        recorded_def: String,
        live_def: String,
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
            | Action::Keep { create_sql, .. } => Some(create_sql),
            Action::Drop { .. } | Action::Forget { .. } | Action::Released { .. } => None,
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
            Action::Create { .. }
            | Action::Adopt { .. }
            | Action::Conflict { .. }
            | Action::Recreate { .. }
            | Action::Keep { .. }
            | Action::Forget { .. }
            | Action::Released { .. } => None,
        }
    }

    /// The statements that put the desired object in place. The migration runs every addition
    /// after its own operations, which may create the table or column the object needs.
    pub fn addition_sql(&self) -> Vec<String> {
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
            } => vec![create_sql.clone()],
            Action::Adopt {
                key,
                reason: AdoptReason::Stamped,
                comment,
                ..
            } => key
                .comment_sql(crate::managed::comment_without_stamp(comment.as_deref()).as_deref())
                .into_iter()
                .collect(),
            Action::Create { inline: true, .. }
            | Action::Recreate { inline: true, .. }
            | Action::Replace { inline: true, .. }
            | Action::Drift { inline: true, .. }
            | Action::Adopt { .. }
            | Action::Conflict { .. }
            | Action::Drop { .. }
            | Action::Keep { .. }
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
    /// being dropped (an affordance function takes its table), in which case the function must go
    /// first or the table cannot.
    pub fn removal_is_late(&self, dropped_tables: &[String]) -> bool {
        let key = self.key();
        key.kind == ObjectKind::Function
            && !dropped_tables.iter().any(|table| {
                key.name.contains(&format!(".{table})")) || key.name.contains(&format!(".{table},"))
            })
    }

    /// Undoes the addition: drops what this action created. An inline `Create` has one too; its
    /// parent's rollback covers it, and the explicit drop is `IF EXISTS`. A replacement in place
    /// is undone by the previous definition alone ([`Action::undo_removal`]).
    pub fn undo_addition(&self) -> Option<String> {
        match self {
            Action::Replace { key, .. } | Action::Drift { key, .. }
                if replaced_in_place(key.kind) =>
            {
                None
            }
            Action::Create { key, .. }
            | Action::Recreate { key, .. }
            | Action::Replace { key, .. }
            | Action::Drift { key, .. } => Some(drop_for(key)),
            Action::Adopt { .. }
            | Action::Conflict { .. }
            | Action::Keep { .. }
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
            Action::Replace { previous_sql, .. } => Some(previous_sql.clone()),
            Action::Drift { create_sql, .. } => Some(create_sql.clone()),
            Action::Drop { recorded_sql, .. } => recorded_sql.clone(),
            Action::Create { .. }
            | Action::Adopt { .. }
            | Action::Conflict { .. }
            | Action::Recreate { .. }
            | Action::Keep { .. }
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

    /// Whether the action changes the database or the ledger.
    pub fn is_change(&self) -> bool {
        !matches!(self, Action::Keep { .. } | Action::Released { .. })
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
            } => RowAfter::Write {
                create_sql,
                status: *status,
            },
            Action::Drop { .. } | Action::Forget { .. } => RowAfter::Remove,
            Action::Conflict { .. } | Action::Released { .. } => RowAfter::Leave,
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

fn drop_for(key: &ObjectKey) -> String {
    key.drop_sql()
        .unwrap_or_else(|| panic!("{key} is on the reconcile with no drop statement"))
}

pub fn reconcile(inputs: Inputs<'_>) -> Plan {
    let kinds: BTreeSet<ObjectKind> = inputs.kinds.iter().copied().collect();
    let desired: BTreeMap<&ObjectKey, &DesiredObject> = inputs
        .desired
        .iter()
        .filter(|d| kinds.contains(&d.key.kind))
        .map(|d| (&d.key, d))
        .collect();
    let ledger: BTreeMap<&ObjectKey, &LedgerRow> = inputs
        .ledger
        .iter()
        .filter(|r| kinds.contains(&r.key.kind))
        .map(|r| (&r.key, r))
        .collect();
    let live: BTreeMap<ObjectKey, &ObjectFingerprint> = inputs
        .live
        .iter()
        .filter(|f| kinds.contains(&f.kind))
        .map(|f| (f.key(), f))
        .collect();

    let goes_with_its_table = |key: &ObjectKey| {
        inputs.dropped_tables.contains(&ObjectKey {
            kind: ObjectKind::Table,
            schema: key.schema.clone(),
            parent: String::new(),
            name: key.parent.clone(),
        })
    };

    let mut removals = Vec::new();
    let mut changes = Vec::new();

    for (&key, row) in &ledger {
        let key = key.clone();
        if row.status == Status::Released {
            changes.push(Action::Released { key });
            continue;
        }
        let status = row.status;
        let inline = inputs.created_by_parent.contains(&key);
        match (desired.get(&key), live.get(&key)) {
            (Some(d), None) => changes.push(Action::Recreate {
                key,
                create_sql: d.create_sql.clone(),
                inline,
                status,
            }),
            (Some(d), Some(l)) => {
                if desired_fingerprint(key.kind, &d.create_sql) != row.desired_fp {
                    changes.push(Action::Replace {
                        key,
                        create_sql: d.create_sql.clone(),
                        previous_sql: row.desired_sql.clone(),
                        inline,
                        status,
                    });
                } else if l.fingerprint != row.live_fp {
                    changes.push(Action::Drift {
                        key,
                        recorded_def: row.live_def.clone(),
                        live_def: l.definition.clone(),
                        create_sql: d.create_sql.clone(),
                        security_relevant: d.security_relevant,
                        inline,
                        status,
                    });
                } else {
                    changes.push(Action::Keep {
                        key,
                        create_sql: d.create_sql.clone(),
                        status,
                    });
                }
            }
            (None, Some(_)) if !goes_with_its_table(&key) => removals.push(Action::Drop {
                key,
                recorded_sql: Some(row.desired_sql.clone()),
            }),
            (None, _) => removals.push(Action::Forget { key }),
        }
    }

    for (&key, d) in &desired {
        if ledger.contains_key(key) {
            continue;
        }
        let key = key.clone();
        match live.get(&key) {
            None => {
                let inline = inputs.created_by_parent.contains(&key);
                changes.push(Action::Create {
                    key,
                    create_sql: d.create_sql.clone(),
                    inline,
                    status: Status::Managed,
                });
            }
            Some(l) => {
                // Ours by location (plan 3.4 and section 5): an object in one of the engine's own
                // schemas, or a label under our provider, is ours whoever wrote it, since nothing
                // else writes there. Taken as `managed` when it is what we would create; replaced,
                // with its live definition kept for the rollback, when it was made differently.
                let ours_by_location = inputs.ours_by_location(&key);
                let claim = if l.stamped() {
                    Some((AdoptReason::Stamped, Status::Managed))
                } else if ours_by_location && structure_matches(d, l) {
                    Some((AdoptReason::OwnedSchema, Status::Managed))
                } else if structure_matches(d, l) {
                    Some((AdoptReason::StructureMatches, Status::Adopted))
                } else {
                    None
                };
                match (claim, l.create_sql.as_ref().filter(|_| ours_by_location)) {
                    (Some((reason, status)), _) => changes.push(Action::Adopt {
                        key,
                        reason,
                        create_sql: d.create_sql.clone(),
                        comment: l.comment.clone(),
                        status,
                    }),
                    (None, Some(previous_sql)) => changes.push(Action::Replace {
                        inline: inputs.created_by_parent.contains(&key),
                        key,
                        create_sql: d.create_sql.clone(),
                        previous_sql: previous_sql.clone(),
                        status: Status::Managed,
                    }),
                    (None, None) => changes.push(Action::Conflict {
                        key,
                        create_sql: d.create_sql.clone(),
                        live_def: l.definition.clone(),
                    }),
                }
            }
        }
    }

    // Objects of a moved kind that nothing declares any more and that are ours by their own record
    // (an older engine's stamp, section 7, last paragraph) or by their provider (section 5): they
    // are dropped, as the stamp-reading differ and the stale-label sweep dropped them. The live
    // definition, where the catalog renders one, is what a rollback restores.
    for (key, l) in &live {
        if !(l.stamped() || inputs.under_owned_provider(key))
            || ledger.contains_key(key)
            || desired.contains_key(key)
            || goes_with_its_table(key)
        {
            continue;
        }
        removals.push(Action::Drop {
            key: key.clone(),
            recorded_sql: l.create_sql.clone(),
        });
    }

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
            owned_schemas: &[],
            owned_label_providers: &[],
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
            owned_schemas: &[],
            owned_label_providers: &[],
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
            owned_schemas: &[],
            owned_label_providers: &[],
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
            owned_schemas: &[],
            owned_label_providers: &[],
            kinds: &[ObjectKind::Check],
        });
        // The row goes; no `ALTER TABLE` is emitted against a table that will not be there.
        assert_eq!(plan.actions, [Action::Forget { key: d.key.clone() }]);
        assert!(plan.actions.iter().all(|a| a.sql().is_empty()));
    }
}
