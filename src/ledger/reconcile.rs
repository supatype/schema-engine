//! The reconcile: desired objects against the ledger against the catalog, into actions.
//!
//! Plan 3.3 (the table) and section 7 (objects with no ledger row), as one pure function. It takes
//! what a push wants (`desired`), what the ledger says we own, what the catalog holds now, and two
//! facts the caller establishes from the database: which live objects carry a `supatype:managed`
//! stamp, and which same-named unstamped objects the database itself deparses to the definition
//! we would write. Nothing here touches a connection, so every row of the table has a unit test.
//!
//! Only the kinds in `kinds` are reconciled. A kind moves onto the reconcile one PR at a time
//! (plan section 9); until it moves, its old differ stays authoritative and its rows do not exist.

use std::collections::{BTreeMap, BTreeSet};

use crate::desired::{DesiredObject, ObjectKey};
use crate::introspector::fingerprint::{ObjectFingerprint, ObjectKind};

use super::{desired_fingerprint, LedgerRow, Status};

pub struct Inputs<'a> {
    pub desired: &'a [DesiredObject],
    pub ledger: &'a [LedgerRow],
    pub live: &'a [ObjectFingerprint],
    /// Live objects whose comment carries a `supatype:managed` stamp written by an older engine.
    pub stamped: &'a BTreeSet<ObjectKey>,
    /// Same-named live objects with no row and no stamp that the database deparses to exactly what
    /// we would create. The caller proves this with Postgres (a probe in a savepoint), never by
    /// comparing our text to a deparse. Empty when nothing collided.
    pub equivalent: &'a BTreeSet<ObjectKey>,
    /// Desired objects this push already creates as part of another statement (a constraint
    /// declared inline in `CREATE TABLE` or `ADD COLUMN`). Their `Create` carries no SQL.
    pub created_by_parent: &'a BTreeSet<ObjectKey>,
    pub kinds: &'a [ObjectKind],
}

/// Why an object with no ledger row is taken as ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptReason {
    /// Stamped `supatype:managed` by an older engine: ours by its own record (section 7.1).
    Stamped,
    /// Unstamped, but its structure is exactly what we would create (D2, section 7.2).
    StructureMatches,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// No row, desired, absent. `sql` is `None` when the parent statement creates it.
    Create { key: ObjectKey, sql: Option<String> },
    /// No row, desired, present and recognisably ours. A row is added; nothing is executed.
    Adopt { key: ObjectKey, reason: AdoptReason },
    /// No row, desired, present and not ours. The push refuses; `adopt` or a rename resolves it.
    Conflict { key: ObjectKey, live_def: String },
    /// Owned, desired, absent: someone dropped it. Recreated and reported.
    Recreate { key: ObjectKey, sql: String },
    /// Owned, desired, present, and this push's `CREATE` differs from the one recorded.
    Replace {
        key: ObjectKey,
        drop_sql: String,
        create_sql: String,
        previous_sql: String,
    },
    /// Owned, desired, present, and the catalog no longer matches what was recorded after the last
    /// apply: changed outside Supatype. Shown as a diff, then re-asserted (O1, subject to 3.5).
    Drift {
        key: ObjectKey,
        recorded_def: String,
        live_def: String,
        drop_sql: String,
        create_sql: String,
        security_relevant: bool,
    },
    /// Owned, desired, present, unchanged. The row is refreshed after apply, nothing is executed.
    Keep { key: ObjectKey },
    /// Owned, no longer desired, present. `sql` is `None` when no drop is known for the kind yet,
    /// which the caller must treat as a refusal rather than a silent skip.
    Drop { key: ObjectKey, sql: Option<String> },
    /// Owned, no longer desired, already gone. The row goes.
    Forget { key: ObjectKey },
    /// `released`: the user took it back. Left alone whatever the schema says.
    Released { key: ObjectKey },
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
            | Action::Keep { key }
            | Action::Drop { key, .. }
            | Action::Forget { key }
            | Action::Released { key } => key,
        }
    }

    /// The statements this action runs, in order. Empty for the bookkeeping-only actions.
    pub fn sql(&self) -> Vec<&str> {
        match self {
            Action::Create { sql: Some(sql), .. } | Action::Recreate { sql, .. } => vec![sql],
            Action::Replace {
                drop_sql,
                create_sql,
                ..
            }
            | Action::Drift {
                drop_sql,
                create_sql,
                ..
            } => vec![drop_sql, create_sql],
            Action::Drop { sql: Some(sql), .. } => vec![sql],
            Action::Create { sql: None, .. }
            | Action::Drop { sql: None, .. }
            | Action::Adopt { .. }
            | Action::Conflict { .. }
            | Action::Keep { .. }
            | Action::Forget { .. }
            | Action::Released { .. } => Vec::new(),
        }
    }

    /// Whether the action changes the database or the ledger.
    pub fn is_change(&self) -> bool {
        !matches!(self, Action::Keep { .. } | Action::Released { .. })
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Forgets and drops first, then replacements, re-creations and creations, each group in key
    /// order. Dependency ordering across kinds arrives with the kinds that need it.
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

    let mut removals = Vec::new();
    let mut changes = Vec::new();

    for (&key, row) in &ledger {
        let key = key.clone();
        if row.status == Status::Released {
            changes.push(Action::Released { key });
            continue;
        }
        match (desired.get(&key), live.get(&key)) {
            (Some(d), None) => changes.push(Action::Recreate {
                key,
                sql: d.create_sql.clone(),
            }),
            (Some(d), Some(l)) => {
                if desired_fingerprint(key.kind, &d.create_sql) != row.desired_fp {
                    changes.push(Action::Replace {
                        key,
                        drop_sql: d.drop_sql.clone(),
                        create_sql: d.create_sql.clone(),
                        previous_sql: row.desired_sql.clone(),
                    });
                } else if l.fingerprint != row.live_fp {
                    changes.push(Action::Drift {
                        key,
                        recorded_def: row.live_def.clone(),
                        live_def: l.definition.clone(),
                        drop_sql: d.drop_sql.clone(),
                        create_sql: d.create_sql.clone(),
                        security_relevant: d.security_relevant,
                    });
                } else {
                    changes.push(Action::Keep { key });
                }
            }
            (None, Some(_)) => {
                let sql = key.drop_sql();
                removals.push(Action::Drop { key, sql });
            }
            (None, None) => removals.push(Action::Forget { key }),
        }
    }

    for (&key, d) in &desired {
        if ledger.contains_key(key) {
            continue;
        }
        let key = key.clone();
        match live.get(&key) {
            None => {
                let sql = (!inputs.created_by_parent.contains(&key)).then(|| d.create_sql.clone());
                changes.push(Action::Create { key, sql });
            }
            Some(l) => {
                let reason = if inputs.stamped.contains(&key) {
                    Some(AdoptReason::Stamped)
                } else if structure_matches(d, l) || inputs.equivalent.contains(&key) {
                    Some(AdoptReason::StructureMatches)
                } else {
                    None
                };
                match reason {
                    Some(reason) => changes.push(Action::Adopt { key, reason }),
                    None => changes.push(Action::Conflict {
                        key,
                        live_def: l.definition.clone(),
                    }),
                }
            }
        }
    }

    // Stamped objects of a moved kind that nothing declares any more (section 7, last paragraph):
    // ours by their own record, so they are dropped, as the stamp-reading differ dropped them.
    for key in inputs.stamped {
        if !kinds.contains(&key.kind) || ledger.contains_key(key) || desired.contains_key(key) {
            continue;
        }
        if live.contains_key(key) {
            removals.push(Action::Drop {
                key: key.clone(),
                sql: key.drop_sql(),
            });
        }
    }

    removals.sort_by(|a, b| a.key().cmp(b.key()));
    changes.sort_by(|a, b| a.key().cmp(b.key()));
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
            drop_sql: format!(
                "ALTER TABLE \"public\".\"posts\" DROP CONSTRAINT IF EXISTS \"{name}\";"
            ),
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
        }
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
        stamped: &[ObjectKey],
        equivalent: &[ObjectKey],
        created_by_parent: &[ObjectKey],
    ) -> Vec<Action> {
        reconcile(Inputs {
            desired,
            ledger,
            live,
            stamped: &stamped.iter().cloned().collect(),
            equivalent: &equivalent.iter().cloned().collect(),
            created_by_parent: &created_by_parent.iter().cloned().collect(),
            kinds: &[ObjectKind::Check],
        })
        .actions
    }

    #[test]
    fn no_row_desired_absent_is_a_create_with_sql_unless_the_parent_creates_it() {
        let d = desired("posts_title_check", "length(title) > 0");
        let actions = run(std::slice::from_ref(&d), &[], &[], &[], &[], &[]);
        assert_eq!(
            actions,
            [Action::Create {
                key: d.key.clone(),
                sql: Some(d.create_sql.clone())
            }]
        );
        let inline = run(
            std::slice::from_ref(&d),
            &[],
            &[],
            &[],
            &[],
            std::slice::from_ref(&d.key),
        );
        assert_eq!(
            inline,
            [Action::Create {
                key: d.key.clone(),
                sql: None
            }]
        );
    }

    #[test]
    fn no_row_and_a_same_named_live_object_is_adopted_only_when_stamped_or_proven_equivalent() {
        let d = desired("posts_title_check", "length(title) > 0");
        let l = live("posts_title_check", "length(title) > 0");

        let unproven = run(
            std::slice::from_ref(&d),
            &[],
            std::slice::from_ref(&l),
            &[],
            &[],
            &[],
        );
        assert!(
            matches!(&unproven[..], [Action::Conflict { key, live_def }] if *key == d.key && live_def == &l.definition),
            "{unproven:?}"
        );

        let stamped = run(
            std::slice::from_ref(&d),
            &[],
            std::slice::from_ref(&l),
            std::slice::from_ref(&d.key),
            &[],
            &[],
        );
        assert_eq!(
            stamped,
            [Action::Adopt {
                key: d.key.clone(),
                reason: AdoptReason::Stamped
            }]
        );

        let equivalent = run(
            std::slice::from_ref(&d),
            &[],
            std::slice::from_ref(&l),
            &[],
            std::slice::from_ref(&d.key),
            &[],
        );
        assert_eq!(
            equivalent,
            [Action::Adopt {
                key: d.key.clone(),
                reason: AdoptReason::StructureMatches
            }]
        );
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
        let plan = reconcile(Inputs {
            desired: std::slice::from_ref(&d),
            ledger: &[],
            live: std::slice::from_ref(&l),
            stamped: &BTreeSet::new(),
            equivalent: &BTreeSet::new(),
            created_by_parent: &BTreeSet::new(),
            kinds: &kinds,
        });
        assert!(
            matches!(
                &plan.actions[..],
                [Action::Adopt {
                    reason: AdoptReason::StructureMatches,
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
            stamped: &BTreeSet::new(),
            equivalent: &BTreeSet::new(),
            created_by_parent: &BTreeSet::new(),
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
        let r = row(&d, &l, Status::Managed);

        let kept = run(
            std::slice::from_ref(&d),
            std::slice::from_ref(&r),
            std::slice::from_ref(&l),
            &[],
            &[],
            &[],
        );
        assert_eq!(kept, [Action::Keep { key: d.key.clone() }]);
        assert!(!Plan { actions: kept }.has_changes());

        let tightened = desired("posts_title_check", "length(title) > 3");
        let replaced = run(
            std::slice::from_ref(&tightened),
            std::slice::from_ref(&r),
            std::slice::from_ref(&l),
            &[],
            &[],
            &[],
        );
        assert!(
            matches!(&replaced[..], [Action::Replace { previous_sql, create_sql, .. }]
                if previous_sql == &d.create_sql && create_sql == &tightened.create_sql),
            "{replaced:?}"
        );

        let edited = live("posts_title_check", "length(title) > 1");
        let drifted = run(
            std::slice::from_ref(&d),
            std::slice::from_ref(&r),
            std::slice::from_ref(&edited),
            &[],
            &[],
            &[],
        );
        assert!(
            matches!(&drifted[..], [Action::Drift { recorded_def, live_def, .. }]
                if recorded_def == &l.definition && live_def == &edited.definition),
            "{drifted:?}"
        );

        let recreated = run(
            std::slice::from_ref(&d),
            std::slice::from_ref(&r),
            &[],
            &[],
            &[],
            &[],
        );
        assert_eq!(
            recreated,
            [Action::Recreate {
                key: d.key.clone(),
                sql: d.create_sql.clone()
            }]
        );
    }

    #[test]
    fn an_owned_object_the_schema_dropped_is_dropped_or_forgotten_and_a_released_one_is_left() {
        let d = desired("posts_title_check", "length(title) > 0");
        let l = live("posts_title_check", "length(title) > 0");
        let r = row(&d, &l, Status::Managed);

        let dropped = run(
            &[],
            std::slice::from_ref(&r),
            std::slice::from_ref(&l),
            &[],
            &[],
            &[],
        );
        assert_eq!(
            dropped,
            [Action::Drop {
                key: d.key.clone(),
                sql: d.key.drop_sql()
            }]
        );
        assert!(dropped[0].sql()[0].contains("DROP CONSTRAINT IF EXISTS \"posts_title_check\""));

        let forgotten = run(&[], std::slice::from_ref(&r), &[], &[], &[], &[]);
        assert_eq!(forgotten, [Action::Forget { key: d.key.clone() }]);

        let released = row(&d, &l, Status::Released);
        let tightened = desired("posts_title_check", "length(title) > 3");
        let left = run(
            std::slice::from_ref(&tightened),
            std::slice::from_ref(&released),
            std::slice::from_ref(&l),
            &[],
            &[],
            &[],
        );
        assert_eq!(left, [Action::Released { key: d.key.clone() }]);
    }

    #[test]
    fn a_stamped_object_nothing_declares_is_dropped_and_a_user_object_is_never_touched() {
        let l = live("posts_old_check", "true");
        let stamped = run(&[], &[], std::slice::from_ref(&l), &[l.key()], &[], &[]);
        assert!(matches!(&stamped[..], [Action::Drop { .. }]), "{stamped:?}");

        let user = run(&[], &[], std::slice::from_ref(&l), &[], &[], &[]);
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
            &[],
            &[],
        );
        assert!(
            matches!(&actions[..], [Action::Drop { .. }, Action::Create { .. }]),
            "{actions:?}"
        );
        assert!(actions.iter().all(|a| a.key().kind == ObjectKind::Check));
    }
}
