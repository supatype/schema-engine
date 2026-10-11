//! Plan 3.5: drift on what decides access needs a person's consent.
//!
//! A reconcile puts back what was changed or removed outside Supatype. That assumes someone reads
//! what it is about to do. In a pipeline a push would revert a deliberate hand edit (an RLS
//! hot-fix made at 2am, a policy dropped on purpose to open a table) on the next deploy, and a
//! rollback could not bring it back: it restores Supatype's definition, not the operator's. So a
//! push refuses when a policy, grant, security label or RLS attribute has drifted or been removed,
//! unless the caller says to overwrite it: interactively after showing the diff, or with
//! `--overwrite-drift`. Drift on any other kind is reported and put back as before.

use serde::Serialize;

use super::reconcile::{Action, Plan};
use crate::desired::{security_relevant, ObjectKey};

/// The stable name a caller matches on, in the engine's JSON output and the server's response.
pub const SECURITY_DRIFT: &str = "security_drift";

/// One object a push would put back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DriftedObject {
    pub key: ObjectKey,
    /// What Supatype recorded after its last push, or for one removed by hand what it would make.
    pub recorded: String,
    /// What the catalog holds now; `None` when it was removed.
    pub live: Option<String>,
    /// Why it could not be compared with what Supatype made, when it could not (F16): it is then
    /// treated as changed, and `recorded` says it was not checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unchecked: Option<String>,
}

/// The objects that decide access and were changed or removed outside Supatype, whether the push
/// puts them back, replaces them because the schema changed them as well, or drops them because
/// the schema no longer declares them or their table (F15 (c)).
pub fn security_drift(plan: &Plan) -> Vec<DriftedObject> {
    plan.actions
        .iter()
        .filter_map(|action| match action {
            Action::Drift {
                key,
                recorded_def,
                live_def,
                security_relevant: true,
                ..
            } => Some(DriftedObject {
                key: key.clone(),
                recorded: recorded_def.clone(),
                live: Some(live_def.clone()),
                unchecked: None,
            }),
            Action::Recreate {
                key, create_sql, ..
            } if security_relevant(key) => Some(DriftedObject {
                key: key.clone(),
                recorded: create_sql.clone(),
                live: None,
                unchecked: None,
            }),
            // The schema changed it too, so the reconcile replaces or drops it rather than puts
            // it back; the hand edit is lost all the same.
            action => action
                .hand_edit()
                .filter(|_| security_relevant(action.key()))
                .map(|edit| DriftedObject {
                    key: action.key().clone(),
                    recorded: edit.recorded_def.clone(),
                    live: Some(edit.live_def.clone()),
                    unchecked: edit.unchecked.clone(),
                }),
        })
        .collect()
}

/// A push refused because it would overwrite access changed outside Supatype. A type so a caller
/// can show the objects and ask, rather than match the wording.
#[derive(Debug)]
pub struct SecurityDrift {
    pub objects: Vec<DriftedObject>,
}

impl std::fmt::Display for SecurityDrift {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let objects = self
            .objects
            .iter()
            .map(|o| match (&o.unchecked, &o.live) {
                (Some(reason), _) => format!("{} (not checked: {reason})", o.key),
                (None, Some(_)) => format!("{} (changed)", o.key),
                (None, None) => format!("{} (removed)", o.key),
            })
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            f,
            "{} object(s) that decide who may read or write were changed outside Supatype, or \
             could not be checked for changes: {objects}.\n\nNothing was applied. A push that is not interactive does not overwrite \
             them, because the change may be deliberate and a rollback could not bring it back. \
             Run the push interactively to review the difference, or pass --overwrite-drift to put \
             Supatype's definitions back.",
            self.objects.len()
        )
    }
}

impl std::error::Error for SecurityDrift {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::introspector::fingerprint::ObjectKind;
    use crate::ledger::Status;

    fn key(kind: ObjectKind) -> ObjectKey {
        ObjectKey {
            kind,
            schema: "public".into(),
            parent: "posts".into(),
            name: "x".into(),
        }
    }

    fn drift(kind: ObjectKind) -> Action {
        Action::Drift {
            key: key(kind),
            recorded_def: "before".into(),
            live_def: "after".into(),
            live_fp: "after-fp".into(),
            create_sql: "CREATE".into(),
            security_relevant: security_relevant(&key(kind)),
            inline: false,
            status: Status::Managed,
        }
    }

    fn recreate(kind: ObjectKind) -> Action {
        Action::Recreate {
            key: key(kind),
            create_sql: "CREATE".into(),
            inline: false,
            status: Status::Managed,
        }
    }

    /// A policy as the schema declares it, the catalog holds it and the ledger records it.
    mod policy {
        use std::collections::{BTreeMap, BTreeSet};

        use crate::desired::DesiredObject;
        use crate::introspector::fingerprint::{hash, ObjectFingerprint, ObjectKind};
        use crate::ledger::reconcile::{no_location, reconcile, Inputs, Plan};
        use crate::ledger::{desired_fingerprint, LedgerRow, Status};

        pub fn desired(using: &str) -> DesiredObject {
            let key = super::key(ObjectKind::Policy);
            DesiredObject {
                drop_sql: key.drop_sql().unwrap(),
                key,
                structure: BTreeMap::new(),
                create_sql: format!(
                    "CREATE POLICY \"x\" ON \"public\".\"posts\" FOR SELECT USING ({using});"
                ),
                depends_on: Vec::new(),
                security_relevant: true,
            }
        }

        pub fn live(using: &str) -> ObjectFingerprint {
            ObjectFingerprint {
                kind: ObjectKind::Policy,
                schema: "public".into(),
                parent: "posts".into(),
                name: "x".into(),
                fingerprint: hash(ObjectKind::Policy, &[using]),
                definition: format!("using={using}"),
                comment: None,
                create_sql: None,
            }
        }

        pub fn row(d: &DesiredObject, l: &ObjectFingerprint) -> LedgerRow {
            LedgerRow {
                key: d.key.clone(),
                desired_fp: desired_fingerprint(d.key.kind, &d.create_sql),
                desired_sql: d.create_sql.clone(),
                live_fp: l.fingerprint.clone(),
                live_def: l.definition.clone(),
                status: Status::Managed,
                migration_id: Some(1),
            }
        }

        pub fn plan(d: &DesiredObject, r: &LedgerRow, l: &ObjectFingerprint) -> Plan {
            reconcile(Inputs {
                desired: std::slice::from_ref(d),
                ledger: std::slice::from_ref(r),
                live: std::slice::from_ref(l),
                created_by_parent: &BTreeSet::new(),
                dropped_tables: &BTreeSet::new(),
                location: no_location,
                named_by_the_engine: &BTreeSet::new(),
                renamed_tables: &BTreeMap::new(),
                kinds: &[ObjectKind::Policy],
            })
        }
    }

    #[test]
    fn a_hand_edit_the_schema_also_changes_still_needs_consent() {
        // Pushed as `true`; then edited by hand to `false`, and the schema now says `owner`.
        let pushed = policy::desired("true");
        let recorded = policy::row(&pushed, &policy::live("true"));
        let changed = policy::desired("owner");
        let edited = policy::plan(&changed, &recorded, &policy::live("false"));
        assert!(
            matches!(
                &edited.actions[..],
                [Action::Replace {
                    drifted: Some(_),
                    ..
                }]
            ),
            "{edited:?}"
        );
        assert_eq!(
            security_drift(&edited),
            [DriftedObject {
                key: key(ObjectKind::Policy),
                recorded: "using=true".into(),
                live: Some("using=false".into()),
                unchecked: None,
            }],
            "the hand edit was overwritten without consent"
        );

        // Only the schema changed: an ordinary replacement, nothing to consent to.
        let untouched = policy::plan(&changed, &recorded, &policy::live("true"));
        assert!(
            matches!(
                &untouched.actions[..],
                [Action::Replace { drifted: None, .. }]
            ),
            "{untouched:?}"
        );
        assert!(security_drift(&untouched).is_empty());
    }

    #[test]
    fn only_access_changed_or_removed_by_hand_needs_consent() {
        let plan = Plan {
            actions: vec![
                drift(ObjectKind::Policy),
                recreate(ObjectKind::TableGrant),
                drift(ObjectKind::Trigger),
                recreate(ObjectKind::Index),
            ],
        };
        let drifted = security_drift(&plan);
        assert_eq!(
            drifted,
            [
                DriftedObject {
                    key: key(ObjectKind::Policy),
                    recorded: "before".into(),
                    live: Some("after".into()),
                    unchecked: None,
                },
                DriftedObject {
                    key: key(ObjectKind::TableGrant),
                    recorded: "CREATE".into(),
                    live: None,
                    unchecked: None,
                },
            ]
        );
    }
}
