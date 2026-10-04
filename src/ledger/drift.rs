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
}

/// The objects that decide access and were changed or removed outside Supatype.
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
            }),
            Action::Recreate {
                key, create_sql, ..
            } if security_relevant(key.kind) => Some(DriftedObject {
                key: key.clone(),
                recorded: create_sql.clone(),
                live: None,
            }),
            _ => None,
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
            .map(|o| {
                let what = if o.live.is_some() {
                    "changed"
                } else {
                    "removed"
                };
                format!("{} ({what})", o.key)
            })
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            f,
            "{} object(s) that decide who may read or write were changed outside Supatype: \
             {objects}.\n\nNothing was applied. A push that is not interactive does not overwrite \
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
            security_relevant: security_relevant(kind),
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
                },
                DriftedObject {
                    key: key(ObjectKind::TableGrant),
                    recorded: "CREATE".into(),
                    live: None,
                },
            ]
        );
    }
}
