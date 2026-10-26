//! Every refusal a caller acts on by its reason, in one place (LK6, CL3).
//!
//! The binary prints each as one JSON line on stdout, `{"status":"refused","reason":...}`, beside
//! the error on stderr, and the HTTP server answers each with 409 and the same `reason` and
//! fields. Callers used to match some of them by their wording (Cloud on "no schema snapshot",
//! self-host-control too), and a lock or a step after commit that failed came back as a plain
//! error. Each now has a stable reason:
//!
//! * `engine_busy`: another writer holds the engine's lock, or landed while this one was planned.
//! * `unmanaged_model_tables`, `security_drift`, `drift_changed`: as before.
//! * `lock_unavailable`: a table lock another session holds, named with the session (LK6).
//! * `validation_failed`: the migration applied, and a step after its commit did not (LK6).
//! * `no_schema_snapshot`: a migration with no schema sources to return (CL3).
//! * `no_applied_migration`, `no_rollback_sql`: a rollback with nothing to undo (CL3).

use serde_json::{json, Map, Value};

use crate::generator::sql::migration::{UnmanagedModelTables, UNMANAGED_MODEL_TABLES};
use crate::inspect::{DriftChangedSincePreview, DRIFT_CHANGED};
use crate::ledger::drift::{SecurityDrift, SECURITY_DRIFT};
use crate::online::{AfterCommitFailed, LockNotAvailable, LOCK_UNAVAILABLE};
use crate::push::{EngineBusy, ENGINE_BUSY};
use crate::state::migration_history::{NoSchemaSnapshot, RollbackRefused, NO_SCHEMA_SNAPSHOT};

/// The stable name a caller matches an [`AfterCommitFailed`] refusal on.
pub const VALIDATION_FAILED: &str = "validation_failed";

/// One refusal: its reason, its message, and what else it names.
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub reason: &'static str,
    pub message: String,
    /// The fields beside `reason`: `tables`, `objects`, `unseen` and `gone`, `table` and
    /// `holders`, `failures`, `migration`.
    pub details: Map<String, Value>,
}

impl Refusal {
    fn new(reason: &'static str, message: String, details: Value) -> Refusal {
        let details = match details {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        Refusal {
            reason,
            message,
            details,
        }
    }

    /// The line the binary prints on stdout.
    pub fn line(&self) -> Value {
        let mut line = Map::new();
        line.insert("status".into(), json!("refused"));
        line.insert("reason".into(), json!(self.reason));
        line.extend(self.details.clone());
        line.insert("message".into(), json!(self.message));
        Value::Object(line)
    }
}

/// The refusal `e` is, through any context added to it, or `None` for any other failure.
pub fn of(e: &anyhow::Error) -> Option<Refusal> {
    if let Some(busy) = e.downcast_ref::<EngineBusy>() {
        return Some(Refusal::new(ENGINE_BUSY, busy.to_string(), json!({})));
    }
    if let Some(r) = e.downcast_ref::<UnmanagedModelTables>() {
        let details = json!({ "tables": r.tables });
        return Some(Refusal::new(UNMANAGED_MODEL_TABLES, r.to_string(), details));
    }
    if let Some(r) = e.downcast_ref::<SecurityDrift>() {
        let details = json!({ "objects": r.objects });
        return Some(Refusal::new(SECURITY_DRIFT, r.to_string(), details));
    }
    if let Some(r) = e.downcast_ref::<DriftChangedSincePreview>() {
        let details = json!({ "unseen": r.unseen, "gone": r.gone });
        return Some(Refusal::new(DRIFT_CHANGED, r.to_string(), details));
    }
    lock_or_after_commit(e).or_else(|| nothing_to_return(e))
}

/// LK6: a lock another session holds, or a step after commit that did not finish.
fn lock_or_after_commit(e: &anyhow::Error) -> Option<Refusal> {
    if let Some(r) = e.downcast_ref::<LockNotAvailable>() {
        let mut details = json!({ "attempts": r.attempts });
        if let Some(wait) = &r.wait {
            let holders: Vec<Value> = wait
                .holders
                .iter()
                .map(|h| {
                    json!({ "pid": h.pid, "state": h.state,
                                 "runningForSecs": h.running_for.as_secs() })
                })
                .collect();
            details["table"] = json!(wait.table);
            details["mode"] = json!(wait.mode);
            details["holders"] = json!(holders);
        }
        return Some(Refusal::new(LOCK_UNAVAILABLE, r.to_string(), details));
    }
    let r = e.downcast_ref::<AfterCommitFailed>()?;
    let details = json!({ "migration": r.name, "failures": r.failures });
    Some(Refusal::new(VALIDATION_FAILED, r.to_string(), details))
}

/// CL3: a migration with no sources, or a rollback with nothing to undo.
fn nothing_to_return(e: &anyhow::Error) -> Option<Refusal> {
    if let Some(r) = e.downcast_ref::<NoSchemaSnapshot>() {
        let details = json!({ "migration": r.name });
        return Some(Refusal::new(NO_SCHEMA_SNAPSHOT, r.to_string(), details));
    }
    let r = e.downcast_ref::<RollbackRefused>()?;
    Some(Refusal::new(r.reason(), r.to_string(), json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::online::{Holder, LockWait};
    use std::time::Duration;

    fn refused(e: anyhow::Error) -> Refusal {
        of(&e.context("under a caller's context")).expect("a refusal")
    }

    #[test]
    fn a_lock_held_by_another_session_is_lock_unavailable_naming_it() {
        let e = LockNotAvailable {
            what: "rollback",
            attempts: 1,
            wait: Some(LockWait {
                table: "public.items".into(),
                mode: "AccessExclusiveLock".into(),
                holders: vec![Holder {
                    pid: 42,
                    state: "idle in transaction".into(),
                    running_for: Duration::from_secs(7),
                }],
            }),
        };
        let r = refused(e.into());
        assert_eq!(r.reason, "lock_unavailable");
        assert_eq!(r.details["table"], "public.items");
        assert_eq!(r.details["holders"][0]["pid"], 42);
        assert!(r.message.contains("pid 42"), "{}", r.message);
        let line = r.line();
        assert_eq!(line["status"], "refused");
        assert_eq!(line["reason"], "lock_unavailable");
    }

    #[test]
    fn a_step_after_commit_that_failed_is_validation_failed() {
        let e = AfterCommitFailed {
            name: Some("push_1".into()),
            failures: vec!["index i could not be built".into()],
        };
        let r = refused(e.into());
        assert_eq!(r.reason, "validation_failed");
        assert_eq!(r.details["migration"], "push_1");
        assert_eq!(r.details["failures"][0], "index i could not be built");
    }

    #[test]
    fn a_migration_with_no_sources_and_a_rollback_with_nothing_to_undo_have_reasons() {
        let r = refused(
            NoSchemaSnapshot {
                name: "push_1".into(),
            }
            .into(),
        );
        assert_eq!(r.reason, "no_schema_snapshot");
        // The wording callers matched on before the reason existed.
        assert!(r.message.contains("no schema snapshot"), "{}", r.message);
        let r = refused(RollbackRefused::NoAppliedMigration.into());
        assert_eq!(r.reason, "no_applied_migration");
        assert!(r.message.starts_with("no_applied_migration: "));
    }

    #[test]
    fn any_other_failure_is_no_refusal() {
        assert_eq!(of(&anyhow::anyhow!("failed")), None);
    }
}
