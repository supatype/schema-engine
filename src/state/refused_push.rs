//! A push refused before it applied anything, recorded in `_supatype.migrations` as `refused`.
//!
//! A push that fails mid-apply has long been recorded (`failed`). One refused before it began, a
//! destructive change without `force` say, recorded nothing, so the history said every push had
//! applied while the database was still on the schema before it, and Studio had no way to say so.
//!
//! A refused row is kept apart from every other row:
//!
//! * Its name is `refused_<hash>`, never a name a push asks for, so it takes no migration's name.
//!   The same plan refused again moves its one row forward rather than adding one per save.
//! * Its statements are in `refusal.sql`, not `sql_up`: Studio from before this lists every row
//!   with statements as an applied migration, and leaves out one with none.
//! * It has no schema snapshot and no admin config, so nothing that reads the schema in force
//!   from the history (the previous schema, the latest admin config, rollback) can take it for an
//!   applied push; those readers also ask for `status = 'applied'`.
//! * A later push that applies, with changes or none, dates it `superseded_at`, which is what tells
//!   Studio the refusal no longer describes the project.

use anyhow::Result;
use serde_json::{json, Value};
use sqlx::{PgConnection, PgPool};

use super::audit::{PushAudit, PushChannel};
use crate::differ::{DiffOutput, Risk};
use crate::parser::annotations::RenameCandidate;

/// The status a refused push is recorded with.
pub const REFUSED: &str = "refused";

/// Why a push was refused, as recorded in `refusal.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// The change drops data and `force` was not given.
    Destructive,
    /// The change rewrites a large table under a lock and `force` was not given.
    Rewrite,
    /// Access Supatype manages was changed outside it and `overwrite_drift` was not given.
    SecurityDrift,
    /// An object Supatype did not create holds a name the schema needs.
    Conflicts,
}

impl RefusalReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RefusalReason::Destructive => "destructive",
            RefusalReason::Rewrite => "rewrite",
            RefusalReason::SecurityDrift => "security_drift",
            RefusalReason::Conflicts => "conflicts",
        }
    }

    /// The commands that apply the change on purpose, or deal with what refused it.
    fn hints(self, renames: &[RenameCandidate]) -> Vec<String> {
        match self {
            RefusalReason::Destructive => {
                let mut hints: Vec<String> = renames.iter().map(rename_hint).collect();
                hints.push("supatype push --yes".into());
                hints
            }
            RefusalReason::Rewrite => vec!["supatype push --yes".into()],
            RefusalReason::SecurityDrift => vec![
                "supatype push --overwrite-drift".into(),
                "supatype doctor --rebaseline --accept-access-drift".into(),
            ],
            RefusalReason::Conflicts => vec!["supatype adopt".into()],
        }
    }
}

/// The `supatype rename` that records `candidate`, as the CLI words it.
fn rename_hint(candidate: &RenameCandidate) -> String {
    if candidate.kind == "table" {
        format!("supatype rename {} {}", candidate.from, candidate.to)
    } else {
        let table = &candidate.table;
        format!(
            "supatype rename {table}.{} {table}.{}",
            candidate.from, candidate.to
        )
    }
}

/// One operation of a diff in a line: its own warning when it has one, else its kind and target,
/// as `supatype diff` prints it ("drop_column tags.name").
fn operation_label(op: &crate::differ::Operation) -> String {
    let value = serde_json::to_value(op).unwrap_or(Value::Null);
    let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_string);
    if let Some(warning) = text("warning") {
        return warning;
    }
    let kind = text("type").unwrap_or_else(|| "operation".into());
    match (text("table"), text("column")) {
        (Some(table), Some(column)) => format!("{kind} {table}.{column}"),
        (Some(table), None) => format!("{kind} {table}"),
        _ => kind,
    }
}

/// What the refusal names: the operations that drop data, or the tables a rewrite would lock, or
/// the objects in the way, one line each.
pub fn named_operations(
    reason: RefusalReason,
    diff: &DiffOutput,
    objects: &[String],
) -> Vec<String> {
    match reason {
        RefusalReason::Destructive => diff
            .operations
            .iter()
            .filter(|op| *crate::differ::risk_of(op) == Risk::Destructive)
            .map(operation_label)
            .collect(),
        RefusalReason::Rewrite => diff
            .rewrites
            .iter()
            .filter(|r| r.needs_consent)
            .map(|r| r.message())
            .collect(),
        RefusalReason::SecurityDrift | RefusalReason::Conflicts => objects.to_vec(),
    }
}

/// A refused push, as its row records it.
pub struct RefusedPush<'a> {
    /// The hash of the migration it would have applied, which names its row.
    pub hash: &'a str,
    /// The statements it would have run.
    pub sql: &'a str,
    /// The engine's refusal, as the push reported it.
    pub error: &'a str,
    pub reason: RefusalReason,
    /// What it would drop, rewrite or was stopped by ([`named_operations`]).
    pub operations: Vec<String>,
    pub rename_candidates: &'a [RenameCandidate],
    pub audit: &'a PushAudit,
}

impl RefusedPush<'_> {
    /// The row's name: one per plan, so the same plan refused again is the same row.
    pub fn name(&self) -> String {
        let hex = self.hash.strip_prefix("sha256:").unwrap_or(self.hash);
        format!("refused_{}", &hex[..hex.len().min(16)])
    }

    /// The `refusal` column.
    pub fn refusal(&self) -> Value {
        json!({
            "reason": self.reason.as_str(),
            "sql": self.sql,
            "operations": self.operations,
            "renameCandidates": self.rename_candidates,
            "hints": self.reason.hints(self.rename_candidates),
        })
    }
}

/// Insert the refused row, or move the one already recorded for this plan forward. A row of that
/// name with any other status is never touched.
pub fn upsert_refused_sql() -> String {
    "INSERT INTO _supatype.migrations \
     (name, hash, engine_version, status, error_message, refusal, \
      pushed_by, pushed_via, pushed_from, pushed_by_verified) \
     VALUES ($1, $2, $3, 'refused', $4, $5, $6, $7, $8, $9) \
     ON CONFLICT (name) DO UPDATE SET applied_at = NOW(), superseded_at = NULL, \
       engine_version = EXCLUDED.engine_version, error_message = EXCLUDED.error_message, \
       refusal = EXCLUDED.refusal, pushed_by = EXCLUDED.pushed_by, \
       pushed_via = EXCLUDED.pushed_via, pushed_from = EXCLUDED.pushed_from, \
       pushed_by_verified = EXCLUDED.pushed_by_verified \
     WHERE _supatype.migrations.status = 'refused'"
        .to_string()
}

/// Record `refused`. Outside any transaction: nothing was applied, so there is nothing to commit
/// with it.
pub async fn record(pool: &PgPool, refused: &RefusedPush<'_>) -> Result<()> {
    let audit = refused.audit;
    sqlx::query(&upsert_refused_sql())
        .bind(refused.name())
        .bind(refused.hash)
        .bind(env!("ENGINE_VERSION"))
        .bind(refused.error)
        .bind(refused.refusal())
        .bind(audit.pushed_by.as_deref())
        .bind(audit.pushed_via.map(PushChannel::as_str))
        .bind(audit.pushed_from.as_deref())
        .bind(audit.pushed_by.as_ref().map(|_| audit.pushed_by_verified))
        .execute(pool)
        .await?;
    Ok(())
}

/// Date every refused or failed push not yet superseded: a push just applied, so none of them
/// describes the project any more. Run in the applying push's transaction.
pub async fn supersede(tx: &mut PgConnection) -> Result<()> {
    sqlx::query(SUPERSEDE_SQL).execute(&mut *tx).await?;
    Ok(())
}

/// [`supersede`]'s statement, which a `migrate` file runs with the history row it writes.
pub const SUPERSEDE_SQL: &str = "UPDATE _supatype.migrations SET superseded_at = NOW() \
     WHERE status IN ('refused', 'failed') AND superseded_at IS NULL";

/// The columns a refused row adds to the history: what it would have run and why it did not, and
/// when a later push made it history.
pub fn ensure_columns_sql() -> String {
    "ALTER TABLE _supatype.migrations ADD COLUMN IF NOT EXISTS refusal JSONB;\
     ALTER TABLE _supatype.migrations ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(kind: &str) -> RenameCandidate {
        RenameCandidate {
            kind: kind.into(),
            table: "site".into(),
            from: "tagline".into(),
            to: "strapline".into(),
        }
    }

    #[test]
    fn a_destructive_refusal_names_each_rename_then_the_forced_push() {
        let hints = RefusalReason::Destructive.hints(&[candidate("column"), candidate("table")]);
        assert_eq!(
            hints,
            [
                "supatype rename site.tagline site.strapline",
                "supatype rename tagline strapline",
                "supatype push --yes",
            ]
        );
    }

    #[test]
    fn the_row_is_named_by_its_plan() {
        let audit = PushAudit::default();
        let refused = RefusedPush {
            hash: "sha256:0123456789abcdef0123",
            sql: "",
            error: "",
            reason: RefusalReason::Rewrite,
            operations: Vec::new(),
            rename_candidates: &[],
            audit: &audit,
        };
        assert_eq!(refused.name(), "refused_0123456789abcdef");
        assert_eq!(refused.refusal()["hints"], json!(["supatype push --yes"]));
    }
}
