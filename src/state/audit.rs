//! Who pushed, through what, from where, and which renames the push applied (the audit trail).
//!
//! A migration row recorded the SQL a rename ran and nothing about who asked for it. The only "who"
//! was a `pushedBy` inside the schema sources manifest, which the client set and nothing checked.
//! The row now has columns of its own (`_supatype.migrations`, see `migration_history`):
//!
//! - `pushed_by`: the author. A control plane sets it from the identity it authenticated, and says
//!   so with `pushed_by_verified`; anything else is the client's claim (git's user, or the OS user).
//! - `pushed_via`: `cli`, `studio`, `cloud` or `self-host` ([`PushChannel`]).
//! - `pushed_from`: a host name or a CI run.
//! - `renames`: each rename the push applied, with who declared it and when, from the project's
//!   rename journal (the schema's `renameJournal`).

use serde::{Deserialize, Serialize};

use crate::differ::Operation;
use crate::parser::annotations::{DeclaredRename, RenameCandidate};

/// The channels a push comes through. Anything else is refused where it enters, by the binary's
/// argument parser and by the HTTP server's request parser: a record a reader cannot interpret is
/// worse than none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PushChannel {
    Cli,
    Studio,
    Cloud,
    SelfHost,
}

impl PushChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            PushChannel::Cli => "cli",
            PushChannel::Studio => "studio",
            PushChannel::Cloud => "cloud",
            PushChannel::SelfHost => "self-host",
        }
    }
}

impl std::str::FromStr for PushChannel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_value(serde_json::Value::String(s.to_string())).map_err(|_| {
            format!(
                "\"{s}\" is not a channel a push comes through: cli, studio, cloud or self-host"
            )
        })
    }
}

/// What a push records about itself beside the schema it applied: the HTTP request's
/// `pushed_by`, `pushed_via`, `pushed_from` and `pushed_by_verified`, flattened into it.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PushAudit {
    pub pushed_by: Option<String>,
    pub pushed_via: Option<PushChannel>,
    pub pushed_from: Option<String>,
    pub pushed_by_verified: bool,
}

/// Each rename `operations` applies, with who declared it and when where the `journal` says, as
/// the `renames` column holds them; `None` when the push renamed nothing.
pub fn applied_renames(
    journal: &[DeclaredRename],
    operations: &[Operation],
) -> Option<serde_json::Value> {
    let applied: Vec<DeclaredRename> = operations
        .iter()
        .filter_map(|op| match op {
            Operation::RenameColumn {
                table, from, to, ..
            } => Some(declared(journal, "column", table, from, to)),
            Operation::RenameTable { from, to, .. } => {
                Some(declared(journal, "table", from, from, to))
            }
            _ => None,
        })
        .collect();
    (!applied.is_empty()).then(|| serde_json::to_value(applied).unwrap_or_default())
}

/// The rename as applied, with the journal's `declared_by` and `declared_at` when it has them: from
/// the entry that named this target (a chain is recorded as the step that reached it).
fn declared(
    journal: &[DeclaredRename],
    kind: &str,
    table: &str,
    from: &str,
    to: &str,
) -> DeclaredRename {
    let entry = journal
        .iter()
        .rev()
        .find(|r| r.rename.kind == kind && r.rename.to == to);
    DeclaredRename {
        rename: RenameCandidate {
            kind: kind.to_string(),
            table: table.to_string(),
            from: from.to_string(),
            to: to.to_string(),
        },
        declared_by: entry.and_then(|r| r.declared_by.clone()),
        declared_at: entry.and_then(|r| r.declared_at.clone()),
    }
}
