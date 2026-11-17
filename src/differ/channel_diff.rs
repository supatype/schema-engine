//! What a push changes about realtime channels, listed the way model rule changes are: which
//! declarations are added, removed or changed and which operation's rule moved, with a warning
//! where the change loosens or tightens who can reach a topic. And the drift check: the channel
//! functions are re-asserted on every push, so a hand edit is overwritten, and this says so first.

use crate::generator::sql::realtime;
use crate::parser::ast::{ChannelAst, ChannelMode, SchemaAst};
use crate::state::database_state::DatabaseState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ChannelChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChannelChange {
    pub name: String,
    pub pattern: String,
    pub change: ChannelChangeKind,
    /// For a changed channel, what moved: any of `pattern`, `params`, `join`, `send`, `track`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<String>>,
}

/// The mode before and after a push.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModeChange {
    pub before: String,
    pub after: String,
}

fn mode_of(ast: &SchemaAst) -> ChannelMode {
    ast.realtime
        .as_ref()
        .map_or(ChannelMode::Open, |r| r.channels)
}

/// What a push does to channels and to the mode, from the database's own word where it has one.
pub struct Outcome {
    pub channels: Vec<ChannelChange>,
    pub mode: Option<ModeChange>,
}

/// The channel changes between `previous` (nothing, when there is no earlier push to read) and
/// `ast`, in declaration order with removals last. Pushes their warnings onto `warnings`.
pub fn diff(
    ast: &SchemaAst,
    db: &DatabaseState,
    previous: Option<&SchemaAst>,
    warnings: &mut Vec<String>,
) -> Outcome {
    let changes = changes(ast, previous);
    let known = mode_before(db, previous);
    let before = known.unwrap_or(ChannelMode::Open);
    // A mode change is warned of only against a mode that is known: a first push has nothing to
    // loosen or tighten.
    let warned_from = known.unwrap_or(mode_of(ast));
    warnings.extend(change_warnings(mode_of(ast), warned_from, &changes));
    if let Some(previous) = previous {
        warnings.extend(drift_warnings(previous, db));
    }
    let after = mode_of(ast);
    let mode = (before != after).then(|| ModeChange {
        before: before.as_str().to_string(),
        after: after.as_str().to_string(),
    });
    Outcome {
        channels: changes,
        mode,
    }
}

/// The mode the database holds now, read from `realtime_channel_mode()`'s body; else the last
/// push's; else unknown.
fn mode_before(db: &DatabaseState, previous: Option<&SchemaAst>) -> Option<ChannelMode> {
    let live = db
        .realtime_functions
        .get("realtime_channel_mode")
        .and_then(|body| {
            [ChannelMode::Declared, ChannelMode::Open]
                .into_iter()
                .find(|m| body.contains(&format!("'{}'", m.as_str())))
        });
    live.or_else(|| previous.map(mode_of))
}

fn changes(ast: &SchemaAst, previous: Option<&SchemaAst>) -> Vec<ChannelChange> {
    let before: BTreeMap<&str, &ChannelAst> = previous
        .map(|p| p.channels.iter().map(|c| (c.name.as_str(), c)).collect())
        .unwrap_or_default();
    let mut out: Vec<ChannelChange> = ast
        .channels
        .iter()
        .filter_map(|now| match before.get(now.name.as_str()) {
            None => Some(change(now, ChannelChangeKind::Added, Vec::new())),
            Some(was) => {
                let moved = moved_parts(was, now);
                (!moved.is_empty()).then(|| change(now, ChannelChangeKind::Changed, moved))
            }
        })
        .collect();
    let still: Vec<&str> = ast.channels.iter().map(|c| c.name.as_str()).collect();
    out.extend(
        before
            .values()
            .filter(|c| !still.contains(&c.name.as_str()))
            .map(|c| change(c, ChannelChangeKind::Removed, Vec::new())),
    );
    out
}

fn change(channel: &ChannelAst, kind: ChannelChangeKind, moved: Vec<String>) -> ChannelChange {
    ChannelChange {
        name: channel.name.clone(),
        pattern: channel.pattern.clone(),
        change: kind,
        operations: (kind == ChannelChangeKind::Changed).then_some(moved),
    }
}

fn moved_parts(was: &ChannelAst, now: &ChannelAst) -> Vec<String> {
    [
        ("pattern", was.pattern != now.pattern),
        ("params", was.params != now.params),
        ("join", was.access.join != now.access.join),
        ("send", was.access.send != now.access.send),
        ("track", was.access.track != now.access.track),
    ]
    .into_iter()
    .filter(|(_, moved)| *moved)
    .map(|(name, _)| name.to_string())
    .collect()
}

/// Warnings for what loosens or tightens access: a removed declaration (its topics become
/// undeclared) and a change of mode.
fn change_warnings(mode: ChannelMode, was: ChannelMode, changes: &[ChannelChange]) -> Vec<String> {
    let mut warnings: Vec<String> = changes
        .iter()
        .filter(|c| c.change == ChannelChangeKind::Removed)
        .map(|c| removed_warning(c, mode))
        .collect();
    if was != mode {
        warnings.push(mode_warning(was, mode));
    }
    warnings
}

fn removed_warning(change: &ChannelChange, mode: ChannelMode) -> String {
    let (name, pattern) = (&change.name, &change.pattern);
    match mode {
        ChannelMode::Declared => format!(
            "Channel {name} (\"{pattern}\") is removed. Its topics become undeclared, so \
             broadcast and presence on them are refused (realtime.channels is \"declared\")."
        ),
        ChannelMode::Open => format!(
            "Channel {name} (\"{pattern}\") is removed. Its topics become undeclared, and \
             realtime.channels is \"open\", so anyone who can connect may join, broadcast and \
             track on them."
        ),
    }
}

fn mode_warning(was: ChannelMode, now: ChannelMode) -> String {
    match now {
        ChannelMode::Declared => format!(
            "realtime.channels changes from \"{}\" to \"declared\": broadcast and presence on a \
             channel no declaration matches stop working. Check the Studio realtime inspector \
             for live undeclared channels before pushing.",
            was.as_str()
        ),
        ChannelMode::Open => format!(
            "realtime.channels changes from \"{}\" to \"open\": broadcast and presence on a \
             channel no declaration matches are allowed again.",
            was.as_str()
        ),
    }
}

/// A function whose live body is not what `previous` rendered: edited by hand, or written by an
/// engine that rendered it differently. Either way the push replaces it, and says so. A function
/// the database does not have is not drift.
fn drift_warnings(previous: &SchemaAst, db: &DatabaseState) -> Vec<String> {
    realtime::functions(previous, &db.schema)
        .into_iter()
        .filter(|f| {
            db.realtime_functions
                .get(f.name)
                .is_some_and(|live| *live != f.body)
        })
        .map(|f| {
            format!(
                "_supatype.{} was changed outside Supatype (by hand, or by an older engine). \
                 This push replaces it with what the schema declares.",
                f.name
            )
        })
        .collect()
}
