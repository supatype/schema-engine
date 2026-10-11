//! `supatype doctor`, and `doctor --rebaseline` (plan sections 8 and 3.2), on a database read the
//! way a push reads it (`push::read_state`).
//!
//! Rebaselining accepts what the database holds now. The structural fingerprint can still move
//! with no change of meaning: a Postgres major upgrade that deparses an expression differently
//! makes every object it touched read as drifted, and the next push would put each one back
//! (asking first for access rules). Rebaselining records each drifted object's live fingerprint
//! and definition as the new baseline, changing no object, and reports every one it moved,
//! recorded beside live, so it is never silent. It is the drift doctor shows, taken as intended;
//! anything else (a missing object, a conflict) is left to a push.
//!
//! Drift on what decides access (a policy, grant, security label or RLS attribute) is a hand edit
//! a push would ask about before overwriting (plan 3.5), and rebaselining it would make the hand
//! edit Supatype's own without anyone having looked. So it is rebaselined only with consent of its
//! own, `--accept-access-drift` (HTTP `accept_access_drift`); without it each one is left drifted
//! and listed as refused. The push's `--overwrite-drift` puts Supatype's definition back, the
//! opposite of accepting the hand edit, so doctor refuses it rather than reading it as this.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use sqlx::PgPool;

use crate::adopt::parse_object;
use crate::desired::{security_relevant, ObjectKey};
use crate::differ::doctor::{self, DoctorItem, DoctorReport};
use crate::ledger::{self, reconcile, LedgerRow};
use crate::parser::ast::SchemaAst;
use crate::push;

/// `supatype doctor` on a database. With `rebaseline`, the drift it finds is recorded as the new
/// baseline first and listed as rebaselined, except drift on access ([`rebaseline`] without
/// consent).
pub async fn doctor(
    pool: &PgPool,
    ast: &SchemaAst,
    schema: &str,
    rebaseline: bool,
) -> Result<DoctorReport> {
    if rebaseline {
        return self::rebaseline(pool, ast, schema, false).await;
    }
    let mut conn = pool.acquire().await?;
    let (state, decision) = push::read_and_decide(&mut conn, pool, ast, schema).await?;
    Ok(doctor::report_of(ast, &state, &decision))
}

/// Records every drifted object's live definition as its baseline, in one transaction, and returns
/// the report with those objects moved from `drifted` to `rebaselined`. Drift on access is recorded
/// only with `accept_access_drift`; without it, it stays under `drifted` and is listed under
/// `rebaseline_refused`.
pub async fn rebaseline(
    pool: &PgPool,
    ast: &SchemaAst,
    schema: &str,
    accept_access_drift: bool,
) -> Result<DoctorReport> {
    rebaseline_previewed(pool, ast, schema, accept_access_drift, None).await
}

/// [`rebaseline`], of exactly the drift a person was shown (F22). `previewed` names the drifted
/// objects the preview listed, as doctor and `adopt` name them (`kind:table.name`); if the drift
/// found now is not that set, an object drifted since or one put back since, nothing is written
/// and the refusal is a [`DriftChangedSincePreview`] naming the difference. `None` records
/// whatever drift there is when it runs.
pub async fn rebaseline_previewed(
    pool: &PgPool,
    ast: &SchemaAst,
    schema: &str,
    accept_access_drift: bool,
    previewed: Option<&[String]>,
) -> Result<DoctorReport> {
    let mut tx = pool.begin().await?;
    // As a push does: these are ledger writes too.
    push::take_engine_lock(&mut tx).await?;
    push::take_push_lock(&mut tx).await?;
    let (state, decision) = push::read_and_decide(&mut tx, pool, ast, schema).await?;
    let rows: BTreeMap<&ObjectKey, &LedgerRow> = state.ledger.iter().map(|r| (&r.key, r)).collect();
    let drift: Vec<(&ObjectKey, LedgerRow, DoctorItem)> = decision
        .reconcile
        .actions
        .iter()
        .filter_map(|action| rebaselined(action, &rows))
        .collect();
    if let Some(previewed) = previewed {
        DriftChangedSincePreview::check(previewed, drift.iter().map(|(key, ..)| *key))?;
    }
    let mut report = doctor::report_of(ast, &state, &decision);
    let moved = sort_out(drift, accept_access_drift, &mut report);
    ledger::upsert(&mut tx, &moved).await?;
    tx.commit().await?;
    // Drift is a row's live definition moving, so every drifted object had a row; those recorded
    // are drifted no longer.
    let same = |a: &DoctorItem, b: &DoctorItem| {
        (&a.kind, &a.table, &a.name) == (&b.kind, &b.table, &b.name)
    };
    let rebaselined = &report.rebaselined;
    report
        .drifted
        .retain(|item| !rebaselined.iter().any(|r| same(r, item)));
    report.blocking = doctor::has_strict_issues(&report);
    Ok(report)
}

/// The rows to record, with each listed in `report` as rebaselined, or as refused where it decides
/// access and `accept_access_drift` was not given.
fn sort_out(
    drift: Vec<(&ObjectKey, LedgerRow, DoctorItem)>,
    accept_access_drift: bool,
    report: &mut DoctorReport,
) -> Vec<LedgerRow> {
    let mut moved = Vec::new();
    for (key, row, item) in drift {
        if security_relevant(key) && !accept_access_drift {
            let mut refused = DoctorItem::about(
                key,
                "decides who may read or write and was changed outside Supatype: not \
                 rebaselined without --accept-access-drift, so a push still asks before putting \
                 it back",
            );
            refused.recorded = item.recorded;
            refused.live = item.live;
            report.rebaseline_refused.push(refused);
            continue;
        }
        moved.push(row);
        report.rebaselined.push(item);
    }
    moved
}

/// The stable name a caller matches a [`DriftChangedSincePreview`] refusal on, in the engine's
/// JSON output and the server's response.
pub const DRIFT_CHANGED: &str = "drift_changed";

/// A rebaseline refused because the drift it found is not the drift its preview showed: the
/// person agreed to record what they saw, and something else has moved since (C04). Nothing was
/// written. Both lists name objects as the preview does.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DriftChangedSincePreview {
    /// Drifted now, and not in the preview.
    pub unseen: Vec<String>,
    /// In the preview, and not drifted now.
    pub gone: Vec<String>,
}

impl DriftChangedSincePreview {
    /// Refuses unless `found` is exactly the set `previewed` names.
    fn check<'k>(
        previewed: &[String],
        found: impl Iterator<Item = &'k ObjectKey>,
    ) -> std::result::Result<(), DriftChangedSincePreview> {
        let found: BTreeSet<String> = found.map(spec).collect();
        let mut shown = BTreeSet::new();
        for name in previewed {
            // A name that is not an object cannot be drifted now, so it is one that has gone.
            shown.insert(parse_object(name).map(|k| spec(&k)).unwrap_or(name.clone()));
        }
        let changed = DriftChangedSincePreview {
            unseen: found.difference(&shown).cloned().collect(),
            gone: shown.difference(&found).cloned().collect(),
        };
        if changed.unseen.is_empty() && changed.gone.is_empty() {
            Ok(())
        } else {
            Err(changed)
        }
    }
}

/// `kind:table.name`, or `kind:name` for a table-level object: how doctor and `adopt` name one.
fn spec(key: &ObjectKey) -> String {
    if key.parent.is_empty() {
        format!("{}:{}", key.kind.as_str(), key.name)
    } else {
        format!("{}:{}.{}", key.kind.as_str(), key.parent, key.name)
    }
}

impl std::fmt::Display for DriftChangedSincePreview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let list = |names: &[String]| match names {
            [] => "none".to_string(),
            names => names.join(", "),
        };
        write!(
            f,
            "The drift changed after the preview, so nothing was rebaselined. Drifted since: {}. \
             No longer drifted: {}. Run the rebaseline again to review the drift as it is now.",
            list(&self.unseen),
            list(&self.gone)
        )
    }
}

impl std::error::Error for DriftChangedSincePreview {}

/// Why a doctor request's consent flags are refused, if they are: `overwrite_drift` is the push's
/// (put Supatype's definition back), and the consent to take drift on access as the baseline is
/// `accept_access_drift`, which only means anything with `rebaseline`.
pub fn doctor_flags_refusal(
    rebaseline: bool,
    accept_access_drift: bool,
    overwrite_drift: bool,
) -> Option<&'static str> {
    if overwrite_drift {
        return Some(
            "--overwrite-drift (overwrite_drift) is a push option: it puts Supatype's definitions \
             back. To record drift on policies, grants, labels and RLS as the new baseline, run \
             doctor --rebaseline --accept-access-drift (HTTP: rebaseline with \
             accept_access_drift: true).",
        );
    }
    if accept_access_drift && !rebaseline {
        return Some(
            "--accept-access-drift (accept_access_drift) only applies with --rebaseline \
             (rebaseline: true).",
        );
    }
    None
}

/// For a drifted object (put back, or replaced as well because the schema changed it): its row
/// holding what the database holds now, and the item that says so.
fn rebaselined<'a>(
    action: &'a reconcile::Action,
    rows: &BTreeMap<&ObjectKey, &LedgerRow>,
) -> Option<(&'a ObjectKey, LedgerRow, DoctorItem)> {
    let (key, recorded_def, live_def, live_fp, next) = match action {
        reconcile::Action::Drift {
            key,
            recorded_def,
            live_def,
            live_fp,
            ..
        } => (
            key,
            recorded_def,
            live_def,
            live_fp,
            "is recorded as it is now: a push leaves it until the schema changes it",
        ),
        reconcile::Action::Replace {
            key,
            drifted: Some(edit),
            ..
        } => (
            key,
            &edit.recorded_def,
            &edit.live_def,
            &edit.live_fp,
            "is recorded as it is now: a push replaces it with the schema's changed definition",
        ),
        _ => return None,
    };
    let row = LedgerRow {
        live_fp: live_fp.clone(),
        live_def: live_def.clone(),
        ..(*rows.get(key)?).clone()
    };
    let mut item = DoctorItem::about(key, next);
    item.recorded = Some(recorded_def.clone());
    item.live = Some(live_def.clone());
    Some((key, row, item))
}
