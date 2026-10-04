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

use std::collections::BTreeMap;

use anyhow::Result;
use sqlx::PgPool;

use crate::desired::ObjectKey;
use crate::differ::doctor::{self, DoctorItem, DoctorReport};
use crate::ledger::{self, reconcile, LedgerRow};
use crate::parser::ast::SchemaAst;
use crate::push;

/// `supatype doctor` on a database. With `rebaseline`, the drift it finds is recorded as the new
/// baseline first and listed as rebaselined.
pub async fn doctor(
    pool: &PgPool,
    ast: &SchemaAst,
    schema: &str,
    rebaseline: bool,
) -> Result<DoctorReport> {
    if rebaseline {
        return self::rebaseline(pool, ast, schema).await;
    }
    let mut conn = pool.acquire().await?;
    let (state, decision) = push::read_and_decide(&mut conn, pool, ast, schema).await?;
    Ok(doctor::report_of(ast, &state, &decision))
}

/// Records every drifted object's live definition as its baseline, in one transaction, and returns
/// the report with those objects moved from `drifted` to `rebaselined`.
pub async fn rebaseline(pool: &PgPool, ast: &SchemaAst, schema: &str) -> Result<DoctorReport> {
    let mut tx = pool.begin().await?;
    let (state, decision) = push::read_and_decide(&mut tx, pool, ast, schema).await?;
    let mut report = doctor::report_of(ast, &state, &decision);
    let rows: BTreeMap<&ObjectKey, &LedgerRow> = state.ledger.iter().map(|r| (&r.key, r)).collect();
    let (moved, items): (Vec<LedgerRow>, Vec<DoctorItem>) = decision
        .reconcile
        .actions
        .iter()
        .filter_map(|action| rebaselined(action, &rows))
        .unzip();
    ledger::upsert(&mut tx, &moved).await?;
    tx.commit().await?;
    // Drift is a row's live definition moving, so every drifted object had a row and was recorded.
    report.drifted.clear();
    report.rebaselined = items;
    report.blocking = doctor::has_strict_issues(&report);
    Ok(report)
}

/// For a drifted object: its row holding what the database holds now, and the item that says so.
fn rebaselined(
    action: &reconcile::Action,
    rows: &BTreeMap<&ObjectKey, &LedgerRow>,
) -> Option<(LedgerRow, DoctorItem)> {
    let reconcile::Action::Drift {
        key,
        recorded_def,
        live_def,
        live_fp,
        ..
    } = action
    else {
        return None;
    };
    let row = LedgerRow {
        live_fp: live_fp.clone(),
        live_def: live_def.clone(),
        ..(*rows.get(key)?).clone()
    };
    let mut item = DoctorItem::about(
        key,
        "is recorded as it is now: a push leaves it until the schema changes it",
    );
    item.recorded = Some(recorded_def.clone());
    item.live = Some(live_def.clone());
    Some((row, item))
}
