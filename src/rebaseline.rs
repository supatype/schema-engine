//! `supatype doctor --rebaseline` (plan section 3.2): accept what the database holds now.
//!
//! The structural fingerprint can still move with no change of meaning: a Postgres major upgrade
//! that deparses an expression differently makes every object it touched read as drifted, and the
//! next push would put each one back (asking first for access rules). Rebaselining records each
//! drifted object's live fingerprint and definition as the new baseline, changing no object, and
//! reports every one it moved, recorded beside live, so it is never silent. It is the drift doctor
//! shows, taken as intended; anything else (a missing object, a conflict) is left to a push.

use anyhow::Result;
use sqlx::PgPool;

use crate::differ::doctor::{self, DoctorItem, DoctorReport};
use crate::ledger::{self, reconcile, LedgerRow};
use crate::parser::ast::SchemaAst;

/// Records every drifted object's live definition as its baseline, in one transaction, and returns
/// the report with those objects moved from `drifted` to `rebaselined`.
pub async fn run(pool: &PgPool, ast: &SchemaAst, schema: &str) -> Result<DoctorReport> {
    let mut tx = pool.begin().await?;
    let (db, catalog, rows) = crate::adopt::read_state(&mut tx, schema).await?;
    let (plan, mut report) = doctor::plan_and_report(ast, &db, &catalog, &rows)?;
    let (moved, items): (Vec<LedgerRow>, Vec<DoctorItem>) = plan
        .actions
        .iter()
        .filter_map(|action| rebaselined(action, &rows))
        .unzip();
    ledger::upsert(&mut tx, &moved).await?;
    tx.commit().await?;
    report.drifted.retain(|d| {
        !items
            .iter()
            .any(|i| i.kind == d.kind && i.table == d.table && i.name == d.name)
    });
    report.rebaselined = items;
    Ok(report)
}

/// For a drifted object: its row holding what the database holds now, and the item that says so.
fn rebaselined(action: &reconcile::Action, rows: &[LedgerRow]) -> Option<(LedgerRow, DoctorItem)> {
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
    let row = rows.iter().find(|r| &r.key == key)?;
    let mut item = DoctorItem::for_key(
        key,
        format!(
            "{} is recorded as it is now: a push leaves it until the schema changes it",
            doctor::label(key)
        ),
    );
    item.recorded = Some(recorded_def.clone());
    item.live = Some(live_def.clone());
    let row = LedgerRow {
        live_fp: live_fp.clone(),
        live_def: live_def.clone(),
        ..row.clone()
    };
    Some((row, item))
}
