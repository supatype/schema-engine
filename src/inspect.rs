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
    // What another session holds exclusively is left out of the read rather than waited on, and
    // reported as not checked (IN-B).
    let held = held_exclusively(&mut conn).await?;
    set_unreadable(&mut conn, &held).await?;
    let decided = push::read_and_decide(&mut conn, ast, schema).await;
    set_unreadable(&mut conn, &[]).await?;
    let (state, decision) = match decided {
        Ok(decided) => decided,
        Err(e) => return Err(push::busy_if_waiting_on_a_writer(pool, e).await),
    };
    let mut report = doctor::report_of(ast, &state, &decision);
    not_checked(&mut report, &held, schema);
    report
        .missing
        .extend(missing_studio_objects(&mut conn).await?);
    report.notes.extend(scheduling_note(&mut conn, ast).await?);
    report.blocking = doctor::has_strict_issues(&report);
    Ok(report)
}

/// Studio's objects that are not there (CC4). The engine's setup makes them, and runs again only
/// when the engine changes, so one dropped by hand stays missing until someone makes it run.
async fn missing_studio_objects(conn: &mut sqlx::PgConnection) -> Result<Vec<DoctorItem>> {
    let (kinds, signatures): (Vec<&str>, Vec<&str>) = crate::state::studio_state::STUDIO_OBJECTS
        .iter()
        .copied()
        .unzip();
    let missing: Vec<(String, String)> = sqlx::query_as(
        "SELECT o.kind, o.signature FROM unnest($1::text[], $2::text[]) AS o(kind, signature)
          WHERE (CASE WHEN o.kind = 'function' THEN to_regprocedure(o.signature)::oid
                      ELSE to_regclass(o.signature)::oid END) IS NULL",
    )
    .bind(&kinds)
    .bind(&signatures)
    .fetch_all(&mut *conn)
    .await?;
    Ok(missing
        .iter()
        .map(|(kind, signature)| missing_studio_object(kind, signature))
        .collect())
}

/// The item for the Studio object `signature` (a `kind`) that is not there.
fn missing_studio_object(kind: &str, signature: &str) -> DoctorItem {
    use crate::introspector::fingerprint::ObjectKind;
    let (schema, name) = signature.split_once('.').unwrap_or(("", signature));
    let key = ObjectKey {
        kind: if kind == "function" {
            ObjectKind::Function
        } else {
            ObjectKind::Table
        },
        schema: schema.to_string(),
        parent: schema.to_string(),
        name: name.to_string(),
    };
    DoctorItem::for_key(
        &key,
        format!(
            "The Studio {kind} {signature} is missing, so the Studio features that use it fail. \
             The engine's setup makes it, and runs again only when the engine changes: to make it \
             now, run `DELETE FROM _supatype.engine_bootstrap;` and push again"
        ),
    )
}

/// The note for a copy of a database (a branch, a restore under a new name) whose schema publishes
/// on a schedule (CC5): pg_cron runs only the jobs of the database `cron.database_name` names, so
/// here a scheduled publish is recorded and never runs.
async fn scheduling_note(
    conn: &mut sqlx::PgConnection,
    ast: &SchemaAst,
) -> Result<Option<DoctorItem>> {
    let scheduled = !crate::generator::sql::versions::versioned_models(ast).is_empty();
    if !scheduled {
        return Ok(None);
    }
    let (database, cron_database, installed): (String, Option<String>, bool) = sqlx::query_as(
        "SELECT current_database()::text, current_setting('cron.database_name', true),
                EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron')",
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(cron_runs_elsewhere(
        &database,
        cron_database.as_deref(),
        installed,
    ))
}

/// The CC5 note, when pg_cron is installed here and runs another database's jobs.
fn cron_runs_elsewhere(
    database: &str,
    cron_database: Option<&str>,
    installed: bool,
) -> Option<DoctorItem> {
    let cron_database = cron_database.filter(|d| !d.is_empty() && *d != database)?;
    if !installed {
        return None;
    }
    let key = ObjectKey {
        kind: crate::introspector::fingerprint::ObjectKind::CronJob,
        schema: String::new(),
        parent: String::new(),
        name: "supatype-scheduled-publish".to_string(),
    };
    Some(DoctorItem::for_key(
        &key,
        format!(
            "Scheduled publishing is recorded here but never runs: pg_cron runs only the jobs of \
             database {cron_database} (cron.database_name), and this is {database}, a copy of it \
             such as a branch or a restore. Call _supatype.run_due_publishes() from a scheduler \
             of your own, or point cron.database_name at this database"
        ),
    ))
}

/// A relation another session holds in ACCESS EXCLUSIVE, or a view reading one: reading its
/// deparsed parts would wait on that session.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    oid: i64,
    schema: String,
    name: String,
    pid: i32,
}

/// Every relation of this database another session holds in ACCESS EXCLUSIVE, and every view
/// reading one, with the session. From `pg_locks`, which takes no lock.
async fn held_exclusively(conn: &mut sqlx::PgConnection) -> Result<Vec<Held>> {
    let rows: Vec<(i64, String, String, i32)> = sqlx::query_as(
        "WITH held AS (
           SELECT l.relation, l.pid FROM pg_locks l
            WHERE l.locktype = 'relation' AND l.granted AND l.mode = 'AccessExclusiveLock'
              AND l.pid <> pg_backend_pid()
              AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database()))
         SELECT c.oid::bigint, n.nspname::text, c.relname::text, h.pid
           FROM held h JOIN pg_class c ON c.oid = h.relation
           JOIN pg_namespace n ON n.oid = c.relnamespace
         UNION
         SELECT v.oid::bigint, n.nspname::text, v.relname::text, h.pid
           FROM held h
           JOIN pg_depend d ON d.refobjid = h.relation AND d.classid = 'pg_rewrite'::regclass
           JOIN pg_rewrite r ON r.oid = d.objid
           JOIN pg_class v ON v.oid = r.ev_class AND v.oid <> h.relation
           JOIN pg_namespace n ON n.oid = v.relnamespace",
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(oid, schema, name, pid)| Held {
            oid,
            schema,
            name,
            pid,
        })
        .collect())
}

/// Names `held` in the session setting the introspection leaves out ([`crate::introspector::UNREADABLE`]),
/// or clears it.
async fn set_unreadable(conn: &mut sqlx::PgConnection, held: &[Held]) -> Result<()> {
    let oids: Vec<String> = held.iter().map(|h| h.oid.to_string()).collect();
    sqlx::query("SELECT set_config($1, $2, false)")
        .bind(crate::introspector::UNREADABLE)
        .bind(oids.join(","))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Moves every finding about a relation in `held` to `not_checked`: it was left out of the read,
/// so it reads as missing or changed when it was only not looked at. A held table of `schema` with
/// no finding is listed too, so the report says what it did not read.
fn not_checked(report: &mut DoctorReport, held: &[Held], schema: &str) {
    if held.is_empty() {
        return;
    }
    let sections = [
        &mut report.missing,
        &mut report.stale_managed,
        &mut report.unmanaged_drift,
        &mut report.drifted,
        &mut report.conflicting,
        &mut report.claimed,
        &mut report.pending,
    ];
    let mut unread = Vec::new();
    for items in sections {
        unread.extend(take_unread(items, held));
    }
    report.not_checked.extend(unread);
    for h in held.iter().filter(|h| h.schema == schema) {
        if !report.not_checked.iter().any(|i| i.table == h.name) {
            let item = DoctorItem::for_key(
                &ObjectKey {
                    kind: crate::introspector::fingerprint::ObjectKind::Table,
                    schema: h.schema.clone(),
                    parent: String::new(),
                    name: h.name.clone(),
                },
                unread_message("table", &h.name, &h.name, h.pid),
            );
            report.not_checked.push(item);
        }
    }
    report.blocking = doctor::has_strict_issues(report);
}

/// Takes the items about a relation in `held` out of `items`, each said as not checked.
fn take_unread(items: &mut Vec<DoctorItem>, held: &[Held]) -> Vec<DoctorItem> {
    let holder = |item: &DoctorItem| {
        held.iter()
            .find(|h| h.name == item.table || h.name == item.name)
            .map(|h| h.pid)
    };
    let (unread, read): (Vec<DoctorItem>, Vec<DoctorItem>) = std::mem::take(items)
        .into_iter()
        .partition(|i| holder(i).is_some());
    *items = read;
    unread
        .into_iter()
        .map(|mut item| {
            let pid = holder(&item).unwrap_or_default();
            item.message = unread_message(&item.kind, &item.table, &item.name, pid);
            item.recorded = None;
            item.live = None;
            item
        })
        .collect()
}

fn unread_message(kind: &str, table: &str, name: &str, pid: i32) -> String {
    let what = doctor::kind_words(kind);
    let object = if table == name {
        name.to_string()
    } else {
        format!("{table}.{name}")
    };
    format!(
        "{what} {object} not checked (lock held by pid {pid}): another session holds {table} \
         exclusively; run doctor again once it is done"
    )
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
    // As a push does: these are ledger writes too. A person is waiting: a lock it cannot take at
    // once is named, not retried (LK1).
    let (mut tx, pid) = push::begin_watched_writer(pool).await?;
    let work = async move {
        let (state, decision) = push::read_and_decide(&mut tx, ast, schema).await?;
        let rows: BTreeMap<&ObjectKey, &LedgerRow> =
            state.ledger.iter().map(|r| (&r.key, r)).collect();
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
        Ok(report)
    };
    let mut report = crate::online::fail_fast(pool, pid, "rebaseline", work).await?;
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

#[cfg(test)]
mod tests {
    use super::cron_runs_elsewhere;

    /// CC5: the note appears only where pg_cron is installed and runs another database's jobs.
    #[test]
    fn a_copy_whose_jobs_pg_cron_runs_elsewhere_gets_the_note() {
        let note = cron_runs_elsewhere("branch_1", Some("postgres"), true).expect("a note");
        assert!(note.message.contains("never runs"), "{}", note.message);
        assert!(note.message.contains("branch_1"), "{}", note.message);
        assert!(cron_runs_elsewhere("postgres", Some("postgres"), true).is_none());
        assert!(cron_runs_elsewhere("branch_1", Some("postgres"), false).is_none());
        assert!(cron_runs_elsewhere("branch_1", None, true).is_none());
    }
}
