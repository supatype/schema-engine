//! `supatype adopt` (plan section 8): handing objects to Supatype, and taking them back.
//!
//! Adopting never edits an object. It writes the ledger row a push refuses without: one for each
//! object under a name the schema needs that Supatype did not create (the reconcile's conflicts),
//! with status `adopted`. The row records the object as it is as what was intended, so the next
//! push brings it to the schema's definition (replacing it, or for a table letting the table
//! differ converge its columns), and a rollback of that push restores the user's version.
//!
//! `--release` marks a row `released`, adding one for an object that has none, and every push
//! leaves it alone whatever the schema says (section 3.3). It is how a hand edit is kept (3.5).

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sqlx::PgPool;

use crate::desired::DesiredObject;
use crate::differ::doctor::{self, DoctorItem, DoctorReport};
use crate::introspector::fingerprint::{ObjectFingerprint, ObjectKey, ObjectKind};
use crate::ledger::{self, desired_fingerprint, reconcile, LedgerRow, Status};
use crate::parser::ast::SchemaAst;
use crate::push::{self, Decision, State};
use crate::state::migration_history;

/// What `adopt` would do, or did.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    /// `preview` until applied; then `adopted` when anything was adopted, otherwise `released`,
    /// `reclaimed` or `released_and_reclaimed`, or `nothing_to_adopt` when nothing was written.
    pub status: &'static str,
    /// The objects handed over: what a push refuses because their names are taken.
    pub adopt: Vec<DoctorItem>,
    /// The objects taken back.
    pub release: Vec<DoctorItem>,
    /// Released objects handed back to Supatype.
    pub reclaim: Vec<DoctorItem>,
    /// The whole report, for context.
    pub doctor: DoctorReport,
}

/// What to do beyond adopting the conflicts. Objects are named as doctor prints them: `kind:name`
/// for a table-level object, `kind:table.name` otherwise.
#[derive(Debug, Default, Clone, Copy)]
pub struct Request<'a> {
    /// Objects every push should leave alone from now on.
    pub release: &'a [String],
    /// Released objects to hand back, so the next push brings them to the schema again.
    pub reclaim: &'a [String],
    /// Write the rows; without it, a preview.
    pub apply: bool,
    /// The conflicts the preview showed, named the same way: only these are adopted, and if any
    /// of them is no longer a conflict nothing is written, since the database is not the one
    /// previewed. A key may also name a column added outside the schema (`column:table.name`),
    /// which is adopted only when named. `None` adopts whatever conflicts there are when it runs.
    pub keys: Option<&'a [String]>,
}

/// Reads, decides, and with `request.apply` writes the rows, in one transaction.
///
/// Bootstraps first, as a push does: adopt is the first command a project on an existing database
/// runs, so the engine's tables may not exist yet. The project schema is checked as the state is
/// read, inside the transaction that writes (`push::read_state`).
pub async fn run(
    pool: &PgPool,
    ast: &SchemaAst,
    schema: &str,
    request: Request<'_>,
) -> Result<Outcome> {
    migration_history::bootstrap_internal_state(pool)
        .await
        .context("Failed to bootstrap _supatype internal state")?;
    // As a push does: these are ledger writes too. A preview writes nothing and takes no lock.
    let mut tx = if request.apply {
        push::begin_writer(pool).await?
    } else {
        pool.begin().await?
    };
    let (state, decision) = push::read_and_decide(&mut tx, ast, schema).await?;
    let (outcome, changes, forgotten) = choose(ast, &state, &decision, request)?;
    if request.apply {
        ledger::upsert(&mut tx, &changes).await?;
        ledger::delete(&mut tx, &forgotten).await?;
        tx.commit().await?;
    }
    Ok(outcome)
}

/// The rows adopting would write and those it would remove, and the outcome that says so.
/// Releasing wins over adopting a conflict; an object named both to release and to reclaim is
/// refused; one named twice is written once.
fn choose(
    ast: &SchemaAst,
    state: &State,
    decision: &Decision,
    request: Request<'_>,
) -> Result<(Outcome, Vec<LedgerRow>, Vec<ObjectKey>)> {
    let plan = &decision.reconcile;
    let report = doctor::report_of(ast, state, decision);
    let live: BTreeMap<ObjectKey, &ObjectFingerprint> =
        state.fingerprints.iter().map(|f| (f.key(), f)).collect();
    let released = rows_named(request.release, |spec| {
        released_row(spec, &state.ledger, &live, plan)
    })?;
    let reclaimed = rows_named(request.reclaim, |spec| {
        reclaimed_row(spec, &state.ledger, &live, &decision.desired)
    })?;
    if let Some(both) = released
        .iter()
        .find(|r| reclaimed.iter().any(|c| c.key == r.key))
    {
        bail!(
            "{} is named both to release and to reclaim: choose one",
            both.key
        );
    }
    let columns = undeclared_columns(ast, state, decision);
    let mut adopted = adopted_rows(plan, &live, &columns, request.keys)?;
    adopted.retain(|a| !released.iter().any(|r| r.key == a.key));
    let outcome = Outcome {
        status: status(
            request.apply,
            !adopted.is_empty(),
            !released.is_empty(),
            !reclaimed.is_empty(),
        ),
        adopt: items(
            &adopted,
            "will be Supatype's: the next push makes it match the schema",
        ),
        release: items(
            &released,
            "will be left alone by every push, whatever the schema says",
        ),
        reclaim: items(
            &reclaimed,
            "will be Supatype's again: the next push brings it to the schema, and a change made \
             while it was released is a change made outside Supatype, which for an access rule \
             the push asks about first",
        ),
        doctor: report,
    };
    // A reclaimed row with no record of an object that is not there is no row: the next push
    // creates the object, as it would one it never knew.
    let (forgotten, reclaimed): (Vec<LedgerRow>, Vec<LedgerRow>) = reclaimed
        .into_iter()
        .partition(|r| records_nothing(r) && !live.contains_key(&r.key));
    let forgotten = forgotten.into_iter().map(|r| r.key).collect();
    Ok((outcome, [adopted, released, reclaimed].concat(), forgotten))
}

/// The row for each object `specs` names, each object once however often it is named.
fn rows_named(specs: &[String], row: impl Fn(&str) -> Result<LedgerRow>) -> Result<Vec<LedgerRow>> {
    let mut rows: Vec<LedgerRow> = Vec::new();
    for spec in specs {
        let next = row(spec)?;
        if !rows.iter().any(|r| r.key == next.key) {
            rows.push(next);
        }
    }
    Ok(rows)
}

/// The released row `spec` names, handed back as `adopted`. A row with a record keeps it, so the
/// next push treats the object as any of Supatype's: puts back a hand edit made while it was
/// released (asking first for access rules), or replaces what it recorded with what the schema
/// declares.
///
/// A row released before the object existed records nothing. If the object is there now, it is
/// recorded as it was found, as `adopt` records one, so a rollback of the next push puts it back:
/// but with no live fingerprint, since Supatype never applied it, unless it already is what the
/// schema declares. Whatever the push would do to it then reads as overwriting a change made
/// outside Supatype, which for an access rule needs consent, rather than an ordinary replacement.
/// If it is not there, the row records nothing still and is removed on apply.
fn reclaimed_row(
    spec: &str,
    rows: &[LedgerRow],
    live: &BTreeMap<ObjectKey, &ObjectFingerprint>,
    desired: &[DesiredObject],
) -> Result<LedgerRow> {
    let wanted = parse_object(spec)?;
    let released = rows.iter().filter(|r| r.status == Status::Released);
    let key = resolve(spec, &wanted, released.map(|r| &r.key), "released")?;
    let row = rows
        .iter()
        .find(|r| r.key == key)
        .expect("resolved from the ledger's own rows");
    if !records_nothing(row) {
        return Ok(LedgerRow {
            status: Status::Adopted,
            ..row.clone()
        });
    }
    let Some(l) = live.get(&key) else {
        return Ok(LedgerRow {
            status: Status::Adopted,
            ..row.clone()
        });
    };
    let found = as_found(l, Status::Adopted);
    let declared = desired
        .iter()
        .any(|d| d.key == key && found.intends(&d.create_sql));
    Ok(LedgerRow {
        live_fp: if declared {
            found.live_fp.clone()
        } else {
            String::new()
        },
        ..found
    })
}

/// A row released before its object existed: it says only that the object is released.
fn records_nothing(row: &LedgerRow) -> bool {
    row.desired_sql.is_empty() && row.live_fp.is_empty()
}

/// What an applied run did: `adopted` when it adopted anything, otherwise `released`,
/// `reclaimed` or both, and `nothing_to_adopt` when it wrote nothing.
fn status(apply: bool, adopted: bool, released: bool, reclaimed: bool) -> &'static str {
    match (apply, adopted, released, reclaimed) {
        (false, ..) => "preview",
        (true, true, ..) => "adopted",
        (true, false, true, true) => "released_and_reclaimed",
        (true, false, true, false) => "released",
        (true, false, false, true) => "reclaimed",
        (true, false, false, false) => "nothing_to_adopt",
    }
}

fn items(rows: &[LedgerRow], consequence: &str) -> Vec<DoctorItem> {
    rows.iter()
        .map(|r| DoctorItem::about(&r.key, consequence))
        .collect()
}

/// The columns someone added to a model table of ours that the schema does not declare and the
/// ledger has no row for: Supatype leaves them alone (D4), and `adopt` takes one only when it is
/// named, so that a field rule's narrowed write grant includes it (#63).
fn undeclared_columns(ast: &SchemaAst, state: &State, decision: &Decision) -> Vec<ObjectKey> {
    let desired: Vec<&ObjectKey> = decision.desired.iter().map(|d| &d.key).collect();
    state
        .fingerprints
        .iter()
        .map(ObjectFingerprint::key)
        .filter(|k| {
            k.kind == ObjectKind::Column
                && k.schema == state.db.schema
                && ast.models.iter().any(|m| m.table_name() == k.parent)
                && state
                    .db
                    .tables
                    .iter()
                    .any(|t| t.name == k.parent && state.db.owns_table(t))
                && !desired.contains(&k)
                && !state.ledger.iter().any(|r| r.key == *k)
        })
        .collect()
}

/// A row for each conflict: the object under a name the schema needs, recorded as it is. With
/// `keys`, only the conflicts they name, and none at all if one of them is not a conflict now; a
/// key may also name one of `columns`, a column added outside the schema, which is adopted only
/// when named.
fn adopted_rows(
    plan: &reconcile::Plan,
    live: &BTreeMap<ObjectKey, &ObjectFingerprint>,
    columns: &[ObjectKey],
    keys: Option<&[String]>,
) -> Result<Vec<LedgerRow>> {
    let conflicts = plan.conflicts().map(reconcile::Action::key);
    let chosen: Vec<ObjectKey> = match keys {
        None => conflicts.cloned().collect(),
        Some(specs) => {
            let conflicts: Vec<&ObjectKey> = conflicts.chain(columns).collect();
            let mut chosen = Vec::new();
            for spec in specs {
                let wanted = parse_object(spec)?;
                let key = resolve(spec, &wanted, conflicts.iter().copied(), "conflicting")
                    .with_context(|| {
                        format!(
                            "{spec} was to be adopted but is not a conflict now: the database \
                             changed since the preview. Nothing was written; run `supatype adopt` \
                             again to see what it would adopt now"
                        )
                    })?;
                if !chosen.contains(&key) {
                    chosen.push(key);
                }
            }
            chosen
        }
    };
    Ok(chosen
        .iter()
        .filter_map(|key| live.get(key).map(|l| as_found(l, Status::Adopted)))
        .collect())
}

/// `live` as it is, as what was intended: its own definition, so the next push replaces it with the
/// schema's, and a rollback of that push puts it back.
fn as_found(live: &ObjectFingerprint, status: Status) -> LedgerRow {
    let sql = live.create_sql.clone().unwrap_or_default();
    LedgerRow {
        key: live.key(),
        desired_fp: desired_fingerprint(live.kind, &sql),
        desired_sql: sql,
        live_fp: live.fingerprint.clone(),
        live_def: live.definition.clone(),
        status,
        migration_id: None,
    }
}

/// The row that releases the object `spec` names: its own row if it has one, else one recording
/// it as it is, else (an object the push would create) one that says only that it is released.
fn released_row(
    spec: &str,
    rows: &[LedgerRow],
    live: &BTreeMap<ObjectKey, &ObjectFingerprint>,
    plan: &reconcile::Plan,
) -> Result<LedgerRow> {
    let wanted = parse_object(spec)?;
    let known = rows
        .iter()
        .map(|r| &r.key)
        .chain(live.keys())
        .chain(plan.actions.iter().map(reconcile::Action::key));
    let key = resolve(spec, &wanted, known, "to release")?;
    if let Some(row) = rows.iter().find(|r| r.key == key) {
        return Ok(LedgerRow {
            status: Status::Released,
            ..row.clone()
        });
    }
    if let Some(l) = live.get(&key) {
        return Ok(as_found(l, Status::Released));
    }
    Ok(LedgerRow {
        key,
        desired_fp: String::new(),
        desired_sql: String::new(),
        live_fp: String::new(),
        live_def: String::new(),
        status: Status::Released,
        migration_id: None,
    })
}

/// The one known object with `wanted`'s kind, parent and name, in whatever schema it lives.
/// `which` says what was being looked for ("to release", "released"), for the error.
fn resolve<'k>(
    spec: &str,
    wanted: &ObjectKey,
    known: impl Iterator<Item = &'k ObjectKey>,
    which: &str,
) -> Result<ObjectKey> {
    let mut matches: Vec<&ObjectKey> = known
        .filter(|k| k.kind == wanted.kind && k.parent == wanted.parent && k.name == wanted.name)
        .collect();
    matches.sort_by(|a, b| a.schema.cmp(&b.schema));
    matches.dedup();
    match matches.as_slice() {
        [one] => Ok((*one).clone()),
        [] => bail!("nothing {which} is named {spec:?}: run `supatype doctor` for the names"),
        many => bail!(
            "{spec:?} names {} objects, one per schema ({}); adopt is not yet able to tell them apart",
            many.len(),
            many.iter().map(|k| k.schema.as_str()).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// `kind:name` or `kind:table.name`, as doctor prints an object. The schema is found, not given.
pub fn parse_object(spec: &str) -> Result<ObjectKey> {
    let Some((kind_text, path)) = spec.split_once(':') else {
        bail!("{spec:?} is not `kind:table.name` (or `kind:name` for a table-level object)");
    };
    let Some(kind) = ObjectKind::parse(kind_text) else {
        let kinds: Vec<&str> = ObjectKind::ALL.iter().map(|k| k.as_str()).collect();
        bail!("{kind_text:?} is not a kind; one of: {}", kinds.join(", "));
    };
    let (parent, name) = if kind.table_level() {
        ("", path)
    } else {
        match path.rsplit_once('.') {
            Some((parent, name)) => (parent, name),
            None => bail!("{spec:?} names no table: use `{kind_text}:table.name`"),
        }
    };
    Ok(ObjectKey {
        kind,
        schema: String::new(),
        parent: parent.to_string(),
        name: name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_object_is_named_as_doctor_prints_it() {
        let key = parse_object("index:posts.posts_title_idx").unwrap();
        assert_eq!(
            (key.kind, key.parent.as_str(), key.name.as_str()),
            (ObjectKind::Index, "posts", "posts_title_idx")
        );
        let table = parse_object("table:posts").unwrap();
        assert_eq!((table.parent.as_str(), table.name.as_str()), ("", "posts"));
        let label = parse_object("security_label:posts.email.supatype").unwrap();
        assert_eq!(label.parent, "posts.email");
    }

    #[test]
    fn an_applied_run_says_what_it_did() {
        assert_eq!(status(false, true, true, true), "preview");
        assert_eq!(status(true, true, true, false), "adopted");
        assert_eq!(status(true, false, true, false), "released");
        assert_eq!(status(true, false, false, true), "reclaimed");
        assert_eq!(status(true, false, true, true), "released_and_reclaimed");
        assert_eq!(status(true, false, false, false), "nothing_to_adopt");
    }

    #[test]
    fn a_name_that_cannot_be_an_object_says_what_would() {
        assert!(format!("{:#}", parse_object("posts").unwrap_err()).contains("kind:table.name"));
        assert!(format!("{:#}", parse_object("idx:posts.a").unwrap_err()).contains("one of"));
        assert!(
            format!("{:#}", parse_object("index:posts").unwrap_err()).contains("index:table.name")
        );
    }
}
