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
    /// `preview` until applied; then `adopted`, or `nothing_to_adopt` when there was nothing.
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
}

/// Reads, decides, and with `request.apply` writes the rows, in one transaction.
///
/// Bootstraps first and checks the project schema after, as a push does: adopt is the first
/// command a project on an existing database runs, so the engine's tables may not exist yet, and
/// checking before they did failed with `relation "_supatype.schema_state" does not exist`.
pub async fn run(
    pool: &PgPool,
    ast: &SchemaAst,
    schema: &str,
    request: Request<'_>,
) -> Result<Outcome> {
    migration_history::bootstrap_internal_state(pool)
        .await
        .context("Failed to bootstrap _supatype internal state")?;
    migration_history::assert_project_schema(pool, schema).await?;
    let mut tx = pool.begin().await?;
    let (state, decision) = push::read_and_decide(&mut tx, pool, ast, schema).await?;
    let (outcome, changes) = choose(ast, &state, &decision, request)?;
    if request.apply {
        ledger::upsert(&mut tx, &changes).await?;
        tx.commit().await?;
    }
    Ok(outcome)
}

/// The rows adopting would write, and the outcome that says so. Releasing wins over adopting a
/// conflict; an object named both to release and to reclaim is refused; one named twice is written
/// once.
fn choose(
    ast: &SchemaAst,
    state: &State,
    decision: &Decision,
    request: Request<'_>,
) -> Result<(Outcome, Vec<LedgerRow>)> {
    let plan = &decision.reconcile;
    let report = doctor::report_of(ast, state, decision);
    let live: BTreeMap<ObjectKey, &ObjectFingerprint> =
        state.fingerprints.iter().map(|f| (f.key(), f)).collect();
    let released = rows_named(request.release, |spec| {
        released_row(spec, &state.ledger, &live, plan)
    })?;
    let reclaimed = rows_named(request.reclaim, |spec| reclaimed_row(spec, &state.ledger))?;
    if let Some(both) = released
        .iter()
        .find(|r| reclaimed.iter().any(|c| c.key == r.key))
    {
        bail!(
            "{} is named both to release and to reclaim: choose one",
            both.key
        );
    }
    let mut adopted = adopted_rows(plan, &live);
    adopted.retain(|a| !released.iter().any(|r| r.key == a.key));
    let outcome = Outcome {
        status: status(
            request.apply,
            adopted.len() + released.len() + reclaimed.len(),
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
            "will be Supatype's again: the next push makes it match the schema",
        ),
        doctor: report,
    };
    Ok((outcome, [adopted, released, reclaimed].concat()))
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

/// The released row `spec` names, handed back as `adopted`. Its record is kept, so the next push
/// treats it as any object of Supatype's: puts back a hand edit (asking first for access rules), or
/// replaces what it recorded with what the schema declares.
fn reclaimed_row(spec: &str, rows: &[LedgerRow]) -> Result<LedgerRow> {
    let wanted = parse_object(spec)?;
    let released = rows.iter().filter(|r| r.status == Status::Released);
    let key = resolve(spec, &wanted, released.map(|r| &r.key), "released")?;
    let row = rows
        .iter()
        .find(|r| r.key == key)
        .expect("resolved from the ledger's own rows");
    Ok(LedgerRow {
        status: Status::Adopted,
        ..row.clone()
    })
}

fn status(apply: bool, changes: usize) -> &'static str {
    match (apply, changes) {
        (false, _) => "preview",
        (true, 0) => "nothing_to_adopt",
        (true, _) => "adopted",
    }
}

fn items(rows: &[LedgerRow], consequence: &str) -> Vec<DoctorItem> {
    rows.iter()
        .map(|r| DoctorItem::about(&r.key, consequence))
        .collect()
}

/// A row for each conflict: the object under a name the schema needs, recorded as it is.
fn adopted_rows(
    plan: &reconcile::Plan,
    live: &BTreeMap<ObjectKey, &ObjectFingerprint>,
) -> Vec<LedgerRow> {
    plan.actions
        .iter()
        .filter_map(|action| match action {
            reconcile::Action::Conflict { key, .. } => {
                live.get(key).map(|l| as_found(l, Status::Adopted))
            }
            _ => None,
        })
        .collect()
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
    fn a_name_that_cannot_be_an_object_says_what_would() {
        assert!(format!("{:#}", parse_object("posts").unwrap_err()).contains("kind:table.name"));
        assert!(format!("{:#}", parse_object("idx:posts.a").unwrap_err()).contains("one of"));
        assert!(
            format!("{:#}", parse_object("index:posts").unwrap_err()).contains("index:table.name")
        );
    }
}
