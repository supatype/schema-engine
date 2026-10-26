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

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sqlx::PgPool;

use crate::differ::doctor::{self, DoctorItem, DoctorReport};
use crate::introspector::{
    self,
    catalog::{self, CatalogState},
    fingerprint::{fingerprints, ObjectFingerprint, ObjectKey, ObjectKind},
};
use crate::ledger::{self, desired_fingerprint, reconcile, LedgerRow, Status};
use crate::parser::ast::SchemaAst;
use crate::state::{database_state::DatabaseState, migration_history};

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
    /// The whole report, for context.
    pub doctor: DoctorReport,
}

/// Reads, decides, and with `apply` writes the rows, in one transaction. `release` names objects
/// as doctor prints them: `kind:name` for a table-level object, `kind:table.name` otherwise.
pub async fn run(
    pool: &PgPool,
    ast: &SchemaAst,
    schema: &str,
    release: &[String],
    apply: bool,
) -> Result<Outcome> {
    migration_history::bootstrap_internal_state(pool)
        .await
        .context("Failed to bootstrap _supatype internal state")?;
    let mut tx = pool.begin().await?;
    let db = introspector::introspect_connection(&mut tx, schema).await?;
    let catalog = catalog::read(&mut tx, schema).await?;
    let rows = ledger::load(&mut tx).await?;
    let (outcome, changes) = decide(ast, &db, &catalog, &rows, release, apply)?;
    if apply {
        ledger::upsert(&mut tx, &changes).await?;
        tx.commit().await?;
    }
    Ok(outcome)
}

/// The rows adopting would write, and the outcome that says so. Releasing wins: an object that is
/// both a conflict and named in `release` is released, and one named twice is released once.
fn decide(
    ast: &SchemaAst,
    db: &DatabaseState,
    catalog: &CatalogState,
    rows: &[LedgerRow],
    release: &[String],
    apply: bool,
) -> Result<(Outcome, Vec<LedgerRow>)> {
    let (plan, report) = doctor::plan_and_report(ast, db, catalog, rows)?;
    let live = fingerprints(db, catalog);
    let mut released: Vec<LedgerRow> = Vec::new();
    for spec in release {
        let row = released_row(spec, rows, &live, &plan)?;
        if !released.iter().any(|r| r.key == row.key) {
            released.push(row);
        }
    }
    let mut adopted = adopted_rows(&plan, &live);
    adopted.retain(|a| !released.iter().any(|r| r.key == a.key));
    let outcome = Outcome {
        status: status(apply, adopted.len() + released.len()),
        adopt: items(
            &adopted,
            "will be Supatype's: the next push makes it match the schema",
        ),
        release: items(
            &released,
            "will be left alone by every push, whatever the schema says",
        ),
        doctor: report,
    };
    Ok((outcome, [adopted, released].concat()))
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
        .map(|r| {
            let message = format!("{} {consequence}", doctor::label(&r.key));
            DoctorItem::for_key(&r.key, message)
        })
        .collect()
}

/// A row for each conflict: the object under a name the schema needs, recorded as it is.
fn adopted_rows(plan: &reconcile::Plan, live: &[ObjectFingerprint]) -> Vec<LedgerRow> {
    plan.actions
        .iter()
        .filter_map(|action| match action {
            reconcile::Action::Conflict { key, .. } => live
                .iter()
                .find(|l| &l.key() == key)
                .map(|l| as_found(l, Status::Adopted)),
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
    live: &[ObjectFingerprint],
    plan: &reconcile::Plan,
) -> Result<LedgerRow> {
    let wanted = parse_object(spec)?;
    let known = rows
        .iter()
        .map(|r| r.key.clone())
        .chain(live.iter().map(ObjectFingerprint::key))
        .chain(plan.actions.iter().map(|a| a.key().clone()));
    let key = resolve(spec, &wanted, known)?;
    if let Some(row) = rows.iter().find(|r| r.key == key) {
        return Ok(LedgerRow {
            status: Status::Released,
            ..row.clone()
        });
    }
    if let Some(l) = live.iter().find(|l| l.key() == key) {
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
fn resolve(
    spec: &str,
    wanted: &ObjectKey,
    known: impl Iterator<Item = ObjectKey>,
) -> Result<ObjectKey> {
    let mut matches: Vec<ObjectKey> = known
        .filter(|k| k.kind == wanted.kind && k.parent == wanted.parent && k.name == wanted.name)
        .collect();
    matches.sort_by(|a, b| a.schema.cmp(&b.schema));
    matches.dedup();
    match matches.as_slice() {
        [one] => Ok(one.clone()),
        [] => bail!("nothing to release is named {spec:?}: run `supatype doctor` for the names"),
        many => bail!(
            "{spec:?} names {} objects, one per schema ({}); release is not yet able to tell them apart",
            many.len(),
            many.iter().map(|k| k.schema.as_str()).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// The kinds named by themselves rather than by their table.
fn table_level(kind: ObjectKind) -> bool {
    matches!(
        kind,
        ObjectKind::Schema
            | ObjectKind::Table
            | ObjectKind::Function
            | ObjectKind::View
            | ObjectKind::EnumType
            | ObjectKind::Sequence
            | ObjectKind::CronJob
    )
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
    let (parent, name) = if table_level(kind) {
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
