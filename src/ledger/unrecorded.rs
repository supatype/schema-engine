//! Access objects no ledger row records, settled before a push decides (F15 (a), F16, F10).
//!
//! The reconcile takes a policy, grant or RLS attribute with no row as ours by its name, and a
//! label or access function as ours when the last push's schema made it, and replaces each with
//! the schema's definition. Whose it is does not settle what it holds, though, so each is compared
//! first, without changing anything (`super::compare`):
//!
//! - One the last push's schema declared was an older engine's, made before the ledger recorded
//!   it. Compared with what that schema renders, and with the claim readers written as the `auth.*`
//!   helpers an older engine called: equal, it is taken over as it always was; different, it was
//!   edited by hand, and the push asks before overwriting it, as for drift on a recorded object.
//! - One no earlier push made (nothing was ever pushed here, or the last push's schema did not
//!   declare it) is someone's own object under a name the schema needs. Equal to what the schema
//!   renders, it is adopted as it is; different, it is a conflict `supatype adopt` resolves, never
//!   replaced without a word (E22). Row-level security is the exception: the push only ever turns
//!   it on, which takes no access away from anyone who had none.
//! - With no last schema to compare with (pushes were applied and left none, or the one left
//!   cannot be read), each counts as changed: the push asks, and doctor says it was not checked
//!   and why (E29, E11). So does any single object the comparison could not settle.

use std::collections::{BTreeMap, BTreeSet};

use sqlx::PgConnection;

use super::compare::{Comparer, HeldGrant, Verdict};
use super::reconcile::{Action, AdoptReason, HandEdit};
use super::Status;
use crate::desired::{
    desired_objects_for, security_relevant, DesiredObject, FieldEnforcement, ObjectKey,
};
use crate::differ::FieldMaskingTier;
use crate::generator::sql::auth_functions::through_auth_aliases;
use crate::generator::sql::{field_views, grants};
use crate::introspector::fingerprint::{holding_nothing, ObjectFingerprint, ObjectKind};
use crate::parser::ast::SchemaAst;
use crate::push::{Decision, State};

/// The schema of the last push, as far as it can be read.
#[derive(Debug, Clone)]
pub enum Previous {
    /// No push has been applied here, so nothing on the database is an older engine's.
    NeverPushed,
    Found(Box<SchemaAst>),
    /// Pushes were applied and none left the schema it pushed.
    Missing,
    /// The last push's schema is recorded and does not decode.
    Unreadable(String),
}

impl Previous {
    pub fn ast(&self) -> Option<&SchemaAst> {
        match self {
            Previous::Found(ast) => Some(ast),
            _ => None,
        }
    }

    /// What a push and doctor say about a recorded schema they could not read (F10): never
    /// "there is no earlier schema", which is not what happened.
    pub fn warning(&self) -> Option<String> {
        match self {
            Previous::Unreadable(e) => Some(format!(
                "the last push's schema could not be read: {e}. Access objects no earlier push \
                 recorded are treated as changed by hand until a push records them"
            )),
            _ => None,
        }
    }

    /// Why an older engine's object cannot be compared, when nothing can be.
    fn unchecked(&self) -> Option<String> {
        match self {
            Previous::Missing => {
                Some("no earlier push left its schema to compare it with".to_string())
            }
            Previous::Unreadable(e) => {
                Some(format!("the last push's schema could not be read: {e}"))
            }
            Previous::NeverPushed | Previous::Found(_) => None,
        }
    }
}

/// Where an unrecorded object's expectation comes from.
enum Basis<'a> {
    /// The last push's schema declared it: an older engine made it from that schema.
    Older(&'a DesiredObject),
    /// No push made it: a same-named object, compared with what this schema renders.
    Declared(&'a DesiredObject),
    /// Nothing to compare it with, and why.
    Unknown(String),
}

/// What [`settle`] needs besides the decision it settles.
#[derive(Clone, Copy)]
pub struct Inputs<'a> {
    pub ast: &'a SchemaAst,
    pub state: &'a State,
    pub previous: &'a Previous,
}

/// Compares every access object the reconcile would replace with no row, and turns each into what
/// the comparison found: kept as a takeover, marked as a hand edit, adopted, or a conflict.
pub async fn settle(conn: &mut PgConnection, inputs: Inputs<'_>, decision: &mut Decision) {
    decision.diff.warnings.extend(inputs.previous.warning());
    let candidates = candidates(inputs.state, decision);
    if candidates.is_empty() {
        return;
    }
    let before = match earlier_objects(inputs, decision) {
        Ok(before) => before,
        Err(reason) => {
            for i in candidates {
                mark_unchecked(&mut decision.reconcile.actions[i], inputs.state, &reason);
            }
            return;
        }
    };
    let verdicts = compare_all(conn, inputs, decision, &before, &candidates).await;
    for (i, (older, verdict)) in candidates.into_iter().zip(verdicts) {
        apply(
            &mut decision.reconcile.actions[i],
            inputs.state,
            older,
            verdict,
        );
    }
}

/// The indices of the access objects the reconcile replaces with no row to say what they held.
fn candidates(state: &State, decision: &Decision) -> Vec<usize> {
    let recorded: BTreeSet<&ObjectKey> = state.ledger.iter().map(|r| &r.key).collect();
    decision
        .reconcile
        .actions
        .iter()
        .enumerate()
        .filter(|(_, a)| {
            matches!(a, Action::Replace { key, drifted: None, .. }
                if security_relevant(key) && !recorded.contains(key))
        })
        .map(|(i, _)| i)
        .collect()
}

/// What the last push's schema renders, by key; empty where nothing was ever pushed, and the
/// reason nothing can be compared where a push left no schema that can be read.
fn earlier_objects(
    inputs: Inputs<'_>,
    decision: &Decision,
) -> std::result::Result<BTreeMap<ObjectKey, DesiredObject>, String> {
    if let Some(reason) = inputs.previous.unchecked() {
        return Err(reason);
    }
    let Some(previous) = inputs.previous.ast() else {
        return Ok(BTreeMap::new());
    };
    let plan = field_views::field_view_plan(previous, &inputs.state.db);
    let fields = match decision.diff.field_masking {
        FieldMaskingTier::Views => FieldEnforcement::Views(&plan),
        FieldMaskingTier::None | FieldMaskingTier::Extension => FieldEnforcement::Labels,
    };
    desired_objects_for(previous, schema_of(inputs.state), fields)
        .map(|objects| objects.into_iter().map(|d| (d.key.clone(), d)).collect())
        .map_err(|e| format!("the last push's schema could not be rendered ({e:#})"))
}

fn schema_of(state: &State) -> &str {
    match state.db.schema.as_str() {
        "" => "public",
        named => named,
    }
}

/// Each candidate's verdict, and whether it was compared as an older engine's.
async fn compare_all(
    conn: &mut PgConnection,
    inputs: Inputs<'_>,
    decision: &Decision,
    before: &BTreeMap<ObjectKey, DesiredObject>,
    candidates: &[usize],
) -> Vec<(bool, Verdict)> {
    let now: BTreeMap<&ObjectKey, &DesiredObject> =
        decision.desired.iter().map(|d| (&d.key, d)).collect();
    let mut comparer = match Comparer::begin(conn, schema_of(inputs.state)).await {
        Ok(comparer) => Some(comparer),
        Err(e) => {
            tracing::warn!("access objects not compared: {e:#}");
            None
        }
    };
    let views = decision.diff.field_masking == FieldMaskingTier::Views;
    let mut out = Vec::new();
    for &i in candidates {
        let key = decision.reconcile.actions[i].key();
        let basis = match (before.get(key), now.get(key)) {
            (Some(d), _) => Basis::Older(d),
            (None, Some(d)) => Basis::Declared(d),
            (None, None) => Basis::Unknown("the schema does not declare it".into()),
        };
        let older = matches!(basis, Basis::Older(_));
        let verdict = match (comparer.as_mut(), live_of(inputs.state, key)) {
            (Some(c), Some(l)) => verdict(c, inputs, views, basis, &l).await,
            (None, _) => Verdict::Unchecked("the comparison could not begin".into()),
            (_, None) => Verdict::Unchecked("it is no longer there".into()),
        };
        out.push((older, verdict));
    }
    if let Some(comparer) = comparer {
        if let Err(e) = comparer.finish().await {
            tracing::warn!("{e:#}");
        }
    }
    out
}

/// One candidate against its basis.
async fn verdict(
    comparer: &mut Comparer<'_>,
    inputs: Inputs<'_>,
    views: bool,
    basis: Basis<'_>,
    live: &ObjectFingerprint,
) -> Verdict {
    match basis {
        Basis::Unknown(reason) => Verdict::Unchecked(reason),
        Basis::Declared(d) if d.key.kind == ObjectKind::TableGrant => {
            match declared_grant(inputs.ast, views, &d.key) {
                Some(held) => Comparer::grant(live, &held),
                None => Verdict::Unchecked("its grant could not be rendered".into()),
            }
        }
        Basis::Declared(d) => comparer.object(live, d, &d.create_sql).await,
        Basis::Older(d) if d.key.kind == ObjectKind::TableGrant => {
            let previous = inputs.previous.ast().unwrap_or(inputs.ast);
            match older_grant(comparer, previous, views, &d.key).await {
                Ok(held) => Comparer::grant(live, &held),
                Err(reason) => Verdict::Unchecked(reason),
            }
        }
        Basis::Older(d) => older_object(comparer, live, d).await,
    }
}

/// An older engine's object against the last push's schema as this engine renders it, then as an
/// older engine wrote it: the claims read through the `auth.*` helpers. Before this engine's first
/// push the claim readers do not exist yet, so only that older form can be compared at all. Same
/// if any form is; otherwise what differed, or why nothing could be compared.
async fn older_object(
    comparer: &mut Comparer<'_>,
    live: &ObjectFingerprint,
    d: &DesiredObject,
) -> Verdict {
    let [wrapped, bare] = through_auth_aliases(&d.create_sql);
    let mut found = Vec::new();
    for sql in [d.create_sql.as_str(), wrapped.as_str(), bare.as_str()] {
        match comparer.object(live, d, sql).await {
            Verdict::Same => return Verdict::Same,
            other => found.push(other),
        }
    }
    let differs = found.iter().find(|v| matches!(v, Verdict::Differs(_)));
    differs.or(found.first()).cloned().unwrap_or(Verdict::Same)
}

/// What the schema's grant to `key`'s grantee leaves it holding.
fn declared_grant(ast: &SchemaAst, views: bool, key: &ObjectKey) -> Option<HeldGrant> {
    let grant = grants::table_grants(ast, views)
        .into_iter()
        .find(|g| g.table == key.parent && g.role == key.name)?;
    let (table, columns) = grant.held();
    Some(HeldGrant { table, columns })
}

/// What an older engine's push of `previous` left `key`'s grantee holding. It granted and revoked
/// only the four privileges the rules govern, on model tables, for the API roles, on top of the
/// database's default privileges: so a role it granted to holds the rendered set and whatever else
/// the defaults gave, and a grantee it never granted to (`PUBLIC`, any role on a junction table)
/// holds exactly what the defaults gave. Under tier 2 that engine took every privilege off the base
/// table, defaults included.
async fn older_grant(
    comparer: &mut Comparer<'_>,
    previous: &SchemaAst,
    views: bool,
    key: &ObjectKey,
) -> std::result::Result<HeldGrant, String> {
    let junction = previous
        .junction_tables
        .iter()
        .any(|j| j.name == key.parent);
    if key.name == grants::PUBLIC || junction {
        return Ok(HeldGrant {
            table: comparer.default_privileges(key).await?,
            columns: BTreeMap::new(),
        });
    }
    let mut held = declared_grant(previous, views, key)
        .ok_or_else(|| "the last push's schema grants it nothing".to_string())?;
    if !views {
        let extra = comparer.default_privileges(key).await?;
        held.table.extend(
            extra
                .into_iter()
                .filter(|p| !grants::RULED.contains(&p.as_str())),
        );
        held.table.sort();
        held.table.dedup();
    }
    Ok(held)
}

/// The action as the comparison of an object with no row left it.
fn apply(action: &mut Action, state: &State, older: bool, verdict: Verdict) {
    let Action::Replace {
        key, create_sql, ..
    } = &*action
    else {
        return;
    };
    let live = live_of(state, key);
    let live_def = live
        .as_ref()
        .map(|l| l.definition.clone())
        .unwrap_or_default();
    match (older, verdict) {
        (true, Verdict::Same) => {}
        (false, Verdict::Same) => {
            *action = Action::Adopt {
                key: key.clone(),
                reason: AdoptReason::DeparsesEqual,
                create_sql: create_sql.clone(),
                comment: None,
                renamed_from: None,
                status: Status::Adopted,
            }
        }
        (true, Verdict::Differs(expected)) => set_hand_edit(action, live.as_ref(), expected, None),
        // Turning row-level security on takes nothing from anyone, so it needs no adopt.
        (false, _) if key.kind == ObjectKind::RlsAttributes => {}
        (false, _) => {
            *action = Action::Conflict {
                key: key.clone(),
                create_sql: create_sql.clone(),
                live_def,
            }
        }
        (true, Verdict::Unchecked(reason)) => mark_unchecked(action, state, &reason),
    }
}

/// What the catalog holds for `key`: its fingerprint, or for a grant with no catalog row, the grant
/// of nothing it is (`push::decide` reads it the same way).
fn live_of(state: &State, key: &ObjectKey) -> Option<ObjectFingerprint> {
    let found = state.fingerprints.iter().find(|f| f.key() == *key).cloned();
    match found {
        None if key.kind == ObjectKind::TableGrant => Some(holding_nothing(key)),
        found => found,
    }
}

/// Marks a replacement as overwriting what may be a hand edit, since it could not be compared.
fn mark_unchecked(action: &mut Action, state: &State, reason: &str) {
    let key = action.key().clone();
    let live = live_of(state, &key);
    set_hand_edit(
        action,
        live.as_ref(),
        format!("(not checked: {reason})"),
        Some(reason.to_string()),
    );
}

fn set_hand_edit(
    action: &mut Action,
    live: Option<&ObjectFingerprint>,
    recorded_def: String,
    unchecked: Option<String>,
) {
    if let Action::Replace { drifted, .. } = action {
        *drifted = Some(HandEdit {
            recorded_def,
            live_def: live.map(|l| l.definition.clone()).unwrap_or_default(),
            live_fp: live.map(|l| l.fingerprint.clone()).unwrap_or_default(),
            unchecked,
        });
    }
}
