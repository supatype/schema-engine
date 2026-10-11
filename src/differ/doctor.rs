//! `supatype doctor`: what a push would find, without applying anything.
//!
//! The report is the reconcile's (plan section 8), so doctor and push cannot disagree about any
//! object the ledger owns: an owned object that is absent is **missing**, one changed outside
//! Supatype is **drifted** (with what Supatype recorded beside what the database holds), one the
//! schema no longer asks for is **stale**, a desired name taken by someone else's object is
//! **conflicting**, and one the user took back is **released**. One of Supatype's own from an
//! earlier engine, which no row records yet (a policy or grant named for its table, an object in
//! the engine's own schemas), is **claimed**: the next push records it, and that is not a failure. Objects on a model table that
//! Supatype did not create, columns included (D4), are **unmanaged**: a push leaves them in place.
//! A table the schema no longer declares is stale when it is ours and unmanaged when it is not.

use anyhow::Result;

use crate::desired::ObjectKey;
use crate::introspector::catalog::CatalogState;
use crate::introspector::constraints::DbConstraintType;
use crate::introspector::fingerprint::{ObjectFingerprint, ObjectKind};
use crate::ledger::reconcile::{Action, HandEdit, Plan};
use crate::ledger::LedgerRow;
use crate::parser::ast::SchemaAst;
use crate::push::{Decision, State};
use crate::state::database_state::DatabaseState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorReport {
    /// Desired and absent: an owned object removed outside Supatype, or one never created.
    pub missing: Vec<DoctorItem>,
    /// Owned and no longer desired: a push drops it.
    pub stale_managed: Vec<DoctorItem>,
    /// Not Supatype's, on a table it manages (or a table it does not): a push leaves it in place.
    pub unmanaged_drift: Vec<DoctorItem>,
    /// Owned and changed outside Supatype: a push puts it back, with consent where it decides
    /// access (plan 3.5).
    #[serde(default)]
    pub drifted: Vec<DoctorItem>,
    /// A name the schema needs, taken by an object Supatype did not create: a push refuses.
    #[serde(default)]
    pub conflicting: Vec<DoctorItem>,
    /// Taken back with `adopt --release`: left alone whatever the schema says.
    #[serde(default)]
    pub released: Vec<DoctorItem>,
    /// Supatype's own object from an earlier engine, which no row records yet: the next push
    /// records it, with the schema's definition. Reported, not a failure (`--strict` passes).
    #[serde(default)]
    pub claimed: Vec<DoctorItem>,
    /// A key or check of ours added `NOT VALID` and not validated yet, or an index of ours a
    /// concurrent build left INVALID: the next push finishes it (IN-C 2).
    #[serde(default)]
    pub pending: Vec<DoctorItem>,
    /// Drifted objects whose live definition `doctor --rebaseline` just recorded as the baseline.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rebaselined: Vec<DoctorItem>,
    /// Drifted objects that decide access, which `doctor --rebaseline` did not record because
    /// `--accept-access-drift` was not given (plan 3.5). Still listed under `drifted`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rebaseline_refused: Vec<DoctorItem>,
    /// Whether a push would change or refuse something: what `doctor --strict` fails on, so a
    /// caller reads the engine's rule rather than keeping a copy of it.
    #[serde(default)]
    pub blocking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorItem {
    pub kind: String,
    pub table: String,
    pub name: String,
    pub fields: Vec<String>,
    pub message: String,
    /// What Supatype recorded, for a drifted object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded: Option<String>,
    /// What the database holds now, for a drifted or conflicting object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live: Option<String>,
}

impl DoctorItem {
    fn new(kind: &str, table: &str, name: &str, message: String) -> DoctorItem {
        DoctorItem {
            kind: kind.to_string(),
            table: table.to_string(),
            name: name.to_string(),
            fields: Vec::new(),
            message,
            recorded: None,
            live: None,
        }
    }

    /// An item about one ledger key: its table is its parent, or itself for a table-level object.
    pub(crate) fn for_key(key: &ObjectKey, message: String) -> DoctorItem {
        let table = if key.parent.is_empty() {
            &key.name
        } else {
            &key.parent
        };
        DoctorItem::new(key.kind.as_str(), table, &key.name, message)
    }

    /// An item whose message is the object's label and then `rest`: "Index posts.x {rest}".
    pub(crate) fn about(key: &ObjectKey, rest: &str) -> DoctorItem {
        DoctorItem::for_key(key, format!("{} {rest}", label(key)))
    }
}

/// The kind, then `table.name` or the name alone for a table-level object. Every message opens
/// with it, so it reads as the start of a sentence: "Table widget", "RLS attributes posts.rls".
pub(crate) fn label(key: &ObjectKey) -> String {
    let words = key.kind.as_str().replace('_', " ").replace("rls", "RLS");
    let mut chars = words.chars();
    let kind: String = chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default();
    if key.parent.is_empty() {
        format!("{kind} {}", key.name)
    } else {
        format!("{kind} {}.{}", key.parent, key.name)
    }
}

/// The report for states read separately, for a caller with no connection to read them through
/// `push::read_state` (a test). `ledger` is what the push ledger owns (`_supatype.managed_objects`),
/// empty for a database no push has bootstrapped.
pub fn report(
    ast: &SchemaAst,
    db: &DatabaseState,
    catalog: &CatalogState,
    ledger: &[LedgerRow],
) -> Result<DoctorReport> {
    let state = State::of(db.clone(), catalog.clone(), ledger.to_vec());
    let decision = crate::push::decide(ast, &state, None)?;
    Ok(report_of(ast, &state, &decision))
}

/// What a push deciding `decision` against `state` would do, sorted for an operator.
pub fn report_of(ast: &SchemaAst, state: &State, decision: &Decision) -> DoctorReport {
    let plan = &decision.reconcile;
    let mut out = DoctorReport::default();
    let recorded: BTreeSet<&ObjectKey> = state.ledger.iter().map(|r| &r.key).collect();
    for action in &plan.actions {
        classify(action, &recorded, &mut out);
    }
    out.unmanaged_drift
        .extend(unmanaged_objects(ast, state, plan));
    // A column added outside Supatype that a narrowed write grant leaves unwritable says so, and
    // how to include it (#63).
    let narrowed = crate::push::NarrowedColumns::of(ast, state, &decision.diff, &state.db.schema);
    for (table, column, roles) in &narrowed.ungranted {
        if let Some(item) = out
            .unmanaged_drift
            .iter_mut()
            .find(|i| i.kind == "column" && i.table == *table && i.name == *column)
        {
            item.message = crate::push::ungranted_message(table, column, roles);
        }
    }
    // Every table a push owns in the project schema (models, junction and versions tables). The
    // engine's own tables are the ledger's to account for.
    let declared: HashSet<&str> = decision
        .desired
        .iter()
        .filter(|o| o.key.kind == ObjectKind::Table && o.key.schema == state.db.schema)
        .map(|o| o.key.name.as_str())
        .collect();
    undeclared_tables(&state.db, &declared, &mut out);
    if decision.diff.field_masking == crate::differ::FieldMaskingTier::Views {
        tier_two_messages(state, &mut out);
    }
    out.pending = pending_items(state, decision);
    out.blocking = has_strict_issues(&out);
    out
}

/// What tier 2 changes about the report. A mask label is not undeclared there, only unused: the
/// `api` views enforce the rule instead, so the push takes the label off (F17). And a hand-written
/// policy restricted to roles applies through the views no more (plan D5, point 4b).
fn tier_two_messages(state: &State, out: &mut DoctorReport) {
    for item in out
        .stale_managed
        .iter_mut()
        .filter(|i| i.kind == ObjectKind::SecurityLabel.as_str())
    {
        item.message = format!(
            "Security label {}.{} is not used: this database has no supatype_mask, so the api \
             views enforce field rules instead, and `supatype push` takes the label off",
            item.table, item.name
        );
    }
    for item in out.unmanaged_drift.iter_mut() {
        if let Some(message) = role_restricted_policy(state, item) {
            item.message = message;
        }
    }
}

/// The warning for a hand-written policy on a model table that names roles. Under tier 2 the API
/// reads the table through views that run as their owner, and a policy's roles are compared with the
/// owner, not the caller: a permissive one stops granting (fail closed) and a restrictive one stops
/// restricting.
fn role_restricted_policy(state: &State, item: &DoctorItem) -> Option<String> {
    if item.kind != ObjectKind::Policy.as_str() {
        return None;
    }
    let policy = state
        .fingerprints
        .iter()
        .find(|f| f.kind == ObjectKind::Policy && f.parent == item.table && f.name == item.name)?;
    let roles = policy
        .definition
        .lines()
        .find_map(|l| l.strip_prefix("roles="))?;
    if roles.split(',').any(|r| r == "public") {
        return None;
    }
    let consequence = if policy.definition.lines().any(|l| l == "permissive=f") {
        "as a RESTRICTIVE policy it no longer narrows what callers of the API can reach"
    } else {
        "the rows it grants are no longer reachable through the API"
    };
    Some(format!(
        "Policy {}.{} was not created by Supatype and applies only to {roles}. This database masks \
         fields with api views, which read the table as their owner ({}), so the policy no longer \
         applies through them: {consequence}. Make it apply to PUBLIC and test the role in its \
         expression, or declare the rule in the schema.",
        item.table,
        item.name,
        crate::generator::sql::field_views::API_OWNER,
    ))
}

/// The item for an object changed outside Supatype: what was recorded beside what is live.
fn drifted_item(
    key: &ObjectKey,
    security_relevant: bool,
    recorded_def: &str,
    live_def: &str,
) -> DoctorItem {
    let mut item = DoctorItem::about(
        key,
        if security_relevant {
            "was changed outside Supatype: `supatype push` puts it back, after asking, \
             since it decides who may read or write"
        } else {
            "was changed outside Supatype: `supatype push` puts it back"
        },
    );
    item.recorded = Some(recorded_def.to_string());
    item.live = Some(live_def.to_string());
    item
}

/// The item for an object the push overwrites that may have been changed outside Supatype: one
/// found changed, as [`drifted_item`], or one that could not be compared with what Supatype made
/// (F16), which says so and why, since it is treated as changed.
fn hand_edit_item(key: &ObjectKey, edit: &HandEdit) -> DoctorItem {
    let security_relevant = crate::desired::security_relevant(key);
    let Some(reason) = &edit.unchecked else {
        return drifted_item(key, security_relevant, &edit.recorded_def, &edit.live_def);
    };
    let mut item = DoctorItem::about(
        key,
        &format!(
            "was not checked for changes made by hand ({reason}): `supatype push` replaces it \
             only after asking, since it decides who may read or write"
        ),
    );
    item.recorded = Some(edit.recorded_def.clone());
    item.live = Some(edit.live_def.clone());
    item
}

/// The item for an object the push drops, outright or with its table, that was changed outside
/// Supatype since it was recorded (F15 (c)).
fn dropped_edit_item(key: &ObjectKey, edit: &HandEdit, with_its_table: bool) -> DoctorItem {
    let mut item = DoctorItem::about(
        key,
        if with_its_table {
            "goes with its table, which the schema no longer declares, and was changed outside \
             Supatype: `supatype push` drops it, after asking, since it decides who may read or \
             write"
        } else {
            "is Supatype's and no longer declared, and was changed outside Supatype: `supatype \
             push` drops it, after asking, since it decides who may read or write"
        },
    );
    item.recorded = Some(edit.recorded_def.clone());
    item.live = Some(edit.live_def.clone());
    item
}

/// One reconcile action as the report's category, or nothing for what needs no attention: a
/// kept, forgotten or adopted object, or one of Supatype's the schema changed. `recorded` is every
/// key the ledger has a row for.
fn classify(action: &Action, recorded: &BTreeSet<&ObjectKey>, out: &mut DoctorReport) {
    match action {
        Action::Create { key, .. } => out.missing.push(DoctorItem::about(
            key,
            "is declared and does not exist: `supatype push` creates it",
        )),
        Action::Recreate { key, .. } => out.missing.push(DoctorItem::about(
            key,
            "is Supatype's and was removed outside Supatype: `supatype push` recreates it",
        )),
        Action::Drift {
            key,
            recorded_def,
            live_def,
            security_relevant,
            ..
        } => out.drifted.push(drifted_item(
            key,
            *security_relevant,
            recorded_def,
            live_def,
        )),
        // Changed by hand and by the schema: the push overwrites the hand edit, so it is drift.
        Action::Replace {
            key,
            drifted: Some(edit),
            ..
        } => out.drifted.push(hand_edit_item(key, edit)),
        // No row: Supatype's own object from an earlier engine, which its name or location makes
        // ours (a policy or grant named for its table, an object in the engine's own schemas).
        // The push records it with the schema's definition rather than refusing, as it does on
        // every upgrade, so it is reported apart from the conflicts and fails nothing. One changed
        // by hand since is a `Replace` with `drifted` set, reported above.
        Action::Replace {
            key, previous_sql, ..
        } if !recorded.contains(key) => {
            let mut item = DoctorItem::about(
                key,
                "is Supatype's own from an earlier engine and not recorded yet: the next \
                 `supatype push` records it, with the schema's definition",
            );
            item.live = Some(previous_sql.clone());
            out.claimed.push(item);
        }
        Action::Drop {
            key,
            drifted: Some(edit),
            ..
        } if crate::desired::security_relevant(key) => {
            out.stale_managed.push(dropped_edit_item(key, edit, false))
        }
        Action::Forget {
            key,
            drifted: Some(edit),
        } if crate::desired::security_relevant(key) => {
            out.stale_managed.push(dropped_edit_item(key, edit, true))
        }
        Action::Drop { key, .. } => out.stale_managed.push(DoctorItem::about(
            key,
            "is Supatype's and no longer declared: `supatype push` drops it",
        )),
        Action::Conflict { key, live_def, .. } => {
            let mut item = DoctorItem::about(
                key,
                "exists under a name the schema needs and was not created by Supatype: \
                 `supatype push` refuses until it is adopted with `supatype adopt` or renamed",
            );
            item.live = Some(live_def.clone());
            out.conflicting.push(item);
        }
        Action::Released { key } => out.released.push(DoctorItem::about(
            key,
            "was released with `supatype adopt --release`: Supatype leaves it alone",
        )),
        Action::Adopt { .. }
        | Action::Keep { .. }
        | Action::Restate { .. }
        | Action::Rename { .. }
        | Action::Rebuild { .. }
        | Action::Replace { .. }
        | Action::Forget { .. } => {}
    }
}

/// The kinds a user adds to a model table that a push must leave alone (D4 for columns).
const USER_KINDS: [ObjectKind; 7] = [
    ObjectKind::Column,
    ObjectKind::Index,
    ObjectKind::Check,
    ObjectKind::Unique,
    ObjectKind::ForeignKey,
    ObjectKind::Policy,
    ObjectKind::Trigger,
];

/// Objects on a model table that Supatype did not create and does not record: someone else's,
/// so a push leaves them in place. Not reported: the index behind a primary key or unique
/// constraint, which is the constraint's, and a `NOT NULL` check, which no one declared.
fn unmanaged_objects(ast: &SchemaAst, state: &State, plan: &Plan) -> Vec<DoctorItem> {
    let filter = UserObjects {
        schema: &state.db.schema,
        model_tables: ast.models.iter().map(|m| m.table_name()).collect(),
        // A live object the push takes over under another name is known by that name too.
        known: state
            .ledger
            .iter()
            .map(|r| r.key.clone())
            .chain(plan.actions.iter().map(|a| a.key().clone()))
            .chain(plan.actions.iter().filter_map(Action::found_as))
            .collect(),
        constraint_names: state
            .db
            .constraints
            .iter()
            .filter(|c| {
                matches!(
                    c.constraint_type,
                    DbConstraintType::PrimaryKey | DbConstraintType::Unique
                )
            })
            .map(|c| (c.table.as_str(), c.name.as_str()))
            .collect(),
    };
    state
        .fingerprints
        .iter()
        .filter(|f| filter.reportable(f))
        .map(unmanaged_item)
        .collect()
}

/// What decides whether a live object on a model table is someone else's to report.
struct UserObjects<'a> {
    schema: &'a str,
    model_tables: HashSet<&'a str>,
    known: BTreeSet<ObjectKey>,
    /// Primary key and unique constraints, whose indexes are theirs, not separate objects.
    constraint_names: HashSet<(&'a str, &'a str)>,
}

impl UserObjects<'_> {
    fn reportable(&self, f: &ObjectFingerprint) -> bool {
        USER_KINDS.contains(&f.kind)
            && f.schema == self.schema
            && self.model_tables.contains(f.parent.as_str())
            && !f.stamped()
            && !self.known.contains(&f.key())
            && match f.kind {
                ObjectKind::Index => {
                    !f.definition.contains("primary=t")
                        && !self
                            .constraint_names
                            .contains(&(f.parent.as_str(), f.name.as_str()))
                }
                ObjectKind::Check => !f.definition.contains("IS NOT NULL"),
                _ => true,
            }
    }
}

fn unmanaged_item(f: &ObjectFingerprint) -> DoctorItem {
    let key = f.key();
    let mut item = DoctorItem::about(
        &key,
        if key.kind == ObjectKind::Column {
            "was not created by Supatype: `supatype push` leaves it in place. Declare the column \
             in the schema to manage it."
        } else {
            "was not created by Supatype: `supatype push` leaves it in place. Declare it in the \
             schema to manage it, or drop it by hand."
        },
    );
    // Its definition, since its name rarely says what it does: a check's expression, say, which
    // the operator compares with the one the schema declares.
    item.live = Some(f.definition.clone());
    item
}

/// Tables the schema does not declare, which the reconcile records but leaves to the table differ
/// (Phase 4.11). Ours means a push drops it; not ours means it never will, and saying so keeps an
/// operator from concluding push is broken when it leaves a table behind. A declared table that is
/// not ours is the reconcile's conflict.
fn undeclared_tables(db: &DatabaseState, schema_tables: &HashSet<&str>, out: &mut DoctorReport) {
    for table in &db.tables {
        if schema_tables.contains(table.name.as_str()) {
            continue;
        }
        if db.owns_table(table) {
            out.stale_managed.push(DoctorItem::new(
                "table",
                &table.name,
                &table.name,
                format!(
                    "Managed table {} is not in AST; review before push",
                    table.name
                ),
            ));
        } else {
            out.unmanaged_drift.push(DoctorItem::new(
                "table",
                &table.name,
                &table.name,
                format!(
                    "Unmanaged table {}: push will not drop; manual decision required",
                    table.name
                ),
            ));
        }
    }
}

/// Whether the report has something a push would change or refuse: what `doctor --strict` fails
/// on. Unmanaged, released and claimed objects are reported, not failures.
pub fn has_strict_issues(report: &DoctorReport) -> bool {
    !report.missing.is_empty()
        || !report.stale_managed.is_empty()
        || !report.drifted.is_empty()
        || !report.conflicting.is_empty()
        || !report.pending.is_empty()
}

/// The keys and checks of ours a push added `NOT VALID` and has not validated, and the INVALID
/// indexes a concurrent build of ours left (IN-C 2): the next push finishes each.
fn pending_items(state: &State, decision: &Decision) -> Vec<DoctorItem> {
    let schema = state.db.schema.as_str();
    let ours = |key: &ObjectKey| {
        state
            .ledger
            .iter()
            .any(|r| r.key == *key && r.status != crate::ledger::Status::Released)
            || decision.desired.iter().any(|d| d.key == *key)
    };
    state
        .catalog
        .pending
        .iter()
        .map(|p| ObjectKey {
            kind: p.kind,
            schema: schema.to_string(),
            parent: p.table.clone(),
            name: p.name.clone(),
        })
        .filter(ours)
        .map(|key| {
            let rest = if key.kind == ObjectKind::Index {
                "is INVALID: a concurrent build did not finish. `supatype push` drops it and builds \
                 it again"
            } else {
                "was added NOT VALID and has not been validated against the rows already there: \
                 `supatype push` validates it"
            };
            DoctorItem::about(&key, rest)
        })
        .collect()
}
