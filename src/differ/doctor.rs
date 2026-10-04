//! `supatype doctor`: what a push would find, without applying anything.
//!
//! The report is the reconcile's (plan section 8), so doctor and push cannot disagree about any
//! object the ledger owns: an owned object that is absent is **missing**, one changed outside
//! Supatype is **drifted** (with what Supatype recorded beside what the database holds), one the
//! schema no longer asks for is **stale**, a desired name taken by someone else's object is
//! **conflicting**, and one the user took back is **released**. Objects on a model table that
//! Supatype did not create, columns included (D4), are **unmanaged**: a push leaves them in place.
//! Tables are still classified by their ownership stamp, until tables move onto the ledger.

use anyhow::Result;

use crate::desired::{desired_objects, ObjectKey};
use crate::introspector::catalog::CatalogState;
use crate::introspector::constraints::DbConstraintType;
use crate::introspector::fingerprint::{fingerprints, ObjectKind};
use crate::ledger::reconcile::{Action, Plan};
use crate::ledger::LedgerRow;
use crate::managed::{is_managed_comment, managed_comment};
use crate::parser::ast::SchemaAst;
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
    fn for_key(key: &ObjectKey, message: String) -> DoctorItem {
        let table = if key.parent.is_empty() {
            &key.name
        } else {
            &key.parent
        };
        DoctorItem::new(key.kind.as_str(), table, &key.name, message)
    }
}

/// `table.name`, or the name alone for a table-level object.
fn label(key: &ObjectKey) -> String {
    let kind = key.kind.as_str().replace('_', " ");
    if key.parent.is_empty() {
        format!("{kind} {}", key.name)
    } else {
        format!("{kind} {}.{}", key.parent, key.name)
    }
}

/// The tables, unique constraints and indexes a push of `ast` creates, read off the desired set.
struct Expected {
    /// Every table a push owns: models, junction tables and versions tables.
    tables: HashSet<String>,
    uniques: Vec<ExpectedConstraint>,
    indexes: Vec<ExpectedIndex>,
}

struct ExpectedConstraint {
    table: String,
    columns: Vec<String>,
}

struct ExpectedIndex {
    table: String,
    name: String,
    fields: Vec<String>,
    unique: bool,
}

fn expected(ast: &SchemaAst, schema: &str) -> Result<Expected> {
    let mut out = Expected {
        tables: HashSet::new(),
        uniques: Vec::new(),
        indexes: Vec::new(),
    };
    // The project schema only: doctor reads `DatabaseState`, which stops there, and the engine's
    // own tables and indexes are the ledger's to account for.
    for object in desired_objects(ast, schema)?
        .into_iter()
        .filter(|o| o.key.schema == schema)
    {
        let ObjectKey {
            kind, parent, name, ..
        } = object.key;
        let columns = |label: &str| -> Vec<String> {
            object
                .structure
                .get(label)
                .map(|c| c.split(',').map(str::to_string).collect())
                .unwrap_or_default()
        };
        match kind {
            ObjectKind::Table => {
                out.tables.insert(name);
            }
            ObjectKind::Unique => out.uniques.push(ExpectedConstraint {
                table: parent,
                columns: columns("columns"),
            }),
            ObjectKind::Index => out.indexes.push(ExpectedIndex {
                table: parent,
                name,
                fields: columns("columns"),
                unique: object.structure.get("unique").map(String::as_str) == Some("t"),
            }),
            _ => {}
        }
    }
    Ok(out)
}

/// `ledger` is what the push ledger owns (`_supatype.managed_objects`); a kind that has moved onto
/// it is classified from these rows rather than from comment stamps. Empty for a database no push
/// has bootstrapped.
pub fn report(
    ast: &SchemaAst,
    db: &DatabaseState,
    catalog: &CatalogState,
    ledger: &[LedgerRow],
) -> Result<DoctorReport> {
    let plan = crate::push::reconcile_for_report(ast, db, catalog, ledger)?;
    let mut out = DoctorReport::default();
    for action in &plan.actions {
        classify(action, &mut out);
    }
    out.unmanaged_drift
        .extend(unmanaged_objects(ast, db, catalog, ledger, &plan));
    let expected = expected(ast, &db.schema)?;
    table_items(db, &expected.tables, &mut out);
    Ok(out)
}

/// One reconcile action as the report's category, or nothing for what needs no attention: a
/// kept, forgotten, adopted or replaced object.
fn classify(action: &Action, out: &mut DoctorReport) {
    match action {
        Action::Create { key, .. } => out.missing.push(DoctorItem::for_key(
            key,
            format!(
                "{} is declared and does not exist: `supatype push` creates it",
                label(key)
            ),
        )),
        Action::Recreate { key, .. } => out.missing.push(DoctorItem::for_key(
            key,
            format!(
                "{} is Supatype's and was removed outside Supatype: `supatype push` recreates it",
                label(key)
            ),
        )),
        Action::Drift {
            key,
            recorded_def,
            live_def,
            security_relevant,
            ..
        } => {
            let consent = if *security_relevant {
                ", after asking, since it decides who may read or write"
            } else {
                ""
            };
            let mut item = DoctorItem::for_key(
                key,
                format!(
                    "{} was changed outside Supatype: `supatype push` puts it back{consent}",
                    label(key)
                ),
            );
            item.recorded = Some(recorded_def.clone());
            item.live = Some(live_def.clone());
            out.drifted.push(item);
        }
        Action::Drop { key, .. } => out.stale_managed.push(DoctorItem::for_key(
            key,
            format!(
                "{} is Supatype's and no longer declared: `supatype push` drops it",
                label(key)
            ),
        )),
        Action::Conflict { key, live_def, .. } => {
            let mut item = DoctorItem::for_key(
                key,
                format!(
                    "{} exists under a name the schema needs and was not created by Supatype: \
                     `supatype push` refuses until it is adopted with `supatype adopt` or renamed",
                    label(key)
                ),
            );
            item.live = Some(live_def.clone());
            out.conflicting.push(item);
        }
        Action::Released { key } => out.released.push(DoctorItem::for_key(
            key,
            format!(
                "{} was released with `supatype adopt --release`: Supatype leaves it alone",
                label(key)
            ),
        )),
        Action::Adopt { .. }
        | Action::Keep { .. }
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
fn unmanaged_objects(
    ast: &SchemaAst,
    db: &DatabaseState,
    catalog: &CatalogState,
    ledger: &[LedgerRow],
    plan: &Plan,
) -> Vec<DoctorItem> {
    let model_tables: HashSet<&str> = ast.models.iter().map(|m| m.table_name()).collect();
    let known: BTreeSet<&ObjectKey> = ledger
        .iter()
        .map(|r| &r.key)
        .chain(plan.actions.iter().map(Action::key))
        .collect();
    let constraint_names: HashSet<(&str, &str)> = db
        .constraints
        .iter()
        .filter(|c| {
            matches!(
                c.constraint_type,
                DbConstraintType::PrimaryKey | DbConstraintType::Unique
            )
        })
        .map(|c| (c.table.as_str(), c.name.as_str()))
        .collect();

    fingerprints(db, catalog)
        .into_iter()
        .filter(|f| USER_KINDS.contains(&f.kind) && f.schema == db.schema)
        .filter(|f| model_tables.contains(f.parent.as_str()))
        .filter(|f| !f.stamped() && !known.contains(&f.key()))
        .filter(|f| match f.kind {
            ObjectKind::Index => {
                !f.definition.contains("primary=t")
                    && !constraint_names.contains(&(f.parent.as_str(), f.name.as_str()))
            }
            ObjectKind::Check => !f.definition.contains("IS NOT NULL"),
            _ => true,
        })
        .map(|f| {
            let key = f.key();
            let declare = if key.kind == ObjectKind::Column {
                "Declare the column in the schema to manage it."
            } else {
                "Declare it in the schema to manage it, or drop it by hand."
            };
            let mut item = DoctorItem::for_key(
                &key,
                format!(
                    "{} was not created by Supatype: `supatype push` leaves it in place. {declare}",
                    label(&key)
                ),
            );
            // Its definition, since its name rarely says what it does: a check's expression,
            // say, which the operator compares with the one the schema declares.
            item.live = Some(f.definition);
            item
        })
        .collect()
}

/// Tables, still by their ownership stamp. The gate declines to drop an unmarked table, and
/// declines to drop a column from one, so an operator seeing a clean report and a push that leaves
/// a table behind would conclude push is broken.
fn table_items(db: &DatabaseState, schema_tables: &HashSet<String>, out: &mut DoctorReport) {
    for table in &db.tables {
        let managed = is_managed_comment(table.comment.as_deref());
        let in_schema = schema_tables.contains(&table.name);

        // In the schema and unmarked: push refuses to attach access rules to it until it is
        // adopted. That is the difference `adopt` resolves.
        if in_schema && !managed {
            out.unmanaged_drift.push(DoctorItem::new(
                "table",
                &table.name,
                &table.name,
                format!(
                    "Table {} matches a model but is not managed: push will not drop its columns; \
                     run `supatype adopt` to bring it under management",
                    table.name
                ),
            ));
            continue;
        }
        if in_schema {
            continue;
        }

        // Absent from the schema. Marked means push will drop it; unmarked means push will not.
        if managed {
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
/// on. Unmanaged objects and released ones are reported, not failures.
pub fn has_strict_issues(report: &DoctorReport) -> bool {
    !report.missing.is_empty()
        || !report.stale_managed.is_empty()
        || !report.drifted.is_empty()
        || !report.conflicting.is_empty()
}

/// SQL statements to stamp matching tables/constraints/indexes during adoption (comments only).
///
/// Tables are stamped **first**: the ownership gate is what makes an unmarked table safe from
/// `DropTable` and its columns safe from `DropColumn`, and until a table carries the marker, adopting
/// only its indexes leaves the confusing half-state where push manages the indexes on a table it
/// will not otherwise touch.
///
/// Only objects a push of this schema would create are stamped. Adoption is an opt-in ceremony for
/// objects the operator has decided belong to Supatype; stamping anything found in the schema
/// would make the gate meaningless on its first run, which is the one case it exists for.
pub fn adopt_stamp_sql(
    ast: &SchemaAst,
    db: &DatabaseState,
    catalog: &CatalogState,
    schema: &str,
) -> Result<Vec<String>> {
    let expected = expected(ast, schema)?;
    let mut lines = Vec::new();

    for db_table in &db.tables {
        if !expected.tables.contains(&db_table.name)
            || is_managed_comment(db_table.comment.as_deref())
        {
            continue;
        }
        // The same marker `CREATE TABLE` writes. A different shape would leave the table
        // permanently undroppable and the differ unable to converge.
        let comment = managed_comment("table", &db_table.name, &[]);
        lines.push(crate::managed::comment_on_table_sql(
            &db_table.name,
            &comment,
            schema,
        ));
    }

    for exp in &expected.uniques {
        let constraint = db.constraints.iter().find(|c| {
            c.constraint_type == DbConstraintType::Unique
                && c.table == exp.table
                && c.columns == exp.columns
        });
        if let Some(c) = constraint {
            if !is_managed_comment(c.comment.as_deref()) {
                let fields: Vec<&str> = exp.columns.iter().map(String::as_str).collect();
                let comment = managed_comment("unique_constraint", &exp.table, &fields);
                lines.push(crate::managed::comment_on_constraint_sql(
                    &exp.table, &c.name, &comment, schema,
                ));
            }
        }
    }

    for exp in &expected.indexes {
        let idx = db
            .indexes
            .iter()
            .chain(&catalog.expression_indexes)
            .find(|i| i.table == exp.table && i.name == exp.name);
        if let Some(i) = idx {
            if !is_managed_comment(i.comment.as_deref()) {
                let kind = if exp.unique { "unique_index" } else { "index" };
                let field_refs: Vec<&str> = exp.fields.iter().map(String::as_str).collect();
                let comment = managed_comment(kind, &exp.table, &field_refs);
                lines.push(crate::managed::comment_on_index_sql(
                    &exp.name, &comment, schema,
                ));
            }
        }
    }

    Ok(lines)
}
