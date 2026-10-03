//! A structural fingerprint for every object the engine can see.
//!
//! The ledger (`plans/Managed-Object-Ownership-Plan.md`) records what an owned object looked like
//! right after a push and compares that with what it looks like now, which is how a change made
//! outside Supatype is told from one Supatype made. Two choices decide whether that comparison is
//! trustworthy:
//!
//! - **Deparsed text, whitespace-normalised, rather than `pg_node_tree`.** Node trees embed OIDs:
//!   of user functions, of types, of columns by position. A dump and restore, or a column dropped
//!   and re-added, changes them without changing a thing the object does, and the ledger is meant
//!   to survive exactly those. Deparsed text (`pg_get_expr`, `pg_get_constraintdef`,
//!   `pg_get_viewdef`, policy quals) names things instead. It does reformat across Postgres major
//!   versions, which is what `doctor --rebaseline` is for.
//! - **Only what changes behaviour.** Comments are the user's and never enter a fingerprint, nor do
//!   names: the name is the key.
//!
//! Pure over state already read, so it is testable without a database and runs once per push.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::catalog::CatalogState;
use super::constraints::DbConstraintType;
use crate::state::database_state::DatabaseState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    Schema,
    Table,
    Column,
    PrimaryKey,
    ForeignKey,
    Unique,
    Check,
    Index,
    Trigger,
    Function,
    View,
    Policy,
    RlsAttributes,
    EnumType,
    Sequence,
    TableGrant,
    ColumnGrant,
    SecurityLabel,
    CronJob,
}

impl ObjectKind {
    fn tag(self) -> &'static str {
        match self {
            ObjectKind::Schema => "schema",
            ObjectKind::Table => "table",
            ObjectKind::Column => "column",
            ObjectKind::PrimaryKey => "primary_key",
            ObjectKind::ForeignKey => "foreign_key",
            ObjectKind::Unique => "unique",
            ObjectKind::Check => "check",
            ObjectKind::Index => "index",
            ObjectKind::Trigger => "trigger",
            ObjectKind::Function => "function",
            ObjectKind::View => "view",
            ObjectKind::Policy => "policy",
            ObjectKind::RlsAttributes => "rls_attributes",
            ObjectKind::EnumType => "enum_type",
            ObjectKind::Sequence => "sequence",
            ObjectKind::TableGrant => "table_grant",
            ObjectKind::ColumnGrant => "column_grant",
            ObjectKind::SecurityLabel => "security_label",
            ObjectKind::CronJob => "cron_job",
        }
    }
}

/// One object's identity and the hash of what it does.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectFingerprint {
    pub kind: ObjectKind,
    pub schema: String,
    /// The table for table-scoped kinds, `table.column` for column-scoped ones, empty otherwise.
    pub parent: String,
    pub name: String,
    pub fingerprint: String,
    /// What was hashed, one `label=value` line per part, so a ledger can show a drifted object's
    /// recorded definition against its live one without a renderer per kind.
    pub definition: String,
}

/// Whitespace collapsed to single spaces, trimmed, no trailing semicolon. Case is kept: deparsed
/// SQL quotes identifiers that need it, so folding case would conflate `"A"` with `a`.
pub fn normalise_sql(sql: &str) -> String {
    let collapsed = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.trim_end_matches(';').trim().to_string()
}

/// Sixteen hex characters of SHA-256 over the kind and the parts, separated so that no two part
/// lists can concatenate to the same bytes.
pub fn hash(kind: ObjectKind, parts: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(kind.tag().as_bytes());
    for part in parts {
        hasher.update([0x1f]);
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn flag(b: bool) -> &'static str {
    if b {
        "t"
    } else {
        "f"
    }
}

impl ObjectKind {
    /// The label of each hashed part, in the order the part lists below supply them. Empty for the
    /// kinds whose parts are a dynamic list (a table's columns) or nothing at all (a schema).
    pub(crate) fn labels(self) -> &'static [&'static str] {
        match self {
            ObjectKind::Schema | ObjectKind::Table => &[],
            ObjectKind::Column => &["type", "udt", "nullable", "default", "precision", "scale"],
            ObjectKind::PrimaryKey | ObjectKind::Unique => &["columns"],
            ObjectKind::ForeignKey => &["columns", "references", "referenced_columns", "on_delete"],
            ObjectKind::Check => &["expression"],
            ObjectKind::Index => &[
                "columns",
                "expressions",
                "predicate",
                "method",
                "unique",
                "primary",
            ],
            ObjectKind::Trigger => &[
                "timing",
                "events",
                "columns",
                "for_each_row",
                "function",
                "enabled",
                "definition",
            ],
            ObjectKind::Function => &[
                "returns",
                "language",
                "volatility",
                "security_definer",
                "body",
            ],
            ObjectKind::View => &["materialized", "definition"],
            ObjectKind::Policy => &["command", "permissive", "roles", "using", "with_check"],
            ObjectKind::RlsAttributes => &["enabled", "forced"],
            ObjectKind::EnumType => &["values"],
            ObjectKind::Sequence => &["owned_by"],
            ObjectKind::TableGrant | ObjectKind::ColumnGrant => &["privileges"],
            ObjectKind::SecurityLabel => &["label"],
            ObjectKind::CronJob => &["schedule", "command", "active"],
        }
    }
}

/// The hashed parts rendered for a person: `label=value` lines where the kind has labels, the bare
/// parts otherwise.
fn render_definition(kind: ObjectKind, parts: &[&str]) -> String {
    let labels = kind.labels();
    if labels.is_empty() {
        return parts.join("\n");
    }
    debug_assert_eq!(
        labels.len(),
        parts.len(),
        "{kind:?} parts and labels disagree"
    );
    labels
        .iter()
        .zip(parts)
        .map(|(label, value)| format!("{label}={value}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn entry(
    kind: ObjectKind,
    schema: &str,
    parent: &str,
    name: &str,
    parts: &[&str],
) -> ObjectFingerprint {
    ObjectFingerprint {
        kind,
        schema: schema.to_string(),
        parent: parent.to_string(),
        name: name.to_string(),
        fingerprint: hash(kind, parts),
        definition: render_definition(kind, parts),
    }
}

/// Every fingerprint the two states support, sorted by kind, schema, parent and name.
pub fn fingerprints(db: &DatabaseState, catalog: &CatalogState) -> Vec<ObjectFingerprint> {
    let schema = db.schema.as_str();
    let mut out = Vec::new();

    for s in &catalog.schemas {
        out.push(entry(ObjectKind::Schema, &s.name, "", &s.name, &[]));
    }

    for table in &db.tables {
        let mut column_parts: Vec<String> = Vec::with_capacity(table.columns.len());
        for col in &table.columns {
            let default = col
                .default
                .as_deref()
                .map(normalise_sql)
                .unwrap_or_default();
            let precision = col
                .numeric_precision
                .map(|p| p.to_string())
                .unwrap_or_default();
            let scale = col.numeric_scale.map(|s| s.to_string()).unwrap_or_default();
            let parts = [
                col.data_type.as_str(),
                col.udt_name.as_str(),
                flag(col.nullable),
                default.as_str(),
                precision.as_str(),
                scale.as_str(),
            ];
            out.push(entry(
                ObjectKind::Column,
                &table.schema,
                &table.name,
                &col.name,
                &parts,
            ));
            column_parts.push(format!("{}={}", col.name, hash(ObjectKind::Column, &parts)));
        }
        // Sorted by name: the position of a column is not something a push controls on an existing
        // table, so it must not read as a change.
        column_parts.sort();
        let refs: Vec<&str> = column_parts.iter().map(String::as_str).collect();
        out.push(entry(
            ObjectKind::Table,
            &table.schema,
            "",
            &table.name,
            &refs,
        ));
    }

    for c in &db.constraints {
        let columns = c.columns.join(",");
        match c.constraint_type {
            DbConstraintType::PrimaryKey => out.push(entry(
                ObjectKind::PrimaryKey,
                schema,
                &c.table,
                &c.name,
                &[columns.as_str()],
            )),
            DbConstraintType::Unique => out.push(entry(
                ObjectKind::Unique,
                schema,
                &c.table,
                &c.name,
                &[columns.as_str()],
            )),
            DbConstraintType::ForeignKey => {
                let foreign_columns = c
                    .foreign_columns
                    .as_ref()
                    .map(|v| v.join(","))
                    .unwrap_or_default();
                out.push(entry(
                    ObjectKind::ForeignKey,
                    schema,
                    &c.table,
                    &c.name,
                    &[
                        columns.as_str(),
                        c.foreign_table.as_deref().unwrap_or(""),
                        foreign_columns.as_str(),
                        c.on_delete.as_deref().unwrap_or(""),
                    ],
                ))
            }
            DbConstraintType::Check => {
                let expression = c
                    .check_expression
                    .as_deref()
                    .map(normalise_sql)
                    .unwrap_or_default();
                out.push(entry(
                    ObjectKind::Check,
                    schema,
                    &c.table,
                    &c.name,
                    &[expression.as_str()],
                ))
            }
        }
    }

    // Columnar indexes from the differ's state, expression-only ones from the catalog: the same
    // type, kept in two lists only until the ledger owns indexes.
    for i in db.indexes.iter().chain(catalog.expression_indexes.iter()) {
        let columns = i.columns.join(",");
        let expressions = i
            .expressions
            .as_deref()
            .map(normalise_sql)
            .unwrap_or_default();
        let predicate = i
            .predicate
            .as_deref()
            .map(normalise_sql)
            .unwrap_or_default();
        out.push(entry(
            ObjectKind::Index,
            schema,
            &i.table,
            &i.name,
            &[
                columns.as_str(),
                expressions.as_str(),
                predicate.as_str(),
                i.method.as_str(),
                flag(i.unique),
                flag(i.is_primary),
            ],
        ));
    }

    let roles_of: HashMap<(&str, &str), &Vec<String>> = catalog
        .policy_roles
        .iter()
        .map(|r| ((r.table.as_str(), r.policy.as_str()), &r.roles))
        .collect();
    for p in &db.rls_policies {
        let using = p
            .using_expr
            .as_deref()
            .map(normalise_sql)
            .unwrap_or_default();
        let check = p
            .check_expr
            .as_deref()
            .map(normalise_sql)
            .unwrap_or_default();
        let roles = roles_of
            .get(&(p.table.as_str(), p.name.as_str()))
            .map(|r| r.join(","))
            .unwrap_or_default();
        out.push(entry(
            ObjectKind::Policy,
            schema,
            &p.table,
            &p.name,
            &[
                p.command.as_str(),
                flag(p.permissive),
                roles.as_str(),
                using.as_str(),
                check.as_str(),
            ],
        ));
    }

    for a in &catalog.rls_attributes {
        out.push(entry(
            ObjectKind::RlsAttributes,
            &a.schema,
            &a.table,
            "rls",
            &[flag(a.enabled), flag(a.forced)],
        ));
    }

    for t in &catalog.triggers {
        let events = t.events.join(",");
        let columns = t.columns.join(",");
        let definition = normalise_sql(&t.definition);
        out.push(entry(
            ObjectKind::Trigger,
            &t.schema,
            &t.table,
            &t.name,
            &[
                t.timing.as_str(),
                events.as_str(),
                columns.as_str(),
                flag(t.for_each_row),
                t.function.as_str(),
                flag(t.enabled),
                definition.as_str(),
            ],
        ));
    }

    for f in &catalog.functions {
        let name = format!("{}({})", f.name, f.identity_arguments);
        let body = normalise_sql(&f.body);
        out.push(entry(
            ObjectKind::Function,
            &f.schema,
            "",
            &name,
            &[
                f.return_type.as_str(),
                f.language.as_str(),
                f.volatility.as_str(),
                flag(f.security_definer),
                body.as_str(),
            ],
        ));
    }

    for v in &catalog.views {
        let definition = normalise_sql(&v.definition);
        out.push(entry(
            ObjectKind::View,
            &v.schema,
            "",
            &v.name,
            &[flag(v.materialized), definition.as_str()],
        ));
    }

    let enum_values: HashMap<&str, String> = db
        .enums
        .iter()
        .map(|e| (e.name.as_str(), e.values.join(",")))
        .collect();
    for t in &catalog.enum_types {
        let values = if t.schema == schema {
            enum_values
                .get(t.name.as_str())
                .cloned()
                .unwrap_or_default()
        } else {
            String::new()
        };
        out.push(entry(
            ObjectKind::EnumType,
            &t.schema,
            "",
            &t.name,
            &[values.as_str()],
        ));
    }

    for s in &catalog.sequences {
        out.push(entry(
            ObjectKind::Sequence,
            &s.schema,
            "",
            &s.name,
            &[s.owned_by.as_deref().unwrap_or("")],
        ));
    }

    for g in &catalog.table_grants {
        let privileges = g.privileges.join(",");
        out.push(entry(
            ObjectKind::TableGrant,
            &g.schema,
            &g.table,
            &g.grantee,
            &[privileges.as_str()],
        ));
    }

    for g in &catalog.column_grants {
        let parent = format!("{}.{}", g.table, g.column);
        let privileges = g.privileges.join(",");
        out.push(entry(
            ObjectKind::ColumnGrant,
            &g.schema,
            &parent,
            &g.grantee,
            &[privileges.as_str()],
        ));
    }

    for l in &catalog.security_labels {
        let parent = match &l.column {
            Some(column) => format!("{}.{}", l.table, column),
            None => l.table.clone(),
        };
        out.push(entry(
            ObjectKind::SecurityLabel,
            &l.schema,
            &parent,
            &l.provider,
            &[l.label.as_str()],
        ));
    }

    for j in &catalog.cron_jobs {
        out.push(entry(
            ObjectKind::CronJob,
            "",
            "",
            &j.name,
            &[j.schedule.as_str(), j.command.as_str(), flag(j.active)],
        ));
    }

    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::introspector::constraints::DbConstraint;

    fn check(expression: &str) -> DatabaseState {
        DatabaseState {
            schema: "public".into(),
            constraints: vec![DbConstraint {
                table: "t".into(),
                name: "t_c_check".into(),
                constraint_type: DbConstraintType::Check,
                columns: vec![],
                foreign_table: None,
                foreign_schema: None,
                foreign_columns: None,
                check_expression: Some(expression.into()),
                on_delete: None,
                comment: None,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn whitespace_does_not_change_a_fingerprint_but_meaning_does() {
        let catalog = CatalogState::default();
        let a = fingerprints(&check("CHECK ((x > 1))"), &catalog);
        let b = fingerprints(&check("CHECK  ((x >   1));"), &catalog);
        let c = fingerprints(&check("CHECK ((x > 2))"), &catalog);
        assert_eq!(a, b);
        assert_ne!(a[0].fingerprint, c[0].fingerprint);
        assert_eq!(
            a[0].definition, "expression=CHECK ((x > 1))",
            "the definition is what was hashed, labelled"
        );
    }

    #[test]
    fn a_comment_never_enters_a_fingerprint() {
        let catalog = CatalogState::default();
        let mut with = check("CHECK ((x > 1))");
        with.constraints[0].comment = Some("supatype:managed;kind=check".into());
        assert_eq!(
            fingerprints(&with, &catalog),
            fingerprints(&check("CHECK ((x > 1))"), &catalog)
        );
    }

    #[test]
    fn parts_are_separated_so_lists_cannot_collide() {
        assert_ne!(
            hash(ObjectKind::Index, &["a,b", ""]),
            hash(ObjectKind::Index, &["a", "b"])
        );
        assert_ne!(hash(ObjectKind::Index, &[]), hash(ObjectKind::View, &[]));
    }
}
