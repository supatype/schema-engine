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
use std::collections::{BTreeMap, HashMap};

use super::catalog::{CatalogState, DbFunction, DbPolicy, DbSecurityLabel};
use super::constraints::{DbConstraint, DbConstraintType};
use super::indexes::DbIndex;
use super::tables::DbTable;
use crate::sql_quote::{quote_ident, quote_literal, quote_qualified};
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
    SecurityLabel,
    CronJob,
    /// A table's `REPLICA IDENTITY`, which decides what the WAL carries of a row an `UPDATE` or
    /// `DELETE` touches: realtime judges a `DELETE` from the whole old row (F68).
    ReplicaIdentity,
}

impl ObjectKind {
    /// Every kind, in declaration order.
    pub const ALL: [ObjectKind; 19] = [
        ObjectKind::Schema,
        ObjectKind::Table,
        ObjectKind::Column,
        ObjectKind::PrimaryKey,
        ObjectKind::ForeignKey,
        ObjectKind::Unique,
        ObjectKind::Check,
        ObjectKind::Index,
        ObjectKind::Trigger,
        ObjectKind::Function,
        ObjectKind::View,
        ObjectKind::Policy,
        ObjectKind::RlsAttributes,
        ObjectKind::EnumType,
        ObjectKind::Sequence,
        ObjectKind::TableGrant,
        ObjectKind::SecurityLabel,
        ObjectKind::CronJob,
        ObjectKind::ReplicaIdentity,
    ];

    /// The kind written as `snake_case` text: the serde form, the ledger's `kind` column and the
    /// first bytes of every hash.
    pub fn parse(text: &str) -> Option<ObjectKind> {
        Self::ALL.into_iter().find(|k| k.as_str() == text)
    }

    pub fn as_str(self) -> &'static str {
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
            ObjectKind::SecurityLabel => "security_label",
            ObjectKind::CronJob => "cron_job",
            ObjectKind::ReplicaIdentity => "replica_identity",
        }
    }
}

/// What identifies an object: the four things both the desired set and the live fingerprints are
/// keyed by, and the ledger's primary key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectKey {
    pub kind: ObjectKind,
    pub schema: String,
    /// The table for table-scoped kinds, `table.column` for column-scoped ones, empty otherwise.
    pub parent: String,
    pub name: String,
}

impl std::fmt::Display for ObjectKey {
    /// `check public.posts.posts_title_check`: the kind, then the dotted path, with an empty
    /// parent folded away.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.kind.as_str(), self.schema)?;
        if !self.parent.is_empty() {
            write!(f, ".{}", self.parent)?;
        }
        write!(f, ".{}", self.name)
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
    /// recorded definition against its live one without a renderer per kind. Each value is
    /// written with [`definition_value`], so a line break inside one (a multi-line string literal
    /// in a function body) cannot end its line.
    pub definition: String,
    /// The object's `COMMENT`, for the kinds that carry one. Never hashed: comments are the
    /// user's (D1). Read so an older engine's `supatype:managed` stamp can be recognised and
    /// moved into the ledger (plan section 7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// The statement that would create this object as it is, from the catalog's own rendering, for
    /// the kinds whose definition Postgres hands back whole (triggers, functions). What a rollback
    /// runs to put back an object the push replaced without a ledger row to remember it by.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_sql: Option<String>,
}

impl ObjectFingerprint {
    fn commented(mut self, comment: Option<&str>) -> Self {
        self.comment = comment.map(str::to_string);
        self
    }

    /// Whether an older engine stamped this object as managed.
    pub fn stamped(&self) -> bool {
        crate::managed::is_managed_comment(self.comment.as_deref())
    }

    pub fn key(&self) -> ObjectKey {
        ObjectKey {
            kind: self.kind,
            schema: self.schema.clone(),
            parent: self.parent.clone(),
            name: self.name.clone(),
        }
    }
}

/// Whitespace collapsed to single spaces, trimmed, no trailing semicolon. Case is kept: deparsed
/// SQL quotes identifiers that need it, so folding case would conflate `"A"` with `a`.
///
/// Quoted text is kept byte for byte: a string literal (`'a  b'`, with `''` and, in an `E''`
/// string, `\'` escapes), a quoted identifier (`"a  b"`) and a dollar-quoted body (`$fn$...$fn$`).
/// Whitespace inside those is the value, so `'a  b'` and `'a b'` are different objects. A `--` or
/// `/* */` comment is collapsed like code, and a quote inside one opens nothing.
pub fn normalise_sql(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let n = bytes.len();
    let mut out = String::with_capacity(n);
    // Whether whitespace has been seen since the last token, so a run of it becomes one space.
    let mut gap = false;
    let mut i = 0;
    fn push(out: &mut String, text: &str, gap: &mut bool) {
        if *gap && !out.is_empty() {
            out.push(' ');
        }
        *gap = false;
        out.push_str(text);
    }
    while i < n {
        let c = bytes[i];
        let start = i;
        if c.is_ascii_whitespace() {
            gap = true;
            i += 1;
            continue;
        }
        match c {
            b'\'' => {
                // An `E'...'` string also escapes with a backslash.
                let escapes = i > 0
                    && matches!(bytes[i - 1], b'E' | b'e')
                    && (i < 2 || !(bytes[i - 2].is_ascii_alphanumeric() || bytes[i - 2] == b'_'));
                i += 1;
                while i < n {
                    match bytes[i] {
                        b'\\' if escapes => i += 2,
                        b'\'' if i + 1 < n && bytes[i + 1] == b'\'' => i += 2,
                        b'\'' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
            }
            b'"' => {
                i += 1;
                while i < n {
                    if bytes[i] == b'"' {
                        if i + 1 < n && bytes[i + 1] == b'"' {
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
            b'$' => {
                // `$tag$` where the tag is empty or an identifier; `$1` is a parameter, and a `$`
                // inside an identifier (`a$b`) is part of it.
                let in_word =
                    i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
                let mut j = i + 1;
                while j < n && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                let tagged = !in_word
                    && j < n
                    && bytes[j] == b'$'
                    && !(j > i + 1 && bytes[i + 1].is_ascii_digit());
                if tagged {
                    let tag = &sql[i..=j];
                    i = match sql[j + 1..].find(tag) {
                        Some(off) => j + 1 + off + tag.len(),
                        None => n,
                    };
                } else {
                    i += 1;
                }
            }
            b'-' if i + 1 < n && bytes[i + 1] == b'-' => {
                // A line comment: its words collapse like code, its quotes open nothing.
                let end = sql[i..].find('\n').map(|o| i + o).unwrap_or(n);
                for word in sql[i..end].split_whitespace() {
                    push(&mut out, word, &mut gap);
                    gap = true;
                }
                i = end;
                continue;
            }
            b'/' if i + 1 < n && bytes[i + 1] == b'*' => {
                let end = sql[i + 2..].find("*/").map(|o| i + 2 + o + 2).unwrap_or(n);
                for word in sql[i..end].split_whitespace() {
                    push(&mut out, word, &mut gap);
                    gap = true;
                }
                gap = false;
                i = end;
                continue;
            }
            _ => {
                // Plain text up to the next whitespace or the next character that may open a
                // quoted region or a comment.
                i += 1;
                while i < n
                    && !bytes[i].is_ascii_whitespace()
                    && !matches!(bytes[i], b'\'' | b'"' | b'$' | b'-' | b'/')
                {
                    i += 1;
                }
            }
        }
        i = i.min(n);
        push(&mut out, &sql[start..i], &mut gap);
    }
    // A trailing `;` (or several) goes, with the whitespace before it.
    while out.ends_with(';') {
        out.pop();
        let trimmed = out.trim_end().len();
        out.truncate(trimmed);
    }
    out
}

/// Sixteen hex characters of SHA-256 over the kind and the parts, separated so that no two part
/// lists can concatenate to the same bytes.
pub fn hash(kind: ObjectKind, parts: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(kind.as_str().as_bytes());
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
    /// The kinds named by themselves rather than by their table: their key's parent is empty.
    pub fn table_level(self) -> bool {
        matches!(
            self,
            ObjectKind::Schema
                | ObjectKind::Table
                | ObjectKind::Function
                | ObjectKind::View
                | ObjectKind::EnumType
                | ObjectKind::Sequence
                | ObjectKind::CronJob
        )
    }

    /// The label of each hashed part, in the order the part lists below supply them. Empty for the
    /// kinds that are hashed on existence alone: a schema and a table.
    pub(crate) fn labels(self) -> &'static [&'static str] {
        match self {
            ObjectKind::Schema | ObjectKind::Table => &[],
            ObjectKind::Column => &["type", "udt", "nullable", "default", "precision", "scale"],
            ObjectKind::PrimaryKey | ObjectKind::Unique => &["columns"],
            ObjectKind::ForeignKey => &[
                "columns",
                "references",
                "referenced_columns",
                "on_delete",
                "on_update",
                "match_type",
                "deferrable",
                "initially_deferred",
                "definition",
            ],
            ObjectKind::Check => &["expression"],
            ObjectKind::Index => &[
                "columns",
                "expressions",
                "predicate",
                "method",
                "unique",
                "primary",
                "include",
                "options",
                "definition",
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
                "arguments",
                "config",
                "strict",
                "leakproof",
                "parallel",
                "cost",
                "rows",
            ],
            ObjectKind::View => &["materialized", "definition"],
            ObjectKind::Policy => &["command", "permissive", "roles", "using", "with_check"],
            ObjectKind::RlsAttributes => &["enabled"],
            ObjectKind::EnumType => &["values"],
            ObjectKind::Sequence => &["owned_by"],
            ObjectKind::TableGrant => &["privileges", "columns"],
            ObjectKind::SecurityLabel => &["label"],
            ObjectKind::CronJob => &["schedule", "command", "active"],
            ObjectKind::ReplicaIdentity => &["identity"],
        }
    }
}

/// A part as it is written into a definition line: backslashes doubled and line breaks written
/// `\n` and `\r`, so every part stays on its own line and the line reads back to exactly one
/// value. [`normalise_sql`] keeps a string literal's line breaks, which are its value. A desired
/// object's structure value that can hold one is written this way too, so the two compare.
pub fn definition_value(part: &str) -> String {
    if !part.contains(['\\', '\n', '\r']) {
        return part.to_string();
    }
    part.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
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
        .map(|(label, value)| format!("{label}={}", definition_value(value)))
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
        comment: None,
        create_sql: None,
    }
}

/// `CREATE OR REPLACE FUNCTION` for a function as the catalog reports it: the O1 definition
/// renderer for this kind, and what a rollback runs to restore one the push replaced.
///
/// `pg_get_functiondef`'s own statement, which carries everything the function is: its `SET
/// search_path`, `STRICT`, `LEAKPROOF`, `PARALLEL`, `COST`, `ROWS`, argument names and defaults,
/// and a procedure as a procedure. Rebuilt from parts, a rollback put a `SECURITY DEFINER`
/// function back without the `search_path` it pinned. The parts are the fallback only for a
/// catalog serialised before the definition was read.
fn function_create_sql(f: &DbFunction) -> String {
    let definition = f.definition.trim();
    if !definition.is_empty() {
        return format!("{};", definition.trim_end_matches(';'));
    }
    let volatility = match f.volatility.as_str() {
        "i" => "IMMUTABLE",
        "s" => "STABLE",
        _ => "VOLATILE",
    };
    let security = if f.security_definer {
        " SECURITY DEFINER"
    } else {
        ""
    };
    format!(
        "CREATE OR REPLACE FUNCTION {}({}) RETURNS {} LANGUAGE {} {volatility}{security} AS $supatype_previous${}$supatype_previous$;",
        quote_qualified(&f.schema, &f.name),
        f.identity_arguments,
        f.return_type,
        f.language,
        f.body
    )
}

/// `pg_get_triggerdef` gives the whole `CREATE TRIGGER`; `OR REPLACE` makes it a restore.
fn trigger_create_sql(definition: &str) -> String {
    format!(
        "{};",
        definition.replacen("CREATE TRIGGER ", "CREATE OR REPLACE TRIGGER ", 1)
    )
}

/// The `SECURITY LABEL` that puts a label back as the catalog reports it: what a rollback runs to
/// restore one the push took off or replaced.
fn security_label_create_sql(l: &DbSecurityLabel) -> String {
    let table = quote_qualified(&l.schema, &l.table);
    let target = match &l.column {
        Some(column) => format!("COLUMN {table}.{}", quote_ident(column)),
        None => format!("TABLE {table}"),
    };
    format!(
        "SECURITY LABEL FOR {} ON {target} IS {};",
        quote_ident(&l.provider),
        quote_literal(&l.label)
    )
}

/// `CREATE POLICY` for a policy as the catalog reports it: what a rollback runs to restore one
/// the push dropped or replaced.
fn policy_create_sql(p: &DbPolicy) -> String {
    let command = match p.command.as_str() {
        "r" => "SELECT",
        "a" => "INSERT",
        "w" => "UPDATE",
        "d" => "DELETE",
        _ => "ALL",
    };
    let roles = p
        .roles
        .iter()
        .map(|r| {
            if r == "public" {
                "PUBLIC".to_string()
            } else {
                quote_ident(r)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let using = p
        .using_expr
        .as_deref()
        .map(|e| format!(" USING ({e})"))
        .unwrap_or_default();
    let check = p
        .check_expr
        .as_deref()
        .map(|e| format!(" WITH CHECK ({e})"))
        .unwrap_or_default();
    format!(
        "CREATE POLICY {} ON {}.{} AS {} FOR {command} TO {roles}{using}{check};",
        quote_ident(&p.name),
        quote_ident(&p.schema),
        quote_ident(&p.table),
        if p.permissive {
            "PERMISSIVE"
        } else {
            "RESTRICTIVE"
        },
    )
}

/// One grantee's privileges on one table: what it holds on the table, and on each column.
#[derive(Default)]
struct HeldPrivileges<'a> {
    table: Vec<&'a str>,
    columns: BTreeMap<&'a str, Vec<&'a str>>,
}

/// One fingerprint per grantee and table, carrying its table privileges and its column privileges
/// together: Postgres revokes a table privilege on every column too, so the two are one object
/// (Phase 4.7c).
fn grant_entries(catalog: &CatalogState, out: &mut Vec<ObjectFingerprint>) {
    let mut held: BTreeMap<(&str, &str, &str), HeldPrivileges<'_>> = BTreeMap::new();
    for g in &catalog.table_grants {
        let entry = held
            .entry((g.schema.as_str(), g.table.as_str(), g.grantee.as_str()))
            .or_default();
        entry.table = g.privileges.iter().map(String::as_str).collect();
    }
    for g in &catalog.column_grants {
        held.entry((g.schema.as_str(), g.table.as_str(), g.grantee.as_str()))
            .or_default()
            .columns
            .insert(
                g.column.as_str(),
                g.privileges.iter().map(String::as_str).collect(),
            );
    }
    for ((schema, table, grantee), privileges) in held {
        let mut fingerprint = grant_entry(schema, table, grantee, &privileges);
        fingerprint.create_sql = Some(grant_create_sql(schema, table, grantee, &privileges));
        out.push(fingerprint);
    }
}

fn grant_entry(
    schema: &str,
    table: &str,
    grantee: &str,
    privileges: &HeldPrivileges<'_>,
) -> ObjectFingerprint {
    let columns = privileges
        .columns
        .iter()
        .map(|(column, privs)| format!("{column}={}", privs.join("|")))
        .collect::<Vec<_>>()
        .join(";");
    entry(
        ObjectKind::TableGrant,
        schema,
        table,
        grantee,
        &[privileges.table.join(",").as_str(), columns.as_str()],
    )
}

/// A grantee that holds nothing on a table, which the catalog has no row for. The ledger records
/// it when the rules allow a role nothing, so a push compares "nothing" with "nothing".
pub fn holding_nothing(key: &ObjectKey) -> ObjectFingerprint {
    let mut fingerprint = grant_entry(
        &key.schema,
        &key.parent,
        &key.name,
        &HeldPrivileges::default(),
    );
    fingerprint.create_sql = Some(grant_create_sql(
        &key.schema,
        &key.parent,
        &key.name,
        &HeldPrivileges::default(),
    ));
    fingerprint
}

/// Revoke everything, then grant exactly what the catalog reports: what a rollback runs to
/// restore a grantee's privileges the push replaced.
fn grant_create_sql(
    schema: &str,
    table: &str,
    grantee: &str,
    privileges: &HeldPrivileges<'_>,
) -> String {
    let target = quote_qualified(schema, table);
    let role = if grantee == "PUBLIC" {
        "PUBLIC".to_string()
    } else {
        quote_ident(grantee)
    };
    let mut statements = vec![format!("REVOKE ALL PRIVILEGES ON {target} FROM {role};")];
    if !privileges.table.is_empty() {
        statements.push(format!(
            "GRANT {} ON {target} TO {role};",
            privileges.table.join(", ")
        ));
    }
    for (column, privs) in &privileges.columns {
        for privilege in privs {
            statements.push(format!(
                "GRANT {privilege} ({}) ON {target} TO {role};",
                quote_ident(column)
            ));
        }
    }
    statements.join("\n")
}

/// `ENABLE ROW LEVEL SECURITY` on a table: the one statement an RLS attributes object runs, and
/// what a rollback runs to restore it. Row-level security is never turned off automatically (D9).
pub fn rls_enable_sql(schema: &str, table: &str) -> String {
    format!(
        "ALTER TABLE {} ENABLE ROW LEVEL SECURITY;",
        quote_qualified(schema, table)
    )
}

/// The name a replica identity object goes by: one per table, keyed by the table as its parent.
pub const REPLICA_IDENTITY: &str = "replica_identity";

/// What a model table's replica identity is: `FULL`, so the WAL carries the whole old row of an
/// `UPDATE` or `DELETE`, which realtime needs to judge whether a subscriber could see it (F68).
pub const REPLICA_IDENTITY_FULL: &str = "f";

/// The statement that sets a table's replica identity to `letter`, as `pg_class.relreplident`
/// spells it: `d`efault, `f`ull or `n`othing. `None` for `i`, an index the letter does not name, so
/// a rollback cannot put that one back.
pub fn replica_identity_sql(schema: &str, table: &str, letter: &str) -> Option<String> {
    let identity = match letter {
        "d" => "DEFAULT",
        "f" => "FULL",
        "n" => "NOTHING",
        _ => return None,
    };
    Some(format!(
        "ALTER TABLE {} REPLICA IDENTITY {identity};",
        quote_qualified(schema, table)
    ))
}

/// Every fingerprint the two states support, sorted by kind, schema, parent and name.
pub fn fingerprints(db: &DatabaseState, catalog: &CatalogState) -> Vec<ObjectFingerprint> {
    let schema = db.schema.as_str();
    let mut out = Vec::new();

    for s in &catalog.schemas {
        out.push(
            entry(ObjectKind::Schema, &s.name, "", &s.name, &[]).commented(s.comment.as_deref()),
        );
    }

    // Columnar indexes from the differ's state, expression-only ones from the catalog: the same
    // type, kept in two lists only until the ledger owns indexes.
    relation_entries(
        schema,
        &db.tables,
        &db.constraints,
        db.indexes.iter().chain(&catalog.expression_indexes),
        &mut out,
    );
    for e in &catalog.engine_tables {
        relation_entries(&e.schema, &e.tables, &e.constraints, &e.indexes, &mut out);
    }

    policy_and_catalog_entries(db, catalog, &mut out);

    out.sort();
    out
}

/// Tables with their columns, constraints and indexes, for the project schema and for each engine
/// schema alike.
fn relation_entries<'a>(
    schema: &str,
    tables: &[DbTable],
    constraints: &[DbConstraint],
    indexes: impl IntoIterator<Item = &'a DbIndex>,
    out: &mut Vec<ObjectFingerprint>,
) {
    for table in tables {
        for col in &table.columns {
            // An identity or generated column cannot have a default: how the database fills it
            // takes the default's place, so a plain column's fingerprint is unchanged.
            let default = col
                .default
                .clone()
                .or_else(|| col.generation())
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
        }
        // Existence only (Phase 4.11, a deviation from plan 3.2's "the set of its columns"): each
        // column is its own ledger row, and one someone added is theirs under D4, so a column set in
        // the table's fingerprint would report every user column as the table drifting.
        out.push(
            entry(ObjectKind::Table, &table.schema, "", &table.name, &[])
                .commented(table.comment.as_deref()),
        );
    }

    for c in constraints {
        let columns = c.columns.join(",");
        let fingerprint = match c.constraint_type {
            DbConstraintType::PrimaryKey => entry(
                ObjectKind::PrimaryKey,
                schema,
                &c.table,
                &c.name,
                &[columns.as_str()],
            ),
            DbConstraintType::Unique => entry(
                ObjectKind::Unique,
                schema,
                &c.table,
                &c.name,
                &[columns.as_str()],
            ),
            DbConstraintType::ForeignKey => {
                let foreign_columns = c
                    .foreign_columns
                    .as_ref()
                    .map(|v| v.join(","))
                    .unwrap_or_default();
                // Schema-qualified: a key to `auth.users` is not a key to `public.users`.
                let references = format!(
                    "{}.{}",
                    c.foreign_schema.as_deref().unwrap_or(schema),
                    c.foreign_table.as_deref().unwrap_or("")
                );
                // Parts of their own, so a desired key predicts them and a user's key that differs
                // only in one of them is not taken for ours.
                let options = c.foreign_key_options.clone().unwrap_or_default();
                // The whole deparsed constraint also carries `NOT VALID`, which no part does.
                let definition = c
                    .definition
                    .as_deref()
                    .map(normalise_sql)
                    .unwrap_or_default();
                entry(
                    ObjectKind::ForeignKey,
                    schema,
                    &c.table,
                    &c.name,
                    &[
                        columns.as_str(),
                        references.as_str(),
                        foreign_columns.as_str(),
                        c.on_delete.as_deref().unwrap_or(""),
                        options.on_update.as_str(),
                        options.match_type.as_str(),
                        flag(options.deferrable),
                        flag(options.initially_deferred),
                        definition.as_str(),
                    ],
                )
            }
            DbConstraintType::Check => {
                let expression = c
                    .check_expression
                    .as_deref()
                    .map(normalise_sql)
                    .unwrap_or_default();
                entry(
                    ObjectKind::Check,
                    schema,
                    &c.table,
                    &c.name,
                    &[expression.as_str()],
                )
            }
        };
        out.push(fingerprint.commented(c.comment.as_deref()));
    }

    for i in indexes {
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
        let include = i.include.join(",");
        // `pg_get_indexdef` from the method on (`btree (a, b DESC) INCLUDE (c) WHERE ...`): the
        // name is the key and the table the parent, and what follows carries whatever the parts
        // before it do not (an expression's collation, storage parameters, `NULLS NOT DISTINCT`).
        let definition = i
            .definition
            .as_deref()
            .and_then(|d| d.split_once(" USING ").map(|(_, rest)| normalise_sql(rest)))
            .unwrap_or_default();
        out.push(
            entry(
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
                    include.as_str(),
                    i.options.as_str(),
                    definition.as_str(),
                ],
            )
            .commented(i.comment.as_deref()),
        );
    }
}

/// Every kind the catalog sweep reads.
fn policy_and_catalog_entries(
    db: &DatabaseState,
    catalog: &CatalogState,
    out: &mut Vec<ObjectFingerprint>,
) {
    let schema = db.schema.as_str();
    for p in &catalog.policies {
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
        let roles = p.roles.join(",");
        let mut fingerprint = entry(
            ObjectKind::Policy,
            &p.schema,
            &p.table,
            &p.name,
            &[
                p.command.as_str(),
                flag(p.permissive),
                roles.as_str(),
                using.as_str(),
                check.as_str(),
            ],
        )
        .commented(p.comment.as_deref());
        fingerprint.create_sql = Some(policy_create_sql(p));
        out.push(fingerprint);
    }

    // Enablement only (D9): `FORCE` is not the engine's, so a hand-set one is not drift.
    for a in &catalog.rls_attributes {
        let mut fingerprint = entry(
            ObjectKind::RlsAttributes,
            &a.schema,
            &a.table,
            "rls",
            &[flag(a.enabled)],
        );
        fingerprint.create_sql = Some(rls_enable_sql(&a.schema, &a.table));
        out.push(fingerprint);

        // The letter `pg_class.relreplident` holds, read in the same pass.
        let mut fingerprint = entry(
            ObjectKind::ReplicaIdentity,
            &a.schema,
            &a.table,
            REPLICA_IDENTITY,
            &[a.replica_identity.as_str()],
        );
        fingerprint.create_sql = replica_identity_sql(&a.schema, &a.table, &a.replica_identity);
        out.push(fingerprint);
    }

    for t in &catalog.triggers {
        let events = t.events.join(",");
        let columns = t.columns.join(",");
        let definition = normalise_sql(&t.definition);
        let mut fingerprint = entry(
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
        )
        .commented(t.comment.as_deref());
        fingerprint.create_sql = Some(trigger_create_sql(&t.definition));
        out.push(fingerprint);
    }

    for f in &catalog.functions {
        let name = format!("{}({})", f.name, f.identity_types);
        let body = normalise_sql(&f.body);
        let arguments = normalise_sql(&f.arguments);
        // One `SET` per entry, as `proconfig` holds them; a value may itself hold a comma
        // (`search_path=a, b`), so entries are joined on what no setting contains.
        let config = f.config.join("\u{1f}");
        let mut fingerprint = entry(
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
                arguments.as_str(),
                config.as_str(),
                flag(f.strict),
                flag(f.leakproof),
                f.parallel.as_str(),
                f.cost.as_str(),
                f.rows.as_str(),
            ],
        )
        .commented(f.comment.as_deref());
        fingerprint.create_sql = Some(function_create_sql(f));
        out.push(fingerprint);
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

    grant_entries(catalog, out);

    for l in &catalog.security_labels {
        let parent = match &l.column {
            Some(column) => format!("{}.{}", l.table, column),
            None => l.table.clone(),
        };
        let mut fingerprint = entry(
            ObjectKind::SecurityLabel,
            &l.schema,
            &parent,
            &l.provider,
            &[l.label.as_str()],
        );
        fingerprint.create_sql = Some(security_label_create_sql(l));
        out.push(fingerprint);
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
                definition: None,
                comment: None,
                foreign_key_options: None,
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
        let stamped = fingerprints(&with, &catalog);
        let bare = fingerprints(&check("CHECK ((x > 1))"), &catalog);
        assert_eq!(stamped[0].fingerprint, bare[0].fingerprint);
        assert_eq!(stamped[0].definition, bare[0].definition);
        // The comment travels beside the fingerprint, where the reconcile reads the stamp.
        assert!(stamped[0].stamped() && !bare[0].stamped());
    }

    #[test]
    fn whitespace_inside_quoted_text_is_kept() {
        // Outside quotes: collapsed, as before.
        assert_eq!(normalise_sql("  SELECT\n  1 ,\t2 ;\n"), "SELECT 1 , 2");
        // Inside a literal, a quoted identifier or a dollar-quoted body the whitespace is the
        // value, and two values that differ only there are different objects.
        assert_eq!(
            normalise_sql("CHECK ((x = 'a  b'))"),
            "CHECK ((x = 'a  b'))"
        );
        assert_ne!(normalise_sql("x = 'a  b'"), normalise_sql("x = 'a b'"));
        assert_eq!(
            normalise_sql("SELECT  \"my  col\"  FROM t"),
            "SELECT \"my  col\" FROM t"
        );
        assert_eq!(
            normalise_sql("AS $fn$\n  SELECT  1\n$fn$ ;"),
            "AS $fn$\n  SELECT  1\n$fn$"
        );
        assert_eq!(normalise_sql("AS $$ a   b $$"), "AS $$ a   b $$");
        // Escaped quotes do not end the literal early.
        assert_eq!(normalise_sql("'it''s   x'   y"), "'it''s   x' y");
        assert_eq!(normalise_sql("E'it\\'s   x'   y"), "E'it\\'s   x' y");
        assert_eq!(normalise_sql("\"a\"\"b   c\"   d"), "\"a\"\"b   c\" d");
        // A parameter and a `$` inside an identifier are not dollar quotes.
        assert_eq!(normalise_sql("f($1,   $2)  a$b   c"), "f($1, $2) a$b c");
        // A quote in a comment opens nothing.
        assert_eq!(
            normalise_sql("-- don't\nSELECT   1"),
            normalise_sql("-- don't\n  SELECT 1")
        );
        // Text with no quotes normalises exactly as a plain whitespace split did.
        let plain = "CREATE  INDEX i\n ON t USING btree (a, b)  WHERE (x > 1);";
        assert_eq!(
            normalise_sql(plain),
            plain
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .trim_end_matches(';')
                .to_string()
        );
        // Unterminated quotes run to the end without panicking.
        assert_eq!(normalise_sql("'abc  "), "'abc  ");
        assert_eq!(normalise_sql("E'ab\\"), "E'ab\\");
    }

    fn definer(config: &[&str]) -> CatalogState {
        let set = config
            .iter()
            .map(|c| {
                let (k, v) = c.split_once('=').unwrap();
                format!(" SET {k} TO '{v}'\n")
            })
            .collect::<String>();
        CatalogState {
            functions: vec![DbFunction {
                schema: "_supatype".into(),
                name: "whoami".into(),
                identity_arguments: String::new(),
                identity_types: String::new(),
                return_type: "text".into(),
                language: "sql".into(),
                volatility: "s".into(),
                security_definer: true,
                body: " SELECT current_user ".into(),
                comment: None,
                arguments: String::new(),
                config: config.iter().map(|c| c.to_string()).collect(),
                strict: false,
                leakproof: false,
                parallel: "u".into(),
                cost: "100".into(),
                rows: "0".into(),
                definition: format!(
                    "CREATE OR REPLACE FUNCTION _supatype.whoami()\n RETURNS text\n LANGUAGE sql\n \
                     STABLE SECURITY DEFINER\n{set}AS $function$ SELECT current_user $function$\n"
                ),
            }],
            ..Default::default()
        }
    }

    /// A security definer function whose pinned `search_path` was taken off is a different
    /// function: the fingerprint has to say so, and the statement a rollback runs has to put
    /// the pin back.
    #[test]
    fn a_function_differing_only_in_its_settings_is_a_different_function() {
        let db = DatabaseState::default();
        let pinned = fingerprints(&db, &definer(&["search_path="]));
        let bare = fingerprints(&db, &definer(&[]));
        assert_ne!(pinned[0].fingerprint, bare[0].fingerprint);
        assert!(pinned[0].definition.contains("config=search_path="));

        let sql = pinned[0].create_sql.as_deref().unwrap();
        assert!(sql.contains("SET search_path TO ''"), "{sql}");
        assert!(sql.ends_with("$function$;"), "{sql}");

        let mut strict = definer(&["search_path="]);
        strict.functions[0].strict = true;
        assert_ne!(
            fingerprints(&db, &strict)[0].fingerprint,
            pinned[0].fingerprint
        );
        let mut parallel = definer(&["search_path="]);
        parallel.functions[0].parallel = "s".into();
        assert_ne!(
            fingerprints(&db, &parallel)[0].fingerprint,
            pinned[0].fingerprint
        );
        let mut defaults = definer(&["search_path="]);
        defaults.functions[0].arguments = "n integer DEFAULT 1".into();
        assert_ne!(
            fingerprints(&db, &defaults)[0].fingerprint,
            pinned[0].fingerprint
        );
    }

    fn foreign_key(schema: &str, definition: &str) -> DatabaseState {
        DatabaseState {
            schema: "public".into(),
            constraints: vec![DbConstraint {
                table: "ticket".into(),
                name: "ticket_user_id_fkey".into(),
                constraint_type: DbConstraintType::ForeignKey,
                columns: vec!["user_id".into()],
                foreign_table: Some("users".into()),
                foreign_schema: Some(schema.into()),
                foreign_columns: Some(vec!["id".into()]),
                check_expression: None,
                on_delete: Some("CASCADE".into()),
                definition: Some(definition.into()),
                comment: None,
                foreign_key_options: Some(Default::default()),
            }],
            ..Default::default()
        }
    }

    /// A key to `auth.users` is not a key to a `users` model, and `ON UPDATE`, `DEFERRABLE` and
    /// `NOT VALID` change what a key does.
    #[test]
    fn a_foreign_key_is_fingerprinted_with_its_schema_and_its_whole_definition() {
        let catalog = CatalogState::default();
        let def = "FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE";
        let auth = fingerprints(&foreign_key("auth", def), &catalog);
        let public = fingerprints(
            &foreign_key(
                "public",
                "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE",
            ),
            &catalog,
        );
        assert_ne!(auth[0].fingerprint, public[0].fingerprint);
        assert!(auth[0].definition.contains("references=auth.users\n"));
        assert!(public[0].definition.contains("references=public.users\n"));
        for changed in [
            format!("{def} ON UPDATE CASCADE"),
            format!("{def} DEFERRABLE INITIALLY DEFERRED"),
            format!("{def} NOT VALID"),
            def.replace("REFERENCES", "MATCH FULL REFERENCES"),
        ] {
            assert_ne!(
                fingerprints(&foreign_key("auth", &changed), &catalog)[0].fingerprint,
                auth[0].fingerprint,
                "{changed}"
            );
        }
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
