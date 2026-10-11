//! A push, one statement at a time, each attributed to the object it creates.
//!
//! Phase 2c of the managed-object ownership plan, option B. The generator renders most of what a
//! push re-asserts as blobs: a function with its `GRANT EXECUTE` in one string, the whole versions
//! layer in one call. Rather than rewrite those templates, this splits the rendered SQL into
//! statements and reads each statement's head to say which object it belongs to. Drizzle does the
//! equivalent at generation time with a `--> statement-breakpoint` between changes; here it is done
//! after the fact, which keeps every blob byte-identical, and the test proves that joining the
//! statements reproduces the blob and that no statement is left unattributed.
//!
//! What that proof covers is the statements a push renders against an empty database
//! (`statement_attribution_tests`, every fixture): the creations and the re-asserted layers. The
//! incremental statements a later push renders from the differ's operations (`ALTER COLUMN`,
//! `RENAME`, a backfill `UPDATE`) are not all recognised, and one that is not reads as
//! [`Attribution::Unknown`], naming no object. `push::created_by_parent` reads every operation
//! through this, but only for the objects a statement creates inline.
//!
//! The split is honest about SQL: a `;` inside a string, a quoted identifier, a line comment or a
//! dollar-quoted body does not end a statement. Everything else is kept verbatim, so each segment
//! is a slice of the original and the concatenation is the original.

use std::collections::HashMap;

use crate::generator::sql::{auth_functions, field_views};
use crate::introspector::fingerprint::ObjectKind;

use super::ObjectKey;

/// One statement of a push, with the leading comments and whitespace that preceded it.
#[derive(Debug, Clone)]
pub struct Statement {
    pub sql: String,
    pub attribution: Attribution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution {
    /// Creates, replaces, comments on, grants on or drops exactly this object.
    Object(ObjectKey),
    /// One statement that several objects share (a `GRANT ... TO a, b`, the cron `DO` block).
    Shared(Vec<ObjectKey>),
    /// Not an object the ledger tracks, and known not to be: `BEGIN`, an extension, a sweep.
    Ignored(&'static str),
    /// A head this module does not recognise. The test treats any of these as a failure.
    Unknown,
}

impl Attribution {
    /// The objects the statement belongs to: one, several, or none.
    pub fn keys(&self) -> &[ObjectKey] {
        match self {
            Attribution::Object(key) => std::slice::from_ref(key),
            Attribution::Shared(keys) => keys,
            Attribution::Ignored(_) | Attribution::Unknown => &[],
        }
    }
}

/// Split `sql` into statements. Concatenating the results reproduces `sql` exactly.
pub fn split_statements(sql: &str) -> Vec<String> {
    let bytes = sql.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        match bytes[i] {
            b'\'' => {
                i += 1;
                while i < n {
                    if bytes[i] == b'\'' {
                        if i + 1 < n && bytes[i + 1] == b'\'' {
                            i += 2;
                            continue;
                        }
                        break;
                    }
                    i += 1;
                }
                i += 1;
            }
            b'"' => {
                i += 1;
                while i < n && bytes[i] != b'"' {
                    i += 1;
                }
                i += 1;
            }
            b'-' if i + 1 < n && bytes[i + 1] == b'-' => {
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'$' => {
                // A dollar quote is `$tag$` where tag is empty or an identifier. Anything else
                // (a `$1` parameter) is not a quote.
                let mut j = i + 1;
                while j < n && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                if j < n && bytes[j] == b'$' && !(j > i + 1 && bytes[i + 1].is_ascii_digit()) {
                    let tag = &sql[i..=j];
                    let body_start = j + 1;
                    match sql[body_start..].find(tag) {
                        Some(off) => i = body_start + off + tag.len(),
                        None => i = n,
                    }
                } else {
                    i += 1;
                }
            }
            b';' => {
                out.push(sql[start..=i].to_string());
                start = i + 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    if start < n {
        // Trailing whitespace and comments belong to the last statement, so nothing is lost.
        match out.last_mut() {
            Some(last) => last.push_str(&sql[start..]),
            None => out.push(sql[start..].to_string()),
        }
    }
    out
}

/// What the attribution has learned so far from earlier statements: which table an index or a
/// constraint belongs to, since a `COMMENT ON INDEX` or `DROP INDEX` names only the index.
#[derive(Default)]
pub struct Context {
    index_parent: HashMap<String, String>,
    constraint_kind: HashMap<(String, String), ObjectKind>,
}

/// Attribute every statement of `statements`, in order; [`Attribution::Unknown`] for a head this
/// module does not recognise (see the module docs for which statements it is proved on).
///
/// A push drops an index before it creates it, so which table an index belongs to is learned
/// from every `CREATE INDEX` first, then the statements are attributed in order.
pub fn attribute_all(schema: &str, statements: Vec<String>) -> Vec<Statement> {
    let mut ctx = Context::default();
    for sql in &statements {
        if let Some((_, table, name)) = created_index(schema, head(sql)) {
            ctx.index_parent.insert(name, table);
        }
    }
    statements
        .into_iter()
        .map(|sql| {
            let attribution = attribute(schema, &sql, &mut ctx);
            Statement { sql, attribution }
        })
        .collect()
}

/// The table an `ALTER TABLE`, `DROP TABLE` or `CREATE TABLE` statement acts on, and the column or
/// constraint its clause names, for what [`attribute_all`] does not name: the differ's incremental
/// and rollback statements (`DROP COLUMN`, `ALTER COLUMN`, `DROP CONSTRAINT`, a table's rename).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableTarget {
    pub schema: String,
    pub table: String,
    pub column: Option<String>,
    pub constraint: Option<String>,
}

/// [`TableTarget`] for `sql`, or `None` when it is not a statement on a table.
pub fn table_target(schema: &str, sql: &str) -> Option<TableTarget> {
    let h = head(sql);
    let rest = [
        "DROP TABLE IF EXISTS ",
        "DROP TABLE ",
        "CREATE TABLE IF NOT EXISTS ",
    ]
    .iter()
    .find_map(|p| h.strip_prefix(p));
    if let Some(rest) = rest {
        let (parts, _) = qualified_name(rest)?;
        let (schema, table) = split_schema(parts, schema);
        return Some(TableTarget {
            schema,
            table,
            column: None,
            constraint: None,
        });
    }
    let rest = h.strip_prefix("ALTER TABLE ")?;
    let rest = rest.strip_prefix("IF EXISTS ").unwrap_or(rest);
    let rest = rest.strip_prefix("ONLY ").unwrap_or(rest);
    let (parts, clause) = qualified_name(rest)?;
    let (schema, table) = split_schema(parts, schema);
    let clause = clause.trim_start();
    let named = |prefixes: &[&str]| {
        prefixes.iter().find_map(|p| {
            let (parts, _) = qualified_name(clause.strip_prefix(p)?)?;
            parts.into_iter().next()
        })
    };
    let column = named(&[
        "DROP COLUMN IF EXISTS ",
        "DROP COLUMN ",
        "ALTER COLUMN ",
        "RENAME COLUMN ",
        "ADD COLUMN IF NOT EXISTS ",
        "ADD COLUMN ",
    ]);
    let constraint = named(&[
        "DROP CONSTRAINT IF EXISTS ",
        "DROP CONSTRAINT ",
        "RENAME CONSTRAINT ",
        "VALIDATE CONSTRAINT ",
        "ADD CONSTRAINT ",
    ]);
    Some(TableTarget {
        schema,
        table,
        column,
        constraint,
    })
}

/// The statement with leading whitespace and `--` comment lines removed.
pub fn head(sql: &str) -> &str {
    let mut rest = sql;
    loop {
        let trimmed = rest.trim_start();
        if let Some(after) = trimmed.strip_prefix("--") {
            rest = match after.find('\n') {
                Some(i) => &after[i + 1..],
                None => "",
            };
            continue;
        }
        return trimmed;
    }
}

/// `"a"."b"`, `a.b`, `"a"` or `a` at the start of `s`: the parts and what follows.
fn qualified_name(s: &str) -> Option<(Vec<String>, &str)> {
    let mut parts = Vec::new();
    let mut rest = s.trim_start();
    loop {
        if let Some(after) = rest.strip_prefix('"') {
            let end = after.find('"')?;
            parts.push(after[..end].to_string());
            rest = &after[end + 1..];
        } else {
            let end = rest
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            if end == 0 {
                return None;
            }
            parts.push(rest[..end].to_string());
            rest = &rest[end..];
        }
        if let Some(after) = rest.strip_prefix('.') {
            rest = after;
            continue;
        }
        return Some((parts, rest));
    }
}

fn split_schema(parts: Vec<String>, default_schema: &str) -> (String, String) {
    let mut it = parts.into_iter();
    match (it.next(), it.next()) {
        (Some(a), Some(b)) => (a, b),
        (Some(a), None) => (default_schema.to_string(), a),
        _ => (default_schema.to_string(), String::new()),
    }
}

/// `schema.name.column` for a column target.
fn split_column(parts: Vec<String>, default_schema: &str) -> (String, String, String) {
    let mut it = parts.into_iter();
    match (it.next(), it.next(), it.next()) {
        (Some(s), Some(t), Some(c)) => (s, t, c),
        (Some(t), Some(c), None) => (default_schema.to_string(), t, c),
        _ => (default_schema.to_string(), String::new(), String::new()),
    }
}

/// `(schema, table, index)` for a `CREATE [UNIQUE] INDEX IF NOT EXISTS` head, or `None`.
fn created_index(schema: &str, h: &str) -> Option<(String, String, String)> {
    let rest = h
        .strip_prefix("CREATE INDEX IF NOT EXISTS ")
        .or_else(|| h.strip_prefix("CREATE UNIQUE INDEX IF NOT EXISTS "))?;
    let (name_parts, rest) = qualified_name(rest)?;
    let name = name_parts.last().cloned().unwrap_or_default();
    let (table_parts, _) = qualified_name(after_keyword(rest, "ON")?)?;
    let (s, t) = split_schema(table_parts, schema);
    Some((s, t, name))
}

/// Every `CONSTRAINT "name" <kind>` declared inline in a `CREATE TABLE` body or an `ADD COLUMN`
/// clause, as keys on table `t`, recorded in `ctx` so a later `COMMENT ON CONSTRAINT` finds the
/// kind.
fn inline_constraints(s: &str, t: &str, body: &str, ctx: &mut Context) -> Vec<ObjectKey> {
    let mut keys = Vec::new();
    for (i, m) in body.match_indices("CONSTRAINT \"") {
        let Some((name_parts, rest)) = qualified_name(&body[i + m.len() - 1..]) else {
            continue;
        };
        let name = name_parts.into_iter().next().unwrap_or_default();
        let Some(kind) = constraint_kind(rest) else {
            continue;
        };
        ctx.constraint_kind
            .insert((t.to_string(), name.clone()), kind);
        keys.push(key(kind, s, t, &name));
    }
    keys
}

/// The kind of constraint whose body starts `s` (what follows `CONSTRAINT "name"`).
fn constraint_kind(s: &str) -> Option<ObjectKind> {
    let u = s.trim_start().to_ascii_uppercase();
    if u.starts_with("PRIMARY KEY") {
        Some(ObjectKind::PrimaryKey)
    } else if u.starts_with("FOREIGN KEY") || u.starts_with("REFERENCES ") {
        // A column-level foreign key (`"a" UUID CONSTRAINT "x" REFERENCES ...`) has no
        // `FOREIGN KEY` keyword; junction tables are declared that way.
        Some(ObjectKind::ForeignKey)
    } else if u.starts_with("UNIQUE") {
        Some(ObjectKind::Unique)
    } else if u.starts_with("CHECK") {
        Some(ObjectKind::Check)
    } else {
        None
    }
}

fn key(kind: ObjectKind, schema: &str, parent: &str, name: &str) -> ObjectKey {
    ObjectKey {
        kind,
        schema: schema.to_string(),
        parent: parent.to_string(),
        name: name.to_string(),
    }
}

/// What follows the first `keyword` that stands alone (whitespace on both sides), compared without
/// case, so an `ON` or `TO` inside a quoted name is never mistaken for the clause.
fn after_keyword<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
    let upper = s.to_ascii_uppercase();
    let mut from = 0;
    while let Some(i) = upper[from..].find(keyword) {
        let at = from + i;
        let end = at + keyword.len();
        let before_ok = at == 0 || upper.as_bytes()[at - 1].is_ascii_whitespace();
        let after_ok = end < upper.len() && upper.as_bytes()[end].is_ascii_whitespace();
        if before_ok && after_ok {
            return Some(&s[end..]);
        }
        from = end;
    }
    None
}

/// What follows `keyword` when `s` starts with it as a whole word, compared without case.
fn strip_keyword<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
    let s = s.trim_start();
    let head = s.get(..keyword.len())?;
    let rest = &s[keyword.len()..];
    (head.eq_ignore_ascii_case(keyword) && rest.starts_with(|c: char| c.is_ascii_whitespace()))
        .then_some(rest)
}

/// The roles after `TO` or `FROM`, trimmed, without the trailing `;`.
fn roles_after(s: &str, word: &str) -> Vec<String> {
    let Some(rest) = after_keyword(s, word) else {
        return Vec::new();
    };
    rest.trim_end()
        .trim_end_matches(';')
        .split(',')
        .map(|r| r.trim().trim_matches('"').to_string())
        .filter(|r| !r.is_empty())
        .collect()
}

/// A function's key name: `name(types)`, the declared argument list canonicalised by
/// [`super::identity::function_key`] to what the catalog reports as `identity_types`.
fn function_key_name(after_name: &str, name: &str) -> String {
    let args = after_name
        .strip_prefix('(')
        .and_then(parenthesised)
        .unwrap_or("");
    super::identity::function_key(name, args)
}

/// The expression of an `ADD CONSTRAINT ... CHECK (...)` statement the desired set wrote: the
/// text between `CHECK (` and its closing parenthesis.
pub fn check_expression(create_sql: &str) -> Option<&str> {
    let start = create_sql.find("CHECK (")? + "CHECK (".len();
    parenthesised(&create_sql[start..])
}

/// The text up to the parenthesis that closes one already opened before `after_open`, with nested
/// parentheses balanced. `None` when it never closes.
pub(crate) fn parenthesised(after_open: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (i, c) in after_open.char_indices() {
        match c {
            '(' => depth += 1,
            ')' if depth == 0 => return Some(&after_open[..i]),
            ')' => depth -= 1,
            _ => {}
        }
    }
    None
}

fn attribute(schema: &str, sql: &str, ctx: &mut Context) -> Attribution {
    let h = head(sql);
    let upper = h.to_ascii_uppercase();
    let starts = |p: &str| upper.starts_with(p);
    let after = |p: &str| &h[p.len()..];

    if h.is_empty() || starts("BEGIN;") || starts("COMMIT;") {
        return Attribution::Ignored("transaction marker");
    }
    if starts("CREATE EXTENSION") {
        return Attribution::Ignored("extension");
    }
    if starts("ALTER DEFAULT PRIVILEGES ") {
        return Attribution::Ignored("default privileges");
    }
    if starts("CREATE SCHEMA IF NOT EXISTS ") {
        let (parts, _) = match qualified_name(after("CREATE SCHEMA IF NOT EXISTS ")) {
            Some(x) => x,
            None => return Attribution::Unknown,
        };
        let name = parts.into_iter().next().unwrap_or_default();
        return Attribution::Object(key(ObjectKind::Schema, &name, "", &name));
    }
    for prefix in [
        "GRANT USAGE ON SCHEMA ",
        "REVOKE ALL ON SCHEMA ",
        "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA ",
    ] {
        if starts(prefix) {
            let (parts, _) = match qualified_name(after(prefix)) {
                Some(x) => x,
                None => return Attribution::Unknown,
            };
            let name = parts.into_iter().next().unwrap_or_default();
            return Attribution::Object(key(ObjectKind::Schema, &name, "", &name));
        }
    }
    if starts("CREATE TABLE IF NOT EXISTS ") {
        let (parts, body) = match qualified_name(after("CREATE TABLE IF NOT EXISTS ")) {
            Some(x) => x,
            None => return Attribution::Unknown,
        };
        let (s, t) = split_schema(parts, schema);
        // The constraints declared inline are created by this statement too.
        let mut keys = vec![key(ObjectKind::Table, &s, "", &t)];
        keys.extend(inline_constraints(&s, &t, body, ctx));
        return one_or_shared(keys);
    }
    if starts("COMMENT ON TABLE ") {
        let (parts, _) = match qualified_name(after("COMMENT ON TABLE ")) {
            Some(x) => x,
            None => return Attribution::Unknown,
        };
        let (s, t) = split_schema(parts, schema);
        return Attribution::Object(key(ObjectKind::Table, &s, "", &t));
    }
    if starts("INSERT INTO ") || starts("DELETE FROM ") || starts("UPDATE ") {
        let p = if starts("INSERT INTO ") {
            "INSERT INTO "
        } else if starts("DELETE FROM ") {
            "DELETE FROM "
        } else {
            "UPDATE "
        };
        let (parts, _) = match qualified_name(after(p)) {
            Some(x) => x,
            None => return Attribution::Unknown,
        };
        let (s, t) = split_schema(parts, schema);
        // Rows the engine keeps in its own tables (the registry, the settings) travel with the table.
        return Attribution::Object(key(ObjectKind::Table, &s, "", &t));
    }
    if starts("CREATE INDEX IF NOT EXISTS ") || starts("CREATE UNIQUE INDEX IF NOT EXISTS ") {
        return match created_index(schema, h) {
            Some((s, t, name)) => {
                ctx.index_parent.insert(name.clone(), t.clone());
                Attribution::Object(key(ObjectKind::Index, &s, &t, &name))
            }
            None => Attribution::Unknown,
        };
    }
    if starts("COMMENT ON INDEX ") || starts("DROP INDEX IF EXISTS ") {
        let p = if starts("COMMENT ON INDEX ") {
            "COMMENT ON INDEX "
        } else {
            "DROP INDEX IF EXISTS "
        };
        let (parts, _) = match qualified_name(after(p)) {
            Some(x) => x,
            None => return Attribution::Unknown,
        };
        let (s, name) = split_schema(parts, schema);
        let parent = ctx.index_parent.get(&name).cloned().unwrap_or_default();
        return Attribution::Object(key(ObjectKind::Index, &s, &parent, &name));
    }
    if starts("ALTER TABLE ") {
        let (parts, rest) = match qualified_name(after("ALTER TABLE ")) {
            Some(x) => x,
            None => return Attribution::Unknown,
        };
        let (s, t) = split_schema(parts, schema);
        let rest_u = rest.trim_start().to_ascii_uppercase();
        if rest_u.starts_with("ENABLE ROW LEVEL SECURITY")
            || rest_u.starts_with("FORCE ROW LEVEL SECURITY")
        {
            return Attribution::Object(key(ObjectKind::RlsAttributes, &s, &t, "rls"));
        }
        if let Some(c) = rest.trim_start().strip_prefix("ADD CONSTRAINT ") {
            let (name_parts, body) = match qualified_name(c) {
                Some(x) => x,
                None => return Attribution::Unknown,
            };
            let name = name_parts.into_iter().next().unwrap_or_default();
            let Some(kind) = constraint_kind(body) else {
                return Attribution::Unknown;
            };
            ctx.constraint_kind.insert((t.clone(), name.clone()), kind);
            return Attribution::Object(key(kind, &s, &t, &name));
        }
        // `ADD COLUMN [IF NOT EXISTS] "c" type ... [CONSTRAINT "x" CHECK (...)]`: the column, and
        // any constraint declared inline with it.
        let add_column = rest
            .trim_start()
            .strip_prefix("ADD COLUMN IF NOT EXISTS ")
            .or_else(|| rest.trim_start().strip_prefix("ADD COLUMN "));
        if let Some(c) = add_column {
            let (column_parts, body) = match qualified_name(c) {
                Some(x) => x,
                None => return Attribution::Unknown,
            };
            let column = column_parts.into_iter().next().unwrap_or_default();
            let mut keys = vec![key(ObjectKind::Column, &s, &t, &column)];
            keys.extend(inline_constraints(&s, &t, body, ctx));
            return one_or_shared(keys);
        }
        return Attribution::Unknown;
    }
    if starts("COMMENT ON CONSTRAINT ") {
        let (name_parts, rest) = match qualified_name(after("COMMENT ON CONSTRAINT ")) {
            Some(x) => x,
            None => return Attribution::Unknown,
        };
        let name = name_parts.into_iter().next().unwrap_or_default();
        let on = rest.trim_start();
        let on = on.strip_prefix("ON ").unwrap_or(on);
        let (table_parts, _) = match qualified_name(on) {
            Some(x) => x,
            None => return Attribution::Unknown,
        };
        let (s, t) = split_schema(table_parts, schema);
        // A comment on a constraint created inline names a kind this module has not seen declared;
        // the only inline comments the generator writes are on uniques and bounds checks.
        let kind = ctx
            .constraint_kind
            .get(&(t.clone(), name.clone()))
            .copied()
            .unwrap_or(if name.ends_with("_key") {
                ObjectKind::Unique
            } else {
                ObjectKind::Check
            });
        return Attribution::Object(key(kind, &s, &t, &name));
    }
    if starts("CREATE OR REPLACE FUNCTION ") || starts("CREATE FUNCTION ") {
        let p = if starts("CREATE OR REPLACE FUNCTION ") {
            "CREATE OR REPLACE FUNCTION "
        } else {
            "CREATE FUNCTION "
        };
        let (parts, rest) = match qualified_name(after(p)) {
            Some(x) => x,
            None => return Attribution::Unknown,
        };
        let (s, f) = split_schema(parts, schema);
        return Attribution::Object(key(
            ObjectKind::Function,
            &s,
            "",
            &function_key_name(rest.trim_start(), &f),
        ));
    }
    if starts("GRANT EXECUTE ON FUNCTION ") || starts("REVOKE ALL ON FUNCTION ") {
        let p = if starts("GRANT EXECUTE ON FUNCTION ") {
            "GRANT EXECUTE ON FUNCTION "
        } else {
            "REVOKE ALL ON FUNCTION "
        };
        let (parts, rest) = match qualified_name(after(p)) {
            Some(x) => x,
            None => return Attribution::Unknown,
        };
        let (s, f) = split_schema(parts, schema);
        return Attribution::Object(key(
            ObjectKind::Function,
            &s,
            "",
            &function_key_name(rest.trim_start(), &f),
        ));
    }
    for p in [
        "CREATE OR REPLACE TRIGGER ",
        "CREATE TRIGGER ",
        "DROP TRIGGER IF EXISTS ",
    ] {
        if starts(p) {
            let (name_parts, rest) = match qualified_name(after(p)) {
                Some(x) => x,
                None => return Attribution::Unknown,
            };
            let name = name_parts.into_iter().next().unwrap_or_default();
            let Some(on) = after_keyword(rest, "ON") else {
                return Attribution::Unknown;
            };
            let (table_parts, _) = match qualified_name(on) {
                Some(x) => x,
                None => return Attribution::Unknown,
            };
            let (s, t) = split_schema(table_parts, schema);
            return Attribution::Object(key(ObjectKind::Trigger, &s, &t, &name));
        }
    }
    for p in [
        "CREATE POLICY ",
        "DROP POLICY IF EXISTS ",
        "COMMENT ON POLICY ",
    ] {
        if starts(p) {
            let (name_parts, rest) = match qualified_name(after(p)) {
                Some(x) => x,
                None => return Attribution::Unknown,
            };
            let name = name_parts.into_iter().next().unwrap_or_default();
            let on = rest.trim_start();
            let on = on.strip_prefix("ON ").unwrap_or(on);
            let (table_parts, _) = match qualified_name(on) {
                Some(x) => x,
                None => return Attribution::Unknown,
            };
            let (s, t) = split_schema(table_parts, schema);
            return Attribution::Object(key(ObjectKind::Policy, &s, &t, &name));
        }
    }
    if starts("ALTER FUNCTION ") {
        // Tier 2's write triggers: given to the views' owner once made.
        let (parts, rest) = match qualified_name(after("ALTER FUNCTION ")) {
            Some(x) => x,
            None => return Attribution::Unknown,
        };
        let (s, f) = split_schema(parts, schema);
        return Attribution::Object(key(
            ObjectKind::Function,
            &s,
            "",
            &function_key_name(rest.trim_start(), &f),
        ));
    }
    for p in [
        "CREATE VIEW ",
        "DROP VIEW IF EXISTS ",
        "ALTER VIEW ",
        "COMMENT ON VIEW ",
    ] {
        if starts(p) {
            let (parts, _) = match qualified_name(after(p)) {
                Some(x) => x,
                None => return Attribution::Unknown,
            };
            let (s, v) = split_schema(parts, schema);
            return Attribution::Object(key(ObjectKind::View, &s, "", &v));
        }
    }
    if starts("SECURITY LABEL ") {
        // A label on a column is keyed `table.column`, one on the table itself by the table.
        let Some(on) = after_keyword(h, "ON") else {
            return Attribution::Unknown;
        };
        let (s, parent) = if let Some(column) = strip_keyword(on, "COLUMN") {
            let (parts, _) = match qualified_name(column) {
                Some(x) => x,
                None => return Attribution::Unknown,
            };
            let (s, t, c) = split_column(parts, schema);
            (s, format!("{t}.{c}"))
        } else if let Some(table) = strip_keyword(on, "TABLE") {
            let (parts, _) = match qualified_name(table) {
                Some(x) => x,
                None => return Attribution::Unknown,
            };
            split_schema(parts, schema)
        } else {
            return Attribution::Unknown;
        };
        let provider = h["SECURITY LABEL ".len()..]
            .trim_start()
            .strip_prefix("FOR ")
            .and_then(|r| r.split_whitespace().next())
            .unwrap_or("")
            .to_string();
        return Attribution::Object(key(ObjectKind::SecurityLabel, &s, &parent, &provider));
    }
    if starts("GRANT ") || starts("REVOKE ") {
        // Table and view privileges: `GRANT ... ON [TABLE] s.t TO r1, r2` / `REVOKE ... ON s.t
        // FROM r`. Any other object type, and the `ALL ... IN SCHEMA` forms, name no one table:
        // read as one, their keyword became the table's name.
        let Some(on) = after_keyword(h, "ON") else {
            return Attribution::Unknown;
        };
        let on = strip_keyword(on, "TABLE").unwrap_or(on);
        if [
            "ALL",
            "SEQUENCE",
            "FUNCTION",
            "PROCEDURE",
            "ROUTINE",
            "SCHEMA",
            "DATABASE",
            "DOMAIN",
            "TYPE",
            "LANGUAGE",
            "LARGE",
            "FOREIGN",
            "TABLESPACE",
            "PARAMETER",
        ]
        .iter()
        .any(|object_type| strip_keyword(on, object_type).is_some())
        {
            return Attribution::Unknown;
        }
        let (parts, _) = match qualified_name(on) {
            Some(x) => x,
            None => return Attribution::Unknown,
        };
        let (s, t) = split_schema(parts, schema);
        let roles = if starts("GRANT ") {
            roles_after(h, "TO")
        } else {
            roles_after(h, "FROM")
        };
        return one_or_shared(
            roles
                .iter()
                .map(|r| key(ObjectKind::TableGrant, &s, &t, r))
                .collect(),
        );
    }
    if starts("DO ") {
        return attribute_do_block(schema, h);
    }
    Attribution::Unknown
}

fn one_or_shared(mut keys: Vec<ObjectKey>) -> Attribution {
    keys.dedup();
    match keys.len() {
        0 => Attribution::Unknown,
        1 => Attribution::Object(keys.remove(0)),
        _ => Attribution::Shared(keys),
    }
}

/// Every `ON "s"."t"` target inside a `DO` block's `EXECUTE` strings, first occurrence first.
fn execute_targets(schema: &str, block: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (i, _) in block.match_indices(" ON \"") {
        if let Some((parts, _)) = qualified_name(&block[i + 4..]) {
            let target = split_schema(parts, schema);
            if !out.contains(&target) {
                out.push(target);
            }
        }
    }
    out
}

/// The role a guarded block is for: the one its `pg_roles` probe names.
fn guarded_role(block: &str) -> Option<String> {
    let rest = &block[block.find("rolname = '")? + "rolname = '".len()..];
    rest.find('\'').map(|end| rest[..end].to_string())
}

/// The `DO` blocks a push contains, told apart by their dollar tag or their contents.
fn attribute_do_block(schema: &str, h: &str) -> Attribution {
    if h.starts_with("DO $cron$") {
        return one_or_shared(
            h.match_indices("cron.schedule('")
                .filter_map(|(i, m)| {
                    let rest = &h[i + m.len()..];
                    rest.find('\'')
                        .map(|end| key(ObjectKind::CronJob, "", "", &rest[..end]))
                })
                .collect(),
        );
    }
    if h.starts_with("DO $mask_label$") {
        // The guarded removal of one label: the statement it executes names it.
        let Some(at) = h.find("SECURITY LABEL ") else {
            return Attribution::Unknown;
        };
        let executed = h[at..].replace("''", "'");
        return attribute(schema, &executed, &mut Context::default());
    }
    let tagged = |tag: &str| h.starts_with(&format!("DO ${tag}$"));
    if tagged(auth_functions::AUTH_SCHEMA_USAGE_TAG) {
        return Attribution::Object(key(ObjectKind::Schema, "auth", "", "auth"));
    }
    if tagged(field_views::OWNER_TAG) || tagged(field_views::OWNER_REACH_TAG) {
        // Tier 2's view owner: made, and given the schemas and functions the views use.
        let api = field_views::VIEW_SCHEMA;
        return Attribution::Object(key(ObjectKind::Schema, api, "", api));
    }
    if tagged(field_views::VIEW_SETUP_TAG) {
        // A view's defaults, copied from its table: part of the view, named in the block by its
        // `regclass` literal.
        let marker = format!("'\"{}\".", field_views::VIEW_SCHEMA);
        let Some(at) = h.find(&marker) else {
            return Attribution::Unknown;
        };
        return match qualified_name(&h[at + 1..]) {
            Some((parts, _)) => {
                let (s, v) = split_schema(parts, schema);
                Attribution::Object(key(ObjectKind::View, &s, "", &v))
            }
            None => Attribution::Unknown,
        };
    }
    if tagged(auth_functions::CLAIMS_ACCESS_TAG) {
        // The API roles' way in to the claim readers: usage on their schema and execute on each.
        let helper = auth_functions::CLAIMS_SCHEMA;
        return Attribution::Object(key(ObjectKind::Schema, helper, "", helper));
    }
    if h.starts_with("DO $grants$") {
        // One block per role and table: the privileges a role holds on a model table (a ledger
        // object since Phase 4.7c), or on a tier 2 view (re-asserted with the view).
        let Some(role) = guarded_role(h) else {
            return Attribution::Unknown;
        };
        return one_or_shared(
            execute_targets(schema, h)
                .iter()
                .map(|(s, t)| key(ObjectKind::TableGrant, s, t, &role))
                .collect(),
        );
    }
    if h.contains("DROP VIEW IF EXISTS ") {
        // `drop_draft_views_sql`: the guarded drop of every draft view, which belongs to the views.
        return one_or_shared(
            h.match_indices("DROP VIEW IF EXISTS ")
                .filter_map(|(i, m)| {
                    qualified_name(&h[i + m.len()..]).map(|(parts, _)| {
                        let (s, v) = split_schema(parts, schema);
                        key(ObjectKind::View, &s, "", &v)
                    })
                })
                .collect(),
        );
    }
    Attribution::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_table_statement_names_its_table_column_and_constraint() {
        let target = |sql: &str| table_target("public", sql).unwrap();
        let t = target("ALTER TABLE \"public\".\"order_item\" DROP COLUMN IF EXISTS \"note\";");
        assert_eq!(
            (t.table.as_str(), t.column.as_deref()),
            ("order_item", Some("note"))
        );
        let t =
            target("-- undo\nALTER TABLE \"public\".\"t\" DROP CONSTRAINT IF EXISTS \"t_a_key\";");
        assert_eq!(
            (t.table.as_str(), t.constraint.as_deref()),
            ("t", Some("t_a_key"))
        );
        let t = target("DROP TABLE IF EXISTS \"public\".\"posts\";");
        assert_eq!(
            (t.table.as_str(), t.column, t.constraint),
            ("posts", None, None)
        );
        assert_eq!(
            table_target("public", "DROP POLICY IF EXISTS \"p\" ON \"public\".\"t\";"),
            None
        );
    }

    #[test]
    fn splitting_keeps_every_byte_and_respects_quotes() {
        let sql = "-- lead\nCREATE TABLE a (x text DEFAULT 'a;b');\nCREATE FUNCTION f() RETURNS text AS $$ SELECT 'x;y'; $$ LANGUAGE sql;\nSELECT 1;\n";
        let parts = split_statements(sql);
        assert_eq!(parts.len(), 3, "{parts:#?}");
        assert_eq!(parts.concat(), sql);
        assert!(parts[1].contains("'x;y';"));
    }

    #[test]
    fn a_tagged_dollar_body_with_semicolons_is_one_statement() {
        let sql = "DO $grants$\nBEGIN\n  EXECUTE 'GRANT SELECT ON \"public\".\"t\" TO anon';\nEND\n$grants$;\n";
        assert_eq!(split_statements(sql).len(), 1);
    }

    #[test]
    fn heads_are_attributed_to_the_right_kind() {
        let mut ctx = Context::default();
        let cases = [
            ("CREATE SCHEMA IF NOT EXISTS _platform;", ObjectKind::Schema, "_platform", "", "_platform"),
            ("CREATE TABLE IF NOT EXISTS \"public\".\"posts\" (\"id\" uuid);", ObjectKind::Table, "public", "", "posts"),
            ("CREATE INDEX IF NOT EXISTS \"posts_x_idx\" ON \"public\".\"posts\" USING btree (\"x\");", ObjectKind::Index, "public", "posts", "posts_x_idx"),
            ("COMMENT ON INDEX \"public\".\"posts_x_idx\" IS 'm';", ObjectKind::Index, "public", "posts", "posts_x_idx"),
            ("ALTER TABLE \"public\".\"posts\" ADD CONSTRAINT \"posts_a_fkey\" FOREIGN KEY (\"a\") REFERENCES \"public\".\"u\" (\"id\");", ObjectKind::ForeignKey, "public", "posts", "posts_a_fkey"),
            ("ALTER TABLE \"public\".\"posts\" ENABLE ROW LEVEL SECURITY;", ObjectKind::RlsAttributes, "public", "posts", "rls"),
            ("CREATE OR REPLACE FUNCTION \"public\".\"can_read_posts\"(\"posts\" \"public\".\"posts\") RETURNS boolean LANGUAGE sql STABLE AS $can$ SELECT TRUE $can$;", ObjectKind::Function, "public", "", "can_read_posts(public.posts)"),
            ("GRANT EXECUTE ON FUNCTION _supatype.\"publish\"(text, text) TO authenticated, service_role;", ObjectKind::Function, "_supatype", "", "publish(text, text)"),
            ("CREATE OR REPLACE TRIGGER \"posts_updated_at_trigger\" BEFORE UPDATE ON \"public\".\"posts\" FOR EACH ROW EXECUTE FUNCTION _platform.set_updated_at();", ObjectKind::Trigger, "public", "posts", "posts_updated_at_trigger"),
            ("DROP POLICY IF EXISTS \"posts_select\" ON \"public\".\"posts\";", ObjectKind::Policy, "public", "posts", "posts_select"),
            ("CREATE VIEW \"draft\".\"posts\" WITH (security_invoker = true) AS SELECT 1;", ObjectKind::View, "draft", "", "posts"),
            ("SECURITY LABEL FOR supatype ON COLUMN \"public\".\"posts\".\"salary\" IS 'MASK READ x';", ObjectKind::SecurityLabel, "public", "posts.salary", "supatype"),
            ("GRANT SELECT ON \"draft\".\"posts\" TO authenticated;", ObjectKind::TableGrant, "draft", "posts", "authenticated"),
            ("GRANT SELECT ON TABLE \"draft\".\"posts\" TO authenticated;", ObjectKind::TableGrant, "draft", "posts", "authenticated"),
            ("REVOKE ALL ON TABLE public.posts FROM anon;", ObjectKind::TableGrant, "public", "posts", "anon"),
            ("SECURITY LABEL FOR supatype ON TABLE \"public\".\"posts\" IS NULL;", ObjectKind::SecurityLabel, "public", "posts", "supatype"),
        ];
        for (sql, kind, schema, parent, name) in cases {
            match attribute("public", sql, &mut ctx) {
                Attribution::Object(k) => {
                    assert_eq!(
                        (
                            k.kind,
                            k.schema.as_str(),
                            k.parent.as_str(),
                            k.name.as_str()
                        ),
                        (kind, schema, parent, name),
                        "{sql}"
                    );
                }
                other => panic!("{sql}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_grant_on_no_one_table_is_not_read_as_a_table_grant() {
        // The object-type keyword used to be taken as the table's name.
        for sql in [
            "GRANT ALL ON ALL TABLES IN SCHEMA public TO anon;",
            "GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO anon;",
            "REVOKE EXECUTE ON FUNCTION public.f(integer) FROM anon;",
            "GRANT USAGE ON SEQUENCE public.s TO anon;",
            "GRANT USAGE ON TYPE public.mood TO anon;",
        ] {
            assert_eq!(
                attribute("public", sql, &mut Context::default()),
                Attribution::Unknown,
                "{sql}"
            );
        }
    }

    #[test]
    fn a_create_table_also_claims_its_inline_constraints() {
        let mut ctx = Context::default();
        let sql = "CREATE TABLE IF NOT EXISTS \"public\".\"article_tags\" (\n    \"article_id\" UUID NOT NULL CONSTRAINT \"article_tags_article_id_fkey\" REFERENCES \"public\".\"articles\" (\"id\") ON DELETE CASCADE,\n    \"slug\" TEXT CONSTRAINT \"article_tags_slug_key\" UNIQUE,\n    CONSTRAINT \"article_tags_pkey\" PRIMARY KEY (\"article_id\", \"slug\"),\n    CONSTRAINT \"article_tags_slug_check\" CHECK (length(\"slug\") > 0)\n);";
        match attribute("public", sql, &mut ctx) {
            Attribution::Shared(keys) => {
                let got: Vec<(ObjectKind, &str)> =
                    keys.iter().map(|k| (k.kind, k.name.as_str())).collect();
                assert_eq!(
                    got,
                    [
                        (ObjectKind::Table, "article_tags"),
                        (ObjectKind::ForeignKey, "article_tags_article_id_fkey"),
                        (ObjectKind::Unique, "article_tags_slug_key"),
                        (ObjectKind::PrimaryKey, "article_tags_pkey"),
                        (ObjectKind::Check, "article_tags_slug_check"),
                    ]
                );
                assert!(keys
                    .iter()
                    .all(|k| k.kind == ObjectKind::Table || k.parent == "article_tags"));
            }
            other => panic!("{other:?}"),
        }
        // A later comment on one of them finds the kind the table declared.
        match attribute("public", "COMMENT ON CONSTRAINT \"article_tags_article_id_fkey\" ON \"public\".\"article_tags\" IS 'x';", &mut ctx) {
            Attribution::Object(k) => assert_eq!(k.kind, ObjectKind::ForeignKey),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_grant_to_several_roles_is_shared_and_a_cron_block_names_its_jobs() {
        let mut ctx = Context::default();
        match attribute(
            "public",
            "GRANT SELECT ON \"draft\".\"posts\" TO authenticated, service_role;",
            &mut ctx,
        ) {
            Attribution::Shared(keys) => assert_eq!(keys.len(), 2),
            other => panic!("{other:?}"),
        }
        let cron = "DO $cron$\nBEGIN\n  PERFORM cron.schedule('supatype-scheduled-publish', '* * * * *', 'x');\n  PERFORM cron.schedule('supatype-prune-versions', '0 * * * *', 'y');\nEND\n$cron$;";
        match attribute("public", cron, &mut ctx) {
            Attribution::Shared(keys) => {
                assert_eq!(
                    keys.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(),
                    ["supatype-scheduled-publish", "supatype-prune-versions"]
                );
            }
            other => panic!("{other:?}"),
        }
    }
}
