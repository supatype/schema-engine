//! Desired objects read off a rendered blob (plan 2c, option B).
//!
//! The versions layer is rendered as one script, and rewriting it per object would mean a second
//! copy of every template. Instead the script is split into statements, each statement is
//! attributed to the object it creates (`super::statements`), the statements of one object are
//! joined into its `create_sql`, and the parts the catalog will report for it are read off our own
//! text: a function's return type, language, volatility and body; a trigger's timing, events and
//! function; an index's columns and method; a policy's command and roles. What cannot be read off
//! the text (a view's definition as Postgres deparses it) is left out, and the desired-versus-live
//! comparison then rests on the parts that are there.

use std::collections::BTreeMap;

use crate::introspector::fingerprint::{definition_value, normalise_sql, ObjectKind};

use super::statements::{attribute_all, head, split_statements};
use super::{DesiredObject, ObjectKey};

/// The kinds a blob's statements become desired objects of. Labels and RLS attributes are left for
/// their own phases. A role's privileges on a table or view are here (F14): what the drafts layer
/// and tier 2's views grant decides who may read and write through them, so a hand change to it is
/// drift like any other.
const KINDS: &[ObjectKind] = &[
    ObjectKind::Table,
    ObjectKind::Index,
    ObjectKind::Function,
    ObjectKind::Trigger,
    ObjectKind::View,
    ObjectKind::Policy,
    ObjectKind::CronJob,
    ObjectKind::TableGrant,
];

/// Every object the statements of `sql` create, in key order.
pub fn objects(sql: &str, schema: &str) -> Vec<DesiredObject> {
    let mut grouped: BTreeMap<ObjectKey, Vec<String>> = BTreeMap::new();
    for statement in attribute_all(schema, split_statements(sql)) {
        let h = head(&statement.sql);
        // The drop before a create and the stamp are the old mechanism's; the reconcile drops and
        // the ledger records.
        if h.starts_with("DROP ") || h.starts_with("COMMENT ON ") {
            continue;
        }
        // A `REVOKE` is part of what a grant intends (a role holding nothing is a grant too), and
        // of a function, whose callers are part of it (F14): a rollback that put a function back
        // without its `REVOKE ... FROM PUBLIC` would leave it callable by anyone.
        let revoke = h.starts_with("REVOKE ");
        for key in statement.attribution.keys() {
            if revoke && !matches!(key.kind, ObjectKind::TableGrant | ObjectKind::Function) {
                continue;
            }
            if key.kind == ObjectKind::TableGrant && !governed_role(&key.name) {
                continue;
            }
            if KINDS.contains(&key.kind) {
                grouped
                    .entry(key.clone())
                    .or_default()
                    .push(statement.sql.trim().to_string());
            }
        }
    }
    grouped
        .into_iter()
        .map(|(key, statements)| {
            let create_sql = statements.join("\n");
            DesiredObject {
                structure: structure(&key, &create_sql),
                drop_sql: key.drop_sql().unwrap_or_default(),
                security_relevant: super::security_relevant(key.kind),
                depends_on: Vec::new(),
                key,
                create_sql,
            }
        })
        .collect()
}

/// The roles whose privileges the ledger governs, as on a model table: the API roles a caller can
/// reach the API as, and the owner of tier 2's views. `service_role` and `PUBLIC` are left alone,
/// as they are on the model tables.
fn governed_role(role: &str) -> bool {
    crate::generator::sql::grants::GRANTED_ROLES.contains(&role)
        || role == crate::generator::sql::field_views::API_OWNER
}

/// A grant whose every statement is a `REVOKE` intends the role to hold nothing, which the
/// catalog reports by having no row for it: said so, as a model table's grant of nothing says so.
fn grant_structure(create_sql: &str) -> BTreeMap<&'static str, String> {
    let revokes_only = split_statements(create_sql)
        .iter()
        .all(|s| head(s).starts_with("REVOKE "));
    if revokes_only {
        BTreeMap::from([("privileges", String::new())])
    } else {
        BTreeMap::new()
    }
}

/// The parts of `create_sql` the catalog will report for `key`, labelled as the fingerprint
/// labels them (`ObjectKind::labels`).
fn structure(key: &ObjectKey, create_sql: &str) -> BTreeMap<&'static str, String> {
    if key.kind == ObjectKind::TableGrant {
        return grant_structure(create_sql);
    }
    // The creating statement, found by a split that knows a `;` inside a dollar-quoted body is
    // not the end of one, and read past its leading comments, which may say anything.
    let statements = split_statements(create_sql);
    let created = statements
        .iter()
        .map(|s| head(s))
        .find(|s| s.starts_with("CREATE") || s.starts_with("DO "))
        .unwrap_or(create_sql);
    match key.kind {
        ObjectKind::Function => function_structure(created),
        ObjectKind::Trigger => trigger_structure(created, &key.schema),
        ObjectKind::Index => index_structure(created),
        ObjectKind::Policy => policy_structure(created),
        ObjectKind::View => BTreeMap::from([("materialized", flag(false))]),
        ObjectKind::CronJob => cron_structure(created, &key.name),
        _ => BTreeMap::new(),
    }
}

fn flag(b: bool) -> String {
    if b { "t" } else { "f" }.to_string()
}

/// The text after `keyword` as a word of its own (surrounded by whitespace), compared without
/// case, or None.
fn after_word<'a>(s: &'a str, keyword: &str) -> Option<&'a str> {
    let upper = s.to_ascii_uppercase();
    let mut from = 0;
    while let Some(i) = upper[from..].find(keyword) {
        let at = from + i;
        let before_ok = at == 0 || upper.as_bytes()[at - 1].is_ascii_whitespace();
        let end = at + keyword.len();
        let after_ok = end == upper.len() || upper.as_bytes()[end].is_ascii_whitespace();
        if before_ok && after_ok {
            return Some(s[end..].trim_start());
        }
        from = end;
    }
    None
}

fn first_word(s: &str) -> &str {
    s.split(|c: char| c.is_whitespace() || c == '(' || c == ';')
        .next()
        .unwrap_or("")
}

/// `"a"."b"` or `a.b` as `a.b`, the way the catalog names a function or a table.
fn unquote_path(s: &str) -> String {
    s.split('.')
        .map(|part| part.trim().trim_matches('"'))
        .collect::<Vec<_>>()
        .join(".")
}

/// The body between the first pair of dollar quotes after `AS`.
fn dollar_quoted_body(s: &str) -> Option<&str> {
    let as_at = after_word(s, "AS")?;
    let open = as_at.find('$')?;
    let tag_end = as_at[open + 1..].find('$')? + open + 2;
    let tag = &as_at[open..tag_end];
    let body = &as_at[tag_end..];
    let close = body.find(tag)?;
    Some(&body[..close])
}

/// `returns`, `language`, `volatility`, `security_definer`, `body`. The return type is read only
/// when it is one word (`boolean`, `trigger`); `TABLE(...)` and `SETOF` forms are left to the
/// catalog's spelling.
fn function_structure(sql: &str) -> BTreeMap<&'static str, String> {
    let mut out = BTreeMap::new();
    let signature_end = sql.find('$').unwrap_or(sql.len());
    let signature = &sql[..signature_end];
    if let Some(returns) = after_word(signature, "RETURNS") {
        let word = first_word(returns);
        let upper = word.to_ascii_uppercase();
        if !word.is_empty() && upper != "TABLE" && upper != "SETOF" && !word.contains('.') {
            out.insert("returns", word.to_ascii_lowercase());
        }
    }
    if let Some(language) = after_word(signature, "LANGUAGE") {
        out.insert("language", first_word(language).to_ascii_lowercase());
    }
    let upper = signature.to_ascii_uppercase();
    let volatility = if upper.contains(" IMMUTABLE") {
        "i"
    } else if upper.contains(" STABLE") {
        "s"
    } else {
        "v"
    };
    out.insert("volatility", volatility.to_string());
    out.insert("security_definer", flag(upper.contains("SECURITY DEFINER")));
    if let Some(body) = dollar_quoted_body(sql) {
        out.insert("body", definition_value(&normalise_sql(body)));
    }
    out.extend(function_options(sql));
    out
}

/// A word, a quoted name or a string literal of a function's clauses, or one punctuation mark.
#[derive(Debug, PartialEq)]
enum Token {
    Word(String),
    Quoted(String),
    Literal(String),
    Mark(char),
}

/// `s` as [`Token`]s. Text between dollar quotes (the body) is left out.
fn tokens(s: &str) -> Vec<Token> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let quoted = |i: &mut usize, close: char| {
        let mut text = String::new();
        *i += 1;
        while *i < chars.len() {
            if chars[*i] == close {
                if chars.get(*i + 1) == Some(&close) {
                    text.push(close);
                    *i += 2;
                    continue;
                }
                *i += 1;
                break;
            }
            text.push(chars[*i]);
            *i += 1;
        }
        text
    };
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '\'' {
            out.push(Token::Literal(quoted(&mut i, '\'')));
        } else if c == '"' {
            out.push(Token::Quoted(quoted(&mut i, '"')));
        } else if c == '$' {
            // `$tag$ ... $tag$`: skip to the closing tag.
            let tag_end = chars[i + 1..]
                .iter()
                .position(|&c| c == '$')
                .map(|p| i + 1 + p + 1)
                .unwrap_or(chars.len());
            let tag: String = chars[i..tag_end].iter().collect();
            let rest: String = chars[tag_end..].iter().collect();
            i = match rest.find(&tag) {
                Some(at) => tag_end + rest[..at].chars().count() + tag.chars().count(),
                None => chars.len(),
            };
        } else if c.is_alphanumeric() || c == '_' || c == '.' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || matches!(chars[i], '_' | '.')) {
                i += 1;
            }
            out.push(Token::Word(chars[start..i].iter().collect()));
        } else {
            out.push(Token::Mark(c));
            i += 1;
        }
    }
    out
}

/// One element of a list setting as `proconfig` stores it: a name that needs no quotes bare, any
/// other in double quotes (`''` is `""`).
fn list_element(value: &str) -> String {
    let plain = value
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '$'));
    if plain {
        value.to_string()
    } else {
        crate::sql_quote::quote_ident(value)
    }
}

/// `config`, `strict`, `leakproof`, `parallel`, `cost` and `rows`, as `pg_proc` will hold them for
/// the `CREATE FUNCTION` in `sql`: every `SET` as a `proconfig` entry, and each property at
/// Postgres's default when the statement leaves it out (a cost of 100 for SQL and PL/pgSQL, 1
/// otherwise; 1000 rows for a set-returning function, 0 for any other). Clauses are read on
/// either side of the body, and inside no parentheses, so an argument or a returned column cannot
/// be taken for one.
pub(super) fn function_options(sql: &str) -> BTreeMap<&'static str, String> {
    let all = tokens(sql);
    // From `RETURNS` on: the clauses, not the name or the arguments.
    let start = all
        .iter()
        .position(|t| matches!(t, Token::Word(w) if w.eq_ignore_ascii_case("RETURNS")))
        .unwrap_or(all.len());
    let mut depth = 0usize;
    let mut words: Vec<&Token> = Vec::new();
    for t in &all[start..] {
        match t {
            Token::Mark('(') => depth += 1,
            Token::Mark(')') => depth = depth.saturating_sub(1),
            Token::Mark(';') => break,
            _ if depth == 0 => words.push(t),
            _ => {}
        }
    }
    let is = |i: usize, word: &str| matches!(words.get(i), Some(Token::Word(w)) if w.eq_ignore_ascii_case(word));
    let mut config: Vec<String> = Vec::new();
    let mut strict = false;
    let mut leakproof = false;
    let mut parallel = "u";
    let mut cost: Option<String> = None;
    let mut rows: Option<String> = None;
    let mut language = String::new();
    let set_returning = is(1, "SETOF") || is(1, "TABLE");
    let number = |t: Option<&&Token>| match t {
        Some(Token::Word(n)) => n.parse::<f64>().ok().map(|n| n.to_string()),
        _ => None,
    };
    let mut i = 0;
    while i < words.len() {
        if is(i, "STRICT") || (is(i, "RETURNS") && is(i + 1, "NULL") && is(i + 2, "ON")) {
            strict = true;
        } else if is(i, "CALLED") && is(i + 1, "ON") {
            strict = false;
        } else if is(i, "LEAKPROOF") {
            leakproof = !(i > 0 && is(i - 1, "NOT"));
        } else if is(i, "PARALLEL") {
            parallel = if is(i + 1, "SAFE") {
                "s"
            } else if is(i + 1, "RESTRICTED") {
                "r"
            } else {
                "u"
            };
        } else if is(i, "COST") {
            cost = number(words.get(i + 1));
        } else if is(i, "ROWS") {
            rows = number(words.get(i + 1));
        } else if is(i, "LANGUAGE") {
            if let Some(Token::Word(l)) = words.get(i + 1) {
                language = l.to_ascii_lowercase();
            }
        } else if is(i, "SET") {
            if let Some(Token::Word(name)) = words.get(i + 1) {
                let name = name.to_ascii_lowercase();
                let mut j = i + 2;
                if matches!(words.get(j), Some(Token::Mark('='))) || is(j, "TO") {
                    j += 1;
                }
                let mut values = Vec::new();
                while let Some(t) = words.get(j) {
                    let value = match t {
                        Token::Literal(v) | Token::Quoted(v) => v.clone(),
                        Token::Word(w) => w.to_ascii_lowercase(),
                        Token::Mark(_) => break,
                    };
                    values.push(if name == "search_path" {
                        list_element(&value)
                    } else {
                        value
                    });
                    j += 1;
                    if !matches!(words.get(j), Some(Token::Mark(','))) {
                        break;
                    }
                    j += 1;
                }
                config.push(format!("{name}={}", values.join(", ")));
                i = j;
                continue;
            }
        }
        i += 1;
    }
    let default_cost = if matches!(language.as_str(), "sql" | "plpgsql") {
        "100"
    } else {
        "1"
    };
    BTreeMap::from([
        ("config", definition_value(&config.join("\u{1f}"))),
        ("strict", flag(strict)),
        ("leakproof", flag(leakproof)),
        ("parallel", parallel.to_string()),
        ("cost", cost.unwrap_or_else(|| default_cost.to_string())),
        (
            "rows",
            rows.unwrap_or_else(|| if set_returning { "1000" } else { "0" }.to_string()),
        ),
    ])
}

/// `timing`, `events`, `columns`, `for_each_row`, `function`, `enabled`, with the events in the
/// order `pg_trigger` reports them.
fn trigger_structure(sql: &str, schema: &str) -> BTreeMap<&'static str, String> {
    let mut out = BTreeMap::new();
    let upper = sql.to_ascii_uppercase();
    let (timing, after_timing) = ["INSTEAD OF", "BEFORE", "AFTER"]
        .iter()
        .find_map(|t| upper.find(&format!(" {t} ")).map(|i| (*t, i + t.len() + 2)))
        .unwrap_or(("AFTER", 0));
    out.insert("timing", timing.to_string());
    let on_at = upper[after_timing..]
        .find(" ON ")
        .map(|i| after_timing + i)
        .unwrap_or(upper.len());
    let events_text = &upper[after_timing..on_at];
    let mut events: Vec<&str> = Vec::new();
    let mut columns = String::new();
    for event in events_text.split(" OR ") {
        let event = event.trim();
        if let Some(cols) = event.strip_prefix("UPDATE OF ") {
            events.push("UPDATE");
            columns = cols
                .split(',')
                .map(|c| c.trim().trim_matches('"').to_ascii_lowercase())
                .collect::<Vec<_>>()
                .join(",");
        } else if !event.is_empty() {
            events.push(event);
        }
    }
    let order = ["DELETE", "INSERT", "TRUNCATE", "UPDATE"];
    events.sort_by_key(|e| order.iter().position(|o| o == e).unwrap_or(usize::MAX));
    out.insert("events", events.join(","));
    out.insert("columns", columns);
    out.insert("for_each_row", flag(upper.contains("FOR EACH ROW")));
    if let Some(function) = after_word(sql, "FUNCTION").or_else(|| after_word(sql, "PROCEDURE")) {
        let path = unquote_path(function.split('(').next().unwrap_or(""));
        let qualified = if path.contains('.') {
            path
        } else {
            format!("{schema}.{path}")
        };
        out.insert("function", qualified);
    }
    out.insert("enabled", flag(true));
    out
}

/// `columns` (when every key is a column), `method`, `unique`, `primary`; and when the statement
/// has no `WHERE` or `INCLUDE` and every key is a column with at most a direction and a `NULLS`
/// order, the empty `expressions`, `predicate` and `include` and the `options` that says so, as
/// `DbIndex::options` spells them.
fn index_structure(sql: &str) -> BTreeMap<&'static str, String> {
    let mut out = BTreeMap::new();
    let upper = sql.to_ascii_uppercase();
    out.insert("unique", flag(upper.starts_with("CREATE UNIQUE INDEX")));
    out.insert("primary", flag(false));
    let method = after_word(sql, "USING")
        .map(first_word)
        .unwrap_or("btree")
        .to_ascii_lowercase();
    out.insert("method", method);
    if let (Some(open), Some(close)) = (sql.find('(').filter(|_| true), sql.rfind(')')) {
        // The key list is the last parenthesised group; `USING btree (...)` puts it after `USING`.
        let keys_open = sql[..close].rfind('(').unwrap_or(open);
        let inner = &sql[keys_open + 1..close];
        // With a `WHERE` or an `INCLUDE` the last group is not the key list, so nothing is read
        // from it. Over-cautious on purpose: a column that merely contains either word goes
        // unpredicted, which only leaves labels out.
        let plain = !upper.contains("WHERE") && !upper.contains("INCLUDE");
        if plain && !inner.contains('(') {
            let columns: Vec<String> = inner
                .split(',')
                .map(|c| c.trim().trim_matches('"').to_string())
                .collect();
            if columns.iter().all(|c| !c.contains(' ')) {
                out.insert("columns", columns.join(","));
            }
            if let Some((columns, options)) = ordered_keys(inner) {
                out.insert("columns", columns);
                out.insert("options", options);
                out.insert("expressions", String::new());
                out.insert("predicate", String::new());
                out.insert("include", String::new());
            }
        }
    }
    out
}

/// `"a", "b" DESC` as its columns (`a,b`) and the options of the keys that have any (`2 DESC`),
/// or None when a key is anything but a column with an optional direction and `NULLS` order.
fn ordered_keys(inner: &str) -> Option<(String, String)> {
    let mut columns = Vec::new();
    let mut options = Vec::new();
    for (i, key) in inner.split(',').enumerate() {
        let key = key.trim();
        let (column, rest) = match key.strip_prefix('"') {
            Some(quoted) => {
                let end = quoted.find('"')?;
                (quoted[..end].to_string(), &quoted[end + 1..])
            }
            None => {
                let end = key.find(char::is_whitespace).unwrap_or(key.len());
                (key[..end].to_string(), &key[end..])
            }
        };
        if column.is_empty() {
            return None;
        }
        let words: Vec<String> = rest
            .split_whitespace()
            .map(str::to_ascii_uppercase)
            .collect();
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        let (desc, nulls) = match words.as_slice() {
            [] | ["ASC"] => (false, None),
            ["DESC"] => (true, None),
            ["NULLS", n] | ["ASC", "NULLS", n] => (false, Some(*n)),
            ["DESC", "NULLS", n] => (true, Some(*n)),
            _ => return None,
        };
        // Only what differs from the direction's default is reported: ASC sorts nulls last and
        // DESC first.
        let nulls = match (desc, nulls) {
            (false, Some("FIRST")) => Some("NULLS FIRST"),
            (true, Some("LAST")) => Some("NULLS LAST"),
            (_, Some("FIRST" | "LAST")) | (_, None) => None,
            _ => return None,
        };
        let said: Vec<&str> = desc.then_some("DESC").into_iter().chain(nulls).collect();
        if !said.is_empty() {
            options.push(format!("{} {}", i + 1, said.join(" ")));
        }
        columns.push(column);
    }
    Some((columns.join(","), options.join(",")))
}

/// `command` as `pg_policy.polcmd` spells it, `permissive`, `roles` (sorted, `public` when none).
fn policy_structure(sql: &str) -> BTreeMap<&'static str, String> {
    let mut out = BTreeMap::new();
    let upper = sql.to_ascii_uppercase();
    let command = match after_word(&upper, "FOR").map(first_word) {
        Some("SELECT") => "r",
        Some("INSERT") => "a",
        Some("UPDATE") => "w",
        Some("DELETE") => "d",
        _ => "*",
    };
    out.insert("command", command.to_string());
    out.insert("permissive", flag(!upper.contains("AS RESTRICTIVE")));
    let roles = after_word(sql, "TO")
        .map(|rest| {
            let end = rest
                .to_ascii_uppercase()
                .find(" USING")
                .or_else(|| rest.to_ascii_uppercase().find(" WITH CHECK"))
                .unwrap_or(rest.len());
            let mut roles: Vec<String> = rest[..end]
                .split(',')
                .map(|r| r.trim().trim_matches('"').trim_end_matches(';').to_string())
                .filter(|r| !r.is_empty())
                .collect();
            roles.sort();
            roles.join(",")
        })
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| "public".to_string());
    out.insert("roles", roles);
    out
}

/// `schedule`, `command`, `active` for the job `name` schedules in a `DO $cron$` block.
fn cron_structure(sql: &str, name: &str) -> BTreeMap<&'static str, String> {
    let mut out = BTreeMap::new();
    let marker = format!("cron.schedule('{name}',");
    if let Some(at) = sql.find(&marker) {
        let rest = &sql[at + marker.len()..];
        let mut literals = rest.split('\'').skip(1).step_by(2);
        if let (Some(schedule), Some(command)) = (literals.next(), literals.next()) {
            out.insert("schedule", schedule.to_string());
            out.insert("command", command.to_string());
            out.insert("active", flag(true));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_function_statement_yields_its_catalog_parts() {
        let sql = "CREATE OR REPLACE FUNCTION \"_supatype\".\"can_edit_posts\"(p_record uuid)\n  RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER AS $fn$\n    SELECT TRUE;\n  $fn$;\nGRANT EXECUTE ON FUNCTION \"_supatype\".\"can_edit_posts\"(uuid) TO authenticated;";
        let objects = objects(sql, "public");
        assert_eq!(objects.len(), 1);
        let f = &objects[0];
        assert_eq!(f.key.kind, ObjectKind::Function);
        assert_eq!(f.key.schema, "_supatype");
        assert_eq!(f.key.name, "can_edit_posts(uuid)");
        assert_eq!(f.structure["returns"], "boolean");
        assert_eq!(f.structure["language"], "sql");
        assert_eq!(f.structure["volatility"], "s");
        assert_eq!(f.structure["security_definer"], "f");
        assert_eq!(f.structure["body"], "SELECT TRUE");
        assert!(f.create_sql.contains("GRANT EXECUTE"), "{}", f.create_sql);
        assert!(
            f.drop_sql.starts_with("DROP FUNCTION IF EXISTS"),
            "{}",
            f.drop_sql
        );
    }

    #[test]
    fn a_trigger_statement_yields_its_catalog_parts_and_its_drop_is_left_out() {
        let sql = "DROP TRIGGER IF EXISTS \"posts_versions_audit\" ON \"public\".\"posts\";\nCREATE TRIGGER \"posts_versions_audit\" AFTER INSERT OR UPDATE ON \"public\".\"posts\"\n  FOR EACH ROW EXECUTE FUNCTION \"_supatype\".\"posts_versions_audit\"();";
        let objects = objects(sql, "public");
        assert_eq!(objects.len(), 1);
        let t = &objects[0];
        assert_eq!(t.key.kind, ObjectKind::Trigger);
        assert_eq!(t.key.parent, "posts");
        assert!(!t.create_sql.contains("DROP TRIGGER"));
        assert_eq!(t.structure["timing"], "AFTER");
        assert_eq!(t.structure["events"], "INSERT,UPDATE");
        assert_eq!(t.structure["columns"], "");
        assert_eq!(t.structure["for_each_row"], "t");
        assert_eq!(t.structure["function"], "_supatype.posts_versions_audit");
        assert_eq!(t.structure["enabled"], "t");
    }

    #[test]
    fn a_policy_an_index_and_a_cron_block_yield_theirs() {
        let sql = "CREATE POLICY \"posts_draft_select\" ON \"public\".\"posts\"\n  FOR SELECT USING (TRUE);\nCREATE INDEX IF NOT EXISTS \"idx_a\" ON \"public\".\"posts\" USING btree (\"a\", \"b\");\nDO $cron$\nBEGIN\n  PERFORM cron.schedule('supatype-prune-versions', '0 * * * *',\n    'SELECT _supatype.prune_versions()');\nEND;\n$cron$;";
        let objects = objects(sql, "public");
        let by_kind = |kind: ObjectKind| objects.iter().find(|o| o.key.kind == kind).unwrap();
        let policy = by_kind(ObjectKind::Policy);
        assert_eq!(policy.structure["command"], "r");
        assert_eq!(policy.structure["permissive"], "t");
        assert_eq!(policy.structure["roles"], "public");
        assert!(policy.security_relevant);
        let index = by_kind(ObjectKind::Index);
        assert_eq!(index.structure["columns"], "a,b");
        assert_eq!(index.structure["options"], "");
        assert_eq!(index.structure["predicate"], "");
        assert_eq!(index.structure["expressions"], "");
        assert_eq!(index.structure["method"], "btree");
        assert_eq!(index.structure["unique"], "f");
        let cron = by_kind(ObjectKind::CronJob);
        assert_eq!(cron.key.name, "supatype-prune-versions");
        assert_eq!(cron.structure["schedule"], "0 * * * *");
        assert_eq!(
            cron.structure["command"],
            "SELECT _supatype.prune_versions()"
        );
        assert_eq!(cron.structure["active"], "t");
    }

    /// A body whose string literal spans lines keeps those line breaks through normalising, and the
    /// live definition (one `label=value` line per part) must still carry the whole body for the
    /// desired one to compare with: written raw, the body ended at the literal's first line break.
    #[test]
    fn a_body_with_a_multi_line_literal_matches_its_live_definition() {
        use crate::introspector::catalog::{CatalogState, DbFunction};
        use crate::introspector::fingerprint::fingerprints;
        use crate::ledger::reconcile::parse_definition;

        let body = "\n  BEGIN\n    EXECUTE format('DELETE FROM %I\n      WHERE x = ''a\\b''', t);\n  END\n";
        let sql = format!(
            "CREATE OR REPLACE FUNCTION \"_supatype\".\"prune\"(t text) RETURNS void LANGUAGE plpgsql AS $fn${body}$fn$;"
        );
        let desired = function_structure(&sql);
        let catalog = CatalogState {
            functions: vec![DbFunction {
                schema: "_supatype".into(),
                name: "prune".into(),
                identity_arguments: "t text".into(),
                identity_types: "text".into(),
                return_type: "void".into(),
                language: "plpgsql".into(),
                volatility: "v".into(),
                security_definer: false,
                body: body.into(),
                comment: None,
                arguments: "t text".into(),
                config: Vec::new(),
                strict: false,
                leakproof: false,
                parallel: "u".into(),
                cost: "100".into(),
                rows: "0".into(),
                definition: String::new(),
                acl: Vec::new(),
            }],
            ..Default::default()
        };
        let live = fingerprints(&Default::default(), &catalog).remove(0);
        assert_eq!(
            live.definition.lines().count(),
            ObjectKind::Function.labels().len(),
            "{}",
            live.definition
        );
        let parts = parse_definition(&live.definition);
        assert!(parts["body"].contains("WHERE x"), "{}", parts["body"]);
        assert_eq!(parts["body"], desired["body"]);
    }

    /// Every option `pg_proc` holds is predicted from the statement, each at Postgres's default
    /// when left out, spelled as the catalog read spells it.
    #[test]
    fn a_function_statement_predicts_its_options() {
        let pinned = function_options(
            "CREATE OR REPLACE FUNCTION \"_supatype\".\"f\"(\"strict\" text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $fn$ SELECT TRUE $fn$;",
        );
        assert_eq!(pinned["config"], "search_path=\"\"");
        assert_eq!(
            pinned["strict"], "f",
            "an argument named strict is not STRICT"
        );
        assert_eq!(pinned["leakproof"], "f");
        assert_eq!(pinned["parallel"], "u");
        assert_eq!(pinned["cost"], "100");
        assert_eq!(pinned["rows"], "0");

        let listed = function_options(
            "CREATE FUNCTION s.g(a int) RETURNS SETOF text LANGUAGE plpgsql SET search_path = pg_catalog, \"My\", public SET work_mem = '64MB' AS $$ BEGIN END $$;",
        );
        assert_eq!(
            listed["config"],
            "search_path=pg_catalog, \"My\", public\u{1f}work_mem=64MB"
        );
        assert_eq!(listed["rows"], "1000");

        let helper = function_options(
            "CREATE FUNCTION s.h(v jsonb) RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT LEAKPROOF COST 5 AS $fn$ SELECT '' $fn$;",
        );
        assert_eq!(
            (
                helper["strict"].as_str(),
                helper["parallel"].as_str(),
                helper["leakproof"].as_str(),
                helper["cost"].as_str(),
            ),
            ("t", "s", "t", "5")
        );

        // Clauses after the body count too, as the `_platform` functions write them.
        let after = function_options(
            "CREATE FUNCTION s.t() RETURNS TRIGGER AS $$ BEGIN END $$ LANGUAGE plpgsql STRICT;",
        );
        assert_eq!(
            (after["strict"].as_str(), after["cost"].as_str()),
            ("t", "100")
        );
    }

    /// A same-named function that differs from ours only in its options is not taken for ours: one
    /// missing our `SET search_path` resolves names through its caller's path. With no row and a
    /// neutral location it is a conflict, where the same function with the `SET` is adopted.
    #[test]
    fn a_function_missing_our_search_path_is_a_conflict() {
        use crate::introspector::catalog::{CatalogState, DbFunction};
        use crate::introspector::fingerprint::fingerprints;
        use crate::ledger::reconcile::{reconcile, Action, Inputs, Location};
        use std::collections::BTreeSet;

        let sql = "CREATE OR REPLACE FUNCTION \"public\".\"who\"() RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $fn$ SELECT auth.uid() $fn$;";
        let desired = objects(sql, "public");
        assert_eq!(desired.len(), 1);
        let live = |config: Vec<String>| {
            let catalog = CatalogState {
                functions: vec![DbFunction {
                    schema: "public".into(),
                    name: "who".into(),
                    identity_arguments: String::new(),
                    identity_types: String::new(),
                    return_type: "uuid".into(),
                    language: "sql".into(),
                    volatility: "s".into(),
                    security_definer: true,
                    body: " SELECT auth.uid() ".into(),
                    comment: None,
                    arguments: String::new(),
                    config,
                    strict: false,
                    leakproof: false,
                    parallel: "u".into(),
                    cost: "100".into(),
                    rows: "0".into(),
                    definition: String::new(),
                    acl: Vec::new(),
                }],
                ..Default::default()
            };
            fingerprints(&Default::default(), &catalog)
        };
        let plan = |live: &[crate::introspector::fingerprint::ObjectFingerprint]| {
            let none = BTreeSet::new();
            reconcile(Inputs {
                desired: &desired,
                ledger: &[],
                live,
                created_by_parent: &none,
                dropped_tables: &none,
                location: |_| Location::Neutral,
                named_by_the_engine: &none,
                renamed_tables: &BTreeMap::new(),
                kinds: &[ObjectKind::Function],
            })
            .actions
        };
        let ours = plan(&live(vec!["search_path=\"\"".into()]));
        assert!(matches!(&ours[..], [Action::Adopt { .. }]), "{ours:?}");
        let unpinned = plan(&live(Vec::new()));
        assert!(
            matches!(&unpinned[..], [Action::Conflict { .. }]),
            "{unpinned:?}"
        );
    }

    #[test]
    fn an_index_statement_predicts_its_key_options_and_nothing_it_cannot_read() {
        let s = index_structure(
            "CREATE INDEX IF NOT EXISTS \"v_idx\" ON \"public\".\"v\" (\"record_id\", \"version\" DESC);",
        );
        assert_eq!(s["columns"], "record_id,version");
        assert_eq!(s["options"], "2 DESC");
        assert_eq!(s["predicate"], "");
        assert_eq!(s["include"], "");
        let s = index_structure(
            "CREATE INDEX i ON t (a ASC NULLS FIRST, b DESC NULLS FIRST, c DESC NULLS LAST);",
        );
        assert_eq!(s["columns"], "a,b,c");
        assert_eq!(s["options"], "1 NULLS FIRST,2 DESC,3 DESC NULLS LAST");
        // A partial index, or one with an included column, says nothing about its keys: the last
        // parenthesised group is not the key list.
        for sql in [
            "CREATE INDEX i ON t (a) WHERE (active);",
            "CREATE INDEX i ON t (a) INCLUDE (b);",
        ] {
            let s = index_structure(sql);
            assert!(
                !s.contains_key("columns") && !s.contains_key("predicate"),
                "{sql}: {s:?}"
            );
        }
        let s = index_structure("CREATE INDEX i ON t (a text_pattern_ops);");
        assert!(!s.contains_key("options"), "{s:?}");
    }
}
