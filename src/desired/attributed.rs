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

use crate::introspector::fingerprint::{normalise_sql, ObjectKind};

use super::statements::{attribute_all, head, split_statements};
use super::{DesiredObject, ObjectKey};

/// The kinds a blob's statements become desired objects of. Grants, labels and RLS attributes are
/// left for their own phases: a `REVOKE` leaves nothing live to compare with.
const KINDS: &[ObjectKind] = &[
    ObjectKind::Table,
    ObjectKind::Index,
    ObjectKind::Function,
    ObjectKind::Trigger,
    ObjectKind::View,
    ObjectKind::Policy,
    ObjectKind::CronJob,
];

/// Every object the statements of `sql` create, in key order.
pub fn objects(sql: &str, schema: &str) -> Vec<DesiredObject> {
    let mut grouped: BTreeMap<ObjectKey, Vec<String>> = BTreeMap::new();
    for statement in attribute_all(schema, split_statements(sql)) {
        let h = head(&statement.sql);
        // The drop before a create and the stamp are the old mechanism's; the reconcile drops and
        // the ledger records.
        if h.starts_with("DROP ") || h.starts_with("REVOKE ") || h.starts_with("COMMENT ON ") {
            continue;
        }
        for key in statement.attribution.keys() {
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

/// The parts of `create_sql` the catalog will report for `key`, labelled as the fingerprint
/// labels them (`ObjectKind::labels`).
fn structure(key: &ObjectKey, create_sql: &str) -> BTreeMap<&'static str, String> {
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
        out.insert("body", normalise_sql(body));
    }
    out
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

/// `columns` (when every key is a column), `method`, `unique`, `primary`.
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
        if !inner.contains('(') {
            let columns: Vec<String> = inner
                .split(',')
                .map(|c| c.trim().trim_matches('"').to_string())
                .collect();
            if columns.iter().all(|c| !c.contains(' ')) {
                out.insert("columns", columns.join(","));
            }
        }
    }
    out
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
}
