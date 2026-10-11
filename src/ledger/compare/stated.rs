//! What a grant's own statements leave a role holding on one relation, read off their text.
//!
//! The model and junction tables' grants are rendered from the rules (`generator::sql::grants`),
//! so what they leave is known without reading SQL. The other grants the ledger records come from
//! statements of their own: the versions layer's on its draft views and history tables, tier 2's on
//! its views and on the tables their owner reads. Those statements are plain `GRANT` and `REVOKE`
//! on the relation, some run as `EXECUTE '...'` inside a `DO` block guarded on the role existing,
//! and applying them in order to what the role held before says what it holds after.

use std::collections::BTreeSet;

use crate::desired::statements::{head, split_statements};

/// The privileges `role` holds on the relation `sql` grants on, starting from `start` (what it
/// held before, such as the default privileges a new relation gets) and applying each `GRANT` and
/// `REVOKE` that names the role, in order. `None` when a statement cannot be read this way (a
/// column privilege, `GRANT ALL`, whose set depends on the server's version): the caller then
/// cannot compare it.
pub fn held_after(sql: &str, role: &str, start: &[String]) -> Option<Vec<String>> {
    let mut held: BTreeSet<String> = start.iter().cloned().collect();
    for statement in statements(sql) {
        apply(&statement, role, &mut held)?;
    }
    Some(held.into_iter().collect())
}

/// Each statement in `sql`, with those a `DO` block runs through `EXECUTE '...'` in its place.
fn statements(sql: &str) -> Vec<String> {
    split_statements(sql)
        .iter()
        .flat_map(|s| {
            let s = head(s).trim().to_string();
            if s.to_ascii_uppercase().starts_with("DO ") {
                executed(&s)
            } else {
                vec![s]
            }
        })
        .collect()
}

/// The literal of every `EXECUTE '...'` in a `DO` block, unquoted.
fn executed(block: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = block;
    while let Some(at) = rest.find("EXECUTE '") {
        let body = &rest[at + "EXECUTE '".len()..];
        let mut text = String::new();
        let mut chars = body.char_indices().peekable();
        let mut end = body.len();
        while let Some((i, c)) = chars.next() {
            if c == '\'' {
                if chars.peek().map(|(_, n)| *n) == Some('\'') {
                    chars.next();
                    text.push('\'');
                    continue;
                }
                end = i + 1;
                break;
            }
            text.push(c);
        }
        out.push(text);
        rest = &body[end..];
    }
    out
}

/// Applies one statement to `held` when it is a `GRANT` or `REVOKE` on a relation naming `role`;
/// `None` when it is one this reading cannot follow.
fn apply(statement: &str, role: &str, held: &mut BTreeSet<String>) -> Option<()> {
    let upper = statement.to_ascii_uppercase();
    let (granting, privileges_end, grantee_word) = if upper.starts_with("GRANT ") {
        (true, upper.find(" ON ")?, " TO ")
    } else if upper.starts_with("REVOKE ") {
        (false, upper.find(" ON ")?, " FROM ")
    } else {
        return Some(());
    };
    let on = &upper[privileges_end + " ON ".len()..];
    if [
        "FUNCTION ",
        "SCHEMA ",
        "SEQUENCE ",
        "ALL ",
        "ROUTINE ",
        "PROCEDURE ",
    ]
    .iter()
    .any(|k| on.starts_with(k))
    {
        return Some(());
    }
    let grantees_at = upper.rfind(grantee_word)? + grantee_word.len();
    let grantees = grantees(&statement[grantees_at..]);
    if !grantees.iter().any(|g| g == role) {
        return Some(());
    }
    let start = if granting {
        "GRANT ".len()
    } else {
        "REVOKE ".len()
    };
    let words = upper[start..privileges_end].trim();
    if words.contains('(') || upper.contains("GRANT OPTION") {
        return None;
    }
    let all = words == "ALL" || words == "ALL PRIVILEGES";
    match (granting, all) {
        (true, true) => return None,
        (false, true) => held.clear(),
        (true, false) => held.extend(words.split(',').map(|p| p.trim().to_string())),
        (false, false) => {
            for privilege in words.split(',') {
                held.remove(privilege.trim());
            }
        }
    }
    Some(())
}

/// The grantees a `TO` or `FROM` list names, unquoted, before any `CASCADE` or `RESTRICT`.
fn grantees(list: &str) -> Vec<String> {
    list.trim()
        .trim_end_matches(';')
        .split(',')
        .map(|g| {
            let g = g.trim();
            let g = g
                .strip_suffix(" CASCADE")
                .or_else(|| g.strip_suffix(" RESTRICT"))
                .unwrap_or(g)
                .trim();
            match g.strip_prefix('"').and_then(|q| q.strip_suffix('"')) {
                Some(quoted) => quoted.replace("\"\"", "\""),
                None if g.eq_ignore_ascii_case("public") => "PUBLIC".to_string(),
                None => g.to_ascii_lowercase(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_draft_views_statements_leave_what_they_grant() {
        let sql = "REVOKE ALL ON \"draft\".\"posts\" FROM anon;\n\
                   GRANT SELECT ON \"draft\".\"posts\" TO authenticated, service_role;";
        let defaults = ["TRUNCATE".to_string()];
        assert_eq!(held_after(sql, "authenticated", &[]).unwrap(), ["SELECT"]);
        assert_eq!(
            held_after(sql, "authenticated", &defaults).unwrap(),
            ["SELECT", "TRUNCATE"]
        );
        assert_eq!(
            held_after(sql, "anon", &defaults).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn guarded_blocks_are_read_through_their_executes() {
        let sql = "DO $grants$\nBEGIN\n  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN\n    \
                   EXECUTE 'REVOKE DELETE ON \"api\".\"t\" FROM anon';\n    \
                   EXECUTE 'GRANT SELECT ON \"api\".\"t\" TO anon';\n  END IF;\nEND\n$grants$;";
        assert_eq!(held_after(sql, "anon", &[]).unwrap(), ["SELECT"]);
        assert_eq!(
            held_after(sql, "authenticated", &[]).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn what_cannot_be_followed_is_said_so() {
        let column = "GRANT UPDATE (title) ON \"public\".\"t\" TO authenticated;";
        assert_eq!(held_after(column, "authenticated", &[]), None);
        let all = "GRANT ALL ON \"public\".\"t\" TO authenticated;";
        assert_eq!(held_after(all, "authenticated", &[]), None);
        let function = "GRANT EXECUTE ON FUNCTION f() TO authenticated;";
        assert_eq!(
            held_after(function, "authenticated", &[]).unwrap(),
            Vec::<String>::new()
        );
    }
}
