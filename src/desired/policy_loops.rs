//! Access rules that read each other's tables in a loop, refused while the push is planned.
//!
//! A rule that reads another table's rows (`Rows`, a related owner, a junction's ends) is a
//! subquery inside the policy, and Postgres expands that subquery under the other table's own
//! `SELECT` policies. While it expands a table's policies the table is on its stack, and meeting it
//! again with a policy that holds a subquery of its own ends the query with `infinite recursion
//! detected in policy for relation`. `CREATE POLICY` accepts such rules without complaint, so a
//! push would succeed and every query on those tables would then fail.
//!
//! The check reads the policies the push is about to create rather than the access rules, so every
//! construct that renders a subquery counts, whichever generator wrote it: a model's rules, a
//! junction's derived policies, the versions layer's and the engine's own. It follows Postgres's
//! rule exactly: a path through `SELECT` policies that returns to a table already on it, where the
//! `SELECT` policies met there read some table, is a loop. A path back to a table whose read reads
//! nothing is not, because Postgres has nothing left to expand there.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Result};

use super::DesiredObject;
use crate::introspector::fingerprint::ObjectKind;
use crate::sql_quote::quote_ident;

/// One policy: the operation it governs, as the access rules name it, and the tables it reads.
struct Policy {
    operation: &'static str,
    reads: BTreeSet<String>,
}

/// Refuses `desired` when its policies on `schema`'s tables read each other in a loop, naming the
/// loop.
pub(crate) fn refuse_policy_loops(desired: &[DesiredObject], schema: &str) -> Result<()> {
    let policies = policies_by_table(desired, schema);
    let graph = select_reads(&policies);
    for (table, on_table) in &policies {
        for policy in on_table.iter().filter(|p| !p.reads.is_empty()) {
            let mut search = Search {
                graph: &graph,
                path: vec![(table.as_str(), policy.operation)],
                done: BTreeSet::new(),
            };
            if let Some(chain) = search.find_loop(policy.reads.iter().map(String::as_str)) {
                bail!(
                    "Access rules loop: {chain}. Postgres refuses to run looping rules (\"infinite \
                     recursion detected in policy\"), so every query on these tables would fail. \
                     Change one of these rules so it no longer reads the next table."
                );
            }
        }
    }
    Ok(())
}

/// Every policy in `desired`, by the table it is on.
fn policies_by_table(desired: &[DesiredObject], schema: &str) -> BTreeMap<String, Vec<Policy>> {
    let mut out: BTreeMap<String, Vec<Policy>> = BTreeMap::new();
    let on_schema = |o: &&DesiredObject| o.key.kind == ObjectKind::Policy && o.key.schema == schema;
    for object in desired.iter().filter(on_schema) {
        out.entry(object.key.parent.clone())
            .or_default()
            .push(Policy {
                operation: operation(&object.structure),
                reads: tables_read(&object.create_sql, schema),
            });
    }
    out
}

/// The search for a loop from one policy: a depth-first walk of the `SELECT` reads.
struct Search<'a> {
    /// [`select_reads`].
    graph: &'a BTreeMap<&'a str, BTreeSet<&'a str>>,
    /// The policy the search starts from, then each table entered through its reads.
    path: Vec<(&'a str, &'static str)>,
    /// Tables already followed to the end without meeting the path. Meeting one again along
    /// another path cannot meet the path either: anything it reached that is on the path now
    /// would have been on the path then, a loop already found. So each table is followed once,
    /// and the search is linear in the policies, not in the paths through them.
    done: BTreeSet<&'a str>,
}

impl<'a> Search<'a> {
    /// The tables the path reaches next by reading `reads`, followed through their `SELECT`
    /// policies until one returns to a table on the path: the loop, written out, or `None`.
    fn find_loop(&mut self, reads: impl IntoIterator<Item = &'a str>) -> Option<String> {
        let graph = self.graph;
        for next in reads {
            let Some(next_reads) = graph.get(next) else {
                continue;
            };
            if self.done.contains(next) {
                continue;
            }
            let on_path = self.path.iter().any(|(table, _)| *table == next);
            self.path.push((next, "read"));
            if on_path {
                return Some(chain(&self.path));
            }
            if let Some(found) = self.find_loop(next_reads.iter().copied()) {
                return Some(found);
            }
            self.path.pop();
            self.done.insert(next);
        }
        None
    }
}

/// The tables each table's `SELECT` policies read: the ones a subquery on it is expanded under.
/// A table whose reads read nothing is left out, since Postgres has nothing to expand there.
fn select_reads(policies: &BTreeMap<String, Vec<Policy>>) -> BTreeMap<&str, BTreeSet<&str>> {
    policies
        .iter()
        .map(|(table, on_table)| {
            let reads: BTreeSet<&str> = on_table
                .iter()
                .filter(|p| matches!(p.operation, "read" | "all"))
                .flat_map(|p| p.reads.iter().map(String::as_str))
                .collect();
            (table.as_str(), reads)
        })
        .filter(|(_, reads)| !reads.is_empty())
        .collect()
}

/// `a.read -> b.read -> a.read`.
fn chain(path: &[(&str, &str)]) -> String {
    path.iter()
        .map(|(table, operation)| format!("{table}.{operation}"))
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// The operation a policy governs, as the access rules name it, read from the `pg_policy.polcmd`
/// spelling every desired policy records in its structure. A policy for no single command (`*`)
/// governs all of them.
fn operation(structure: &BTreeMap<&'static str, String>) -> &'static str {
    match structure.get("command").map(String::as_str) {
        Some("r") => "read",
        Some("a") => "create",
        Some("w") => "update",
        Some("d") => "delete",
        _ => "all",
    }
}

/// The tables of `schema` a policy reads: every `FROM "schema"."table"` and `JOIN` of one, which is
/// how every generator writes a subquery over a managed table.
fn tables_read(create_sql: &str, schema: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let qualifier = format!("{}.", quote_ident(schema));
    for keyword in ["FROM ", "JOIN "] {
        let needle = format!("{keyword}{qualifier}");
        let mut rest = create_sql;
        while let Some(at) = rest.find(&needle) {
            rest = &rest[at + needle.len()..];
            if let Some(table) = leading_identifier(rest) {
                out.insert(table);
            }
        }
    }
    out
}

/// The quoted identifier `text` starts with, unquoted, or `None`.
fn leading_identifier(text: &str) -> Option<String> {
    let body = text.strip_prefix('"')?;
    let mut name = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            name.push(c);
        } else if chars.peek() == Some(&'"') {
            name.push('"');
            chars.next();
        } else {
            return Some(name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{leading_identifier, operation, tables_read};

    #[test]
    fn a_policy_reads_the_qualified_tables_of_its_schema_only() {
        let sql = "CREATE POLICY \"q_select\" ON \"public\".\"q\" FOR SELECT USING (EXISTS \
                   (SELECT 1 FROM \"public\".\"form\" WHERE x) OR EXISTS (SELECT 1 FROM \
                   jsonb_array_elements_text(y)) OR EXISTS (SELECT 1 FROM \"other\".\"t\"))";
        let read: Vec<String> = tables_read(sql, "public").into_iter().collect();
        assert_eq!(read, vec!["form".to_string()]);
    }

    #[test]
    fn a_quoted_name_keeps_its_doubled_quotes() {
        assert_eq!(
            leading_identifier("\"a\"\"b\" rest").as_deref(),
            Some("a\"b")
        );
        assert_eq!(leading_identifier("unquoted"), None);
    }

    #[test]
    fn a_policy_without_for_governs_every_operation() {
        let command = |c: &str| BTreeMap::from([("command", c.to_string())]);
        assert_eq!(operation(&command("*")), "all");
        assert_eq!(operation(&command("a")), "create");
        assert_eq!(operation(&command("r")), "read");
    }
}
