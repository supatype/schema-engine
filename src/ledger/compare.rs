//! Whether a live access object is the one a statement would make, decided without changing
//! anything (F16).
//!
//! A policy, grant, label, RLS attribute or access function with no ledger row has to be compared
//! with what Supatype would have made of it: an older engine's object with what the last push's
//! schema renders, a same-named object no push made with what this schema renders (F15 (a)). The
//! comparison used to run that schema's statements in a transaction it rolled back, which takes
//! `ACCESS EXCLUSIVE` on every table with a policy (`DROP POLICY`, `ALTER TABLE ... ROW LEVEL
//! SECURITY`), so `doctor`, `diff` and `migrate` stopped an application's reads, and a lock it
//! could not get within its timeout made it skip the comparison and replace unchecked (E09, E29).
//!
//! Here the expected object is read off the statement's text, as the desired side reads it
//! (`desired::attributed`): a function's body, language and options, a policy's command and roles,
//! a label's text, the privileges a grant leaves. The one part text cannot settle is a policy's
//! expressions, which Postgres rewrites on the way in: `name = 'x'` reads back as
//! `(name = 'x'::text)`. Both expressions are given to the planner instead, as the filter of a
//! `SELECT` from the policy's table under `EXPLAIN`, which parses, resolves and prints each the
//! same way and runs nothing. That takes `ACCESS SHARE`, which no reader or writer of the table
//! waits on. What still cannot be compared (a table someone holds exclusively, an expression the
//! database refuses) is reported as such, and the caller counts it as changed.

pub mod stated;

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Result};
use sqlx::{Connection, PgConnection, Postgres, Transaction};

use crate::desired::statements::{head, split_statements};
use crate::desired::{attributed, DesiredObject, ObjectKey};
use crate::introspector::fingerprint::{plain_grant, ObjectFingerprint, ObjectKind};
use crate::ledger::reconcile::parse_definition;
use crate::sql_quote::quote_qualified;

/// What comparing one live object with one expectation found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The live object is what was expected.
    Same,
    /// It is not: what was expected, as the parts that differ were expected.
    Differs(String),
    /// It could not be compared, and why.
    Unchecked(String),
}

/// What a grant is expected to leave its grantee holding: on the table, and per column.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeldGrant {
    pub table: Vec<String>,
    pub columns: BTreeMap<String, Vec<String>>,
}

/// The planner settings the comparison runs under: one scan shape for every table, so the same
/// expression always prints the same plan, and nothing that waits long on a lock.
const SETTINGS: &[(&str, &str)] = &[
    ("lock_timeout", "1s"),
    ("statement_timeout", "10s"),
    ("enable_indexscan", "off"),
    ("enable_indexonlyscan", "off"),
    ("enable_bitmapscan", "off"),
    ("max_parallel_workers_per_gather", "0"),
    ("jit", "off"),
];

/// Compares live objects with expectations on one connection, inside a transaction (a savepoint,
/// on a caller's transaction) that is always rolled back, so its settings go with it. Each policy
/// expression is planned once.
pub struct Comparer<'c> {
    tx: Transaction<'c, Postgres>,
    plans: HashMap<(String, String), std::result::Result<String, String>>,
}

impl<'c> Comparer<'c> {
    /// Begins the comparison with `schema` on the `search_path`, as a push runs the statements
    /// it compares: a rule may name a table of the project schema unqualified. The catalog's side
    /// was read under the pinned path, so it names everything outside `pg_catalog` in full.
    pub async fn begin(conn: &'c mut PgConnection, schema: &str) -> Result<Comparer<'c>> {
        let mut tx = conn.begin().await.context("begin the comparison")?;
        let path = crate::sql_quote::quote_ident(schema);
        let settings = SETTINGS
            .iter()
            .copied()
            .chain([("search_path", path.as_str())]);
        for (name, value) in settings {
            sqlx::query("SELECT set_config($1, $2, true)")
                .bind(name)
                .bind(value)
                .execute(&mut *tx)
                .await
                .with_context(|| format!("set {name} for the comparison"))?;
        }
        Ok(Comparer {
            tx,
            plans: HashMap::new(),
        })
    }

    /// `live` against `expected`'s statement: [`Verdict::Same`] when they agree on every part the
    /// statement predicts.
    pub async fn object(
        &mut self,
        live: &ObjectFingerprint,
        expected: &DesiredObject,
        create_sql: &str,
    ) -> Verdict {
        let key = &expected.key;
        match key.kind {
            ObjectKind::RlsAttributes => parts(live, &BTreeMap::from([("enabled", "t".into())])),
            ObjectKind::Policy => self.policy(key, live, create_sql).await,
            ObjectKind::Function => parts(live, &attributed::structure(key, create_sql)),
            ObjectKind::SecurityLabel => parts(live, &expected.structure),
            other => Verdict::Unchecked(format!("{} is not compared", other.as_str())),
        }
    }

    /// A grant against what it is expected to leave its grantee holding.
    pub fn grant(live: &ObjectFingerprint, expected: &HeldGrant) -> Verdict {
        let wanted = plain_grant(&live.key(), &expected.table, &expected.columns);
        if wanted.fingerprint == live.fingerprint {
            Verdict::Same
        } else {
            Verdict::Differs(wanted.definition)
        }
    }

    /// A policy: its command, permissiveness and roles as text, its expressions by their plans.
    async fn policy(&mut self, key: &ObjectKey, live: &ObjectFingerprint, sql: &str) -> Verdict {
        let wanted = attributed::structure(key, sql);
        let verdict = parts(live, &wanted);
        if verdict != Verdict::Same {
            return verdict;
        }
        let Some(live_sql) = live.create_sql.as_deref() else {
            return Verdict::Unchecked("the live policy could not be rendered".into());
        };
        let (want, have) = (policy_clauses(sql), policy_clauses(live_sql));
        for (clause, ours, theirs) in [
            ("using", want.using, have.using),
            ("with_check", want.check, have.check),
        ] {
            match self
                .same_expression(key, ours.as_deref(), theirs.as_deref())
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Verdict::Differs(format!("{clause}={}", ours.unwrap_or_default()))
                }
                Err(reason) => return Verdict::Unchecked(reason),
            }
        }
        Verdict::Same
    }

    /// Whether two expressions on `key`'s table plan alike: both absent, or both present and the
    /// same once Postgres has parsed them.
    async fn same_expression(
        &mut self,
        key: &ObjectKey,
        ours: Option<&str>,
        theirs: Option<&str>,
    ) -> std::result::Result<bool, String> {
        match (ours, theirs) {
            (None, None) => Ok(true),
            (Some(a), Some(b)) => {
                let target = quote_qualified(&key.schema, &key.parent);
                Ok(self.plan(&target, a).await? == self.plan(&target, b).await?)
            }
            _ => Ok(false),
        }
    }

    /// The plan of a `SELECT` from `target` filtered by `expression`, as `EXPLAIN` prints it, in a
    /// savepoint of its own so a refusal leaves the rest comparable.
    async fn plan(
        &mut self,
        target: &str,
        expression: &str,
    ) -> std::result::Result<String, String> {
        let cache_key = (target.to_string(), expression.to_string());
        if let Some(found) = self.plans.get(&cache_key) {
            return found.clone();
        }
        let planned = explain(&mut self.tx, target, expression).await;
        self.plans.insert(cache_key, planned.clone());
        planned
    }

    /// The defaults a grant `key`'s grantee gets on its table, created by the table's owner in its
    /// schema (`ALTER DEFAULT PRIVILEGES`, global and per schema): what an older engine left beside
    /// what it granted.
    pub async fn default_privileges(
        &mut self,
        key: &ObjectKey,
    ) -> std::result::Result<Vec<String>, String> {
        sqlx::query_scalar(
            "SELECT DISTINCT a.privilege_type::text
               FROM pg_class c
               JOIN pg_default_acl d ON d.defaclrole = c.relowner AND d.defaclobjtype = 'r'
                                    AND d.defaclnamespace IN (0, c.relnamespace)
               CROSS JOIN LATERAL aclexplode(d.defaclacl) a
              WHERE c.oid = to_regclass($1)
                AND a.grantee = COALESCE((SELECT oid FROM pg_roles WHERE rolname = $2), 0)
              ORDER BY 1",
        )
        .bind(quote_qualified(&key.schema, &key.parent))
        .bind(&key.name)
        .fetch_all(&mut *self.tx)
        .await
        .map_err(|e| format!("the default privileges could not be read ({e})"))
    }

    /// Ends the comparison, keeping nothing it did.
    pub async fn finish(self) -> Result<()> {
        self.tx.rollback().await.context("roll the comparison back")
    }
}

async fn explain(
    conn: &mut PgConnection,
    target: &str,
    expression: &str,
) -> std::result::Result<String, String> {
    let sql =
        format!("EXPLAIN (VERBOSE, COSTS OFF) SELECT 1 FROM ONLY {target} WHERE ({expression})");
    let mut one = conn
        .begin()
        .await
        .map_err(|e| format!("the comparison could not begin ({e})"))?;
    let planned: std::result::Result<Vec<String>, sqlx::Error> =
        sqlx::query_scalar(&sql).fetch_all(&mut *one).await;
    let _ = one.rollback().await;
    planned
        .map(|lines| lines.join("\n"))
        .map_err(|e| format!("{target} could not be read to compare its policies ({e})"))
}

/// [`Verdict::Same`] when every part `wanted` names is what `live`'s definition holds.
fn parts(live: &ObjectFingerprint, wanted: &BTreeMap<&'static str, String>) -> Verdict {
    let have = parse_definition(&live.definition);
    let differing: Vec<String> = wanted
        .iter()
        .filter(|(label, value)| have.get(*label) != Some(&value.as_str()))
        .map(|(label, value)| format!("{label}={value}"))
        .collect();
    if differing.is_empty() {
        Verdict::Same
    } else {
        Verdict::Differs(differing.join("\n"))
    }
}

/// The `USING` and `WITH CHECK` expressions of the `CREATE POLICY` in a statement.
#[derive(Debug, Default, PartialEq, Eq)]
struct PolicyClauses {
    using: Option<String>,
    check: Option<String>,
}

fn policy_clauses(sql: &str) -> PolicyClauses {
    let statement = split_statements(sql)
        .into_iter()
        .find(|s| head(s).to_ascii_uppercase().starts_with("CREATE POLICY"))
        .unwrap_or_default();
    let statement = head(&statement);
    PolicyClauses {
        using: clause(statement, &["USING"]),
        check: clause(statement, &["WITH", "CHECK"]),
    }
}

/// The parenthesised text after `words` where they appear outside any parentheses or quotes.
fn clause(sql: &str, words: &[&str]) -> Option<String> {
    let bytes = sql.as_bytes();
    let (mut i, mut depth) = (0, 0usize);
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'$' => i = skip_quoted(sql, i),
            b'(' => (depth, i) = (depth + 1, i + 1),
            b')' => (depth, i) = (depth.saturating_sub(1), i + 1),
            c if depth == 0 && c.is_ascii_alphabetic() && starts_word(bytes, i) => {
                if let Some(open) = after_words(sql, i, words) {
                    return parenthesised(sql, open);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

fn starts_word(bytes: &[u8], i: usize) -> bool {
    i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_')
}

/// Where the `(` after `words` (each a whole word, case aside, whitespace between) starts at `i`.
fn after_words(sql: &str, mut i: usize, words: &[&str]) -> Option<usize> {
    for word in words {
        i += sql[i..].len() - sql[i..].trim_start().len();
        let end = i + word.len();
        let next = sql.as_bytes().get(end).copied().unwrap_or(b' ');
        if !sql.get(i..end)?.eq_ignore_ascii_case(word)
            || next.is_ascii_alphanumeric()
            || next == b'_'
        {
            return None;
        }
        i = end;
    }
    let open = i + (sql[i..].len() - sql[i..].trim_start().len());
    (sql.as_bytes().get(open) == Some(&b'(')).then_some(open)
}

/// The text inside the parentheses opened at `open`, quotes respected.
fn parenthesised(sql: &str, open: usize) -> Option<String> {
    let bytes = sql.as_bytes();
    let (mut i, mut depth) = (open, 0usize);
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'$' => {
                i = skip_quoted(sql, i);
                continue;
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(sql[open + 1..i].trim().to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The index after a quoted region opening at `i` (a literal, a quoted name or a dollar-quoted
/// string), or `i + 1` when nothing opens there (a `$1` parameter).
fn skip_quoted(sql: &str, i: usize) -> usize {
    let bytes = sql.as_bytes();
    match bytes[i] {
        quote @ (b'\'' | b'"') => {
            let mut j = i + 1;
            while j < bytes.len() {
                if bytes[j] == quote {
                    if bytes.get(j + 1) == Some(&quote) {
                        j += 2;
                        continue;
                    }
                    return j + 1;
                }
                j += 1;
            }
            bytes.len()
        }
        _ => {
            let tag_end = sql[i + 1..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .map(|o| i + 1 + o);
            match tag_end {
                Some(end) if bytes[end] == b'$' && !bytes[i + 1].is_ascii_digit() => {
                    let tag = &sql[i..=end];
                    sql[end + 1..]
                        .find(tag)
                        .map(|o| end + 1 + o + tag.len())
                        .unwrap_or(bytes.len())
                }
                _ => i + 1,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policys_expressions_are_read_whole_and_only_at_the_top() {
        let sql = "DROP POLICY IF EXISTS \"p\" ON \"public\".\"t\";\n\
            CREATE POLICY \"using\" ON \"public\".\"t\"\nFOR UPDATE USING (\n  (a = ')' OR b IN (1, 2))\n) \
            with   check ($x$ ( $x$ = c);";
        assert_eq!(
            policy_clauses(sql),
            PolicyClauses {
                using: Some("(a = ')' OR b IN (1, 2))".into()),
                check: Some("$x$ ( $x$ = c".into()),
            }
        );
        let insert = "CREATE POLICY p ON t FOR INSERT TO anon WITH CHECK (TRUE);";
        assert_eq!(
            policy_clauses(insert),
            PolicyClauses {
                using: None,
                check: Some("TRUE".into()),
            }
        );
        // A word that only starts with the keyword, and the keyword inside a body, are not it.
        let tricky = "CREATE POLICY p ON t USING_X (1) USING (EXISTS (SELECT 1 USING (x)))";
        assert_eq!(
            policy_clauses(tricky).using.as_deref(),
            Some("EXISTS (SELECT 1 USING (x))")
        );
    }
}
