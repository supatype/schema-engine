//! The online forms of the statements that would otherwise stop an application's reads or writes
//! for as long as they scan a table (IN-C 2).
//!
//! `CREATE INDEX` holds a SHARE lock for its whole build, which stops every write; adding a foreign
//! key or a check validates every row under the lock it takes (SHARE ROW EXCLUSIVE for a key,
//! ACCESS EXCLUSIVE for a check), held until the push commits. On a table that has rows, a new
//! index is built with `CREATE INDEX CONCURRENTLY` once the push's transaction has committed, and a
//! key or check is added `NOT VALID` inside it and validated after it, under SHARE UPDATE
//! EXCLUSIVE, which lets reads and writes through. A table the push creates, or one with no rows,
//! keeps the plain statements: there is nothing to scan.

use std::collections::BTreeSet;

use crate::desired::ObjectKey;
use crate::introspector::fingerprint::ObjectKind;
use crate::ledger::reconcile::Action;
use crate::ledger::Status;
use crate::sql_quote::{quote_ident, quote_qualified};

/// What a push knows about the tables it changes that decides whether a statement runs online.
#[derive(Debug, Clone, Default)]
pub struct OnlineTables {
    /// The project schema's tables that exist before the push and hold rows (or once did: a table
    /// with storage is taken to have rows).
    pub with_rows: BTreeSet<String>,
    /// INVALID indexes in the project schema, left by a concurrent build that did not finish.
    /// Introspection does not see them, so one the push makes again is dropped first.
    pub invalid_indexes: BTreeSet<String>,
    /// Keys and checks of ours in the project schema that are `NOT VALID`: validated after commit.
    pub unvalidated: Vec<ObjectKey>,
}

/// An index built after the push's transaction has committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcurrentIndex {
    pub key: ObjectKey,
    /// `CREATE INDEX CONCURRENTLY IF NOT EXISTS ...`.
    pub build_sql: String,
    /// The plain `CREATE INDEX` the ledger records, as for any index.
    pub create_sql: String,
    pub status: Status,
}

/// What runs after a push's transaction has committed: the index builds, then the validations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AfterCommit {
    pub indexes: Vec<ConcurrentIndex>,
    /// Foreign keys and checks added `NOT VALID`, by this push or one before it.
    pub validations: Vec<ObjectKey>,
}

impl AfterCommit {
    pub fn is_empty(&self) -> bool {
        self.indexes.is_empty() && self.validations.is_empty()
    }

    /// The keys the push's transaction leaves for later: the indexes, which are absent when it
    /// commits.
    pub fn deferred_keys(&self) -> BTreeSet<ObjectKey> {
        self.indexes.iter().map(|i| i.key.clone()).collect()
    }

    /// Every statement, in the order they run.
    pub fn statements(&self) -> Vec<String> {
        self.indexes
            .iter()
            .map(|i| i.build_sql.clone())
            .chain(self.validations.iter().map(validate_sql))
            .collect()
    }

    /// Adds a validation unless it is already there.
    pub fn validate(&mut self, key: ObjectKey) {
        if !self.validations.contains(&key) {
            self.validations.push(key);
        }
    }
}

/// How one reconcile action runs on a table with rows.
pub enum Online {
    /// In the transaction, as rendered.
    No,
    /// Built concurrently after commit, in place of its `CREATE INDEX`.
    Concurrent(ConcurrentIndex),
    /// Added `NOT VALID` in the transaction, then validated after commit.
    NotValid { create_sql: String },
}

/// How `action` runs, given the tables of `schema` that hold rows.
pub fn online(action: &Action, schema: &str, tables: &OnlineTables) -> Online {
    let key = action.key();
    if key.schema != schema || !tables.with_rows.contains(&key.parent) {
        return Online::No;
    }
    let found = match key.kind {
        ObjectKind::Index => concurrent_index(action).map(Online::Concurrent),
        ObjectKind::ForeignKey | ObjectKind::Check => placed(action, true)
            .and_then(not_valid)
            .map(|create_sql| Online::NotValid { create_sql }),
        _ => None,
    };
    found.unwrap_or(Online::No)
}

/// A new index, made by its own statement, as a concurrent build.
fn concurrent_index(action: &Action) -> Option<ConcurrentIndex> {
    let status = match action {
        Action::Create { status, .. } | Action::Recreate { status, .. } => *status,
        _ => return None,
    };
    let create_sql = placed(action, false)?;
    Some(ConcurrentIndex {
        key: action.key().clone(),
        build_sql: concurrently(create_sql)?,
        create_sql: create_sql.to_string(),
        status,
    })
}

/// The statement `action` places its object with, when it runs one of its own: a creation, or with
/// `replacing` a replacement or a put-back too.
fn placed(action: &Action, replacing: bool) -> Option<&str> {
    match action {
        Action::Create {
            create_sql,
            inline: false,
            ..
        }
        | Action::Recreate {
            create_sql,
            inline: false,
            ..
        } => Some(create_sql),
        Action::Replace {
            create_sql,
            inline: false,
            ..
        }
        | Action::Drift {
            create_sql,
            inline: false,
            ..
        } if replacing => Some(create_sql),
        _ => None,
    }
}

/// `CREATE [UNIQUE] INDEX IF NOT EXISTS ...` as its concurrent form, or `None` for any other shape
/// of statement.
pub fn concurrently(create_sql: &str) -> Option<String> {
    let sql = create_sql.trim();
    let single = sql.ends_with(';') && !sql[..sql.len() - 1].contains(';');
    if !single {
        return None;
    }
    [
        "CREATE INDEX IF NOT EXISTS ",
        "CREATE UNIQUE INDEX IF NOT EXISTS ",
    ]
    .iter()
    .find_map(|prefix| {
        let rest = sql.strip_prefix(prefix)?;
        let head = prefix.trim_end_matches("IF NOT EXISTS ");
        Some(format!("{head}CONCURRENTLY IF NOT EXISTS {rest}"))
    })
}

/// `ALTER TABLE ... ADD CONSTRAINT ...;` with `NOT VALID` added, or `None` for any other shape of
/// statement (one that also comments on the constraint, say).
pub fn not_valid(create_sql: &str) -> Option<String> {
    let sql = create_sql.trim();
    let body = sql.strip_suffix(';')?.trim_end();
    let upper = body.to_ascii_uppercase();
    let added = upper.starts_with("ALTER TABLE ") && upper.contains(" ADD CONSTRAINT ");
    let one_statement = !body.contains(";\n") && !upper.contains("COMMENT ON ");
    if !added || !one_statement || upper.ends_with(" NOT VALID") {
        return None;
    }
    Some(format!("{body} NOT VALID;"))
}

/// `ALTER TABLE ... VALIDATE CONSTRAINT ...` for a key or check.
pub fn validate_sql(key: &ObjectKey) -> String {
    format!(
        "ALTER TABLE {} VALIDATE CONSTRAINT {};",
        quote_qualified(&key.schema, &key.parent),
        quote_ident(&key.name)
    )
}

/// `DROP INDEX IF EXISTS` for an INVALID index of `key`'s name, run in the transaction before the
/// index is made again there.
pub fn drop_invalid_sql(key: &ObjectKey) -> String {
    format!(
        "DROP INDEX IF EXISTS {};",
        quote_qualified(&key.schema, &key.name)
    )
}

/// The section a migration file prints after its `COMMIT`.
pub fn file_section(after: &AfterCommit) -> String {
    if after.is_empty() {
        return String::new();
    }
    let mut lines = vec![
        "-- After the transaction: each index is built without stopping writes to its table, and"
            .to_string(),
        "-- each key and check is validated without stopping reads or writes. CREATE INDEX"
            .to_string(),
        "-- CONCURRENTLY cannot run inside a transaction. If a build fails it leaves an INVALID"
            .to_string(),
        "-- index: drop it and run the statement again.".to_string(),
    ];
    lines.extend(after.statements());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_index_is_built_concurrently_and_a_key_added_not_valid() {
        assert_eq!(
            concurrently("CREATE UNIQUE INDEX IF NOT EXISTS \"i\" ON \"public\".\"t\" USING btree (\"a\");")
                .as_deref(),
            Some("CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS \"i\" ON \"public\".\"t\" USING btree (\"a\");")
        );
        assert_eq!(
            concurrently("CREATE INDEX IF NOT EXISTS i ON t (a);").as_deref(),
            Some("CREATE INDEX CONCURRENTLY IF NOT EXISTS i ON t (a);")
        );
        assert_eq!(
            concurrently("CREATE INDEX i ON t (a); COMMENT ON INDEX i IS 'x';"),
            None
        );
        assert_eq!(
            not_valid("ALTER TABLE \"public\".\"t\" ADD CONSTRAINT \"k\" FOREIGN KEY (\"a\") REFERENCES \"public\".\"u\" (\"id\") ON DELETE RESTRICT;")
                .as_deref(),
            Some("ALTER TABLE \"public\".\"t\" ADD CONSTRAINT \"k\" FOREIGN KEY (\"a\") REFERENCES \"public\".\"u\" (\"id\") ON DELETE RESTRICT NOT VALID;")
        );
        assert_eq!(
            not_valid("ALTER TABLE t ADD CONSTRAINT c CHECK (a > 0) NOT VALID;"),
            None
        );
        assert_eq!(not_valid("CREATE INDEX i ON t (a);"), None);
    }
}
