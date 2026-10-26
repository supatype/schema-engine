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

/// An index built after the push's transaction has committed: a new index, the index a new
/// unique constraint is attached to, or an index rebuilt under a temporary name and swapped in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcurrentIndex {
    pub key: ObjectKey,
    /// The index the build makes, in the key's schema: the key's own name, or a temporary one
    /// for a rebuild.
    pub built: String,
    /// `CREATE INDEX CONCURRENTLY IF NOT EXISTS ...`.
    pub build_sql: String,
    /// Run in one short transaction once the build is valid: the unique constraint attached to
    /// the index, or the rebuilt index swapped in for the one it replaces.
    pub then_sql: Vec<String>,
    /// Dropped concurrently after that: the index a rebuild replaced, under the name the swap gave
    /// it.
    pub drop_after: Option<String>,
    /// The statement the ledger records, as for any index or unique constraint.
    pub create_sql: String,
    pub status: Status,
}

impl ConcurrentIndex {
    /// Every statement, in the order they run.
    fn statements(&self) -> Vec<String> {
        let mut out = vec![self.build_sql.clone()];
        out.extend(self.then_sql.iter().cloned());
        out.extend(self.drop_after.iter().map(|old| drop_concurrently_sql(old)));
        out
    }
}

/// `DROP INDEX CONCURRENTLY IF EXISTS` for the quoted, qualified index `relation`.
pub fn drop_concurrently_sql(relation: &str) -> String {
    format!("DROP INDEX CONCURRENTLY IF EXISTS {relation};")
}

/// A column made `NOT NULL` on a table with rows (LK7). `SET NOT NULL` scans every row under
/// ACCESS EXCLUSIVE, unless a validated check already proves no row is NULL: so the push adds
/// `CHECK (column IS NOT NULL) NOT VALID`, validates it after commit under a lock that lets reads
/// and writes through, then sets `NOT NULL`, which skips its scan, and drops the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotNull {
    pub schema: String,
    pub table: String,
    pub column: String,
    /// The helper check's name.
    pub check: String,
}

impl NotNull {
    pub fn new(schema: &str, table: &str, column: &str) -> NotNull {
        NotNull {
            schema: schema.to_string(),
            table: table.to_string(),
            column: column.to_string(),
            check: crate::managed::make_object_name(table, Some(column), "set_not_null"),
        }
    }

    fn target(&self) -> String {
        quote_qualified(&self.schema, &self.table)
    }

    /// The column's ledger key, whose row records its nullability.
    pub fn key(&self) -> ObjectKey {
        ObjectKey {
            kind: ObjectKind::Column,
            schema: self.schema.clone(),
            parent: self.table.clone(),
            name: self.column.clone(),
        }
    }

    /// In the push's transaction, in place of `SET NOT NULL`: the helper check, NOT VALID. One
    /// left by a push that did not finish is replaced in the same statement.
    pub fn add_sql(&self) -> String {
        format!(
            "ALTER TABLE {} DROP CONSTRAINT IF EXISTS {check}, \
             ADD CONSTRAINT {check} CHECK ({} IS NOT NULL) NOT VALID;",
            self.target(),
            quote_ident(&self.column),
            check = quote_ident(&self.check),
        )
    }

    pub fn validate_sql(&self) -> String {
        format!(
            "ALTER TABLE {} VALIDATE CONSTRAINT {};",
            self.target(),
            quote_ident(&self.check)
        )
    }

    /// `SET NOT NULL`, proved by the validated check, then the check dropped. Two statements: in
    /// one `ALTER TABLE` the drop would run first and `SET NOT NULL` would scan.
    pub fn set_sql(&self) -> [String; 2] {
        [
            format!(
                "ALTER TABLE {} ALTER COLUMN {} SET NOT NULL;",
                self.target(),
                quote_ident(&self.column)
            ),
            self.drop_sql(),
        ]
    }

    pub fn drop_sql(&self) -> String {
        format!(
            "ALTER TABLE {} DROP CONSTRAINT IF EXISTS {};",
            self.target(),
            quote_ident(&self.check)
        )
    }
}

/// What runs after a push's transaction has committed: the index builds, then the validations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AfterCommit {
    pub indexes: Vec<ConcurrentIndex>,
    /// Foreign keys and checks added `NOT VALID`, by this push or one before it.
    pub validations: Vec<ObjectKey>,
    /// Columns made `NOT NULL` once their helper check is validated.
    pub not_null: Vec<NotNull>,
}

impl AfterCommit {
    pub fn is_empty(&self) -> bool {
        self.indexes.is_empty() && self.validations.is_empty() && self.not_null.is_empty()
    }

    /// The keys whose ledger row is written once they are in place, not when the push's
    /// transaction commits: the indexes and unique constraints, absent or not yet as wanted then.
    pub fn deferred_keys(&self) -> BTreeSet<ObjectKey> {
        self.indexes.iter().map(|i| i.key.clone()).collect()
    }

    /// Everything not yet as the schema wants it when the push's transaction commits: the
    /// deferred keys and the columns not yet `NOT NULL`.
    pub fn unfinished_keys(&self) -> BTreeSet<ObjectKey> {
        let mut keys = self.deferred_keys();
        keys.extend(self.not_null.iter().map(NotNull::key));
        keys
    }

    /// The indexes rebuilt under a temporary name and swapped in, whose old one stays until then.
    pub fn rebuilt_keys(&self) -> BTreeSet<ObjectKey> {
        self.indexes
            .iter()
            .filter(|i| i.drop_after.is_some())
            .map(|i| i.key.clone())
            .collect()
    }

    /// Every statement, in the order they run: the validations, the columns made `NOT NULL`, then
    /// the index builds.
    pub fn statements(&self) -> Vec<String> {
        let mut out: Vec<String> = self.validations.iter().map(validate_sql).collect();
        for column in &self.not_null {
            out.push(column.validate_sql());
            out.extend(column.set_sql());
        }
        out.extend(self.indexes.iter().flat_map(ConcurrentIndex::statements));
        out
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
        ObjectKind::Index => concurrent_index(action)
            .or_else(|| rebuilt_index(action))
            .map(Online::Concurrent),
        ObjectKind::Unique => unique_using_index(action).map(Online::Concurrent),
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
        built: action.key().name.clone(),
        build_sql: concurrently(create_sql)?,
        then_sql: Vec::new(),
        drop_after: None,
        create_sql: create_sql.to_string(),
        status,
    })
}

/// An index the push replaces, or puts back after a hand change, rebuilt concurrently under a
/// temporary name and swapped in by renaming, so neither the build nor the drop of the old one
/// stops writes, and the table is never without one of them.
fn rebuilt_index(action: &Action) -> Option<ConcurrentIndex> {
    let status = match action {
        Action::Replace { status, .. } | Action::Drift { status, .. } => *status,
        _ => return None,
    };
    let key = action.key();
    let create_sql = placed(action, true)?;
    let built = crate::managed::make_object_name(&key.name, None, "rebuilt");
    let old = crate::managed::make_object_name(&key.name, None, "replaced");
    let named = format!(" {} ON ", quote_ident(&key.name));
    if !create_sql.contains(&named) {
        return None;
    }
    let renamed = create_sql.replacen(&named, &format!(" {} ON ", quote_ident(&built)), 1);
    let rename = |from: &str, to: &str| {
        format!(
            "ALTER INDEX {} RENAME TO {};",
            quote_qualified(&key.schema, from),
            quote_ident(to)
        )
    };
    Some(ConcurrentIndex {
        key: key.clone(),
        build_sql: concurrently(&renamed)?,
        then_sql: vec![rename(&key.name, &old), rename(&built, &key.name)],
        drop_after: Some(quote_qualified(&key.schema, &old)),
        built,
        create_sql: create_sql.to_string(),
        status,
    })
}

/// A new unique constraint whose index is built concurrently and then attached with `ADD
/// CONSTRAINT ... UNIQUE USING INDEX`, which takes ACCESS EXCLUSIVE only for the moment it records
/// the constraint.
fn unique_using_index(action: &Action) -> Option<ConcurrentIndex> {
    let status = match action {
        Action::Create { status, .. } | Action::Recreate { status, .. } => *status,
        _ => return None,
    };
    let key = action.key();
    let create_sql = placed(action, false)?;
    let target = quote_qualified(&key.schema, &key.parent);
    let name = quote_ident(&key.name);
    let head = format!("ALTER TABLE {target} ADD CONSTRAINT {name} UNIQUE (");
    let columns = create_sql.trim().strip_prefix(&head)?.strip_suffix(");")?;
    if columns.contains([')', ';']) {
        return None;
    }
    Some(ConcurrentIndex {
        key: key.clone(),
        built: key.name.clone(),
        build_sql: format!(
            "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS {name} ON {target} ({columns});"
        ),
        then_sql: vec![format!(
            "ALTER TABLE {target} ADD CONSTRAINT {name} UNIQUE USING INDEX {name};"
        )],
        drop_after: None,
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
