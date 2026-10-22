//! Refusing, before anything is applied, a key or check that rows already break, which the push
//! would otherwise add `NOT VALID` and fail to validate after commit, with the rest applied.

use anyhow::Result;
use sqlx::{Connection, PgConnection};

use crate::desired::ObjectKey;
use crate::introspector::fingerprint::ObjectKind;
use crate::sql_quote::quote_qualified;

/// Before anything is applied, refuses when rows already break a key or check this push adds
/// `NOT VALID` (one of `validations` that an action of `actions` places): it would be validated
/// only after commit, and fail there with the rest applied. A count the database cannot make (a
/// column this push adds, a key this cannot read) is left to the validation.
pub async fn refuse_broken_rows(
    tx: &mut PgConnection,
    actions: &[crate::ledger::reconcile::Action],
    validations: &[ObjectKey],
) -> Result<()> {
    for key in validations {
        let placed = actions.iter().find(|a| a.key() == key && a.is_change());
        let Some(create_sql) = placed.and_then(|a| a.create_sql()) else {
            continue;
        };
        let Some(count_sql) = broken_rows_sql(key, create_sql) else {
            continue;
        };
        let mut savepoint = tx.begin().await?;
        let counted: std::result::Result<i64, sqlx::Error> = sqlx::query_scalar(&count_sql)
            .fetch_one(&mut *savepoint)
            .await;
        savepoint.rollback().await?;
        if let Ok(rows) = counted.map_err(|e| tracing::debug!("{key}: rows not counted: {e}")) {
            if rows > 0 {
                anyhow::bail!(broken_rows_message(key, create_sql, rows));
            }
        }
    }
    Ok(())
}

/// What to say about `rows` rows that break `key`. A key to `auth.users` is the one a
/// `SupatypeAuthUserId<{ onDelete }>` field asks for, and its rows name users that do not exist.
fn broken_rows_message(key: &ObjectKey, create_sql: &str, rows: i64) -> String {
    let Some(column) = auth_user_column(key, create_sql) else {
        return format!(
            "{rows} row(s) of {} break {key}, which this push adds. Nothing was applied: fix or \
             remove those rows, then push again.",
            key.parent
        );
    };
    let parent = &key.parent;
    let field = column.trim_matches('"');
    let table = quote_qualified(&key.schema, parent);
    format!(
        "{rows} row(s) of {parent} have a {field} that names no user in auth.users, so \
         {parent}.{field} cannot be linked to its user ({key}). Nothing was applied. Delete those \
         rows (DELETE FROM {table} WHERE {column} NOT IN (SELECT id FROM \"auth\".\"users\");), \
         point them at an existing user, or set {field} to NULL if the field is Optional; then \
         push again."
    )
}

/// The column of `key`, as its statement quotes it, when `key` is a foreign key to `auth.users`.
fn auth_user_column<'a>(key: &ObjectKey, create_sql: &'a str) -> Option<&'a str> {
    use crate::desired::AUTH_USERS;
    let (column, target, _) = single_column_key(create_sql)?;
    let to_auth_users = target == quote_qualified(AUTH_USERS.0, AUTH_USERS.1);
    (key.kind == ObjectKind::ForeignKey && to_auth_users).then_some(column)
}

/// Before anything is applied, refuses a push that adds a key to `auth.users` where there is no
/// `auth.users`. Supatype's auth server creates it, and a project that brings its own auth or keeps
/// its schema apart has none, so the key would fail inside the migration with Postgres's
/// `relation "auth.users" does not exist`, naming neither the field nor the way out.
pub async fn refuse_missing_auth_users(
    conn: &mut PgConnection,
    actions: &[crate::ledger::reconcile::Action],
) -> Result<()> {
    let links: Vec<String> = actions
        .iter()
        .filter(|a| a.is_change())
        .filter_map(|a| {
            let column = auth_user_column(a.key(), a.create_sql()?)?;
            Some(format!("{}.{}", a.key().parent, column.trim_matches('"')))
        })
        .collect();
    if links.is_empty() {
        return Ok(());
    }
    let present: bool = sqlx::query_scalar("SELECT to_regclass('auth.users') IS NOT NULL")
        .fetch_one(&mut *conn)
        .await?;
    anyhow::ensure!(
        present,
        "This push links rows to their user in auth.users ({}), and this database has no \
         auth.users: Supatype's auth server creates it, and a project that brings its own auth or \
         keeps its schema apart has none. Nothing was applied. Start the auth server against this database \
         once and push again, or remove onDelete from the SupatypeAuthUserId field (or the \
         RelatedTo<SupatypeAuthUser> relation) so it holds a user id with no foreign key.",
        links.join(", ")
    );
    Ok(())
}

/// A count of the rows of `key`'s table that break it, from the statement that adds it.
fn broken_rows_sql(key: &ObjectKey, create_sql: &str) -> Option<String> {
    let table = quote_qualified(&key.schema, &key.parent);
    match key.kind {
        ObjectKind::Check => {
            let expression = crate::desired::statements::check_expression(create_sql)?;
            Some(format!(
                "SELECT count(*) FROM {table} WHERE NOT ({expression})"
            ))
        }
        ObjectKind::ForeignKey => {
            let (column, target, referenced) = single_column_key(create_sql)?;
            Some(format!(
                "SELECT count(*) FROM {table} c WHERE c.{column} IS NOT NULL AND NOT EXISTS \
                 (SELECT 1 FROM {target} p WHERE p.{referenced} = c.{column})"
            ))
        }
        _ => None,
    }
}

/// `(column, referenced table, referenced column)` of `FOREIGN KEY (c) REFERENCES t (r)`, each as
/// the statement quotes it; `None` for a key of more than one column.
fn single_column_key(create_sql: &str) -> Option<(&str, &str, &str)> {
    let rest = &create_sql[create_sql.find("FOREIGN KEY (")? + "FOREIGN KEY (".len()..];
    let (column, rest) = rest.split_once(')')?;
    let rest = rest.trim_start().strip_prefix("REFERENCES ")?;
    let (target, rest) = rest.split_once(" (")?;
    let (referenced, _) = rest.split_once(')')?;
    let single = |s: &str| !s.contains(',') && !s.trim().is_empty();
    (single(column) && single(referenced)).then_some((
        column.trim(),
        target.trim(),
        referenced.trim(),
    ))
}
