//! Refusing, before anything is applied, a key or check that rows already break, which the push
//! would otherwise add `NOT VALID` and fail to validate after commit, with the rest applied.

use anyhow::Result;
use sqlx::{Connection, PgConnection};

use crate::desired::ObjectKey;
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
        let Some(count_sql) = placed
            .and_then(|a| a.create_sql())
            .and_then(|sql| broken_rows_sql(key, sql))
        else {
            continue;
        };
        let mut savepoint = tx.begin().await?;
        let counted: std::result::Result<i64, sqlx::Error> = sqlx::query_scalar(&count_sql)
            .fetch_one(&mut *savepoint)
            .await;
        savepoint.rollback().await?;
        if let Ok(rows) = counted.map_err(|e| tracing::debug!("{key}: rows not counted: {e}")) {
            if rows > 0 {
                anyhow::bail!(
                    "{rows} row(s) of {} break {key}, which this push adds. Nothing was \
                     applied: fix or remove those rows, then push again.",
                    key.parent
                );
            }
        }
    }
    Ok(())
}

/// A count of the rows of `key`'s table that break it, from the statement that adds it.
fn broken_rows_sql(key: &ObjectKey, create_sql: &str) -> Option<String> {
    use crate::introspector::fingerprint::ObjectKind;
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
