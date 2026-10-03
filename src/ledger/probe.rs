//! Asking Postgres whether a same-named object we did not create is the one we would create.
//!
//! The reconcile refuses a desired object whose name is taken by an unstamped live object it
//! cannot match structurally (plan section 7.4). For an expression kind that comparison cannot be
//! made from text: `pg_get_constraintdef` rewrites a check on the way in, so our expression and
//! the live one never read the same even when they mean the same. Prisma and Atlas settle this by
//! applying the declaration to a shadow database and comparing catalogs; this does the same at the
//! scale of one object. In one transaction that is always rolled back, each conflicting table is
//! cloned as a temporary table (`LIKE`, so the same column names and types, which is all a check's
//! deparse depends on), the declared constraint is added to the clone, its definition read back
//! from the catalog and compared, normalised, with the live one. The real table is never locked
//! beyond `ACCESS SHARE` and no DDL runs against it, which matters because `diff` runs this too.
//! Equal means Postgres itself deparses both to the same thing, which is the only equality that
//! counts.

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use sqlx::{Connection, PgConnection};

use crate::desired::statements::check_expression;
use crate::desired::ObjectKey;
use crate::introspector::fingerprint::{normalise_sql, ObjectKind};
use crate::ledger::reconcile::{parse_definition, Action, Plan};

/// The conflicts of `plan` whose live object the database deparses to the declared definition.
/// Only check constraints are probed today; other kinds stay conflicts.
pub async fn equivalent(conn: &mut PgConnection, plan: &Plan) -> Result<BTreeSet<ObjectKey>> {
    // Owned before the first await: a borrow of `plan` held across one trips rustc's
    // higher-ranked lifetime check and the future stops being `Send`.
    let candidates: Vec<(ObjectKey, String, String)> = plan
        .actions
        .iter()
        .filter_map(|action| match action {
            Action::Conflict {
                key,
                create_sql,
                live_def,
            } if key.kind == ObjectKind::Check => Some((
                key.clone(),
                check_expression(create_sql)?.to_string(),
                parse_definition(live_def)
                    .get("expression")
                    .copied()?
                    .to_string(),
            )),
            _ => None,
        })
        .collect();
    if candidates.is_empty() {
        return Ok(BTreeSet::new());
    }
    probe_all(conn, candidates).await
}

async fn probe_all(
    conn: &mut PgConnection,
    candidates: Vec<(ObjectKey, String, String)>,
) -> Result<BTreeSet<ObjectKey>> {
    let mut tx = conn.begin().await.context("begin the equivalence probe")?;
    for (i, (key, expression, _)) in candidates.iter().enumerate() {
        let clone = format!(
            "CREATE TEMP TABLE \"_supatype_probe_{i}\" (LIKE \"{}\".\"{}\")",
            key.schema, key.parent
        );
        let declare = format!(
            "ALTER TABLE pg_temp.\"_supatype_probe_{i}\" ADD CONSTRAINT \"_supatype_probe_{i}\" CHECK ({expression})"
        );
        sqlx::query(&clone)
            .execute(&mut *tx)
            .await
            .with_context(|| {
                format!(
                    "clone {}.{} for the equivalence probe",
                    key.schema, key.parent
                )
            })?;
        sqlx::query(&declare)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("probe the declared check for {key}"))?;
    }
    let names: Vec<String> = (0..candidates.len())
        .map(|i| format!("_supatype_probe_{i}"))
        .collect();
    let deparsed: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname::text, pg_get_constraintdef(oid) FROM pg_constraint
         WHERE conname = ANY($1) AND connamespace = pg_my_temp_schema()",
    )
    .bind(names)
    .fetch_all(&mut *tx)
    .await
    .context("read the probed checks back")?;
    tx.rollback()
        .await
        .context("roll the equivalence probe back")?;

    let mut proven = BTreeSet::new();
    for (name, definition) in deparsed {
        let Some(i) = name
            .strip_prefix("_supatype_probe_")
            .and_then(|n| n.parse::<usize>().ok())
        else {
            continue;
        };
        let (key, _, live) = &candidates[i];
        if normalise_sql(&definition) == *live {
            proven.insert(key.clone());
        }
    }
    Ok(proven)
}
