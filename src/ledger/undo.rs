//! Putting the ledger back when a push is rolled back.
//!
//! A rollback runs the migration's `sql_down`, which puts the objects back as they were; the ledger
//! has to go back with them, or the next push reads rows for objects that are gone, and none for
//! ones that are back. So before a push writes its rows it records, against its migration, each
//! touched row as it was (or that there was none), and rolling that migration back restores
//! exactly those. A rollback only ever undoes the latest applied migration, so what was recorded is
//! what the ledger held just before it.
//!
//! A migration from an engine before this has nothing recorded: rolling it back leaves the ledger
//! as it is, as every rollback did then, and the next push reconciles it.

use anyhow::{Context, Result};
use sqlx::PgConnection;

use super::{key_columns, table_of, ObjectKey, SCHEMA};
use crate::desired::statements;
use crate::introspector::fingerprint::ObjectKind;

/// One row per (migration, object) the migration's push wrote or removed: the row as it was, or
/// `existed = false` when there was none.
pub fn create_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.managed_objects_undo (
    migration_id        INT NOT NULL REFERENCES {SCHEMA}.migrations (id),
    kind                TEXT NOT NULL,
    schema_name         TEXT NOT NULL,
    parent              TEXT NOT NULL,
    name                TEXT NOT NULL,
    existed             BOOLEAN NOT NULL,
    desired_fp          TEXT,
    desired_sql         TEXT,
    live_fp             TEXT,
    live_def            TEXT,
    status              TEXT,
    prior_migration_id  INT,
    created_at          TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ,
    PRIMARY KEY (migration_id, kind, schema_name, parent, name)
)"#
    )
}

/// Records, against `migration_id`, the rows for `keys` as they are now, before the push writes
/// them. Called once per push, in its transaction.
pub async fn remember(
    conn: &mut PgConnection,
    migration_id: i32,
    keys: &[ObjectKey],
) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    let keys = key_columns(keys.iter());
    sqlx::query(&format!(
        "INSERT INTO {SCHEMA}.managed_objects_undo
            (migration_id, kind, schema_name, parent, name, existed, desired_fp, desired_sql,
             live_fp, live_def, status, prior_migration_id, created_at, updated_at)
         SELECT $5, k.kind, k.schema_name, k.parent, k.name, m.kind IS NOT NULL, m.desired_fp,
                m.desired_sql, m.live_fp, m.live_def, m.status, m.migration_id, m.created_at,
                m.updated_at
           FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[])
                AS k(kind, schema_name, parent, name)
           LEFT JOIN {SCHEMA}.managed_objects m
             ON m.kind = k.kind AND m.schema_name = k.schema_name
            AND m.parent = k.parent AND m.name = k.name
         ON CONFLICT DO NOTHING"
    ))
    .bind(&keys.kinds)
    .bind(&keys.schemas)
    .bind(&keys.parents)
    .bind(&keys.names)
    .bind(migration_id)
    .execute(&mut *conn)
    .await
    .context("record the ledger as it was before the push")?;
    Ok(())
}

/// Puts the ledger back as it was before `migration_id`'s push: rows it added go, rows it changed
/// or removed come back as they were. In the rollback's transaction.
///
/// Only rows still as the push left them. The ledger is also written outside a migration (`adopt`,
/// `adopt --release`, `doctor --rebaseline`), and a write made after the push is not the push's to
/// undo: a release made since would otherwise be silently reverted. Every row a push writes carries
/// its transaction's `NOW()`, as does its migration's `applied_at`, so a row written since is one
/// updated after it.
pub async fn restore(conn: &mut PgConnection, migration_id: i32) -> Result<()> {
    let untouched_since = format!("(SELECT applied_at FROM {SCHEMA}.migrations WHERE id = $1)");
    let statements = [
        format!(
            "DELETE FROM {SCHEMA}.managed_objects m USING {SCHEMA}.managed_objects_undo u
              WHERE u.migration_id = $1 AND NOT u.existed
                AND m.kind = u.kind AND m.schema_name = u.schema_name
                AND m.parent = u.parent AND m.name = u.name
                AND m.updated_at <= {untouched_since}"
        ),
        format!(
            "INSERT INTO {SCHEMA}.managed_objects
                (kind, schema_name, parent, name, desired_fp, desired_sql, live_fp, live_def,
                 status, migration_id, created_at, updated_at)
             SELECT kind, schema_name, parent, name, desired_fp, desired_sql, live_fp, live_def,
                    status, prior_migration_id, created_at, updated_at
               FROM {SCHEMA}.managed_objects_undo
              WHERE migration_id = $1 AND existed
             ON CONFLICT (kind, schema_name, parent, name) DO UPDATE SET
                desired_fp = EXCLUDED.desired_fp,
                desired_sql = EXCLUDED.desired_sql,
                live_fp = EXCLUDED.live_fp,
                live_def = EXCLUDED.live_def,
                status = EXCLUDED.status,
                migration_id = EXCLUDED.migration_id,
                created_at = EXCLUDED.created_at,
                updated_at = EXCLUDED.updated_at
              WHERE {SCHEMA}.managed_objects.updated_at <= {untouched_since}"
        ),
        format!("DELETE FROM {SCHEMA}.managed_objects_undo WHERE migration_id = $1"),
    ];
    for sql in &statements {
        sqlx::query(sql)
            .bind(migration_id)
            .execute(&mut *conn)
            .await
            .context("put the ledger back as it was before the push")?;
    }
    Ok(())
}

/// An object a rollback must leave as it is, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftAlone {
    pub key: ObjectKey,
    /// Taken back by `adopt --release`; otherwise its row was recorded again since the push.
    pub released: bool,
}

/// The objects a rollback of `migration_id` must leave as they are: every released object, which a
/// push never touches, and every object the push wrote whose row has been written again since
/// (`adopt --release`, `doctor --rebaseline`). [`restore`] already leaves those rows; their objects
/// stay with them, or a rollback would drop a column the user took back after the push, with its
/// data, and leave a row for a column that is gone.
pub async fn rewritten_since(conn: &mut PgConnection, migration_id: i32) -> Result<Vec<LeftAlone>> {
    let rows: Vec<(String, String, String, String, bool)> = sqlx::query_as(&format!(
        "SELECT m.kind, m.schema_name, m.parent, m.name, m.status = 'released'
           FROM {SCHEMA}.managed_objects m
          WHERE m.status = 'released'
             OR (m.updated_at > (SELECT applied_at FROM {SCHEMA}.migrations WHERE id = $1)
                 AND EXISTS (SELECT 1 FROM {SCHEMA}.managed_objects_undo u
                              WHERE u.migration_id = $1 AND u.kind = m.kind
                                AND u.schema_name = m.schema_name AND u.parent = m.parent
                                AND u.name = m.name))
          ORDER BY 1, 2, 3, 4"
    ))
    .bind(migration_id)
    .fetch_all(&mut *conn)
    .await
    .context("read the objects released or recorded again since the push")?;
    Ok(rows
        .into_iter()
        .filter_map(|(kind, schema, parent, name, released)| {
            Some(LeftAlone {
                key: ObjectKey {
                    kind: ObjectKind::parse(&kind)?,
                    schema,
                    parent,
                    name,
                },
                released,
            })
        })
        .collect())
}

/// The objects of `leave` that `sql_down` would drop with their table: one on a table the script
/// drops, when the table itself is not left alone. Leaving out the object's own statement does
/// not spare it, since the table takes it along, with a column's data.
pub fn dropped_with_their_table<'a>(
    sql_down: &str,
    schema: &str,
    leave: &'a [LeftAlone],
) -> Vec<&'a LeftAlone> {
    let dropped: Vec<statements::TableTarget> = statements::split_statements(sql_down)
        .iter()
        .filter(|sql| statements::head(sql).starts_with("DROP TABLE "))
        .filter_map(|sql| statements::table_target(schema, sql))
        .collect();
    let table_left = |s: &str, t: &str| {
        leave
            .iter()
            .any(|l| l.key.kind == ObjectKind::Table && l.key.schema == s && l.key.name == t)
    };
    leave
        .iter()
        .filter(|l| {
            table_of(&l.key).is_some_and(|table| {
                !table_left(&l.key.schema, table)
                    && dropped
                        .iter()
                        .any(|d| d.schema == l.key.schema && d.table == table)
            })
        })
        .collect()
}

/// What a rollback does about the objects released or recorded again since its push.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Sparing {
    /// Left as they are: their statements are left out of `sql_down` ([`leaving_alone`]).
    pub leave: Vec<ObjectKey>,
    /// Recorded again since the push but still Supatype's, on a table the rollback drops: they go
    /// with the table, and their rows with them.
    pub with_their_table: Vec<ObjectKey>,
}

/// Decides [`Sparing`] for rolling back `migration`, or refuses: a released object is the user's,
/// and one on a table the rollback drops would go with the table, with its data. The refusal
/// names each, with the `adopt --reclaim` that hands it back.
pub fn sparing(
    migration: &str,
    sql_down: &str,
    schema: &str,
    leave: &[LeftAlone],
) -> Result<Sparing> {
    let on_dropped = dropped_with_their_table(sql_down, schema, leave);
    let released: Vec<&ObjectKey> = on_dropped
        .iter()
        .filter(|l| l.released)
        .map(|l| &l.key)
        .collect();
    if !released.is_empty() {
        anyhow::bail!(refusal(migration, &released));
    }
    let with_their_table: Vec<ObjectKey> = on_dropped.iter().map(|l| l.key.clone()).collect();
    Ok(Sparing {
        leave: leave
            .iter()
            .map(|l| l.key.clone())
            .filter(|k| !with_their_table.contains(k))
            .collect(),
        with_their_table,
    })
}

fn refusal(migration: &str, released: &[&ObjectKey]) -> String {
    let named: Vec<String> = released.iter().map(ToString::to_string).collect();
    let reclaim: Vec<String> = released
        .iter()
        .map(|k| format!("--reclaim {}:{}.{}", k.kind.as_str(), k.parent, k.name))
        .collect();
    format!(
        "rollback_refused: Rolling back migration {migration} would drop the table that holds {}, \
         released since the push, and its data with it. Nothing was rolled back. To roll back \
         anyway, hand it back first with `supatype adopt {}`, or move what you need out of the \
         table.",
        named.join(", "),
        reclaim.join(" ")
    )
}

/// `sql_down` without the statements that act on any of `leave`: on the object itself, on a column
/// or constraint of it, or on anything of a table among them. Returns the script and the objects
/// whose statements were left out.
pub fn leaving_alone(
    sql_down: &str,
    schema: &str,
    leave: &[ObjectKey],
) -> (String, Vec<ObjectKey>) {
    if leave.is_empty() {
        return (sql_down.to_string(), Vec::new());
    }
    let table = |s: &str, t: &str| {
        leave
            .iter()
            .find(|k| k.kind == ObjectKind::Table && k.schema == s && k.name == t)
    };
    let constraint = |s: &str, t: &str, n: &str| {
        leave.iter().find(|k| {
            matches!(
                k.kind,
                ObjectKind::PrimaryKey
                    | ObjectKind::Unique
                    | ObjectKind::ForeignKey
                    | ObjectKind::Check
            ) && k.schema == s
                && k.parent == t
                && k.name == n
        })
    };
    let mut kept = String::new();
    let mut left: Vec<ObjectKey> = Vec::new();
    for statement in statements::attribute_all(schema, statements::split_statements(sql_down)) {
        let mut hit: Option<&ObjectKey> = statement.attribution.keys().iter().find_map(|k| {
            // A `DROP INDEX` names no table, and attributes to none unless the script created
            // the index too.
            leave
                .iter()
                .find(|l| {
                    (l.kind, &l.schema, &l.name) == (k.kind, &k.schema, &k.name)
                        && (k.parent.is_empty() || l.parent == k.parent)
                })
                .or_else(|| table(&k.schema, &k.parent))
        });
        if hit.is_none() {
            if let Some(target) = statements::table_target(schema, &statement.sql) {
                hit = table(&target.schema, &target.table)
                    .or_else(|| {
                        let column = target.column.as_deref()?;
                        leave.iter().find(|k| {
                            k.kind == ObjectKind::Column
                                && k.schema == target.schema
                                && k.parent == target.table
                                && k.name == column
                        })
                    })
                    .or_else(|| {
                        constraint(&target.schema, &target.table, target.constraint.as_deref()?)
                    });
            }
        }
        match hit {
            Some(key) => {
                if !left.contains(key) {
                    left.push(key.clone());
                }
                // The statement goes; a comment says why, so the stored script still reads true.
                kept.push_str(&format!(
                    "\n-- left as it is: {key} was released or recorded again since this push\n"
                ));
            }
            None => kept.push_str(&statement.sql),
        }
    }
    (kept, left)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(kind: ObjectKind, parent: &str, name: &str) -> ObjectKey {
        ObjectKey {
            kind,
            schema: "public".into(),
            parent: parent.into(),
            name: name.into(),
        }
    }

    const DOWN: &str = "-- reconciled objects\n\
        DROP POLICY IF EXISTS \"posts_select\" ON \"public\".\"posts\";\n\
        ALTER TABLE \"public\".\"order_item\" DROP COLUMN IF EXISTS \"note\";\n\
        ALTER TABLE \"public\".\"order_item\" DROP COLUMN IF EXISTS \"other\";\n\
        ALTER TABLE \"public\".\"posts\" DROP CONSTRAINT IF EXISTS \"posts_a_check\";\n\
        DROP TABLE IF EXISTS \"public\".\"tags\";\n\
        DROP INDEX IF EXISTS \"public\".\"posts_body_idx\";\n";

    #[test]
    fn nothing_released_leaves_the_script_as_it_is() {
        assert_eq!(
            leaving_alone(DOWN, "public", &[]),
            (DOWN.to_string(), vec![])
        );
    }

    #[test]
    fn a_released_column_policy_constraint_and_table_are_left_alone() {
        let leave = [
            key(ObjectKind::Column, "order_item", "note"),
            key(ObjectKind::Policy, "posts", "posts_select"),
            key(ObjectKind::Check, "posts", "posts_a_check"),
            key(ObjectKind::Table, "", "tags"),
            key(ObjectKind::Index, "posts", "posts_body_idx"),
        ];
        let (sql, left) = leaving_alone(DOWN, "public", &leave);
        assert!(!sql.contains("DROP COLUMN IF EXISTS \"note\""), "{sql}");
        assert!(sql.contains("DROP COLUMN IF EXISTS \"other\""), "{sql}");
        assert!(!sql.contains("DROP POLICY"), "{sql}");
        assert!(!sql.contains("DROP CONSTRAINT"), "{sql}");
        assert!(!sql.contains("DROP TABLE"), "{sql}");
        assert!(!sql.contains("DROP INDEX"), "{sql}");
        assert_eq!(left.len(), 5);
    }

    fn left(kind: ObjectKind, parent: &str, name: &str, released: bool) -> LeftAlone {
        LeftAlone {
            key: key(kind, parent, name),
            released,
        }
    }

    #[test]
    fn a_released_column_on_a_dropped_table_blocks_the_rollback() {
        let leave = [
            left(ObjectKind::Column, "tags", "c", true),
            left(ObjectKind::SecurityLabel, "tags.a", "supatype", false),
            left(ObjectKind::Column, "order_item", "note", true),
        ];
        let blocked = dropped_with_their_table(DOWN, "public", &leave);
        assert_eq!(blocked, [&leave[0], &leave[1]]);
        let message = sparing("create_tags", DOWN, "public", &leave)
            .expect_err("a released column would go with its table")
            .to_string();
        assert!(
            message.contains("column public.tags.c, released"),
            "{message}"
        );
        assert!(
            message.contains("adopt --reclaim column:tags.c`"),
            "{message}"
        );
        assert!(!message.contains("security_label"), "{message}");
    }

    #[test]
    fn what_was_recorded_again_on_a_dropped_table_goes_with_it() {
        let leave = [
            left(ObjectKind::SecurityLabel, "tags.a", "supatype", false),
            left(ObjectKind::Column, "order_item", "note", true),
        ];
        assert_eq!(
            sparing("create_tags", DOWN, "public", &leave).unwrap(),
            Sparing {
                leave: vec![leave[1].key.clone()],
                with_their_table: vec![leave[0].key.clone()],
            }
        );
    }

    #[test]
    fn a_dropped_table_that_is_itself_left_alone_blocks_nothing() {
        let leave = [
            left(ObjectKind::Table, "", "tags", true),
            left(ObjectKind::Column, "tags", "c", true),
            left(ObjectKind::Function, "", "slugify(text)", true),
        ];
        assert!(dropped_with_their_table(DOWN, "public", &leave).is_empty());
    }

    #[test]
    fn everything_on_a_released_table_is_left_alone() {
        let leave = [key(ObjectKind::Table, "", "order_item")];
        let (sql, left) = leaving_alone(DOWN, "public", &leave);
        assert!(!sql.contains("order_item\" DROP COLUMN"), "{sql}");
        assert!(sql.contains("DROP POLICY"), "{sql}");
        assert_eq!(left, leave);
    }
}
