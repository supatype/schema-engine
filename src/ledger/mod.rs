//! The push ledger: `_supatype.managed_objects`, one row per object a push owns.
//!
//! Phase 3 of the managed-object ownership plan (`plans/Managed-Object-Ownership-Plan.md`, 3.2).
//! The ledger is the authority on what Supatype created (D1); comments belong to the user. A row
//! records two things about an object, compared two ways (D6, Drizzle's split):
//!
//! - `desired_sql` and its hash `desired_fp`: the `CREATE` this engine wrote at the last push.
//!   Compared text to text against this push's `CREATE`; when it differs, our intent changed and
//!   the object is replaced.
//! - `live_def` and its hash `live_fp`: the structural fingerprint read from the catalog after the
//!   last apply (D5). Compared against the catalog now; when it differs, someone changed the object
//!   outside Supatype, which is drift.
//!
//! Keyed by name, never OID, so it survives a dump and restore. Lives in `_supatype`, which
//! PostgREST does not expose, so the data plane cannot read or write it. The reconcile that reads
//! these rows is [`reconcile`]; this module is only the storage.

pub mod probe;
pub mod reconcile;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

use crate::desired::ObjectKey;
use crate::introspector::fingerprint::{hash, normalise_sql, ObjectKind};

const SCHEMA: &str = "_supatype";

/// How a row came to be ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Created by a push, or found stamped `supatype:managed` and taken over.
    Managed,
    /// Found unstamped under our name with the structure we wanted (D2), or handed over by `adopt`.
    Adopted,
    /// Taken back by `adopt --release`. Left alone by every push; kept so D2 does not re-adopt it.
    Released,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Managed => "managed",
            Status::Adopted => "adopted",
            Status::Released => "released",
        }
    }

    pub const ALL: [Status; 3] = [Status::Managed, Status::Adopted, Status::Released];

    pub fn parse(text: &str) -> Option<Status> {
        Self::ALL.into_iter().find(|s| s.as_str() == text)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRow {
    pub key: ObjectKey,
    pub desired_fp: String,
    pub desired_sql: String,
    pub live_fp: String,
    pub live_def: String,
    pub status: Status,
    /// The `_supatype.migrations` row that last changed this object, once one has.
    pub migration_id: Option<i32>,
}

/// The hash of what we intend: the normalised `CREATE` text. Our own text both times, so no
/// deparse normalisation is involved.
pub fn desired_fingerprint(kind: ObjectKind, create_sql: &str) -> String {
    hash(kind, &[&normalise_sql(create_sql)])
}

pub fn create_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.managed_objects (
    kind          TEXT NOT NULL,
    schema_name   TEXT NOT NULL,
    parent        TEXT NOT NULL DEFAULT '',
    name          TEXT NOT NULL,
    desired_fp    TEXT NOT NULL,
    desired_sql   TEXT NOT NULL,
    live_fp       TEXT NOT NULL,
    live_def      TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('managed', 'adopted', 'released')),
    migration_id  INT REFERENCES {SCHEMA}.migrations (id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (kind, schema_name, parent, name)
)"#
    )
}

type Row = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<i32>,
);

/// [`load`], or no rows when the table does not exist yet: a `diff` or `doctor` against a
/// database no push has bootstrapped.
pub async fn load_if_present(conn: &mut PgConnection) -> Result<Vec<LedgerRow>> {
    match load_rows(conn).await {
        // `undefined_table`: nothing has bootstrapped the ledger yet, so it holds nothing.
        Err(e) if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("42P01") => {
            Ok(Vec::new())
        }
        other => other
            .context("load the managed-object ledger")
            .and_then(decode_rows),
    }
}

/// Every row, in key order. A kind or status the running engine does not know (a row written by
/// a newer engine) is an error, not a skipped row: skipping it would make the reconcile treat the
/// object as unowned and create a second copy.
pub async fn load(conn: &mut PgConnection) -> Result<Vec<LedgerRow>> {
    load_rows(conn)
        .await
        .context("load the managed-object ledger")
        .and_then(decode_rows)
}

async fn load_rows(conn: &mut PgConnection) -> std::result::Result<Vec<Row>, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT kind, schema_name, parent, name, desired_fp, desired_sql, live_fp, live_def,
                status, migration_id
         FROM {SCHEMA}.managed_objects
         ORDER BY kind, schema_name, parent, name"
    ))
    .fetch_all(&mut *conn)
    .await
}

fn decode_rows(rows: Vec<Row>) -> Result<Vec<LedgerRow>> {
    rows.into_iter()
        .map(
            |(
                kind,
                schema,
                parent,
                name,
                desired_fp,
                desired_sql,
                live_fp,
                live_def,
                status,
                migration_id,
            )| {
                let kind = ObjectKind::parse(&kind).with_context(|| {
                    format!("ledger row {schema}.{parent}.{name}: unknown kind {kind:?}")
                })?;
                let status = Status::parse(&status).with_context(|| {
                    format!("ledger row {schema}.{parent}.{name}: unknown status {status:?}")
                })?;
                Ok(LedgerRow {
                    key: ObjectKey {
                        kind,
                        schema,
                        parent,
                        name,
                    },
                    desired_fp,
                    desired_sql,
                    live_fp,
                    live_def,
                    status,
                    migration_id,
                })
            },
        )
        .collect()
}

/// The four key columns as parallel arrays, the shape every batch statement binds.
struct KeyColumns<'a> {
    kinds: Vec<&'static str>,
    schemas: Vec<&'a str>,
    parents: Vec<&'a str>,
    names: Vec<&'a str>,
}

fn key_columns<'a>(keys: impl Iterator<Item = &'a ObjectKey>) -> KeyColumns<'a> {
    let mut out = KeyColumns {
        kinds: Vec::new(),
        schemas: Vec::new(),
        parents: Vec::new(),
        names: Vec::new(),
    };
    for k in keys {
        out.kinds.push(k.kind.as_str());
        out.schemas.push(&k.schema);
        out.parents.push(&k.parent);
        out.names.push(&k.name);
    }
    out
}

/// Joins a row `m` to the unnested key arrays `$1` to `$4`.
const KEY_MATCH: &str = "UNNEST($1::text[], $2::text[], $3::text[], $4::text[]) \
     AS k(kind, schema_name, parent, name) \
     WHERE m.kind = k.kind AND m.schema_name = k.schema_name \
       AND m.parent = k.parent AND m.name = k.name";

/// Insert or replace rows by key, in one statement.
pub async fn upsert(conn: &mut PgConnection, rows: &[LedgerRow]) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let keys = key_columns(rows.iter().map(|r| &r.key));
    let desired_fps: Vec<&str> = rows.iter().map(|r| r.desired_fp.as_str()).collect();
    let desired_sqls: Vec<&str> = rows.iter().map(|r| r.desired_sql.as_str()).collect();
    let live_fps: Vec<&str> = rows.iter().map(|r| r.live_fp.as_str()).collect();
    let live_defs: Vec<&str> = rows.iter().map(|r| r.live_def.as_str()).collect();
    let statuses: Vec<&str> = rows.iter().map(|r| r.status.as_str()).collect();
    let migrations: Vec<Option<i32>> = rows.iter().map(|r| r.migration_id).collect();

    sqlx::query(&format!(
        "INSERT INTO {SCHEMA}.managed_objects
            (kind, schema_name, parent, name, desired_fp, desired_sql, live_fp, live_def, status,
             migration_id)
         SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[],
                              $6::text[], $7::text[], $8::text[], $9::text[], $10::int[])
         ON CONFLICT (kind, schema_name, parent, name) DO UPDATE SET
            desired_fp = EXCLUDED.desired_fp,
            desired_sql = EXCLUDED.desired_sql,
            live_fp = EXCLUDED.live_fp,
            live_def = EXCLUDED.live_def,
            status = EXCLUDED.status,
            migration_id = EXCLUDED.migration_id,
            updated_at = NOW()"
    ))
    .bind(&keys.kinds)
    .bind(&keys.schemas)
    .bind(&keys.parents)
    .bind(&keys.names)
    .bind(&desired_fps)
    .bind(&desired_sqls)
    .bind(&live_fps)
    .bind(&live_defs)
    .bind(&statuses)
    .bind(&migrations)
    .execute(&mut *conn)
    .await
    .context("write the managed-object ledger")?;
    Ok(())
}

/// Remove rows by key.
pub async fn delete(conn: &mut PgConnection, keys: &[ObjectKey]) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    let keys = key_columns(keys.iter());
    sqlx::query(&format!(
        "DELETE FROM {SCHEMA}.managed_objects m USING {KEY_MATCH}"
    ))
    .bind(&keys.kinds)
    .bind(&keys.schemas)
    .bind(&keys.parents)
    .bind(&keys.names)
    .execute(&mut *conn)
    .await
    .context("delete from the managed-object ledger")?;
    Ok(())
}

/// Point rows at the migration that changed them, once its `_supatype.migrations` row exists.
pub async fn set_migration(
    conn: &mut PgConnection,
    keys: &[ObjectKey],
    migration_id: i32,
) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    let keys = key_columns(keys.iter());
    sqlx::query(&format!(
        "UPDATE {SCHEMA}.managed_objects m SET migration_id = $5, updated_at = NOW() FROM {KEY_MATCH}"
    ))
    .bind(&keys.kinds)
    .bind(&keys.schemas)
    .bind(&keys.parents)
    .bind(&keys.names)
    .bind(migration_id)
    .execute(&mut *conn)
    .await
    .context("link ledger rows to their migration")?;
    Ok(())
}
