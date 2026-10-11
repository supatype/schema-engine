//! What the engine creates but [`crate::state::database_state::DatabaseState`] does not carry.
//!
//! `DatabaseState` is what every differ reads, and seventy-odd tests build it by hand, so a field
//! added there is a field every one of them must name. This struct holds the kinds the ledger
//! (`plans/Managed-Object-Ownership-Plan.md`) needs to see and nothing diffs against yet. It is
//! read beside `DatabaseState`, not inside it, and the two merge when the ledger gives the differ
//! a reason to read these.
//!
//! Every reader sweeps the project schema and the schemas the engine writes to on its own
//! ([`ENGINE_SCHEMAS`]), records which schema each object sits in, and leaves out anything an
//! extension owns (`pg_depend.deptype = 'e'`), the way the table reader already does for PostGIS.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};

use super::fingerprint::ObjectKind;
use super::indexes::{self, DbIndex};

/// The schemas a push writes to besides the project's own.
///
/// `auth` and `storage` are here for the helper functions and policies the engine adds to them,
/// not for their tables, which the server and the Postgres image own.
pub const ENGINE_SCHEMAS: &[&str] = &[
    "_supatype",
    "_platform",
    "draft",
    "api",
    "supatype",
    "auth",
    "storage",
];

/// The schemas the engine creates for itself and nothing else writes to. An object the schema
/// wants that already exists in one of these with no ledger row is ours by location, whatever an
/// older engine made of it (plan 3.4): taken over and brought up to date, never refused.
pub const OWNED_SCHEMAS: &[&str] = &["_supatype", "_platform", "draft", "api", "supatype"];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogState {
    /// The project schema's indexes made only of expressions, which `DatabaseState::indexes`
    /// leaves out: see [`indexes::DbIndexes`] for why they are kept apart. An engine schema's are
    /// in [`Self::engine_tables`] with the rest of its indexes, so between them every swept schema
    /// whose tables are read is covered; `auth` and `storage` tables are never read
    /// ([`HELPER_ONLY_SCHEMAS`]).
    pub expression_indexes: Vec<DbIndex>,
    pub triggers: Vec<DbCatalogTrigger>,
    pub functions: Vec<DbFunction>,
    pub views: Vec<DbView>,
    pub schemas: Vec<DbSchema>,
    pub sequences: Vec<DbSequence>,
    pub enum_types: Vec<DbEnumType>,
    pub table_grants: Vec<DbTableGrant>,
    pub column_grants: Vec<DbColumnGrant>,
    pub security_labels: Vec<DbSecurityLabel>,
    /// Empty when the database has no `cron.job`, which is most databases.
    pub cron_jobs: Vec<DbCronJob>,
    /// Whether `cron.job` exists here at all. A job the schema wants is desired only where it can
    /// be scheduled; elsewhere the layer says so and the ledger records nothing (plan section 10).
    /// A fact about the database, not its state, so not part of the serialised catalog.
    #[serde(skip)]
    pub cron_available: bool,
    /// The API roles the engine grants to that exist here. A self-hosted database may have neither,
    /// and a grant to a role that does not exist is desired nowhere (plan section 10). A fact
    /// about the database, not its state, so not part of the serialised catalog.
    #[serde(skip)]
    pub granted_roles: Vec<String>,
    pub rls_attributes: Vec<DbRlsAttributes>,
    /// Every policy in the swept schemas, with the roles and comment `DatabaseState::rls_policies`
    /// does not carry.
    pub policies: Vec<DbPolicy>,
    /// The engine's own tables, with their constraints and indexes, one entry per engine schema
    /// that has any. `DatabaseState` reads the project schema only; without this the registry and
    /// the preview links have no live fingerprint and the ledger could not record them.
    #[serde(default)]
    pub engine_tables: Vec<EngineSchemaTables>,
    /// The project schema's objects a concurrent build or a `NOT VALID` addition left unfinished.
    #[serde(default)]
    pub pending: Vec<PendingObject>,
}

/// A key or check not yet validated, or an INVALID index, in the project schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingObject {
    pub kind: ObjectKind,
    pub table: String,
    pub name: String,
}

/// The tables of one engine schema, read with the same readers as the project schema so an engine
/// table gets the same fingerprints as a model table.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineSchemaTables {
    pub schema: String,
    pub tables: Vec<super::tables::DbTable>,
    /// Columnar and expression-only indexes together: the ledger keys them the same way.
    pub indexes: Vec<DbIndex>,
    pub constraints: Vec<super::constraints::DbConstraint>,
}

/// The engine schemas swept for the functions and policies the engine adds to them but never for
/// tables: those belong to the server and the image. Every other engine schema's tables are ours.
const HELPER_ONLY_SCHEMAS: &[&str] = &["auth", "storage"];

/// A policy as `pg_policy` describes it, in the project schema or an engine schema (the
/// `storage.objects` policies a bucket's rules become, the layer's own).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbPolicy {
    pub schema: String,
    pub table: String,
    pub name: String,
    /// `polcmd`: `r` select, `a` insert, `w` update, `d` delete, `*` all.
    pub command: String,
    pub permissive: bool,
    /// Sorted role names; `public` when the policy applies to everyone.
    pub roles: Vec<String>,
    pub using_expr: Option<String>,
    pub check_expr: Option<String>,
    pub comment: Option<String>,
}

/// A trigger as `pg_trigger` describes it. `DatabaseState::triggers` reads `information_schema`,
/// which has no comment, no `WHEN` clause and one row per event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbCatalogTrigger {
    pub schema: String,
    pub table: String,
    pub name: String,
    /// `BEFORE`, `AFTER` or `INSTEAD OF`.
    pub timing: String,
    /// Sorted: any of `DELETE`, `INSERT`, `TRUNCATE`, `UPDATE`.
    pub events: Vec<String>,
    /// `UPDATE OF` columns, when the trigger names any.
    pub columns: Vec<String>,
    pub for_each_row: bool,
    /// Schema-qualified function the trigger calls.
    pub function: String,
    /// The `WHEN` condition, as `pg_get_triggerdef` renders the whole statement.
    pub definition: String,
    pub enabled: bool,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbFunction {
    pub schema: String,
    pub name: String,
    /// `pg_get_function_identity_arguments`: what, with the name, identifies an overload.
    pub identity_arguments: String,
    /// The argument types alone, built-ins as `format_type` writes them and everything else
    /// schema-qualified: `text, timestamp with time zone, public.posts`. Unlike
    /// `identity_arguments` this does not depend on the session's `search_path` and carries no
    /// argument names, so the declared side (`crate::desired::identity`) can produce the same
    /// string without a database. The ledger keys a function by name plus this.
    #[serde(default)]
    pub identity_types: String,
    /// `pg_get_function_result`, empty for a procedure, which returns nothing.
    pub return_type: String,
    pub language: String,
    /// `i`, `s` or `v`.
    pub volatility: String,
    pub security_definer: bool,
    /// `prosrc`, or for a `BEGIN ATOMIC` body, whose `prosrc` is empty, the body as
    /// `pg_get_function_sqlbody` deparses it.
    pub body: String,
    pub comment: Option<String>,
    /// `pg_get_function_arguments`: names, modes and defaults, which the identity leaves out.
    #[serde(default)]
    pub arguments: String,
    /// `proconfig`, in catalog order: the `SET search_path = ''` a security definer function
    /// pins, and any other `SET` it carries.
    #[serde(default)]
    pub config: Vec<String>,
    #[serde(default)]
    pub strict: bool,
    #[serde(default)]
    pub leakproof: bool,
    /// `s` safe, `r` restricted or `u` unsafe.
    #[serde(default)]
    pub parallel: String,
    /// `procost` and `prorows` as text.
    #[serde(default)]
    pub cost: String,
    #[serde(default)]
    pub rows: String,
    /// `pg_get_functiondef`: the whole `CREATE OR REPLACE FUNCTION` (or `PROCEDURE`), with every
    /// property above. What a rollback runs to put the function back as it was.
    #[serde(default)]
    pub definition: String,
    /// Who may call it besides its owner, as sorted `grantee=PRIVILEGE` entries (`PUBLIC` for the
    /// default grant): which API role can reach an RPC function is part of what it is (F14).
    #[serde(default)]
    pub acl: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbView {
    pub schema: String,
    pub name: String,
    pub materialized: bool,
    pub definition: String,
    pub comment: Option<String>,
    /// `reloptions`, sorted: `security_invoker` and `security_barrier` decide whose rights the view
    /// reads with and whether a caller's filter can run beneath it.
    #[serde(default)]
    pub options: Vec<String>,
    /// The role it runs as when it is not `security_invoker`.
    #[serde(default)]
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbSchema {
    pub name: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbSequence {
    pub schema: String,
    pub name: String,
    /// `table.column` when the sequence is owned by a column: `SERIAL` and `OWNED BY` record that
    /// as an auto dependency (`pg_depend.deptype = 'a'`), an identity column as an internal one
    /// (`'i'`).
    pub owned_by: Option<String>,
    pub comment: Option<String>,
}

/// An enum type with its comment. `DatabaseState::enums` carries the values; this carries identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbEnumType {
    pub schema: String,
    pub name: String,
    pub comment: Option<String>,
}

/// One grantee's privileges on one table or view, sorted. `PUBLIC` is spelled as such.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbTableGrant {
    pub schema: String,
    pub table: String,
    pub grantee: String,
    pub privileges: Vec<String>,
    /// How the privileges are held beyond a plain grant from the table's owner (E16).
    #[serde(default)]
    pub held_with: HeldWith,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbColumnGrant {
    pub schema: String,
    pub table: String,
    pub column: String,
    pub grantee: String,
    pub privileges: Vec<String>,
    #[serde(default)]
    pub held_with: HeldWith,
}

/// What a grantee may do with its privileges beyond using them, read from `aclexplode`: those it
/// may grant on (`WITH GRANT OPTION`), and those it holds from a grantor other than the table's
/// owner, as `<privilege> GRANTED BY <role>`. Either lets a role hand access on, or keep it after
/// the owner revokes it, so either is a change to what the role may do. Both are empty for every
/// grant the engine makes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeldWith {
    #[serde(default)]
    pub grant_option: Vec<String>,
    #[serde(default)]
    pub other_grantors: Vec<String>,
}

/// The two `SELECT` columns that read a grantee's [`HeldWith`] from the `aclexplode` rows `g` of a
/// relation `c`, aggregated per grantee, with the grantor's role joined as `gr`.
const HELD_WITH_COLUMNS: &str = "COALESCE(array_agg(DISTINCT g.privilege_type::text
                    ORDER BY g.privilege_type::text) FILTER (WHERE g.is_grantable), ARRAY[]::text[]),
                COALESCE(array_agg(DISTINCT g.privilege_type::text || ' GRANTED BY '
                    || COALESCE(quote_ident(gr.rolname::text), 'PUBLIC'))
                    FILTER (WHERE g.grantor <> c.relowner), ARRAY[]::text[])";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbSecurityLabel {
    pub schema: String,
    pub table: String,
    /// Empty for a label on the table itself.
    pub column: Option<String>,
    pub provider: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbCronJob {
    pub name: String,
    pub schedule: String,
    pub command: String,
    pub active: bool,
}

/// A table's row-level security attributes, and its replica identity, read in the same pass over
/// `pg_class`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbRlsAttributes {
    pub schema: String,
    pub table: String,
    pub enabled: bool,
    pub forced: bool,
    /// `pg_class.relreplident`: `d`efault, `f`ull, `n`othing or `i`ndex.
    #[serde(default)]
    pub replica_identity: String,
}

fn swept_schemas(schema: &str) -> Vec<String> {
    let mut out = vec![schema.to_string()];
    for s in ENGINE_SCHEMAS {
        if *s != schema {
            out.push((*s).to_string());
        }
    }
    out
}

pub async fn read(conn: &mut PgConnection, schema: &str) -> Result<CatalogState> {
    let schemas = swept_schemas(schema);
    let indexes = indexes::read_all(conn, schema).await?;
    Ok(CatalogState {
        expression_indexes: indexes.expression_only,
        triggers: read_triggers(conn, &schemas).await?,
        functions: read_functions(conn, &schemas).await?,
        views: read_views(conn, &schemas).await?,
        schemas: read_schemas(conn, &schemas).await?,
        sequences: read_sequences(conn, &schemas).await?,
        enum_types: read_enum_types(conn, &schemas).await?,
        table_grants: read_table_grants(conn, &schemas).await?,
        column_grants: read_column_grants(conn, &schemas).await?,
        security_labels: read_security_labels(conn, &schemas).await?,
        cron_jobs: read_cron_jobs(conn).await?,
        cron_available: cron_available(conn).await?,
        granted_roles: granted_roles(conn).await?,
        rls_attributes: read_rls_attributes(conn, &schemas).await?,
        policies: read_policies(conn, &schemas).await?,
        engine_tables: read_engine_tables(conn, schema).await?,
        pending: read_pending(conn, schema).await?,
    })
}

async fn read_engine_tables(
    conn: &mut PgConnection,
    project_schema: &str,
) -> Result<Vec<EngineSchemaTables>> {
    let mut out = Vec::new();
    for s in ENGINE_SCHEMAS
        .iter()
        .filter(|s| **s != project_schema && !HELPER_ONLY_SCHEMAS.contains(s))
    {
        let tables = super::tables::read(conn, s).await?;
        if tables.is_empty() {
            continue;
        }
        let indexes = indexes::read_all(conn, s).await?;
        out.push(EngineSchemaTables {
            schema: (*s).to_string(),
            tables,
            indexes: indexes
                .columnar
                .into_iter()
                .chain(indexes.expression_only)
                .collect(),
            constraints: super::constraints::read(conn, s).await?,
        });
    }
    Ok(out)
}

async fn read_policies(conn: &mut PgConnection, schemas: &[String]) -> Result<Vec<DbPolicy>> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        String,
        bool,
        Vec<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT n.nspname::text, c.relname::text, p.polname::text, p.polcmd::text, p.polpermissive,
                (SELECT array_agg(role_name ORDER BY role_name)
                   FROM unnest(p.polroles) AS r(oid)
                   CROSS JOIN LATERAL (SELECT CASE WHEN r.oid = 0 THEN 'public'
                                                   ELSE (SELECT rolname::text FROM pg_roles WHERE oid = r.oid)
                                              END AS role_name) x),
                pg_get_expr(p.polqual, p.polrelid),
                pg_get_expr(p.polwithcheck, p.polrelid),
                obj_description(p.oid, 'pg_policy')
         FROM pg_policy p
         JOIN pg_class c ON c.oid = p.polrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = ANY($1)
         ORDER BY n.nspname, c.relname, p.polname",
    )
    .bind(schemas)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(schema, table, name, command, permissive, roles, using_expr, check_expr, comment)| {
                DbPolicy {
                    schema,
                    table,
                    name,
                    command,
                    permissive,
                    roles,
                    using_expr,
                    check_expr,
                    comment,
                }
            },
        )
        .collect())
}

/// `tgtype` bits, from `pg_trigger.h`.
const TRIGGER_ROW: i16 = 1;
const TRIGGER_BEFORE: i16 = 2;
const TRIGGER_INSERT: i16 = 4;
const TRIGGER_DELETE: i16 = 8;
const TRIGGER_UPDATE: i16 = 16;
const TRIGGER_TRUNCATE: i16 = 32;
const TRIGGER_INSTEAD: i16 = 64;

type TriggerRow = (
    String,
    String,
    String,
    i16,
    Option<Vec<String>>,
    String,
    String,
    String,
    Option<String>,
);

async fn read_triggers(
    conn: &mut PgConnection,
    schemas: &[String],
) -> Result<Vec<DbCatalogTrigger>> {
    let rows: Vec<TriggerRow> = sqlx::query_as(
        "SELECT n.nspname::text, c.relname::text, t.tgname::text, t.tgtype,
                (SELECT array_agg(a.attname::text ORDER BY k.ord)
                   FROM unnest(t.tgattr) WITH ORDINALITY AS k(attnum, ord)
                   JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum),
                pn.nspname::text || '.' || p.proname::text,
                pg_get_triggerdef(t.oid),
                t.tgenabled::text,
                obj_description(t.oid, 'pg_trigger')
         FROM pg_trigger t
         JOIN pg_class c ON c.oid = t.tgrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         JOIN pg_proc p ON p.oid = t.tgfoid
         JOIN pg_namespace pn ON pn.oid = p.pronamespace
         LEFT JOIN pg_depend d ON d.classid = 'pg_trigger'::regclass AND d.objid = t.oid AND d.deptype = 'e'
         WHERE n.nspname = ANY($1) AND NOT t.tgisinternal AND d.objid IS NULL
         ORDER BY n.nspname, c.relname, t.tgname",
    )
    .bind(schemas)
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(schema, table, name, tgtype, columns, function, definition, enabled, comment)| {
                let timing = if tgtype & TRIGGER_INSTEAD != 0 {
                    "INSTEAD OF"
                } else if tgtype & TRIGGER_BEFORE != 0 {
                    "BEFORE"
                } else {
                    "AFTER"
                };
                let mut events = Vec::new();
                for (bit, event) in [
                    (TRIGGER_DELETE, "DELETE"),
                    (TRIGGER_INSERT, "INSERT"),
                    (TRIGGER_TRUNCATE, "TRUNCATE"),
                    (TRIGGER_UPDATE, "UPDATE"),
                ] {
                    if tgtype & bit != 0 {
                        events.push(event.to_string());
                    }
                }
                DbCatalogTrigger {
                    schema,
                    table,
                    name,
                    timing: timing.to_string(),
                    events,
                    columns: columns.unwrap_or_default(),
                    for_each_row: tgtype & TRIGGER_ROW != 0,
                    function,
                    definition,
                    enabled: enabled != "D",
                    comment,
                }
            },
        )
        .collect())
}

async fn read_functions(conn: &mut PgConnection, schemas: &[String]) -> Result<Vec<DbFunction>> {
    // `identity_types`: `proargtypes` holds the input argument types in order. A `pg_catalog`
    // type is written by `format_type` (`timestamp with time zone`, `text[]`); any other type is
    // schema-qualified by hand, because `format_type` would leave it bare when its schema is on
    // the `search_path`, and the key must not change with the session. An array of such a type
    // is its element type, qualified, with `[]` (`public.things[]`), as the declaration writes
    // it, not the array type's own name (`public._things`).
    let rows = sqlx::query(
        "SELECT n.nspname::text, p.proname::text,
                pg_get_function_identity_arguments(p.oid),
                COALESCE((SELECT string_agg(
                            CASE WHEN tn.nspname = 'pg_catalog'
                                 THEN pg_catalog.format_type(a.oid, NULL)
                                 WHEN e.oid IS NOT NULL
                                 THEN quote_ident(en.nspname) || '.' || quote_ident(e.typname) || '[]'
                                 ELSE quote_ident(tn.nspname) || '.' || quote_ident(t.typname) END,
                            ', ' ORDER BY a.ord)
                          FROM unnest(p.proargtypes) WITH ORDINALITY AS a(oid, ord)
                          JOIN pg_type t ON t.oid = a.oid
                          JOIN pg_namespace tn ON tn.oid = t.typnamespace
                          -- A true array type, by `format_type`'s own test.
                          LEFT JOIN pg_type e ON t.typelem <> 0 AND t.typlen = -1 AND e.oid = t.typelem
                          LEFT JOIN pg_namespace en ON en.oid = e.typnamespace), ''),
                COALESCE(pg_get_function_result(p.oid), ''),
                l.lanname::text, p.provolatile::text, p.prosecdef,
                CASE WHEN p.prosqlbody IS NOT NULL THEN pg_get_function_sqlbody(p.oid)
                     ELSE p.prosrc END,
                obj_description(p.oid, 'pg_proc'),
                pg_get_function_arguments(p.oid),
                p.proconfig::text[], p.proisstrict, p.proleakproof, p.proparallel::text,
                p.procost::text, p.prorows::text,
                pg_get_functiondef(p.oid),
                ARRAY(SELECT CASE WHEN g.grantee = 0 THEN 'PUBLIC'
                                  ELSE pg_get_userbyid(g.grantee)::text END
                             || '=' || g.privilege_type
                        FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) g
                       WHERE g.grantee <> p.proowner
                       ORDER BY 1)
         FROM pg_proc p
         JOIN pg_namespace n ON n.oid = p.pronamespace
         JOIN pg_language l ON l.oid = p.prolang
         LEFT JOIN pg_depend d ON d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e'
         WHERE n.nspname = ANY($1) AND p.prokind IN ('f', 'p') AND d.objid IS NULL
         ORDER BY n.nspname, p.proname, 3",
    )
    .bind(schemas)
    .fetch_all(&mut *conn)
    .await?;

    rows.iter()
        .map(|row| -> Result<DbFunction> {
            Ok(DbFunction {
                schema: row.try_get(0)?,
                name: row.try_get(1)?,
                identity_arguments: row.try_get(2)?,
                identity_types: row.try_get(3)?,
                return_type: row.try_get(4)?,
                language: row.try_get(5)?,
                volatility: row.try_get(6)?,
                security_definer: row.try_get(7)?,
                body: row.try_get(8)?,
                comment: row.try_get(9)?,
                arguments: row.try_get(10)?,
                config: row
                    .try_get::<Option<Vec<String>>, _>(11)?
                    .unwrap_or_default(),
                strict: row.try_get(12)?,
                leakproof: row.try_get(13)?,
                parallel: row.try_get(14)?,
                cost: row.try_get(15)?,
                rows: row.try_get(16)?,
                definition: row.try_get(17)?,
                acl: row.try_get(18)?,
            })
        })
        .collect()
}

type ViewRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Vec<String>,
    String,
);

async fn read_views(conn: &mut PgConnection, schemas: &[String]) -> Result<Vec<DbView>> {
    let rows: Vec<ViewRow> = sqlx::query_as(
        "SELECT n.nspname::text, c.relname::text, c.relkind::text,
                pg_get_viewdef(c.oid, true), obj_description(c.oid, 'pg_class'),
                COALESCE(ARRAY(SELECT o FROM unnest(c.reloptions) AS o ORDER BY o), '{}'),
                pg_get_userbyid(c.relowner)::text
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         LEFT JOIN pg_depend d ON d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e'
         WHERE n.nspname = ANY($1) AND c.relkind IN ('v', 'm') AND d.objid IS NULL
         ORDER BY n.nspname, c.relname",
    )
    .bind(schemas)
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(schema, name, relkind, definition, comment, options, owner)| DbView {
                schema,
                name,
                materialized: relkind == "m",
                definition,
                comment,
                options,
                owner,
            },
        )
        .collect())
}

async fn read_schemas(conn: &mut PgConnection, schemas: &[String]) -> Result<Vec<DbSchema>> {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT n.nspname::text, obj_description(n.oid, 'pg_namespace')
         FROM pg_namespace n
         WHERE n.nspname = ANY($1)
         ORDER BY n.nspname",
    )
    .bind(schemas)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(name, comment)| DbSchema { name, comment })
        .collect())
}

async fn read_sequences(conn: &mut PgConnection, schemas: &[String]) -> Result<Vec<DbSequence>> {
    let rows: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT n.nspname::text, c.relname::text,
                (SELECT t.relname::text || '.' || a.attname::text
                   FROM pg_depend d
                   JOIN pg_class t ON t.oid = d.refobjid
                   JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
                  WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid
                    AND d.deptype IN ('a', 'i')
                  LIMIT 1),
                obj_description(c.oid, 'pg_class')
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         LEFT JOIN pg_depend e ON e.classid = 'pg_class'::regclass AND e.objid = c.oid AND e.deptype = 'e'
         WHERE n.nspname = ANY($1) AND c.relkind = 'S' AND e.objid IS NULL
         ORDER BY n.nspname, c.relname",
    )
    .bind(schemas)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(schema, name, owned_by, comment)| DbSequence {
            schema,
            name,
            owned_by,
            comment,
        })
        .collect())
}

async fn read_enum_types(conn: &mut PgConnection, schemas: &[String]) -> Result<Vec<DbEnumType>> {
    let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT n.nspname::text, t.typname::text, obj_description(t.oid, 'pg_type')
         FROM pg_type t
         JOIN pg_namespace n ON n.oid = t.typnamespace
         LEFT JOIN pg_depend d ON d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e'
         WHERE n.nspname = ANY($1) AND t.typtype = 'e' AND d.objid IS NULL
         ORDER BY n.nspname, t.typname",
    )
    .bind(schemas)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(schema, name, comment)| DbEnumType {
            schema,
            name,
            comment,
        })
        .collect())
}

async fn read_table_grants(
    conn: &mut PgConnection,
    schemas: &[String],
) -> Result<Vec<DbTableGrant>> {
    type Row = (
        String,
        String,
        String,
        Vec<String>,
        Vec<String>,
        Vec<String>,
    );
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT n.nspname::text, c.relname::text,
                CASE WHEN g.grantee = 0 THEN 'PUBLIC' ELSE r.rolname::text END,
                array_agg(DISTINCT g.privilege_type::text ORDER BY g.privilege_type::text),
                {HELD_WITH_COLUMNS}
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         CROSS JOIN LATERAL aclexplode(c.relacl) g
         LEFT JOIN pg_roles r ON r.oid = g.grantee
         LEFT JOIN pg_roles gr ON gr.oid = g.grantor
         LEFT JOIN pg_depend d ON d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e'
         WHERE n.nspname = ANY($1) AND c.relkind IN ('r', 'v', 'm', 'p') AND c.relacl IS NOT NULL
           AND d.objid IS NULL
         GROUP BY n.nspname, c.relname, g.grantee, r.rolname
         ORDER BY n.nspname, c.relname, 3"
    ))
    .bind(schemas)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(schema, table, grantee, privileges, grant_option, other_grantors)| DbTableGrant {
                schema,
                table,
                grantee,
                privileges,
                held_with: HeldWith {
                    grant_option,
                    other_grantors,
                },
            },
        )
        .collect())
}

async fn read_column_grants(
    conn: &mut PgConnection,
    schemas: &[String],
) -> Result<Vec<DbColumnGrant>> {
    type Row = (
        String,
        String,
        String,
        String,
        Vec<String>,
        Vec<String>,
        Vec<String>,
    );
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT n.nspname::text, c.relname::text, a.attname::text,
                CASE WHEN g.grantee = 0 THEN 'PUBLIC' ELSE r.rolname::text END,
                array_agg(DISTINCT g.privilege_type::text ORDER BY g.privilege_type::text),
                {HELD_WITH_COLUMNS}
         FROM pg_attribute a
         JOIN pg_class c ON c.oid = a.attrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
         CROSS JOIN LATERAL aclexplode(a.attacl) g
         LEFT JOIN pg_roles r ON r.oid = g.grantee
         LEFT JOIN pg_roles gr ON gr.oid = g.grantor
         LEFT JOIN pg_depend d ON d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e'
         WHERE n.nspname = ANY($1) AND c.relkind IN ('r', 'v', 'm', 'p')
           AND a.attnum > 0 AND NOT a.attisdropped AND a.attacl IS NOT NULL
           AND d.objid IS NULL
         GROUP BY n.nspname, c.relname, a.attname, g.grantee, r.rolname
         ORDER BY n.nspname, c.relname, a.attname, 4"
    ))
    .bind(schemas)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(schema, table, column, grantee, privileges, grant_option, other_grantors)| {
                DbColumnGrant {
                    schema,
                    table,
                    column,
                    grantee,
                    privileges,
                    held_with: HeldWith {
                        grant_option,
                        other_grantors,
                    },
                }
            },
        )
        .collect())
}

async fn read_security_labels(
    conn: &mut PgConnection,
    schemas: &[String],
) -> Result<Vec<DbSecurityLabel>> {
    let rows: Vec<(String, String, Option<String>, String, String)> = sqlx::query_as(
        "SELECT n.nspname::text, c.relname::text,
                CASE WHEN s.objsubid > 0 THEN a.attname::text END,
                s.provider::text, s.label::text
         FROM pg_seclabel s
         JOIN pg_class c ON c.oid = s.objoid AND s.classoid = 'pg_class'::regclass
         JOIN pg_namespace n ON n.oid = c.relnamespace
         LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = s.objsubid AND s.objsubid > 0
         WHERE n.nspname = ANY($1)
         ORDER BY n.nspname, c.relname, s.objsubid, s.provider",
    )
    .bind(schemas)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(schema, table, column, provider, label)| DbSecurityLabel {
            schema,
            table,
            column,
            provider,
            label,
        })
        .collect())
}

async fn granted_roles(conn: &mut PgConnection) -> Result<Vec<String>> {
    let wanted: Vec<String> = crate::generator::sql::grants::GRANTED_ROLES
        .iter()
        .map(|r| (*r).to_string())
        .collect();
    Ok(sqlx::query_scalar(
        "SELECT rolname::text FROM pg_roles WHERE rolname = ANY($1) ORDER BY rolname",
    )
    .bind(wanted)
    .fetch_all(&mut *conn)
    .await?)
}

/// The project schema's keys and checks still `NOT VALID`, and its INVALID indexes: what a push
/// added online and has not finished (IN-C 2), or what someone left half made.
async fn read_pending(conn: &mut PgConnection, schema: &str) -> Result<Vec<PendingObject>> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT CASE con.contype WHEN 'f' THEN 'foreign_key' ELSE 'check' END,
                rel.relname::text, con.conname::text
           FROM pg_constraint con
           JOIN pg_class rel ON rel.oid = con.conrelid
           JOIN pg_namespace n ON n.oid = rel.relnamespace
          WHERE n.nspname = $1 AND NOT con.convalidated AND con.contype IN ('f', 'c')
         UNION ALL
         SELECT 'index', t.relname::text, i.relname::text
           FROM pg_index ix
           JOIN pg_class i ON i.oid = ix.indexrelid
           JOIN pg_class t ON t.oid = ix.indrelid
           JOIN pg_namespace n ON n.oid = t.relnamespace
          WHERE n.nspname = $1 AND NOT ix.indisvalid
          ORDER BY 1, 2, 3",
    )
    .bind(schema)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(kind, table, name)| PendingObject {
            kind: match kind.as_str() {
                "foreign_key" => ObjectKind::ForeignKey,
                "check" => ObjectKind::Check,
                _ => ObjectKind::Index,
            },
            table,
            name,
        })
        .collect())
}

async fn cron_available(conn: &mut PgConnection) -> Result<bool> {
    Ok(
        sqlx::query_scalar("SELECT to_regclass('cron.job') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?,
    )
}

/// This database's jobs, as `cron.schedule` records them
/// ([`crate::generator::sql::versions::cron_job_database`]).
async fn read_cron_jobs(conn: &mut PgConnection) -> Result<Vec<DbCronJob>> {
    if !cron_available(conn).await? {
        return Ok(Vec::new());
    }
    let sql = format!(
        "SELECT jobname::text, schedule::text, command::text, active
         FROM cron.job
         WHERE database = {}
         ORDER BY jobname, jobid",
        crate::generator::sql::versions::cron_job_database()
    );
    let rows: Vec<(Option<String>, String, String, bool)> =
        sqlx::query_as(&sql).fetch_all(&mut *conn).await?;
    Ok(rows
        .into_iter()
        .map(|(name, schedule, command, active)| DbCronJob {
            name: name.unwrap_or_default(),
            schedule,
            command,
            active,
        })
        .collect())
}

async fn read_rls_attributes(
    conn: &mut PgConnection,
    schemas: &[String],
) -> Result<Vec<DbRlsAttributes>> {
    let rows: Vec<(String, String, bool, bool, String)> = sqlx::query_as(
        "SELECT n.nspname::text, c.relname::text, c.relrowsecurity, c.relforcerowsecurity,
                c.relreplident::text
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         LEFT JOIN pg_depend d ON d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e'
         WHERE n.nspname = ANY($1) AND c.relkind IN ('r', 'p') AND d.objid IS NULL
         ORDER BY n.nspname, c.relname",
    )
    .bind(schemas)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(schema, table, enabled, forced, replica_identity)| DbRlsAttributes {
                schema,
                table,
                enabled,
                forced,
                replica_identity,
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_project_schema_is_swept_once_even_when_it_is_an_engine_schema() {
        let swept = swept_schemas("public");
        assert_eq!(swept[0], "public");
        assert_eq!(swept.len(), 1 + ENGINE_SCHEMAS.len());

        let swept = swept_schemas("api");
        assert_eq!(swept.iter().filter(|s| *s == "api").count(), 1);
        assert_eq!(swept.len(), ENGINE_SCHEMAS.len());
    }
}
