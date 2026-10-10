use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::{Executor, PgConnection, PgPool, Postgres, Transaction};

// Internal bookkeeping lives in a dedicated schema so it never appears in the
// user's `public` schema and is never touched by introspection or diffs.
const SCHEMA: &str = "_supatype";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationListItem {
    pub id: i32,
    pub name: String,
    pub hash: String,
    pub applied_at: String,
    pub rolled_back: bool,
    pub engine_version: String,
    pub status: String,
    pub schema_sources_manifest: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RollbackResult {
    pub status: String,
    pub name: String,
    pub message: String,
    pub restored_migration_name: Option<String>,
    pub schema_sources_manifest: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_sources_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationRecord {
    pub id: i32,
    pub name: String,
    pub hash: String,
    pub applied_at: String,
    pub rolled_back: bool,
    pub engine_version: String,
    pub schema_snapshot: Option<serde_json::Value>,
    pub status: String,
    pub error_message: Option<String>,
}

pub fn create_internal_schema_sql() -> &'static str {
    "CREATE SCHEMA IF NOT EXISTS _supatype"
}

pub fn create_migrations_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.migrations (
    id                      SERIAL PRIMARY KEY,
    name                    TEXT NOT NULL UNIQUE,
    hash                    TEXT NOT NULL,
    applied_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rolled_back             BOOLEAN NOT NULL DEFAULT FALSE,
    rolled_back_at          TIMESTAMPTZ,
    engine_version          TEXT NOT NULL,
    schema_snapshot         JSONB,
    admin_config            JSONB,
    sql_up                  TEXT,
    sql_down                TEXT,
    schema_sources          BYTEA,
    schema_sources_manifest JSONB,
    status                  TEXT NOT NULL DEFAULT 'applied',
    error_message           TEXT
)"#
    )
}

pub fn create_schema_state_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.schema_state (
    id               INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    db_state         JSONB NOT NULL,
    captured_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    engine_version   TEXT NOT NULL
)"#
    )
}

/// Studio membership: who may use the admin UI, and with what capability set.
///
/// Deliberately NOT a JWT claim and NOT in the `public` schema: `_supatype` is
/// absent from PGRST_DB_SCHEMAS, so nothing the developer's app or API surface
/// does can read or write it. Studio roles are Supatype's namespace; the
/// developer's own app roles live in their claims/tables and are unrelated.
///
/// A row identifies its holder by exactly one of two identities:
///
/// * `user_id`: a project `auth.users` id. How self-host grants access, and how
///   a project's own users are admitted in either host.
/// * `platform_user_id`: a Supatype Cloud account. Cloud callers are platform
///   accounts, not project users, so they cannot be looked up by `user_id`.
///
/// Keeping both in one table means "who may use Studio for this project" has a
/// single answer wherever the project runs, and the grants survive an export from
/// cloud to self-host. The CHECK makes the identity space of every row explicit,
/// so neither lookup can ever match a row it was not meant to.
pub fn create_studio_members_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.studio_members (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID UNIQUE,
    platform_user_id  UUID UNIQUE,
    role              TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT studio_members_one_identity
        CHECK (num_nonnulls(user_id, platform_user_id) = 1)
)"#
    )
}

/// Audit trail for Studio membership changes and elevated data access.
///
/// Access-control changes need a durable record, not a log line that rotates
/// away: "who gave this person admin, and when" has to be answerable months
/// later. Lives in `_supatype` for the same reason `studio_members` does:
/// nothing reachable through the data plane can read or rewrite it.
///
/// `actor_id` is nullable because a change can come from the CLI against the
/// database directly, where there is no signed-in actor to attribute it to.
/// `target_id` is nullable because not every audited event is *about* someone:
/// an elevated request has an actor and no target. `detail` carries the shape of
/// whatever the action was: the method and path of an elevated request, say.
pub fn create_studio_audit_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.studio_audit (
    id          BIGSERIAL PRIMARY KEY,
    actor_id    UUID,
    target_id   UUID,
    action      TEXT NOT NULL,
    role        TEXT,
    detail      JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
)"#
    )
}

/// Bring an audit table created for membership changes only up to the shape that
/// also records elevated access.
pub fn ensure_studio_audit_columns_sql() -> String {
    format!(
        r#"DO $$
BEGIN
    IF to_regclass('{SCHEMA}.studio_audit') IS NULL THEN
        RETURN;
    END IF;
    ALTER TABLE {SCHEMA}.studio_audit ADD COLUMN IF NOT EXISTS detail JSONB;
    ALTER TABLE {SCHEMA}.studio_audit ALTER COLUMN target_id DROP NOT NULL;
END $$"#
    )
}

/// Migrate a `studio_members` table created before cloud accounts could hold a
/// membership: `user_id` was the primary key and the only identity.
///
/// Written as a guarded DO block rather than plain `ALTER`s because the target
/// shape has to be reached from either starting point (the pre-cloud table or
/// the current one), and a push must never fail on a table that is already right.
pub fn ensure_studio_members_platform_identity_sql() -> String {
    format!(
        r#"DO $$
BEGIN
    IF to_regclass('{SCHEMA}.studio_members') IS NULL THEN
        RETURN;
    END IF;

    ALTER TABLE {SCHEMA}.studio_members
        ADD COLUMN IF NOT EXISTS platform_user_id UUID;

    -- `user_id` becomes optional, so the primary key has to move off it.
    IF EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = '{SCHEMA}.studio_members'::regclass
           AND contype = 'p'
           AND conkey = ARRAY[(SELECT attnum FROM pg_attribute
                                WHERE attrelid = '{SCHEMA}.studio_members'::regclass
                                  AND attname = 'user_id')]::smallint[]
    ) THEN
        ALTER TABLE {SCHEMA}.studio_members DROP CONSTRAINT studio_members_pkey;
        ALTER TABLE {SCHEMA}.studio_members
            ADD COLUMN IF NOT EXISTS id UUID NOT NULL DEFAULT gen_random_uuid();
        ALTER TABLE {SCHEMA}.studio_members ADD PRIMARY KEY (id);
        ALTER TABLE {SCHEMA}.studio_members ALTER COLUMN user_id DROP NOT NULL;
        ALTER TABLE {SCHEMA}.studio_members ADD CONSTRAINT studio_members_user_id_key
            UNIQUE (user_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = '{SCHEMA}.studio_members'::regclass
           AND conname = 'studio_members_platform_user_id_key'
    ) THEN
        ALTER TABLE {SCHEMA}.studio_members
            ADD CONSTRAINT studio_members_platform_user_id_key UNIQUE (platform_user_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = '{SCHEMA}.studio_members'::regclass
           AND conname = 'studio_members_one_identity'
    ) THEN
        ALTER TABLE {SCHEMA}.studio_members
            ADD CONSTRAINT studio_members_one_identity
            CHECK (num_nonnulls(user_id, platform_user_id) = 1);
    END IF;
END $$"#
    )
}

/// Seed `studio_members` from the admin roles that used to live in
/// `app_metadata`.
///
/// Studio access moved out of JWT claims and into this table. Without a seed,
/// the first push after that change locks every existing admin out of their own
/// Studio: their claim no longer grants anything and they have no membership
/// row. Runs only while the table is empty, so it cannot resurrect access that
/// was deliberately revoked later.
///
/// Only the roles that actually admitted anyone are carried over, and they all
/// become the Studio role `admin`:
///
/// * `app_metadata.role` was the developer's own namespace, so it holds arbitrary
///   application roles: `moderator`, `staff`, whatever their app needed. Those
///   never granted Studio access (`STUDIO_ADMIN_ROLES` did, defaulting to `admin`
///   and `supatype_admin`), so seeding them would *hand out* access rather than
///   preserve it.
/// * A Studio role has to be one the deployment understands, or the capability
///   check refuses it. Copying claim strings verbatim would seed rows that deny.
///
/// A deployment that customised `STUDIO_ADMIN_ROLES` seeds nobody and falls
/// through to the CLI's first-admin prompt, which is the right recovery, better
/// than guessing which app roles were meant to be administrators.
pub fn seed_studio_members_from_claims_sql() -> String {
    format!(
        r#"DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM {SCHEMA}.studio_members) THEN
        IF EXISTS (
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'auth' AND table_name = 'users'
        ) THEN
            INSERT INTO {SCHEMA}.studio_members (user_id, platform_user_id, role)
            SELECT id, NULL, 'admin'
              FROM auth.users
             WHERE raw_app_meta_data->>'role' IN ('admin', 'supatype_admin')
            ON CONFLICT (user_id) DO NOTHING;
        END IF;
    END IF;
END $$"#
    )
}

pub fn ensure_migrations_admin_config_column_sql() -> String {
    format!("ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS admin_config JSONB")
}

pub fn ensure_migrations_sql_down_column_sql() -> String {
    format!("ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS sql_down TEXT")
}

pub fn ensure_migrations_sql_up_column_sql() -> String {
    format!("ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS sql_up TEXT")
}

pub fn ensure_migrations_schema_sources_column_sql() -> String {
    format!(
        "ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS schema_sources BYTEA;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS schema_sources_manifest JSONB"
    )
}

/// Repair a `migrations` table that predates this engine's layout.
///
/// [`create_migrations_table_sql`] uses CREATE TABLE IF NOT EXISTS, so a table
/// created by anything else (e.g. an older engine, or a provisioner that
/// pre-created it) silently wins and every insert then fails on a missing
/// column. These columns are NOT NULL at creation time; added after the fact
/// they must be nullable, which is harmless because every insert supplies them.
pub fn ensure_migrations_core_columns_sql() -> String {
    format!(
        "ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS hash TEXT;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS engine_version TEXT;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW();\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS rolled_back BOOLEAN NOT NULL DEFAULT FALSE;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS rolled_back_at TIMESTAMPTZ;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS schema_snapshot JSONB"
    )
}

/// A foreign `migrations` table may carry NOT NULL columns this engine never
/// writes (a legacy layout used `version`, `sql`, `checksum`), and may lack the
/// UNIQUE constraint on `name` that failed-migration upserts rely on. Relax the
/// columns we don't own and restore the constraint so inserts can succeed.
pub fn ensure_migrations_writable_sql() -> String {
    format!(
        "DO $$
DECLARE
  col RECORD;
BEGIN
  FOR col IN
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema = '{SCHEMA}'
      AND table_name = 'migrations'
      AND is_nullable = 'NO'
      AND column_default IS NULL
      AND column_name <> ALL (ARRAY['id', 'name', 'hash', 'engine_version'])
  LOOP
    EXECUTE format('ALTER TABLE {SCHEMA}.migrations ALTER COLUMN %I DROP NOT NULL', col.column_name);
  END LOOP;

  IF NOT EXISTS (
    SELECT 1
    FROM pg_index i
    JOIN pg_class c ON c.oid = i.indrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY (i.indkey)
    WHERE n.nspname = '{SCHEMA}'
      AND c.relname = 'migrations'
      AND i.indisunique
      AND i.indnatts = 1
      AND a.attname = 'name'
  ) THEN
    EXECUTE 'CREATE UNIQUE INDEX migrations_name_key ON {SCHEMA}.migrations (name)';
  END IF;
END $$"
    )
}

pub fn ensure_all_migration_columns_sql() -> Vec<String> {
    vec![
        ensure_migrations_core_columns_sql(),
        ensure_migrations_writable_sql(),
        ensure_migrations_admin_config_column_sql(),
        ensure_migrations_sql_up_column_sql(),
        ensure_migrations_status_columns_sql(),
        ensure_migrations_sql_down_column_sql(),
        ensure_migrations_schema_sources_column_sql(),
    ]
}

pub fn ensure_migrations_status_columns_sql() -> String {
    format!(
        "ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'applied';\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS error_message TEXT"
    )
}

pub fn ensure_schema_state_studio_columns_sql() -> String {
    format!(
        "ALTER TABLE {SCHEMA}.schema_state ADD COLUMN IF NOT EXISTS ast_snapshot JSONB;\
         ALTER TABLE {SCHEMA}.schema_state ADD COLUMN IF NOT EXISTS admin_config JSONB"
    )
}

/// What this database can actually enforce, as opposed to what the schema declares.
pub fn ensure_schema_state_capabilities_column_sql() -> String {
    format!("ALTER TABLE {SCHEMA}.schema_state ADD COLUMN IF NOT EXISTS capabilities JSONB")
}

/// Which project schema this database belongs to. See [`assert_project_schema`].
pub fn ensure_schema_state_project_schema_column_sql() -> String {
    format!("ALTER TABLE {SCHEMA}.schema_state ADD COLUMN IF NOT EXISTS project_schema TEXT")
}

/// Record the project schema of a `schema_state` row an engine from before the column wrote, from
/// the schema its own snapshot names. Without it such a row passed [`assert_project_schema`] for
/// any schema, and the first push to arrive, whichever project it was for, claimed the database.
pub fn backfill_schema_state_project_schema_sql() -> String {
    format!(
        "UPDATE {SCHEMA}.schema_state SET project_schema = db_state->>'schema' \
         WHERE project_schema IS NULL AND COALESCE(db_state->>'schema', '') <> ''"
    )
}

/// Refuse to run a command for one project against a database that holds another.
///
/// `_supatype.migrations` has no project column, `schema_state` is one row, and the publishing cron
/// jobs are named with no schema, so two projects in one database share a history they should not:
/// the second one's push loads the first one's snapshot as "the previous schema" and diffs against
/// it. Cloud runs one Postgres per project; this makes the same shape explicit for self-host rather
/// than letting it fail in a way that names nothing. Every command that reads the project asks
/// (`push::read_state` does, inside the writer's transaction when there is one), not only push and
/// adopt: a rebaseline for another schema rewrote this project's ledger (E14b).
///
/// A database with no recorded schema (a fresh one) passes, and [`save_schema_state`] records the
/// schema at the end of that push. One written by an engine from before this column has its schema
/// recorded from its snapshot by the bootstrap ([`backfill_schema_state_project_schema_sql`]), and
/// read from the snapshot here too: the bootstrap runs only when its version changes, so a row
/// emptied since is not filled again.
pub async fn assert_project_schema(pool: &PgPool, schema: &str) -> Result<()> {
    assert_project_schema_on(&mut *pool.acquire().await?, schema).await
}

/// [`assert_project_schema`] on `conn`, inside its transaction when it has one. Asks the catalog
/// first, so a database no engine has written to passes without a failed statement that would
/// abort that transaction.
pub async fn assert_project_schema_on(conn: &mut PgConnection, schema: &str) -> Result<()> {
    let present: bool = sqlx::query_scalar(&format!(
        "SELECT to_regclass('{SCHEMA}.schema_state') IS NOT NULL"
    ))
    .fetch_one(&mut *conn)
    .await?;
    if !present {
        return Ok(());
    }
    // `to_jsonb` reads `project_schema` whether or not an older engine's table has the column.
    let sql = format!(
        "SELECT COALESCE(to_jsonb(s) ->> 'project_schema', NULLIF(s.db_state ->> 'schema', '')) \
         FROM {SCHEMA}.schema_state s WHERE s.id = 1"
    );
    let recorded: Option<Option<String>> =
        sqlx::query_scalar(&sql).fetch_optional(&mut *conn).await?;
    match recorded.flatten() {
        Some(existing) if existing != schema => anyhow::bail!(
            "This database already holds the project schema \"{existing}\", not \"{schema}\". \
             Supatype runs one project per database: point this project at a database of its own, \
             or set pg_schema back to \"{existing}\"."
        ),
        _ => Ok(()),
    }
}

/// Record how field-level access is enforced here, from a live probe rather than an
/// assumption.
///
/// Studio and `explain` need to state which mechanism is in force, and a value derived
/// on demand is a value that can disagree with the push that actually applied the
/// schema. Writing it makes the tier a recorded fact.
///
/// A database with field rules cannot reach here without the extension (the migration
/// refuses to apply first), so `unenforced` means only "no field rules in this schema".
/// That distinction is the point: a deployment that quietly stopped enforcing must be
/// visible, not inferred.
pub async fn record_field_enforcement(
    conn: &mut sqlx::PgConnection,
    labelled_columns: usize,
) -> Result<()> {
    let extension: Option<String> =
        sqlx::query_scalar("SELECT extversion FROM pg_extension WHERE extname = $1")
            .bind(crate::generator::sql::rls::MASK_EXTENSION)
            .fetch_optional(&mut *conn)
            .await?
            .flatten();

    // Tier 2 is real enforcement, not a failure, but only if the views are actually there. Asking
    // the database rather than assuming: a schema that *should* have views and does not is exactly
    // the state worth recording as broken.
    let views_present: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_class c            JOIN pg_namespace n ON n.oid = c.relnamespace           WHERE n.nspname = $1 AND c.relkind = 'v')",
    )
    .bind(crate::generator::sql::field_views::VIEW_SCHEMA)
    .fetch_one(&mut *conn)
    .await?;

    let tier = if labelled_columns == 0 {
        "unenforced"
    } else if extension.is_some() {
        "extension"
    } else if views_present {
        "views"
    } else {
        // The extension is gone and no views stand in for it. Reachable by dropping the extension
        // under a tier-1 database, and worth recording honestly rather than asserting.
        "broken"
    };

    let record = serde_json::json!({
        "fieldMasking": {
            "tier": tier,
            "extension": crate::generator::sql::rls::MASK_EXTENSION,
            "extensionVersion": extension,
            "labelledColumns": labelled_columns,
        }
    });

    // Merged rather than replaced, so a future capability recorded elsewhere survives.
    let sql = format!(
        "UPDATE {SCHEMA}.schema_state \
         SET capabilities = COALESCE(capabilities, '{{}}'::jsonb) || $1::jsonb \
         WHERE id = 1"
    );
    sqlx::query(&sql).bind(record).execute(&mut *conn).await?;

    Ok(())
}

/// How many columns the schema declares field rules for: the number recorded alongside
/// the tier, and what makes "no field rules" distinguishable from "rules that stopped
/// being enforced".
pub fn labelled_column_count(ast: &crate::parser::ast::SchemaAst) -> usize {
    ast.models
        .iter()
        .map(|model| {
            crate::parser::accessors::platform_access(model)
                .fields
                .values()
                .filter(|rules| rules.read.is_some() || rules.write.is_some())
                .count()
        })
        .sum()
}

fn snapshot_hash(schema_snapshot: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(schema_snapshot.to_string().as_bytes());
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// The schema as it was at the last push, decoded. History, not a cache of the database: what
/// tells a rename apart from a drop and an add.
pub async fn load_latest_schema_ast(
    conn: &mut PgConnection,
) -> Result<Option<crate::parser::ast::SchemaAst>> {
    Ok(load_latest_schema_snapshot(conn)
        .await?
        .and_then(|v| serde_json::from_value(v).ok()))
}

/// Latest applied schema AST snapshot (for kind-aware diffs when PG types are unchanged), read on
/// the caller's connection: inside its transaction when it has one, and never a second connection
/// from a pool the caller may be holding the only one of.
///
/// `None` where nothing records one: no push yet, or tables from before the columns. A read that
/// fails for any other reason (a lock it gave up waiting for, a lost connection) is an error, not
/// "no earlier schema": a push decided without its last schema guesses renames and skips the
/// upgrade check.
pub async fn load_latest_schema_snapshot(
    conn: &mut PgConnection,
) -> Result<Option<serde_json::Value>> {
    if has_columns(
        conn,
        "migrations",
        &["schema_snapshot", "rolled_back", "applied_at"],
    )
    .await?
    {
        let sql = format!(
            "SELECT schema_snapshot FROM {SCHEMA}.migrations \
             WHERE rolled_back = false AND schema_snapshot IS NOT NULL \
             ORDER BY applied_at DESC LIMIT 1"
        );
        if let Some(v) = sqlx::query_scalar(&sql).fetch_optional(&mut *conn).await? {
            return Ok(Some(v));
        }
    }
    if !has_columns(conn, "schema_state", &["id", "ast_snapshot"]).await? {
        return Ok(None);
    }
    let fallback = format!(
        "SELECT ast_snapshot FROM {SCHEMA}.schema_state WHERE id = 1 AND ast_snapshot IS NOT NULL"
    );
    Ok(sqlx::query_scalar(&fallback)
        .fetch_optional(&mut *conn)
        .await?)
}

/// Whether `_supatype.<table>` exists with every one of `columns`. Asked of the catalog, so a
/// table an older engine left without them is "nothing recorded" rather than an error that would
/// abort the caller's transaction.
async fn has_columns(conn: &mut PgConnection, table: &str, columns: &[&str]) -> Result<bool> {
    let found: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2 AND column_name = ANY($3)",
    )
    .bind(SCHEMA)
    .bind(table)
    .bind(columns)
    .fetch_one(&mut *conn)
    .await?;
    Ok(found == columns.len() as i64)
}

/// The SQLSTATE of a database error.
pub(crate) fn sql_state(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
}

/// Latest Studio admin config from migration history or schema_state fallback.
pub async fn load_latest_admin_config(pool: &PgPool) -> Option<serde_json::Value> {
    let sql = format!(
        "SELECT admin_config FROM {SCHEMA}.migrations \
         WHERE rolled_back = false AND admin_config IS NOT NULL \
         ORDER BY applied_at DESC LIMIT 1"
    );
    if let Ok(Some((v,))) = sqlx::query_as::<_, (serde_json::Value,)>(&sql)
        .fetch_optional(pool)
        .await
    {
        return Some(v);
    }

    let fallback = format!(
        "SELECT admin_config FROM {SCHEMA}.schema_state WHERE id = 1 AND admin_config IS NOT NULL"
    );
    sqlx::query_as::<_, (serde_json::Value,)>(&fallback)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|(v,)| v)
}

/// Printed when `--no-cache` is passed to push or adopt, which no longer read a cache at all.
///
/// Both used to diff against the snapshot the last push wrote, which cannot see anything changed
/// outside Supatype since: a table that lost its ownership marker, a column dropped by hand. They
/// read the database live now, so the flag has nothing left to bypass. It is still accepted, for
/// one release, so a script that passes it keeps working.
pub const NO_CACHE_NOTICE: &str = "--no-cache is no longer needed: push and adopt always read the \
     database live. The flag does nothing and will be removed in a future release.";

pub async fn list_migrations(pool: &PgPool) -> Result<Vec<MigrationRecord>> {
    let sql = format!(
        "SELECT id, name, hash, applied_at::TEXT, rolled_back, engine_version, schema_snapshot, \
         COALESCE(status, 'applied'), error_message \
         FROM {SCHEMA}.migrations ORDER BY applied_at ASC"
    );
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        i32,
        String,
        String,
        String,
        bool,
        String,
        Option<serde_json::Value>,
        String,
        Option<String>,
    )> = sqlx::query_as(&sql).fetch_all(pool).await?;

    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                name,
                hash,
                applied_at,
                rolled_back,
                engine_version,
                schema_snapshot,
                status,
                error_message,
            )| {
                MigrationRecord {
                    id,
                    name,
                    hash,
                    applied_at,
                    rolled_back,
                    engine_version,
                    schema_snapshot,
                    status,
                    error_message,
                }
            },
        )
        .collect())
}

/// Record what the database looks like after a push or an adoption.
///
/// Nothing diffs against `db_state` any more: push and adopt introspect live. It is still written
/// because this is the statement that creates the `schema_state` row, and the Studio metadata and
/// capability writers are all `UPDATE ... WHERE id = 1` against it.
pub async fn save_schema_state<'e, E>(
    executor: E,
    state: &crate::state::database_state::DatabaseState,
) -> Result<()>
where
    E: Executor<'e, Database = Postgres>,
{
    let sql = format!(
        "INSERT INTO {SCHEMA}.schema_state (id, db_state, engine_version, project_schema)
         VALUES (1, $1, $2, $3)
         ON CONFLICT (id) DO UPDATE SET db_state = EXCLUDED.db_state,
             captured_at = NOW(), engine_version = EXCLUDED.engine_version,
             project_schema = EXCLUDED.project_schema"
    );
    sqlx::query(&sql)
        .bind(serde_json::to_value(state)?)
        .bind(env!("ENGINE_VERSION"))
        .bind(&state.schema)
        .execute(executor)
        .await?;
    Ok(())
}

pub fn insert_migration_sql() -> String {
    format!(
        "INSERT INTO {SCHEMA}.migrations \
         (name, hash, engine_version, schema_snapshot, admin_config, sql_up, sql_down, schema_sources, schema_sources_manifest) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id"
    )
}

/// What a migration row records beside its forward statements. `sql_up` and `sql_down` hold
/// statements only, no `BEGIN`/`COMMIT`: whoever runs them owns the transaction, as
/// [`apply_rollback`] does.
#[derive(Default)]
pub struct AppliedMigrationSources {
    pub sql_down: Option<String>,
    pub schema_sources: Option<Vec<u8>>,
    pub schema_sources_manifest: Option<serde_json::Value>,
}

/// Record a successful migration row (same shape as [`insert_migration_sql`]). Returns the row's
/// id, which the ledger points its rows at.
pub async fn insert_applied_migration<'e, E>(
    executor: E,
    name: &str,
    hash: &str,
    schema_snapshot: Option<serde_json::Value>,
    admin_config: Option<serde_json::Value>,
    sql_up: &str,
    sources: &AppliedMigrationSources,
) -> Result<i32>
where
    E: Executor<'e, Database = Postgres>,
{
    let sql = insert_migration_sql();
    let id = sqlx::query_scalar(&sql)
        .bind(name)
        .bind(hash)
        .bind(env!("ENGINE_VERSION"))
        .bind(schema_snapshot)
        .bind(admin_config)
        .bind(sql_up)
        .bind(sources.sql_down.as_deref())
        .bind(sources.schema_sources.as_deref())
        .bind(sources.schema_sources_manifest.as_ref())
        .fetch_one(executor)
        .await?;
    Ok(id)
}

/// Updates `admin_config` and `schema_snapshot` on the latest non-rolled-back migration row.
/// Returns the number of rows updated (0 if there are no applicable migration records).
pub async fn update_latest_migration_admin(
    pool: impl sqlx::PgExecutor<'_>,
    admin_config: &serde_json::Value,
    schema_snapshot: &serde_json::Value,
) -> Result<u64> {
    let sql = format!(
        "UPDATE {SCHEMA}.migrations SET admin_config = $1, schema_snapshot = $2 \
         WHERE id = (SELECT MAX(id) FROM {SCHEMA}.migrations WHERE rolled_back = FALSE)"
    );
    let res = sqlx::query(&sql)
        .bind(admin_config)
        .bind(schema_snapshot)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// When push finds no DDL diff: refresh Studio metadata on the latest migration row, or
/// record a one-time `initial_*` baseline when no active migration exists yet.
pub async fn refresh_metadata_on_up_to_date_push(
    conn: &mut sqlx::PgConnection,
    admin_config: &serde_json::Value,
    schema_snapshot: &serde_json::Value,
) -> Result<()> {
    save_studio_metadata_if_present(&mut *conn, admin_config, schema_snapshot).await?;

    let n = update_latest_migration_admin(&mut *conn, admin_config, schema_snapshot).await?;
    if n > 0 {
        return Ok(());
    }

    let migration_name = format!("initial_{}", chrono::Utc::now().format("%Y%m%d_%H%M%S"));
    let hash = snapshot_hash(schema_snapshot);
    sqlx::query(&insert_migration_sql())
        .bind(&migration_name)
        .bind(&hash)
        .bind(env!("ENGINE_VERSION"))
        .bind(schema_snapshot)
        .bind(admin_config)
        .bind(None::<String>)
        .bind(None::<String>)
        .bind(None::<Vec<u8>>)
        .bind(None::<serde_json::Value>)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Persist Studio metadata on `schema_state` when a cached DB snapshot row already exists.
pub async fn save_studio_metadata_if_present(
    pool: impl sqlx::PgExecutor<'_>,
    admin_config: &serde_json::Value,
    schema_snapshot: &serde_json::Value,
) -> Result<()> {
    let sql = format!(
        "UPDATE {SCHEMA}.schema_state SET ast_snapshot = $1, admin_config = $2 WHERE id = 1"
    );
    sqlx::query(&sql)
        .bind(schema_snapshot)
        .bind(admin_config)
        .execute(pool)
        .await?;
    Ok(())
}

/// Record a failed push, never touching a row already recorded: under `$1` when no migration has
/// that name, and nothing otherwise (`ON CONFLICT DO NOTHING`). It once took the name over with
/// `ON CONFLICT (name) DO UPDATE SET status = 'failed'`, marking an applied migration failed, so a
/// rollback undid the push before it instead (E10).
pub fn insert_failed_migration_sql() -> String {
    format!(
        "INSERT INTO {SCHEMA}.migrations \
         (name, hash, engine_version, sql_up, status, error_message) \
         VALUES ($1, $2, $3, $4, 'failed', $5) \
         ON CONFLICT (name) DO NOTHING"
    )
}

/// Record a failed push under `name`, or, when a migration already has that name, under
/// `<name>.failed.<time>`: a name of its own, so the failure is kept and the earlier row is not
/// changed.
pub async fn record_failed_migration(
    pool: &PgPool,
    name: &str,
    hash: &str,
    sql_up: &str,
    error: &str,
) -> Result<()> {
    let unique = format!(
        "{name}.failed.{}",
        chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f")
    );
    for name in [name, unique.as_str()] {
        let recorded = sqlx::query(&insert_failed_migration_sql())
            .bind(name)
            .bind(hash)
            .bind(env!("ENGINE_VERSION"))
            .bind(sql_up)
            .bind(error)
            .execute(pool)
            .await?;
        if recorded.rows_affected() == 1 {
            return Ok(());
        }
    }
    anyhow::bail!("a migration named {unique} already exists")
}

/// Refuse a push named as a migration already recorded here, applied, failed or rolled back:
/// history is looked up by name (`migrations --name`), so two rows cannot share one. Asked before
/// planning, and again under the engine's lock before anything is written.
pub async fn assert_name_unused<'e, E>(executor: E, name: &str) -> Result<()>
where
    E: Executor<'e, Database = Postgres>,
{
    let sql = format!(
        "SELECT status || CASE WHEN rolled_back THEN ', rolled back' ELSE '' END \
         FROM {SCHEMA}.migrations WHERE name = $1"
    );
    let found: Option<String> = match sqlx::query_scalar(&sql)
        .bind(name)
        .fetch_optional(executor)
        .await
    {
        Ok(found) => found,
        // No history yet: every name is free.
        Err(e) if sql_state(&e).as_deref() == Some("42P01") => None,
        Err(e) => return Err(e).context("look up the migration name"),
    };
    match found {
        Some(status) => anyhow::bail!(
            "A migration named \"{name}\" is already recorded here ({status}), so nothing was \
             applied. Give this push a name of its own, or leave the name out for a generated one."
        ),
        None => Ok(()),
    }
}

/// Roll back an in-flight push transaction and best-effort record a failed migration row.
pub async fn rollback_push_tx(
    tx: Transaction<'_, Postgres>,
    pool: &PgPool,
    migration_name: &str,
    hash: &str,
    sql_up: &str,
    err: &str,
) {
    let _ = tx.rollback().await;
    if let Err(record_err) = record_failed_migration(pool, migration_name, hash, sql_up, err).await
    {
        eprintln!("Warning: could not record failed migration: {record_err}");
    }
}

pub async fn list_migrations_summary(pool: &PgPool) -> Result<Vec<MigrationListItem>> {
    type MigrationSummaryRow = (
        i32,
        String,
        String,
        String,
        bool,
        String,
        String,
        Option<serde_json::Value>,
    );

    let sql = format!(
        "SELECT id, name, hash, applied_at::TEXT, rolled_back, engine_version, \
         COALESCE(status, 'applied'), schema_sources_manifest \
         FROM {SCHEMA}.migrations ORDER BY applied_at DESC"
    );
    let rows: Vec<MigrationSummaryRow> = sqlx::query_as(&sql).fetch_all(pool).await?;

    Ok(rows
        .into_iter()
        .map(
            |(id, name, hash, applied_at, rolled_back, engine_version, status, manifest)| {
                MigrationListItem {
                    id,
                    name,
                    hash,
                    applied_at,
                    rolled_back,
                    engine_version,
                    status,
                    schema_sources_manifest: manifest,
                }
            },
        )
        .collect())
}

struct LatestMigrationRow {
    id: i32,
    name: String,
    sql_down: Option<String>,
}

async fn load_latest_applied_migration(
    conn: &mut PgConnection,
) -> Result<Option<LatestMigrationRow>> {
    let sql = format!(
        "SELECT id, name, sql_down FROM {SCHEMA}.migrations \
         WHERE rolled_back = false AND COALESCE(status, 'applied') = 'applied' \
         ORDER BY applied_at DESC LIMIT 1"
    );
    Ok(sqlx::query_as::<_, (i32, String, Option<String>)>(&sql)
        .fetch_optional(&mut *conn)
        .await?
        .map(|(id, name, sql_down)| LatestMigrationRow { id, name, sql_down }))
}

struct PriorMigrationRow {
    name: String,
    schema_snapshot: Option<serde_json::Value>,
    admin_config: Option<serde_json::Value>,
    schema_sources: Option<Vec<u8>>,
    schema_sources_manifest: Option<serde_json::Value>,
}

async fn load_prior_applied_migration(
    conn: &mut PgConnection,
    exclude_id: i32,
) -> Result<Option<PriorMigrationRow>> {
    let sql = format!(
        "SELECT name, schema_snapshot, admin_config, schema_sources, schema_sources_manifest \
         FROM {SCHEMA}.migrations \
         WHERE rolled_back = false AND COALESCE(status, 'applied') = 'applied' AND id <> $1 \
         ORDER BY applied_at DESC LIMIT 1"
    );
    Ok(sqlx::query_as::<
        _,
        (
            String,
            Option<serde_json::Value>,
            Option<serde_json::Value>,
            Option<Vec<u8>>,
            Option<serde_json::Value>,
        ),
    >(&sql)
    .bind(exclude_id)
    .fetch_optional(&mut *conn)
    .await?
    .map(
        |(name, schema_snapshot, admin_config, schema_sources, schema_sources_manifest)| {
            PriorMigrationRow {
                name,
                schema_snapshot,
                admin_config,
                schema_sources,
                schema_sources_manifest,
            }
        },
    ))
}

/// `sql` without its top-level `BEGIN`/`COMMIT` statements. An engine from before Phase 4.0 stored
/// `sql_down` as a script of its own, wrapped in `BEGIN;`…`COMMIT;`; run inside the rollback's
/// transaction, that `COMMIT` ended it early, so the history and ledger updates after it ran
/// outside any transaction and a failure there left the objects rolled back and the record not.
/// Statements inside a function body or a `DO` block are not top-level and are kept.
fn without_transaction_control(sql: &str) -> String {
    crate::desired::statements::split_statements(sql)
        .into_iter()
        .filter(|statement| {
            let head = crate::desired::statements::head(statement)
                .trim_end()
                .trim_end_matches(';')
                .trim_end()
                .to_ascii_uppercase();
            let head = head.split_whitespace().collect::<Vec<_>>().join(" ");
            !matches!(
                head.as_str(),
                "BEGIN"
                    | "BEGIN TRANSACTION"
                    | "BEGIN WORK"
                    | "START TRANSACTION"
                    | "COMMIT"
                    | "COMMIT TRANSACTION"
                    | "COMMIT WORK"
                    | "END"
                    | "END TRANSACTION"
            )
        })
        .collect()
}

/// Roll back the latest applied migration: its `sql_down`, the ledger rows it wrote, its history
/// row and Studio's metadata, in one writer's transaction under the engine's lock, refused while a
/// push, adopt or rebaseline holds it.
///
/// Every statement runs on that transaction's connection, the lock taken before the migration to
/// undo is chosen, so it is still the latest when it is undone. The choice, the project check and
/// the `schema_state` repairs once ran on other pool sessions, which autocommitted outside the lock
/// and committed even when the rollback was then refused (E36).
pub async fn apply_rollback(pool: &PgPool, schema: &str) -> Result<RollbackResult> {
    bootstrap_internal_state(pool).await?;
    let mut tx = crate::push::begin_writer(pool).await?;
    // The history is one project's; rolling it back from another would undo that project's
    // migration and record this schema as the database's.
    assert_project_schema_on(&mut tx, schema).await?;
    let latest = load_latest_applied_migration(&mut tx)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("no_applied_migration: No applied migration to roll back")
        })?;
    let sql_down = latest
        .sql_down
        .clone()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("no_rollback_sql: Migration has no rollback SQL (metadata-only push?)")
        })?;
    let prior = load_prior_applied_migration(&mut tx, latest.id).await?;
    let left = undo_migration(&mut tx, latest.id, &sql_down, schema).await?;
    restore_studio_metadata(&mut tx, prior.as_ref()).await?;
    let new_state = crate::introspector::introspect_connection(&mut tx, schema).await?;
    save_schema_state(&mut *tx, &new_state).await?;
    tx.commit().await?;
    Ok(rolled_back(&latest.name, prior, &left))
}

/// Run `sql_down` for migration `id`, put the ledger back as it was before it and mark it rolled
/// back. Returns the objects left as they are: released or recorded again since the push, so no
/// longer the push's to undo.
async fn undo_migration(
    tx: &mut PgConnection,
    id: i32,
    sql_down: &str,
    schema: &str,
) -> Result<Vec<crate::desired::ObjectKey>> {
    // Both tables exist on any database a push bootstrapped since; asserted here for one
    // bootstrapped before the undo table was.
    for sql in [
        crate::ledger::create_table_sql(),
        crate::ledger::undo::create_table_sql(),
    ] {
        (&mut *tx).execute(sqlx::raw_sql(&sql)).await?;
    }
    let leave = crate::ledger::undo::rewritten_since(tx, id).await?;
    let (sql_down, left) = crate::ledger::undo::leaving_alone(sql_down, schema, &leave);
    (&mut *tx)
        .execute(sqlx::raw_sql(&without_transaction_control(&sql_down)))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to apply rollback SQL: {e}"))?;
    crate::ledger::undo::restore(tx, id).await?;
    let mark_sql = format!(
        "UPDATE {SCHEMA}.migrations SET rolled_back = true, rolled_back_at = NOW() WHERE id = $1"
    );
    sqlx::query(&mark_sql).bind(id).execute(&mut *tx).await?;
    Ok(left)
}

/// Studio reads the schema of the migration now in force: the one before the rolled-back push.
async fn restore_studio_metadata(
    tx: &mut PgConnection,
    prior: Option<&PriorMigrationRow>,
) -> Result<()> {
    let Some(PriorMigrationRow {
        admin_config: Some(admin),
        schema_snapshot: Some(snap),
        ..
    }) = prior
    else {
        return Ok(());
    };
    let studio_sql = format!(
        "UPDATE {SCHEMA}.schema_state SET ast_snapshot = $1, admin_config = $2 WHERE id = 1"
    );
    sqlx::query(&studio_sql)
        .bind(snap)
        .bind(admin)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

/// What a rollback of `name` reports, with the migration now in force and its sources.
fn rolled_back(
    name: &str,
    prior: Option<PriorMigrationRow>,
    left: &[crate::desired::ObjectKey],
) -> RollbackResult {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let (restored_name, manifest, sources_b64) = prior
        .map(|p| {
            (
                Some(p.name),
                p.schema_sources_manifest,
                p.schema_sources.map(|b| B64.encode(b)),
            )
        })
        .unwrap_or((None, None, None));
    let message = if left.is_empty() {
        format!("Rolled back migration {name}.")
    } else {
        let left: Vec<String> = left.iter().map(ToString::to_string).collect();
        format!(
            "Rolled back migration {name}, leaving {} as they are: released or recorded again \
             since the push.",
            left.join(", ")
        )
    };
    RollbackResult {
        status: "rolled_back".into(),
        name: name.to_string(),
        message,
        restored_migration_name: restored_name,
        schema_sources_manifest: manifest,
        schema_sources_base64: sources_b64,
    }
}

pub async fn load_migration_sources(
    pool: &PgPool,
    name: &str,
) -> Result<Option<(Vec<u8>, Option<serde_json::Value>)>> {
    let sql = format!(
        "SELECT schema_sources, schema_sources_manifest FROM {SCHEMA}.migrations WHERE name = $1"
    );
    let row: Option<(Option<Vec<u8>>, Option<serde_json::Value>)> =
        sqlx::query_as(&sql).bind(name).fetch_optional(pool).await?;
    Ok(row.and_then(|(sources, manifest)| sources.map(|s| (s, manifest))))
}

/// Re-apply the `auth.*` helper functions used by RLS policies.
///
/// These were only ever written at provision time, so an engine change to
/// `auth.role()` (for example, resolving application roles from
/// `app_metadata.role`) never reached an existing project: its policies kept
/// calling the old definition indefinitely. They are CREATE OR REPLACE, so
/// re-applying on every push is cheap and idempotent. Every push runs this inside its own
/// transaction, under the engine's lock (`push::reassert_auth_helpers`).
///
/// Skipped when there is no `auth` schema (a plain Postgres target), rather than
/// failing a push that has nothing to do with auth.
pub async fn reapply_auth_helpers(conn: &mut PgConnection, auth_schema: &str) -> Result<bool> {
    let exists: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM information_schema.schemata WHERE schema_name = $1")
            .bind(auth_schema)
            .fetch_optional(&mut *conn)
            .await?;
    if exists.is_none() {
        return Ok(false);
    }

    let config = crate::generator::sql::auth_functions::AuthFunctionConfig {
        project_ref: String::new(),
        auth_schema: auth_schema.to_string(),
    };
    let sql = crate::generator::sql::auth_functions::generate_auth_functions(&config);
    (&mut *conn).execute(sqlx::raw_sql(&sql)).await?;
    Ok(true)
}

/// Which bootstrap a database has had: the [`bootstrap_version`] of the engine that last ran it.
pub fn create_bootstrap_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.engine_bootstrap (
    id              INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    version         TEXT NOT NULL,
    engine_version  TEXT NOT NULL,
    applied_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
)"#
    )
}

/// Every statement that creates and repairs what the engine owns, in order, each with what it is
/// for: the `_supatype` tables and their repairs, then Studio's objects.
fn bootstrap_statements() -> Vec<(&'static str, String)> {
    let mut statements = vec![
        ("_supatype schema", create_internal_schema_sql().to_string()),
        ("migrations table", create_migrations_table_sql()),
        // Created with `migrations`, so a seed run never creates its own mid-transaction.
        ("seeds table", crate::seed::ledger::create_seeds_table_sql()),
        ("seeds index", crate::seed::ledger::create_seeds_index_sql()),
        ("studio_members table", create_studio_members_table_sql()),
        (
            "studio_members identities",
            ensure_studio_members_platform_identity_sql(),
        ),
        ("studio_audit table", create_studio_audit_table_sql()),
        ("studio_audit columns", ensure_studio_audit_columns_sql()),
        ("schema_state table", create_schema_state_table_sql()),
        (
            "schema_state Studio columns",
            ensure_schema_state_studio_columns_sql(),
        ),
        (
            "schema_state capabilities",
            ensure_schema_state_capabilities_column_sql(),
        ),
        (
            "schema_state project_schema",
            ensure_schema_state_project_schema_column_sql(),
        ),
        (
            "project_schema backfill",
            backfill_schema_state_project_schema_sql(),
        ),
    ];
    statements.extend(
        ensure_all_migration_columns_sql()
            .into_iter()
            .map(|sql| ("migrations columns", sql)),
    );
    // After `migrations`, which both reference.
    statements.push(("managed_objects table", crate::ledger::create_table_sql()));
    statements.push((
        "managed_objects undo table",
        crate::ledger::undo::create_table_sql(),
    ));
    statements.push(("engine_bootstrap table", create_bootstrap_table_sql()));
    statements.extend(crate::state::studio_state::bootstrap_statements());
    statements
}

/// The bootstrap this engine runs, as a fingerprint of its statements' text: any statement added
/// or changed is a new version, so no one has to remember to bump it.
pub fn bootstrap_version() -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for (_, sql) in bootstrap_statements() {
        h.update(sql.as_bytes());
        h.update([0]);
    }
    h.update(seed_studio_members_from_claims_sql().as_bytes());
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// The bootstrap version this database records, `None` before any engine recorded one. Takes no
/// lock a writer holds, so it never waits behind one.
async fn recorded_bootstrap(conn: &mut PgConnection) -> Result<Option<String>> {
    let present: bool = sqlx::query_scalar(&format!(
        "SELECT to_regclass('{SCHEMA}.engine_bootstrap') IS NOT NULL"
    ))
    .fetch_one(&mut *conn)
    .await?;
    if !present {
        return Ok(None);
    }
    Ok(sqlx::query_scalar(&format!(
        "SELECT version FROM {SCHEMA}.engine_bootstrap WHERE id = 1"
    ))
    .fetch_optional(&mut *conn)
    .await?)
}

/// Create and repair everything the engine owns inside `_supatype`, and Studio's objects, when
/// this database has not had this engine's bootstrap yet.
///
/// Every command that writes calls this first. It once ran on every push, outside any lock: its
/// `ALTER TABLE _supatype.migrations` waited behind a push in flight and every reader of the table
/// queued behind it (A4-N1), and two first pushes raced on the catalog (E14a). Now a read that
/// takes no lock decides whether it is needed, and when it is, it runs in one writer's transaction
/// under the engine's lock, so a second writer is refused with `engine_busy` instead of waiting.
pub async fn bootstrap_internal_state(pool: &PgPool) -> Result<()> {
    let version = bootstrap_version();
    let recorded = recorded_bootstrap(&mut *pool.acquire().await?).await?;
    if recorded.as_deref() == Some(version.as_str()) {
        return Ok(());
    }
    let mut tx = crate::push::begin_writer(pool).await?;
    // Another writer may have run it between the read and the lock.
    if recorded_bootstrap(&mut tx).await?.as_deref() != Some(version.as_str()) {
        run_bootstrap(&mut tx, &version).await?;
    }
    tx.commit().await.context("commit the bootstrap")?;
    Ok(())
}

async fn run_bootstrap(tx: &mut PgConnection, version: &str) -> Result<()> {
    for (what, sql) in bootstrap_statements() {
        (&mut *tx)
            .execute(sqlx::raw_sql(&sql))
            .await
            .with_context(|| format!("Failed to bootstrap the {what}"))?;
    }
    seed_studio_members(tx).await?;
    sqlx::query(&format!(
        "INSERT INTO {SCHEMA}.engine_bootstrap (id, version, engine_version) VALUES (1, $1, $2)
         ON CONFLICT (id) DO UPDATE SET version = EXCLUDED.version,
             engine_version = EXCLUDED.engine_version, applied_at = NOW()"
    ))
    .bind(version)
    .bind(env!("ENGINE_VERSION"))
    .execute(&mut *tx)
    .await
    .context("record the bootstrap version")?;
    Ok(())
}

/// Migrating an existing project: carry forward the admins who only have the old
/// `app_metadata.role` claim, before that claim stops meaning anything. Best effort, in a
/// savepoint, so a failure leaves the rest of the bootstrap standing.
async fn seed_studio_members(tx: &mut PgConnection) -> Result<()> {
    use sqlx::Connection;
    let mut savepoint = tx.begin().await?;
    match (&mut *savepoint)
        .execute(sqlx::raw_sql(&seed_studio_members_from_claims_sql()))
        .await
    {
        Ok(_) => savepoint.commit().await?,
        Err(e) => {
            savepoint.rollback().await?;
            eprintln!("Warning: failed to seed Studio membership from existing admin roles: {e}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::without_transaction_control;

    #[test]
    fn a_legacy_rollback_script_loses_its_own_transaction() {
        let legacy = "-- ============================================================\n\
                      -- ROLLBACK MIGRATION\n\
                      -- ============================================================\n\n\
                      BEGIN;\n\n\
                      ALTER TABLE \"public\".\"t\" DROP COLUMN IF EXISTS \"c\";\n\
                      COMMIT;\n";
        let sql = without_transaction_control(legacy);
        assert!(!sql.contains("BEGIN;"), "{sql}");
        assert!(!sql.contains("COMMIT;"), "{sql}");
        assert!(sql.contains("DROP COLUMN IF EXISTS \"c\";"), "{sql}");
    }

    #[test]
    fn transaction_words_inside_a_body_or_a_statement_are_kept() {
        let sql = "DO $x$\nBEGIN\n  PERFORM 1;\nEND;\n$x$;\n\
                   CREATE OR REPLACE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$\n\
                   BEGIN\n  COMMIT;\nEND;\n$$;\n\
                   DROP TABLE IF EXISTS \"begin\";";
        assert_eq!(without_transaction_control(sql), sql);
    }

    #[test]
    fn a_rollback_from_this_engine_is_unchanged() {
        let sql = "-- reconciled objects\nALTER TABLE \"public\".\"t\" DROP CONSTRAINT IF EXISTS \"c\";\n";
        assert_eq!(without_transaction_control(sql), sql);
    }
}
