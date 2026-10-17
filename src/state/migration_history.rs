use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sqlx::{Executor, PgConnection, PgPool, Postgres};

use super::audit::{PushAudit, PushChannel};

// Internal bookkeeping lives in a dedicated schema so it never appears in the
// user's `public` schema and is never touched by introspection or diffs.
const SCHEMA: &str = "_supatype";

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
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
    /// Who pushed it: verified when a control plane authenticated them, else their own claim.
    pub pushed_by: Option<String>,
    pub pushed_via: Option<String>,
    pub pushed_from: Option<String>,
    pub pushed_by_verified: Option<bool>,
    /// Each rename it applied, with who declared it and when.
    pub renames: Option<serde_json::Value>,
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
    error_message           TEXT,
    pushed_by               TEXT,
    pushed_via              TEXT,
    pushed_from             TEXT,
    pushed_by_verified      BOOLEAN,
    renames                 JSONB,
    refusal                 JSONB,
    superseded_at           TIMESTAMPTZ
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

/// SQL that is true when the `studio_members` row aliased `member` is held by `subject` (a uuid
/// expression), under either identity the row can carry.
///
/// Every check the engine generates goes through this, so a member admitted in one place is
/// admitted in all of them. Matching `user_id` alone shut every Cloud account out of the Studio
/// statistics, the saved dashboards and the drafts its role may see, although the Cloud control
/// plane admits that account to Studio. A NULL subject matches nothing, and neither does a row's
/// NULL column, so a caller with no `sub` is never a member.
pub fn studio_member_held_by_sql(member: &str, subject: &str) -> String {
    format!("{subject} IN ({member}.user_id, {member}.platform_user_id)")
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

/// Which project user a Supatype Cloud account acts as when Studio runs as them.
///
/// Cloud signs a short-lived project token for the linked user, so RLS and field masks apply to a
/// member exactly as the app applies them to that user. The control plane writes a row only after
/// the member has signed in to this project's own auth and the two emails matched.
///
/// A table of its own rather than a second id on a `studio_members` row: a membership row still
/// names exactly one identity, so self-host's lookups by `user_id` are unchanged, and an org owner,
/// who holds no membership row, can still link. Deleting the project user deletes the link, so the
/// member fails closed. The foreign key is added once `auth.users` exists, since a project can be
/// pushed before its auth schema is.
pub fn create_studio_identity_links_table_sql() -> String {
    format!(
        r#"DO $$
BEGIN
    CREATE TABLE IF NOT EXISTS {SCHEMA}.studio_identity_links (
        platform_user_id  UUID PRIMARY KEY,
        user_id           UUID NOT NULL UNIQUE,
        email             TEXT NOT NULL,
        linked_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    IF to_regclass('auth.users') IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = '{SCHEMA}.studio_identity_links'::regclass
           AND conname = 'studio_identity_links_user_id_fkey'
    ) THEN
        DELETE FROM {SCHEMA}.studio_identity_links l
         WHERE NOT EXISTS (SELECT 1 FROM auth.users u WHERE u.id = l.user_id);
        ALTER TABLE {SCHEMA}.studio_identity_links
            ADD CONSTRAINT studio_identity_links_user_id_fkey
            FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE;
    END IF;
END $$"#
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

/// Deleting a project user deletes their membership, by any route, a raw SQL delete included, as
/// it already deletes their identity link. A row left behind kept a Studio role for an id nobody
/// can sign in as.
///
/// Only `user_id` references `auth.users`: a Cloud account's row has no project user, and its
/// NULL `user_id` is never checked. Like the link table's, the key is added once `auth.users`
/// exists, since a project can be pushed before its auth schema is, and a membership whose user
/// is already gone is dropped first so the constraint can be added to an existing database. Runs
/// after the identities migration, which leaves `user_id` nullable on a pre-cloud table.
pub fn ensure_studio_members_user_foreign_key_sql() -> String {
    format!(
        r#"DO $$
BEGIN
    IF to_regclass('{SCHEMA}.studio_members') IS NOT NULL
       AND to_regclass('auth.users') IS NOT NULL
       AND NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = '{SCHEMA}.studio_members'::regclass
           AND conname = 'studio_members_user_id_fkey'
    ) THEN
        DELETE FROM {SCHEMA}.studio_members m
         WHERE m.user_id IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM auth.users u WHERE u.id = m.user_id);
        ALTER TABLE {SCHEMA}.studio_members
            ADD CONSTRAINT studio_members_user_id_fkey
            FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE;
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
        ensure_migrations_audit_columns_sql(),
        super::refused_push::ensure_columns_sql(),
    ]
}

/// The audit trail's columns (`crate::state::audit`): who pushed, through what, from where,
/// whether a control plane authenticated the author, and the renames the push applied. Nullable:
/// a row from before them, or written by a caller that sent none, says nothing rather than
/// something untrue.
pub fn ensure_migrations_audit_columns_sql() -> String {
    format!(
        "ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS pushed_by TEXT;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS pushed_via TEXT;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS pushed_from TEXT;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS pushed_by_verified BOOLEAN;\
         ALTER TABLE {SCHEMA}.migrations ADD COLUMN IF NOT EXISTS renames JSONB"
    )
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
/// `unenforced` means only "no field rules in this schema", and `broken` a schema with rules
/// and neither the extension nor the views to enforce them. That distinction is the point: a deployment that quietly stopped enforcing must be
/// visible, not inferred.
///
/// Beside the tier, `columns` says which predicate decides each masked column
/// ([`crate::generator::sql::rls::field_predicates`]): what the labels carry under tier 1, and
/// what nothing else carries under tier 2, where realtime needs it to mask a change.
pub async fn record_field_enforcement(
    conn: &mut sqlx::PgConnection,
    ast: &crate::parser::ast::SchemaAst,
    schema: &str,
) -> Result<()> {
    let labelled_columns = labelled_column_count(ast);
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
            "columns": crate::generator::sql::rls::field_predicates(ast, schema),
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
/// tells a rename apart from a drop and an add, and what an older engine's access objects are
/// compared with (`ledger::unrecorded`). A snapshot that does not decode is said to, with the
/// error (F10), rather than read as no snapshot; and no snapshot after a push was applied is told
/// from a database nothing was ever pushed to, since only the first means something is unknown.
/// Read on the caller's connection, as [`load_latest_schema_snapshot`] is; a read that fails is an
/// error, not one of these.
pub async fn load_previous_schema(
    conn: &mut PgConnection,
) -> Result<crate::ledger::unrecorded::Previous> {
    use crate::ledger::unrecorded::Previous;
    Ok(match load_latest_schema_snapshot(conn).await? {
        Some(snapshot) => match serde_json::from_value(snapshot) {
            Ok(ast) => Previous::Found(Box::new(ast)),
            Err(e) => Previous::Unreadable(e.to_string()),
        },
        None if any_push_applied(conn).await? => Previous::Missing,
        None => Previous::NeverPushed,
    })
}

/// Whether a push was applied here and not rolled back. No history table is no push, and a failed
/// push recorded no schema and applied nothing; asked of the catalog first, so a database no engine
/// has written to aborts no transaction. `to_jsonb` reads `status` whether or not an older engine's
/// table has the column.
async fn any_push_applied(conn: &mut PgConnection) -> Result<bool> {
    if !has_columns(conn, "migrations", &["rolled_back"]).await? {
        return Ok(false);
    }
    Ok(sqlx::query_scalar::<_, bool>(&format!(
        "SELECT EXISTS (SELECT 1 FROM {SCHEMA}.migrations m WHERE NOT m.rolled_back
                          AND COALESCE(to_jsonb(m) ->> 'status', 'applied') = 'applied')"
    ))
    .fetch_one(&mut *conn)
    .await?)
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
         (name, hash, engine_version, schema_snapshot, admin_config, sql_up, sql_down, schema_sources, schema_sources_manifest, \
          pushed_by, pushed_via, pushed_from, pushed_by_verified, renames) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id"
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
    /// Who pushed, through what and from where.
    pub audit: PushAudit,
    /// The renames the push applied, with who declared each ([`PushAudit::applied_renames`]).
    pub renames: Option<serde_json::Value>,
}

/// `pushed_by_verified` as recorded: true or false when the push said who it was from, and
/// nothing when it did not, so an absent author is not recorded as an unverified one.
fn verified_column(audit: &PushAudit) -> Option<bool> {
    audit.pushed_by.as_ref().map(|_| audit.pushed_by_verified)
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
        .bind(sources.audit.pushed_by.as_deref())
        .bind(sources.audit.pushed_via.map(PushChannel::as_str))
        .bind(sources.audit.pushed_from.as_deref())
        .bind(verified_column(&sources.audit))
        .bind(sources.renames.as_ref())
        .fetch_one(executor)
        .await?;
    Ok(id)
}

/// Updates `admin_config` and `schema_snapshot` on the latest applied, non-rolled-back migration
/// row: never a failed or refused one, which applied nothing and must not be read back as the
/// schema in force. Returns the number of rows updated (0 if there are no applicable records).
pub async fn update_latest_migration_admin(
    pool: impl sqlx::PgExecutor<'_>,
    admin_config: &serde_json::Value,
    schema_snapshot: &serde_json::Value,
) -> Result<u64> {
    let sql = format!(
        "UPDATE {SCHEMA}.migrations SET admin_config = $1, schema_snapshot = $2 \
         WHERE id = (SELECT MAX(id) FROM {SCHEMA}.migrations \
                     WHERE rolled_back = FALSE AND COALESCE(status, 'applied') = 'applied')"
    );
    let res = sqlx::query(&sql)
        .bind(admin_config)
        .bind(schema_snapshot)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// When push finds no DDL diff: refresh Studio metadata on the latest migration row, or
/// record a one-time `initial_*` baseline when no active migration exists yet, by `audit`'s author.
pub async fn refresh_metadata_on_up_to_date_push(
    conn: &mut sqlx::PgConnection,
    admin_config: &serde_json::Value,
    schema_snapshot: &serde_json::Value,
    audit: &PushAudit,
) -> Result<()> {
    save_studio_metadata_if_present(&mut *conn, admin_config, schema_snapshot).await?;
    // This push applied: a refusal or failure before it no longer describes the project.
    super::refused_push::supersede(&mut *conn).await?;

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
        .bind(audit.pushed_by.as_deref())
        .bind(audit.pushed_via.map(PushChannel::as_str))
        .bind(audit.pushed_from.as_deref())
        .bind(verified_column(audit))
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
         (name, hash, engine_version, sql_up, status, error_message, \
          pushed_by, pushed_via, pushed_from, pushed_by_verified) \
         VALUES ($1, $2, $3, $4, 'failed', $5, $6, $7, $8, $9) \
         ON CONFLICT (name) DO NOTHING"
    )
}

/// What a failed push records: its name, hash and statements, why it failed, and who tried it.
pub struct FailedMigration<'a> {
    pub name: &'a str,
    pub hash: &'a str,
    pub sql_up: &'a str,
    pub error: &'a str,
    pub audit: &'a PushAudit,
}

/// Record a failed push under its name, or, when a migration already has that name, under
/// `<name>.failed.<time>`: a name of its own, so the failure is kept and the earlier row is not
/// changed.
pub async fn record_failed_migration(pool: &PgPool, failed: FailedMigration<'_>) -> Result<()> {
    let FailedMigration {
        name,
        hash,
        sql_up,
        error,
        audit,
    } = failed;
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
            .bind(audit.pushed_by.as_deref())
            .bind(audit.pushed_via.map(PushChannel::as_str))
            .bind(audit.pushed_from.as_deref())
            .bind(verified_column(audit))
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

pub async fn list_migrations_summary(pool: &PgPool) -> Result<Vec<MigrationListItem>> {
    let sql = format!(
        "SELECT id, name, hash, applied_at::TEXT AS applied_at, rolled_back, engine_version, \
         COALESCE(status, 'applied') AS status, schema_sources_manifest, \
         pushed_by, pushed_via, pushed_from, pushed_by_verified, renames \
         FROM {SCHEMA}.migrations m ORDER BY m.applied_at DESC"
    );
    Ok(sqlx::query_as(&sql).fetch_all(pool).await?)
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
    // A person is waiting: a lock it cannot take at once is named, not retried (LK1).
    let (mut tx, pid) = crate::push::begin_watched_writer(pool).await?;
    let work = async move {
        // The history is one project's; rolling it back from another would undo that project's
        // migration and record this schema as the database's.
        assert_project_schema_on(&mut tx, schema).await?;
        let latest = load_latest_applied_migration(&mut tx)
            .await?
            .ok_or(RollbackRefused::NoAppliedMigration)?;
        let sql_down = latest
            .sql_down
            .clone()
            .filter(|s| !s.trim().is_empty())
            .ok_or(RollbackRefused::NoRollbackSql)?;
        refuse_lost_data(&latest.name, &sql_down, schema)?;
        let prior = load_prior_applied_migration(&mut tx, latest.id).await?;
        let (left, index_drops) = undo_migration(&mut tx, &latest, &sql_down, schema).await?;
        restore_studio_metadata(&mut tx, prior.as_ref()).await?;
        let new_state = crate::introspector::introspect_connection(&mut tx, schema).await?;
        save_schema_state(&mut *tx, &new_state).await?;
        tx.commit().await?;
        Ok((rolled_back(&latest.name, prior, &left), index_drops))
    };
    let (result, index_drops) = crate::online::fail_fast(pool, pid, "rollback", work).await?;
    crate::online::drop_concurrently(pool, &index_drops).await?;
    Ok(result)
}

/// Refuses, before anything runs, the rollback of a migration that dropped a table or a column:
/// its data went with it, and the rollback could only warn so and then fail partway, putting back
/// a key or an index on a column that is gone, or succeed with the column still gone.
fn refuse_lost_data(migration: &str, sql_down: &str, schema: &str) -> Result<()> {
    let lost = crate::generator::sql::rollback::unrestorable(sql_down, schema);
    if lost.is_empty() {
        return Ok(());
    }
    Err(RollbackRefused::DataNotRestorable {
        migration: migration.to_string(),
        lost,
    }
    .into())
}

/// A rollback refused (CL3): with nothing to undo, or undoing a migration whose dropped data it
/// cannot bring back. Told apart by its reason, not its wording. The message keeps the reason as
/// its first word, as it always has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RollbackRefused {
    NoAppliedMigration,
    NoRollbackSql,
    /// `migration` dropped each of `lost` (`table <schema>.<table>`, `column <schema>.<table>.<column>`).
    DataNotRestorable {
        migration: String,
        lost: Vec<String>,
    },
}

/// The stable name a caller matches a [`RollbackRefused::DataNotRestorable`] refusal on.
pub use crate::generator::sql::rollback::DATA_NOT_RESTORABLE;

impl RollbackRefused {
    pub fn reason(&self) -> &'static str {
        match self {
            RollbackRefused::NoAppliedMigration => "no_applied_migration",
            RollbackRefused::NoRollbackSql => "no_rollback_sql",
            RollbackRefused::DataNotRestorable { .. } => DATA_NOT_RESTORABLE,
        }
    }

    /// What the refusal names beside its reason.
    pub fn details(&self) -> serde_json::Value {
        match self {
            RollbackRefused::DataNotRestorable { migration, lost } => {
                serde_json::json!({ "migration": migration, "lost": lost })
            }
            _ => serde_json::json!({}),
        }
    }
}

impl std::fmt::Display for RollbackRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let said = match self {
            RollbackRefused::NoAppliedMigration => "No applied migration to roll back",
            RollbackRefused::NoRollbackSql => "Migration has no rollback SQL (metadata-only push?)",
            // Worded once, with a migration file's rollback section, which raises the same.
            RollbackRefused::DataNotRestorable { migration, lost } => {
                let subject = format!("Migration {migration}");
                return f.write_str(&crate::generator::sql::rollback::data_not_restorable(
                    &subject, lost,
                ));
            }
        };
        write!(f, "{}: {said}", self.reason())
    }
}

impl std::error::Error for RollbackRefused {}

/// The stable name a caller matches a [`NoSchemaSnapshot`] refusal on (CL3).
pub const NO_SCHEMA_SNAPSHOT: &str = "no_schema_snapshot";

/// A migration whose schema sources were asked for and that recorded none. The message keeps the
/// wording callers matched on before the reason existed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoSchemaSnapshot {
    pub name: String,
}

impl std::fmt::Display for NoSchemaSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Migration {} has no schema snapshot", self.name)
    }
}

impl std::error::Error for NoSchemaSnapshot {}

/// Run `sql_down` for `migration`, put the ledger back as it was before it and mark it rolled
/// back. Returns the objects left as they are (released or recorded again since the push, so no
/// longer the push's to undo), and the indexes to drop concurrently once `tx` has committed (LK7).
async fn undo_migration(
    tx: &mut PgConnection,
    migration: &LatestMigrationRow,
    sql_down: &str,
    schema: &str,
) -> Result<(Vec<crate::desired::ObjectKey>, Vec<String>)> {
    let id = migration.id;
    // Both tables exist on any database a push bootstrapped since; asserted here for one
    // bootstrapped before the undo table was.
    for sql in [
        crate::ledger::create_table_sql(),
        crate::ledger::undo::create_table_sql(),
    ] {
        (&mut *tx).execute(sqlx::raw_sql(&sql)).await?;
    }
    // What was released or recorded again since the push is no longer the push's to undo: its
    // statements are left out, as `restore` leaves its row. A released one on a table the rollback
    // drops would go with the table whatever is left out, so that rollback is refused before
    // anything runs; one recorded again but still Supatype's goes with its table, row and all.
    let leave = crate::ledger::undo::rewritten_since(tx, id).await?;
    let sparing = crate::ledger::undo::sparing(&migration.name, sql_down, schema, &leave)?;
    let (sql_down, left) = crate::ledger::undo::leaving_alone(sql_down, schema, &sparing.leave);
    let (sql_down, index_drops) = crate::online::concurrent_drops(&sql_down);
    (&mut *tx)
        .execute(sqlx::raw_sql(&without_transaction_control(&sql_down)))
        .await
        .map_err(|e| {
            // The database error stays the cause, so a lock not taken is told apart (LK1).
            let said = format!("Failed to apply rollback SQL: {e}");
            anyhow::Error::from(e).context(said)
        })?;
    crate::ledger::undo::restore(tx, id).await?;
    crate::ledger::delete(tx, &sparing.with_their_table).await?;
    sqlx::query(&mark_rolled_back_sql("$1"))
        .bind(id)
        .execute(&mut *tx)
        .await?;
    Ok((left, index_drops))
}

/// Marks the migration whose id `id` gives rolled back: a parameter, or for a `migrate --record`
/// file's rollback section, a subquery naming it (HI2).
pub fn mark_rolled_back_sql(id: &str) -> String {
    format!(
        "UPDATE {SCHEMA}.migrations SET rolled_back = true, rolled_back_at = NOW() WHERE id = {id}"
    )
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

/// Re-apply the claim readers the generated rules call, and the `auth.*` aliases of them.
///
/// These were only ever written at provision time, so an engine change to
/// `auth.role()` (for example, resolving application roles from
/// `app_metadata.role`) never reached an existing project: its policies kept
/// calling the old definition indefinitely. They are CREATE OR REPLACE, so
/// re-applying on every push is cheap and idempotent. Re-applying also puts back
/// an `auth.*` alias the auth server's own migrations replaced, for hand-written
/// rules; the generated ones never call those. Every push runs this inside its own
/// transaction, under the engine's lock (`push::reassert_auth_helpers`).
///
/// The readers live in `_supatype` and are always applied. The aliases are skipped
/// when there is no `auth` schema (a plain Postgres target), rather than failing a
/// push that has nothing to do with auth; the result says whether they were applied.
pub async fn reapply_auth_helpers(conn: &mut PgConnection, auth_schema: &str) -> Result<bool> {
    let statements = auth_helper_statements(conn, auth_schema).await?;
    for sql in &statements {
        (&mut *conn).execute(sqlx::raw_sql(sql)).await?;
    }
    Ok(statements.len() > 1)
}

/// What [`reapply_auth_helpers`] runs on this database: the claim readers, then the `auth.*`
/// aliases when it has `auth_schema`. A `migrate` file carries the same statements, so applying it
/// by hand installs what a push would.
pub async fn auth_helper_statements(
    conn: &mut PgConnection,
    auth_schema: &str,
) -> Result<Vec<String>> {
    use crate::generator::sql::auth_functions;

    let mut statements = vec![auth_functions::generate_claim_readers()];
    let exists: Option<(i32,)> =
        sqlx::query_as("SELECT 1 FROM information_schema.schemata WHERE schema_name = $1")
            .bind(auth_schema)
            .fetch_optional(&mut *conn)
            .await?;
    if exists.is_some() {
        let config = auth_functions::AuthFunctionConfig {
            project_ref: String::new(),
            auth_schema: auth_schema.to_string(),
        };
        statements.push(auth_functions::generate_auth_aliases(&config));
    }
    Ok(statements)
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
        (
            "studio_members user foreign key",
            ensure_studio_members_user_foreign_key_sql(),
        ),
        ("studio_audit table", create_studio_audit_table_sql()),
        ("studio_audit columns", ensure_studio_audit_columns_sql()),
        (
            "studio_identity_links table",
            create_studio_identity_links_table_sql(),
        ),
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
    // A push or `dev` runs it, and nobody is at a prompt: a lock it cannot take is tried again,
    // as a push's is (LK1).
    let version = version.as_str();
    crate::online::retrying("bootstrap", || async {
        let (mut tx, pid) = crate::push::begin_watched_writer(pool).await?;
        let work = async move {
            // Another writer may have run it between the read and the lock.
            if recorded_bootstrap(&mut tx).await?.as_deref() != Some(version) {
                run_bootstrap(&mut tx, version).await?;
            }
            tx.commit().await.context("commit the bootstrap")
        };
        crate::online::fail_fast(pool, pid, "bootstrap", work).await
    })
    .await
}

/// The bootstrap, run in `tx`, recorded as `version`. `migrate_file` runs it too, in the
/// transaction it rehearses the push in.
pub(crate) async fn run_bootstrap(tx: &mut PgConnection, version: &str) -> Result<()> {
    for (what, sql) in bootstrap_statements() {
        (&mut *tx)
            .execute(sqlx::raw_sql(&sql))
            .await
            .with_context(|| format!("Failed to bootstrap the {what}"))?;
    }
    seed_studio_members(tx).await?;
    (&mut *tx)
        .execute(sqlx::raw_sql(&record_bootstrap_sql(version)))
        .await
        .context("record the bootstrap version")?;
    Ok(())
}

/// Records that this database has had bootstrap `version`, from this engine.
fn record_bootstrap_sql(version: &str) -> String {
    use crate::sql_quote::quote_literal;
    format!(
        "INSERT INTO {SCHEMA}.engine_bootstrap (id, version, engine_version) VALUES (1, {}, {})
         ON CONFLICT (id) DO UPDATE SET version = EXCLUDED.version,
             engine_version = EXCLUDED.engine_version, applied_at = NOW()",
        quote_literal(version),
        quote_literal(env!("ENGINE_VERSION"))
    )
}

/// The bootstrap as a `migrate` file carries it: what [`bootstrap_internal_state`] runs on a
/// database with no bootstrap version, the version row included, so a file applied by hand leaves
/// the next push nothing to bootstrap. The Studio seed is one statement here, where a push runs it
/// best effort in a savepoint: it does nothing unless `auth.users` exists and no member does.
pub fn bootstrap_file_statements() -> Vec<String> {
    let mut statements: Vec<String> = bootstrap_statements()
        .into_iter()
        .map(|(_, sql)| sql)
        .collect();
    statements.push(seed_studio_members_from_claims_sql());
    statements.push(record_bootstrap_sql(&bootstrap_version()));
    statements
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
