use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

// Studio state lives in the `supatype` schema, apart from the internal `_supatype` bookkeeping
// schema, so that PostgREST can serve it when the schema is listed in `db-schemas`. Being
// reachable is why every object here decides for itself who may use it: anon may use none of
// them, a signed-in user only when they are a Studio member, and `service_role` always.
const SCHEMA: &str = "supatype";

type DashboardViewRow = (
    String,
    String,
    bool,
    serde_json::Value,
    Option<String>,
    String,
    String,
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardView {
    pub id: String,
    pub name: String,
    pub is_default: bool,
    pub layout: serde_json::Value,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub fn create_studio_schema_sql() -> &'static str {
    "CREATE SCHEMA IF NOT EXISTS supatype"
}

pub fn grant_studio_schema_sql() -> &'static str {
    "GRANT USAGE ON SCHEMA supatype TO anon, authenticated, service_role"
}

/// Who may call a Studio function: Studio's own callers, never anon or `PUBLIC`.
///
/// Revoked explicitly rather than left to the grant: `CREATE OR REPLACE` keeps the privileges an
/// earlier engine granted (anon and `PUBLIC` among them), and a new function is executable by
/// `PUBLIC` by default.
fn studio_function_grants(signature: &str) -> String {
    format!(
        "REVOKE ALL ON FUNCTION {SCHEMA}.{signature} FROM PUBLIC, anon;\n\
         GRANT EXECUTE ON FUNCTION {SCHEMA}.{signature} TO authenticated, service_role"
    )
}

/// Whether the caller may use Studio's state: `service_role`, or a signed-in user with a row in
/// `_supatype.studio_members`.
///
/// The claims are the ones PostgREST verified and set for the request. SECURITY DEFINER because
/// the membership table is deliberately out of the data plane's reach; the answer is one boolean
/// about the caller themselves, which discloses nothing they could not infer. Executable by
/// `authenticated` because the `dashboard_views` policy calls it as the querying role.
///
/// No membership table, or claims that do not parse, mean no: refusing is the safe answer.
pub fn create_studio_caller_allowed_function_sql() -> String {
    format!(
        r#"CREATE OR REPLACE FUNCTION {SCHEMA}.studio_caller_allowed()
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = '' AS $fn$
DECLARE
    claims jsonb;
BEGIN
    claims := nullif(current_setting('request.jwt.claims', true), '')::jsonb;
    IF claims->>'role' = 'service_role' THEN
        RETURN true;
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM _supatype.studio_members m
         WHERE m.user_id = (claims->>'sub')::uuid
    );
EXCEPTION
    WHEN undefined_table OR invalid_text_representation THEN
        RETURN false;
END
$fn$;
{}"#,
        studio_function_grants("studio_caller_allowed()")
    )
}

/// Raise `insufficient_privilege` unless [`create_studio_caller_allowed_function_sql`] admits the
/// caller. The first statement of every statistics function, which run as their owner and so read
/// past every grant and policy: the check has to be inside them.
///
/// Only ever called from those functions, so nobody else is granted it.
pub fn create_require_studio_caller_function_sql() -> String {
    format!(
        r#"CREATE OR REPLACE FUNCTION {SCHEMA}.require_studio_caller()
RETURNS void
LANGUAGE plpgsql STABLE SET search_path = '' AS $fn$
BEGIN
    IF NOT {SCHEMA}.studio_caller_allowed() THEN
        RAISE EXCEPTION 'Studio statistics are only for Studio members'
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'Sign in to Studio as a member, or call with the service role key.';
    END IF;
END
$fn$;
REVOKE ALL ON FUNCTION {SCHEMA}.require_studio_caller() FROM PUBLIC, anon, authenticated"#
    )
}

/// Saved Studio dashboards. Under RLS, with one policy that admits exactly the callers
/// [`create_studio_caller_allowed_function_sql`] does; anon holds no privilege on it at all.
///
/// The `REVOKE` and `ENABLE` are idempotent and run on every push, because `CREATE TABLE IF NOT
/// EXISTS` leaves a table an earlier engine made (granted to anon, without RLS) as it was.
pub fn create_dashboard_views_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {SCHEMA}.dashboard_views (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    is_default  BOOLEAN NOT NULL DEFAULT FALSE,
    layout      JSONB NOT NULL DEFAULT '[]',
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
REVOKE ALL ON TABLE {SCHEMA}.dashboard_views FROM PUBLIC, anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {SCHEMA}.dashboard_views TO authenticated, service_role;
ALTER TABLE {SCHEMA}.dashboard_views ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS studio_callers_only ON {SCHEMA}.dashboard_views;
CREATE POLICY studio_callers_only ON {SCHEMA}.dashboard_views
    FOR ALL TO authenticated, service_role
    USING ((SELECT {SCHEMA}.studio_caller_allowed()))
    WITH CHECK ((SELECT {SCHEMA}.studio_caller_allowed()))"#
    )
}

pub fn create_db_stats_function_sql() -> String {
    format!(
        r#"CREATE OR REPLACE FUNCTION {SCHEMA}.db_stats()
RETURNS TABLE(db_size_bytes BIGINT, db_size_pretty TEXT)
LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = '' AS $fn$
BEGIN
    PERFORM {SCHEMA}.require_studio_caller();
    RETURN QUERY
        SELECT pg_database_size(current_database()),
               pg_size_pretty(pg_database_size(current_database()));
END
$fn$;
{}"#,
        studio_function_grants("db_stats()")
    )
}

pub fn create_daily_signups_function_sql() -> String {
    // plpgsql for the same reason as `storage_stats` below: it defers the table reference to
    // runtime. As `LANGUAGE sql` this validated `auth.users` at creation time, so the first push to
    // a database GoTrue had not yet booted against failed outright (`relation "auth.users" does not
    // exist`), from a Studio analytics helper, aborting a migration that had nothing to do with auth.
    // `supatype/postgres` bootstraps the auth schema in its image, which is why this only showed up
    // on a database Supatype did not create.
    format!(
        r#"CREATE OR REPLACE FUNCTION {SCHEMA}.daily_signups(days INT DEFAULT 30)
RETURNS TABLE(day DATE, count INT)
LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = '' AS $fn$
BEGIN
    PERFORM {SCHEMA}.require_studio_caller();
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'auth' AND table_name = 'users'
    ) THEN
        RETURN QUERY
            SELECT date_trunc('day', u.created_at)::date AS day,
                   count(*)::int
            FROM auth.users u
            WHERE u.created_at > now() - make_interval(days => daily_signups.days)
            GROUP BY 1
            ORDER BY 1;
    END IF;
END
$fn$;
{}"#,
        studio_function_grants("daily_signups(INT)")
    )
}

pub fn create_storage_stats_function_sql() -> String {
    // plpgsql defers table-reference validation to runtime, so this compiles
    // even when the storage schema hasn't been bootstrapped yet (no buckets
    // declared in the schema). The guard returns zeros in that case.
    format!(
        r#"CREATE OR REPLACE FUNCTION {SCHEMA}.storage_stats()
RETURNS TABLE(file_count BIGINT, total_bytes BIGINT)
LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = '' AS $fn$
BEGIN
    PERFORM {SCHEMA}.require_studio_caller();
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'storage' AND table_name = 'objects'
    ) THEN
        RETURN QUERY
            SELECT count(*)::bigint,
                   coalesce(sum((o.metadata->>'size')::bigint), 0)::bigint
            FROM storage.objects o;
    ELSE
        RETURN QUERY SELECT 0::bigint, 0::bigint;
    END IF;
END
$fn$;
{}"#,
        studio_function_grants("storage_stats()")
    )
}

/// Rows created per day in one model table.
///
/// Runs as its owner, so it would count the rows of any relation it was named, past RLS and every
/// grant. So it takes only a table the push ledger records as a table of the project's schema
/// (`_supatype.managed_objects`, whose `released` rows a push has handed back), and refuses
/// anything else with `invalid_parameter_value` before a query is built. The name is then quoted
/// as an identifier, never spliced.
pub fn create_daily_content_creates_function_sql() -> String {
    format!(
        r#"CREATE OR REPLACE FUNCTION {SCHEMA}.daily_content_creates(table_name TEXT, days INT DEFAULT 30)
RETURNS TABLE(day DATE, count INT)
LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = '' AS $fn$
DECLARE
    model_schema text;
BEGIN
    PERFORM {SCHEMA}.require_studio_caller();
    SELECT m.schema_name INTO model_schema
      FROM _supatype.managed_objects m
      JOIN _supatype.schema_state s ON s.id = 1 AND s.project_schema = m.schema_name
     WHERE m.kind = 'table'
       AND m.parent = ''
       AND m.name = daily_content_creates.table_name
       AND m.status IN ('managed', 'adopted');
    IF model_schema IS NULL THEN
        RAISE EXCEPTION 'No model table is named %', daily_content_creates.table_name
            USING ERRCODE = 'invalid_parameter_value';
    END IF;
    RETURN QUERY EXECUTE format(
        'SELECT date_trunc(''day'', created_at)::date, count(*)::int
           FROM %I.%I
          WHERE created_at > now() - make_interval(days => $1)
          GROUP BY 1 ORDER BY 1',
        model_schema, daily_content_creates.table_name
    ) USING daily_content_creates.days;
END
$fn$;
{}"#,
        studio_function_grants("daily_content_creates(TEXT, INT)")
    )
}

pub async fn list_dashboard_views(pool: &PgPool) -> Result<Vec<DashboardView>> {
    let sql = format!(
        "SELECT id::TEXT, name, is_default, layout, created_by, \
         created_at::TEXT, updated_at::TEXT \
         FROM {SCHEMA}.dashboard_views ORDER BY created_at ASC"
    );
    let rows: Vec<DashboardViewRow> = sqlx::query_as(&sql).fetch_all(pool).await?;

    Ok(rows
        .into_iter()
        .map(
            |(id, name, is_default, layout, created_by, created_at, updated_at)| DashboardView {
                id,
                name,
                is_default,
                layout,
                created_by,
                created_at,
                updated_at,
            },
        )
        .collect())
}

/// Everything Studio needs in the database, in order, applied by every push and carried by a
/// `migrate` file. Lives beside the statements so a new one is applied the moment it is added
/// here. The caller gate comes before the table whose policy and the functions whose bodies call
/// it.
pub fn bootstrap_statements() -> Vec<(&'static str, String)> {
    vec![
        ("supatype schema", create_studio_schema_sql().to_string()),
        (
            "supatype schema usage",
            grant_studio_schema_sql().to_string(),
        ),
        (
            "supatype.studio_caller_allowed function",
            create_studio_caller_allowed_function_sql(),
        ),
        (
            "supatype.require_studio_caller function",
            create_require_studio_caller_function_sql(),
        ),
        (
            "supatype.dashboard_views table",
            create_dashboard_views_table_sql(),
        ),
        (
            "supatype.storage_stats function",
            create_storage_stats_function_sql(),
        ),
        ("supatype.db_stats function", create_db_stats_function_sql()),
        (
            "supatype.daily_signups function",
            create_daily_signups_function_sql(),
        ),
        (
            "supatype.daily_content_creates function",
            create_daily_content_creates_function_sql(),
        ),
    ]
}

/// [`bootstrap_statements`], applied.
pub async fn bootstrap(pool: &PgPool) -> Result<()> {
    use anyhow::Context as _;
    for (what, sql) in bootstrap_statements() {
        sqlx::raw_sql(&sql)
            .execute(pool)
            .await
            .with_context(|| format!("Failed to create {what}"))?;
    }
    Ok(())
}
