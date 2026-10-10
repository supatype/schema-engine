use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

// Studio state lives in the `supatype` schema, separate from the internal
// `_supatype` bookkeeping schema so it is accessible via PostgREST when the
// schema is listed in `db-schemas`.
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
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {SCHEMA}.dashboard_views TO anon, authenticated, service_role"#
    )
}

pub fn create_db_stats_function_sql() -> String {
    format!(
        r#"CREATE OR REPLACE FUNCTION {SCHEMA}.db_stats()
RETURNS TABLE(db_size_bytes BIGINT, db_size_pretty TEXT)
LANGUAGE sql SECURITY DEFINER STABLE AS $$
    SELECT pg_database_size(current_database()),
           pg_size_pretty(pg_database_size(current_database()))
$$;
GRANT EXECUTE ON FUNCTION {SCHEMA}.db_stats() TO anon, authenticated, service_role"#
    )
}

pub fn create_daily_signups_function_sql() -> String {
    // plpgsql for the same reason as `storage_stats` below: it defers the table reference to
    // runtime. As `LANGUAGE sql` this validated `auth.users` at creation time, so the first push to
    // a database GoTrue had not yet booted against failed outright with `relation "auth.users"
    // does not exist`, from a Studio analytics helper, aborting a migration that had nothing to do
    // with auth.
    // `supatype/postgres` bootstraps the auth schema in its image, which is why this only showed up
    // on a database Supatype did not create.
    format!(
        r#"CREATE OR REPLACE FUNCTION {SCHEMA}.daily_signups(days INT DEFAULT 30)
RETURNS TABLE(day DATE, count INT)
LANGUAGE plpgsql SECURITY DEFINER STABLE AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'auth' AND table_name = 'users'
    ) THEN
        RETURN QUERY
            SELECT date_trunc('day', created_at)::date AS day,
                   count(*)::int
            FROM auth.users
            WHERE created_at > now() - (days || ' days')::interval
            GROUP BY day
            ORDER BY day;
    END IF;
END
$$;
GRANT EXECUTE ON FUNCTION {SCHEMA}.daily_signups(INT) TO anon, authenticated, service_role"#
    )
}

pub fn create_storage_stats_function_sql() -> String {
    // plpgsql defers table-reference validation to runtime, so this compiles
    // even when the storage schema hasn't been bootstrapped yet (no buckets
    // declared in the schema). The guard returns zeros in that case.
    format!(
        r#"CREATE OR REPLACE FUNCTION {SCHEMA}.storage_stats()
RETURNS TABLE(file_count BIGINT, total_bytes BIGINT)
LANGUAGE plpgsql SECURITY DEFINER STABLE AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'storage' AND table_name = 'objects'
    ) THEN
        RETURN QUERY
            SELECT count(*)::bigint,
                   coalesce(sum((metadata->>'size')::bigint), 0)::bigint
            FROM storage.objects;
    ELSE
        RETURN QUERY SELECT 0::bigint, 0::bigint;
    END IF;
END
$$;
GRANT EXECUTE ON FUNCTION {SCHEMA}.storage_stats() TO anon, authenticated, service_role"#
    )
}

pub fn create_daily_content_creates_function_sql() -> String {
    format!(
        r#"CREATE OR REPLACE FUNCTION {SCHEMA}.daily_content_creates(table_name TEXT, days INT DEFAULT 30)
RETURNS TABLE(day DATE, count INT)
LANGUAGE plpgsql SECURITY DEFINER STABLE AS $$
BEGIN
    RETURN QUERY EXECUTE format(
        'SELECT date_trunc(''day'', created_at)::date, count(*)::int
         FROM public.%I
         WHERE created_at > now() - ($1 || '' days'')::interval
         GROUP BY 1 ORDER BY 1',
        table_name
    ) USING days;
END
$$;
GRANT EXECUTE ON FUNCTION {SCHEMA}.daily_content_creates(TEXT, INT) TO anon, authenticated, service_role"#
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

/// Everything Studio needs in the database, in order, each with what it creates. Part of the
/// engine's bootstrap (`migration_history::bootstrap_internal_state`), whose version is the text
/// of every statement it runs, so a statement added or changed here is applied by the next push.
pub fn bootstrap_statements() -> Vec<(&'static str, String)> {
    vec![
        ("supatype schema", create_studio_schema_sql().to_string()),
        (
            "supatype schema usage",
            grant_studio_schema_sql().to_string(),
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

/// [`bootstrap_statements`], run on `pool` one by one.
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
