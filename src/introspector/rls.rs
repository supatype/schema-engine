use anyhow::Result;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbRlsPolicy {
    pub table: String,
    pub name: String,
    pub command: String, // SELECT, INSERT, UPDATE, DELETE, ALL
    pub permissive: bool,
    pub using_expr: Option<String>,
    pub check_expr: Option<String>,
    /// True when the policy carries the Supatype managed marker comment.
    /// Ownership must not be inferred from the name: a user-written policy that
    /// happens to match `{table}_{op}` would otherwise be silently replaced, and
    /// one that doesn't would be silently dropped.
    #[serde(default)]
    pub managed: bool,
}

pub async fn read(conn: &mut PgConnection, schema: &str) -> Result<Vec<DbRlsPolicy>> {
    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        String,
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT c.relname, p.polname, p.polcmd::text,
                    p.polpermissive,
                    pg_get_expr(p.polqual, p.polrelid),
                    pg_get_expr(p.polwithcheck, p.polrelid),
                    obj_description(p.oid, 'pg_policy')
             FROM pg_policy p
             JOIN pg_class c ON c.oid = p.polrelid
             JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = $1
             ORDER BY c.relname, p.polname",
    )
    .bind(schema)
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows
        .into_iter()
        .map(
            |(table, name, command, permissive, using_expr, check_expr, comment)| DbRlsPolicy {
                table,
                name,
                command,
                permissive,
                using_expr,
                check_expr,
                managed: crate::managed::is_managed_comment(comment.as_deref()),
            },
        )
        .collect())
}

/// Tables with `relrowsecurity` set.
///
/// RLS-enabled state cannot be inferred from the policy list: a table with RLS
/// on and zero policies (deny-all, the default for a model that declares no
/// access rules) has no policies at all, so a policy-based guess would report it
/// disabled forever and the differ would re-emit ENABLE ROW LEVEL SECURITY on
/// every push.
pub async fn read_rls_enabled_tables(conn: &mut PgConnection, schema: &str) -> Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT c.relname
             FROM pg_class c
             JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = $1 AND c.relkind = 'r' AND c.relrowsecurity
             ORDER BY c.relname",
    )
    .bind(schema)
    .fetch_all(&mut *conn)
    .await?;

    Ok(rows.into_iter().map(|(name,)| name).collect())
}
