use serde::{Deserialize, Serialize};

// ── Request types ───────────────────────────────────────────────────────────

/// Request body for endpoints that only need a schema AST (no DB).
#[derive(Deserialize)]
pub struct AstRequest {
    pub ast: serde_json::Value,
    /// Schema Supatype manages. Defaults to `public`, so an older client keeps working; the DB
    /// endpoints have always carried this, and the previews rendered `public` regardless.
    #[serde(default = "default_schema", deserialize_with = "plain_schema")]
    pub schema: String,
}

/// Request body for /generate endpoint.
#[derive(Deserialize)]
pub struct GenerateRequest {
    pub ast: serde_json::Value,
    #[serde(default = "default_lang")]
    pub lang: String,
}

fn default_lang() -> String {
    "typescript".to_string()
}

/// Request body for DB-dependent endpoints (diff, migrate, introspect, push).
#[derive(Deserialize)]
pub struct DbRequest {
    #[serde(default)]
    pub ast: Option<serde_json::Value>,
    /// Ignored when `DATABASE_URL` is set on the engine process (trusted-proxy mode).
    #[serde(default)]
    pub database_url: Option<String>,
    #[serde(default = "default_schema", deserialize_with = "plain_schema")]
    pub schema: String,
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub non_interactive: bool,
    #[serde(default)]
    pub no_cache: bool,
    #[serde(default)]
    pub strict: bool,
    /// For `push`: put back access changed outside Supatype (plan 3.5). Without it, a push that
    /// would have to refuses instead. Push only: `doctor` refuses it.
    #[serde(default)]
    pub overwrite_drift: bool,
    /// For `migrate`: rehearse the push so the file also records the history and the ledger,
    /// under the table locks a push takes. Without it the file is planned with no such lock.
    #[serde(default)]
    pub record: bool,
    /// For `doctor` with `rebaseline`: record drift on access as the baseline too, which is
    /// otherwise refused and listed.
    #[serde(default)]
    pub accept_access_drift: bool,
    #[serde(default)]
    pub yes: bool,
    /// For `adopt`: objects every push should leave alone, as `kind:table.name` (plan section 8).
    #[serde(default)]
    pub release: Vec<String>,
    /// For `adopt`: released objects to hand back to Supatype, named the same way.
    #[serde(default)]
    pub reclaim: Vec<String>,
    /// For `adopt` with `yes`: the conflicts the preview listed, named the same way. Only these are
    /// adopted, and nothing is if one is no longer a conflict. Absent, every conflict found is.
    /// For `doctor` with `rebaseline`: the drifted objects the preview listed. The rebaseline
    /// records only if the drift it finds is exactly these, and otherwise answers 409
    /// `drift_changed` with `unseen` and `gone`. Absent, whatever drift there is is recorded.
    #[serde(default)]
    pub keys: Option<Vec<String>>,
    /// For `doctor`: record the drift it finds as the new baseline (plan 3.2).
    #[serde(default)]
    pub rebaseline: bool,
    #[serde(default)]
    pub schema_sources_base64: Option<String>,
    #[serde(default)]
    pub schema_sources_manifest: Option<serde_json::Value>,
    /// For `push`, the audit trail: who pushed (`pushed_by`), through what (`pushed_via`: `cli`,
    /// `studio`, `cloud` or `self-host`, anything else refused), from where (`pushed_from`, a host
    /// or CI run), and whether a control plane authenticated the author (`pushed_by_verified`).
    /// Recorded on the migration row. A control plane sets the author from its own authentication.
    #[serde(flatten)]
    pub audit: crate::state::audit::PushAudit,
}

fn default_schema() -> String {
    "public".to_string()
}

/// A `schema` or `auth_schema` that is a plain identifier, refused otherwise before anything runs
/// (Q1, Q3): see [`crate::sql_quote::plain_schema_name`].
fn plain_schema<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let name = String::deserialize(deserializer)?;
    crate::sql_quote::plain_schema_name(&name).map_err(serde::de::Error::custom)?;
    Ok(name)
}

/// Request body for /auth-functions endpoint.
#[derive(Deserialize)]
pub struct AuthFunctionsRequest {
    #[serde(default)]
    pub project_ref: String,
    #[serde(default = "default_auth_schema", deserialize_with = "plain_schema")]
    pub auth_schema: String,
}

fn default_auth_schema() -> String {
    "auth".to_string()
}

/// Studio reads persisted AdminConfig from the DB (single-tenant: URL from env or body).
#[derive(Deserialize)]
pub struct StudioConfigRequest {
    #[serde(default)]
    pub database_url: Option<String>,
    #[serde(default = "default_schema", deserialize_with = "plain_schema")]
    pub schema: String,
}

/// Arbitrary SQL for dev/self-host Studio tools. `database_url` should be omitted in production
/// (set `DATABASE_URL` on the engine); never pass untrusted URLs from browsers.
#[derive(Deserialize)]
pub struct SqlExecRequest {
    pub query: String,
    #[serde(default)]
    pub database_url: Option<String>,
}

// ── Response types ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

#[derive(Serialize, Default)]
pub struct ErrorResponse {
    pub error: String,
    /// A stable name for a refusal a caller can act on, such as `unmanaged_model_tables`
    /// (`crate::refusal`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// What the refusal names beside its reason, as fields of the response: `tables`, `objects`,
    /// `unseen` and `gone`, `table` and `holders`, `failures`, `migration`.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Serialize)]
pub struct SqlResponse {
    pub sql: String,
}

#[derive(Serialize)]
pub struct CodeResponse {
    pub code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlExecResponse {
    pub rows: Vec<serde_json::Value>,
    pub row_count: i64,
}
