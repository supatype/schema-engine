use serde::{Deserialize, Serialize};

// ── Request types ───────────────────────────────────────────────────────────

/// Request body for endpoints that only need a schema AST (no DB).
#[derive(Deserialize)]
pub struct AstRequest {
    pub ast: serde_json::Value,
    /// Schema Supatype manages. Defaults to `public`, so an older client keeps working; the DB
    /// endpoints have always carried this, and the previews rendered `public` regardless.
    #[serde(default = "default_schema")]
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
    #[serde(default = "default_schema")]
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
    /// Put back access changed outside Supatype (plan 3.5). Without it, a push that would have to
    /// refuses instead. For `doctor` with `rebaseline`: record drift on access as the baseline too,
    /// which is otherwise refused and listed.
    #[serde(default)]
    pub overwrite_drift: bool,
    #[serde(default)]
    pub yes: bool,
    /// For `adopt`: objects every push should leave alone, as `kind:table.name` (plan section 8).
    #[serde(default)]
    pub release: Vec<String>,
    /// For `adopt`: released objects to hand back to Supatype, named the same way.
    #[serde(default)]
    pub reclaim: Vec<String>,
    /// For `doctor`: record the drift it finds as the new baseline (plan 3.2).
    #[serde(default)]
    pub rebaseline: bool,
    #[serde(default)]
    pub schema_sources_base64: Option<String>,
    #[serde(default)]
    pub schema_sources_manifest: Option<serde_json::Value>,
}

fn default_schema() -> String {
    "public".to_string()
}

/// Request body for /auth-functions endpoint.
#[derive(Deserialize)]
pub struct AuthFunctionsRequest {
    #[serde(default)]
    pub project_ref: String,
    #[serde(default = "default_auth_schema")]
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
    #[serde(default = "default_schema")]
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
    /// A stable name for a refusal a caller can act on, such as `unmanaged_model_tables`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// The tables a refusal is about, when it is about tables.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tables: Option<Vec<String>>,
    /// The objects a refusal is about, when it is about access changed outside Supatype.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objects: Option<Vec<crate::ledger::drift::DriftedObject>>,
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
