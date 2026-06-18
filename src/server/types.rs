use serde::{Deserialize, Serialize};

// ── Request types ───────────────────────────────────────────────────────────

/// Request body for endpoints that only need a schema AST (no DB).
#[derive(Deserialize)]
pub struct AstRequest {
    pub ast: serde_json::Value,
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
    #[serde(default)]
    pub yes: bool,
}

fn default_schema() -> String {
    "public".to_string()
}

/// Request body for /validate endpoint.
#[derive(Deserialize)]
pub struct ValidateRequest {
    pub diff: serde_json::Value,
    #[serde(default)]
    pub database_url: Option<String>,
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

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
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
