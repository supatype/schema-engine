//! Generates auth helper SQL functions for per-project RLS support.
//!
//! These functions are created in the developer's schema during provisioning
//! and are used by RLS policies to extract information from the JWT set by PostgREST.
//!
//! PostgREST sets `request.jwt.claims` as a GUC on each request.

use serde::{Deserialize, Serialize};

/// Configuration for auth function generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFunctionConfig {
    /// Project reference (e.g., "kxv4m2np")
    pub project_ref: String,
    /// Schema where auth functions are created (default: "auth")
    pub auth_schema: String,
}

impl Default for AuthFunctionConfig {
    fn default() -> Self {
        Self {
            project_ref: String::new(),
            auth_schema: "auth".to_string(),
        }
    }
}

/// Generate all auth helper functions for a project.
pub fn generate_auth_functions(config: &AuthFunctionConfig) -> String {
    let mut sql = String::new();

    sql.push_str(&format!(
        "-- Auth helper functions for project: {}\n",
        config.project_ref
    ));
    sql.push_str(&format!(
        "CREATE SCHEMA IF NOT EXISTS {};\n\n",
        config.auth_schema
    ));

    sql.push_str(&generate_uid_function(&config.auth_schema));
    sql.push_str("\n\n");
    sql.push_str(&generate_role_function(
        &config.auth_schema,
        &config.project_ref,
    ));
    sql.push_str("\n\n");
    sql.push_str(&generate_email_function(&config.auth_schema));
    sql.push_str("\n\n");
    sql.push_str(&generate_jwt_function(&config.auth_schema));
    sql.push_str("\n\n");
    sql.push_str(&generate_claim_function(&config.auth_schema));

    sql
}

/// auth.uid() — extracts the user ID (sub claim) from the JWT.
fn generate_uid_function(schema: &str) -> String {
    format!(
        r#"-- auth.uid() -- extracts user ID from JWT claims set by PostgREST
CREATE OR REPLACE FUNCTION {schema}.uid() RETURNS uuid AS $$
  SELECT COALESCE(
    NULLIF(
      current_setting('request.jwt.claims', true)::jsonb ->> 'sub',
      ''
    )::uuid,
    '00000000-0000-0000-0000-000000000000'::uuid
  );
$$ LANGUAGE sql STABLE;"#,
        schema = schema
    )
}

/// auth.role() — extracts the role from JWT claims (self-host / dedicated cloud).
fn generate_role_function(schema: &str, _project_ref: &str) -> String {
    format!(
        r#"-- auth.role() -- application role for access rules.
--
-- Reads `app_metadata.role` first, falling back to the top-level `role` claim.
-- The top-level claim is the one PostgREST uses to pick the Postgres role it
-- runs the request as, so it can only ever be anon / authenticated /
-- service_role; application roles (admin, editor, etc.) live in app_metadata,
-- which only the Auth admin API can write -- never `user_metadata`, which the
-- user can edit themselves.
CREATE OR REPLACE FUNCTION {schema}.role() RETURNS text AS $$
  SELECT COALESCE(
    current_setting('request.jwt.claims', true)::jsonb -> 'app_metadata' ->> 'role',
    current_setting('request.jwt.claims', true)::jsonb ->> 'role',
    'anon'
  );
$$ LANGUAGE sql STABLE;"#,
        schema = schema
    )
}

/// auth.email() — extracts the email from the JWT claims.
fn generate_email_function(schema: &str) -> String {
    format!(
        r#"-- auth.email() -- extracts email from JWT claims
CREATE OR REPLACE FUNCTION {schema}.email() RETURNS text AS $$
  SELECT COALESCE(
    current_setting('request.jwt.claims', true)::jsonb ->> 'email',
    ''
  );
$$ LANGUAGE sql STABLE;"#,
        schema = schema
    )
}

/// auth.claim(path) — reads a nested JWT claim by dotted path.
///
/// `Claim<"app_metadata.tier">` in a schema compiles to a call here. Returning
/// `jsonb` rather than `text` keeps arrays usable: a claim holding a list is what
/// membership checks like `In<"site_id", Claim<"app_metadata.sites">>` read, and
/// flattening it to text would lose that. Callers wanting a scalar cast with
/// `->>`-style semantics use `#>>`, which this mirrors.
///
/// A missing path yields SQL NULL, so a policy comparing against an absent claim
/// is false rather than an error — an unauthenticated or partial token must deny,
/// not break the query.
fn generate_claim_function(schema: &str) -> String {
    format!(
        r#"-- auth.claim(path) -- nested JWT claim by dotted path, e.g. 'app_metadata.tier'
CREATE OR REPLACE FUNCTION {schema}.claim(claim_path text) RETURNS jsonb AS $$
  SELECT COALESCE(
    current_setting('request.jwt.claims', true)::jsonb,
    '{{}}'::jsonb
  ) #> string_to_array(claim_path, '.');
$$ LANGUAGE sql STABLE;

-- auth.claim_text(path) -- the same claim as text, for scalar comparisons.
CREATE OR REPLACE FUNCTION {schema}.claim_text(claim_path text) RETURNS text AS $$
  SELECT COALESCE(
    current_setting('request.jwt.claims', true)::jsonb,
    '{{}}'::jsonb
  ) #>> string_to_array(claim_path, '.');
$$ LANGUAGE sql STABLE;"#,
        schema = schema
    )
}

/// auth.jwt() — returns the full JWT claims as JSONB.
fn generate_jwt_function(schema: &str) -> String {
    format!(
        r#"-- auth.jwt() -- returns full JWT claims as JSONB
CREATE OR REPLACE FUNCTION {schema}.jwt() RETURNS jsonb AS $$
  SELECT COALESCE(
    current_setting('request.jwt.claims', true)::jsonb,
    '{{}}'::jsonb
  );
$$ LANGUAGE sql STABLE;"#,
        schema = schema
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_auth_functions_cloud() {
        let config = AuthFunctionConfig {
            project_ref: "kxv4m2np".to_string(),
            auth_schema: "auth".to_string(),
        };
        let sql = generate_auth_functions(&config);

        assert!(sql.contains("CREATE SCHEMA IF NOT EXISTS auth;"));
        assert!(sql.contains("auth.uid()"));
        assert!(sql.contains("auth.role()"));
        assert!(sql.contains("auth.email()"));
        assert!(sql.contains("auth.jwt()"));
        // Dedicated cloud uses unprefixed JWT roles (self-host parity)
        assert!(!sql.contains("kxv4m2np_anon"));
        assert!(!sql.contains("kxv4m2np_authenticated"));
    }

    #[test]
    fn test_generate_auth_functions_self_hosted() {
        let config = AuthFunctionConfig {
            project_ref: String::new(),
            auth_schema: "auth".to_string(),
        };
        let sql = generate_auth_functions(&config);

        assert!(sql.contains("auth.uid()"));
        assert!(sql.contains("auth.role()"));
        assert!(!sql.contains("_anon"));
    }

    #[test]
    fn test_uid_returns_uuid() {
        let sql = generate_uid_function("auth");
        assert!(sql.contains("RETURNS uuid"));
        assert!(sql.contains("request.jwt.claims"));
        assert!(sql.contains("sub"));
    }

    #[test]
    fn test_role_prefers_app_metadata_over_postgrest_role_claim() {
        let sql = generate_role_function("auth", "abc123");
        let app_idx = sql.find("'app_metadata' ->> 'role'").expect("app_metadata lookup");
        let claim_idx = sql.find("::jsonb ->> 'role'").expect("top-level role fallback");
        assert!(
            app_idx < claim_idx,
            "app role must take precedence over the PostgREST role claim",
        );
        // user_metadata is user-writable and must never grant authorization.
        // (Checks for a JSON key lookup, not the word in the explanatory comment.)
        assert!(!sql.contains("'user_metadata'"));
    }

    #[test]
    fn test_role_unprefixed() {
        let sql = generate_role_function("auth", "abc123");
        assert!(!sql.contains("abc123_anon"));
        assert!(sql.contains("request.jwt.claims"));
    }
}
