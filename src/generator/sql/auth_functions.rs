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

    sql
}

/// auth.uid() — extracts the user ID (sub claim) from the JWT.
fn generate_uid_function(schema: &str) -> String {
    format!(
        r#"-- auth.uid() — extracts user ID from JWT claims set by PostgREST
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

/// auth.role() — extracts the role, stripping the project ref prefix.
fn generate_role_function(schema: &str, project_ref: &str) -> String {
    if project_ref.is_empty() {
        // Self-hosted mode: no prefix stripping needed
        return format!(
            r#"-- auth.role() — extracts role from JWT claims
CREATE OR REPLACE FUNCTION {schema}.role() RETURNS text AS $$
  SELECT COALESCE(
    current_setting('request.jwt.claims', true)::jsonb ->> 'role',
    'anon'
  );
$$ LANGUAGE sql STABLE;"#,
            schema = schema
        );
    }

    // Cloud mode: strip project ref prefix from role name
    format!(
        r#"-- auth.role() — extracts role from JWT claims (strips project ref prefix)
CREATE OR REPLACE FUNCTION {schema}.role() RETURNS text AS $$
  SELECT CASE current_setting('request.jwt.claims', true)::jsonb ->> 'role'
    WHEN '{ref}_anon' THEN 'anon'
    WHEN '{ref}_authenticated' THEN 'authenticated'
    ELSE COALESCE(
      current_setting('request.jwt.claims', true)::jsonb ->> 'role',
      'anon'
    )
  END;
$$ LANGUAGE sql STABLE;"#,
        ref = project_ref
    )
}

/// auth.email() — extracts the email from the JWT claims.
fn generate_email_function(schema: &str) -> String {
    format!(
        r#"-- auth.email() — extracts email from JWT claims
CREATE OR REPLACE FUNCTION {schema}.email() RETURNS text AS $$
  SELECT COALESCE(
    current_setting('request.jwt.claims', true)::jsonb ->> 'email',
    ''
  );
$$ LANGUAGE sql STABLE;"#,
        schema = schema
    )
}

/// auth.jwt() — returns the full JWT claims as JSONB.
fn generate_jwt_function(schema: &str) -> String {
    format!(
        r#"-- auth.jwt() — returns full JWT claims as JSONB
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
        assert!(sql.contains("kxv4m2np_anon"));
        assert!(sql.contains("kxv4m2np_authenticated"));
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
        // Self-hosted should NOT have ref prefix logic
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
    fn test_role_strips_prefix() {
        let sql = generate_role_function("auth", "abc123");
        assert!(sql.contains("abc123_anon"));
        assert!(sql.contains("abc123_authenticated"));
    }
}
