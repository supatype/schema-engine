use anyhow::Result;

use crate::parser::ast::SsoConfigAst;

/// Generate the full `_sso` schema DDL: schema creation, all five `oauth_*`
/// tables, indexes, and RLS policies.
///
/// The output is idempotent (all statements use `IF NOT EXISTS` or `IF NOT
/// EXISTS` guards) and can be applied repeatedly without error.
pub fn generate(sso: &SsoConfigAst) -> Result<String> {
    if !sso.enabled {
        return Ok(String::new());
    }

    let mut out = String::new();

    out.push_str(&schema_ddl());
    out.push_str(&oauth_clients_ddl());
    out.push_str(&oauth_authorization_codes_ddl());
    out.push_str(&oauth_access_tokens_ddl());
    out.push_str(&oauth_refresh_tokens_ddl());
    out.push_str(&oauth_consents_ddl());
    out.push_str(&rls_policies());

    Ok(out)
}

// ─── Schema ───────────────────────────────────────────────────────────────────

fn schema_ddl() -> String {
    "-- _sso schema\nCREATE SCHEMA IF NOT EXISTS _sso;\n\n".to_string()
}

// ─── Tables ───────────────────────────────────────────────────────────────────

fn oauth_clients_ddl() -> String {
    r#"-- OAuth2 client registrations
CREATE TABLE IF NOT EXISTS _sso.oauth_clients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_secret       TEXT NOT NULL,
    name                TEXT NOT NULL,
    redirect_uris       TEXT[] NOT NULL DEFAULT '{}',
    allowed_scopes      TEXT[] NOT NULL DEFAULT '{"openid","profile","email"}',
    eligible_roles      TEXT[],
    eligible_rules      JSONB,
    eligible_function   TEXT,
    logo_url            TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by          UUID REFERENCES auth.users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS oauth_clients_created_by_idx ON _sso.oauth_clients (created_by);

"#
    .to_string()
}

fn oauth_authorization_codes_ddl() -> String {
    r#"-- Single-use authorization codes (PKCE, 10-minute expiry)
CREATE TABLE IF NOT EXISTS _sso.oauth_authorization_codes (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code             TEXT NOT NULL UNIQUE,
    client_id        UUID NOT NULL REFERENCES _sso.oauth_clients(id) ON DELETE CASCADE,
    user_id          UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    scopes           TEXT[] NOT NULL DEFAULT '{}',
    redirect_uri     TEXT NOT NULL,
    code_challenge   TEXT,
    expires_at       TIMESTAMPTZ NOT NULL,
    used             BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS oauth_authorization_codes_code_idx ON _sso.oauth_authorization_codes (code);
CREATE INDEX IF NOT EXISTS oauth_authorization_codes_user_id_idx ON _sso.oauth_authorization_codes (user_id);

"#
    .to_string()
}

fn oauth_access_tokens_ddl() -> String {
    r#"-- Issued access tokens (JWT; record kept for revocation)
CREATE TABLE IF NOT EXISTS _sso.oauth_access_tokens (
    token_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id   UUID NOT NULL REFERENCES _sso.oauth_clients(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS oauth_access_tokens_user_id_idx ON _sso.oauth_access_tokens (user_id);
CREATE INDEX IF NOT EXISTS oauth_access_tokens_client_user_idx ON _sso.oauth_access_tokens (client_id, user_id);

"#
    .to_string()
}

fn oauth_refresh_tokens_ddl() -> String {
    r#"-- Opaque refresh tokens (stored hashed; single-use rotation)
CREATE TABLE IF NOT EXISTS _sso.oauth_refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token       TEXT NOT NULL UNIQUE,
    client_id   UUID NOT NULL REFERENCES _sso.oauth_clients(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_token_idx ON _sso.oauth_refresh_tokens (token);
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_user_id_idx ON _sso.oauth_refresh_tokens (user_id);

"#
    .to_string()
}

fn oauth_consents_ddl() -> String {
    r#"-- User consent records — tracks which users have approved which clients
CREATE TABLE IF NOT EXISTS _sso.oauth_consents (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    client_id   UUID NOT NULL REFERENCES _sso.oauth_clients(id) ON DELETE CASCADE,
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT oauth_consents_user_client_unique UNIQUE (user_id, client_id)
);
CREATE INDEX IF NOT EXISTS oauth_consents_user_id_idx ON _sso.oauth_consents (user_id);

"#
    .to_string()
}

// ─── RLS ─────────────────────────────────────────────────────────────────────

fn rls_policies() -> String {
    r#"-- RLS: enable on user-facing tables
ALTER TABLE _sso.oauth_access_tokens  ENABLE ROW LEVEL SECURITY;
ALTER TABLE _sso.oauth_refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE _sso.oauth_consents       ENABLE ROW LEVEL SECURITY;

-- Users may only read their own access tokens
CREATE POLICY IF NOT EXISTS oauth_access_tokens_select
    ON _sso.oauth_access_tokens FOR SELECT
    USING (user_id = auth.uid());

-- Users may revoke (delete) their own access tokens
CREATE POLICY IF NOT EXISTS oauth_access_tokens_delete
    ON _sso.oauth_access_tokens FOR DELETE
    USING (user_id = auth.uid());

-- Users may only read their own refresh tokens
CREATE POLICY IF NOT EXISTS oauth_refresh_tokens_select
    ON _sso.oauth_refresh_tokens FOR SELECT
    USING (user_id = auth.uid());

-- Users may revoke (delete) their own refresh tokens
CREATE POLICY IF NOT EXISTS oauth_refresh_tokens_delete
    ON _sso.oauth_refresh_tokens FOR DELETE
    USING (user_id = auth.uid());

-- Users may view their own consent records
CREATE POLICY IF NOT EXISTS oauth_consents_select
    ON _sso.oauth_consents FOR SELECT
    USING (user_id = auth.uid());

-- Users may revoke (delete) their own consents
CREATE POLICY IF NOT EXISTS oauth_consents_delete
    ON _sso.oauth_consents FOR DELETE
    USING (user_id = auth.uid());
"#
    .to_string()
}
