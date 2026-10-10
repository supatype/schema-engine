use anyhow::Result;

use crate::generator::sql::rls::AUTH_UID;
use crate::parser::ast::SsoConfigAst;

/// Generate the full `_sso` schema DDL: schema creation, all five `oauth_*`
/// tables, indexes, and RLS policies.
///
/// The output is idempotent (`IF NOT EXISTS` guards, and each policy dropped
/// before it is made) and can be applied repeatedly without error.
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
    r#"-- User consent records: which users have approved which clients
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

/// Each user-facing table, and what its owner may do with their own rows: read them, and delete
/// them to revoke.
const OWNED_BY_USER: [(&str, &str); 3] = [
    ("oauth_access_tokens", "access tokens"),
    ("oauth_refresh_tokens", "refresh tokens"),
    ("oauth_consents", "consent records"),
];

/// Row-level security on the user-facing tables: a user reads and revokes only their own rows.
///
/// Dropped and made again rather than `CREATE POLICY IF NOT EXISTS`, which Postgres does not have:
/// that spelling made the whole script fail at the first policy. The caller is read through the
/// engine's own reader, not `auth.uid()`, which the auth server's migrations replace.
fn rls_policies() -> String {
    let mut out = String::from("-- RLS: enable on user-facing tables\n");
    for (table, _) in OWNED_BY_USER {
        out.push_str(&format!(
            "ALTER TABLE _sso.{table} ENABLE ROW LEVEL SECURITY;\n"
        ));
    }
    for (table, what) in OWNED_BY_USER {
        for (op, verb) in [("select", "read"), ("delete", "revoke (delete)")] {
            out.push_str(&format!(
                "\n-- Users may only {verb} their own {what}\n\
                 DROP POLICY IF EXISTS {table}_{op} ON _sso.{table};\n\
                 CREATE POLICY {table}_{op}\n    \
                 ON _sso.{table} FOR {OP}\n    \
                 USING (user_id = {AUTH_UID});\n",
                OP = op.to_uppercase(),
            ));
        }
    }
    out
}
