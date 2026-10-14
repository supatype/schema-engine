//! The SQL functions access rules read the caller's JWT claims through.
//!
//! PostgREST (and Realtime and Storage, which follow it) puts the verified claims in the
//! `request.jwt.claims` setting for each request. Two sets of functions read it:
//!
//! - **The claim readers in `_supatype`** ([`CLAIMS_SCHEMA`]): `jwt_claims()`, `jwt_uid()`,
//!   `jwt_role()`, `jwt_claim(path)` and `jwt_claim_text(path)`. Everything the engine generates
//!   calls these and nothing else: row policies, the `can_*` predicates, the masking labels' and
//!   field views' expressions, storage policies and the drafts layer.
//! - **The `auth.*` helpers**: `auth.jwt()`, `auth.uid()`, `auth.role()`, `auth.email()`,
//!   `auth.claim()` and `auth.claim_text()`. Thin aliases of the readers, kept for rules people
//!   write by hand, which is what those names mean to anyone who has met them before.
//!
//! **Why the generated rules do not call `auth.*`.** The auth server owns the `auth` schema and
//! runs its own migrations there. Three of them (`20211124214934`, `20220224000811` and
//! `20220531120530` in supatype-auth) `CREATE OR REPLACE` `auth.uid()`, `auth.role()`,
//! `auth.email()` and `auth.jwt()`. On a fresh stack the engine's first push lands before the auth
//! server has migrated, so the auth server's versions replace the engine's about ten seconds later.
//! Its `auth.role()` reads only the top-level `role` claim, which PostgREST pins to `anon`,
//! `authenticated` or `service_role`, so every `Role<"admin">` rule stopped matching until a second
//! push put the engine's version back. Its `auth.jwt()` answers NULL rather than an empty object
//! for an anonymous request. Any later auth migration could do the same to any of them, so the fix
//! is that no generated rule depends on a function another component may rewrite, rather than
//! winning the race.

use serde::{Deserialize, Serialize};

use crate::generator::sql::versions::HELPER_SCHEMA;
use crate::sql_quote::{comment_text, quote_ident, quote_literal};

/// Configuration for auth function generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFunctionConfig {
    /// Project reference (e.g., "kxv4m2np")
    pub project_ref: String,
    /// Schema where the `auth.*` aliases are created (default: "auth")
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

/// The schema the `auth.*` aliases live in on every path that is not explicitly configured.
pub const AUTH_SCHEMA: &str = "auth";

/// The schema holding the claim readers: the engine's own helper schema, which nothing but the
/// engine writes to and the API never exposes.
pub const CLAIMS_SCHEMA: &str = HELPER_SCHEMA;

/// The roles PostgREST switches to per request, in the order the cloud provisioner lists them.
pub const API_ROLES: [&str; 3] = ["anon", "authenticated", "service_role"];

/// The claim readers' signatures, as `GRANT EXECUTE` names them.
pub(crate) const CLAIM_READERS: [&str; 5] = [
    "jwt_claims()",
    "jwt_uid()",
    "jwt_role()",
    "jwt_claim(text)",
    "jwt_claim_text(text)",
];

/// The dollar tag of the block granting the API roles access to the claim readers. Statement
/// attribution recognises the block by it.
pub const CLAIMS_ACCESS_TAG: &str = "claims_access";

/// The dollar tag of the block granting the API roles usage on the `auth` schema.
pub const AUTH_SCHEMA_USAGE_TAG: &str = "auth_schema_usage";

/// One `DO` block running `statements(role)` for each API role that exists.
///
/// Guarded on role existence, as `grants.rs` guards its own statements: `anon` and `authenticated`
/// belong to a deployment, and a database may legitimately have neither.
pub(crate) fn for_each_api_role(tag: &str, statements: impl Fn(&str) -> Vec<String>) -> String {
    let body: String = API_ROLES
        .iter()
        .map(|role| {
            let executes: String = statements(role)
                .iter()
                .map(|s| format!("    EXECUTE {};\n", quote_literal(s)))
                .collect();
            format!(
                "  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {}) THEN\n\
                 {executes}  END IF;\n",
                quote_literal(role)
            )
        })
        .collect();

    format!("DO ${tag}$\nBEGIN\n{body}END\n${tag}$;")
}

/// `GRANT USAGE` on the auth schema, for each API role that exists.
///
/// Creating the schema is not enough: a hand-written rule that calls an `auth.*` alias from the
/// query rather than from a policy expression runs as the caller, and a query-time call needs USAGE
/// on the function's schema.
///
/// On `supatype/postgres` the init scripts grant this at initdb, so here it is a no-op. It is
/// absent exactly where the engine created the schema itself, which is the `database.external`
/// self-host path. A caller that does not own the schema cannot grant on it, and Postgres reports
/// that as a `WARNING: no privileges were granted`, not an error.
pub fn grant_auth_schema_usage(schema: &str) -> String {
    let quoted = quote_ident(schema);
    for_each_api_role(AUTH_SCHEMA_USAGE_TAG, |role| {
        vec![format!("GRANT USAGE ON SCHEMA {quoted} TO {role}")]
    })
}

/// `GRANT USAGE` on the claims schema and `EXECUTE` on each reader, for each API role that exists.
///
/// Policies are evaluated with the table owner's privileges, but `supatype_mask` rewrites a masked
/// column into `CASE WHEN can_read_t__c(t) ...` in the target list, which runs as the caller and
/// reaches the readers directly; without these the caller gets `42501` instead of a masked value.
/// `EXECUTE` is granted by name rather than left to the `PUBLIC` default, which a hardened database
/// may have revoked. USAGE alone discloses nothing here: every table in the schema needs its own
/// grant, which none is given. `rls::generate_security_labels` checks the privilege afterwards.
fn grant_claims_access() -> String {
    let schema = quote_ident(CLAIMS_SCHEMA);
    for_each_api_role(CLAIMS_ACCESS_TAG, |role| {
        let mut statements = vec![format!("GRANT USAGE ON SCHEMA {schema} TO {role}")];
        statements.extend(
            CLAIM_READERS
                .iter()
                .map(|reader| format!("GRANT EXECUTE ON FUNCTION {schema}.{reader} TO {role}")),
        );
        statements
    })
}

/// The claim readers and their grants, which every push asserts whether or not the database has an
/// `auth` schema: the generated rules call them on a plain Postgres too.
pub fn generate_claim_readers() -> String {
    let schema = CLAIMS_SCHEMA;
    // `jwt_claims()` first: every other reader goes through it, and a `LANGUAGE sql` body is
    // validated when the function is created, so a caller emitted before its callee fails the push.
    [
        format!(
            "-- Claim readers the generated access rules call\n\
             CREATE SCHEMA IF NOT EXISTS {schema};"
        ),
        jwt_claims_reader(schema),
        jwt_uid_reader(schema),
        jwt_role_reader(schema),
        jwt_claim_readers(schema),
        grant_claims_access(),
    ]
    .join("\n\n")
}

/// Each `auth.*` alias: its name, arguments, return type and body, where `{s}` is the claims schema.
const AUTH_ALIASES: [(&str, &str, &str, &str); 6] = [
    ("jwt", "", "jsonb", "{s}.jwt_claims()"),
    ("uid", "", "uuid", "{s}.jwt_uid()"),
    ("role", "", "text", "{s}.jwt_role()"),
    (
        "email",
        "",
        "text",
        "COALESCE({s}.jwt_claims() ->> 'email', '')",
    ),
    (
        "claim",
        "claim_path text",
        "jsonb",
        "{s}.jwt_claim(claim_path)",
    ),
    (
        "claim_text",
        "claim_path text",
        "text",
        "{s}.jwt_claim_text(claim_path)",
    ),
];

/// `sql` as an engine from before the claim readers wrote the same rules, which the upgrade
/// comparison (`ledger::unrecorded`) also reads an older engine's object as, so the readers
/// replacing the helpers is not taken for a hand edit. Two forms: every reader call written as the
/// `auth.*` helper that aliases it (`_supatype.jwt_uid()` was `auth.uid()`), as the model rules
/// were; and that with a reader called alone in a subquery unwrapped too (`(SELECT
/// _supatype.jwt_uid())` was a bare `auth.uid()`), as the storage rules were.
pub fn through_auth_aliases(sql: &str) -> [String; 2] {
    let mut wrapped = sql.to_string();
    let mut bare = sql.to_string();
    for (name, _, _, body) in AUTH_ALIASES {
        let Some((reader, _)) = body.strip_prefix("{s}.").and_then(|c| c.split_once('(')) else {
            continue;
        };
        let helper = format!("{AUTH_SCHEMA}.{name}(");
        bare = bare.replace(
            &format!("(SELECT {CLAIMS_SCHEMA}.{reader}())"),
            &format!("{helper})"),
        );
        for form in [&mut wrapped, &mut bare] {
            *form = form.replace(&format!("{CLAIMS_SCHEMA}.{reader}("), &helper);
        }
    }
    [wrapped, bare]
}

/// The `auth.*` aliases, in `config.auth_schema`. They call the readers, so those must exist first.
pub fn generate_auth_aliases(config: &AuthFunctionConfig) -> String {
    let auth = &config.auth_schema;
    let header = format!(
        "-- auth.* aliases of the claim readers, for hand-written rules (project: {})\n\
         CREATE SCHEMA IF NOT EXISTS {auth};",
        comment_text(&config.project_ref)
    );
    let aliases = AUTH_ALIASES.iter().map(|(name, args, returns, body)| {
        let body = body.replace("{s}", CLAIMS_SCHEMA);
        format!(
            "CREATE OR REPLACE FUNCTION {auth}.{name}({args}) RETURNS {returns} AS $$\n  \
             SELECT {body};\n$$ LANGUAGE sql STABLE;"
        )
    });
    [header, grant_auth_schema_usage(auth)]
        .into_iter()
        .chain(aliases)
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// Generate the claim readers and the `auth.*` aliases for a project.
pub fn generate_auth_functions(config: &AuthFunctionConfig) -> String {
    format!(
        "{}\n\n{}",
        generate_claim_readers(),
        generate_auth_aliases(config)
    )
}

/// `jwt_claims()`: the verified claims, and the one place they are read.
///
/// **Every other reader goes through this**, which is what makes the guard below worth having
/// rather than repeating: `current_setting(..., true)` returns NULL when the setting is unset but
/// the empty string when something has set it to one, and `''::jsonb` raises `22P02`. Seven
/// functions each carried their own copy of the unguarded cast, so any request that arrived with an
/// empty claims setting failed with a JSON syntax error instead of reading as anonymous.
fn jwt_claims_reader(schema: &str) -> String {
    format!(
        r#"-- jwt_claims(): the verified claims, or an empty object for an anonymous request.
CREATE OR REPLACE FUNCTION {schema}.jwt_claims() RETURNS jsonb AS $$
  SELECT COALESCE(
    NULLIF(current_setting('request.jwt.claims', true), '')::jsonb,
    '{{}}'::jsonb
  );
$$ LANGUAGE sql STABLE;"#
    )
}

/// `jwt_uid()`: the caller's user id, or NULL when the request has no subject.
///
/// **NULL, not the nil UUID.** It used to fall back to `00000000-0000-0000-0000-000000000000`, and
/// that is a hole rather than a convenience: any rule shaped `column = uid` then matches for
/// *every* subject-less caller wherever that column can hold the nil UUID, and a column holds it
/// exactly when a subject-less writer stamped it, which is what a `service_role` write is. So a row
/// written through the admin API became readable by anyone whose token carried no `sub`.
///
/// NULL can only ever deny more: `x = uid` matches nothing and `NOT (x = uid)` is NULL, which
/// denies. A `DEFAULT` of it on a `NOT NULL` column refuses an anonymous insert instead of letting
/// it claim ownership of the row. It is also what `auth.uid()` means everywhere else people have
/// met it, so a rule copied in from a Supabase project behaves the way its author expected.
fn jwt_uid_reader(schema: &str) -> String {
    format!(
        r#"-- jwt_uid(): the caller's user id, or NULL when the request has no subject.
CREATE OR REPLACE FUNCTION {schema}.jwt_uid() RETURNS uuid AS $$
  SELECT NULLIF({schema}.jwt_claims() ->> 'sub', '')::uuid;
$$ LANGUAGE sql STABLE;"#
    )
}

/// `jwt_role()`: the application role a `Role<...>` rule compares against.
fn jwt_role_reader(schema: &str) -> String {
    format!(
        r#"-- jwt_role(): application role for access rules.
--
-- Reads `app_metadata.role` first, falling back to the top-level `role` claim.
-- The top-level claim is the one PostgREST uses to pick the Postgres role it
-- runs the request as, so it can only ever be anon / authenticated /
-- service_role; application roles (admin, editor, etc.) live in app_metadata,
-- which only the Auth admin API can write. Never `user_metadata`, which the
-- user can edit themselves.
CREATE OR REPLACE FUNCTION {schema}.jwt_role() RETURNS text AS $$
  SELECT COALESCE(
    {schema}.jwt_claims() -> 'app_metadata' ->> 'role',
    {schema}.jwt_claims() ->> 'role',
    'anon'
  );
$$ LANGUAGE sql STABLE;"#
    )
}

/// `jwt_claim(path)` and `jwt_claim_text(path)`: a nested claim by dotted path.
///
/// `Claim<"app_metadata.tier">` in a schema compiles to a call here. Returning `jsonb` rather than
/// `text` keeps arrays usable: a claim holding a list is what membership checks like
/// `In<"site_id", Claim<"app_metadata.sites">>` read, and flattening it to text would lose that.
/// Callers wanting a scalar use the text form, which mirrors `#>>`.
///
/// A missing path yields SQL NULL, so a policy comparing against an absent claim is false rather
/// than an error: an unauthenticated or partial token must deny, not break the query.
fn jwt_claim_readers(schema: &str) -> String {
    format!(
        r#"-- jwt_claim(path): nested JWT claim by dotted path, e.g. 'app_metadata.tier'.
CREATE OR REPLACE FUNCTION {schema}.jwt_claim(claim_path text) RETURNS jsonb AS $$
  SELECT {schema}.jwt_claims() #> string_to_array(claim_path, '.');
$$ LANGUAGE sql STABLE;

-- jwt_claim_text(path): the same claim as text, for scalar comparisons.
CREATE OR REPLACE FUNCTION {schema}.jwt_claim_text(claim_path text) RETURNS text AS $$
  SELECT {schema}.jwt_claims() #>> string_to_array(claim_path, '.');
$$ LANGUAGE sql STABLE;"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_sql() -> String {
        generate_auth_functions(&AuthFunctionConfig::default())
    }

    // Creating the schema without granting usage on it leaves the aliases unreachable from a
    // query. Guarded on the role existing, because a database may have neither.
    #[test]
    fn creating_the_auth_schema_grants_usage_on_it() {
        let sql = default_sql();

        for role in API_ROLES {
            assert!(
                sql.contains(&format!("GRANT USAGE ON SCHEMA \"auth\" TO {role}")),
                "no usage grant for {role}:\n{sql}"
            );
        }
        assert!(
            sql.contains("IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon')"),
            "the grant was not guarded on the role existing:\n{sql}"
        );
        let schema_at = sql
            .find("CREATE SCHEMA IF NOT EXISTS auth")
            .expect("schema");
        let grant_at = sql.find("GRANT USAGE ON SCHEMA \"auth\"").expect("grant");
        assert!(
            schema_at < grant_at,
            "granted on the schema before creating it:\n{sql}"
        );
    }

    // A masked column's predicate runs as the caller and calls the readers, so every API role
    // needs USAGE on their schema and EXECUTE on each of them.
    #[test]
    fn the_api_roles_can_reach_every_claim_reader() {
        let sql = generate_claim_readers();
        for role in API_ROLES {
            assert!(
                sql.contains(&format!("GRANT USAGE ON SCHEMA \"_supatype\" TO {role}")),
                "no usage on the claims schema for {role}:\n{sql}"
            );
            for reader in CLAIM_READERS {
                assert!(
                    sql.contains(&format!(
                        "GRANT EXECUTE ON FUNCTION \"_supatype\".{reader} TO {role}"
                    )),
                    "{role} cannot execute {reader}:\n{sql}"
                );
            }
        }
        // Every name granted is a function this script defines.
        for reader in CLAIM_READERS {
            let name = reader.split('(').next().unwrap_or(reader);
            assert!(
                sql.contains(&format!("FUNCTION _supatype.{name}(")),
                "{reader} is granted but not defined:\n{sql}"
            );
        }
    }

    // A non-default auth schema still gets the grant, quoted.
    #[test]
    fn a_configured_auth_schema_is_granted_and_quoted() {
        let config = AuthFunctionConfig {
            project_ref: String::new(),
            auth_schema: "project_auth".to_string(),
        };
        let sql = generate_auth_functions(&config);
        assert!(
            sql.contains("GRANT USAGE ON SCHEMA \"project_auth\" TO authenticated"),
            "configured schema was not granted:\n{sql}"
        );
        assert!(sql.contains("FUNCTION project_auth.role()"));
    }

    #[test]
    fn test_generate_auth_functions_cloud() {
        let config = AuthFunctionConfig {
            project_ref: "kxv4m2np".to_string(),
            auth_schema: "auth".to_string(),
        };
        let sql = generate_auth_functions(&config);

        assert!(sql.contains("CREATE SCHEMA IF NOT EXISTS auth;"));
        for alias in [
            "uid()",
            "role()",
            "email()",
            "jwt()",
            "claim(",
            "claim_text(",
        ] {
            assert!(
                sql.contains(&format!("FUNCTION auth.{alias}")),
                "auth.{alias} is no longer installed:\n{sql}"
            );
        }
        // Dedicated cloud uses unprefixed JWT roles (self-host parity)
        assert!(!sql.contains("kxv4m2np_anon"));
        assert!(!sql.contains("kxv4m2np_authenticated"));
    }

    // The aliases read nothing themselves: each is one call into the readers, so the auth server
    // replacing one changes what a hand-written rule sees and nothing the engine generated.
    #[test]
    fn every_auth_alias_delegates_to_a_claim_reader() {
        let sql = generate_auth_aliases(&AuthFunctionConfig::default());
        assert!(
            !sql.contains("current_setting"),
            "an alias reads the claims itself:\n{sql}"
        );
        for (alias, reader) in [
            ("jwt()", "_supatype.jwt_claims()"),
            ("uid()", "_supatype.jwt_uid()"),
            ("role()", "_supatype.jwt_role()"),
            ("claim(claim_path text)", "_supatype.jwt_claim(claim_path)"),
            (
                "claim_text(claim_path text)",
                "_supatype.jwt_claim_text(claim_path)",
            ),
        ] {
            let at = sql
                .find(&format!("FUNCTION auth.{alias}"))
                .unwrap_or_else(|| panic!("auth.{alias} missing"));
            let body_end = sql[at..].find("LANGUAGE sql").expect("body end") + at;
            assert!(
                sql[at..body_end].contains(&format!("SELECT {reader};")),
                "auth.{alias} does not delegate to {reader}:\n{}",
                &sql[at..body_end]
            );
        }
    }

    #[test]
    fn test_uid_returns_uuid() {
        let sql = jwt_uid_reader("_supatype");
        assert!(sql.contains("RETURNS uuid"));
        assert!(sql.contains("'sub'"));
        // Through `jwt_claims()` rather than reading the setting itself. One guarded accessor is
        // what stops a second reader growing its own idea of what an absent claim means: the
        // nil-UUID fallback that used to live here made every subject-less caller look like the
        // same user.
        assert!(sql.contains("_supatype.jwt_claims()"));
        assert!(!sql.contains("current_setting"));
    }

    #[test]
    fn test_role_prefers_app_metadata_over_postgrest_role_claim() {
        let sql = jwt_role_reader("_supatype");
        let app_idx = sql
            .find("'app_metadata' ->> 'role'")
            .expect("app_metadata lookup");
        let claim_idx = sql
            .find("_supatype.jwt_claims() ->> 'role'")
            .expect("top-level role fallback");
        assert!(
            app_idx < claim_idx,
            "app role must take precedence over the PostgREST role claim",
        );
        // user_metadata is user-writable and must never grant authorization.
        // (Checks for a JSON key lookup, not the word in the explanatory comment.)
        assert!(!sql.contains("'user_metadata'"));
    }

    #[test]
    fn test_jwt_accessor_is_defined_before_its_callers() {
        // `LANGUAGE sql` bodies are parsed and their references resolved when the function is
        // created, so a function calling `jwt_claims()` fails outright if it does not exist yet.
        // The whole bundle is applied in order, which makes emission order load-bearing and
        // invisible: reorder these and the failure is at migration time, not here.
        let sql = default_sql();
        let defined = sql
            .find("FUNCTION _supatype.jwt_claims()")
            .expect("jwt_claims() must be generated");
        let readers_done = sql
            .find("FUNCTION _supatype.jwt_claim_text(")
            .expect("jwt_claim_text() must be generated");
        for caller in [
            "FUNCTION _supatype.jwt_uid()",
            "FUNCTION _supatype.jwt_role()",
            "FUNCTION _supatype.jwt_claim(",
        ] {
            let at = sql
                .find(caller)
                .unwrap_or_else(|| panic!("{caller} missing"));
            assert!(
                at > defined,
                "{caller} is created before jwt_claims() exists"
            );
        }
        for alias in [
            "FUNCTION auth.jwt()",
            "FUNCTION auth.uid()",
            "FUNCTION auth.role()",
        ] {
            let at = sql.find(alias).unwrap_or_else(|| panic!("{alias} missing"));
            assert!(
                at > readers_done,
                "{alias} is created before the readers exist"
            );
        }
    }
}
