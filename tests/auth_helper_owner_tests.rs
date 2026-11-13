//! The `auth.*` helpers belong to whoever made them, and a push replaces only those it may.
//!
//! On Supatype Cloud the database image makes `auth.uid()` and the rest, owned by its own role, and
//! a push runs as the customer's plain login. Postgres refuses `CREATE OR REPLACE FUNCTION` on a
//! function the role does not own ("must be owner of function"), even for an identical body, so
//! every push failed. The generated rules read the claims through the engine's own `_supatype`
//! readers and never call these, so a push skips a helper it may not replace and says so, creates
//! one that is absent, and replaces one it owns or holds the owner's privileges for: on self-host
//! the push is a superuser, which replaces them all as it always did.

mod common;

use common::{ephemeral_name, exec};
use serde_json::json;
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst};

fn posts() -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": [{
        "name": "Post",
        "fields": {
            "id": { "kind": "serial", "primaryKey": true, "required": true,
                    "annotations": { "db": { "pgType": "SERIAL" } } }
        },
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": { "tableName": "posts", "indexes": [] },
                         "platform": { "access": {} } }
    }]});
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// The roles a test makes. Roles belong to the server, so the names are unique to the test.
struct Roles {
    /// Owns the `auth` schema and its helpers, as the database image's role does.
    image: String,
    /// The customer's login, which owns the database and runs the push.
    customer: String,
}

/// `url` with its user and password replaced, for connecting as another role.
fn url_as(url: &str, user: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("a URL with a scheme");
    let (_, host) = rest.split_once('@').expect("a URL with credentials");
    format!("{scheme}://{user}:{user}@{host}")
}

/// The helpers the image made, each with a body that is not the engine's, so a replacement can be
/// told from a skip.
const IMAGE_HELPERS: &str = "
    CREATE FUNCTION auth.uid() RETURNS uuid AS $$ SELECT NULL::uuid; $$ LANGUAGE sql STABLE;
    CREATE FUNCTION auth.role() RETURNS text AS $$ SELECT 'image'::text; $$ LANGUAGE sql STABLE;
    CREATE FUNCTION auth.email() RETURNS text AS $$ SELECT 'image'::text; $$ LANGUAGE sql STABLE;
    CREATE FUNCTION auth.jwt() RETURNS jsonb AS $$ SELECT NULL::jsonb; $$ LANGUAGE sql STABLE;
    CREATE FUNCTION auth.roles() RETURNS text[] AS $$ SELECT NULL::text[]; $$ LANGUAGE sql STABLE;
    CREATE FUNCTION auth.claim(claim_path text) RETURNS jsonb AS $$ SELECT NULL::jsonb; $$
        LANGUAGE sql STABLE;
    CREATE FUNCTION auth.claim_text(claim_path text) RETURNS text AS $$ SELECT NULL::text; $$
        LANGUAGE sql STABLE;";

/// A database whose `auth` schema and every one of its helpers belong to a role other than the
/// customer, which owns the database. `customer_can_create` also lets it create in `auth`.
async fn set_up(pool: &PgPool, customer_can_create: bool) -> Roles {
    let roles = Roles {
        image: ephemeral_name("st_image"),
        customer: ephemeral_name("st_cust"),
    };
    let (image, customer) = (&roles.image, &roles.customer);
    let privilege = if customer_can_create { "ALL" } else { "USAGE" };
    exec(
        pool,
        &format!(
            "CREATE ROLE {image} NOLOGIN NOSUPERUSER;
             CREATE ROLE {customer} LOGIN PASSWORD '{customer}' NOSUPERUSER;
             DO $$ BEGIN
               EXECUTE format('ALTER DATABASE %I OWNER TO {customer}', current_database());
             END $$;
             CREATE SCHEMA auth AUTHORIZATION {image};
             GRANT {privilege} ON SCHEMA auth TO {customer};
             SET ROLE {image};
             {IMAGE_HELPERS}
             RESET ROLE;"
        ),
    )
    .await
    .expect("make the image's helpers");
    roles
}

/// Hands the database back and drops what `set_up` made, so the next test starts clean.
async fn tear_down(pool: &PgPool, roles: &Roles) {
    let (image, customer) = (&roles.image, &roles.customer);
    exec(
        pool,
        &format!(
            "DO $$ BEGIN
               EXECUTE format('ALTER DATABASE %I OWNER TO %I', current_database(), current_user);
             END $$;
             REASSIGN OWNED BY {customer} TO current_user;
             DROP OWNED BY {customer};
             DROP SCHEMA auth CASCADE;
             DROP OWNED BY {image};
             DROP ROLE {customer};
             DROP ROLE {image};"
        ),
    )
    .await
    .expect("drop the test's roles");
}

/// `(owner, body)` of the function `signature` names, schema included, or `None` when it does not
/// exist.
async fn function(pool: &PgPool, signature: &str) -> Option<(String, String)> {
    sqlx::query_as(
        "SELECT pg_get_userbyid(proowner)::text, prosrc FROM pg_proc
          WHERE oid = to_regprocedure($1)",
    )
    .bind(signature)
    .fetch_optional(pool)
    .await
    .expect("read the function")
}

/// Pushes as the customer, which does not own the image's helpers: the push succeeds, the image's
/// helpers are untouched, and the engine's own readers are in place.
#[tokio::test(flavor = "multi_thread")]
async fn a_push_as_a_non_owner_skips_the_helpers_it_may_not_replace() {
    common::with_integration_url(|url| async move {
        let admin = PgPool::connect(&url).await.expect("connect as admin");
        let roles = set_up(&admin, true).await;
        let customer = PgPool::connect(&url_as(&url, &roles.customer))
            .await
            .expect("connect as the customer");
        let pushed = common::push(&customer, &posts()).await.map(|_| ());
        customer.close().await;
        let uid = function(&admin, "auth.uid()").await;
        let role = function(&admin, "auth.role()").await;
        let claim = function(&admin, "auth.claim(text)").await;
        let email = function(&admin, "auth.email()").await;
        let roles_helper = function(&admin, "auth.roles()").await;
        let reader = function(&admin, "_supatype.jwt_uid()").await;
        let customer_name = roles.customer.clone();
        tear_down(&admin, &roles).await;

        pushed.expect("a push as the customer");
        let helpers = [
            ("uid", uid),
            ("role", role),
            ("claim", claim),
            ("email", email),
            ("roles", roles_helper),
        ];
        for (name, found) in helpers {
            let (owner, body) = found.unwrap_or_else(|| panic!("auth.{name} is gone"));
            assert_ne!(owner, customer_name, "auth.{name} changed hands");
            assert!(!body.contains("_supatype"), "auth.{name} was replaced");
        }
        let (reader_owner, _) = reader.expect("the engine's reader exists");
        assert_eq!(reader_owner, customer_name);
    })
    .await;
}

/// A login that may not create in `auth` leaves an absent helper absent rather than failing.
#[tokio::test(flavor = "multi_thread")]
async fn a_push_without_create_on_auth_leaves_an_absent_helper_absent() {
    common::with_integration_url(|url| async move {
        let admin = PgPool::connect(&url).await.expect("connect as admin");
        let roles = set_up(&admin, false).await;
        exec(&admin, "DROP FUNCTION auth.email();")
            .await
            .expect("make auth.email absent");
        let customer = PgPool::connect(&url_as(&url, &roles.customer))
            .await
            .expect("connect as the customer");
        let pushed = common::push(&customer, &posts()).await.map(|_| ());
        customer.close().await;
        let email = function(&admin, "auth.email()").await;
        let uid = function(&admin, "auth.uid()").await;
        tear_down(&admin, &roles).await;

        pushed.expect("a push without create on auth");
        assert!(email.is_none(), "created without the privilege: {email:?}");
        assert!(uid.is_some_and(|(_, body)| !body.contains("_supatype")));
    })
    .await;
}

/// A login that holds the privileges of the helpers' owner replaces them, and one that may create
/// in `auth` makes the helpers that are absent.
#[tokio::test(flavor = "multi_thread")]
async fn a_push_replaces_what_it_holds_the_owners_privileges_for_and_creates_what_is_absent() {
    common::with_integration_url(|url| async move {
        let admin = PgPool::connect(&url).await.expect("connect as admin");
        let roles = set_up(&admin, true).await;
        exec(
            &admin,
            &format!(
                "GRANT {} TO {}; DROP FUNCTION auth.email();",
                roles.image, roles.customer
            ),
        )
        .await
        .expect("make the customer a member of the owner, and auth.email absent");
        let customer = PgPool::connect(&url_as(&url, &roles.customer))
            .await
            .expect("connect as the customer");
        let pushed = common::push(&customer, &posts()).await.map(|_| ());
        customer.close().await;
        let uid = function(&admin, "auth.uid()").await;
        let email = function(&admin, "auth.email()").await;
        let image = roles.image.clone();
        tear_down(&admin, &roles).await;

        pushed.expect("a push as a member of the owner");
        let (owner, body) = uid.expect("auth.uid exists");
        assert_eq!(owner, image, "replacing a function keeps its owner");
        assert!(body.contains("_supatype.jwt_uid"), "not replaced: {body}");
        assert!(email.is_some(), "an absent helper was not created");
    })
    .await;
}

/// Self-host: the push is a superuser, which replaces every helper whoever owns it, as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_superuser_push_replaces_helpers_another_role_owns() {
    common::with_integration_url(|url| async move {
        let admin = PgPool::connect(&url).await.expect("connect as admin");
        let roles = set_up(&admin, false).await;
        let pushed = common::push(&admin, &posts()).await.map(|_| ());
        let uid = function(&admin, "auth.uid()").await;
        let role = function(&admin, "auth.role()").await;
        let claim = function(&admin, "auth.claim(text)").await;
        let email = function(&admin, "auth.email()").await;
        let image = roles.image.clone();
        tear_down(&admin, &roles).await;

        pushed.expect("a superuser push");
        for (name, reader, found) in [
            ("uid", "_supatype.jwt_uid", uid),
            ("role", "_supatype.jwt_role", role),
            ("claim", "_supatype.jwt_claim(", claim),
            ("email", "_supatype.jwt_claims", email),
        ] {
            let (owner, body) = found.unwrap_or_else(|| panic!("auth.{name} is gone"));
            assert_eq!(owner, image, "auth.{name} keeps its owner");
            assert!(body.contains(reader), "auth.{name} not replaced: {body}");
        }
    })
    .await;
}
