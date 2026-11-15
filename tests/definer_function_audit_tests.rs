//! Nothing the engine creates in `_supatype` runs with its owner's rights for a caller who was
//! never meant to call it.
//!
//! The API roles (`anon`, `authenticated`, `service_role`) hold `USAGE` on `_supatype`: the rule
//! helpers the generated policies call live there, and a policy runs as the querying role.
//! Postgres grants `EXECUTE` on every new function to `PUBLIC`, so a `SECURITY DEFINER` function
//! in that schema is callable through the data plane by anyone with the schema's `USAGE` unless
//! the push revokes it. Such a function reads and writes past every grant and policy, so each one
//! needs the revoke, or a line in [`PUBLIC_DEFINERS`] saying why everyone may call it.
//!
//! The test pushes a schema for each feature that generates definer functions, into a database
//! where the three API roles exist and hold `USAGE` on `_supatype`, then reads `pg_proc`. A
//! function is offending when `PUBLIC` can execute it (a NULL `proacl` is the default grant, so
//! `PUBLIC` can) or `anon` or `authenticated` holds `EXECUTE` on it directly, and it is not on the
//! allowlist. An allowlist entry no push produced fails too, so the list cannot rot.

mod common;

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::parser::{self, ast::SchemaAst};

/// Definer functions in `_supatype` that `PUBLIC` may execute on purpose, as
/// `(signature, why everyone may call it)`. Empty until a function needs to be here: the default
/// is that a definer function in `_supatype` is not for everyone. A signature ending in `*` is a
/// prefix, for the functions the engine makes one of per model.
const PUBLIC_DEFINERS: &[(&str, &str)] = &[];

/// Definer functions in `_supatype` that `anon` or `authenticated` hold `EXECUTE` on through a
/// grant of their own, as `(signature, why they must)`. `PUBLIC` is revoked for every one of these;
/// the API roles are granted by name. A signature ending in `*` is a prefix.
const API_ROLE_DEFINERS: &[(&str, &str)] = &[
    (
        "_supatype.sees_all_drafts()",
        "A draft policy calls it as the querying role. Returns one boolean about the caller's own Studio membership, and runs as its owner because the membership table is unreachable through the data plane.",
    ),
    (
        "_supatype.preview_epoch()",
        "`preview_allows`, which every draft policy reaches, reads it as the querying role. An integer that only says whether a preview link was revoked.",
    ),
    (
        "_supatype.sees_draft_*",
        "The draft policy of each versioned model is `USING (sees_draft_<table>(id))`, evaluated as the querying role. It reads the model's snapshot table as its owner, and answers whether the caller may see one record.",
    ),
    (
        "_supatype.newest_created_record(text)",
        "`create_record` runs as the caller and asks for the key of the row its own insert made. Reads only the calling transaction's notes. Not granted to anon.",
    ),
    (
        "_supatype.versioned_model(text)",
        "The draft RPCs (create_draft, publish, ...) run as the caller and resolve the model's registry row through it. Returns the registry row, which holds no data. Not granted to anon.",
    ),
    (
        "_supatype.studio_creates(*",
        "Write predicates call it as the querying role to tell a Studio create from an update. It runs as its owner to read the table, and returns one boolean about the candidate row.",
    ),
];

/// Whether `signature` is named by an allowlist entry: exactly, or by prefix when it ends in `*`.
fn allowed(list: &[(&str, &str)], signature: &str) -> bool {
    list.iter().any(|(entry, _)| matches(entry, signature))
}

fn matches(entry: &str, signature: &str) -> bool {
    match entry.strip_suffix('*') {
        Some(prefix) => signature.starts_with(prefix),
        None => entry == signature,
    }
}

/// One pushed schema, named for the feature that makes it generate definer functions.
struct Scenario {
    feature: &'static str,
    /// Pushed in order; the database is fresh for each scenario.
    pushes: Vec<SchemaAst>,
    /// Statements run between the pushes.
    between: &'static str,
    /// Field rules refuse to apply without the `supatype_mask` extension.
    needs_mask: bool,
}

fn fixture(json: &str) -> SchemaAst {
    parser::parse(json).expect("fixture parses")
}

/// A model with a read-everything rule and the given fields.
fn model(name: &str, table: &str, fields: Value) -> Value {
    json!({
           "name": name, "fields": fields, "options": {},
           "annotations": {
    "db": { "tableName": table, "indexes": [] },
    "platform": { "access": { "read": { "type": "public" } } }
           }
       })
}

fn uuid_field(primary_key: bool) -> Value {
    let mut field = json!({
        "kind": "uuid", "required": true,
        "annotations": { "db": { "pgType": "UUID", "unique": false, "index": false } }
    });
    if primary_key {
        field["primaryKey"] = json!(true);
        field["default"] = json!({ "kind": "genRandomUuid" });
    }
    field
}

/// Two tables and a private channel whose rules are checked by the realtime access functions.
fn realtime_channels() -> SchemaAst {
    let lots = model(
        "Lot",
        "lots",
        json!({ "id": uuid_field(true), "seller_id": uuid_field(false) }),
    );
    let watchers = model(
        "LotWatcher",
        "lot_watchers",
        json!({ "id": uuid_field(true), "lot_id": uuid_field(false), "user_id": uuid_field(false) }),
    );
    let doc = json!({
           "astVersion": 2,
           "models": [lots, watchers],
           "channels": [{
    "name": "LotChannel", "pattern": "lot:{id}",
    "params": [{ "name": "id", "type": "uuid" }],
    "access": {
    "join": { "type": "authenticated" },
    "send": { "type": "role", "roles": ["auctioneer"] },
    "track": { "type": "authenticated" }
    }
           }],
           "realtime": { "channels": "declared" }
       });
    fixture(&doc.to_string())
}

/// Rows inserted with the triggers off, as a seed or an older engine left them, so the second
/// push of the versioned blog has records to give a baseline version.
const UNVERSIONED_ROWS: &str = "
    BEGIN;
    SET LOCAL session_replication_role = replica;
    INSERT INTO posts (id, title, body, published_at)
      VALUES ('a0000000-0000-0000-0000-000000000001', 'Old', '{\"en\": \"x\"}', now());
    COMMIT;";

fn scenario(feature: &'static str, pushes: Vec<SchemaAst>) -> Scenario {
    Scenario {
        feature,
        pushes,
        between: "",
        needs_mask: false,
    }
}

fn scenarios() -> Vec<Scenario> {
    let versioned = || fixture(include_str!("fixtures/versioned_blog.json"));
    vec![
        Scenario {
            between: UNVERSIONED_ROWS,
            ..scenario(
                "versions and baseline versions",
                vec![versioned(), versioned()],
            )
        },
        scenario(
            "drafts and publishing",
            vec![fixture(include_str!("fixtures/drafts_content.json"))],
        ),
        Scenario {
            needs_mask: true,
            ..scenario(
                "field rules and field masking",
                vec![fixture(include_str!("fixtures/rls_field_rules.json"))],
            )
        },
        scenario(
            "row rules and studio members",
            vec![fixture(include_str!("fixtures/rls_access_rules.json"))],
        ),
        scenario(
            "storage buckets and versioned pages",
            vec![fixture(include_str!("fixtures/kitchen_sink_example.json"))],
        ),
        scenario("private realtime channels", vec![realtime_channels()]),
    ]
}

/// The API roles, as the database image makes them, holding `USAGE` on `_supatype`, and the
/// `auth.users` the auth server makes, which the kitchen sink's user relations need.
const GIVE_API_ROLES_USAGE: &str = "
    DO $$ BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN
        CREATE ROLE anon NOLOGIN; END IF;
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticated') THEN
        CREATE ROLE authenticated NOLOGIN; END IF;
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'service_role') THEN
        CREATE ROLE service_role NOLOGIN BYPASSRLS; END IF;
    END $$;
    CREATE SCHEMA IF NOT EXISTS auth;
    CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY);
    CREATE SCHEMA IF NOT EXISTS _supatype;
    GRANT USAGE ON SCHEMA _supatype TO anon, authenticated, service_role;";

/// Every definer function in `_supatype` that `PUBLIC`, `anon` or `authenticated` can execute
/// through a grant of its own, as `(signature, grantee)`, one row per grantee.
const GRANTEES: &str = "
    SELECT p.oid::regprocedure::text,
 CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE a.grantee::regrole::text END
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = '_supatype'
      CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
     WHERE p.prosecdef
       AND a.privilege_type = 'EXECUTE'
       AND (a.grantee = 0 OR a.grantee::regrole::text IN ('anon', 'authenticated'))
     ORDER BY 1, 2";

/// Every definer function in `_supatype`.
const DEFINERS: &str = "
    SELECT p.oid::regprocedure::text FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = '_supatype'
     WHERE p.prosecdef ORDER BY 1";

/// What the audit found across the scenarios that ran.
#[derive(Default)]
struct Findings {
    ran: usize,
    definers: Vec<String>,
    offending: Vec<String>,
}

/// Pushes the scenario and records every definer function it left and the offending ones.
async fn audit(pool: &PgPool, scenario: &Scenario, findings: &mut Findings) {
    if scenario.needs_mask && !common::mask_extension_available(pool).await {
        return;
    }
    common::exec(pool, GIVE_API_ROLES_USAGE)
        .await
        .expect("make the API roles");
    for (i, ast) in scenario.pushes.iter().enumerate() {
        if i > 0 && !scenario.between.is_empty() {
            common::exec(pool, scenario.between)
                .await
                .expect("between pushes");
        }
        common::push(pool, ast)
            .await
            .unwrap_or_else(|e| panic!("{}: push {i}: {e:#}", scenario.feature));
        // A push may create the schema afresh; the roles hold USAGE on it either way.
        common::exec(pool, GIVE_API_ROLES_USAGE)
            .await
            .expect("grant usage again");
    }
    let definers: Vec<String> = sqlx::query_scalar(DEFINERS)
        .fetch_all(pool)
        .await
        .expect("read the definer functions");
    let grants: Vec<(String, String)> = sqlx::query_as(GRANTEES)
        .fetch_all(pool)
        .await
        .expect("read the grants");
    findings.ran += 1;
    findings.definers.extend(definers);
    findings.offending.extend(
        grants
            .into_iter()
            .filter(|(sig, who)| {
                let list = if who == "PUBLIC" {
                    PUBLIC_DEFINERS
                } else {
                    API_ROLE_DEFINERS
                };
                !allowed(list, sig)
            })
            .map(|(sig, who)| format!("{}: {sig} (executable by {who})", scenario.feature)),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_definer_function_in_the_engine_schema_is_executable_by_everyone() {
    let findings: Arc<Mutex<Findings>> = Default::default();
    for scenario in scenarios() {
        let sink = findings.clone();
        common::with_integration_pool(|pool| async move {
            let mut found = Findings::default();
            audit(&pool, &scenario, &mut found).await;
            let mut all = sink.lock().unwrap();
            all.ran += found.ran;
            all.definers.extend(found.definers);
            all.offending.extend(found.offending);
        })
        .await;
    }
    let found = findings.lock().unwrap();
    if found.ran == 0 {
        return; // no database, and integration tests are not forced: skipped
    }
    assert!(
        !found.definers.is_empty(),
        "no definer function found in _supatype: the audit is looking at nothing"
    );
    assert!(
        found.offending.is_empty(),
        "SECURITY DEFINER functions in _supatype that everyone can execute. REVOKE ALL ... FROM \
 PUBLIC and GRANT EXECUTE to the roles that need it, or add the function to \
 PUBLIC_DEFINERS with the reason:\n  {}",
        found.offending.join("\n  ")
    );
    for (entry, why) in PUBLIC_DEFINERS.iter().chain(API_ROLE_DEFINERS) {
        assert!(
            found.definers.iter().any(|d| matches(entry, d)),
            "the allowlist names {entry} ({why}), which no push produced"
        );
    }
}
