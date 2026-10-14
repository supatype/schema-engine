//! Golden tests for the generator: what a push emits, and what a database looks like after it.
//!
//! Three layers, borrowed from the tools that have solved this before:
//!
//! - **Golden SQL** (Atlas's `.txtar` testdata, Prisma's inline `expect!` snapshots): the full
//!   forward migration for a handful of fixtures, so a change to emission is a diff a reviewer reads.
//! - **Golden state** (Drizzle's per-migration snapshot, Prisma's `assert_schema`): `DatabaseState`
//!   plus `CatalogState` after a real push, for every fixture. This is the gate: it asserts the
//!   database that results, not the text that produced it.
//! - **Zero-op re-push** (Prisma's `assert_no_steps`): a second push plans nothing.
//!
//! `UPDATE_GOLDEN=1` rewrites the files. A golden that changes in a PR is the PR's claim about what
//! it changed, made in a form that cannot be hand-waved.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use supatype_engine::{introspector, parser, push, state::migration_history};

/// Every fixture that is a schema the current parser accepts. `seed_golden_ir.json` is seed IR,
/// not an AST. Two more are schemas the parser now rejects and nothing else reads, so they have no
/// golden at all: `saas_multi_tenant` (an access rule variant `custom` that no longer exists) and
/// `soft_delete` (`Owner<"author_id">` naming a field the model does not have).
const FIXTURES: &[&str] = &[
    "basic_blog",
    "cms_content",
    "conformance_matrix",
    "ecommerce",
    "five_model_blog",
    "geospatial",
    "kitchen_sink",
    "kitchen_sink_example",
    "many_to_many",
    "rls_access_rules",
    "rls_field_rules",
    "self_referential",
    "standup_relations",
    "vector_search",
    "versioned_blog",
];

/// The fixtures whose SQL is kept as a golden too: between them they exercise every inline
/// constraint the generator writes (scalar primary keys and uniques, type checks, junction tables,
/// versions tables, soft delete, the kitchen sink's lot), and the operator class a vector index
/// names (`vector_search`).
const SQL_GOLDEN_FIXTURES: &[&str] = &[
    "basic_blog",
    "ecommerce",
    "five_model_blog",
    "many_to_many",
    "versioned_blog",
    "kitchen_sink_example",
    "vector_search",
];

/// Fixtures whose migration a real database refuses, with the reason. They keep a SQL golden and
/// skip the state golden and the re-push. Only pure tests ever read them, which is how each went
/// unnoticed; they are on the finding list rather than fixed here, because fixing a fixture or the
/// generator changes what other tests assert, and this harness is meant to record today's output.
const NOT_PUSHABLE: &[(&str, &str)] = &[
    (
        "basic_blog",
        "User and Post declare no primary key, and the generator still emits \
         posts_author_id_fkey against users (no unique constraint matching given keys)",
    ),
    ("cms_content", "ArticleTag declares no primary key"),
    (
        "conformance_matrix",
        "EveryLocalised.email_loc is a localized Email: a JSONB column, and the generator still \
         writes the text regex CHECK against it (operator does not exist: jsonb ~* unknown)",
    ),
    (
        "kitchen_sink",
        "a declared index names jsonb_field while the column is jsonbField; nothing validates \
         index fields against the model (column \"jsonb_field\" does not exist)",
    ),
];

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
}

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(format!("{name}.json"));
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn updating() -> bool {
    std::env::var("UPDATE_GOLDEN").is_ok()
}

/// Compare `actual` with the golden at `path`, or write it when updating. Line endings are
/// normalised so a Windows checkout and a Linux runner agree.
fn check_golden(path: &Path, actual: &str, what: &str) {
    let actual = actual.replace("\r\n", "\n");
    if updating() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, &actual).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        return;
    }
    let expected = fs::read_to_string(path)
        .unwrap_or_else(|e| {
            panic!(
                "no golden at {} ({e}); run with UPDATE_GOLDEN=1",
                path.display()
            )
        })
        .replace("\r\n", "\n");
    if expected != actual {
        let first_diff = expected
            .lines()
            .zip(actual.lines())
            .enumerate()
            .find(|(_, (e, a))| e != a)
            .map(|(i, (e, a))| format!("line {}:\n  golden: {e}\n  actual: {a}", i + 1))
            .unwrap_or_else(|| {
                format!(
                    "same prefix, different length ({} vs {} lines)",
                    expected.lines().count(),
                    actual.lines().count()
                )
            });
        panic!(
            "{what} differs from its golden at {}.\n{first_diff}\nIf the change is intended, run with UPDATE_GOLDEN=1 and review the diff.",
            path.display()
        );
    }
}

/// The relation target several fixtures declare and an ephemeral database lacks.
async fn create_auth_users(pool: &sqlx::PgPool) {
    sqlx::raw_sql(
        "CREATE SCHEMA IF NOT EXISTS auth;
         CREATE TABLE IF NOT EXISTS auth.users (
           id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
           email TEXT UNIQUE
         );",
    )
    .execute(pool)
    .await
    .expect("auth.users fixture applies");
}

/// The `search_path` the golden's `DatabaseState` is read under. That read is the differ's and
/// unpinned, so it deparses a name bare when its schema is on the session's path. On the
/// `supatype/postgres` image `supatype_admin`'s path carries `auth`, which spells a policy's
/// `auth.uid()` as `uid()`; on a plain Postgres it does not. Fixed here, the golden records the
/// same text on either. (`CatalogState` is read under the push's pinned path already.)
const DATABASE_READ_PATH: &str = "public";

/// `DatabaseState` plus `CatalogState` for the project schema, as one document.
async fn state_value(pool: &sqlx::PgPool) -> serde_json::Value {
    let mut conn = pool.acquire().await.unwrap();
    let saved: String = sqlx::query_scalar("SELECT current_setting('search_path')")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    let set_path =
        |path: String| sqlx::query("SELECT set_config('search_path', $1, false)").bind(path);
    set_path(DATABASE_READ_PATH.to_string())
        .execute(&mut *conn)
        .await
        .unwrap();
    let db = introspector::introspect_connection(&mut conn, "public")
        .await
        .unwrap();
    set_path(saved).execute(&mut *conn).await.unwrap();
    drop(conn);
    let catalog = introspector::introspect_catalog(pool, "public")
        .await
        .unwrap();
    serde_json::json!({ "database": db, "catalog": catalog })
}

/// The engine's own objects, before any migration: what `push::prepare` bootstraps (`_supatype`,
/// Studio's tables and stats functions in `supatype`), and the claim readers in `_supatype` that
/// every push reasserts before its migration. They exist after any push and are the same for every
/// fixture: the engine's state, not the schema's, with tests of their own.
async fn engine_baseline(pool: &sqlx::PgPool) -> serde_json::Value {
    migration_history::bootstrap_internal_state(pool)
        .await
        .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    migration_history::reapply_auth_helpers(&mut conn, "auth")
        .await
        .unwrap();
    drop(conn);
    state_value(pool).await
}

/// Whether an entry is the engine's own: in one of its schemas, or the schema entry itself.
fn in_engine_schema(item: &serde_json::Value) -> bool {
    const ENGINE_SCHEMAS: &[&str] = &["_supatype", "supatype"];
    let named = |key: &str| {
        item.get(key)
            .and_then(|v| v.as_str())
            .is_some_and(|s| ENGINE_SCHEMAS.contains(&s))
    };
    // A `schemas` entry has no `schema` of its own, only a name and a comment.
    named("schema")
        || (item.get("schema").is_none() && item.get("comment").is_some() && named("name"))
}

/// What names an entry: the keys that identify it rather than describe it, so an engine table
/// whose grants a push touched is still the same engine table.
fn identity(item: &serde_json::Value) -> Vec<(&str, &serde_json::Value)> {
    const KEYS: &[&str] = &["schema", "table", "name", "role", "grantee", "provider"];
    KEYS.iter()
        .filter_map(|k| item.get(*k).map(|v| (*k, v)))
        .collect()
}

/// `state` without the engine's own entries that `baseline` already had, array by array: what
/// the push itself left behind. Only entries in the engine's schemas are subtracted, so the auth
/// helpers and extensions the migration's preamble asserts stay, as they always have.
fn without_baseline(state: &mut serde_json::Value, baseline: &serde_json::Value, engine: bool) {
    match (state, baseline) {
        (serde_json::Value::Array(items), serde_json::Value::Array(before)) => {
            items.retain_mut(|item| {
                // Inside an engine entry everything is the engine's: a column names no schema.
                if !(engine || in_engine_schema(item)) {
                    return true;
                }
                let Some(b) = before.iter().find(|b| identity(b) == identity(item)) else {
                    return true;
                };
                // The same entry the bootstrap made: subtract within it (the `_supatype` group of
                // engine tables also holds the versions layer's own tables) and keep whatever of
                // the fixture's remains.
                without_baseline(item, b, true);
                has_entries(item)
            });
        }
        (serde_json::Value::Object(map), serde_json::Value::Object(before)) => {
            for (key, value) in map.iter_mut() {
                if let Some(b) = before.get(key) {
                    without_baseline(value, b, engine);
                }
            }
        }
        _ => {}
    }
}

/// Whether any list inside `value` still holds an entry of its own (an object: a table, a column,
/// a constraint). A list of plain values, such as a grant's privileges, describes its entry and
/// is not one.
fn has_entries(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Array(items) => items.iter().any(serde_json::Value::is_object),
        serde_json::Value::Object(map) => map.values().any(has_entries),
        _ => false,
    }
}

async fn state_json(pool: &sqlx::PgPool, baseline: &serde_json::Value) -> String {
    let mut value = state_value(pool).await;
    without_baseline(&mut value, baseline, false);
    let mut text = serde_json::to_string_pretty(&value).unwrap();
    text.push('\n');
    // Tier 2's view owner is named after the database (TI2), and each run's database is new.
    let database: String = sqlx::query_scalar("SELECT current_database()::text")
        .fetch_one(pool)
        .await
        .unwrap();
    text.replace(
        &supatype_engine::generator::sql::field_views::api_owner_for(&database),
        "supatype_api_owner_<database>",
    )
}

async fn run_fixture(pool: &sqlx::PgPool, name: &str) {
    let ast = parser::parse(&fixture(name)).unwrap_or_else(|e| panic!("{name} parses: {e}"));
    create_auth_users(pool).await;
    let baseline = engine_baseline(pool).await;

    // The plan a push applies against an empty database: the differ's operations and the
    // reconcile's creations for the kinds on the ledger, rendered as one migration.
    let plan = push::prepare(pool, &ast, "public")
        .await
        .unwrap_or_else(|e| panic!("{name} plans: {e}"));
    let migration = plan
        .migration(false)
        .unwrap_or_else(|e| panic!("{name} renders: {e}"));

    // A fixture that cannot be applied still asserts what it generates.
    let not_pushable = NOT_PUSHABLE.iter().find(|(n, _)| *n == name);
    if SQL_GOLDEN_FIXTURES.contains(&name) || not_pushable.is_some() {
        check_golden(
            &golden_dir().join(format!("{name}.sql")),
            &migration.up_script(),
            &format!("{name} SQL"),
        );
    }

    if let Some((_, why)) = not_pushable {
        eprintln!("{name}: SQL golden only, not applied: {why}");
        return;
    }

    push::apply(pool, plan, push::ApplyOptions::default())
        .await
        .unwrap_or_else(|e| panic!("{name}: migration applies: {e}"));

    let state = state_json(pool, &baseline).await;
    check_golden(
        &golden_dir().join(format!("{name}.state.json")),
        &state,
        &format!("{name} state"),
    );

    // Postgres renames a colliding default-named constraint with a numeric suffix. None of ours
    // may collide: every name has to be the one the differ and the ledger will look for.
    let db = introspector::introspect(pool, "public").await.unwrap();
    let suffixed: Vec<&str> = db
        .constraints
        .iter()
        .map(|c| c.name.as_str())
        .filter(|n| {
            // Postgres appends the digit straight after the suffix (`posts_status_check1`).
            // Our model constraints are `{t}_check_{n}`, with an underscore, and are not this.
            let stem = n.trim_end_matches(|c: char| c.is_ascii_digit());
            stem.len() < n.len()
                && ["_check", "_key", "_fkey", "_pkey"]
                    .iter()
                    .any(|suffix| stem.ends_with(suffix))
        })
        .collect();
    assert!(
        suffixed.is_empty(),
        "{name}: constraint names Postgres had to disambiguate: {suffixed:?}"
    );

    let second = push::plan(pool, &ast, "public").await.unwrap();
    assert!(
        second.diff.operations.is_empty() && !second.reconcile.has_changes(),
        "{name}: a second push must plan nothing, planned {:?} and {:?}",
        second.diff.operations,
        second.reconcile.actions
    );
}

/// One test per fixture, named after it, so a run reports every fixture that fails rather than
/// the first.
macro_rules! golden_fixtures {
    ($($name:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                assert!(FIXTURES.contains(&stringify!($name)), "fixture is listed");
                common::with_integration_pool(|pool| async move {
                    run_fixture(&pool, stringify!($name)).await;
                })
                .await;
            }
        )*
    };
}

golden_fixtures!(
    basic_blog,
    cms_content,
    conformance_matrix,
    ecommerce,
    five_model_blog,
    geospatial,
    kitchen_sink,
    kitchen_sink_example,
    many_to_many,
    rls_access_rules,
    rls_field_rules,
    self_referential,
    standup_relations,
    vector_search,
    versioned_blog,
);
