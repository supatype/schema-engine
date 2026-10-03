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

use supatype_engine::{
    differ,
    generator::sql::{migration, triggers},
    introspector, parser,
};

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
/// versions tables, soft delete, the kitchen sink's lot).
const SQL_GOLDEN_FIXTURES: &[&str] = &[
    "basic_blog",
    "ecommerce",
    "five_model_blog",
    "many_to_many",
    "versioned_blog",
    "kitchen_sink_example",
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
    (
        "vector_search",
        "the hnsw index is emitted with no operator class, which pgvector requires \
         (data type vector has no default operator class for access method \"hnsw\")",
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

async fn state_json(pool: &sqlx::PgPool) -> String {
    let db = introspector::introspect(pool, "public").await.unwrap();
    let catalog = introspector::introspect_catalog(pool, "public")
        .await
        .unwrap();
    let value = serde_json::json!({ "database": db, "catalog": catalog });
    let mut text = serde_json::to_string_pretty(&value).unwrap();
    text.push('\n');
    text
}

async fn run_fixture(pool: &sqlx::PgPool, name: &str) {
    let ast = parser::parse(&fixture(name)).unwrap_or_else(|e| panic!("{name} parses: {e}"));
    create_auth_users(pool).await;

    let empty = introspector::introspect(pool, "public").await.unwrap();
    let diff = differ::diff(&ast, &empty).unwrap();
    let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
    let trigger_sql = triggers::generate(&ast, "public").unwrap();

    // A fixture that cannot be applied still asserts what it generates.
    let not_pushable = NOT_PUSHABLE.iter().find(|(n, _)| *n == name);
    if SQL_GOLDEN_FIXTURES.contains(&name) || not_pushable.is_some() {
        let full = format!("{sql}\n\n-- triggers\n{trigger_sql}");
        check_golden(
            &golden_dir().join(format!("{name}.sql")),
            &full,
            &format!("{name} SQL"),
        );
    }

    if let Some((_, why)) = not_pushable {
        eprintln!("{name}: SQL golden only, not applied: {why}");
        return;
    }

    sqlx::raw_sql(&sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{name}: migration applies: {e}"));
    sqlx::raw_sql(&trigger_sql)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{name}: triggers apply: {e}"));

    let state = state_json(pool).await;
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

    let second = differ::diff(&ast, &db).unwrap();
    assert!(
        second.operations.is_empty(),
        "{name}: a second push must plan nothing, planned {:?}",
        second.operations
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
