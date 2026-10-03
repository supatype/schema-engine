//! Phase 1d of the managed-object ownership plan: what a full read of the database costs.
//!
//! The ledger introspects every kind and fingerprints every object on every push, and `dev` pushes
//! on every save. The plan sets a target of 500 ms on the kitchen sink and asks for it to be
//! measured before any kind moves onto the reconcile. This is that measurement, against the real
//! kitchen sink AST (nine models, three of them versioned, three buckets), and a ceiling that
//! fails the build if the read regresses by an order of magnitude.

mod common;

use std::time::{Duration, Instant};

use supatype_engine::{
    differ,
    generator::sql::{migration, triggers},
    introspector::{self, fingerprint::fingerprints},
    parser,
};

/// Loose on purpose: CI runners are slow and shared, and a timing assertion that flakes teaches
/// people to ignore it. The number that matters is printed; this catches a regression, not drift.
const CEILING: Duration = Duration::from_millis(2_000);
const TARGET: Duration = Duration::from_millis(500);

#[tokio::test]
async fn a_full_read_of_the_kitchen_sink_fits_the_budget() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(include_str!("fixtures/kitchen_sink_example.json")).unwrap();
        // The kitchen sink relates to `auth.users`, which the Postgres image creates and an
        // ephemeral test database does not.
        sqlx::raw_sql(
            "CREATE SCHEMA IF NOT EXISTS auth;
             CREATE TABLE IF NOT EXISTS auth.users (
               id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
               email TEXT UNIQUE
             );",
        )
        .execute(&pool)
        .await
        .expect("auth.users fixture applies");
        let empty = introspector::introspect(&pool, "public").await.unwrap();
        let diff = differ::diff(&ast, &empty).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql).execute(&pool).await.expect("kitchen sink applies");
        let trigger_sql = triggers::generate(&ast, "public").unwrap();
        sqlx::raw_sql(&trigger_sql).execute(&pool).await.expect("triggers apply");

        // Warm once so connection setup and plan caching are not what gets measured.
        let _ = introspector::introspect(&pool, "public").await.unwrap();
        let _ = introspector::introspect_catalog(&pool, "public").await.unwrap();

        let mut samples = Vec::new();
        let mut objects = 0;
        for _ in 0..5 {
            let started = Instant::now();
            let db = introspector::introspect(&pool, "public").await.unwrap();
            let catalog = introspector::introspect_catalog(&pool, "public").await.unwrap();
            objects = fingerprints(&db, &catalog).len();
            samples.push(started.elapsed());
        }
        samples.sort();
        let median = samples[samples.len() / 2];

        eprintln!(
            "introspection budget: {objects} objects, median {:?} over {} runs (target {:?}, ceiling {:?}); samples {:?}",
            median,
            samples.len(),
            TARGET,
            CEILING,
            samples
        );
        assert!(objects > 100, "the kitchen sink should produce well over a hundred objects");
        assert!(
            median <= CEILING,
            "a full read took {median:?}, over the {CEILING:?} ceiling"
        );
    })
    .await;
}
