//! Plan section 9, Phase 3 acceptance: the kitchen sink pushes, doctor reports nothing, and a
//! second push applies nothing.

mod common;

use common::{exec, push};
use supatype_engine::{differ::doctor, introspector, ledger, parser, push as orchestrator};

#[tokio::test]
async fn the_kitchen_sink_pushes_clean_and_a_second_push_does_nothing() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE SCHEMA IF NOT EXISTS auth;
             CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT UNIQUE);",
        )
        .await
        .unwrap();
        let ast = parser::parse(include_str!("fixtures/kitchen_sink_example.json")).unwrap();

        let first = push(&pool, &ast).await.unwrap();
        assert!(
            matches!(first, orchestrator::Outcome::Applied { .. }),
            "{first:?}"
        );

        let db = introspector::introspect(&pool, "public").await.unwrap();
        let catalog = introspector::introspect_catalog(&pool, "public").await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        let rows = ledger::load(&mut conn).await.unwrap();
        assert!(!rows.is_empty(), "the kitchen sink has checks to record");
        let report = doctor::report(&ast, &db, &catalog, &rows).unwrap();
        assert!(
            report.missing.is_empty()
                && report.stale_managed.is_empty()
                && report.unmanaged_drift.is_empty(),
            "doctor after a push must find nothing: {report:#?}"
        );

        let second = push(&pool, &ast).await.unwrap();
        assert!(
            matches!(second, orchestrator::Outcome::UpToDate { .. }),
            "{second:?}"
        );
    })
    .await;
}
