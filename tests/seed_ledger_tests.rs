//! The seed ledger, against a real Postgres.
//!
//! The property worth proving here is the one a unit test cannot: a run that rolls back
//! must not leave a row claiming it committed. A ledger that can be confidently wrong about
//! that is worse than no ledger.

mod common;

use supatype_engine::seed::ledger::{
    already_applied, create_seeds_index_sql, create_seeds_table_sql, has_drifted, history, ir_hash,
    latest_per_file, record, record_rolled_back, RunStatus, SeedRun,
};

async fn bootstrap(pool: &sqlx::PgPool) {
    sqlx::raw_sql("CREATE SCHEMA IF NOT EXISTS _supatype")
        .execute(pool)
        .await
        .expect("schema");
    sqlx::raw_sql(&create_seeds_table_sql())
        .execute(pool)
        .await
        .expect("table");
    sqlx::raw_sql(&create_seeds_index_sql())
        .execute(pool)
        .await
        .expect("index");
}

fn run(file: &str, hash: &str, status: RunStatus) -> SeedRun {
    SeedRun {
        file: file.to_string(),
        ir_hash: hash.to_string(),
        schema_fingerprint: "sha256:schema".to_string(),
        status,
        duration_ms: 12,
        rows_written: serde_json::json!({ "Organiser": 2 }),
        error_message: None,
        engine_version: "test".to_string(),
    }
}

async fn commit_run(pool: &sqlx::PgPool, entry: &SeedRun) {
    let mut tx = pool.begin().await.expect("begin");
    record(&mut tx, entry).await.expect("records");
    tx.commit().await.expect("commit");
}

#[tokio::test]
async fn it_records_a_run_and_reads_it_back() {
    common::with_integration_pool(|pool| async move {
        bootstrap(&pool).await;
        commit_run(&pool, &run("seed.ts", "sha256:a", RunStatus::Committed)).await;

        let rows = history(&pool, "seed.ts", 10).await.expect("history");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].run.status, RunStatus::Committed);
        assert_eq!(rows[0].run.rows_written["Organiser"], 2);
        assert!(
            rows[0].applied_at.starts_with("20"),
            "applied_at reads as a timestamp: {}",
            rows[0].applied_at
        );
    })
    .await;
}

/// The property the ledger exists for.
///
/// The row is written inside the caller's transaction, so a rollback takes it too. If the
/// ledger could commit while the writes it describes did not, it would claim a seed applied
/// that never did.
#[tokio::test]
async fn a_rolled_back_transaction_leaves_no_ledger_row() {
    common::with_integration_pool(|pool| async move {
        bootstrap(&pool).await;

        let mut tx = pool.begin().await.expect("begin");
        record(&mut tx, &run("seed.ts", "sha256:a", RunStatus::Committed))
            .await
            .expect("records");
        tx.rollback().await.expect("rollback");

        let rows = history(&pool, "seed.ts", 10).await.expect("history");
        assert!(
            rows.is_empty(),
            "the ledger row must have rolled back with the writes it describes"
        );
    })
    .await;
}

/// A failed run is still recorded, on its own connection, marked as what it was.
#[tokio::test]
async fn a_failed_run_is_recorded_as_rolled_back() {
    common::with_integration_pool(|pool| async move {
        bootstrap(&pool).await;

        let mut failed = run("seed.ts", "sha256:a", RunStatus::RolledBack);
        failed.error_message = Some("Organiser.slug is already taken".to_string());
        record_rolled_back(&pool, &failed).await;

        let rows = history(&pool, "seed.ts", 10).await.expect("history");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].run.status, RunStatus::RolledBack);
        assert!(rows[0].run.error_message.is_some());
    })
    .await;
}

/// A record, not a gate: the same file runs as often as it likes.
#[tokio::test]
async fn a_file_may_be_recorded_many_times() {
    common::with_integration_pool(|pool| async move {
        bootstrap(&pool).await;
        for _ in 0..3 {
            commit_run(&pool, &run("seed.ts", "sha256:a", RunStatus::Committed)).await;
        }
        assert_eq!(
            history(&pool, "seed.ts", 10).await.expect("history").len(),
            3
        );
    })
    .await;
}

/// "This seed is not what ran" is the question the history view exists to answer.
#[tokio::test]
async fn drift_is_visible_when_the_document_changes() {
    common::with_integration_pool(|pool| async move {
        bootstrap(&pool).await;

        commit_run(&pool, &run("seed.ts", "sha256:a", RunStatus::Committed)).await;
        assert!(
            !has_drifted(&pool, "seed.ts").await.expect("drift"),
            "one run cannot have drifted"
        );

        commit_run(&pool, &run("seed.ts", "sha256:a", RunStatus::Committed)).await;
        assert!(
            !has_drifted(&pool, "seed.ts").await.expect("drift"),
            "the same document twice has not drifted"
        );

        commit_run(&pool, &run("seed.ts", "sha256:b", RunStatus::Committed)).await;
        assert!(
            has_drifted(&pool, "seed.ts").await.expect("drift"),
            "a changed document has drifted"
        );
    })
    .await;
}

/// `runOnce` asks about this exact document, not just this file: a file that changed is a
/// different backfill, and skipping it because an older version ran would be wrong.
#[tokio::test]
async fn already_applied_is_keyed_on_the_document_not_the_file() {
    common::with_integration_pool(|pool| async move {
        bootstrap(&pool).await;
        commit_run(&pool, &run("backfill.ts", "sha256:a", RunStatus::Committed)).await;

        assert!(already_applied(&pool, "backfill.ts", "sha256:a")
            .await
            .expect("applied"));
        assert!(
            !already_applied(&pool, "backfill.ts", "sha256:b")
                .await
                .expect("applied"),
            "a changed document has not been applied"
        );
    })
    .await;
}

/// A rolled-back run has not been applied, whatever its hash.
#[tokio::test]
async fn a_rolled_back_run_does_not_count_as_applied() {
    common::with_integration_pool(|pool| async move {
        bootstrap(&pool).await;
        record_rolled_back(
            &pool,
            &run("backfill.ts", "sha256:a", RunStatus::RolledBack),
        )
        .await;

        assert!(
            !already_applied(&pool, "backfill.ts", "sha256:a")
                .await
                .expect("applied"),
            "a run that rolled back did not apply"
        );
    })
    .await;
}

#[tokio::test]
async fn the_history_view_sees_the_latest_run_of_each_file() {
    common::with_integration_pool(|pool| async move {
        bootstrap(&pool).await;
        commit_run(&pool, &run("a.ts", "sha256:1", RunStatus::Committed)).await;
        commit_run(&pool, &run("b.ts", "sha256:1", RunStatus::Committed)).await;
        commit_run(&pool, &run("a.ts", "sha256:2", RunStatus::Committed)).await;

        let latest = latest_per_file(&pool).await.expect("latest");
        assert_eq!(latest.len(), 2, "one row per file");
        let a = latest.iter().find(|r| r.run.file == "a.ts").expect("a.ts");
        assert_eq!(a.run.ir_hash, "sha256:2", "the most recent run of a.ts");
    })
    .await;
}

#[tokio::test]
async fn the_hash_distinguishes_documents() {
    assert_ne!(ir_hash(r#"{"a":1}"#), ir_hash(r#"{"a":2}"#));
}
