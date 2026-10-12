//! What `doctor` says about a database it cannot fully read, or whose engine-made objects are not
//! what the last setup left (IN-B, CC4, CC5).
//!
//! * IN-B: under another session's exclusive lock on a table, doctor waited 5 s and failed. It now
//!   reports what it could not read on that table as not checked, naming the session.
//! * CC4: Studio's objects are made by the engine's setup, which runs again only when the engine
//!   changes. One dropped by hand stays missing; doctor says so.
//! * CC5: in a copy of a database (a branch, a restore under a new name) pg_cron still runs only
//!   the jobs of the database it was set up for, so scheduled publishing is recorded and never
//!   runs. Doctor points it out.

mod common;

use std::time::{Duration, Instant};

use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use supatype_engine::{parser, parser::ast::SchemaAst};

use common::locks::side_pool;
use common::{exec, push};

fn notes() -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": [{
        "name": "Note",
        "fields": {
            "id": { "kind": "uuid", "primaryKey": true, "required": true,
                    "default": { "kind": "genRandomUuid" },
                    "annotations": { "db": { "pgType": "UUID", "unique": false } } },
            "body": { "kind": "text", "required": false,
                      "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
        },
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": { "tableName": "notes",
                                 "indexes": [{ "fields": ["body"], "unique": false, "using": "btree" }] },
                         "platform": { "access": {
                             "read": { "type": "public" },
                             "update": { "type": "authenticated" } } } } }]});
    parser::parse(&doc.to_string()).expect("fixture parses")
}

async fn hold(pool: &PgPool, lock: &str) -> (Transaction<'static, Postgres>, i32) {
    let mut tx = side_pool(pool, 1).await.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    sqlx::raw_sql(lock).execute(&mut *tx).await.unwrap();
    (tx, pid)
}

/// IN-B: doctor under another session's ACCESS EXCLUSIVE lock on a table answers, and lists that
/// table's objects as not checked, naming the session holding the lock, instead of failing.
#[tokio::test(flavor = "multi_thread")]
async fn doctor_under_an_exclusive_lock_reports_what_it_could_not_check() {
    common::with_integration_url(|url| async move {
        let pool = PgPool::connect(&url).await.unwrap();
        push(&pool, &notes()).await.unwrap();
        let (held, pid) = hold(&pool, "LOCK TABLE public.notes IN ACCESS EXCLUSIVE MODE").await;

        // As the binary and the server read a database for doctor: with the preview lock wait.
        let preview = supatype_engine::db::connect_for_preview(&url)
            .await
            .unwrap();
        let started = Instant::now();
        let report = supatype_engine::inspect::doctor(&preview, &notes(), "public", false).await;
        let took = started.elapsed();
        held.rollback().await.unwrap();
        let report = report.expect("doctor answers under the lock");
        eprintln!("doctor took {took:?}: {:#?}", report.not_checked);
        assert!(took < Duration::from_secs(15), "doctor waited {took:?}");
        assert!(
            report
                .not_checked
                .iter()
                .any(|i| i.table == "notes"
                    && i.message.contains(&format!("lock held by pid {pid}"))),
            "{:#?}",
            report.not_checked
        );
        assert!(
            report.drifted.is_empty(),
            "nothing read as drifted: {report:#?}"
        );
        assert!(
            report.missing.is_empty(),
            "nothing read as missing: {report:#?}"
        );

        // Once the lock is gone, everything is checked again.
        let report = supatype_engine::inspect::doctor(&preview, &notes(), "public", false)
            .await
            .unwrap();
        assert!(report.not_checked.is_empty(), "{:#?}", report.not_checked);
        preview.close().await;
        pool.close().await;
    })
    .await;
}

/// CC4: a Studio object dropped by hand is reported missing, saying how to make it again.
#[tokio::test(flavor = "multi_thread")]
async fn doctor_reports_a_missing_studio_object() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &notes()).await.unwrap();
        let report = common::doctor(&pool, &notes()).await;
        assert!(
            !report.missing.iter().any(|i| i.message.contains("Studio")),
            "{:#?}",
            report.missing
        );
        exec(&pool, "DROP FUNCTION supatype.db_stats()")
            .await
            .unwrap();
        let report = common::doctor(&pool, &notes()).await;
        let item = report
            .missing
            .iter()
            .find(|i| i.name.contains("db_stats"))
            .unwrap_or_else(|| panic!("{:#?}", report.missing));
        assert!(item.message.contains("Studio"), "{}", item.message);
        assert!(
            item.message.contains("engine_bootstrap"),
            "{}",
            item.message
        );
    })
    .await;
}

/// CC5: where pg_cron runs this database's jobs, doctor says nothing about scheduled publishing.
#[tokio::test(flavor = "multi_thread")]
async fn doctor_says_nothing_of_scheduling_where_pg_cron_runs_this_databases_jobs() {
    common::with_cron_database(|pool| async move {
        if exec(&pool, "CREATE EXTENSION IF NOT EXISTS pg_cron")
            .await
            .is_err()
        {
            return;
        }
        push(&pool, &notes()).await.unwrap();
        let report = common::doctor(&pool, &notes()).await;
        assert!(
            !report.notes.iter().any(|i| i.message.contains("cron")),
            "{:#?}",
            report.notes
        );
    })
    .await;
}
