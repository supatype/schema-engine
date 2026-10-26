//! Every writer waits as briefly for a lock as a push does (LK1).
//!
//! ENG-LOCK gave pushes a 3 s lock wait with retries; adopt, rebaseline, rollback and the
//! bootstrap kept the 30 s wait, so an application's queries could queue behind them for that
//! long. Now each waits 3 s. The ones a person runs at a prompt (adopt, rebaseline, rollback) fail
//! at once and name the session holding the lock; the bootstrap, which a push or `dev` runs, tries
//! again as a push does.

mod common;

use std::time::{Duration, Instant};

use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use supatype_engine::push::Outcome;
use supatype_engine::{parser, parser::ast::SchemaAst, state::migration_history};

use common::locks::side_pool;
use common::{exec, push};

fn widgets(extra: bool) -> SchemaAst {
    let text = json!({ "kind": "text", "required": false,
        "annotations": { "db": { "pgType": "TEXT", "unique": false } } });
    let mut fields = json!({
        "id": { "kind": "uuid", "primaryKey": true, "required": true,
                "default": { "kind": "genRandomUuid" },
                "annotations": { "db": { "pgType": "UUID", "unique": false } } },
        "label": text.clone()
    });
    if extra {
        fields["note"] = text;
    }
    let doc = json!({ "astVersion": 2, "models": [{
        "name": "Widget", "fields": fields,
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": { "tableName": "widgets", "indexes": [] },
                         "platform": { "access": {} } } }]});
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// A session holding `lock` in a transaction it leaves open, and its pid.
async fn holder(pool: &PgPool, lock: &str) -> (Transaction<'static, Postgres>, i32) {
    let mut tx = side_pool(pool, 1).await.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    sqlx::raw_sql(lock).execute(&mut *tx).await.unwrap();
    (tx, pid)
}

/// What a writer that failed fast must say: quickly, naming the holder and the operation.
fn assert_failed_fast(what: &str, took: Duration, message: &str, pid: i32) {
    eprintln!("{what} gave up after {took:?}: {message}");
    assert!(took < Duration::from_secs(10), "{what} waited {took:?}");
    assert!(message.contains(&format!("pid {pid}")), "{message}");
    assert!(message.contains(what), "{message}");
}

/// LK1: a rollback behind an application holding its table gives up after one short wait and
/// names the session holding it; nothing is rolled back.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollback_behind_an_open_reader_fails_fast_naming_the_holder() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &widgets(false)).await.unwrap();
        push(&pool, &widgets(true)).await.unwrap();
        let (reader, pid) = holder(&pool, "SELECT count(*) FROM public.widgets").await;

        let started = Instant::now();
        let err = migration_history::apply_rollback(&pool, "public")
            .await
            .expect_err("the rollback cannot drop the column while the reader holds the table");
        assert_failed_fast("rollback", started.elapsed(), &format!("{err:#}"), pid);
        reader.rollback().await.unwrap();

        let note: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns
                             WHERE table_name = 'widgets' AND column_name = 'note')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(note, "nothing was rolled back");
    })
    .await;
}

const LEDGER_LOCK: &str = "LOCK TABLE _supatype.managed_objects IN ACCESS EXCLUSIVE MODE";

/// LK1: `adopt` behind a session holding the ledger gives up after one short wait, naming it.
#[tokio::test(flavor = "multi_thread")]
async fn adopt_behind_a_held_lock_fails_fast_naming_the_holder() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &widgets(false)).await.unwrap();
        let (held, pid) = holder(&pool, LEDGER_LOCK).await;

        let started = Instant::now();
        let request = supatype_engine::adopt::Request {
            apply: true,
            ..Default::default()
        };
        let err = supatype_engine::adopt::run(&pool, &widgets(false), "public", request)
            .await
            .expect_err("adopt cannot read the ledger while it is held");
        assert_failed_fast("adopt", started.elapsed(), &format!("{err:#}"), pid);
        held.rollback().await.unwrap();
    })
    .await;
}

/// LK1: `doctor --rebaseline` behind a session holding the ledger gives up after one short wait,
/// naming it.
#[tokio::test(flavor = "multi_thread")]
async fn rebaseline_behind_a_held_lock_fails_fast_naming_the_holder() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &widgets(false)).await.unwrap();
        let (held, pid) = holder(&pool, LEDGER_LOCK).await;

        let started = Instant::now();
        let err = supatype_engine::inspect::rebaseline(&pool, &widgets(false), "public", false)
            .await
            .expect_err("rebaseline cannot read the ledger while it is held");
        assert_failed_fast("rebaseline", started.elapsed(), &format!("{err:#}"), pid);
        held.rollback().await.unwrap();
    })
    .await;
}

/// Makes the next push bootstrap again, as an engine upgrade does.
async fn as_an_older_engine_bootstrapped(pool: &PgPool) {
    exec(
        pool,
        "UPDATE _supatype.engine_bootstrap SET version = 'older' WHERE id = 1",
    )
    .await
    .unwrap();
}

/// Blocks the bootstrap's record of its version and nothing a read needs.
const BOOTSTRAP_LOCK: &str = "LOCK TABLE _supatype.engine_bootstrap IN EXCLUSIVE MODE";

/// LK1: the bootstrap a push runs waits 3 s for a lock and tries again, so once the session
/// holding it ends, the push goes on and applies.
#[tokio::test(flavor = "multi_thread")]
async fn the_bootstrap_retries_and_the_push_applies_once_the_holder_ends() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &widgets(false)).await.unwrap();
        as_an_older_engine_bootstrapped(&pool).await;
        let (held, _) = holder(&pool, BOOTSTRAP_LOCK).await;
        let ends = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            held.commit().await.unwrap();
        });
        let outcome = push(&pool, &widgets(true)).await;
        ends.await.unwrap();
        assert!(
            matches!(outcome, Ok(Outcome::Applied { .. })),
            "{outcome:?}"
        );
    })
    .await;
}

/// LK1: behind a holder that never ends, the bootstrap gives up within the time a push's retries
/// take, naming the session, rather than after a 30 s wait that names nothing.
#[tokio::test(flavor = "multi_thread")]
async fn the_bootstrap_behind_a_holder_that_never_ends_names_it() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &widgets(false)).await.unwrap();
        as_an_older_engine_bootstrapped(&pool).await;
        let (held, pid) = holder(&pool, BOOTSTRAP_LOCK).await;

        let started = Instant::now();
        let err = push(&pool, &widgets(true))
            .await
            .expect_err("the bootstrap cannot record itself while the table is held");
        let took = started.elapsed();
        let message = format!("{err:#}");
        eprintln!("the push gave up after {took:?}: {message}");
        assert!(took < Duration::from_secs(30), "waited {took:?}");
        assert!(took >= Duration::from_secs(8), "did not retry: {took:?}");
        assert!(message.contains(&format!("pid {pid}")), "{message}");
        assert!(message.contains("bootstrap"), "{message}");
        held.rollback().await.unwrap();
    })
    .await;
}
