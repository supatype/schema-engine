//! A push that cannot take a table's lock waits only briefly, and tries again (IN-C 1, RT-N1).
//!
//! A push used to wait 30 seconds for each lock, and while it waited every application query on
//! that table queued behind it. Now each attempt waits a few seconds, rolls back whole, and tries
//! again after a pause; the last failure names the table and the session holding it. A concurrent
//! push is still refused at once with `engine_busy`, never retried.

mod common;

use std::time::{Duration, Instant};

use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};
use supatype_engine::push::{EngineBusy, Outcome};
use supatype_engine::{parser, parser::ast::SchemaAst};

use common::locks::{side_pool, App};
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

/// A session that read `widgets` in a transaction it leaves open, as an application holding a
/// connection mid-transaction does: it holds ACCESS SHARE until it ends. Its query carries a value
/// that must never reach an error message.
async fn open_reader(pool: &PgPool) -> (Transaction<'static, Postgres>, i32) {
    let mut tx = side_pool(pool, 1).await.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    sqlx::raw_sql("SELECT 'secret-in-the-query' AS s, count(*) FROM public.widgets")
        .execute(&mut *tx)
        .await
        .unwrap();
    (tx, pid)
}

/// IN-C 1: behind a reader that never ends, the push gives up within about 30 seconds, having
/// tried more than once, and names the table and the session (its pid, state and age, never its
/// query). The application's queries on the table wait no longer than one short attempt.
#[tokio::test(flavor = "multi_thread")]
async fn a_push_behind_an_open_reader_retries_then_names_the_table_and_the_holder() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &widgets(false)).await.unwrap();
        exec(
            &pool,
            "INSERT INTO public.widgets (label) SELECT md5(i::text) FROM generate_series(1, 100) i",
        )
        .await
        .unwrap();
        let (reader, reader_pid) = open_reader(&pool).await;
        let app = App::start(&pool, &["SELECT count(*) FROM public.widgets"]).await;

        let started = Instant::now();
        let err = push(&pool, &widgets(true))
            .await
            .expect_err("the push cannot take the table while the reader holds it");
        let took = started.elapsed();
        let (longest, ran) = app.finish().await;
        let message = format!("{err:#}");
        eprintln!("push gave up after {took:?}: {message}\nlongest app query {longest:?} of {ran}");

        assert!(took <= Duration::from_secs(35), "the push waited {took:?}");
        assert!(
            took >= Duration::from_secs(8),
            "the push did not retry: {took:?}"
        );
        assert!(message.contains("widgets"), "{message}");
        assert!(message.contains(&reader_pid.to_string()), "{message}");
        assert!(message.contains("idle in transaction"), "{message}");
        assert!(!message.contains("secret-in-the-query"), "{message}");
        assert!(
            longest <= Duration::from_millis(4_500),
            "an application query waited {longest:?} behind the push"
        );
        let note: Option<String> = sqlx::query_scalar(
            "SELECT column_name::text FROM information_schema.columns
              WHERE table_name = 'widgets' AND column_name = 'note'",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_eq!(note, None, "nothing was applied");
        reader.rollback().await.unwrap();
    })
    .await;
}

/// IN-C 1: once the reader ends, a retry takes the lock and the push applies.
#[tokio::test(flavor = "multi_thread")]
async fn a_push_applies_on_a_retry_once_the_reader_ends() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &widgets(false)).await.unwrap();
        let (reader, _) = open_reader(&pool).await;
        let ends = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            reader.commit().await.unwrap();
        });
        let started = Instant::now();
        let outcome = push(&pool, &widgets(true)).await;
        ends.await.unwrap();
        assert!(
            matches!(outcome, Ok(Outcome::Applied { .. })),
            "{outcome:?}"
        );
        assert!(
            started.elapsed() >= Duration::from_secs(4),
            "applied before the reader ended"
        );
    })
    .await;
}

/// ENG-CONC is unchanged: while a push is retrying, a second push is refused at once with
/// `engine_busy`, between attempts as well as during them.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_push_is_refused_at_once_while_the_first_retries() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &widgets(false)).await.unwrap();
        let (reader, _) = open_reader(&pool).await;
        let first_pool = pool.clone();
        let first = tokio::spawn(async move { push(&first_pool, &widgets(true)).await });
        tokio::time::sleep(Duration::from_secs(1)).await;
        for _ in 0..8 {
            let started = Instant::now();
            let second = push(&pool, &widgets(true)).await;
            assert!(
                matches!(&second, Err(e) if e.downcast_ref::<EngineBusy>().is_some()),
                "{second:?}"
            );
            assert!(started.elapsed() <= Duration::from_secs(1));
            tokio::time::sleep(Duration::from_millis(1_500)).await;
        }
        reader.rollback().await.unwrap();
        let first = first.await.unwrap();
        assert!(matches!(first, Ok(Outcome::Applied { .. })), "{first:?}");
    })
    .await;
}
