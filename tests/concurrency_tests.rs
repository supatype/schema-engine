//! Writers that meet: a lost client, a second writer while one is in flight, and two first pushes
//! at once (pre-launch items E33, A4-N1 and E14a).
//!
//! Every writer (push, adopt, rebaseline, rollback) takes the engine's two advisory lock keys,
//! (872014, 1) and (872014, 2), for one transaction. A writer whose client is lost must not hold
//! them, or its table locks, for longer than the engine's own timeouts; a second writer must be
//! told `engine_busy` at once rather than queue behind the first.

mod common;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use supatype_engine::push::{EngineBusy, Outcome};
use supatype_engine::state::migration_history;
use supatype_engine::{adopt, inspect, parser, parser::ast::SchemaAst};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::push;

/// One model per `table:col,col` entry, every column nullable text and a uuid key, as the
/// verification scripts' generator wrote them.
fn tables_doc(spec: &str) -> String {
    let models: Vec<serde_json::Value> = spec
        .split(';')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (table, cols) = part.split_once(':').unwrap_or((part, ""));
            let mut fields = serde_json::Map::new();
            fields.insert(
                "id".into(),
                json!({ "kind": "uuid", "required": true, "primaryKey": true,
                        "default": { "kind": "genRandomUuid" },
                        "annotations": { "db": { "pgType": "UUID", "unique": false } } }),
            );
            for col in cols.split(',').filter(|c| !c.is_empty()) {
                fields.insert(
                    col.into(),
                    json!({ "kind": "text", "required": false,
                            "annotations": { "db": { "pgType": "TEXT", "unique": false } } }),
                );
            }
            let mut name = table.to_string();
            name[..1].make_ascii_uppercase();
            json!({ "name": name, "fields": fields,
                    "options": { "timestamps": false, "softDelete": false },
                    "annotations": { "db": { "tableName": table, "indexes": [] } } })
        })
        .collect();
    json!({ "astVersion": 2, "models": models }).to_string()
}

fn tables(spec: &str) -> SchemaAst {
    parser::parse(&tables_doc(spec)).expect("fixture parses")
}

/// The backend holding the engine's own key, (872014, 2), in this database, if any.
async fn engine_lock_holder(pool: &PgPool) -> Option<i32> {
    sqlx::query_scalar(
        "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND classid = 872014 AND objid = 2
            AND granted AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
    )
    .fetch_optional(pool)
    .await
    .unwrap()
}

/// How many of the two engine keys are held by anyone in this database.
async fn engine_keys_held(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND classid = 872014
            AND objid IN (1, 2) AND granted
            AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn waits_on_a_lock(pool: &PgPool, pid: i32) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock')",
    )
    .bind(pid)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Whether the backend `pid` is idle with no transaction open.
async fn idle_outside_a_transaction(pool: &PgPool, pid: i32) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND state = 'idle')",
    )
    .bind(pid)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn backend_alive(pool: &PgPool, pid: i32) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = $1)")
        .bind(pid)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Poll `check` every 250 ms until it holds or `limit` passes; how long it took, if it held.
async fn within<F, Fut>(limit: Duration, mut check: F) -> Option<Duration>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    while start.elapsed() < limit {
        if check().await {
            return Some(start.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

/// A session holding SHARE on `_supatype.managed_objects` for `seconds`, which keeps a push inside
/// its transaction at the ledger write, as the verification scripts held one. Returns its pid,
/// once the lock is granted.
async fn hold_the_ledger(pool: &PgPool, seconds: u32) -> i32 {
    // One connection, so the pid read is the session that takes the lock.
    let one = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&one)
        .await
        .unwrap();
    tokio::spawn(async move {
        let sql = format!(
            "BEGIN; LOCK TABLE _supatype.managed_objects IN SHARE MODE; \
             SELECT pg_sleep({seconds}); COMMIT;"
        );
        let _ = sqlx::raw_sql(&sql).execute(&one).await;
    });
    let granted = within(Duration::from_secs(10), || async {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = $1 AND mode = 'ShareLock'
                AND relation = '_supatype.managed_objects'::regclass AND granted)",
        )
        .bind(pid)
        .fetch_one(pool)
        .await
        .unwrap()
    })
    .await;
    assert!(granted.is_some(), "the blocker never got its lock");
    pid
}

async fn end_backend(pool: &PgPool, pid: i32) {
    let _ = sqlx::query("SELECT pg_terminate_backend($1)")
        .bind(pid)
        .execute(pool)
        .await;
}

const OPEN: u8 = 0;
/// Bytes still arrive and are read, so the peer's writes succeed, but none is passed on: a client
/// that stopped answering, or a network that drops everything with no reset.
const SILENT: u8 = 1;
/// Both sockets closed: the client process is gone.
const KILLED: u8 = 2;
/// Nothing is read either way and nothing is lost: bytes wait in the sockets until the relay is
/// open again. A client paused, with its server none the wiser.
const HELD: u8 = 3;

/// A TCP relay between the engine and Postgres that a test can silence or cut, to lose a client
/// mid-push without losing the test's own connections.
struct Relay {
    port: u16,
    mode: Arc<AtomicU8>,
}

impl Relay {
    async fn start(target: &PgConnectOptions) -> Relay {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mode = Arc::new(AtomicU8::new(OPEN));
        let upstream = format!("{}:{}", target.get_host(), target.get_port());
        let shared = mode.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let server = TcpStream::connect(&upstream).await.unwrap();
                let (cr, cw) = client.into_split();
                let (sr, sw) = server.into_split();
                tokio::spawn(pump(cr, sw, shared.clone()));
                tokio::spawn(pump(sr, cw, shared.clone()));
            }
        });
        Relay { port, mode }
    }

    fn options(&self, target: &PgConnectOptions) -> PgConnectOptions {
        target.clone().host("127.0.0.1").port(self.port)
    }

    fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }
}

async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    mode: Arc<AtomicU8>,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        if mode.load(Ordering::SeqCst) == HELD {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        }
        // Bytes read just before the relay is held are still passed on below.
        let read = tokio::select! {
            read = from.read(&mut buf) => read,
            _ = tokio::time::sleep(Duration::from_millis(100)) => Ok(usize::MAX),
        };
        match mode.load(Ordering::SeqCst) {
            KILLED => return,
            SILENT => {}
            _ => match read {
                Ok(0) | Err(_) => return,
                Ok(usize::MAX) => {}
                Ok(n) => {
                    if to.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            },
        }
        if matches!(read, Ok(0) | Err(_)) {
            return;
        }
    }
}

/// A push held inside its transaction at the ledger write, through a relay, after one earlier
/// push (so a rollback has a migration to undo).
struct InFlight {
    relay: Relay,
    /// The push's backend.
    pid: i32,
    /// The session holding the ledger.
    blocker: i32,
    push: tokio::task::JoinHandle<anyhow::Result<Outcome>>,
}

impl InFlight {
    async fn start(pool: &PgPool, hold: u32) -> InFlight {
        push(pool, &tables("t1:a")).await.unwrap();
        let blocker = hold_the_ledger(pool, hold).await;
        let relay = Relay::start(&pool.connect_options()).await;
        let relayed = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(relay.options(&pool.connect_options()))
            .await
            .unwrap();
        let push = tokio::spawn(async move { push(&relayed, &tables("t1:a,b")).await });
        // Holding the lock is not enough: the push must be at the ledger write, waiting on the
        // blocker.
        let waiting = within(Duration::from_secs(60), || async {
            match engine_lock_holder(pool).await {
                Some(pid) => waits_on_a_lock(pool, pid).await,
                None => false,
            }
        })
        .await;
        assert!(waiting.is_some(), "the push never reached the ledger write");
        let pid = engine_lock_holder(pool).await.unwrap();
        InFlight {
            relay,
            pid,
            blocker,
            push,
        }
    }

    /// Keep the push in flight for as long as the test needs, however slow the machine.
    ///
    /// A push waiting on a lock is not in flight for long: each attempt waits 3 s, and after four
    /// (15 to 25 s with the pauses) it gives up and lets the engine's lock go. So the relay is held
    /// while the push's session sits between two attempts: idle, outside a transaction, holding
    /// the engine's lock at session level, which nothing on the server times out. Held at any
    /// other moment the server would time the session out, so the hold is only kept once the
    /// session is seen idle after it.
    async fn hold_between_attempts(&self, pool: &PgPool) {
        let held = within(Duration::from_secs(60), || async {
            if !idle_outside_a_transaction(pool, self.pid).await {
                return false;
            }
            self.relay.set(HELD);
            // Longer than the pump's own wait, so any read already under way has gone through.
            tokio::time::sleep(Duration::from_millis(300)).await;
            let kept = idle_outside_a_transaction(pool, self.pid).await
                && engine_lock_holder(pool).await == Some(self.pid);
            if !kept {
                self.relay.set(OPEN);
            }
            kept
        })
        .await;
        assert!(held.is_some(), "the push was never seen between attempts");
    }

    /// Abandon the push and end both sessions, whatever the test found.
    async fn abandon(self, pool: &PgPool) {
        self.push.abort();
        end_backend(pool, self.pid).await;
        end_backend(pool, self.blocker).await;
    }
}

/// How long until the push's backend is gone and neither engine key is held, up to `limit`.
async fn freed_within(pool: &PgPool, pid: i32, limit: Duration) -> Option<Duration> {
    within(limit, || async {
        engine_keys_held(pool).await == 0 && !backend_alive(pool, pid).await
    })
    .await
}

/// E33, network drop: the client stops answering after the push is inside its transaction. Once
/// the blocker lets go, the backend finishes its statement and waits, idle in transaction, for a
/// client that will never speak again. Without a timeout of its own it held both keys until TCP
/// gave up (15 minutes to over 2 hours).
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_client_frees_both_keys_and_its_table_locks_within_the_idle_timeout() {
    common::with_integration_pool(|pool| async move {
        let push = InFlight::start(&pool, 120).await;
        push.relay.set(SILENT);
        end_backend(&pool, push.blocker).await;
        let freed = freed_within(&pool, push.pid, Duration::from_secs(100)).await;
        push.abandon(&pool).await;
        let freed = freed.expect("a silent client still held the engine's keys after 100 s");
        assert!(
            freed <= Duration::from_secs(80),
            "freed only after {freed:?}"
        );
    })
    .await;
}

/// E33, client killed: the engine process dies while its backend waits on a lock. The backend
/// does not read the socket while it waits, so without a timeout it held both keys until the
/// blocker ended, however long that was.
#[tokio::test(flavor = "multi_thread")]
async fn a_killed_client_waiting_on_a_lock_frees_both_keys_within_the_lock_timeout() {
    common::with_integration_pool(|pool| async move {
        let push = InFlight::start(&pool, 120).await;
        push.relay.set(KILLED);
        let freed = freed_within(&pool, push.pid, Duration::from_secs(45)).await;
        push.abandon(&pool).await;
        freed.expect("a killed client's backend still held the engine's keys after 45 s");
    })
    .await;
}

/// Every connection the engine makes asks Postgres to probe its peer, so a client lost with no
/// reset is noticed in about a minute rather than when the operating system's two hours run out.
#[tokio::test]
async fn the_engines_connections_ask_postgres_to_probe_a_lost_client() {
    common::with_integration_url(|url| async move {
        let pool = supatype_engine::db::connect(&url).await.unwrap();
        for (setting, wanted) in [
            ("tcp_keepalives_idle", "30"),
            ("tcp_keepalives_interval", "10"),
            ("tcp_keepalives_count", "3"),
        ] {
            let value: String = sqlx::query_scalar(&format!("SHOW {setting}"))
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(value, wanted, "{setting}");
        }
        pool.close().await;
    })
    .await;
}

/// Whether this server accepts a non-zero `client_connection_check_interval`, asked with a plain
/// `SET LOCAL` rather than the engine's own code. Postgres refuses it with `invalid_parameter_value`
/// on a platform that cannot tell a closed socket from an idle one (Windows).
async fn server_checks_clients(pool: &PgPool) -> bool {
    let mut tx = pool.begin().await.unwrap();
    let set = sqlx::query("SET LOCAL client_connection_check_interval = '5s'")
        .execute(&mut *tx)
        .await;
    tx.rollback().await.unwrap();
    match set {
        Ok(_) => true,
        Err(e) => {
            let code = e.as_database_error().and_then(|d| d.code());
            assert_eq!(code.as_deref(), Some("22023"), "{e}");
            false
        }
    }
}

/// A writer's transaction asks its backend to check, while a statement runs, that the client is
/// still there, on a server that can; on one that cannot (Postgres on Windows refuses any value
/// but 0), the writer still begins, bounded by its idle and lock timeouts alone. Every native push
/// on Windows failed here with "invalid value for parameter client_connection_check_interval".
#[tokio::test]
async fn a_writer_checks_its_client_where_the_server_can_and_begins_where_it_cannot() {
    common::with_integration_pool(|pool| async move {
        let supported = server_checks_clients(&pool).await;
        let mut session = supatype_engine::online::EngineSession::open(&pool)
            .await
            .unwrap();
        let mut tx = session
            .begin(supatype_engine::online::PUSH_LOCK_TIMEOUT)
            .await
            .expect("the writer's transaction began");
        let interval: String = sqlx::query_scalar("SHOW client_connection_check_interval")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let idle: String = sqlx::query_scalar("SHOW idle_in_transaction_session_timeout")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        session.close().await;
        assert_eq!(interval, if supported { "5s" } else { "0" });
        assert_eq!(idle, "1min");
    })
    .await;
}

/// Refused with `engine_busy`, and within a second: a writer that queues instead holds up everyone
/// who comes after it (A4-N1).
async fn refused_at_once<T: std::fmt::Debug>(
    what: &str,
    run: impl std::future::Future<Output = anyhow::Result<T>>,
) {
    let started = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .unwrap_or_else(|_| panic!("{what} was still waiting after 5 s instead of refusing"));
    let elapsed = started.elapsed();
    let err = outcome.expect_err(&format!("{what} ran while a push was in flight"));
    assert!(
        err.downcast_ref::<EngineBusy>().is_some(),
        "{what} was refused for another reason: {err:#}"
    );
    assert!(
        elapsed <= Duration::from_secs(1),
        "{what} took {elapsed:?} to refuse"
    );
}

/// The engine binary with `args` on `url` and the AST document `doc`, killed after 20 s. Its
/// exit status, stdout and how long it ran.
///
/// How long it ran is counted from the engine's own first log line, not from the spawn: the
/// operating system loading a debug binary is not the engine's time, and on a busy machine (or
/// the first run of a fresh build, which Windows scans) it alone took over 2 s.
async fn engine(url: &str, doc: &str, args: &[&str]) -> (bool, String, Duration) {
    let input = std::env::temp_dir().join(common::ephemeral_name("concurrency_ast") + ".json");
    std::fs::write(&input, doc).unwrap();
    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_supatype-engine"))
        .env_remove("DATABASE_URL")
        .arg("-i")
        .arg(&input)
        .args(args)
        .args(["--database-url", url, "--log", "info"])
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(20), child).await;
    let exited = chrono::Utc::now();
    let _ = std::fs::remove_file(&input);
    let Ok(out) = out else {
        return (
            false,
            "<still running after 20 s>".into(),
            Duration::from_secs(20),
        );
    };
    let out = out.expect("run the engine");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let started = engine_started_at(&stderr)
        .unwrap_or_else(|| panic!("the engine logged no start line: {stderr}"));
    let ran = (exited - started).to_std().unwrap_or_default();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    (out.status.success(), stdout, ran)
}

/// When the engine says it started: the timestamp of its first log line. Piped, the engine
/// writes no colour, so the line starts with the timestamp.
fn engine_started_at(stderr: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let line = stderr
        .lines()
        .find(|l| l.contains("supatype-engine starting"))?;
    let stamp = line.split_whitespace().next()?;
    chrono::DateTime::parse_from_rfc3339(stamp)
        .ok()
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// ENG-CONC: a push waiting on a lock holds the engine's lock between its attempts as well as
/// during them. Before a push plans, it clears the ledger rows of released tables that are gone;
/// that step took the lock per attempt, so for the pause after each failed attempt nobody held it
/// and a second writer arriving then waited behind the same lock instead of being refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_waiting_push_holds_the_engine_lock_through_every_pause() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &tables("t1:a")).await.unwrap();
        let blocker = hold_the_ledger(&pool, 60).await;
        let waiting = tokio::spawn({
            let pool = pool.clone();
            async move { push(&pool, &tables("t1:a,b")).await }
        });
        let first = within(Duration::from_secs(20), || async {
            engine_lock_holder(&pool).await.is_some()
        })
        .await;
        assert!(first.is_some(), "the push never took the engine's lock");
        let holder = engine_lock_holder(&pool).await;
        // Two attempts and the pause between them.
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(8) {
            let now = engine_lock_holder(&pool).await;
            assert_eq!(now, holder, "after {:?}", started.elapsed());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        waiting.abort();
        end_backend(&pool, blocker).await;
    })
    .await;
}

/// A4-N1, the CONC matrix: with a push in flight, every other writer is refused with
/// `engine_busy` within a second, through the library and through the binary. Each used to queue:
/// a push and an adopt on the bootstrap's `ALTER TABLE _supatype.migrations`, behind the push.
///
/// The push is held between two of its attempts for the whole test, so it is still in flight
/// however long the eight refusals take. Left to run, it gave up after its four attempts while a
/// loaded machine was still getting through them, and the last writers found no push to refuse.
#[tokio::test(flavor = "multi_thread")]
async fn every_writer_is_refused_at_once_while_a_push_is_in_flight() {
    common::with_integration_url(|url| async move {
        let pool = PgPool::connect(&url).await.unwrap();
        let in_flight = InFlight::start(&pool, 120).await;
        in_flight.hold_between_attempts(&pool).await;
        library_writers_are_refused(&pool).await;
        binary_writers_are_refused(&url).await;

        // The push in flight is untouched by all of it, and applies once the ledger is free.
        in_flight.relay.set(OPEN);
        end_backend(&pool, in_flight.blocker).await;
        let applied = tokio::time::timeout(Duration::from_secs(60), in_flight.push)
            .await
            .expect("the push in flight finished")
            .unwrap();
        assert!(
            matches!(applied, Ok(Outcome::Applied { .. })),
            "{applied:?}"
        );
    })
    .await;
}

/// Push, adopt, rebaseline and rollback through the library, each refused at once.
async fn library_writers_are_refused(pool: &PgPool) {
    let ast = tables("t1:a");
    refused_at_once("push", push(pool, &tables("t1:a,c"))).await;
    let adopt = adopt::Request {
        apply: true,
        ..Default::default()
    };
    refused_at_once("adopt", adopt::run(pool, &ast, "public", adopt)).await;
    refused_at_once(
        "rebaseline",
        inspect::rebaseline(pool, &ast, "public", true),
    )
    .await;
    refused_at_once(
        "rollback",
        migration_history::apply_rollback(pool, "public"),
    )
    .await;
}

/// The same four writers through the engine binary, each refused at once with `engine_busy`.
async fn binary_writers_are_refused(url: &str) {
    for args in [
        &["push", "--non-interactive"][..],
        &["adopt", "--yes"],
        &["doctor", "--rebaseline", "--accept-access-drift"],
        &["rollback"],
    ] {
        let (ok, stdout, elapsed) = engine(url, &tables_doc("t1:a,c"), args).await;
        assert!(!ok, "{args:?} ran while a push was in flight: {stdout}");
        assert!(stdout.contains("engine_busy"), "{args:?}: {stdout}");
        assert!(
            elapsed <= Duration::from_secs(2),
            "{args:?} took {elapsed:?}"
        );
    }
}

/// E14a: two first pushes on a fresh database at the same moment. One applies; the other is
/// refused with `engine_busy` (it used to fail on a raw catalog error such as
/// `duplicate key ... pg_type_typname_nsp_index`).
#[tokio::test(flavor = "multi_thread")]
async fn two_first_pushes_at_once_give_one_success_and_one_engine_busy() {
    for trial in 0..5 {
        common::with_integration_pool(|pool| async move {
            let ast = tables("t1:a;t2:b");
            let (one, two) = tokio::join!(push(&pool, &ast), push(&pool, &ast));
            let applied = |r: &anyhow::Result<Outcome>| matches!(r, Ok(Outcome::Applied { .. }));
            let busy = |r: &anyhow::Result<Outcome>| {
                matches!(r, Err(e) if e.downcast_ref::<EngineBusy>().is_some())
            };
            assert!(
                (applied(&one) && busy(&two)) || (busy(&one) && applied(&two)),
                "trial {trial}: {one:?} / {two:?}"
            );
        })
        .await;
    }
}

/// The CLI's preview (`diff`, `doctor`) reads without the engine's lock. One that meets a lock a
/// writer holds gives up within its lock timeout and says the engine is busy, instead of waiting
/// as long as the writer does.
#[tokio::test(flavor = "multi_thread")]
async fn a_preview_that_meets_a_writers_lock_is_told_the_engine_is_busy() {
    use sqlx::Connection;
    common::with_integration_url(|url| async move {
        let pool = PgPool::connect(&url).await.unwrap();
        push(&pool, &tables("t1:a")).await.unwrap();
        let mut writer = sqlx::PgConnection::connect_with(&pool.connect_options())
            .await
            .unwrap();
        sqlx::raw_sql(
            "BEGIN; SELECT pg_advisory_xact_lock(872014, 2);
             LOCK TABLE _supatype.migrations IN ACCESS EXCLUSIVE MODE;",
        )
        .execute(&mut writer)
        .await
        .unwrap();
        for args in [&["diff"][..], &["doctor"]] {
            let (ok, stdout, elapsed) = engine(&url, &tables_doc("t1:a,c"), args).await;
            assert!(!ok, "{args:?} read through a writer's lock: {stdout}");
            assert!(stdout.contains("engine_busy"), "{args:?}: {stdout}");
            assert!(
                elapsed <= Duration::from_secs(10),
                "{args:?} took {elapsed:?}"
            );
        }
        writer.close().await.unwrap();
    })
    .await;
}
