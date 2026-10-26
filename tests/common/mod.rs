//! Shared helpers for Postgres integration tests.
//!
//! Uses **`supatype/postgres`** (PostGIS, pgvector, etc.), the same image as local dev and self-host.
//! Override with **`INTEGRATION_POSTGRES_IMAGE`** (e.g. `supatype/postgres:17-latest`).
//!
//! Compiled into every integration suite, and each uses only some of it, so unused items here
//! are expected rather than dead.

#![allow(dead_code)]

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};

use testcontainers::core::IntoContainerPort;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

pub static EPHEMERAL_SEQ: AtomicU64 = AtomicU64::new(0);

/// A database name no other test binary can collide with. The process id alone was not enough:
/// Windows reuses pids, and a suite that panicked before dropping its database left one behind
/// under the name the next binary with that pid chose first (`CREATE DATABASE ... already
/// exists`), so the name also carries the moment it was made.
pub fn ephemeral_name(prefix: &str) -> String {
    let n = EPHEMERAL_SEQ.fetch_add(1, Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{prefix}_{}_{n}_{nanos}", std::process::id())
}

const PG_USER: &str = "supatype_admin";
const PG_PASSWORD: &str = "postgres";
const PG_DB: &str = "postgres";

pub fn integration_postgres_image() -> String {
    std::env::var("INTEGRATION_POSTGRES_IMAGE")
        .unwrap_or_else(|_| "supatype/postgres:latest".into())
}

pub fn parse_image_ref(image_ref: &str) -> (String, String) {
    if let Some((name, tag)) = image_ref.rsplit_once(':') {
        (name.to_string(), tag.to_string())
    } else {
        (image_ref.to_string(), "latest".into())
    }
}

pub fn admin_connection_url(host: &str, port: u16) -> String {
    format!("postgres://{PG_USER}:{PG_PASSWORD}@{host}:{port}/{PG_DB}")
}

pub async fn start_supatype_postgres() -> Result<
    (testcontainers::ContainerAsync<GenericImage>, String),
    testcontainers::TestcontainersError,
> {
    let image_ref = integration_postgres_image();
    let (name, tag) = parse_image_ref(&image_ref);
    let container = GenericImage::new(name, tag)
        .with_exposed_port(5432.tcp())
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_env_var("POSTGRES_USER", PG_USER)
        .with_env_var("POSTGRES_PASSWORD", PG_PASSWORD)
        .with_env_var("POSTGRES_DB", PG_DB)
        .start()
        .await?;
    let port = container.get_host_port_ipv4(5432).await?;
    let url = admin_connection_url("127.0.0.1", port);
    Ok((container, url))
}

pub fn database_url_with_name(admin_url: &str, db: &str) -> String {
    let (base, query) = match admin_url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (admin_url, None),
    };
    let prefix = base
        .rsplit_once('/')
        .expect("DATABASE_URL must include /dbname (e.g. …/postgres)")
        .0;
    match query {
        Some(q) => format!("{prefix}/{db}?{q}"),
        None => format!("{prefix}/{db}"),
    }
}

pub async fn terminate_db_sessions(admin: &sqlx::PgPool, db_name: &str) {
    let safe = db_name.replace('\'', "''");
    let sql = format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE datname = '{safe}' AND pid <> pg_backend_pid()"
    );
    let _ = sqlx::raw_sql(&sql).execute(admin).await;
}

/// Whether a skipped integration test should fail instead.
///
/// CI sets `SUPATYPE_FORCE_INTEGRATION_TESTS=1`, so a suite that cannot reach a database, or an
/// image that cannot provide `supatype_mask`, turns the build red rather than passing quietly.
/// Without it a skip returns from the test body, and a test that returns has passed: the gate
/// would report green having asserted nothing, which is the failure mode it exists to catch.
pub fn force_integration_tests() -> bool {
    std::env::var("SUPATYPE_FORCE_INTEGRATION_TESTS").is_ok()
}

/// Runs `f` against an isolated Postgres (ephemeral DB or testcontainers).
/// Skips when `DATABASE_URL` is unset and Docker/testcontainers is unavailable.
pub async fn with_integration_pool<F, Fut>(f: F)
where
    F: FnOnce(sqlx::PgPool) -> Fut,
    Fut: Future<Output = ()>,
{
    if std::env::var("DATABASE_URL").is_ok() {
        with_ephemeral_database(f).await;
        return;
    }

    let (container, url) = match start_supatype_postgres().await {
        Ok(c) => c,
        Err(e) => {
            if force_integration_tests() {
                panic!(
                    "no database: DATABASE_URL is unset and Docker is unavailable ({e}). \
                     Provide one, or unset SUPATYPE_FORCE_INTEGRATION_TESTS."
                );
            }
            eprintln!("SKIP integration: DATABASE_URL not set and Docker unavailable ({e})");
            return;
        }
    };
    let pool = sqlx::PgPool::connect(&url)
        .await
        .expect("connect testcontainers supatype/postgres");
    f(pool.clone()).await;
    pool.close().await;
    drop(container);
}

/// Create `supatype_mask`, as a provisioned project does through its bootstrap migration.
///
/// Returns false when the image cannot provide it, so a test that needs field-level access
/// can skip rather than fail. Deliberately not fatal and deliberately not called for every
/// pool: the extension ships from **`supatype-postgres`**, so requiring it here would make
/// this whole suite red until that image is republished, and the tests that would break
/// are the policy-convergence ones, which have nothing to do with field rules.
///
/// A schema that declares `fields` rules genuinely refuses to apply without it. That is the
/// capability probe working, not an accident, which is why only the field-access tests are
/// gated on this.
pub async fn mask_extension_available(pool: &sqlx::PgPool) -> bool {
    match sqlx::raw_sql("CREATE EXTENSION IF NOT EXISTS supatype_mask")
        .execute(pool)
        .await
    {
        Ok(_) => true,
        Err(e) => {
            if force_integration_tests() {
                panic!(
                    "image {} cannot provide supatype_mask ({e}). The extension has shipped in \
                     supatype/postgres since v17.2.1, so this is a stale image or a missing \
                     shared_preload_libraries entry, not an absent feature. Point \
                     INTEGRATION_POSTGRES_IMAGE at a current image, or unset \
                     SUPATYPE_FORCE_INTEGRATION_TESTS to let field-access tests skip.",
                    integration_postgres_image()
                );
            }
            eprintln!(
                "SKIP field-level access: image {} cannot provide supatype_mask ({e}). \
                 Point INTEGRATION_POSTGRES_IMAGE at an image built from supatype-postgres \
                 at or after the extension landed.",
                integration_postgres_image()
            );
            false
        }
    }
}

/// Runs `f` with the URL of an isolated, empty database, for a test that drives the engine binary
/// rather than the library.
///
/// The URL rather than a pool because a child process has to connect for itself. Same isolation
/// and skip rules as [`with_integration_pool`].
pub async fn with_integration_url<F, Fut>(f: F)
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = ()>,
{
    if let Ok(admin_url) = std::env::var("DATABASE_URL") {
        let admin = sqlx::PgPool::connect(&admin_url)
            .await
            .expect("DATABASE_URL: connect admin pool");
        let db_name = ephemeral_name("st_engine_url");
        sqlx::raw_sql(&format!(r#"CREATE DATABASE "{db_name}""#))
            .execute(&admin)
            .await
            .unwrap_or_else(|e| panic!("CREATE DATABASE {db_name} failed: {e}"));
        f(database_url_with_name(&admin_url, &db_name)).await;
        terminate_db_sessions(&admin, &db_name).await;
        let _ = sqlx::raw_sql(&format!(r#"DROP DATABASE IF EXISTS "{db_name}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        return;
    }

    match start_supatype_postgres().await {
        Ok((container, url)) => {
            f(url).await;
            drop(container);
        }
        Err(e) if force_integration_tests() => panic!("no database: {e}"),
        Err(e) => eprintln!("SKIP integration: DATABASE_URL not set and Docker unavailable ({e})"),
    }
}

async fn with_ephemeral_database<F, Fut>(f: F)
where
    F: FnOnce(sqlx::PgPool) -> Fut,
    Fut: Future<Output = ()>,
{
    let admin_url =
        std::env::var("DATABASE_URL").expect("with_ephemeral_database requires DATABASE_URL");
    let admin = sqlx::PgPool::connect(&admin_url)
        .await
        .expect("DATABASE_URL: connect admin pool");
    let db_name = ephemeral_name("st_engine_it");
    assert!(
        db_name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
        "generated db name must be a safe identifier: {db_name}"
    );

    sqlx::raw_sql(&format!(r#"CREATE DATABASE "{db_name}""#))
        .execute(&admin)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "CREATE DATABASE {db_name} failed: {e} \
                 (DATABASE_URL user needs CREATEDB / superuser)"
            )
        });

    let child_url = database_url_with_name(&admin_url, &db_name);
    let pool = sqlx::PgPool::connect(&child_url)
        .await
        .unwrap_or_else(|e| panic!("connect ephemeral database {db_name}: {e}"));

    f(pool.clone()).await;
    pool.close().await;

    terminate_db_sessions(&admin, &db_name).await;
    let _ = sqlx::raw_sql(&format!(r#"DROP DATABASE IF EXISTS "{db_name}""#))
        .execute(&admin)
        .await;
    admin.close().await;
}

/// The push a user runs, as the CLI and the server run it: `prepare` then `apply`.
pub async fn push(
    pool: &sqlx::PgPool,
    ast: &supatype_engine::parser::ast::SchemaAst,
) -> anyhow::Result<supatype_engine::push::Outcome> {
    push_with(pool, ast, supatype_engine::push::ApplyOptions::default()).await
}

/// [`push`] with options (`force` for a destructive push).
pub async fn push_with(
    pool: &sqlx::PgPool,
    ast: &supatype_engine::parser::ast::SchemaAst,
    options: supatype_engine::push::ApplyOptions,
) -> anyhow::Result<supatype_engine::push::Outcome> {
    let plan = supatype_engine::push::prepare(pool, ast, "public").await?;
    supatype_engine::push::apply(pool, plan, options).await
}

/// Run `sql` as one batch.
pub async fn exec(pool: &sqlx::PgPool, sql: &str) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(sql).execute(pool).await.map(|_| ())
}
