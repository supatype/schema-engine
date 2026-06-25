//! Shared helpers for Postgres integration tests.
//!
//! Uses **`supatype/postgres`** (PostGIS, pgvector, etc.) — same image as local dev / self-host.
//! Override with **`INTEGRATION_POSTGRES_IMAGE`** (e.g. `supatype/postgres:17-latest`).

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};

use testcontainers::core::IntoContainerPort;
use testcontainers::core::WaitFor;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};

pub static EPHEMERAL_SEQ: AtomicU64 = AtomicU64::new(0);

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
    let n = EPHEMERAL_SEQ.fetch_add(1, Ordering::SeqCst);
    let db_name = format!("st_engine_it_{}_{}", std::process::id(), n);
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
