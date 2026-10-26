//! Shared helpers for Postgres integration tests.
//!
//! Uses **`supatype/postgres`** (PostGIS, pgvector, etc.), the same image as local dev and self-host.
//! Override with **`INTEGRATION_POSTGRES_IMAGE`** (e.g. `supatype/postgres:17-latest`).
//!
//! Compiled into every integration suite, and each uses only some of it, so unused items here
//! are expected rather than dead.

#![allow(dead_code)]

pub mod locks;

use std::future::Future;

use futures_util::FutureExt;
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
        // Caught so the database is dropped whether the test passes or panics.
        let outcome = std::panic::AssertUnwindSafe(f(database_url_with_name(&admin_url, &db_name)))
            .catch_unwind()
            .await;
        terminate_db_sessions(&admin, &db_name).await;
        let _ = sqlx::raw_sql(&format!(r#"DROP DATABASE IF EXISTS "{db_name}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
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

    // Caught so the database is dropped whether the test passes or panics; a failing test used to
    // leave its database behind, and a long session of red runs left hundreds.
    let outcome = std::panic::AssertUnwindSafe(f(pool.clone()))
        .catch_unwind()
        .await;
    pool.close().await;

    terminate_db_sessions(&admin, &db_name).await;
    let _ = sqlx::raw_sql(&format!(r#"DROP DATABASE IF EXISTS "{db_name}""#))
        .execute(&admin)
        .await;
    admin.close().await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// Runs `f` against the database `pg_cron` runs in, for a test of what a push schedules.
///
/// `pg_cron` can only be created in the one database `cron.database_name` names (`postgres` on
/// `supatype/postgres`), so in the ephemeral database [`with_integration_pool`] makes,
/// `CREATE EXTENSION pg_cron` fails with "can only create extension in database postgres" even
/// on an image that preloads it. Where it is preloaded the test runs in that database instead,
/// and everything it adds is dropped after, pass or panic: new schemas, new objects in `public`,
/// new extensions and new cron jobs. Where it is not, this is [`with_integration_pool`], and the
/// test's own `CREATE EXTENSION` reports the image as unable to load it.
pub async fn with_cron_database<F, Fut>(f: F)
where
    F: FnOnce(sqlx::PgPool) -> Fut,
    Fut: Future<Output = ()>,
{
    let Ok(admin_url) = std::env::var("DATABASE_URL") else {
        // A testcontainers database is the image's `postgres`, which is where pg_cron runs.
        return with_integration_pool(f).await;
    };
    let admin = sqlx::PgPool::connect(&admin_url)
        .await
        .expect("DATABASE_URL: connect admin pool");
    let cron_db: Option<String> =
        sqlx::query_scalar("SELECT current_setting('cron.database_name', true)")
            .fetch_one(&admin)
            .await
            .expect("read cron.database_name");
    admin.close().await;
    let Some(cron_db) = cron_db.filter(|d| !d.is_empty()) else {
        return with_integration_pool(f).await;
    };

    // One database for every such test, so one at a time; a suite's tests otherwise run at once.
    let _one_at_a_time = CRON_DATABASE.lock().await;
    let url = database_url_with_name(&admin_url, &cron_db);
    let connect = || async {
        sqlx::PgPool::connect(&url)
            .await
            .unwrap_or_else(|e| panic!("connect the pg_cron database {cron_db}: {e}"))
    };
    let pool = connect().await;
    let before = CronDatabaseObjects::read(&pool).await;
    let outcome = std::panic::AssertUnwindSafe(f(pool.clone()))
        .catch_unwind()
        .await;
    // A fresh pool: the test's connections may still carry a `SET ROLE` of its own.
    pool.close().await;
    let pool = connect().await;
    before.drop_what_was_added(&pool).await;
    pool.close().await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

static CRON_DATABASE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What the `pg_cron` database held before a test, for [`with_cron_database`] to put it back.
struct CronDatabaseObjects {
    schemas: Vec<String>,
    public_relations: Vec<i64>,
    public_functions: Vec<i64>,
    public_types: Vec<i64>,
    extensions: Vec<String>,
    cron_jobs: Vec<i64>,
}

const CRON_DB_SCHEMAS: &str = "SELECT nspname::text FROM pg_namespace
     WHERE left(nspname, 3) <> 'pg_' AND nspname <> 'information_schema'";
const CRON_DB_PUBLIC_RELATIONS: &str = "SELECT c.oid::bigint FROM pg_class c
     WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f', 'c')";
const CRON_DB_PUBLIC_FUNCTIONS: &str = "SELECT p.oid::bigint FROM pg_proc p
     LEFT JOIN pg_depend d ON d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e'
     WHERE p.pronamespace = 'public'::regnamespace AND d.objid IS NULL";
const CRON_DB_PUBLIC_TYPES: &str = "SELECT t.oid::bigint FROM pg_type t
     LEFT JOIN pg_depend d ON d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e'
     WHERE t.typnamespace = 'public'::regnamespace AND t.typtype IN ('e', 'd') AND d.objid IS NULL";
const CRON_DB_EXTENSIONS: &str = "SELECT extname::text FROM pg_extension";

impl CronDatabaseObjects {
    async fn read(pool: &sqlx::PgPool) -> Self {
        let texts = |sql: &'static str| async move {
            sqlx::query_scalar::<_, String>(sql)
                .fetch_all(pool)
                .await
                .unwrap_or_else(|e| panic!("snapshot the pg_cron database: {e}"))
        };
        let oids = |sql: &'static str| async move {
            sqlx::query_scalar::<_, i64>(sql)
                .fetch_all(pool)
                .await
                .unwrap_or_else(|e| panic!("snapshot the pg_cron database: {e}"))
        };
        Self {
            schemas: texts(CRON_DB_SCHEMAS).await,
            public_relations: oids(CRON_DB_PUBLIC_RELATIONS).await,
            public_functions: oids(CRON_DB_PUBLIC_FUNCTIONS).await,
            public_types: oids(CRON_DB_PUBLIC_TYPES).await,
            extensions: texts(CRON_DB_EXTENSIONS).await,
            cron_jobs: cron_job_ids(pool).await,
        }
    }

    async fn drop_what_was_added(&self, pool: &sqlx::PgPool) {
        let now = Self::read(pool).await;
        let mut sql = String::new();
        for job in now.cron_jobs.iter().filter(|j| !self.cron_jobs.contains(j)) {
            sql.push_str(&format!("SELECT cron.unschedule({job}::bigint);\n"));
        }
        for ext in now
            .extensions
            .iter()
            .filter(|e| !self.extensions.contains(e))
        {
            sql.push_str(&format!(
                "DROP EXTENSION IF EXISTS \"{}\" CASCADE;\n",
                ext.replace('"', "\"\"")
            ));
        }
        for oid in now
            .public_relations
            .iter()
            .filter(|o| !self.public_relations.contains(o))
        {
            sql.push_str(&format!(
                "DO $$ DECLARE r record; BEGIN
                   SELECT oid::regclass AS name, relkind INTO r FROM pg_class WHERE oid = {oid};
                   IF FOUND THEN
                     EXECUTE format('DROP %s IF EXISTS %s CASCADE',
                       CASE r.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW'
                         WHEN 'S' THEN 'SEQUENCE' WHEN 'f' THEN 'FOREIGN TABLE'
                         WHEN 'c' THEN 'TYPE' ELSE 'TABLE' END, r.name);
                   END IF;
                 END $$;\n"
            ));
        }
        for oid in now
            .public_functions
            .iter()
            .filter(|o| !self.public_functions.contains(o))
        {
            sql.push_str(&format!(
                "DO $$ BEGIN
                   IF EXISTS (SELECT 1 FROM pg_proc WHERE oid = {oid}) THEN
                     EXECUTE format('DROP ROUTINE IF EXISTS %s CASCADE', {oid}::regprocedure);
                   END IF;
                 END $$;\n"
            ));
        }
        for oid in now
            .public_types
            .iter()
            .filter(|o| !self.public_types.contains(o))
        {
            sql.push_str(&format!(
                "DO $$ BEGIN
                   IF EXISTS (SELECT 1 FROM pg_type WHERE oid = {oid}) THEN
                     EXECUTE format('DROP TYPE IF EXISTS %s CASCADE', {oid}::regtype);
                   END IF;
                 END $$;\n"
            ));
        }
        for schema in now.schemas.iter().filter(|s| !self.schemas.contains(s)) {
            sql.push_str(&format!(
                "DROP SCHEMA IF EXISTS \"{}\" CASCADE;\n",
                schema.replace('"', "\"\"")
            ));
        }
        sqlx::raw_sql(&sql)
            .execute(pool)
            .await
            .unwrap_or_else(|e| panic!("drop what the test added to the pg_cron database: {e}"));
    }
}

/// The jobs in `cron.job`, none where the extension is not created.
async fn cron_job_ids(pool: &sqlx::PgPool) -> Vec<i64> {
    let created: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron')")
            .fetch_one(pool)
            .await
            .expect("read pg_extension");
    if !created {
        return Vec::new();
    }
    sqlx::query_scalar("SELECT jobid FROM cron.job")
        .fetch_all(pool)
        .await
        .expect("read cron.job")
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

/// What a push reads of `public` before it decides: the live state under the pinned
/// `search_path`, its fingerprints and the ledger. A test that compares fingerprints, or hands a
/// state to the doctor, reads through here; the differ's unpinned `introspector::introspect`
/// deparses names the session's path covers bare, and the ledger recorded them qualified.
pub async fn live_state(pool: &sqlx::PgPool) -> supatype_engine::push::State {
    let mut conn = pool.acquire().await.expect("acquire");
    supatype_engine::push::read_state(&mut conn, "public")
        .await
        .expect("read the state a push reads")
}

/// `supatype doctor` on `public`, as the binary and the server run it.
pub async fn doctor(
    pool: &sqlx::PgPool,
    ast: &supatype_engine::parser::ast::SchemaAst,
) -> supatype_engine::differ::doctor::DoctorReport {
    supatype_engine::inspect::doctor(pool, ast, "public", false)
        .await
        .expect("doctor")
}

/// Run `sql` as one batch.
pub async fn exec(pool: &sqlx::PgPool, sql: &str) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(sql).execute(pool).await.map(|_| ())
}

/// The database as an engine from before the ledger left it: no ledger rows, and every table in
/// `public` carrying the `supatype:managed` stamp that engine wrote on the tables it created (the
/// engine has written none since Phase 6, so a test has to put them there).
#[allow(dead_code)]
pub async fn as_an_older_engine_left_it(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    exec(
        pool,
        "DELETE FROM _supatype.managed_objects WHERE true;
         DO $stamp$ DECLARE t text; BEGIN
           FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
             EXECUTE format('COMMENT ON TABLE public.%I IS %L', t,
                            'supatype:managed;kind=table;table=' || t || ';fields=;v=1');
           END LOOP;
         END $stamp$;",
    )
    .await
}

/// Plan 3.5: a push that would put back access changed outside Supatype refuses without consent,
/// before anything is applied; with `overwrite_drift` it puts it back. Asserts the first, then
/// plans again and does the second.
#[allow(dead_code)]
pub async fn apply_with_consent(
    pool: &sqlx::PgPool,
    plan: supatype_engine::push::Plan<'_>,
    ast: &supatype_engine::parser::ast::SchemaAst,
) {
    use supatype_engine::{ledger::drift::SecurityDrift, push};
    let refused = push::apply(pool, plan, push::ApplyOptions::default())
        .await
        .expect_err("a push that would overwrite access changed by hand must refuse");
    assert!(
        refused.downcast_ref::<SecurityDrift>().is_some(),
        "refused for another reason: {refused}"
    );
    let plan = push::prepare(pool, ast, "public").await.unwrap();
    push::apply(
        pool,
        plan,
        push::ApplyOptions {
            overwrite_drift: true,
            ..Default::default()
        },
    )
    .await
    .expect("with consent the push puts it back");
}
