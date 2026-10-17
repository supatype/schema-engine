//! A `migrate --record` file applied by hand is the push it was made from (E17), and a plain
//! `migrate` takes no lock an application waits on (IN-A).
//!
//! The file once carried only the migration: applied by hand, it left Supatype's tables with no
//! history and no ledger, and the next push refused them as unmanaged. With `--record` it carries
//! the bootstrap and what the push would record, so the next push finds nothing to do and a
//! rollback undoes it. Without it, it is planned from a snapshot and says it records nothing.

mod common;

use serde_json::json;
use sqlx::PgPool;
use supatype_engine::{
    migrate_file, parser, parser::ast::SchemaAst, push, state::migration_history,
};

use common::{exec, push};

/// `supatype migrate --record`: the file a push writes, history and ledger included (E17).
const RECORD: migrate_file::Options = migrate_file::Options {
    force: false,
    record: true,
};

fn widgets(extra: bool) -> SchemaAst {
    let text = json!({ "kind": "text", "required": false,
        "annotations": { "db": { "pgType": "TEXT", "unique": false } } });
    let mut fields = json!({
        "id": { "kind": "uuid", "primaryKey": true, "required": true,
                "annotations": { "db": { "pgType": "UUID", "unique": false } } },
        "label": text.clone()
    });
    if extra {
        fields["note"] = text;
    }
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Widget",
            "fields": fields,
            "options": { "timestamps": false, "softDelete": false, "singleton": false },
            "annotations": { "db": { "tableName": "widgets" },
                             "platform": { "access": { "read": { "type": "public" } } } }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// The forward section of a migration file, as the E17 script cut it for `psql`.
fn forward(file: &str) -> &str {
    file.split_once("ROLLBACK MIGRATION")
        .map(|(up, _)| up)
        .expect("the file has a rollback section")
}

async fn exists(pool: &PgPool, relation: &str) -> bool {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(relation)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn ledger_rows(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT concat_ws(' ', kind, schema_name, parent, name, desired_fp, live_fp, status)
           FROM _supatype.managed_objects ORDER BY kind, schema_name, parent, name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The recorded bootstrap version and when it was applied, `None` before any.
async fn bootstrap_record(pool: &PgPool) -> Option<(String, String)> {
    sqlx::query_as("SELECT version, applied_at::text FROM _supatype.engine_bootstrap WHERE id = 1")
        .fetch_optional(pool)
        .await
        .unwrap()
}

async fn exists_function(pool: &PgPool, signature: &str) -> bool {
    sqlx::query_scalar("SELECT to_regprocedure($1) IS NOT NULL")
        .bind(signature)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

#[tokio::test]
async fn a_migrate_file_applied_by_hand_on_a_new_database_is_the_push() {
    common::with_integration_pool(|pool| async move {
        let ast = widgets(false);
        let file = migrate_file::render(&pool, &ast, "public", RECORD)
            .await
            .expect("the file renders");
        assert!(
            !exists(&pool, "_supatype.migrations").await && !exists(&pool, "public.widgets").await,
            "migrate wrote to the database"
        );

        exec(&pool, forward(&file))
            .await
            .expect("the forward section applies");
        // The file bootstraps as a push does on a database with none: the version row, and the
        // claim readers the generated rules call.
        let bootstrapped = bootstrap_record(&pool).await;
        assert_eq!(
            bootstrapped.as_ref().map(|(v, _)| v.as_str()),
            Some(migration_history::bootstrap_version().as_str())
        );
        assert!(exists_function(&pool, "_supatype.jwt_claims()").await);

        let outcome = push(&pool, &ast)
            .await
            .expect("the next push is not refused");
        assert!(up_to_date(&outcome), "{outcome:?}");
        assert_eq!(
            bootstrap_record(&pool).await,
            bootstrapped,
            "the push after the file ran the bootstrap again"
        );

        // Recorded as a push records it, so it rolls back as a push does.
        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the hand-applied migration rolls back");
        assert!(!exists(&pool, "public.widgets").await);
    })
    .await;
}

#[tokio::test]
async fn a_migrate_file_on_a_pushed_database_records_the_same_ledger_as_the_push() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &widgets(false)).await.unwrap();
        let ast = widgets(true);
        let file = migrate_file::render(&pool, &ast, "public", RECORD)
            .await
            .expect("the file renders");
        assert!(!column_exists(&pool).await, "migrate wrote to the database");

        exec(&pool, forward(&file)).await.expect("applies");
        let by_hand = ledger_rows(&pool).await;
        let outcome = push(&pool, &ast).await.unwrap();
        assert!(up_to_date(&outcome), "{outcome:?}");
        assert_eq!(ledger_rows(&pool).await, by_hand);

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("rolls back");
        assert!(!column_exists(&pool).await);
        let outcome = push(&pool, &widgets(false)).await.unwrap();
        assert!(
            up_to_date(&outcome),
            "the rollback put the ledger back: {outcome:?}"
        );
    })
    .await;
}

/// HI2: the file's rollback section, applied by hand after its forward section, puts the ledger
/// back as `supatype rollback` does, and marks the migration rolled back, so the next push of the
/// earlier schema finds nothing to do.
#[tokio::test]
async fn a_migrate_files_rollback_section_puts_the_ledger_back() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &widgets(false)).await.unwrap();
        let before = ledger_rows(&pool).await;
        let file = migrate_file::render(&pool, &widgets(true), "public", RECORD)
            .await
            .expect("the file renders");
        exec(&pool, forward(&file)).await.expect("applies");
        assert_ne!(
            ledger_rows(&pool).await,
            before,
            "the file recorded the push"
        );

        let (_, rollback) = file
            .split_once("ROLLBACK MIGRATION")
            .expect("the file has a rollback section");
        let rollback = rollback.split_once("BEGIN;").map(|(_, r)| r).unwrap();
        exec(&pool, &format!("BEGIN;{rollback}"))
            .await
            .expect("the rollback section applies");
        assert!(!column_exists(&pool).await);
        assert_eq!(ledger_rows(&pool).await, before, "the ledger is put back");
        let rolled_back: bool = sqlx::query_scalar(
            "SELECT rolled_back FROM _supatype.migrations ORDER BY id DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(rolled_back, "the migration is marked rolled back");
        let outcome = push(&pool, &widgets(false)).await.unwrap();
        assert!(up_to_date(&outcome), "{outcome:?}");
    })
    .await;
}

async fn column_exists(pool: &PgPool) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns
                         WHERE table_name = 'widgets' AND column_name = 'note')",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

/// `supatype migrate` without `--record`.
async fn plain_migrate(pool: &PgPool, ast: &SchemaAst) -> anyhow::Result<String> {
    migrate_file::render(pool, ast, "public", migrate_file::Options::default()).await
}

/// IN-A: plain `migrate` writes the file without locking anything an application uses. Another
/// session holds EXCLUSIVE on every table, which lets only ACCESS SHARE through: a migrate that
/// took anything stronger (the rehearsal's `ALTER TABLE`, the bootstrap's) would wait on it.
/// While it runs, no other session holds a lock stronger than ACCESS SHARE on them either.
#[tokio::test(flavor = "multi_thread")]
async fn plain_migrate_takes_no_lock_stronger_than_access_share() {
    use common::locks::{side_pool, LockSampler};
    common::with_integration_pool(|pool| async move {
        push(&pool, &widgets(false)).await.unwrap();
        exec(
            &pool,
            "INSERT INTO public.widgets (id, label) VALUES (gen_random_uuid(), 'a')",
        )
        .await
        .unwrap();
        let holder = side_pool(&pool, 1).await;
        let mut held = holder.begin().await.unwrap();
        let holder_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *held)
            .await
            .unwrap();
        sqlx::raw_sql(
            "LOCK TABLE public.widgets, _supatype.migrations, _supatype.managed_objects,
                        _supatype.managed_objects_undo, _supatype.schema_state,
                        _supatype.engine_bootstrap IN EXCLUSIVE MODE",
        )
        .execute(&mut *held)
        .await
        .unwrap();
        let tables = [
            "widgets",
            "migrations",
            "managed_objects",
            "managed_objects_undo",
            "schema_state",
            "engine_bootstrap",
        ];
        let locks = LockSampler::start(&pool, &tables, vec![holder_pid]).await;
        let file = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            plain_migrate(&pool, &widgets(true)),
        )
        .await
        .expect("migrate waited on a lock another session holds")
        .expect("the file renders");
        let seen = locks.finish().await;
        held.rollback().await.unwrap();

        assert!(
            seen.iter().all(|(_, mode)| mode == "AccessShareLock"),
            "migrate took {seen:?}"
        );
        assert!(file.contains("ADD COLUMN"), "{file}");
        assert!(
            file.contains("does not record") && file.contains("unmanaged"),
            "the file says applying it by hand leaves no record: {file}"
        );
        assert!(!column_exists(&pool).await, "migrate wrote to the database");
    })
    .await;
}

/// A migrate file's forced migration that drops `widgets.note`.
const RECORD_FORCED: migrate_file::Options = migrate_file::Options {
    force: true,
    record: true,
};

/// Every column, migration and ledger row a rollback section could change, in order.
async fn database(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT 'column ' || table_name || '.' || column_name FROM information_schema.columns
          WHERE table_schema = 'public'
         UNION ALL
         SELECT 'migration ' || name || ' ' || status || ' ' || rolled_back FROM _supatype.migrations
         UNION ALL
         SELECT 'ledger ' || concat_ws(' ', kind, parent, name, status) FROM _supatype.managed_objects
         ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The rollback section of a file whose migration dropped a column stops at its first statement
/// with the refusal `supatype rollback` gives, so running it by hand changes nothing. It used to
/// run, mark the migration rolled back and leave the column gone.
#[tokio::test]
async fn a_migrate_files_rollback_section_refuses_when_the_migration_dropped_a_column() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &widgets(true)).await.unwrap();
        let file = migrate_file::render(&pool, &widgets(false), "public", RECORD_FORCED)
            .await
            .expect("the file renders");
        exec(&pool, forward(&file)).await.expect("applies");
        assert!(
            !column_exists(&pool).await,
            "the forward section dropped note"
        );
        let before = database(&pool).await;

        let (_, rollback) = file
            .split_once("ROLLBACK MIGRATION")
            .expect("the file has a rollback section");
        let rollback = rollback.split_once("BEGIN;").map(|(_, r)| r).unwrap();
        let mut conn = pool.acquire().await.unwrap();
        let err = sqlx::raw_sql(&format!("BEGIN;{rollback}"))
            .execute(&mut *conn)
            .await
            .expect_err("the rollback section ran");
        let _ = sqlx::raw_sql("ROLLBACK").execute(&mut *conn).await;
        drop(conn);

        let said = err.to_string();
        assert!(
            said.contains("data_not_restorable: This migration dropped column public.widgets.note"),
            "{said}"
        );
        assert!(
            said.contains("restore the database from a backup"),
            "{said}"
        );
        assert_eq!(
            database(&pool).await,
            before,
            "the refused section changed the database"
        );
    })
    .await;
}
