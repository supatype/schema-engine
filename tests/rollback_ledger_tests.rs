//! Rolling a push back puts the managed-object ledger back with the objects.
//!
//! A rollback runs the migration's `sql_down`, which restores the objects; until now the ledger
//! kept the rolled-back push's rows, so the next push read rows for objects that were gone and
//! none for ones that were back. Each push now records what it overwrote, and a rollback restores
//! it (`ledger::undo`).

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst, push, state::migration_history};

use common::{exec, push};

fn posts(index: &str) -> SchemaAst {
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Post",
            "fields": {
                "id": { "kind": "integer", "primaryKey": true, "required": true,
                        "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
                "title": { "kind": "text", "required": true,
                           "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
                "body": { "kind": "text", "required": true,
                          "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
            },
            "options": { "timestamps": false, "softDelete": false, "singleton": false },
            "annotations": { "db": { "tableName": "posts", "indexes": indexes(index) },
                             "platform": { "access": { "read": { "type": "public" } } } }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

fn indexes(field: &str) -> Value {
    json!([{ "fields": [field], "name": format!("posts_{field}_idx"), "unique": false, "using": "btree" }])
}

/// Every ledger row, in full but for its timestamps, in key order.
async fn ledger(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT concat_ws(' ', kind, schema_name, parent, name, desired_fp, live_fp, status,
                          coalesce(migration_id::text, '-'))
           FROM _supatype.managed_objects ORDER BY kind, schema_name, parent, name",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn index_exists(pool: &PgPool, name: &str) -> bool {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("public.{name}"))
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn rolling_back_a_push_puts_the_ledger_back_as_it_was() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts("title")).await.unwrap();
        let before = ledger(&pool).await;

        // The second push drops the title index (removing its row) and adds the body index.
        push(&pool, &posts("body")).await.unwrap();
        assert_ne!(ledger(&pool).await, before);

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the second push rolls back");
        assert!(index_exists(&pool, "posts_title_idx").await);
        assert!(!index_exists(&pool, "posts_body_idx").await);
        assert_eq!(
            ledger(&pool).await,
            before,
            "the ledger kept the rolled-back push's rows"
        );

        // Ledger and database agree again, so the first schema has nothing left to do.
        let outcome = push(&pool, &posts("title")).await.unwrap();
        assert!(
            matches!(outcome, push::Outcome::UpToDate { .. }),
            "{outcome:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_migration_with_nothing_recorded_rolls_back_and_leaves_the_ledger_alone() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts("title")).await.unwrap();
        push(&pool, &posts("body")).await.unwrap();
        // As a migration an engine from before the undo record left it.
        exec(
            &pool,
            "DELETE FROM _supatype.managed_objects_undo WHERE true",
        )
        .await
        .unwrap();
        let after = ledger(&pool).await;

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("rolls back with nothing recorded");
        assert_eq!(ledger(&pool).await, after);
    })
    .await;
}

/// An engine from before Phase 4.0 stored `sql_down` as a script with its own `BEGIN`/`COMMIT`.
/// Run inside the rollback's transaction, its `COMMIT` ended that transaction after the objects
/// came back and before the history and the ledger were updated.
#[tokio::test]
async fn a_legacy_rollback_script_runs_inside_the_rollbacks_transaction() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts("title")).await.unwrap();
        push(&pool, &posts("body")).await.unwrap();
        exec(
            &pool,
            "UPDATE _supatype.migrations
                SET sql_down = E'-- ROLLBACK MIGRATION\\nBEGIN;\\n' || sql_down || E'\\nCOMMIT;\\n'
              WHERE id = (SELECT max(id) FROM _supatype.migrations)",
        )
        .await
        .unwrap();
        // The rollback's last step fails, after the legacy script's `COMMIT` would have run.
        exec(
            &pool,
            "CREATE FUNCTION public.refuse() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'refused'; END; $$;
             CREATE TRIGGER refuse BEFORE UPDATE ON _supatype.migrations
               FOR EACH ROW EXECUTE FUNCTION public.refuse();",
        )
        .await
        .unwrap();

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect_err("the history update is refused");
        assert!(
            index_exists(&pool, "posts_body_idx").await,
            "the objects' rollback went back with the failed history update"
        );
        assert!(!index_exists(&pool, "posts_title_idx").await);

        exec(&pool, "DROP TRIGGER refuse ON _supatype.migrations")
            .await
            .unwrap();
        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the legacy script rolls back");
        assert!(index_exists(&pool, "posts_title_idx").await);
        assert!(!index_exists(&pool, "posts_body_idx").await);
    })
    .await;
}

async fn table_comment(pool: &PgPool) -> Option<String> {
    sqlx::query_scalar("SELECT obj_description('public.posts'::regclass, 'pg_class')")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn rolling_back_the_push_that_took_over_a_stamped_table_puts_the_stamp_back() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts("title")).await.unwrap();
        // The upgrade: an older engine's stamped table, taken over by the push that takes the stamp
        // out of its comment.
        common::as_an_older_engine_left_it(&pool).await.unwrap();
        let stamp = table_comment(&pool).await;
        assert!(stamp
            .as_deref()
            .unwrap_or_default()
            .starts_with("supatype:managed"));
        push(&pool, &posts("title")).await.unwrap();
        assert_eq!(
            table_comment(&pool).await,
            None,
            "the stamp was not taken out"
        );

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the upgrade push rolls back");
        assert_eq!(
            table_comment(&pool).await,
            stamp,
            "the rollback removed the row and left the table with neither row nor stamp"
        );

        // Recognisably ours again, so the next push takes it over rather than refusing it.
        push(&pool, &posts("title"))
            .await
            .expect("the table is Supatype's after the rollback");
    })
    .await;
}

#[tokio::test]
async fn a_release_made_after_a_push_survives_rolling_that_push_back() {
    use supatype_engine::adopt;
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts("title")).await.unwrap();
        push(&pool, &posts("body")).await.unwrap();
        // Released after the push, outside any migration: not the push's to undo.
        let release = ["policy:posts.posts_select".to_string()];
        adopt::run(
            &pool,
            &posts("body"),
            "public",
            adopt::Request {
                release: &release,
                apply: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the second push rolls back");
        assert!(index_exists(&pool, "posts_title_idx").await);
        let status: String = sqlx::query_scalar(
            "SELECT status FROM _supatype.managed_objects
              WHERE kind = 'policy' AND parent = 'posts' AND name = 'posts_select'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(status, "released", "the rollback overwrote a later release");
    })
    .await;
}

/// `posts` with the `title` index and an extra `note` column.
fn posts_with_note() -> SchemaAst {
    let mut ast = posts("body");
    let doc = serde_json::to_value(&ast).unwrap();
    let mut doc = doc;
    doc["models"][0]["fields"]["note"] = json!({ "kind": "text", "required": false,
        "annotations": { "db": { "pgType": "TEXT", "unique": false } } });
    ast = serde_json::from_value(doc).expect("the AST round-trips");
    ast
}

async fn release(pool: &PgPool, ast: &SchemaAst, objects: &[&str]) {
    use supatype_engine::adopt;
    let release: Vec<String> = objects.iter().map(|o| o.to_string()).collect();
    adopt::run(
        pool,
        ast,
        "public",
        adopt::Request {
            release: &release,
            apply: true,
            keys: Some(&[]),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

/// A column and an index the push made, released after it: rolling the push back leaves both,
/// and the column's data, where they are, with their rows still saying released. It used to drop
/// the column with its data and leave a row for a column that was gone.
#[tokio::test]
async fn rolling_back_leaves_what_was_released_since_the_push() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts("title")).await.unwrap();
        let ast = posts_with_note();
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "INSERT INTO public.posts (id, title, body, note) VALUES (1, 't', 'b', 'kept')",
        )
        .await
        .unwrap();
        release(
            &pool,
            &ast,
            &["column:posts.note", "index:posts.posts_body_idx"],
        )
        .await;

        let result = migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the push rolls back");
        assert!(result.message.contains("posts.note"), "{}", result.message);

        let note: String = sqlx::query_scalar("SELECT note FROM public.posts WHERE id = 1")
            .fetch_one(&pool)
            .await
            .expect("the released column and its data are still there");
        assert_eq!(note, "kept");
        assert!(index_exists(&pool, "posts_body_idx").await);
        // The rest of the push is undone.
        assert!(index_exists(&pool, "posts_title_idx").await);
        let released: Vec<String> = sqlx::query_scalar(
            "SELECT kind || ':' || parent || '.' || name FROM _supatype.managed_objects
              WHERE status = 'released' ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            released,
            ["column:posts.note", "index:posts.posts_body_idx"]
        );
    })
    .await;
}

/// E36: a rollback runs every statement on the transaction that holds the engine's lock. It used
/// to choose the migration, check the project and repair `schema_state` on other pool sessions,
/// which autocommitted outside the lock. On a pool of one connection, any statement sent elsewhere
/// waits for the connection the rollback's own transaction holds, until the pool gives up.
#[tokio::test]
async fn a_rollback_runs_every_statement_on_its_locked_transaction() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts("title")).await.unwrap();
        push(&pool, &posts("body")).await.unwrap();
        let one = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(pool.connect_options().as_ref().clone())
            .await
            .unwrap();
        migration_history::apply_rollback(&one, "public")
            .await
            .expect("the rollback needs no connection beside its own transaction");
        one.close().await;
        assert!(index_exists(&pool, "posts_title_idx").await);
        assert!(!index_exists(&pool, "posts_body_idx").await);
    })
    .await;
}

/// Each migration's name, status and whether it was rolled back, in order.
async fn history(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT name || ' ' || status || CASE WHEN rolled_back THEN ' rolled_back' ELSE '' END
           FROM _supatype.migrations ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// E10: a push that reuses a migration's name is refused before it applies anything, and the
/// earlier migration keeps its record. Recording the failure used to overwrite it
/// (`ON CONFLICT (name) DO UPDATE SET status = 'failed'`), so a rollback undid the push before it
/// and the named one could never be rolled back.
#[tokio::test]
async fn a_reused_migration_name_is_refused_and_rollback_undoes_the_right_push() {
    common::with_integration_pool(|pool| async move {
        let named = |name: &str| push::ApplyOptions {
            name: Some(name.into()),
            ..Default::default()
        };
        push(&pool, &posts("title")).await.unwrap();
        common::push_with(&pool, &posts("body"), named("mig_a"))
            .await
            .unwrap();
        let reused = common::push_with(&pool, &posts("id"), named("mig_a"))
            .await
            .expect_err("a second migration named mig_a was applied");
        assert!(format!("{reused:#}").contains("mig_a"), "{reused:#}");
        assert!(index_exists(&pool, "posts_body_idx").await);
        assert!(
            !index_exists(&pool, "posts_id_idx").await,
            "the refused push applied"
        );
        let names = history(&pool).await;
        assert_eq!(names.len(), 2, "{names:?}");
        assert_eq!(names[1], "mig_a applied", "{names:?}");

        let undone = migration_history::apply_rollback(&pool, "public")
            .await
            .unwrap();
        assert_eq!(undone.name, "mig_a");
        assert!(index_exists(&pool, "posts_title_idx").await);
        assert!(!index_exists(&pool, "posts_body_idx").await);
    })
    .await;
}

/// A failure recorded under a name a migration already has is recorded under a name of its own,
/// and never changes the row that had it.
#[tokio::test]
async fn a_failure_never_overwrites_a_recorded_migration() {
    common::with_integration_pool(|pool| async move {
        common::push_with(
            &pool,
            &posts("title"),
            push::ApplyOptions {
                name: Some("mig_a".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        migration_history::record_failed_migration(&pool, "mig_a", "sha256:x", "SELECT 1;", "boom")
            .await
            .unwrap();
        let names = history(&pool).await;
        assert_eq!(names[0], "mig_a applied", "{names:?}");
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(
            names[1].starts_with("mig_a") && names[1].ends_with(" failed"),
            "{names:?}"
        );
    })
    .await;
}
