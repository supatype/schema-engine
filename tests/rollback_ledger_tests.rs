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

/// `posts`, and a `tags` table with columns `a` and `c` made by the same push.
fn posts_and_tags() -> SchemaAst {
    let mut doc = serde_json::to_value(posts("title")).unwrap();
    let text = || {
        json!({ "kind": "text", "required": false,
        "annotations": { "db": { "pgType": "TEXT", "unique": false } } })
    };
    doc["models"].as_array_mut().unwrap().push(json!({
        "name": "Tag",
        "fields": {
            "id": { "kind": "integer", "primaryKey": true, "required": true,
                    "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
            "a": text(),
            "c": text()
        },
        "options": { "timestamps": false, "softDelete": false, "singleton": false },
        "annotations": { "db": { "tableName": "tags" },
                         "platform": { "access": { "read": { "type": "public" } } } }
    }));
    serde_json::from_value(doc).expect("the AST round-trips")
}

async fn table_exists(pool: &PgPool, name: &str) -> bool {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("public.{name}"))
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Every ledger row on `tags`, as `kind:parent.name status`.
async fn rows_on_tags(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT kind || ':' || parent || '.' || name || ' ' || status
           FROM _supatype.managed_objects
          WHERE parent = 'tags' OR (kind = 'table' AND name = 'tags')
          ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// E35: the push that made `tags` is rolled back after a column of `tags` was released. Dropping
/// the table would drop the released column with its data, so the rollback is refused, naming
/// the column, and nothing changes.
#[tokio::test]
async fn rolling_back_the_push_that_made_a_table_refuses_when_a_column_of_it_was_released() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &posts("title")).await.unwrap();
        let ast = posts_and_tags();
        push(&pool, &ast).await.unwrap();
        release(&pool, &ast, &["column:tags.c"]).await;
        exec(
            &pool,
            "INSERT INTO public.tags (id, a, c) VALUES (1, 'a', 'released data')",
        )
        .await
        .unwrap();
        let before = ledger(&pool).await;

        let err = migration_history::apply_rollback(&pool, "public")
            .await
            .expect_err("the rollback would drop a released column with its table");
        let message = format!("{err:#}");
        assert!(message.contains("public.tags.c"), "{message}");
        assert!(message.contains("released"), "{message}");

        let c: String = sqlx::query_scalar("SELECT c FROM public.tags WHERE id = 1")
            .fetch_one(&pool)
            .await
            .expect("the table and the released column's data are still there");
        assert_eq!(c, "released data");
        assert_eq!(
            ledger(&pool).await,
            before,
            "a refused rollback wrote the ledger"
        );

        // Handed back, the column is the push's again, and the rollback goes ahead.
        let reclaim = ["column:tags.c".to_string()];
        supatype_engine::adopt::run(
            &pool,
            &ast,
            "public",
            supatype_engine::adopt::Request {
                reclaim: &reclaim,
                apply: true,
                keys: Some(&[]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("with nothing released on it, the table goes");
        assert!(!table_exists(&pool, "tags").await);
        assert_eq!(rows_on_tags(&pool).await, Vec::<String>::new());
    })
    .await;
}

/// A released row whose table is gone describes nothing: the next push removes it. An engine
/// before this one left such a row when it rolled back the push that made the table.
#[tokio::test]
async fn a_released_row_whose_table_is_gone_is_removed_by_the_next_push() {
    common::with_integration_pool(|pool| async move {
        let ast = posts_and_tags();
        push(&pool, &ast).await.unwrap();
        release(&pool, &ast, &["column:tags.c"]).await;
        exec(&pool, "DROP TABLE public.tags CASCADE").await.unwrap();

        push(&pool, &posts("title")).await.unwrap();
        assert_eq!(rows_on_tags(&pool).await, Vec::<String>::new());
    })
    .await;
}
