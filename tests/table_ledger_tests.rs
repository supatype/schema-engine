//! Phase 4.11 of the managed-object ownership plan: tables and unique constraints on the ledger.
//!
//! Both were judged by the `supatype:managed` stamp in their comment, which the user can overwrite
//! and PostgREST publishes. A table is a ledger row now: the table differ still makes, renames and
//! drops it, but only where the ledger says it is ours, and a stamp counts only until the next push
//! records it (plan section 7). A unique constraint is an ordinary kind, made and dropped by the
//! reconcile, and its differ is gone.

mod common;

use common::{exec, push, up_to_date};
use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    introspector::fingerprint::ObjectKind, ledger, parser, parser::ast::SchemaAst, push,
};

fn field(pg_type: &str, unique: bool) -> Value {
    json!({ "kind": "text", "annotations": { "db": { "pgType": pg_type, "unique": unique } } })
}

fn model(name: &str, table: &str, fields: Value) -> Value {
    json!({
        "name": name,
        "fields": fields,
        "options": { "timestamps": false, "softDelete": false, "singleton": false },
        "annotations": { "db": { "tableName": table, "indexes": [] },
                         "platform": { "access": { "read": { "type": "public" } } } }
    })
}

fn id() -> Value {
    json!({ "kind": "integer", "primaryKey": true, "required": true,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } })
}

/// `posts` (its `slug` unique or not), and `notes` when asked for.
fn schema(slug_unique: bool, with_notes: bool) -> SchemaAst {
    schema_with_posts_in("posts", slug_unique, with_notes)
}

fn schema_with_posts_in(posts_table: &str, slug_unique: bool, with_notes: bool) -> SchemaAst {
    let mut models = vec![model(
        "Post",
        posts_table,
        json!({ "id": id(), "title": field("TEXT", false), "slug": field("TEXT", slug_unique) }),
    )];
    // Another table name is a rename of `posts`, declared: renames are never guessed (D1).
    if posts_table != "posts" {
        models[0]["annotations"]["db"]["renamedFrom"] = json!("posts");
    }
    if with_notes {
        models.push(model(
            "Note",
            "notes",
            json!({ "id": id(), "body": field("TEXT", false) }),
        ));
    }
    let doc = json!({ "astVersion": 2, "models": models });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

fn forced() -> push::ApplyOptions {
    push::ApplyOptions {
        force: true,
        ..Default::default()
    }
}

/// The recorded rows of `kind`, as `parent.name` (or the name alone) with their status.
async fn recorded(pool: &PgPool, kind: ObjectKind) -> Vec<String> {
    let mut conn = pool.acquire().await.unwrap();
    let mut rows: Vec<String> = ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == kind && r.key.schema == "public")
        .map(|r| {
            let name = if r.key.parent.is_empty() {
                r.key.name
            } else {
                format!("{}.{}", r.key.parent, r.key.name)
            };
            format!("{name} {}", r.status.as_str())
        })
        .collect();
    rows.sort();
    rows
}

async fn table_exists(pool: &PgPool, table: &str) -> bool {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("public.{table}"))
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn constraints_on_posts(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT conname::text FROM pg_constraint
          WHERE conrelid = 'public.posts'::regclass AND contype = 'u' ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn every_table_and_unique_constraint_a_push_makes_is_recorded() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(true, true)).await.unwrap();
        assert_eq!(
            recorded(&pool, ObjectKind::Table).await,
            ["notes managed", "posts managed"]
        );
        assert_eq!(
            recorded(&pool, ObjectKind::Unique).await,
            ["posts.posts_slug_key managed"]
        );
        assert!(up_to_date(&push(&pool, &schema(true, true)).await.unwrap()));
    })
    .await;
}

#[tokio::test]
async fn the_ledger_not_the_comment_says_a_table_is_ours() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(false, true)).await.unwrap();
        // Section 6: comments are the user's. Writing one over the stamp must not disown the table.
        exec(&pool, "COMMENT ON TABLE public.notes IS 'Notes we keep.'")
            .await
            .unwrap();
        assert!(up_to_date(
            &push(&pool, &schema(false, true)).await.unwrap()
        ));

        common::push_with(&pool, &schema(false, false), forced())
            .await
            .unwrap();
        assert!(
            !table_exists(&pool, "notes").await,
            "a table the ledger records was kept because its comment no longer carried the stamp"
        );
        assert_eq!(recorded(&pool, ObjectKind::Table).await, ["posts managed"]);
    })
    .await;
}

#[tokio::test]
async fn a_released_table_is_left_alone() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(false, true)).await.unwrap();
        exec(
            &pool,
            "UPDATE _supatype.managed_objects SET status = 'released'
              WHERE kind = 'table' AND name = 'notes'",
        )
        .await
        .unwrap();

        common::push_with(&pool, &schema(false, false), forced())
            .await
            .unwrap();
        assert!(
            table_exists(&pool, "notes").await,
            "a released table was dropped"
        );
        assert_eq!(
            recorded(&pool, ObjectKind::Table).await,
            ["notes released", "posts managed"]
        );
    })
    .await;
}

#[tokio::test]
async fn a_table_an_older_engine_stamped_is_recorded_by_the_next_push() {
    common::with_integration_pool(|pool| async move {
        exec(
            &pool,
            "CREATE TABLE public.posts (id integer PRIMARY KEY, title text, slug text);
             COMMENT ON TABLE public.posts IS 'supatype:managed;kind=table';",
        )
        .await
        .unwrap();
        push(&pool, &schema(false, false)).await.unwrap();
        assert_eq!(recorded(&pool, ObjectKind::Table).await, ["posts managed"]);
    })
    .await;
}

#[tokio::test]
async fn a_column_someone_adds_does_not_make_its_table_drift() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(false, false);
        push(&pool, &ast).await.unwrap();
        exec(&pool, "ALTER TABLE public.posts ADD COLUMN notes text")
            .await
            .unwrap();

        let report = common::doctor(&pool, &ast).await;
        assert!(report.drifted.is_empty(), "{:#?}", report.drifted);
        assert!(report
            .unmanaged_drift
            .iter()
            .any(|i| i.kind == "column" && i.name == "notes"));
    })
    .await;
}

#[tokio::test]
async fn a_unique_constraint_dropped_by_hand_is_put_back() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(true, false)).await.unwrap();
        exec(
            &pool,
            "ALTER TABLE public.posts DROP CONSTRAINT posts_slug_key",
        )
        .await
        .unwrap();
        push(&pool, &schema(true, false)).await.unwrap();
        assert_eq!(constraints_on_posts(&pool).await, ["posts_slug_key"]);
    })
    .await;
}

#[tokio::test]
async fn an_undeclared_unique_of_ours_goes_and_one_someone_added_stays() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(true, false)).await.unwrap();
        exec(
            &pool,
            "ALTER TABLE public.posts ADD CONSTRAINT posts_title_mine UNIQUE (title)",
        )
        .await
        .unwrap();
        push(&pool, &schema(false, false)).await.unwrap();
        assert_eq!(constraints_on_posts(&pool).await, ["posts_title_mine"]);
        assert!(recorded(&pool, ObjectKind::Unique).await.is_empty());
    })
    .await;
}

#[tokio::test]
async fn a_renamed_table_keeps_its_rows_and_its_records_follow_it() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(true, false)).await.unwrap();
        exec(
            &pool,
            "INSERT INTO public.posts (id, title, slug) VALUES (1, 'a', 'a')",
        )
        .await
        .unwrap();

        common::push_with(
            &pool,
            &schema_with_posts_in("posts_archive", true, false),
            forced(),
        )
        .await
        .unwrap();

        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM public.posts_archive")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1, "the rename lost the table's rows");
        assert!(!table_exists(&pool, "posts").await);
        assert_eq!(
            recorded(&pool, ObjectKind::Table).await,
            ["posts_archive managed"]
        );
        assert_eq!(
            recorded(&pool, ObjectKind::Unique).await,
            ["posts_archive.posts_archive_slug_key managed"]
        );
        assert!(up_to_date(
            &push(&pool, &schema_with_posts_in("posts_archive", true, false))
                .await
                .unwrap()
        ));
    })
    .await;
}

/// A push that renames a table and drops one of its columns drops it: the column's row is still
/// under the table's old name, which is where its ownership is looked up. It used to be looked up
/// under the new name, found no row, and was kept as someone else's.
#[tokio::test]
async fn a_column_dropped_with_its_tables_rename_is_dropped() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(false, false)).await.unwrap();
        let mut archive = model(
            "Post",
            "posts_archive",
            json!({ "id": id(), "title": field("TEXT", false) }),
        );
        archive["annotations"]["db"]["renamedFrom"] = json!("posts");
        let without_slug =
            parser::parse(&json!({ "astVersion": 2, "models": [archive] }).to_string()).unwrap();
        let outcome = common::push_with(&pool, &without_slug, forced())
            .await
            .unwrap();
        let push::Outcome::Applied { warnings, .. } = &outcome else {
            panic!("{outcome:?}");
        };
        assert!(
            !warnings.iter().any(|w| w.contains("not Supatype's")),
            "{warnings:?}"
        );
        let columns: Vec<String> = sqlx::query_scalar(
            "SELECT column_name::text FROM information_schema.columns
              WHERE table_schema = 'public' AND table_name = 'posts_archive' ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(columns, ["id", "title"]);
        assert!(up_to_date(&push(&pool, &without_slug).await.unwrap()));
    })
    .await;
}

#[tokio::test]
async fn a_unique_an_older_engine_recorded_with_its_stamp_is_not_rebuilt() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(true, false)).await.unwrap();
        let oid = || async {
            sqlx::query_scalar::<_, i64>(
                "SELECT oid::bigint FROM pg_constraint WHERE conname = 'posts_slug_key'",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        let before = oid().await;
        // How an engine before Phase 6 recorded it: the statement it ran, stamp and all, and a
        // fingerprint taken over that statement.
        exec(
            &pool,
            "UPDATE _supatype.managed_objects
                SET desired_sql = desired_sql || E'\nCOMMENT ON CONSTRAINT \"posts_slug_key\" ON \"public\".\"posts\" IS ''supatype:managed;kind=unique_constraint;table=posts;fields=slug;v=1'';',
                    desired_fp = 'from-an-older-engine'
              WHERE kind = 'unique' AND name = 'posts_slug_key'",
        )
        .await
        .unwrap();

        let outcome = push(&pool, &schema(true, false)).await.unwrap();
        assert!(up_to_date(&outcome), "the constraint was replaced: {outcome:?}");
        assert_eq!(oid().await, before, "the constraint was dropped and added again");
    })
    .await;
}

/// With no row, a unique constraint is matched by its columns, as the differ it replaced matched
/// it. An older engine's under a name of its own is renamed to ours and recorded, not dropped and
/// built again. One someone added on the same column is theirs: the push refuses until it is
/// adopted, and never builds a duplicate beside it.
#[tokio::test]
async fn a_unique_with_no_row_is_matched_by_its_columns_not_duplicated() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(true, false)).await.unwrap();
        let oid = || async {
            sqlx::query_scalar::<_, i64>(
                "SELECT oid::bigint FROM pg_constraint WHERE conname = 'posts_slug_key'",
            )
            .fetch_one(&pool)
            .await
            .unwrap()
        };
        let before = oid().await;
        common::as_an_older_engine_left_it(&pool).await.unwrap();
        exec(
            &pool,
            "ALTER TABLE public.posts RENAME CONSTRAINT posts_slug_key TO posts_slug_unique;
             COMMENT ON CONSTRAINT posts_slug_unique ON public.posts
               IS 'supatype:managed;kind=unique_constraint;table=posts;fields=slug;v=1';",
        )
        .await
        .unwrap();

        push(&pool, &schema(true, false)).await.unwrap();
        assert_eq!(constraints_on_posts(&pool).await, ["posts_slug_key"]);
        assert_eq!(
            oid().await,
            before,
            "the constraint was dropped and added again"
        );
        assert_eq!(
            recorded(&pool, ObjectKind::Unique).await,
            ["posts.posts_slug_key managed"]
        );
        assert!(up_to_date(
            &push(&pool, &schema(true, false)).await.unwrap()
        ));

        // Someone's own unique on the column, before the schema declares one.
        push(&pool, &schema(false, false)).await.unwrap();
        assert!(constraints_on_posts(&pool).await.is_empty());
        exec(
            &pool,
            "ALTER TABLE public.posts ADD CONSTRAINT posts_slug_mine UNIQUE (slug)",
        )
        .await
        .unwrap();
        let refused = push(&pool, &schema(true, false)).await.unwrap_err();
        let message = format!("{refused:#}");
        assert!(
            message.contains("posts_slug_mine") && message.contains("supatype adopt"),
            "{message}"
        );
        assert_eq!(constraints_on_posts(&pool).await, ["posts_slug_mine"]);

        let keys = ["unique:posts.posts_slug_mine".to_string()];
        supatype_engine::adopt::run(
            &pool,
            &schema(true, false),
            "public",
            supatype_engine::adopt::Request {
                apply: true,
                keys: Some(&keys),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        push(&pool, &schema(true, false)).await.unwrap();
        assert_eq!(constraints_on_posts(&pool).await, ["posts_slug_key"]);
        assert_eq!(
            recorded(&pool, ObjectKind::Unique).await,
            ["posts.posts_slug_key managed"]
        );
        assert!(up_to_date(
            &push(&pool, &schema(true, false)).await.unwrap()
        ));
    })
    .await;
}

/// A model's affordance functions take its table's row type, so a function of the old name goes
/// before the table is renamed: afterwards its drop names a type that no longer exists, is
/// skipped, and leaves the function behind with its row removed.
#[tokio::test]
async fn a_renamed_tables_affordance_functions_do_not_outlive_its_old_name() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(true, false)).await.unwrap();
        common::push_with(
            &pool,
            &schema_with_posts_in("posts_archive", true, false),
            forced(),
        )
        .await
        .unwrap();
        let functions: Vec<String> = sqlx::query_scalar(
            "SELECT p.proname::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'public' AND p.proname LIKE 'can\\_%' ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(
            functions.iter().all(|f| f.ends_with("_posts_archive")),
            "an affordance function of the old name was orphaned: {functions:?}"
        );
        assert!(!functions.is_empty());
    })
    .await;
}
