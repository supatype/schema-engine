//! A rollback of a migration that dropped a column or a table is refused before anything runs.
//!
//! The rollback SQL of such a migration can only warn that the data is gone, and then went on to
//! put back what depended on it: a unique key on the dropped column failed with `column "title"
//! named in key does not exist` partway through, and a dropped column nothing depended on was
//! marked rolled back while it stayed gone. Undo cannot bring the data back, so it now says so,
//! naming what was dropped, and leaves the database as it was.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst, push, refusal, state::migration_history};

use common::push;

fn text(unique: bool) -> Value {
    json!({ "kind": "text", "required": false,
            "annotations": { "db": { "pgType": "TEXT", "unique": unique } } })
}

fn model(name: &str, table: &str, fields: Value) -> Value {
    json!({
        "name": name,
        "fields": fields,
        "options": { "timestamps": false, "softDelete": false, "singleton": false },
        "annotations": { "db": { "tableName": table },
                         "platform": { "access": { "read": { "type": "public" } } } }
    })
}

fn id() -> Value {
    json!({ "kind": "integer", "primaryKey": true, "required": true,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } })
}

/// `posts` with `id`, a unique `title` when `with_title`, `body` when `with_body`, `note` when
/// `with_note`, and a `tags` table when `with_tags`.
struct Shape {
    with_title: bool,
    with_body: bool,
    with_note: bool,
    with_tags: bool,
}

const FULL: Shape = Shape {
    with_title: true,
    with_body: true,
    with_note: false,
    with_tags: false,
};

fn schema(shape: Shape) -> SchemaAst {
    let mut posts = serde_json::Map::new();
    posts.insert("id".into(), id());
    let optional = [
        (shape.with_title, "title", true),
        (shape.with_body, "body", false),
        (shape.with_note, "note", false),
    ];
    for (wanted, field, unique) in optional {
        if wanted {
            posts.insert(field.into(), text(unique));
        }
    }
    let mut models = vec![model("Post", "posts", Value::Object(posts))];
    if shape.with_tags {
        models.push(model(
            "Tag",
            "tags",
            json!({ "id": id(), "label": text(false) }),
        ));
    }
    let doc = json!({ "astVersion": 2, "models": models });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

async fn push_forced(pool: &PgPool, ast: &SchemaAst) {
    let options = push::ApplyOptions {
        force: true,
        ..Default::default()
    };
    common::push_with(pool, ast, options)
        .await
        .expect("the destructive push applies");
}

/// The columns, constraints, migrations and ledger rows a rollback could change, in order.
async fn database(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT 'column ' || table_name || '.' || column_name FROM information_schema.columns
          WHERE table_schema = 'public'
         UNION ALL
         SELECT 'constraint ' || conrelid::regclass::text || ' ' || conname FROM pg_constraint
          WHERE connamespace = 'public'::regnamespace
         UNION ALL
         SELECT 'migration ' || id || ' ' || name || ' ' || status || ' ' || rolled_back
           FROM _supatype.migrations
         UNION ALL
         SELECT 'ledger ' || concat_ws(' ', kind, parent, name, status, migration_id)
           FROM _supatype.managed_objects
         ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// Rolls the latest migration back, expecting it refused for the data it cannot restore, and
/// returns the refusal's message after checking nothing changed.
async fn refused_rollback(pool: &PgPool) -> String {
    let before = database(pool).await;
    let err = migration_history::apply_rollback(pool, "public")
        .await
        .expect_err("a rollback of a migration that dropped data was applied");
    let said = refusal::of(&err).unwrap_or_else(|| panic!("not a refusal: {err:#}"));
    assert_eq!(said.reason, "data_not_restorable", "{}", said.message);
    assert_eq!(
        database(pool).await,
        before,
        "the refused rollback changed the database"
    );
    said.message
}

fn assert_advises_backup_or_forward_change(message: &str) {
    assert!(message.contains("cannot be restored"), "{message}");
    assert!(
        message.contains("restore the database from a backup"),
        "{message}"
    );
    assert!(message.contains("new forward change"), "{message}");
}

#[tokio::test]
async fn rolling_back_a_dropped_unique_column_is_refused_with_nothing_applied() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(FULL)).await.unwrap();
        common::exec(
            &pool,
            "INSERT INTO public.posts (id, title, body) VALUES (1, 't', 'b')",
        )
        .await
        .unwrap();
        let without_title = Shape {
            with_title: false,
            ..FULL
        };
        push_forced(&pool, &schema(without_title)).await;

        let message = refused_rollback(&pool).await;
        assert!(message.contains("public.posts.title"), "{message}");
        assert_advises_backup_or_forward_change(&message);
        let body: String = sqlx::query_scalar("SELECT body FROM public.posts WHERE id = 1")
            .fetch_one(&pool)
            .await
            .expect("the rows are untouched");
        assert_eq!(body, "b");
    })
    .await;
}

/// A dropped column nothing depended on: the rollback used to succeed, mark the migration rolled
/// back, and leave the column gone.
#[tokio::test]
async fn rolling_back_a_dropped_plain_column_is_refused_rather_than_marked_rolled_back() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(FULL)).await.unwrap();
        let without_body = Shape {
            with_body: false,
            ..FULL
        };
        push_forced(&pool, &schema(without_body)).await;

        let message = refused_rollback(&pool).await;
        assert!(message.contains("public.posts.body"), "{message}");
        assert!(!message.contains("public.posts.title"), "{message}");
        assert_advises_backup_or_forward_change(&message);
    })
    .await;
}

#[tokio::test]
async fn rolling_back_a_dropped_table_is_refused_naming_it() {
    common::with_integration_pool(|pool| async move {
        let with_tags = Shape {
            with_tags: true,
            ..FULL
        };
        push(&pool, &schema(with_tags)).await.unwrap();
        push_forced(&pool, &schema(FULL)).await;

        let message = refused_rollback(&pool).await;
        assert!(message.contains("table public.tags"), "{message}");
        assert_advises_backup_or_forward_change(&message);
    })
    .await;
}

/// Undo of a migration that only added is unchanged: the column it added goes.
#[tokio::test]
async fn rolling_back_an_additive_migration_still_works() {
    common::with_integration_pool(|pool| async move {
        push(&pool, &schema(FULL)).await.unwrap();
        let with_note = Shape {
            with_note: true,
            ..FULL
        };
        push(&pool, &schema(with_note)).await.unwrap();

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("an additive migration rolls back");
        let columns = database(&pool).await;
        assert!(
            !columns.contains(&"column posts.note".to_string()),
            "{columns:?}"
        );
        assert!(
            columns.contains(&"column posts.title".to_string()),
            "{columns:?}"
        );
    })
    .await;
}
