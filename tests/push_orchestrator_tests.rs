//! Phase 3c of the managed-object ownership plan: one push, in the library, that the CLI, the
//! server and the tests all run.
//!
//! What the orchestrator promises: a first push applies and records one migration; a second push
//! of the same schema is up to date and records nothing new (the "second push applies zero
//! operations" invariant of plan section 11); a push that fails mid-apply leaves the database as
//! it was and records the failure. The ledger exists and stays empty until a kind moves onto the
//! reconcile.

mod common;

use supatype_engine::{ledger, parser, parser::ast::SchemaAst, push};

fn fixture() -> SchemaAst {
    parser::parse(include_str!("fixtures/five_model_blog.json")).unwrap()
}

/// The fixture with a 10-character bound on `Post.title`, so a push of it over a longer title
/// fails inside the transaction.
fn fixture_with_short_titles() -> SchemaAst {
    let mut doc: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/five_model_blog.json")).unwrap();
    let post = doc["models"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|m| m["name"] == "Post")
        .expect("the fixture has a Post model");
    // The CLI writes both: the bound for the SDKs and the check the generator renders.
    post["fields"]["title"]["validation"] = serde_json::json!({ "maxLength": 10 });
    post["fields"]["title"]["check"] = serde_json::json!("char_length(\"{name}\") <= 10");
    parser::parse(&doc.to_string()).unwrap()
}

async fn create_auth_users(pool: &sqlx::PgPool) {
    sqlx::raw_sql(
        "CREATE SCHEMA IF NOT EXISTS auth;
         CREATE TABLE IF NOT EXISTS auth.users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT UNIQUE);",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn migrations(pool: &sqlx::PgPool) -> Vec<(String, String)> {
    sqlx::query_as("SELECT name, status FROM _supatype.migrations ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn push(pool: &sqlx::PgPool, ast: &SchemaAst) -> anyhow::Result<push::Outcome> {
    let plan = push::prepare(pool, ast, "public").await?;
    push::apply(pool, plan, push::ApplyOptions::default()).await
}

#[tokio::test]
async fn a_first_push_applies_once_and_a_second_is_up_to_date_with_no_new_history() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        let ast = fixture();

        let first = push(&pool, &ast).await.unwrap();
        let push::Outcome::Applied {
            name, operations, ..
        } = first
        else {
            panic!("a push against an empty database applies: {first:?}");
        };
        assert!(operations > 0);
        let history = migrations(&pool).await;
        assert_eq!(history, vec![(name.clone(), "applied".to_string())]);

        let second = push(&pool, &ast).await.unwrap();
        assert!(
            matches!(second, push::Outcome::UpToDate { .. }),
            "the same schema again is up to date: {second:?}"
        );
        assert_eq!(
            migrations(&pool).await,
            vec![(name, "applied".to_string())],
            "an up-to-date push records no migration"
        );

        // The ledger exists from the first push and holds nothing until a kind moves onto the
        // reconcile.
        let mut conn = pool.acquire().await.unwrap();
        assert!(ledger::load(&mut conn).await.unwrap().is_empty());
        assert!(
            push::MOVED_KINDS.is_empty(),
            "update this test with the first moved kind"
        );
    })
    .await;
}

#[tokio::test]
async fn a_push_that_fails_mid_apply_leaves_the_database_as_it_was_and_records_the_failure() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        push(&pool, &fixture()).await.unwrap();
        sqlx::raw_sql(
            "INSERT INTO public.users (email, name) VALUES ('a@example.com', 'a');
             INSERT INTO public.posts (title, slug, content, author_id)
             SELECT 'a title much longer than ten characters', 'long',
                    '{\"type\": \"doc\", \"content\": []}'::jsonb, id
             FROM public.users",
        )
        .execute(&pool)
        .await
        .unwrap();

        let err = push(&pool, &fixture_with_short_titles())
            .await
            .expect_err("a bound the data breaches fails the push");
        assert!(
            format!("{err:#}").contains("Failed to apply migration"),
            "the failure names the step: {err:#}"
        );

        let history = migrations(&pool).await;
        assert_eq!(history.len(), 2, "{history:?}");
        assert_eq!(history[1].1, "failed");

        let constraint_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'posts_title_check')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!constraint_exists, "nothing of the failed push survives");
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM public.posts")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 1);
    })
    .await;
}
