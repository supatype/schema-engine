//! Phase 3c of the managed-object ownership plan: one push, in the library, that the CLI, the
//! server and the tests all run.
//!
//! What the orchestrator promises: a first push applies and records one migration; a second push
//! of the same schema is up to date and records nothing new (the "second push applies zero
//! operations" invariant of plan section 11); a push that fails mid-apply leaves the database as
//! it was and records the failure. The ledger exists and stays empty until a kind moves onto the
//! reconcile.

mod common;

use supatype_engine::{
    introspector::fingerprint::ObjectKind, ledger, parser, parser::ast::SchemaAst, push,
};

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

use common::push;

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

        // The ledger holds a row for every object of a moved kind the push created, each linked
        // to the migration, and nothing of any other kind.
        let mut conn = pool.acquire().await.unwrap();
        let rows = ledger::load(&mut conn).await.unwrap();
        assert!(
            rows.iter().all(|r| push::MOVED_KINDS.contains(&r.key.kind)),
            "{rows:#?}"
        );
        assert!(
            rows.iter()
                .any(|r| r.key.kind == ObjectKind::Check && r.key.name == "users_email_check"),
            "the Email type check on users is recorded: {rows:#?}"
        );
        assert!(rows.iter().all(|r| r.migration_id.is_some()));
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

/// The reconcile is decided from the ledger and the live objects, read before the apply's
/// transaction begins (and, for the CLI, before it asks for confirmation). A change landing in
/// between would have the push apply statements decided against a database that no longer
/// exists, so the apply re-reads them inside its transaction and refuses.
#[tokio::test]
async fn a_database_changed_between_plan_and_apply_is_refused_not_overwritten() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        let ast = fixture();
        push(&pool, &ast).await.unwrap();
        let before = migrations(&pool).await;

        let short = fixture_with_short_titles();
        let plan = push::prepare(&pool, &short, "public").await.unwrap();
        // Someone's own index on a model table, made after the plan was read.
        sqlx::raw_sql("CREATE INDEX their_index ON public.posts (id)")
            .execute(&pool)
            .await
            .unwrap();
        let err = push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .expect_err("a plan for a database that has moved must not apply");
        let message = format!("{err:#}");
        assert!(
            message.contains("changed after this push was planned"),
            "{message}"
        );
        assert!(message.contains("their_index"), "{message}");
        let bound: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_constraint WHERE pg_get_constraintdef(oid) LIKE '%<= 10%'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(bound, 0, "nothing of the stale plan was applied");
        assert_eq!(
            migrations(&pool)
                .await
                .iter()
                .filter(|(_, s)| s == "applied")
                .count(),
            before.len()
        );

        // Planned again, against the database as it is now, the same push applies.
        let plan = push::prepare(&pool, &short, "public").await.unwrap();
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .expect("a fresh plan applies");
    })
    .await;
}
