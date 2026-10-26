//! A push refused before it applied anything is recorded in `_supatype.migrations` as `refused`.
//!
//! Studio reads the migration history to say whether the schema the project declares is the one
//! the database has. A push that failed mid-apply was recorded (`failed`), but one refused before
//! it began (a destructive change without `force`) recorded nothing, so the history said every
//! push had applied while the database was still on the schema before it.
//!
//! What a refused row promises: the statements it would have run, why it was refused, what it
//! would drop and how to apply it, under a name of its own; one row per plan however often it is
//! refused; and nothing that reads the history for the schema in force (the previous schema, the
//! latest applied row, rollback) takes it for an applied push.

mod common;

use supatype_engine::{parser, parser::ast::SchemaAst, push, state::migration_history};

fn fixture() -> SchemaAst {
    parser::parse(include_str!("fixtures/five_model_blog.json")).unwrap()
}

/// The fixture without `Tag.name`, so a push of it would drop that column and its data.
fn fixture_without_tag_name() -> SchemaAst {
    let mut doc: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/five_model_blog.json")).unwrap();
    let tag = doc["models"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|m| m["name"] == "Tag")
        .expect("the fixture has a Tag model");
    tag["fields"].as_object_mut().unwrap().remove("name");
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

/// One history row, as the tests read it.
#[derive(Debug, sqlx::FromRow)]
struct Row {
    name: String,
    status: String,
    applied_at: f64,
    sql_up: Option<String>,
    error_message: Option<String>,
    admin_config: Option<serde_json::Value>,
    refusal: Option<serde_json::Value>,
    superseded: bool,
}

async fn history(pool: &sqlx::PgPool) -> Vec<Row> {
    sqlx::query_as(
        "SELECT name, status, extract(epoch FROM applied_at)::float8 AS applied_at, sql_up, error_message,
                admin_config, to_jsonb(m) -> 'refusal' AS refusal,
                (to_jsonb(m) ->> 'superseded_at') IS NOT NULL AS superseded
           FROM _supatype.migrations m ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

fn refused(rows: &[Row]) -> Vec<&Row> {
    rows.iter().filter(|r| r.status == "refused").collect()
}

/// The fixture applied, then the destructive change pushed without `force` and refused.
async fn applied_then_refused(pool: &sqlx::PgPool) {
    create_auth_users(pool).await;
    common::push(pool, &fixture()).await.unwrap();
    let err = common::push(pool, &fixture_without_tag_name())
        .await
        .expect_err("a destructive change without force is refused");
    assert!(
        format!("{err:#}").contains("destructive operation(s) detected"),
        "{err:#}"
    );
}

#[tokio::test]
async fn a_destructive_refusal_is_recorded_with_its_statements_operations_and_command() {
    common::with_integration_pool(|pool| async move {
        applied_then_refused(&pool).await;
        let rows = history(&pool).await;
        let refused = refused(&rows);
        assert_eq!(refused.len(), 1, "{rows:#?}");
        let row = refused[0];
        assert!(row.name.starts_with("refused_"), "{}", row.name);
        assert!(
            row.error_message
                .as_deref()
                .is_some_and(|m| m.contains("1 destructive operation(s) detected")),
            "{row:#?}"
        );
        // Not in `sql_up`: an older Studio lists every row with statements as applied.
        assert!(row.sql_up.is_none(), "{row:#?}");
        let refusal = row.refusal.as_ref().expect("the refusal is recorded");
        assert_eq!(refusal["reason"], "destructive");
        assert!(
            refusal["sql"]
                .as_str()
                .is_some_and(|s| s.contains("DROP COLUMN")),
            "{refusal:#}"
        );
        assert_eq!(
            refusal["operations"],
            serde_json::json!(["drop_column tags.name"])
        );
        assert_eq!(refusal["hints"], serde_json::json!(["supatype push --yes"]));
    })
    .await;
}

#[tokio::test]
async fn the_same_plan_refused_again_moves_its_one_row_forward() {
    common::with_integration_pool(|pool| async move {
        applied_then_refused(&pool).await;
        let first = history(&pool).await;
        let was = refused(&first)[0].applied_at;
        common::push(&pool, &fixture_without_tag_name())
            .await
            .expect_err("refused again");
        let rows = history(&pool).await;
        let again = refused(&rows);
        assert_eq!(again.len(), 1, "one row per plan: {rows:#?}");
        assert!(
            again[0].applied_at > was,
            "the row is dated by the latest refusal"
        );
        assert_eq!(rows.len(), first.len());
    })
    .await;
}

#[tokio::test]
async fn an_up_to_date_push_after_a_refusal_supersedes_it_and_leaves_its_row_alone() {
    common::with_integration_pool(|pool| async move {
        applied_then_refused(&pool).await;
        let outcome = common::push(&pool, &fixture()).await.unwrap();
        assert!(
            matches!(outcome, push::Outcome::UpToDate { .. }),
            "{outcome:?}"
        );
        let rows = history(&pool).await;
        let row = refused(&rows)[0];
        assert!(row.superseded, "a later push applied: {row:#?}");
        assert!(
            row.admin_config.is_none(),
            "Studio metadata stays on the applied row"
        );
        let applied = rows.iter().find(|r| r.status == "applied").unwrap();
        assert!(applied.admin_config.is_some());

        let mut conn = pool.acquire().await.unwrap();
        let previous = migration_history::load_previous_schema(&mut conn)
            .await
            .unwrap();
        assert!(
            matches!(
                previous,
                supatype_engine::ledger::unrecorded::Previous::Found(_)
            ),
            "the previous schema is the applied one"
        );
    })
    .await;
}

#[tokio::test]
async fn a_forced_push_after_a_refusal_applies_and_supersedes_it() {
    common::with_integration_pool(|pool| async move {
        applied_then_refused(&pool).await;
        let forced = push::ApplyOptions {
            force: true,
            ..Default::default()
        };
        common::push_with(&pool, &fixture_without_tag_name(), forced)
            .await
            .expect("with force the change applies");
        let rows = history(&pool).await;
        let statuses: Vec<&str> = rows.iter().map(|r| r.status.as_str()).collect();
        assert_eq!(statuses, ["applied", "refused", "applied"], "{rows:#?}");
        assert!(refused(&rows)[0].superseded);
    })
    .await;
}

#[tokio::test]
async fn a_rollback_after_a_refusal_undoes_the_last_applied_push() {
    common::with_integration_pool(|pool| async move {
        applied_then_refused(&pool).await;
        let rows = history(&pool).await;
        let rolled = migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the applied push rolls back");
        assert_eq!(
            rolled.name, rows[0].name,
            "the refused row applied nothing, so it is never what a rollback undoes"
        );
    })
    .await;
}

#[tokio::test]
async fn a_refusal_after_a_superseding_push_is_current_again() {
    common::with_integration_pool(|pool| async move {
        applied_then_refused(&pool).await;
        common::push(&pool, &fixture()).await.unwrap();
        common::push(&pool, &fixture_without_tag_name())
            .await
            .expect_err("refused again");
        let rows = history(&pool).await;
        assert!(!refused(&rows)[0].superseded, "{rows:#?}");
    })
    .await;
}

#[tokio::test]
async fn access_changed_outside_supatype_is_recorded_as_a_refusal_until_put_back() {
    common::with_integration_pool(|pool| async move {
        create_auth_users(&pool).await;
        common::push(&pool, &fixture()).await.unwrap();
        common::exec(&pool, "GRANT TRUNCATE ON public.tags TO anon")
            .await
            .unwrap();
        let err = common::push(&pool, &fixture())
            .await
            .expect_err("access changed by hand is put back only with consent");
        assert!(
            err.downcast_ref::<supatype_engine::ledger::drift::SecurityDrift>()
                .is_some(),
            "{err:#}"
        );
        let rows = history(&pool).await;
        let refusal = refused(&rows)[0].refusal.clone().expect("recorded");
        assert_eq!(refusal["reason"], "security_drift");
        assert_eq!(refusal["hints"][0], "supatype push --overwrite-drift");
        assert!(
            refusal["operations"]
                .as_array()
                .is_some_and(|objects| !objects.is_empty()),
            "{refusal:#}"
        );

        let consent = push::ApplyOptions {
            overwrite_drift: true,
            ..Default::default()
        };
        common::push_with(&pool, &fixture(), consent).await.unwrap();
        assert!(refused(&history(&pool).await)[0].superseded);
    })
    .await;
}
