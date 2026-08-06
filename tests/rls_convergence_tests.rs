//! RLS policies must converge: applying a schema, then diffing the same schema
//! against the database it just produced, has to yield no policy work.
//!
//! Non-convergence is the failure mode this differ has been bitten by repeatedly —
//! Postgres rewrites an expression when it stores it (parentheses, casts, lowercase
//! booleans, column qualification, subquery aliases), so any generated shape the
//! normaliser does not account for makes every policy look changed on every push.
//! Unit tests on `normalise` prove the string handling; only a real database proves
//! what Postgres actually stores.

mod common;

use supatype_engine::{
    differ,
    generator::sql::migration,
    introspector,
    parser,
    state::database_state::DatabaseState,
};

// Five models with access rules covering owner, role and multi-role shapes, and
// the same fixture the main integration suite applies cleanly.
const FIXTURE: &str = include_str!("fixtures/rls_access_rules.json");

fn policy_operations(ops: &[differ::Operation]) -> Vec<String> {
    ops.iter()
        .filter_map(|op| {
            let name = format!("{op:?}");
            let is_policy = name.contains("RlsPolicy") || name.contains("EnableRls");
            is_policy.then(|| name.chars().take(120).collect())
        })
        .collect()
}

#[tokio::test]
async fn policies_converge_after_the_first_push() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(FIXTURE).expect("fixture parses");

        // First push: create everything, policies included.
        let empty = DatabaseState::default();
        let first = differ::diff(&ast, &empty).unwrap();
        let sql = migration::forward_sql(&first, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql)
            .execute(&pool)
            .await
            .expect("first migration applies");

        assert!(
            !policy_operations(&first.operations).is_empty(),
            "the fixture is supposed to declare access rules"
        );

        // Second diff against the database that push produced.
        let db = introspector::introspect(&pool, "public").await.unwrap();
        let second = differ::diff(&ast, &db).unwrap();

        let churn = policy_operations(&second.operations);
        assert!(
            churn.is_empty(),
            "a no-op push must not touch policies, got: {churn:#?}"
        );
    })
    .await;
}

// The wrapping is the whole point of the change: a bare `auth.uid()` is
// re-evaluated per row, a wrapped one becomes an InitPlan evaluated once. Assert
// it reaches the database that way rather than trusting the generator's string.
#[tokio::test]
async fn stored_policies_evaluate_auth_once_per_query() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(FIXTURE).expect("fixture parses");
        let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql).execute(&pool).await.expect("migration applies");

        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT polname, pg_get_expr(polqual, polrelid)
               FROM pg_policy
              WHERE pg_get_expr(polqual, polrelid) LIKE '%uid()%'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        assert!(!rows.is_empty(), "expected policies referencing auth.uid()");
        for (name, expr) in rows {
            let expr = expr.unwrap_or_default();
            assert!(
                expr.contains("SELECT auth.uid()"),
                "policy {name} calls auth.uid() per row: {expr}"
            );
        }
    })
    .await;
}
