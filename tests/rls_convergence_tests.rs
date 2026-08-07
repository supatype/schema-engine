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

// Convergence alone would still pass if a rule were silently dropped, so assert
// the composition actually reached the database.
#[tokio::test]
async fn or_composition_and_custom_sql_reach_the_database() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(FIXTURE).expect("fixture parses");
        let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql).execute(&pool).await.expect("migration applies");

        let expr: String = sqlx::query_scalar(
            "SELECT pg_get_expr(polqual, polrelid) FROM pg_policy WHERE polname = 'posts_select'",
        )
        .fetch_one(&pool)
        .await
        .expect("the Post read policy exists");

        // Any<[Role<"admin">, Owner<"authorId">, Custom<"title <> ''">]>
        assert!(expr.contains(" OR "), "expected an OR-join, got: {expr}");
        assert!(expr.contains("auth.role()"), "role branch missing: {expr}");
        assert!(expr.contains("author_id"), "owner branch missing: {expr}");
        assert!(expr.contains("title"), "custom branch missing: {expr}");

        // A Custom rule on its own is used verbatim rather than wrapped in
        // anything that would change its meaning.
        let tag_expr: String = sqlx::query_scalar(
            "SELECT pg_get_expr(polqual, polrelid) FROM pg_policy WHERE polname = 'tags_select'",
        )
        .fetch_one(&pool)
        .await
        .expect("the Tag read policy exists");
        assert!(
            tag_expr.contains("name IS NOT NULL"),
            "custom predicate altered: {tag_expr}"
        );
    })
    .await;
}

// AND-composition, negation, comparisons and claim lookups, checked where it
// counts — in the expression Postgres accepted and stored.
#[tokio::test]
async fn composition_and_comparisons_reach_the_database() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(FIXTURE).expect("fixture parses");
        let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql).execute(&pool).await.expect("migration applies");

        let expr: String = sqlx::query_scalar(
            "SELECT pg_get_expr(polqual, polrelid) FROM pg_policy WHERE polname = 'comments_select'",
        )
        .fetch_one(&pool)
        .await
        .expect("the Comment read policy exists");

        // All<[ Eq<"author_id", AuthUid>, Not<Eq<AuthRole, "banned">>,
        //       NotNull<"body">, Eq<"body", Claim<"app_metadata.tier">> ]>
        assert!(expr.contains(" AND "), "expected an AND-join, got: {expr}");
        assert!(expr.contains("NOT "), "negation missing: {expr}");
        assert!(expr.contains("IS NOT NULL"), "null check missing: {expr}");
        assert!(
            expr.contains("claim_text") && expr.contains("app_metadata.tier"),
            "claim lookup missing: {expr}"
        );

        // A null check must never be rendered as equality: `col = NULL` is null,
        // never true, so the policy would silently deny everything.
        assert!(!expr.contains("= NULL"), "null compared with equality: {expr}");
    })
    .await;
}

// An update policy has two halves. With one rule for both, "you may edit your own
// posts" also decides what they may become, so a distinct result constraint has to
// arrive as a distinct WITH CHECK.
#[tokio::test]
async fn update_using_and_check_are_separate_clauses() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(FIXTURE).expect("fixture parses");
        let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql).execute(&pool).await.expect("migration applies");

        let (using_expr, check_expr): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT pg_get_expr(polqual, polrelid), pg_get_expr(polwithcheck, polrelid)
               FROM pg_policy WHERE polname = 'posts_update'",
        )
        .fetch_one(&pool)
        .await
        .expect("the Post update policy exists");

        let using_expr = using_expr.unwrap_or_default();
        let check_expr = check_expr.unwrap_or_default();

        assert!(using_expr.contains("author_id"), "USING lost the row selection: {using_expr}");
        assert!(check_expr.contains("title"), "WITH CHECK lost the constraint: {check_expr}");
        assert_ne!(
            using_expr, check_expr,
            "the two halves collapsed into one predicate"
        );
    })
    .await;
}

// Membership is the reason the DSL exists: "the rows this caller belongs to".
#[tokio::test]
async fn membership_compiles_to_a_correlated_semi_join() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(FIXTURE).expect("fixture parses");
        let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql).execute(&pool).await.expect("migration applies");

        let expr: String = sqlx::query_scalar(
            "SELECT pg_get_expr(polqual, polrelid) FROM pg_policy WHERE polname = 'categories_select'",
        )
        .fetch_one(&pool)
        .await
        .expect("the Category read policy exists");

        // EXISTS, not IN (SELECT …): the planner stops at the first matching row
        // instead of materialising the whole set.
        assert!(expr.contains("EXISTS"), "expected a semi-join, got: {expr}");
        assert!(!expr.contains("IN (SELECT"), "materialises the set: {expr}");

        // Correlated on the outer table, and the narrowing rule resolved against
        // the *source* table. An unqualified `author_id` here would bind to
        // whichever table Postgres found first.
        assert!(
            expr.contains("categories.id") || expr.contains("categories\".\"id"),
            "not correlated to the outer row: {expr}"
        );
        assert!(
            expr.contains("posts.author_id") || expr.contains("posts\".\"author_id"),
            "narrowing rule not resolved against the source table: {expr}"
        );

        // A fixed set becomes an array test rather than a subquery.
        let tag_expr: String = sqlx::query_scalar(
            "SELECT pg_get_expr(polwithcheck, polrelid) FROM pg_policy WHERE polname = 'tags_insert'",
        )
        .fetch_one(&pool)
        .await
        .expect("the Tag create policy exists");
        assert!(tag_expr.contains("ANY"), "expected an array test, got: {tag_expr}");
    })
    .await;
}

// The DSL names the join column, so the classic RLS trap — a membership subquery
// scanning an unindexed join table once per row tested — becomes generated
// infrastructure rather than something the developer has to know about.
#[tokio::test]
async fn membership_sources_get_their_index() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(FIXTURE).expect("fixture parses");
        let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql).execute(&pool).await.expect("migration applies");

        let indexed: bool = sqlx::query_scalar(
            "SELECT EXISTS (
               SELECT 1 FROM pg_indexes
                WHERE schemaname = 'public' AND tablename = 'posts'
                  AND indexdef LIKE '%category_id%')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(indexed, "the Rows<> join column was left unindexed");
    })
    .await;
}

// Regression: the auth helpers had two definitions — one installed by a
// migration, one reinstalled at bootstrap — and they had already diverged. A
// fresh push installed a `role()` that ignored `app_metadata.role`, and helpers
// added on one side were missing on the other.
#[tokio::test]
async fn a_fresh_push_installs_the_canonical_auth_helpers() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(FIXTURE).expect("fixture parses");
        let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql).execute(&pool).await.expect("migration applies");

        let role_src: String = sqlx::query_scalar(
            "SELECT prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'auth' AND p.proname = 'role'",
        )
        .fetch_one(&pool)
        .await
        .expect("auth.role() exists");
        assert!(
            role_src.contains("app_metadata"),
            "a fresh push installed a stale auth.role(): {role_src}"
        );

        for helper in ["uid", "role", "roles", "claim", "claim_text", "jwt", "email"] {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                                 WHERE n.nspname = 'auth' AND p.proname = $1)",
            )
            .bind(helper)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(exists, "auth.{helper}() missing after a fresh push");
        }
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
