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
    differ, generator::sql::migration, introspector, parser, state::database_state::DatabaseState,
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
async fn or_composition_reaches_the_database() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(FIXTURE).expect("fixture parses");
        let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql)
            .execute(&pool)
            .await
            .expect("migration applies");

        // `pg_get_expr` qualifies a name only when it is not visible on the
        // session's search_path, so with `auth` on the path it deparses
        // `auth.role()` as bare `role()` and an assertion naming the schema fails
        // against an expression that is perfectly correct. Emptying the path on the
        // connection doing the read forces full qualification, so the assertion can
        // check the schema it means rather than being loosened to tolerate both.
        let mut conn = pool.acquire().await.expect("connection");
        sqlx::raw_sql("SET search_path TO ''")
            .execute(&mut *conn)
            .await
            .expect("search_path set");

        let expr: String = sqlx::query_scalar(
            "SELECT pg_get_expr(polqual, polrelid) FROM pg_policy WHERE polname = 'posts_select'",
        )
        .fetch_one(&mut *conn)
        .await
        .expect("the Post read policy exists");

        // The scheduled-publishing rule:
        //   Any<[Role<"editor">, All<[Lte<"created_at", Now>,
        //        Gte<"created_at", Ago<30,"days">>, Lte<"updated_at", FromNow<7,"days">>]>]>
        //
        // The staff branch is what keeps a scheduled row visible to its author in
        // Studio. Without it, FORCE ROW LEVEL SECURITY hides the post the moment a
        // future date is set, which reads as the product being broken.
        assert!(expr.contains(" OR "), "expected an OR-join, got: {expr}");
        assert!(expr.contains("auth.role()"), "staff branch missing: {expr}");
        assert!(expr.contains("now()"), "temporal branch missing: {expr}");
        assert!(expr.contains("30 days"), "Ago interval missing: {expr}");
        assert!(expr.contains("7 days"), "FromNow interval missing: {expr}");

        // `now()`, never `clock_timestamp()` — the latter is VOLATILE and would make
        // the affordance functions' STABLE declaration a lie.
        assert!(
            !expr.contains("clock_timestamp"),
            "a volatile clock reached a policy: {expr}"
        );

        // StartOf on a model that has timestamps (Tag declares `timestamps: false`).
        let user_expr: String = sqlx::query_scalar(
            "SELECT pg_get_expr(polqual, polrelid) FROM pg_policy WHERE polname = 'users_select'",
        )
        .fetch_one(&pool)
        .await
        .expect("the User read policy exists");
        assert!(
            user_expr.contains("date_trunc"),
            "StartOf did not compile to date_trunc: {user_expr}"
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
        sqlx::raw_sql(&sql)
            .execute(&pool)
            .await
            .expect("migration applies");

        let (using_expr, check_expr): (Option<String>, Option<String>) = sqlx::query_as(
            "SELECT pg_get_expr(polqual, polrelid), pg_get_expr(polwithcheck, polrelid)
               FROM pg_policy WHERE polname = 'posts_update'",
        )
        .fetch_one(&pool)
        .await
        .expect("the Post update policy exists");

        let using_expr = using_expr.unwrap_or_default();
        let check_expr = check_expr.unwrap_or_default();

        assert!(
            using_expr.contains("author_id"),
            "USING lost the row selection: {using_expr}"
        );
        assert!(
            check_expr.contains("title"),
            "WITH CHECK lost the constraint: {check_expr}"
        );
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
        sqlx::raw_sql(&sql)
            .execute(&pool)
            .await
            .expect("migration applies");

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
        sqlx::raw_sql(&sql)
            .execute(&pool)
            .await
            .expect("migration applies");

        // Same reason as above: force full qualification so `SELECT auth.uid()` is
        // what the catalog hands back, rather than a search_path-dependent `uid()`.
        let mut conn = pool.acquire().await.expect("connection");
        sqlx::raw_sql("SET search_path TO ''")
            .execute(&mut *conn)
            .await
            .expect("search_path set");

        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT polname, pg_get_expr(polqual, polrelid)
               FROM pg_policy
              WHERE pg_get_expr(polqual, polrelid) LIKE '%uid()%'",
        )
        .fetch_all(&mut *conn)
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

// Studio needs to know, per row, whether the delete button should be enabled. A
// client-side SQL interpreter would be a second implementation of the rules that
// drifts from the enforced one, and a round trip per row does not scale. These
// functions are the answer, generated from the same AST as the policies, and
// exposed by PostgREST as computed columns on the query Studio already runs.
#[tokio::test]
async fn can_functions_answer_per_row_from_the_same_rules() {
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(FIXTURE).expect("fixture parses");
        let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql).execute(&pool).await.expect("migration applies");

        // One function per model per operation, including the operations a model
        // does not declare -- a function that always answers false is easier for a
        // UI than a missing one it has to special-case.
        for name in [
            "can_read_posts",
            "can_create_posts",
            "can_update_posts",
            "can_delete_posts",
            "can_read_comments",
        ] {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                                 WHERE n.nspname = 'public' AND p.proname = $1)",
            )
            .bind(name)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(exists, "{name} was not generated");
        }

        // Takes exactly one argument of the table's composite type and returns
        // boolean -- the shape PostgREST requires to expose it as
        // `?select=*,can_delete_posts`. The parameter is *named* after the table
        // (so the policy expression can be reused verbatim in the body), which is
        // why the signature reads "posts posts".
        let (args, returns, nargs): (String, String, i16) = sqlx::query_as(
            "SELECT pg_get_function_identity_arguments(p.oid),
                    pg_catalog.format_type(p.prorettype, NULL),
                    p.pronargs
               FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = 'public' AND p.proname = 'can_delete_posts'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(nargs, 1, "a computed column takes exactly the row: {args}");
        assert!(args.ends_with("posts"), "argument is not the row type: {args}");
        assert_eq!(returns, "boolean", "computed column must be boolean: {returns}");

        // And it answers. `posts.delete` is Role<"admin">, so with no JWT claims set
        // `auth.role()` is 'anon' and every row answers false -- the same answer the
        // policy gives, which is the whole point.
        sqlx::raw_sql(
            "INSERT INTO users (id, email, name) VALUES
               ('11111111-1111-1111-1111-111111111111', 'a@example.com', 'A');
             INSERT INTO categories (id, name, slug) VALUES
               ('22222222-2222-2222-2222-222222222222', 'General', 'general');
             INSERT INTO posts (id, title, slug, content, author_id, category_id) VALUES
               ('33333333-3333-3333-3333-333333333333', 'T', 't', '{}'::jsonb,
                '11111111-1111-1111-1111-111111111111',
                '22222222-2222-2222-2222-222222222222');",
        )
        .execute(&pool)
        .await
        .expect("seed rows");

        let (can_delete, can_read): (bool, Option<bool>) =
            sqlx::query_as("SELECT can_delete_posts(p), can_read_posts(p) FROM posts p")
                .fetch_one(&pool)
                .await
                .expect("the affordance functions are callable on a row");

        // `posts.delete` is Role<"admin">. With no JWT claims set `auth.role()` is
        // 'anon', so every row answers false -- the same answer the policy gives,
        // which is the whole point of generating both from one AST.
        assert!(!can_delete, "delete is admin-only, so anon must be refused");

        // `posts.read` is the scheduled-publishing rule. The seeded row was created
        // just now, so it is inside the 30-day window and visible. Every rule answers
        // definitively — there is no "unknown" state here, which is the entire point
        // of these functions.
        assert_eq!(can_read, Some(true), "a row created now must be visible");

        // And it is really evaluating the temporal predicate, not defaulting to true:
        // the same row dated 60 days ago falls outside `Ago<30, "days">`, and with no
        // editor role nothing else rescues it. This is what makes Studio able to say
        // "scheduled, visible in N days" rather than just hiding the row.
        let can_read_stale: Option<bool> = sqlx::query_scalar(
            "SELECT can_read_posts(ROW(p.id, p.title, p.slug, p.content, p.author_id,
                                       p.category_id, now() - INTERVAL '60 days',
                                       p.updated_at)::posts)
               FROM posts p LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .expect("callable on a constructed row");
        assert_eq!(
            can_read_stale,
            Some(false),
            "the temporal predicate is not being evaluated against the row"
        );

        // A rule with no Custom anywhere answers definitively. `users.read` is
        // Public.
        sqlx::raw_sql("INSERT INTO users (id, email, name) VALUES
             ('44444444-4444-4444-4444-444444444444', 'b@example.com', 'B');")
            .execute(&pool)
            .await
            .expect("seed a user");
        let can_read_user: Option<bool> =
            sqlx::query_scalar("SELECT can_read_users(u) FROM users u LIMIT 1")
                .fetch_one(&pool)
                .await
                .expect("callable");
        assert_eq!(can_read_user, Some(true), "a public read must answer true");
    })
    .await;
}

// ─── Field-level access ──────────────────────────────────────────────────────

/// Read one column as a given application role, through the same path an app takes:
/// claims in the GUC the generated `auth.role()` reads, and the switched database role.
///
/// Selected by `id`, not by `name`: `name` carries a read rule of its own, so for a
/// non-admin it masks to NULL and `WHERE name = 'probe'` matches nothing. That is the
/// oracle-closing working as intended, and it makes a masked column useless as a filter.
async fn read_email_as(pool: &sqlx::PgPool, app_role: &str, id: &str) -> Option<String> {
    let mut tx = pool.begin().await.expect("begin");
    let claims = format!(r#"{{"role":"{app_role}","app_metadata":{{"role":"{app_role}"}}}}"#);
    sqlx::raw_sql(&format!(
        "SET LOCAL request.jwt.claims = '{claims}'; SET LOCAL ROLE authenticated;"
    ))
    .execute(&mut *tx)
    .await
    .expect("assume the caller's identity");

    let email: Option<String> =
        sqlx::query_scalar("SELECT email FROM public.users WHERE id = $1::uuid")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .expect("the probe row is readable");

    tx.rollback().await.expect("rollback");
    email
}

async fn supatype_labels(pool: &sqlx::PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT a.attname::text, l.label
           FROM pg_seclabel l
           JOIN pg_attribute a ON a.attrelid = l.objoid AND a.attnum = l.objsubid
          WHERE l.provider = 'supatype'
          ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .expect("read security labels")
}

/// A generated `can_read_*` function nobody points the extension at enforces nothing, so
/// this asserts the whole chain: rule -> predicate -> security label -> masked value.
/// The field-rule fixture. Separate from [`FIXTURE`] because a schema declaring field rules
/// refuses to apply without `supatype_mask`, and the convergence tests must not depend on an
/// extension that ships from another repo.
const FIELD_FIXTURE: &str = include_str!("fixtures/rls_field_rules.json");

#[tokio::test]
async fn field_rules_mask_a_column_end_to_end() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            return;
        }
        let ast = parser::parse(FIELD_FIXTURE).expect("fixture parses");
        // Introspected, not `DatabaseState::default()`: the field-masking tier is chosen from the
        // database's extension list, and a default state claims there are none — which selects
        // tier 2 and emits views instead of the labels this test is about.
        let db = introspector::introspect(&pool, "public").await.expect("introspect");
        let diff = differ::diff(&ast, &db).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql)
            .execute(&pool)
            .await
            .expect("migration applies");

        let labels = supatype_labels(&pool).await;
        assert!(
            labels
                .iter()
                .any(|(col, label)| col == "email" && label.contains("can_read_users__email")),
            "the read rule on users.email produced no security label, got: {labels:#?}"
        );
        // A write-only rule must not name a read predicate, or every read of the column
        // pays for a predicate that always answers true.
        assert!(
            labels
                .iter()
                .any(|(col, label)| col == "id" && !label.contains("READ")),
            "the write-only rule on users.id named a read predicate, got: {labels:#?}"
        );

        let probe: String = sqlx::query_scalar(
            "INSERT INTO public.users (email, name) VALUES ('probe@example.com', 'probe')              RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .expect("seed a probe row");

        // The rule is `Role<"admin">`, so identity decides, and the column is present
        // either way -- never an error, which is what would break `SELECT *`.
        assert_eq!(
            read_email_as(&pool, "admin", &probe).await.as_deref(),
            Some("probe@example.com"),
            "an admin could not read a column their own rule allows"
        );
        assert_eq!(
            read_email_as(&pool, "authenticated", &probe).await,
            None,
            "a non-admin read the column the field rule restricts"
        );
    })
    .await;
}

/// Removing a rule has to stop the masking. Nothing diffs labels, so this is the only
/// thing standing between a deleted rule and a column masked forever by a rule that no
/// longer exists.
#[tokio::test]
async fn removing_a_field_rule_clears_its_label() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            return;
        }
        let ast = parser::parse(FIELD_FIXTURE).expect("fixture parses");
        // Introspected, not `DatabaseState::default()`: the field-masking tier is chosen from the
        // database's extension list, and a default state claims there are none — which selects
        // tier 2 and emits views instead of the labels this test is about.
        let db = introspector::introspect(&pool, "public").await.expect("introspect");
        let diff = differ::diff(&ast, &db).unwrap();
        let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
        sqlx::raw_sql(&sql).execute(&pool).await.expect("first push");
        let probe: String = sqlx::query_scalar(
            "INSERT INTO public.users (email, name) VALUES ('probe@example.com', 'probe')              RETURNING id::text",
        )
        .fetch_one(&pool)
        .await
        .expect("seed a probe row");
        assert!(!supatype_labels(&pool).await.is_empty(), "first push set no labels");

        let mut relaxed = parser::parse(FIELD_FIXTURE).expect("fixture parses");
        for model in &mut relaxed.models {
            supatype_engine::parser::accessors::platform_access_mut(model)
                .fields
                .clear();
        }

        let db = introspector::introspect(&pool, "public").await.unwrap();
        let second = differ::diff(&relaxed, &db).unwrap();
        let sql = migration::forward_sql(&second, false, "public", &relaxed).unwrap();
        sqlx::raw_sql(&sql)
            .execute(&pool)
            .await
            .expect("second push applies");

        assert!(
            supatype_labels(&pool).await.is_empty(),
            "labels survived the removal of every field rule"
        );
        assert_eq!(
            read_email_as(&pool, "authenticated", &probe).await.as_deref(),
            Some("probe@example.com"),
            "the column stayed masked after its rule was removed"
        );
    })
    .await;
}
