//! A column whose type changes in place (`ALTER COLUMN ... TYPE`) under objects that read it.
//!
//! Postgres refuses to change the type of a column a policy reads, a trigger fires on or tests, or a
//! view selects. The push drops what it can make again (a policy, a trigger, the engine's own `api`
//! view), changes the type, and makes them again as they were; a view of the user's, or anything in
//! another schema, refuses the push before it changes anything, as it does for a column dropped and
//! added again. Indexes and checks Postgres rebuilds itself, and they come back unchanged.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst, push};

use common::{exec, push};

fn field(kind: &str, required: bool) -> Value {
    json!({ "kind": kind, "required": required })
}

fn uuid_pk() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" } })
}

/// `posts` with `fields` besides its id, under `access`.
fn posts(fields: Value, access: Value) -> SchemaAst {
    let mut all = json!({ "id": uuid_pk(), "title": field("text", true) });
    all.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "Post",
            "fields": all,
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": { "tableName": "posts", "indexes": [] },
                             "platform": { "access": access } }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// Rows anyone may read, as long as their score is not negative: the rule puts `score` in a policy.
fn scored(kind: &str) -> SchemaAst {
    let rule = json!({ "type": "compare", "op": "gte",
                       "left": { "kind": "column", "name": "score" },
                       "right": { "kind": "literal", "value": 0 } });
    posts(
        json!({ "score": field(kind, true) }),
        json!({ "read": rule }),
    )
}

/// A `meta` column of `kind`, readable by anyone.
fn with_meta(kind: &str) -> SchemaAst {
    let meta = match kind {
        "json" => json!({ "kind": "json", "required": false,
                          "annotations": { "db": { "pgType": "JSONB" } } }),
        other => field(other, false),
    };
    posts(
        json!({ "meta": meta }),
        json!({ "read": { "type": "public" } }),
    )
}

/// `score` behind a field rule, which on a database without the masking extension puts the table
/// behind the engine's `api` view.
fn behind_the_api_view(kind: &str) -> SchemaAst {
    let notes = json!({ "read": { "type": "role", "roles": ["admin"] } });
    posts(
        json!({ "score": field(kind, true), "notes": field("text", false) }),
        json!({ "read": { "type": "public" }, "fields": { "notes": notes } }),
    )
}

fn applied(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::Applied { .. })
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

/// Pushed and applied, then a second push of the same schema has nothing to do.
async fn applies_and_converges(pool: &PgPool, ast: &SchemaAst) {
    let outcome = push(pool, ast).await.expect("the push applies");
    assert!(applied(&outcome), "{outcome:?}");
    let again = push(pool, ast).await.expect("second push");
    assert!(up_to_date(&again), "{again:?}");
}

async fn column_type(pool: &PgPool, schema: &str, table: &str, column: &str) -> String {
    sqlx::query_scalar(
        "SELECT format_type(a.atttypid, a.atttypmod) FROM pg_attribute a
          WHERE a.attrelid = to_regclass(format('%I.%I', $1::text, $2::text))
            AND a.attname = $3 AND NOT a.attisdropped",
    )
    .bind(schema)
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("{schema}.{table}.{column}: {e}"))
}

/// Every policy on `posts`, as `pg_policies` describes it.
async fn policies(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT policyname::text, concat_ws(' | ', cmd, roles::text, qual, with_check)
           FROM pg_policies WHERE schemaname = 'public' AND tablename = 'posts'
          ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// How many rows of `posts` the anonymous role sees.
async fn visible_to_anon(pool: &PgPool) -> i64 {
    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql("SET LOCAL ROLE anon")
        .execute(&mut *tx)
        .await
        .unwrap();
    let seen = sqlx::query_scalar("SELECT count(*) FROM public.posts")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    seen
}

/// A read rule on `score` is a policy that reads it. The type change drops it, changes the type and
/// makes it again, so the rows it hides stay hidden and the next push has nothing to do.
#[tokio::test]
async fn alter_type_restores_dependent_policies() {
    common::with_integration_pool(|pool| async move {
        applies_and_converges(&pool, &scored("integer")).await;
        exec(
            &pool,
            "INSERT INTO public.posts (title, score) VALUES ('kept', 5), ('hidden', -1)",
        )
        .await
        .unwrap();
        let before = policies(&pool).await;
        assert!(
            before.iter().any(|(_, def)| def.contains("score >= 0")),
            "{before:?}"
        );

        applies_and_converges(&pool, &scored("bigInt")).await;
        assert_eq!(
            column_type(&pool, "public", "posts", "score").await,
            "bigint"
        );
        assert_eq!(
            policies(&pool).await,
            before,
            "the policies come back as they were"
        );
        assert_eq!(
            visible_to_anon(&pool).await,
            1,
            "the hidden row stays hidden"
        );
    })
    .await;
}

/// A view the user made on the column cannot be made again by the push (it may be anything), so the
/// push refuses before it changes anything and names the view, as it does for a column dropped and
/// added again.
#[tokio::test]
async fn alter_type_under_a_users_view_refuses_before_any_change() {
    common::with_integration_pool(|pool| async move {
        applies_and_converges(&pool, &with_meta("json")).await;
        exec(
            &pool,
            "CREATE VIEW public.post_meta AS SELECT id, meta FROM public.posts",
        )
        .await
        .unwrap();

        let refused = push(&pool, &with_meta("text"))
            .await
            .expect_err("the push is refused");
        let message = format!("{refused:#}");
        assert!(message.contains("view public.post_meta"), "{message}");
        assert!(message.contains("public.posts.meta"), "{message}");
        assert!(
            !message.contains("Failed to apply migration"),
            "refused before anything ran: {message}"
        );
        assert_eq!(column_type(&pool, "public", "posts", "meta").await, "jsonb");
        assert_eq!(
            column_type(&pool, "public", "post_meta", "meta").await,
            "jsonb"
        );
    })
    .await;
}

/// The engine's own `api` view reads every column of its table. It is dropped for the type change
/// and made again with the table's new shape.
#[tokio::test]
async fn alter_type_remakes_the_api_view_over_the_column() {
    common::with_integration_pool(|pool| async move {
        applies_and_converges(&pool, &behind_the_api_view("integer")).await;
        assert_eq!(column_type(&pool, "api", "posts", "score").await, "integer");
        exec(
            &pool,
            "INSERT INTO public.posts (title, score, notes) VALUES ('a', 7, 'private')",
        )
        .await
        .unwrap();

        applies_and_converges(&pool, &behind_the_api_view("bigInt")).await;
        assert_eq!(
            column_type(&pool, "public", "posts", "score").await,
            "bigint"
        );
        assert_eq!(column_type(&pool, "api", "posts", "score").await, "bigint");
        let score: i64 = sqlx::query_scalar("SELECT score FROM api.posts")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(score, 7);
    })
    .await;
}

/// A column dropped and added again under the `api` view (JSON to a number cannot be converted) is
/// handled as a type change is: the view goes first and is made again after.
#[tokio::test]
async fn recreate_remakes_the_api_view_over_the_column() {
    common::with_integration_pool(|pool| async move {
        let json_score = |kind: &str| {
            let score = match kind {
                "json" => json!({ "kind": "json", "required": false,
                                  "annotations": { "db": { "pgType": "JSONB" } } }),
                other => field(other, false),
            };
            let notes = json!({ "read": { "type": "role", "roles": ["admin"] } });
            posts(
                json!({ "score": score, "notes": field("text", false) }),
                json!({ "read": { "type": "public" }, "fields": { "notes": notes } }),
            )
        };
        applies_and_converges(&pool, &json_score("json")).await;
        let forced = push::ApplyOptions {
            force: true,
            ..Default::default()
        };
        let outcome = common::push_with(&pool, &json_score("integer"), forced)
            .await
            .expect("the forced push applies");
        assert!(applied(&outcome), "{outcome:?}");
        let again = push(&pool, &json_score("integer")).await.unwrap();
        assert!(up_to_date(&again), "{again:?}");
        assert_eq!(column_type(&pool, "api", "posts", "score").await, "integer");
    })
    .await;
}

/// Each hand-made object on `posts.meta`, by name, as Postgres prints it.
async fn hand_made_on_meta(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT tgname::text, pg_get_triggerdef(oid) FROM pg_trigger
          WHERE tgrelid = 'public.posts'::regclass AND tgname LIKE 'mine_%'
         UNION ALL
         SELECT relname::text, pg_get_indexdef(oid) FROM pg_class
          WHERE relname LIKE 'mine_%' AND relkind = 'i'
         UNION ALL
         SELECT conname::text, pg_get_constraintdef(oid) FROM pg_constraint
          WHERE conname LIKE 'mine_%'
         ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// A trigger that fires on the column is dropped for the type change and made again exactly as it
/// was; an index and a check that read it are rebuilt by Postgres and are there after as before.
#[tokio::test]
async fn alter_type_restores_a_users_trigger_on_the_column() {
    common::with_integration_pool(|pool| async move {
        applies_and_converges(&pool, &with_meta("json")).await;
        exec(
            &pool,
            "CREATE INDEX mine_meta_present ON public.posts (title) INCLUDE (id)
               WHERE meta IS NOT NULL;
             ALTER TABLE public.posts ADD CONSTRAINT mine_meta_small
               CHECK (meta IS NULL OR length(meta::text) < 1000);
             CREATE FUNCTION public.mine_touch() RETURNS trigger LANGUAGE plpgsql
               AS $$ BEGIN RETURN NEW; END $$;
             CREATE TRIGGER mine_meta_touch BEFORE UPDATE OF meta ON public.posts
               FOR EACH ROW EXECUTE FUNCTION public.mine_touch();
             INSERT INTO public.posts (title, meta) VALUES ('a', '{\"k\": 1}');",
        )
        .await
        .unwrap();
        let before = hand_made_on_meta(&pool).await;
        assert_eq!(before.len(), 3, "{before:?}");

        applies_and_converges(&pool, &with_meta("text")).await;
        assert_eq!(column_type(&pool, "public", "posts", "meta").await, "text");
        let after = hand_made_on_meta(&pool).await;
        assert_eq!(after[2], before[2], "the trigger comes back as it was");
        assert_eq!(
            after.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            before.iter().map(|(name, _)| name).collect::<Vec<_>>(),
        );
    })
    .await;
}

/// A column added to a table behind the `api` view is in the view the same push makes, so the next
/// push has nothing to do.
#[tokio::test]
async fn a_column_added_under_the_api_view_is_in_it_at_once() {
    common::with_integration_pool(|pool| async move {
        applies_and_converges(&pool, &behind_the_api_view("integer")).await;
        let notes = json!({ "read": { "type": "role", "roles": ["admin"] } });
        let wider = posts(
            json!({ "score": field("integer", true), "notes": field("text", false),
                    "extra": field("text", false) }),
            json!({ "read": { "type": "public" }, "fields": { "notes": notes } }),
        );
        applies_and_converges(&pool, &wider).await;
        assert_eq!(column_type(&pool, "api", "posts", "extra").await, "text");
    })
    .await;
}

/// A column renamed under the `api` view is selected by its new name in the view the same push
/// makes.
#[tokio::test]
async fn a_column_renamed_under_the_api_view_is_renamed_in_it_at_once() {
    common::with_integration_pool(|pool| async move {
        applies_and_converges(&pool, &behind_the_api_view("integer")).await;
        let notes = json!({ "read": { "type": "role", "roles": ["admin"] } });
        let points = json!({ "kind": "integer", "required": true,
                             "annotations": { "db": { "renamedFrom": "score" } } });
        let renamed = posts(
            json!({ "points": points, "notes": field("text", false) }),
            json!({ "read": { "type": "public" }, "fields": { "notes": notes } }),
        );
        applies_and_converges(&pool, &renamed).await;
        assert_eq!(
            column_type(&pool, "api", "posts", "points").await,
            "integer"
        );
    })
    .await;
}
