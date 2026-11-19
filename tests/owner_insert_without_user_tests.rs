//! An insert that leaves an owner column empty with nobody signed in says why.
//!
//! `Comment.user_id: SupatypeAuthUserId` with `create: Owner<"user_id">` is NOT NULL and defaults to
//! the caller's id. A service role key has no `sub`, so the default is NULL, on purpose, and the
//! insert failed with `null value in column "user_id" ... violates not-null constraint`: a new
//! user could not tell why. A BEFORE INSERT trigger now raises a plain error with the same
//! SQLSTATE (23502), so anything that classifies the error by code still does.
//!
//! These run against a real database: the claim is what Postgres does with the write.

mod common;

use serde_json::{json, Value};
use sqlx::postgres::PgDatabaseError;
use sqlx::PgPool;
use supatype_engine::generator::sql::triggers;
use supatype_engine::managed::ObjectNames;
use supatype_engine::parser::{self, ast::SchemaAst};
use supatype_engine::push::Outcome;

const CALLER: &str = "55555555-5555-5555-5555-555555555555";
const EXPLICIT: &str = "77777777-7777-7777-7777-777777777777";
const TRIGGER: &str = "oi_comment_user_id_required_trigger";
const FUNCTION: &str = "require_oi_comment_user_id";

fn owner(field: &str) -> Value {
    json!({ "type": "owner", "field": field })
}

fn schema_with(user_id_required: bool, create: Value) -> SchemaAst {
    let comment = json!({
        "name": "Comment",
        "fields": {
            "id": { "kind": "uuid", "primaryKey": true, "required": true,
                    "default": { "kind": "genRandomUuid" },
                    "annotations": { "db": { "pgType": "UUID", "unique": false } } },
            "user_id": { "kind": "uuid", "required": user_id_required,
                         "annotations": { "db": { "pgType": "UUID", "unique": false,
                                                  "authUserId": true } } },
            "body": { "kind": "text", "required": true,
                      "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
        },
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": { "tableName": "oi_comment", "indexes": [] },
                         "platform": { "access": { "read": { "type": "public" },
                                                   "create": create,
                                                   "update": owner("user_id"),
                                                   "delete": owner("user_id") } } }
    });
    let doc = json!({ "astVersion": 2, "models": [comment] });
    parser::parse(&doc.to_string()).expect("the comment fixture parses")
}

fn schema(create: Value) -> SchemaAst {
    schema_with(true, create)
}

async fn prepare(pool: &PgPool) {
    common::exec(
        pool,
        "CREATE SCHEMA IF NOT EXISTS auth;
         DO $$ BEGIN
           BEGIN CREATE ROLE anon NOLOGIN NOINHERIT;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
           BEGIN CREATE ROLE authenticated NOLOGIN NOINHERIT;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
           BEGIN CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS;
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END;
         END $$;",
    )
    .await
    .expect("roles and auth schema");
    common::exec(
        pool,
        &supatype_engine::generator::sql::rls::generate_auth_helpers(),
    )
    .await
    .expect("auth helpers");
}

/// What a failed statement told the client.
#[derive(Debug)]
struct Refusal {
    code: String,
    message: String,
    detail: Option<String>,
    hint: Option<String>,
}

/// Runs `sql` as `role` with `claims`, as PostgREST does, and answers the `user_id` it wrote.
async fn insert_as(pool: &PgPool, role: &str, claims: Value, sql: &str) -> Result<String, Refusal> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(claims.to_string())
        .execute(&mut *tx)
        .await
        .expect("set the claims");
    // The engine grants the API roles through the schema's own rules; the service role of a real
    // project gets its table access from the platform's bootstrap, which this database lacks.
    // Rolled back with the transaction.
    sqlx::raw_sql("GRANT ALL ON public.oi_comment TO service_role")
        .execute(&mut *tx)
        .await
        .expect("grant the service role the table");
    sqlx::raw_sql(&format!("SET LOCAL ROLE {role}"))
        .execute(&mut *tx)
        .await
        .expect("assume the API role");
    let written = sqlx::query_scalar::<_, String>(&format!("{sql} RETURNING user_id::text"))
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            let db = e.as_database_error().expect("a database error");
            let pg = db.downcast_ref::<PgDatabaseError>();
            Refusal {
                code: db.code().map(|c| c.to_string()).unwrap_or_default(),
                message: db.message().to_string(),
                detail: pg.detail().map(str::to_string),
                hint: pg.hint().map(str::to_string),
            }
        });
    tx.rollback().await.expect("rollback");
    written
}

async fn service_role_insert(pool: &PgPool, sql: &str) -> Result<String, Refusal> {
    insert_as(pool, "service_role", json!({ "role": "service_role" }), sql).await
}

async fn trigger_exists(pool: &PgPool, trigger: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid \
         WHERE c.relname = 'oi_comment' AND t.tgname = $1 AND NOT t.tgisinternal)",
    )
    .bind(trigger)
    .fetch_one(pool)
    .await
    .expect("read pg_trigger")
}

async fn function_exists(pool: &PgPool, function: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = '_platform' AND p.proname = $1)",
    )
    .bind(function)
    .fetch_one(pool)
    .await
    .expect("read pg_proc")
}

const INSERT: &str = "INSERT INTO public.oi_comment (body) VALUES ('hi')";

#[tokio::test(flavor = "multi_thread")]
async fn an_insert_with_no_signed_in_user_and_no_owner_says_why() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        common::push(&pool, &schema(owner("user_id")))
            .await
            .expect("push");
        let refused = service_role_insert(&pool, INSERT)
            .await
            .expect_err("a service role insert that leaves the owner out is refused");
        assert_eq!(refused.code, "23502", "{refused:?}");
        assert_eq!(
            refused.message,
            "user_id is required when inserting into oi_comment without a signed-in user"
        );
        assert_eq!(
            refused.detail.as_deref(),
            Some("the database fills user_id from the signed-in user, and this request has none")
        );
        assert_eq!(
            refused.hint.as_deref(),
            Some("set user_id to the owning user's id, for example in a server script using the service role key")
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_in_insert_is_filled_and_an_explicit_owner_is_kept() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        common::push(&pool, &schema(owner("user_id")))
            .await
            .expect("push");
        let signed_in = json!({ "role": "authenticated", "sub": CALLER });
        let filled = insert_as(&pool, "authenticated", signed_in, INSERT)
            .await
            .expect("a signed-in caller may comment without naming themselves");
        assert_eq!(filled, CALLER);

        let explicit =
            format!("INSERT INTO public.oi_comment (body, user_id) VALUES ('hi', '{EXPLICIT}')");
        let kept = service_role_insert(&pool, &explicit)
            .await
            .expect("an explicit owner is the service role's to set");
        assert_eq!(kept, EXPLICIT);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_check_arrives_on_a_push_stays_through_the_next_and_goes_with_the_rule() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        // An existing project: the table is there, and its create rule does not name the owner.
        let before = schema(json!({ "type": "role", "roles": ["admin"] }));
        common::push(&pool, &before).await.expect("first push");
        assert!(!trigger_exists(&pool, TRIGGER).await);

        let owned = schema(owner("user_id"));
        let outcome = common::push(&pool, &owned).await.expect("push the rule");
        assert!(matches!(outcome, Outcome::Applied { .. }), "{outcome:?}");
        assert!(trigger_exists(&pool, TRIGGER).await);
        assert!(function_exists(&pool, FUNCTION).await);
        let refused = service_role_insert(&pool, INSERT)
            .await
            .expect_err("the check is live");
        assert_eq!(refused.code, "23502");
        assert!(refused.message.contains("is required when inserting"));

        let again = common::push(&pool, &owned).await.expect("second push");
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");

        let removed = common::push(&pool, &before).await.expect("remove the rule");
        assert!(matches!(removed, Outcome::Applied { .. }), "{removed:?}");
        assert!(!trigger_exists(&pool, TRIGGER).await);
        assert!(!function_exists(&pool, FUNCTION).await);
    })
    .await;
}

/// An optional owner may hold NULL, so nothing is refused and nothing is generated for it.
#[test]
fn an_optional_owner_gets_no_check() {
    let ast = schema_with(false, owner("user_id"));
    let names = ObjectNames::for_schema(&ast);
    assert!(triggers::model_triggers(&ast.models[0], &names).is_empty());
    assert!(triggers::model_functions(&ast.models[0], &names).is_empty());
}

#[test]
fn the_generated_sql_names_the_check_deterministically() {
    let ast = schema(owner("user_id"));
    let sql = triggers::generate(&ast, "public").expect("generate");
    assert!(
        sql.contains("CREATE OR REPLACE FUNCTION _platform.require_oi_comment_user_id()"),
        "{sql}"
    );
    assert!(
        sql.contains(
            "CREATE OR REPLACE TRIGGER \"oi_comment_user_id_required_trigger\"\nBEFORE INSERT ON \"public\".\"oi_comment\"\nFOR EACH ROW EXECUTE FUNCTION _platform.require_oi_comment_user_id();"
        ),
        "{sql}"
    );
    assert!(
        sql.contains("IF NEW.\"user_id\" IS NULL AND _supatype.jwt_uid() IS NULL THEN"),
        "{sql}"
    );
    assert!(sql.contains("ERRCODE = '23502'"), "{sql}");
}
