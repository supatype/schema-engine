//! An owner column the create rule pins to the caller defaults to the caller's id (C7).
//!
//! `Comment.user_id: SupatypeAuthUserId` with `create: Owner<"user_id">` had no default, so every
//! client had to send its own id and the generated `Insert` type required it, although the rule
//! refuses every value but one the database already knows. The column now defaults to the
//! caller's id; a forged id is still refused by the rule.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::parser::{self, ast::SchemaAst};

const CALLER: &str = "55555555-5555-5555-5555-555555555555";
const SOMEONE_ELSE: &str = "66666666-6666-6666-6666-666666666666";

fn owner(field: &str) -> Value {
    json!({ "type": "owner", "field": field })
}

/// A comment owned through `user_id: SupatypeAuthUserId`, as the fresh-user schema declares it.
fn schema(create: Value) -> SchemaAst {
    let comment = json!({
        "name": "Comment",
        "fields": {
            "id": { "kind": "uuid", "primaryKey": true, "required": true,
                    "default": { "kind": "genRandomUuid" },
                    "annotations": { "db": { "pgType": "UUID", "unique": false } } },
            "user_id": { "kind": "uuid", "required": true,
                         "annotations": { "db": { "pgType": "UUID", "unique": false,
                                                  "authUserId": true } } },
            "body": { "kind": "text", "required": true,
                      "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
        },
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": { "tableName": "oc_comment", "indexes": [] },
                         "platform": { "access": { "read": { "type": "public" },
                                                   "create": create,
                                                   "update": owner("user_id"),
                                                   "delete": owner("user_id") } } }
    });
    let doc = json!({ "astVersion": 2, "models": [comment] });
    parser::parse(&doc.to_string()).expect("the comment fixture parses")
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

/// Runs `sql` as a signed-in caller, as PostgREST does, and answers the `user_id` it wrote.
async fn insert_as_caller(pool: &PgPool, sql: &str) -> Result<String, String> {
    let mut tx = pool.begin().await.expect("begin");
    let claims = json!({ "role": "authenticated", "sub": CALLER }).to_string();
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(claims)
        .execute(&mut *tx)
        .await
        .expect("set the claims");
    sqlx::raw_sql("SET LOCAL ROLE authenticated")
        .execute(&mut *tx)
        .await
        .expect("assume the API role");
    let written = sqlx::query_scalar::<_, String>(&format!("{sql} RETURNING user_id::text"))
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| e.to_string());
    tx.rollback().await.expect("rollback");
    written
}

/// The `Insert` type the generated types give the comment.
fn insert_type(ast: &SchemaAst) -> String {
    let types = supatype_engine::generator::typescript::types::generate(ast).expect("types");
    let start = types.find("Insert: {").expect("an Insert type");
    let end = types[start..]
        .find("Update: {")
        .expect("an Update type after it");
    types[start..start + end].to_string()
}

#[test]
fn the_owner_column_defaults_to_the_caller_and_insert_may_leave_it_out() {
    let ast = schema(owner("user_id"));
    let types = insert_type(&ast);
    assert!(types.contains("user_id?: string"), "{types}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_insert_without_user_id_belongs_to_the_caller() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        common::push(&pool, &schema(owner("user_id")))
            .await
            .expect("push");
        let written = insert_as_caller(&pool, "INSERT INTO public.oc_comment (body) VALUES ('hi')")
            .await
            .expect("a signed-in caller may comment without naming themselves");
        assert_eq!(written, CALLER);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forged_user_id_is_still_refused() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        common::push(&pool, &schema(owner("user_id")))
            .await
            .expect("push");
        let sql = format!(
            "INSERT INTO public.oc_comment (body, user_id) VALUES ('hi', '{SOMEONE_ELSE}')"
        );
        let refused = insert_as_caller(&pool, &sql)
            .await
            .expect_err("a caller may not comment as someone else");
        assert!(refused.contains("row-level security"), "{refused}");
    })
    .await;
}

/// A create rule that does not pin the owner to the caller leaves the column without a default:
/// a role may create a row for anyone, and the default would only guess.
#[test]
fn a_create_rule_without_the_owner_adds_no_default() {
    let ast = schema(json!({ "type": "role", "roles": ["admin"] }));
    let types = insert_type(&ast);
    assert!(!types.contains("user_id?: string"), "{types}");
}
