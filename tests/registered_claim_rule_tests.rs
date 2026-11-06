//! A rule can keep anonymous users out with the `Claim` operand alone.
//!
//! An anonymous sign-in creates a real user, so its token passes `LoggedIn`. The auth server marks
//! every access token with a boolean `is_anonymous` claim, `true` for such a user and `false` for a
//! real account, so `All<[LoggedIn, Eq<Claim<"is_anonymous">, Literal<...>>]>` is the rule that
//! admits only registered users. Both ways of writing the literal must mean the same thing: the
//! string `"false"`, compared with the claim as text, and the boolean `false`, compared with the
//! claim as the JSON boolean it is. A token without the claim is denied by either.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst, push::Outcome};

use common::{exec, push};

const SUBJECT: &str = "8517c5e3-067d-4327-9dfc-ba8f8b4bc4f7";

/// Signed in, and the token says the user is not anonymous, with `literal` as the "not".
fn registered(literal: Value) -> Value {
    json!({ "type": "all", "rules": [
        { "type": "authenticated" },
        { "type": "compare", "op": "eq",
          "left":  { "kind": "claim", "path": "is_anonymous" },
          "right": { "kind": "literal", "value": literal } }
    ] })
}

/// A model any signed-in user reads and only a registered one creates.
fn model(name: &str, table: &str, literal: Value) -> Value {
    json!({
        "name": name,
        "fields": {
            "id": { "kind": "serial", "primaryKey": true, "required": true,
                    "annotations": { "db": { "pgType": "SERIAL" } } },
            "body": { "kind": "text", "required": false,
                      "annotations": { "db": { "pgType": "TEXT", "unique": false } } }
        },
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": { "tableName": table, "indexes": [] },
                         "platform": { "access": { "read": { "type": "authenticated" },
                                                   "create": registered(literal) } } }
    })
}

/// `text_notes` writes the literal as the string `"false"`, `bool_notes` as the boolean `false`.
fn schema() -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": [
        model("TextNote", "text_notes", json!("false")),
        model("BoolNote", "bool_notes", json!(false)),
    ]});
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// The API roles and the claim readers, as a provisioned project has them.
async fn api_roles(pool: &PgPool) {
    exec(
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
    .unwrap();
    exec(
        pool,
        &supatype_engine::generator::sql::rls::generate_auth_helpers(),
    )
    .await
    .unwrap();
}

/// Inserts into `table` as `authenticated` carrying `claims`, rolled back.
async fn insert_with(pool: &PgPool, table: &str, claims: Value) -> Result<(), String> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(claims.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::raw_sql("SET LOCAL ROLE authenticated")
        .execute(&mut *tx)
        .await
        .unwrap();
    let inserted = sqlx::raw_sql(&format!("INSERT INTO public.{table} (body) VALUES ('x')"))
        .execute(&mut *tx)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string());
    let _ = tx.rollback().await;
    inserted
}

/// The claims of a signed-in user's token, with `is_anonymous` set to `flag`, or absent for `None`.
fn token(flag: Option<Value>) -> Value {
    let mut claims = json!({ "role": "authenticated", "sub": SUBJECT });
    if let Some(flag) = flag {
        claims["is_anonymous"] = flag;
    }
    claims
}

/// For both literal forms: an anonymous user is refused, a registered one creates, and a token
/// with no `is_anonymous` claim is refused as a row-level security violation, not a query error.
#[tokio::test(flavor = "multi_thread")]
async fn a_registered_rule_keeps_anonymous_users_out_in_either_literal_form() {
    common::with_integration_pool(|pool| async move {
        api_roles(&pool).await;
        push(&pool, &schema()).await.unwrap();

        for table in ["text_notes", "bool_notes"] {
            insert_with(&pool, table, token(Some(json!(false))))
                .await
                .unwrap_or_else(|e| panic!("{table}: a registered user creates: {e}"));

            for (case, claims) in [
                ("an anonymous user", token(Some(json!(true)))),
                ("a token without the claim", token(None)),
                ("a claim that is not a boolean", token(Some(json!("no")))),
            ] {
                let refused = insert_with(&pool, table, claims)
                    .await
                    .expect_err(&format!("{table}: {case} is refused"));
                assert!(
                    refused.contains("row-level security"),
                    "{table}: {case} is refused by the policy, not an error: {refused}"
                );
            }
        }

        let again = push(&pool, &schema()).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

/// A numeric claim compared with a number literal reads as a number: a claim of 5 passes
/// `Gte<Claim<"app_metadata.level">, Literal<3>>`, one of 2 does not, and a string `"5"` is not a
/// number, so it is refused by the policy rather than breaking the query on a cast.
#[tokio::test(flavor = "multi_thread")]
async fn a_claim_compared_with_a_number_literal_reads_as_a_number() {
    common::with_integration_pool(|pool| async move {
        api_roles(&pool).await;
        let mut doc = json!({ "astVersion": 2, "models": [
            model("LevelNote", "level_notes", json!(false)),
        ]});
        doc["models"][0]["annotations"]["platform"]["access"]["create"] = json!({
            "type": "compare", "op": "gte",
            "left":  { "kind": "claim", "path": "app_metadata.level" },
            "right": { "kind": "literal", "value": 3 } });
        let schema = parser::parse(&doc.to_string()).expect("fixture parses");
        push(&pool, &schema).await.unwrap();

        let level = |value: Value| {
            json!({ "role": "authenticated", "sub": SUBJECT,
                                           "app_metadata": { "level": value } })
        };
        insert_with(&pool, "level_notes", level(json!(5)))
            .await
            .expect("level 5 creates");
        for value in [json!(2), json!("5")] {
            let refused = insert_with(&pool, "level_notes", level(value.clone()))
                .await
                .expect_err(&format!("level {value} is refused"));
            assert!(
                refused.contains("row-level security"),
                "level {value}: {refused}"
            );
        }

        let again = push(&pool, &schema).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}
