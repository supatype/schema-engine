//! A serial key's sequence is usable by exactly the API roles its model's create rule admits.
//!
//! The engine granted nothing on a model's sequences, so an insert into a serial-key model worked
//! only where a broad default privilege on sequences had been set (Cloud and local dev, being
//! narrowed), and an anonymous insert failed with "permission denied for sequence" even where the
//! create rule admits anon. Now each API role the create rule admits holds `USAGE` on the sequence
//! (not `SELECT` or `UPDATE`: `nextval` is all an insert needs), recorded as a grant on the
//! ledger, so a change by hand is drift and putting it back needs consent. An identity column
//! needs no grant: Postgres draws its value without checking the caller's privileges on it.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{parser, parser::ast::SchemaAst, push::Outcome};

use common::{exec, push};

fn model(name: &str, table: &str, create: Value) -> Value {
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
                         "platform": { "access": { "read": { "type": "public" }, "create": create } } }
    })
}

/// `notes` anyone may create, `memos` only a signed-in user.
fn schema() -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": [
        model("Note", "notes", json!({ "type": "public" })),
        model("Memo", "memos", json!({ "type": "authenticated" })),
    ]});
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// The API roles and the auth helpers, and no default privilege on sequences.
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
    let defaults: i64 =
        sqlx::query_scalar("SELECT count(*) FROM pg_default_acl WHERE defaclobjtype = 'S'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        defaults, 0,
        "a default privilege on sequences would hide the gap"
    );
}

/// Inserts into `table` as `role`, with a signed-in subject for `authenticated`, rolled back.
async fn insert_as(pool: &PgPool, role: &str, table: &str) -> Result<(), String> {
    let mut tx = pool.begin().await.unwrap();
    let claims = match role {
        "anon" => json!({ "role": "anon" }),
        _ => json!({ "role": role, "sub": "8517c5e3-067d-4327-9dfc-ba8f8b4bc4f7" }),
    };
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(claims.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::raw_sql(&format!("SET LOCAL ROLE {role}"))
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

async fn usage(pool: &PgPool, role: &str, sequence: &str) -> bool {
    sqlx::query_scalar("SELECT has_sequence_privilege($1, $2, 'USAGE')")
        .bind(role)
        .bind(sequence)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// With no default privilege on sequences: anon inserts into the model anyone may create, not
/// into the one only a signed-in user may, and a signed-in user inserts into both. Each role
/// holds `USAGE` and nothing more on exactly the sequences its create rules admit.
#[tokio::test(flavor = "multi_thread")]
async fn a_serial_keys_sequence_is_usable_by_the_roles_its_create_rule_admits() {
    common::with_integration_pool(|pool| async move {
        api_roles(&pool).await;
        push(&pool, &schema()).await.unwrap();

        insert_as(&pool, "anon", "notes")
            .await
            .expect("anon creates a note");
        assert!(insert_as(&pool, "anon", "memos").await.is_err());
        insert_as(&pool, "authenticated", "notes")
            .await
            .expect("a user creates a note");
        insert_as(&pool, "authenticated", "memos")
            .await
            .expect("a user creates a memo");

        assert!(usage(&pool, "anon", "public.notes_id_seq").await);
        assert!(!usage(&pool, "anon", "public.memos_id_seq").await);
        assert!(usage(&pool, "authenticated", "public.memos_id_seq").await);
        let select: bool = sqlx::query_scalar(
            "SELECT has_sequence_privilege('anon', 'public.notes_id_seq', 'SELECT')
                 OR has_sequence_privilege('anon', 'public.notes_id_seq', 'UPDATE')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!select, "USAGE alone");

        let again = push(&pool, &schema()).await.unwrap();
        assert!(matches!(again, Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

/// The grants are on the ledger: one revoked by hand is drift that decides access, which a push
/// puts back only with consent.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequence_grant_revoked_by_hand_is_drift_that_needs_consent() {
    common::with_integration_pool(|pool| async move {
        api_roles(&pool).await;
        push(&pool, &schema()).await.unwrap();
        exec(
            &pool,
            "REVOKE USAGE ON SEQUENCE public.notes_id_seq FROM anon",
        )
        .await
        .unwrap();
        let report = common::doctor(&pool, &schema()).await;
        assert!(
            report
                .drifted
                .iter()
                .any(|i| i.table == "notes_id_seq" && i.name == "anon"),
            "{:#?}",
            report.drifted
        );
        let refused = push(&pool, &schema()).await.expect_err("needs consent");
        assert!(
            format!("{refused:#}").contains("notes_id_seq"),
            "{refused:#}"
        );
    })
    .await;
}
