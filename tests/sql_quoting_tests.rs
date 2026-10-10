//! Names the engine did not choose reach SQL quoted, never spliced.
//!
//! Two sources of names end up inside generated statements: identifiers read back from the live
//! catalog (an index someone created by hand, a constraint, a policy, a function) and role names a
//! schema declares in an access rule. Both used to be pasted between quotes without doubling the
//! quote character, so `my"idx` broke a column recreate with a syntax error, and a bucket rule for
//! the role `x' OR true OR 'a'='a` applied as a policy that let every caller read every object.
//! Each test here carries a payload that would run a statement of its own, or widen a policy, if
//! the quoting regressed.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{parser, push};

use common::{exec, push as push_schema, push_with};

const INJECTED_ROLE: &str = "x' OR true OR 'a'='a";

fn forced() -> push::ApplyOptions {
    push::ApplyOptions {
        force: true,
        ..Default::default()
    }
}

fn schema(doc: Value) -> parser::ast::SchemaAst {
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// `docs` with a `meta` column of the given kind, as E12 declares it.
fn docs(meta_kind: &str, pg_type: &str) -> parser::ast::SchemaAst {
    schema(json!({
        "astVersion": 2,
        "models": [{
            "name": "Doc",
            "fields": {
                "id": { "kind": "uuid", "required": true, "primaryKey": true,
                        "default": { "kind": "genRandomUuid" },
                        "annotations": { "db": { "pgType": "UUID", "unique": false, "index": false } } },
                "meta": { "kind": meta_kind, "required": false,
                          "annotations": { "db": { "pgType": pg_type, "unique": false, "index": false } } }
            },
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": { "tableName": "docs", "indexes": [] } }
        }]
    }))
}

async fn column_type(pool: &PgPool, table: &str, column: &str) -> String {
    sqlx::query_scalar(
        "SELECT data_type FROM information_schema.columns
          WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_one(pool)
    .await
    .expect("column exists")
}

async fn table_exists(pool: &PgPool, table: &str) -> bool {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(format!("public.{table}"))
        .fetch_one(pool)
        .await
        .expect("regclass reads")
}

/// E12: a column recreate drops every index on the column by the name it has in the catalog.
async fn recreate_with_hand_made_index(pool: &PgPool, index: &str) {
    push_schema(pool, &docs("json", "JSONB"))
        .await
        .expect("first push applies");
    exec(
        pool,
        "CREATE TABLE public.canary (id int);
         INSERT INTO public.canary VALUES (1);",
    )
    .await
    .expect("canary");
    let quoted = index.replace('"', "\"\"");
    exec(
        pool,
        &format!("CREATE INDEX \"{quoted}\" ON public.docs (meta)"),
    )
    .await
    .expect("hand-made index");

    push_with(pool, &docs("integer", "INTEGER"), forced())
        .await
        .expect("the recreate applies around the hand-made index");

    assert_eq!(column_type(pool, "docs", "meta").await, "integer");
    assert!(
        table_exists(pool, "canary").await,
        "an index name ran as a statement of its own"
    );
}

#[tokio::test]
async fn an_index_named_with_a_double_quote_survives_a_column_recreate() {
    common::with_integration_pool(|pool| async move {
        recreate_with_hand_made_index(&pool, "my\"idx").await;
    })
    .await;
}

#[tokio::test]
async fn an_index_name_carrying_a_statement_is_dropped_by_name_not_run() {
    common::with_integration_pool(|pool| async move {
        recreate_with_hand_made_index(&pool, "x\"; DROP TABLE public.canary; --").await;
    })
    .await;
}

/// One private bucket whose read rule names `role`.
fn bucket_read_by(role: &str) -> parser::ast::SchemaAst {
    schema(json!({
        "astVersion": 2,
        "models": [],
        "storageBuckets": [{
            "id": "q-bucket", "public": false, "accessMode": "custom",
            "access": {
                "read": { "type": "role", "roles": [role] },
                "create": { "type": "private" },
                "update": { "type": "private" },
                "delete": { "type": "private" }
            }
        }]
    }))
}

/// What `anon` sees of `storage.objects`, with no claims set.
async fn objects_anon_sees(pool: &PgPool) -> i64 {
    let mut tx = pool.begin().await.expect("begin");
    exec_in(&mut tx, "SET LOCAL ROLE anon").await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM storage.objects")
        .fetch_one(&mut *tx)
        .await
        .expect("anon reads storage.objects");
    tx.rollback().await.expect("rollback");
    n
}

async fn exec_in(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, sql: &str) {
    sqlx::raw_sql(sql).execute(&mut **tx).await.expect(sql);
}

/// The read policy's `USING` expression on `storage.objects`, as Postgres deparses it.
async fn bucket_read_policy(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT pg_get_expr(polqual, polrelid) FROM pg_policy
          WHERE polrelid = 'storage.objects'::regclass AND polname = 'storage_q_bucket_sel'",
    )
    .fetch_one(pool)
    .await
    .expect("the read policy exists")
}

#[tokio::test]
async fn a_bucket_role_with_an_apostrophe_applies_as_that_role() {
    common::with_integration_pool(|pool| async move {
        push_schema(&pool, &bucket_read_by("o'brien"))
            .await
            .expect("a role with an apostrophe applies");
        let using = bucket_read_policy(&pool).await;
        assert!(
            using.contains("'o''brien'"),
            "the policy does not name the declared role: {using}"
        );
    })
    .await;
}

#[tokio::test]
async fn a_bucket_role_carrying_sql_stays_a_role_name() {
    common::with_integration_pool(|pool| async move {
        push_schema(&pool, &bucket_read_by(INJECTED_ROLE))
            .await
            .expect("the push applies");
        exec(
            &pool,
            "INSERT INTO storage.objects (bucket_id, name) VALUES ('q-bucket', 'secret.pdf')",
        )
        .await
        .expect("an object");
        assert_eq!(
            objects_anon_sees(&pool).await,
            0,
            "the role name widened the policy: {}",
            bucket_read_policy(&pool).await
        );
    })
    .await;
}

/// `notes`, readable only by `role`.
fn notes_read_by(role: &str) -> parser::ast::SchemaAst {
    schema(json!({
        "astVersion": 2,
        "models": [{
            "name": "Note",
            "fields": {
                "id": { "kind": "integer", "primaryKey": true, "required": true,
                        "annotations": { "db": { "pgType": "INTEGER", "unique": false } } }
            },
            "options": { "timestamps": false, "softDelete": false },
            "annotations": {
                "db": { "tableName": "notes", "indexes": [] },
                "platform": { "access": {
                    "read": { "type": "role", "roles": [role] },
                    "create": { "type": "private" },
                    "update": { "type": "private" },
                    "delete": { "type": "private" }
                } }
            }
        }]
    }))
}

async fn notes_anon_sees(pool: &PgPool) -> i64 {
    let mut tx = pool.begin().await.expect("begin");
    exec_in(&mut tx, "SET LOCAL ROLE anon").await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM public.notes")
        .fetch_one(&mut *tx)
        .await
        .expect("anon reads notes");
    tx.rollback().await.expect("rollback");
    n
}

#[tokio::test]
async fn a_model_role_with_an_apostrophe_applies() {
    common::with_integration_pool(|pool| async move {
        push_schema(&pool, &notes_read_by("o'brien"))
            .await
            .expect("a role with an apostrophe applies");
    })
    .await;
}

#[tokio::test]
async fn a_model_role_carrying_sql_stays_a_role_name() {
    common::with_integration_pool(|pool| async move {
        push_schema(&pool, &notes_read_by(INJECTED_ROLE))
            .await
            .expect("the push applies");
        // The grant is the test's own, so the policy is the only thing deciding what anon reads.
        exec(
            &pool,
            "INSERT INTO public.notes (id) VALUES (1); GRANT SELECT ON public.notes TO anon;",
        )
        .await
        .expect("a row anon may select");
        assert_eq!(
            notes_anon_sees(&pool).await,
            0,
            "the role name widened the read policy"
        );
    })
    .await;
}
