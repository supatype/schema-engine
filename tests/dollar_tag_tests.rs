//! A body the engine dollar-quotes around a value from the schema is never closed by that value.
//!
//! A role, claim or literal holding `$rule$`, `$can$` or `$trg$` once ended the set helper, the
//! `can_*` predicate or the tier 2 write trigger there, and Postgres ran the rest as SQL: at best
//! the push failed, at worst the rule meant something else. These tests push roles holding each
//! tag and check the rules still mean what they say.

mod common;

use serde_json::{json, Value};
use supatype_engine::parser::{self, ast::SchemaAst};

const READER_ROLE: &str = "r$rule$ OR true --";
const CAN_ROLE: &str = "c$can$ OR true --";
const WRITER_ROLE: &str = "w$trg$ OR true --";
const OWNER: &str = "aaaaaaaa-0000-0000-0000-0000000000a1";
const OTHER: &str = "aaaaaaaa-0000-0000-0000-0000000000a2";
const TEAM: &str = "aaaaaaaa-0000-0000-0000-0000000000b1";

fn column(kind: &str, pg_type: &str, required: bool) -> Value {
    json!({ "kind": kind, "required": required,
            "annotations": { "db": { "pgType": pg_type, "unique": false } } })
}

fn model(name: &str, table: &str, fields: Value, access: Value) -> Value {
    json!({ "name": name, "fields": fields,
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": { "tableName": table, "indexes": [] },
                             "platform": { "access": access } } })
}

fn role(name: &str) -> Value {
    json!({ "type": "role", "roles": [name] })
}

/// A team its owner reads, and a document whose read rule names [`CAN_ROLE`] (the `can_*`
/// predicate), whose `secret` a caller holding [`READER_ROLE`] reads when they may read a team (a
/// set helper), and whose `note` only [`WRITER_ROLE`] writes (the tier 2 write trigger).
fn fixture() -> SchemaAst {
    let id = json!({ "kind": "uuid", "primaryKey": true, "required": true,
                     "annotations": { "db": { "pgType": "UUID", "unique": false } } });
    let team = model(
        "TgTeam",
        "tg_team",
        json!({ "id": id, "owner_id": column("uuid", "UUID", true) }),
        json!({ "read": { "type": "owner", "field": "owner_id" } }),
    );
    let readable_team = json!({ "type": "exists", "source": {
        "kind": "rows", "table": "tg_team", "column": "id", "where": role(READER_ROLE) } });
    let doc = model(
        "TgDoc",
        "tg_doc",
        json!({ "id": id, "secret": column("text", "TEXT", false),
                "note": column("text", "TEXT", false) }),
        json!({ "read": { "type": "any", "rules": [role(CAN_ROLE), { "type": "authenticated" }] },
                "update": { "type": "authenticated" },
                "fields": { "secret": { "read": readable_team },
                            "note": { "write": role(WRITER_ROLE) } } }),
    );
    let doc = json!({ "astVersion": 2, "models": [team, doc] }).to_string();
    parser::parse(&doc).expect("the fixture parses")
}

/// Claims for `sub`, holding `app_role` as their app role when given.
fn claims(sub: &str, app_role: Option<&str>) -> Value {
    let mut claims = json!({ "role": "authenticated", "sub": sub });
    if let Some(app_role) = app_role {
        claims["app_metadata"] = json!({ "role": app_role });
    }
    claims
}

/// Runs `sql` as `authenticated` with `claims` and returns its rows, then the stored note, read as
/// the superuser, all rolled back.
async fn as_caller(
    pool: &sqlx::PgPool,
    claims: &Value,
    sql: &str,
) -> (Result<Vec<Value>, String>, String) {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(claims.to_string())
        .execute(&mut *tx)
        .await
        .expect("set the claims");
    sqlx::raw_sql("SET LOCAL ROLE authenticated; SAVEPOINT caller")
        .execute(&mut *tx)
        .await
        .expect("assume authenticated");
    let wrapped = format!("WITH q AS ({sql}) SELECT coalesce(json_agg(q), '[]')::text FROM q");
    let rows = match sqlx::query_scalar::<_, String>(&wrapped)
        .fetch_one(&mut *tx)
        .await
    {
        Ok(text) => Ok(serde_json::from_str(&text).expect("json rows")),
        Err(e) => {
            sqlx::raw_sql("ROLLBACK TO SAVEPOINT caller")
                .execute(&mut *tx)
                .await
                .expect("rollback");
            Err(e.to_string())
        }
    };
    sqlx::raw_sql("RESET ROLE")
        .execute(&mut *tx)
        .await
        .expect("reset role");
    let note: String = sqlx::query_scalar("SELECT note FROM public.tg_doc")
        .fetch_one(&mut *tx)
        .await
        .expect("read the note");
    let _ = tx.rollback().await;
    (rows, note)
}

/// Pushes the fixture and seeds one team, owned by [`OWNER`], and one document.
async fn pushed(pool: &sqlx::PgPool) {
    common::push(pool, &fixture())
        .await
        .unwrap_or_else(|e| panic!("a role holding a dollar tag broke the push: {e:#}"));
    sqlx::raw_sql(&format!(
        "INSERT INTO public.tg_team (id, owner_id) VALUES ('{TEAM}', '{OWNER}');
         INSERT INTO public.tg_doc (id, secret, note) VALUES (gen_random_uuid(), 's', 'n');"
    ))
    .execute(pool)
    .await
    .expect("seed");
}

/// The source of every function whose name starts with `prefix`, joined.
async fn function_sources(pool: &sqlx::PgPool, prefix: &str) -> String {
    sqlx::query_scalar(
        "SELECT coalesce(string_agg(prosrc, E'\\n'), '') FROM pg_proc WHERE proname LIKE $1 || '%'",
    )
    .bind(prefix)
    .fetch_one(pool)
    .await
    .expect("read the functions")
}

#[tokio::test]
async fn a_role_holding_a_dollar_tag_stays_a_role() {
    common::with_integration_pool(|pool| async move {
        pushed(&pool).await;
        for (prefix, value) in [
            ("rule_set_", READER_ROLE),
            ("can_read_tg_doc", CAN_ROLE),
            ("tg_doc__write", WRITER_ROLE),
        ] {
            let source = function_sources(&pool, prefix).await;
            assert!(
                source.contains(value),
                "{prefix}: the role is not in the body whole: {source}"
            );
        }
        let read = "SELECT secret FROM api.tg_doc";
        for (caller, expected) in [
            (claims(OWNER, Some(READER_ROLE)), json!("s")),
            (claims(OWNER, None), Value::Null),
            (claims(OTHER, Some(READER_ROLE)), Value::Null),
        ] {
            let (rows, _) = as_caller(&pool, &caller, read).await;
            let rows = rows.unwrap_or_else(|e| panic!("{caller}: {e}"));
            assert_eq!(rows, [json!({ "secret": expected })], "{caller}");
        }
        let write = "UPDATE api.tg_doc SET note = 'changed' WHERE true RETURNING note";
        let (_, note) = as_caller(&pool, &claims(OTHER, Some(WRITER_ROLE)), write).await;
        assert_eq!(note, "changed", "the writer's role writes the note");
        let (_, note) = as_caller(&pool, &claims(OTHER, None), write).await;
        assert_eq!(note, "n", "a caller without the role does not");
    })
    .await;
}
