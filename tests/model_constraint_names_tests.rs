//! Model constraints are named for what they check (CK1), and a database whose constraints still
//! carry the positional names (`chat_message_check_1`) is brought to the readable ones in place.
//!
//! Against a real database: a fresh push creates the readable names; a push over positional names
//! the ledger records renames them (same constraint, same table file, the rows untouched, no
//! drift, nothing dropped), and rolling it back restores the old names; a push over positional
//! names 0.6.0 stamped, with no ledger rows, does the same; and every push after has nothing to do.

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use supatype_engine::{
    introspector::fingerprint::ObjectKind, ledger, parser, parser::ast::SchemaAst, push,
    state::migration_history,
};

use common::{exec, push};

const READABLE: [&str; 2] = ["chat_message_body_min_length", "chat_message_lo_lte_hi"];
const POSITIONAL: [&str; 2] = ["chat_message_check_1", "chat_message_check_2"];

fn integer() -> Value {
    json!({ "kind": "integer", "required": true,
            "annotations": { "db": { "pgType": "INTEGER", "unique": false } } })
}

/// kitchen-sink's `ChatMessage` rule, `Gte<Length<"body">, Literal<2>>`, and a cross-column one.
fn chat() -> SchemaAst {
    let mut id = integer();
    id["primaryKey"] = json!(true);
    let doc = json!({
        "astVersion": 2,
        "models": [{
            "name": "ChatMessage",
            "fields": {
                "id": id,
                "body": { "kind": "text", "required": true,
                          "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
                "lo": integer(),
                "hi": integer()
            },
            "options": { "timestamps": false, "softDelete": false },
            "annotations": {
                "db": {
                    "tableName": "chat_message",
                    "indexes": [],
                    "constraints": [
                        { "type": "compare", "op": "gte",
                          "left": { "kind": "length", "column": "body", "form": "chars" },
                          "right": { "kind": "literal", "value": 2 } },
                        { "type": "compare", "op": "lte",
                          "left": { "kind": "column", "name": "lo" },
                          "right": { "kind": "column", "name": "hi" } }
                    ]
                },
                "platform": {}
            }
        }]
    });
    parser::parse(&doc.to_string()).expect("fixture parses")
}

/// `name|oid` of every check on `chat_message`, in name order.
async fn checks(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT conname || '|' || oid FROM pg_constraint
          WHERE conrelid = 'public.chat_message'::regclass AND contype = 'c' ORDER BY conname",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

fn names(checks: &[String]) -> Vec<&str> {
    checks
        .iter()
        .map(|c| c.split_once('|').unwrap().0)
        .collect()
}

fn oids(checks: &[String]) -> Vec<&str> {
    let mut oids: Vec<&str> = checks
        .iter()
        .map(|c| c.split_once('|').unwrap().1)
        .collect();
    oids.sort();
    oids
}

async fn ledger_checks(pool: &PgPool) -> Vec<String> {
    let mut conn = pool.acquire().await.unwrap();
    let mut out: Vec<String> = ledger::load(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.key.kind == ObjectKind::Check && r.key.parent == "chat_message")
        .map(|r| r.key.name)
        .collect();
    out.sort();
    out
}

/// The table's file: a rewrite gives it a new one.
async fn relfilenode(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT relfilenode::bigint FROM pg_class WHERE oid = 'public.chat_message'::regclass",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn rows(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT concat_ws(',', id, body, lo, hi) FROM public.chat_message ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn comments(pool: &PgPool) -> Vec<Option<String>> {
    sqlx::query_scalar(
        "SELECT obj_description(oid, 'pg_constraint') FROM pg_constraint
          WHERE conrelid = 'public.chat_message'::regclass AND contype = 'c' ORDER BY conname",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The statements the last applied push ran.
async fn last_sql_up(pool: &PgPool) -> String {
    sqlx::query_scalar(
        "SELECT sql_up FROM _supatype.migrations WHERE status = 'applied' ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

fn up_to_date(outcome: &push::Outcome) -> bool {
    matches!(outcome, push::Outcome::UpToDate { .. })
}

/// Each readable constraint back under its positional name, as an engine before CK1 named it.
async fn rename_to_positional(pool: &PgPool) {
    for (from, to) in READABLE.iter().zip(POSITIONAL) {
        exec(
            pool,
            &format!("ALTER TABLE public.chat_message RENAME CONSTRAINT {from} TO {to}"),
        )
        .await
        .unwrap();
    }
}

/// The ledger rows as an engine before CK1 wrote them: under the positional names, the statement
/// naming them so, and its fingerprint over that statement (the engine's own formula).
async fn ledger_as_positional(pool: &PgPool) {
    for (from, to) in READABLE.iter().zip(POSITIONAL) {
        exec(
            pool,
            &format!(
                "UPDATE _supatype.managed_objects
                    SET name = '{to}', desired_sql = replace(desired_sql, '\"{from}\"', '\"{to}\"')
                  WHERE kind = 'check' AND name = '{from}';
                 UPDATE _supatype.managed_objects
                    SET desired_fp = left(encode(sha256(convert_to(kind || chr(31) ||
                        rtrim(regexp_replace(desired_sql, '\\s+', ' ', 'g'), ';'), 'UTF8')), 'hex'), 16)
                  WHERE kind = 'check' AND name = '{to}';"
            ),
        )
        .await
        .unwrap();
    }
}

async fn assert_no_drift(pool: &PgPool, ast: &SchemaAst) {
    let report = common::doctor(pool, ast).await;
    assert!(report.drifted.is_empty(), "{:?}", report.drifted);
    assert!(
        report.unmanaged_drift.is_empty(),
        "{:?}",
        report.unmanaged_drift
    );
    assert!(report.missing.is_empty(), "{:?}", report.missing);
    assert!(report.conflicting.is_empty(), "{:?}", report.conflicting);
}

#[tokio::test]
async fn a_fresh_push_names_each_rule_for_what_it_checks() {
    common::with_integration_pool(|pool| async move {
        let ast = chat();
        push(&pool, &ast).await.unwrap();
        assert_eq!(names(&checks(&pool).await), READABLE);
        assert_eq!(ledger_checks(&pool).await, READABLE);

        let refused = exec(
            &pool,
            "INSERT INTO public.chat_message VALUES (1, 'x', 1, 2)",
        )
        .await
        .expect_err("a one-character body is refused");
        assert!(
            refused.to_string().contains("chat_message_body_min_length"),
            "the error names what was checked: {refused}"
        );

        let again = push(&pool, &ast).await.unwrap();
        assert!(up_to_date(&again), "{again:?}");
    })
    .await;
}

#[tokio::test]
async fn positional_names_the_ledger_records_are_renamed_in_place_and_rolled_back() {
    common::with_integration_pool(|pool| async move {
        let ast = chat();
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "INSERT INTO public.chat_message VALUES (1, 'hello', 1, 2), (2, 'hi', 3, 3)",
        )
        .await
        .unwrap();
        rename_to_positional(&pool).await;
        ledger_as_positional(&pool).await;
        let before = checks(&pool).await;
        assert_eq!(names(&before), POSITIONAL);
        let (file, data) = (relfilenode(&pool).await, rows(&pool).await);
        // Not drift: the objects are exactly as the ledger recorded them.
        assert_no_drift(&pool, &ast).await;

        let outcome = push(&pool, &ast)
            .await
            .expect("the upgrade push applies unforced");
        assert!(
            !up_to_date(&outcome),
            "the names have to change: {outcome:?}"
        );
        let after = checks(&pool).await;
        assert_eq!(names(&after), READABLE);
        assert_eq!(
            oids(&before),
            oids(&after),
            "renamed, not dropped and made again"
        );
        assert_eq!(
            relfilenode(&pool).await,
            file,
            "the table was not rewritten"
        );
        assert_eq!(rows(&pool).await, data, "the rows are untouched");
        assert_eq!(
            ledger_checks(&pool).await,
            READABLE,
            "the rows follow the rename"
        );
        let sql = last_sql_up(&pool).await;
        assert!(
            sql.contains(
                r#"RENAME CONSTRAINT "chat_message_check_1" TO "chat_message_body_min_length""#
            ),
            "{sql}"
        );
        assert!(
            !sql.contains("DROP CONSTRAINT") && !sql.contains("ADD CONSTRAINT"),
            "nothing is dropped or added: {sql}"
        );
        assert_no_drift(&pool, &ast).await;
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the rename rolls back");
        let rolled = checks(&pool).await;
        assert_eq!(
            names(&rolled),
            POSITIONAL,
            "the rollback restores the old names"
        );
        assert_eq!(oids(&rolled), oids(&before));
        assert_eq!(
            ledger_checks(&pool).await,
            POSITIONAL,
            "and the ledger with them"
        );
        assert_eq!(rows(&pool).await, data);
    })
    .await;
}

#[tokio::test]
async fn positional_names_engine_0_6_stamped_are_renamed_in_place() {
    common::with_integration_pool(|pool| async move {
        let ast = chat();
        push(&pool, &ast).await.unwrap();
        exec(
            &pool,
            "INSERT INTO public.chat_message VALUES (1, 'hello', 1, 2)",
        )
        .await
        .unwrap();
        rename_to_positional(&pool).await;
        ledger_as_positional(&pool).await;
        // 0.6.0 kept no ledger: it stamped each rule with its columns and a SHA-256 of the
        // expression it generated (`managed_check_comment`).
        exec(
            &pool,
            "DO $old$ DECLARE r record; BEGIN
               FOR r IN SELECT name, substring(desired_sql FROM 'CHECK \\((.*)\\);$') AS expr
                          FROM _supatype.managed_objects
                         WHERE kind = 'check' AND parent = 'chat_message'
               LOOP
                 EXECUTE format('COMMENT ON CONSTRAINT %I ON public.chat_message IS %L', r.name,
                   'supatype:managed;kind=check;table=chat_message;fields=body;v=1;bounds=' ||
                   left(encode(sha256(convert_to(r.expr, 'UTF8')), 'hex'), 16));
               END LOOP;
               DELETE FROM _supatype.managed_objects WHERE kind = 'check';
             END $old$;",
        )
        .await
        .unwrap();
        let before = checks(&pool).await;
        assert_eq!(names(&before), POSITIONAL);
        assert!(comments(&pool).await.iter().all(Option::is_some));
        let (file, data) = (relfilenode(&pool).await, rows(&pool).await);

        push(&pool, &ast)
            .await
            .expect("the upgrade push applies unforced");
        let after = checks(&pool).await;
        assert_eq!(
            names(&after),
            READABLE,
            "renamed, not duplicated: {after:?}"
        );
        assert_eq!(
            oids(&before),
            oids(&after),
            "renamed, not dropped and made again"
        );
        assert_eq!(relfilenode(&pool).await, file);
        assert_eq!(rows(&pool).await, data);
        assert!(
            comments(&pool).await.iter().all(Option::is_none),
            "the stamps are taken out"
        );
        assert_eq!(ledger_checks(&pool).await, READABLE, "and recorded");
        assert_no_drift(&pool, &ast).await;
        assert!(up_to_date(&push(&pool, &ast).await.unwrap()));

        migration_history::apply_rollback(&pool, "public")
            .await
            .expect("the takeover rolls back");
        assert_eq!(names(&checks(&pool).await), POSITIONAL);
        assert!(
            comments(&pool).await.iter().all(Option::is_some),
            "the rollback puts the stamps back"
        );
    })
    .await;
}
