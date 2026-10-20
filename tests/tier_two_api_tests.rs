//! Tier 2 field masking serving the API (F13, F62, F63, F14, F17; plan section D5, Option C).
//!
//! Tier 2 is what every database without `supatype_mask` gets: native dev, `database.external` and
//! custom images. Its `api` views are what PostgREST and pg_graphql serve, and the API roles hold
//! nothing on the base tables, so the views are the only way in. These tests run each caller the
//! API has (anon, two ordinary users, an admin by `app_metadata.role`, and `service_role`) through
//! the views a real push makes, with the grants a real push makes, and compare what comes back and
//! what is stored with tier 1's behaviour.
//!
//! No test here creates `supatype_mask`, so a push selects tier 2 even on `supatype/postgres`.

mod common;

use serde_json::{json, Value};
use supatype_engine::{
    differ::FieldMaskingTier,
    ledger::reconcile::Action,
    parser::{self, ast::SchemaAst},
    push,
};

const A: &str = "8517c5e3-067d-4327-9dfc-ba8f8b4bc4f7";
const B: &str = "e6779ad7-38f7-4f58-a926-a652bb90b8db";
const ADMIN: &str = "ae2c4442-fa2b-430b-8609-c4530b7eed80";

// ---------------------------------------------------------------------------------------------
// The T2 fixture: `Employee` (salary admin-only, ssn owner-only, name any signed-in user) and
// `Payslip` (primary key not named `id`, with a default; amount, and a note with a default,
// readable by its owner only).
// ---------------------------------------------------------------------------------------------

fn column(kind: &str, pg_type: &str, required: bool) -> Value {
    json!({ "kind": kind, "required": required,
            "annotations": { "db": { "pgType": pg_type, "unique": false } } })
}

/// `field` with a literal default.
fn with_default(mut field: Value, value: &str) -> Value {
    field["default"] = json!({ "kind": "value", "value": value });
    field
}

fn uuid_key(default: bool) -> Value {
    let mut field = json!({ "kind": "uuid", "primaryKey": true, "required": true,
                            "annotations": { "db": { "pgType": "UUID", "unique": false } } });
    if default {
        field["default"] = json!({ "kind": "genRandomUuid" });
    }
    field
}

fn model(name: &str, table: &str, fields: Value, access: Value) -> Value {
    json!({
        "name": name,
        "fields": fields,
        "options": { "timestamps": false, "softDelete": false },
        "annotations": {
            "db": { "tableName": table, "indexes": [] },
            "platform": { "access": access }
        }
    })
}

fn logged_in() -> Value {
    json!({ "type": "authenticated" })
}

fn owner(field: &str) -> Value {
    json!({ "type": "owner", "field": field })
}

fn admin() -> Value {
    json!({ "type": "role", "roles": ["admin"] })
}

fn fixture() -> SchemaAst {
    let employee = model(
        "Employee",
        "t2_employee",
        json!({
            "id": uuid_key(false),
            "name": column("text", "TEXT", true),
            "salary": column("integer", "INTEGER", false),
            "ssn": column("text", "TEXT", false),
        }),
        json!({
            "read": logged_in(),
            "create": owner("id"),
            "update": owner("id"),
            "delete": owner("id"),
            "fields": {
                "name": { "read": logged_in() },
                "salary": { "read": admin(), "write": admin() },
                "ssn": { "read": owner("id") }
            }
        }),
    );
    let payslip = model(
        "Payslip",
        "t2_payslip",
        json!({
            "ref": uuid_key(true),
            "owner_id": column("uuid", "UUID", true),
            "month": column("text", "TEXT", true),
            "amount": column("integer", "INTEGER", false),
            "note": with_default(column("text", "TEXT", false), "none"),
        }),
        json!({
            "read": logged_in(),
            "create": admin(),
            "update": admin(),
            "delete": admin(),
            "fields": {
                "amount": { "read": owner("owner_id") },
                "note": { "read": owner("owner_id") }
            }
        }),
    );
    let doc = json!({ "astVersion": 2, "models": [employee, payslip] }).to_string();
    parser::parse(&doc).expect("the T2 fixture parses")
}

// ---------------------------------------------------------------------------------------------
// Setup and callers
// ---------------------------------------------------------------------------------------------

/// The API roles and the auth helpers, as a provisioned database has them. `service_role` is
/// `BYPASSRLS` as on `supatype/postgres`, which is exactly what an owner-rights view takes away.
async fn prepare(pool: &sqlx::PgPool) {
    sqlx::raw_sql(
        "CREATE SCHEMA IF NOT EXISTS auth; \
         DO $$ BEGIN \
           BEGIN CREATE ROLE anon NOLOGIN NOINHERIT; \
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END; \
           BEGIN CREATE ROLE authenticated NOLOGIN NOINHERIT; \
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END; \
           BEGIN CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS; \
           EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END; \
         END $$;",
    )
    .execute(pool)
    .await
    .expect("roles and auth schema");
    sqlx::raw_sql(&supatype_engine::generator::sql::rls::generate_auth_helpers())
        .execute(pool)
        .await
        .expect("auth helpers");
}

/// This database's view owner (TI2).
async fn this_owner(pool: &sqlx::PgPool) -> String {
    let database: String = sqlx::query_scalar("SELECT current_database()::text")
        .fetch_one(pool)
        .await
        .expect("read the database's name");
    supatype_engine::generator::sql::field_views::api_owner_for(&database)
}

async fn push_fixture(pool: &sqlx::PgPool, ast: &SchemaAst) -> push::Outcome {
    let plan = push::prepare(pool, ast, "public")
        .await
        .expect("the push plans");
    assert_eq!(
        plan.diff.field_masking,
        FieldMaskingTier::Views,
        "no supatype_mask here, so tier 2 must be selected"
    );
    push::apply(pool, plan, push::ApplyOptions::default())
        .await
        .unwrap_or_else(|e| panic!("the push applies: {e:#}"))
}

/// Seeds the rows the T2 matrix starts from, as the superuser the tests connect as.
async fn seed(pool: &sqlx::PgPool) {
    sqlx::raw_sql(&format!(
        "DELETE FROM public.t2_payslip WHERE true; DELETE FROM public.t2_employee WHERE true;
         INSERT INTO public.t2_employee (id, name, salary, ssn) VALUES
           ('{A}', 'Alice', 50000, 'A-SSN-111'),
           ('{B}', 'Bob', 90000, 'B-SSN-222'),
           ('{ADMIN}', 'Ada', 150000, 'ADM-SSN-999');
         INSERT INTO public.t2_payslip (owner_id, month, amount) VALUES
           ('{A}', '2026-09', 4100), ('{B}', '2026-09', 7500), ('{ADMIN}', '2026-09', 12500);"
    ))
    .execute(pool)
    .await
    .expect("seed");
}

/// One API caller: the Postgres role PostgREST switches to and the claims it sets.
#[derive(Clone, Copy, Debug)]
enum Caller {
    Anon,
    A,
    B,
    Admin,
    Service,
}

impl Caller {
    fn role(self) -> &'static str {
        match self {
            Caller::Anon => "anon",
            Caller::Service => "service_role",
            _ => "authenticated",
        }
    }

    fn claims(self) -> Value {
        match self {
            Caller::Anon => json!({ "role": "anon" }),
            Caller::A => json!({ "role": "authenticated", "sub": A }),
            Caller::B => json!({ "role": "authenticated", "sub": B }),
            Caller::Admin => json!({ "role": "authenticated", "sub": ADMIN,
                                     "app_metadata": { "role": "admin" } }),
            Caller::Service => json!({ "role": "service_role" }),
        }
    }
}

/// What one statement returned for a caller, and the base table read back afterwards.
#[derive(Debug)]
struct Outcome {
    rows: Result<Vec<Value>, String>,
    /// `name|salary|ssn` per employee, ordered by name, read as the superuser after the statement.
    stored: Vec<String>,
}

/// Runs `sql` (a query, or a DML statement with `RETURNING`) as `caller` the way PostgREST does,
/// then reads the stored rows as the superuser, all in one transaction that is rolled back.
async fn as_caller(pool: &sqlx::PgPool, caller: Caller, sql: &str) -> Outcome {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(caller.claims().to_string())
        .execute(&mut *tx)
        .await
        .expect("set the claims");
    sqlx::raw_sql(&format!("SET LOCAL ROLE {}", caller.role()))
        .execute(&mut *tx)
        .await
        .expect("assume the API role");
    sqlx::raw_sql("SAVEPOINT caller")
        .execute(&mut *tx)
        .await
        .expect("savepoint");
    let wrapped = format!("WITH q AS ({sql}) SELECT coalesce(json_agg(q), '[]')::text FROM q");
    let rows = match sqlx::query_scalar::<_, String>(&wrapped)
        .fetch_one(&mut *tx)
        .await
    {
        Ok(text) => Ok(serde_json::from_str::<Vec<Value>>(&text).expect("json rows")),
        Err(e) => {
            sqlx::raw_sql("ROLLBACK TO SAVEPOINT caller")
                .execute(&mut *tx)
                .await
                .expect("back to the savepoint");
            Err(e.to_string())
        }
    };
    sqlx::raw_sql("RESET ROLE")
        .execute(&mut *tx)
        .await
        .expect("reset role");
    let stored: Vec<String> = sqlx::query_scalar(
        "SELECT name || '|' || coalesce(salary::text, '-') || '|' || coalesce(ssn, '-')
           FROM public.t2_employee ORDER BY name",
    )
    .fetch_all(&mut *tx)
    .await
    .expect("read the stored rows");
    let _ = tx.rollback().await;
    Outcome { rows, stored }
}

/// The rows `caller` gets, failing the test on an error.
async fn rows(pool: &sqlx::PgPool, caller: Caller, sql: &str) -> Vec<Value> {
    as_caller(pool, caller, sql)
        .await
        .rows
        .unwrap_or_else(|e| panic!("{caller:?}: {sql}: {e}"))
}

/// `(name, salary, ssn)` per employee row as JSON values, in order.
fn employees(rows: &[Value]) -> Vec<(Value, Value, Value)> {
    rows.iter()
        .map(|r| (r["name"].clone(), r["salary"].clone(), r["ssn"].clone()))
        .collect()
}

const READ_EMPLOYEES: &str = "SELECT name, salary, ssn FROM api.t2_employee ORDER BY name";
const READ_PAYSLIPS: &str =
    "SELECT owner_id::text AS owner, amount FROM api.t2_payslip ORDER BY amount NULLS FIRST, owner_id";

const STORED: [&str; 3] = [
    "Ada|150000|ADM-SSN-999",
    "Alice|50000|A-SSN-111",
    "Bob|90000|B-SSN-222",
];

async fn pushed(pool: &sqlx::PgPool) -> SchemaAst {
    prepare(pool).await;
    let ast = fixture();
    push_fixture(pool, &ast).await;
    seed(pool).await;
    ast
}

// ---------------------------------------------------------------------------------------------
// F13 and F63: reads
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn every_caller_reads_through_the_views_as_tier_one_would_show_them() {
    common::with_integration_pool(|pool| async move {
        pushed(&pool).await;

        // anon may not read at all (`read` is LoggedIn), so it holds no SELECT on the view: the
        // same 401 tier 1 gives.
        let anon = as_caller(&pool, Caller::Anon, READ_EMPLOYEES).await.rows;
        assert!(
            anon.as_ref()
                .is_err_and(|e| e.contains("permission denied")),
            "anon: {anon:?}"
        );

        let null = Value::Null;
        let s = |v: &str| json!(v);
        assert_eq!(
            employees(&rows(&pool, Caller::A, READ_EMPLOYEES).await),
            vec![
                (s("Ada"), null.clone(), null.clone()),
                (s("Alice"), null.clone(), s("A-SSN-111")),
                (s("Bob"), null.clone(), null.clone()),
            ],
            "A: every name, no salary, only their own ssn"
        );
        assert_eq!(
            employees(&rows(&pool, Caller::B, READ_EMPLOYEES).await),
            vec![
                (s("Ada"), null.clone(), null.clone()),
                (s("Alice"), null.clone(), null.clone()),
                (s("Bob"), null.clone(), s("B-SSN-222")),
            ],
            "B: every name, no salary, only their own ssn"
        );
        assert_eq!(
            employees(&rows(&pool, Caller::Admin, READ_EMPLOYEES).await),
            vec![
                (s("Ada"), json!(150000), s("ADM-SSN-999")),
                (s("Alice"), json!(50000), null.clone()),
                (s("Bob"), json!(90000), null.clone()),
            ],
            "admin: every salary, only their own ssn"
        );
        // F63: service_role is exempt from the masks, as tier 1 exempts it.
        assert_eq!(
            employees(&rows(&pool, Caller::Service, READ_EMPLOYEES).await),
            vec![
                (s("Ada"), json!(150000), s("ADM-SSN-999")),
                (s("Alice"), json!(50000), s("A-SSN-111")),
                (s("Bob"), json!(90000), s("B-SSN-222")),
            ],
            "service_role: everything, unmasked"
        );

        // OwnerFrom on a table whose key is not `id`.
        let amounts = |rows: Vec<Value>| -> Vec<Value> {
            let mut out: Vec<Value> = rows.iter().map(|r| r["amount"].clone()).collect();
            out.sort_by_key(|v| v.to_string());
            out
        };
        assert_eq!(
            amounts(rows(&pool, Caller::B, READ_PAYSLIPS).await),
            vec![json!(7500), Value::Null, Value::Null],
            "B sees only their own payslip's amount"
        );
        assert_eq!(
            amounts(rows(&pool, Caller::Service, READ_PAYSLIPS).await),
            vec![json!(12500), json!(4100), json!(7500)],
            "service_role sees every amount"
        );
    })
    .await;
}

#[tokio::test]
async fn the_api_roles_hold_nothing_on_the_base_tables() {
    common::with_integration_pool(|pool| async move {
        pushed(&pool).await;
        for caller in [Caller::Anon, Caller::A, Caller::Admin] {
            let base = as_caller(&pool, caller, "SELECT * FROM public.t2_employee").await;
            assert!(
                base.rows
                    .as_ref()
                    .is_err_and(|e| e.contains("permission denied")),
                "{caller:?} reached the base table: {:?}",
                base.rows
            );
        }
        for role in ["anon", "authenticated"] {
            let any: bool = sqlx::query_scalar(
                "SELECT has_table_privilege($1, 'public.t2_employee', 'SELECT')
                     OR has_table_privilege($1, 'public.t2_employee', 'INSERT')
                     OR has_table_privilege($1, 'public.t2_employee', 'UPDATE')
                     OR has_table_privilege($1, 'public.t2_employee', 'DELETE')",
            )
            .bind(role)
            .fetch_one(&pool)
            .await
            .expect("read the privilege");
            assert!(!any, "{role} holds a privilege on the base table");
        }
    })
    .await;
}

/// A write trigger function: its name, whether it is `SECURITY DEFINER`, its owner, its settings,
/// and whether `anon` may call it.
type TriggerFunctionRow = (String, bool, String, Option<Vec<String>>, bool);

#[tokio::test]
async fn the_views_and_their_triggers_run_as_a_dedicated_owner() {
    common::with_integration_pool(|pool| async move {
        pushed(&pool).await;
        let expected = this_owner(&pool).await;
        let views: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT c.relname::text, coalesce(array_to_string(c.reloptions, ','), ''),
                    pg_get_userbyid(c.relowner)::text
               FROM pg_class c WHERE c.relnamespace = 'api'::regnamespace AND c.relkind = 'v'
              ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .expect("read the views");
        assert_eq!(views.len(), 2, "{views:?}");
        for (name, options, owner) in &views {
            assert_eq!(options, "security_barrier=true", "{name}");
            assert_eq!(owner, &expected, "{name}");
        }
        let owner: (bool, bool, bool, bool) = sqlx::query_as(
            "SELECT rolcanlogin, rolbypassrls, rolsuper, rolinherit FROM pg_roles
              WHERE rolname = $1",
        )
        .bind(&expected)
        .fetch_one(&pool)
        .await
        .expect("the owner role exists");
        assert_eq!(owner, (false, false, false, false), "NOLOGIN NOBYPASSRLS");

        let functions: Vec<TriggerFunctionRow> = sqlx::query_as(
            "SELECT p.proname::text, p.prosecdef, pg_get_userbyid(p.proowner)::text, p.proconfig,
                    has_function_privilege('anon', p.oid, 'EXECUTE')
               FROM pg_proc p WHERE p.pronamespace = 'api'::regnamespace AND p.prorettype = 'trigger'::regtype
              ORDER BY 1",
        )
        .fetch_all(&pool)
        .await
        .expect("read the trigger functions");
        assert_eq!(functions.len(), 2, "{functions:?}");
        for (name, definer, owner, config, anon_executes) in &functions {
            assert!(definer, "{name} is not SECURITY DEFINER");
            assert_eq!(owner, &expected, "{name}");
            assert!(
                config
                    .as_ref()
                    .is_some_and(|c| c.iter().any(|s| s.starts_with("search_path="))),
                "{name} has no pinned search_path: {config:?}"
            );
            assert!(!anon_executes, "{name} is executable by PUBLIC");
        }
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// F62 and F63: writes
// ---------------------------------------------------------------------------------------------

fn patch(id: &str, set: &str) -> String {
    format!("UPDATE api.t2_employee SET {set} WHERE id = '{id}' RETURNING name, salary, ssn")
}

fn delete(id: &str) -> String {
    format!("DELETE FROM api.t2_employee WHERE id = '{id}' RETURNING name, salary, ssn")
}

#[tokio::test]
async fn an_update_returns_the_row_as_the_caller_may_see_it() {
    common::with_integration_pool(|pool| async move {
        pushed(&pool).await;

        // T2-N1: A's discarded write to the masked salary must not hand back the stored value.
        let out = as_caller(&pool, Caller::A, &patch(A, "salary = 1")).await;
        assert_eq!(
            out.rows.as_deref().map(employees),
            Ok(vec![(json!("Alice"), Value::Null, json!("A-SSN-111"))]),
            "A's own row, salary masked"
        );
        assert_eq!(out.stored, STORED, "the masked write is discarded");

        let out = as_caller(&pool, Caller::A, &patch(A, "name = 'Alice2'")).await;
        assert_eq!(
            out.rows.as_deref().map(employees),
            Ok(vec![(json!("Alice2"), Value::Null, json!("A-SSN-111"))])
        );
        assert_eq!(out.stored[1], "Alice2|50000|A-SSN-111");

        let out = as_caller(&pool, Caller::A, &patch(A, "ssn = 'A-NEW'")).await;
        assert_eq!(
            out.stored[1], "Alice|50000|A-NEW",
            "A may write their own ssn"
        );

        let out = as_caller(&pool, Caller::Admin, &patch(ADMIN, "salary = 160000")).await;
        assert_eq!(
            out.rows.as_deref().map(employees),
            Ok(vec![(json!("Ada"), json!(160000), json!("ADM-SSN-999"))])
        );
    })
    .await;
}

#[tokio::test]
async fn a_refused_write_reports_no_row_and_discloses_nothing() {
    common::with_integration_pool(|pool| async move {
        pushed(&pool).await;

        // T2-N2: RLS refuses each of these (update and delete are Owner<"id">), so the base
        // statement touches nothing and the view must say so rather than echo a row.
        for (caller, sql, what) in [
            (Caller::A, patch(B, "name = 'hacked'"), "A patching B"),
            (Caller::A, delete(B), "A deleting B"),
            (Caller::Admin, patch(A, "salary = 2"), "admin patching A"),
            (Caller::B, patch(A, "name = 'x'"), "B patching A"),
            (
                Caller::B,
                patch(A, "name = 'Alice'"),
                "B's no-op patch of A",
            ),
        ] {
            let out = as_caller(&pool, caller, &sql).await;
            assert_eq!(
                out.rows,
                Ok(Vec::new()),
                "{what}: a refused write returned a row"
            );
            assert_eq!(out.stored, STORED, "{what}: the stored rows changed");
        }
    })
    .await;
}

#[tokio::test]
async fn an_insert_checks_the_field_write_rules() {
    common::with_integration_pool(|pool| async move {
        pushed(&pool).await;

        // MASK-N1 (was T2-N3): each field write rule judges the row being inserted, as an RLS
        // `WITH CHECK` does, as tier 1 does. A value it allows is stored; one it refuses is an
        // error, never quietly dropped. Judged against a row of NULLs instead, `ssn`
        // (Owner<"id">) was stored as NULL for everyone but service_role.
        let insert = |id: &str, name: &str, salary: &str| {
            format!(
                "INSERT INTO api.t2_employee (id, name, salary, ssn)
                 VALUES ('{id}', '{name}', {salary}, '{name}-SSN') RETURNING name, salary, ssn"
            )
        };
        sqlx::raw_sql(&format!(
            "DELETE FROM public.t2_employee WHERE id IN ('{A}', '{ADMIN}')"
        ))
        .execute(&pool)
        .await
        .expect("make room");

        // A user creating their own row sets their own owner-only `ssn`, and reads it back.
        // `salary` is NULL, which is not a write, so a whole-object POST still works.
        let out = as_caller(&pool, Caller::A, &insert(A, "Alice", "NULL")).await;
        assert_eq!(
            out.rows.as_deref().map(employees),
            Ok(vec![(json!("Alice"), Value::Null, json!("Alice-SSN"))])
        );
        assert_eq!(out.stored, ["Alice|-|Alice-SSN", "Bob|90000|B-SSN-222"]);

        // `salary` is admin-only: a value from anyone else is refused and nothing is stored.
        let out = as_caller(&pool, Caller::A, &insert(A, "Alice", "999999")).await;
        let refusal = out.rows.expect_err("a non-admin wrote salary on INSERT");
        assert!(
            refusal.contains("permission denied for column salary of relation t2_employee"),
            "{refusal}"
        );
        assert_eq!(out.stored, ["Bob|90000|B-SSN-222"]);

        // The admin may write salary, on their own row (create is Owner<"id">), and their ssn.
        let out = as_caller(&pool, Caller::Admin, &insert(ADMIN, "Ada", "999999")).await;
        assert_eq!(
            out.rows.as_deref().map(employees),
            Ok(vec![(json!("Ada"), json!(999999), json!("Ada-SSN"))])
        );
        assert_eq!(out.stored[0], "Ada|999999|Ada-SSN");

        // service_role is exempt, as in tier 1: everything it sends is written.
        let out = as_caller(&pool, Caller::Service, &insert(A, "Alice", "999999")).await;
        assert_eq!(out.stored[0], "Alice|999999|Alice-SSN");
    })
    .await;
}

#[tokio::test]
async fn an_insert_through_a_view_gets_the_base_tables_defaults() {
    common::with_integration_pool(|pool| async move {
        pushed(&pool).await;
        // T2-N4: `ref` has a default; PostgREST sends only the columns the client gave. `note`
        // has one too, and it is masked: left out, it is no write by the admin, who does not own
        // B's payslip, so it takes its default rather than being refused.
        let payslip = |columns: &str, values: &str| {
            format!(
                "INSERT INTO api.t2_payslip (owner_id, month{columns}) VALUES ('{B}', '2026-10'{values})
                 RETURNING ref IS NOT NULL AS has_ref, amount, note"
            )
        };
        let out = as_caller(&pool, Caller::Admin, &payslip("", "")).await;
        assert_eq!(
            out.rows,
            Ok(vec![json!({ "has_ref": true, "amount": null, "note": null })]),
            "the admin does not own B's payslip, so its masked columns come back masked"
        );

        // An amount on B's payslip is B's to write (MASK-N1): refused, not stored as NULL.
        let out = as_caller(&pool, Caller::Admin, &payslip(", amount", ", 7600")).await;
        let refusal = out.rows.expect_err("the admin wrote an amount on B's payslip");
        assert!(
            refusal.contains("permission denied for column amount of relation t2_payslip"),
            "{refusal}"
        );

        // A masked column's default stays the base table's, so leaving it out is no write.
        let defaults: Vec<String> = sqlx::query_scalar(
            "SELECT a.attname::text FROM pg_attribute a JOIN pg_attrdef d
                 ON d.adrelid = a.attrelid AND d.adnum = a.attnum
              WHERE a.attrelid = 'api.t2_payslip'::regclass",
        )
        .fetch_all(&pool)
        .await
        .expect("read the view's defaults");
        assert_eq!(defaults, vec!["ref".to_string()]);
    })
    .await;
}

#[tokio::test]
async fn service_role_writes_masked_columns_as_in_tier_one() {
    common::with_integration_pool(|pool| async move {
        pushed(&pool).await;
        // T2-N5 / F63.
        let out = as_caller(&pool, Caller::Service, &patch(B, "salary = 3")).await;
        assert_eq!(
            out.rows.as_deref().map(employees),
            Ok(vec![(json!("Bob"), json!(3), json!("B-SSN-222"))])
        );
        assert_eq!(out.stored[2], "Bob|3|B-SSN-222");
        let out = as_caller(&pool, Caller::Service, &delete(A)).await;
        assert_eq!(out.rows.map(|r| r.len()), Ok(1));
        assert_eq!(out.stored.len(), 2, "service_role deletes any row");
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// T2-N10 and F14: generated, recorded, and guarded
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_second_push_plans_nothing_and_keeps_the_owner_rights_design() {
    common::with_integration_pool(|pool| async move {
        let ast = pushed(&pool).await;
        let second = push::plan(&pool, &ast, "public").await.expect("plans");
        assert!(
            second.diff.operations.is_empty() && !second.reconcile.has_changes(),
            "a second push must plan nothing: {:?}",
            second.reconcile.actions
        );
        // Every predicate the push recorded for realtime is a function the database holds.
        let unknown: Vec<String> = sqlx::query_scalar(
            "SELECT p FROM _supatype.schema_state s,
                    jsonb_array_elements(s.capabilities #> '{fieldMasking,columns}') c,
                    LATERAL (VALUES (c ->> 'read'), (c ->> 'write')) v(p)
              WHERE p IS NOT NULL AND to_regproc(p) IS NULL",
        )
        .fetch_all(&pool)
        .await
        .expect("read the recorded predicates");
        assert!(unknown.is_empty(), "recorded but not there: {unknown:?}");
        let recorded: i32 = sqlx::query_scalar(
            "SELECT jsonb_array_length(capabilities #> '{fieldMasking,columns}')
               FROM _supatype.schema_state WHERE id = 1",
        )
        .fetch_one(&pool)
        .await
        .expect("count the recorded predicates");
        assert_eq!(recorded, 5, "name, salary, ssn, amount and note");
        // And an applied third push leaves the design in place.
        push_fixture(&pool, &ast).await;
        let options: String = sqlx::query_scalar(
            "SELECT coalesce(array_to_string(reloptions, ','), '') || ' ' || pg_get_userbyid(relowner)
               FROM pg_class WHERE oid = 'api.t2_employee'::regclass",
        )
        .fetch_one(&pool)
        .await
        .expect("read the view");
        assert_eq!(options, format!("security_barrier=true {}", this_owner(&pool).await));
    })
    .await;
}

/// A hand change on tier 2's access surface is drift that needs consent to put back.
async fn assert_access_drift(pool: &sqlx::PgPool, ast: &SchemaAst, edit: &str, kind: &str) {
    sqlx::raw_sql(edit)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{edit}: {e}"));
    let plan = push::plan(pool, ast, "public").await.expect("plans");
    let drifted: Vec<String> = plan
        .reconcile
        .actions
        .iter()
        .filter_map(|a| match a {
            Action::Drift {
                key,
                security_relevant: true,
                ..
            } => Some(key.to_string()),
            _ => None,
        })
        .collect();
    assert!(
        drifted.iter().any(|k| k.starts_with(kind)),
        "{edit}: no access drift on a {kind} reported: {:?}",
        plan.reconcile.actions
    );
    let refused = push::apply(pool, plan, push::ApplyOptions::default()).await;
    assert!(
        refused.is_err_and(|e| e.to_string().contains("changed outside Supatype")),
        "{edit}: a push put it back without consent"
    );
    let plan = push::plan(pool, ast, "public").await.expect("plans");
    push::apply(
        pool,
        plan,
        push::ApplyOptions {
            overwrite_drift: true,
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{edit}: the consented push fails: {e:#}"));
}

#[tokio::test]
async fn hand_changes_to_the_views_access_are_reported_and_need_consent() {
    common::with_integration_pool(|pool| async move {
        let ast = pushed(&pool).await;
        // E19 and T2-N10: the view's options and owner.
        assert_access_drift(
            &pool,
            &ast,
            "ALTER VIEW api.t2_employee SET (security_invoker = true)",
            "view api.",
        )
        .await;
        assert_access_drift(
            &pool,
            &ast,
            "ALTER VIEW api.t2_employee RESET (security_barrier)",
            "view api.",
        )
        .await;
        assert_access_drift(
            &pool,
            &ast,
            "ALTER VIEW api.t2_employee OWNER TO CURRENT_USER",
            "view api.",
        )
        .await;
        // E18: the views' privileges.
        assert_access_drift(
            &pool,
            &ast,
            "REVOKE SELECT ON api.t2_employee FROM authenticated",
            "table_grant api.",
        )
        .await;
        assert_access_drift(
            &pool,
            &ast,
            "GRANT DELETE, TRUNCATE ON api.t2_payslip TO anon",
            "table_grant api.",
        )
        .await;

        // Put back, and recorded again: the next push plans nothing.
        let plan = push::plan(&pool, &ast, "public").await.expect("plans");
        assert!(
            !plan.reconcile.has_changes(),
            "{:?}",
            plan.reconcile.actions
        );
        let options: String = sqlx::query_scalar(
            "SELECT coalesce(array_to_string(reloptions, ','), '') || ' ' || pg_get_userbyid(relowner)
               FROM pg_class WHERE oid = 'api.t2_employee'::regclass",
        )
        .fetch_one(&pool)
        .await
        .expect("read the view");
        assert_eq!(options, format!("security_barrier=true {}", this_owner(&pool).await));
    })
    .await;
}

/// A versioned model: its `draft` view and versions table carry privileges of their own.
fn versioned() -> SchemaAst {
    parser::parse(&versioned_document().to_string()).expect("the versioned fixture parses")
}

fn versioned_document() -> Value {
    json!({
        "astVersion": 2,
        "publishing": {
            "draftVisibility": ["admin"],
            "previewDefaultTtl": 900,
            "previewMaxRecordTtl": 604800,
            "previewMaxProjectTtl": 86400,
            "previewAllowProjectScope": true
        },
        "models": [{
            "name": "Article",
            "fields": {
                "id": uuid_key(true),
                "title": column("text", "TEXT", true),
            },
            "options": { "timestamps": false, "softDelete": false,
                         "versions": { "drafts": true, "keep": 5 } },
            "annotations": {
                "db": { "tableName": "t2_article", "indexes": [] },
                "platform": {
                    "access": { "read": { "type": "public" }, "create": logged_in(),
                                "update": logged_in(), "delete": logged_in() }
                }
            }
        }]
    })
}

#[tokio::test]
async fn hand_changes_to_draft_and_versions_privileges_are_reported() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        let ast = versioned();
        push::apply(
            &pool,
            push::prepare(&pool, &ast, "public").await.expect("plans"),
            push::ApplyOptions::default(),
        )
        .await
        .unwrap_or_else(|e| panic!("the push applies: {e:#}"));
        // E18, parts 2 and 3.
        assert_access_drift(
            &pool,
            &ast,
            "GRANT INSERT, UPDATE ON draft.t2_article TO anon",
            "table_grant draft.",
        )
        .await;
        assert_access_drift(
            &pool,
            &ast,
            "GRANT SELECT, DELETE ON public.t2_article_versions TO anon",
            "table_grant public.t2_article_versions",
        )
        .await;

        // E18, part 3: who may call an RPC function. Put back exactly as recorded, a grant to a
        // role the schema never named included.
        let publish = "supatype.publish(text,text,integer,text[])";
        assert_access_drift(
            &pool,
            &ast,
            &format!(
                "REVOKE EXECUTE ON FUNCTION {publish} FROM PUBLIC, anon, authenticated; \
                 GRANT EXECUTE ON FUNCTION {publish} TO pg_monitor"
            ),
            "function supatype.publish",
        )
        .await;
        // Named grants only: `PUBLIC`, which the layer leaves this function, reaches every role.
        let callers: (bool, bool) = sqlx::query_as(&format!(
            "SELECT has_function_privilege('authenticated', '{publish}', 'EXECUTE'),
                    EXISTS (SELECT 1 FROM aclexplode((SELECT proacl FROM pg_proc
                                                       WHERE oid = '{publish}'::regprocedure)) g
                             WHERE g.grantee = 'pg_monitor'::regrole)"
        ))
        .fetch_one(&pool)
        .await
        .expect("read the function's callers");
        assert_eq!(
            callers,
            (true, false),
            "authenticated back, pg_monitor gone"
        );
        assert_access_drift(
            &pool,
            &ast,
            "REVOKE EXECUTE ON FUNCTION public.can_read_t2_article(public.t2_article, boolean) \
             FROM PUBLIC, anon, authenticated",
            "function public.can_read_t2_article",
        )
        .await;
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// F17: the labels a database stops using when it moves to tier 2
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn moving_to_tier_two_takes_the_mask_labels_off() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            eprintln!("SKIP: this image cannot load supatype_mask, so there are no labels to drop");
            return;
        }
        prepare(&pool).await;
        let ast = fixture();
        let plan = push::prepare(&pool, &ast, "public").await.expect("plans");
        assert_eq!(plan.diff.field_masking, FieldMaskingTier::Extension);
        push::apply(&pool, plan, push::ApplyOptions::default())
            .await
            .unwrap_or_else(|e| panic!("tier 1 push: {e:#}"));
        let labels = || async {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM pg_seclabel WHERE provider = 'supatype'",
            )
            .fetch_one(&pool)
            .await
            .expect("count labels")
        };
        assert_eq!(labels().await, 5, "tier 1 labels each field rule");

        // T2-N7: the library is still preloaded, so the labels keep acting until they are gone.
        sqlx::raw_sql("DROP EXTENSION supatype_mask CASCADE")
            .execute(&pool)
            .await
            .expect("drop the extension");
        // Doctor says what the push will do, and why: the rule is still declared.
        let before = supatype_engine::inspect::doctor(&pool, &ast, "public", false)
            .await
            .expect("doctor");
        assert_eq!(before.stale_managed.len(), 5, "{:?}", before.stale_managed);
        assert!(
            before
                .stale_managed
                .iter()
                .all(|i| i.message.contains("is not used")
                    && i.message.contains("takes the label off")),
            "{:?}",
            before.stale_managed
        );
        push_fixture(&pool, &ast).await;
        assert_eq!(labels().await, 0, "A3-N6: the tier 2 push left the labels");

        let report = supatype_engine::inspect::doctor(&pool, &ast, "public", false)
            .await
            .expect("doctor");
        assert!(
            report.stale_managed.is_empty(),
            "doctor still promises to drop: {:?}",
            report.stale_managed
        );
        seed(&pool).await;
        let out = as_caller(&pool, Caller::Admin, &patch(ADMIN, "salary = 1")).await;
        assert!(
            out.rows.is_ok(),
            "an update through the view fails: {:?}",
            out.rows
        );
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// The owner's reach: a policy evaluated as the views' owner calls what the API roles may call
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_versioned_model_reads_through_its_view_under_tier_two() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        // The drafts layer puts a policy on the model's table that calls a function granted to the
        // API roles by name. Under tier 2 every model reads through a view, and a function a view
        // or its table's policies call is checked against the caller, so this works on a database
        // where nothing is callable unless granted. A versioned model may not mask a column, so the
        // masking is the T2 fixture's, beside it. Read by any signed-in user: a rule that is not
        // simply TRUE, which the planner would fold the drafts policy into and never call it.
        let mut doc = versioned_document();
        doc["models"][0]["annotations"]["platform"]["access"]["read"] = logged_in();
        let fixture: Value = serde_json::to_value(fixture()).expect("the fixture serialises");
        for model in fixture["models"].as_array().expect("models") {
            doc["models"]
                .as_array_mut()
                .expect("models")
                .push(model.clone());
        }
        let ast = parser::parse(&doc.to_string()).expect("parses");
        // A hardened database: no function is anyone's to call unless granted by name, which is
        // what makes the drafts layer's grant to the API roles the only way in.
        sqlx::raw_sql("ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC")
            .execute(&pool)
            .await
            .expect("harden");
        push_fixture(&pool, &ast).await;
        sqlx::raw_sql("INSERT INTO public.t2_article (title) VALUES ('hello')")
            .execute(&pool)
            .await
            .expect("seed");
        let read = "SELECT title FROM api.t2_article";
        for caller in [Caller::A, Caller::Admin] {
            assert_eq!(
                rows(&pool, caller, read).await,
                vec![json!({ "title": "hello" })],
                "{caller:?}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn a_write_trigger_may_call_what_the_api_roles_may() {
    common::with_integration_pool(|pool| async move {
        pushed(&pool).await;
        // The write trigger runs as the views' owner, so the policies its statements meet are
        // evaluated with the owner's rights, functions included. A policy written as the docs advise
        // (to PUBLIC, testing in its expression) that calls an affordance function, which only the
        // API roles may call (H2), must not break every write.
        sqlx::raw_sql(
            "CREATE POLICY hand_written ON public.t2_employee AS RESTRICTIVE FOR UPDATE \
             USING (public.can_read_t2_employee(t2_employee))",
        )
        .execute(&pool)
        .await
        .expect("a hand-written policy");
        let out = as_caller(&pool, Caller::A, &patch(A, "name = 'Alice2'")).await;
        assert_eq!(
            out.rows.as_deref().map(employees),
            Ok(vec![(json!("Alice2"), Value::Null, json!("A-SSN-111"))])
        );
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// Plan D5 (4b): a hand-written policy restricted to an API role no longer applies through the views
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn doctor_warns_about_a_policy_restricted_to_an_api_role() {
    common::with_integration_pool(|pool| async move {
        let ast = pushed(&pool).await;
        sqlx::raw_sql(
            "CREATE POLICY hand_written ON public.t2_employee AS RESTRICTIVE FOR SELECT \
             TO authenticated USING (name <> 'Bob')",
        )
        .execute(&pool)
        .await
        .expect("a hand-written policy");
        // Through the view it does not apply, as the warning says: B still sees Bob.
        let names: Vec<Value> = rows(&pool, Caller::B, READ_EMPLOYEES)
            .await
            .iter()
            .map(|r| r["name"].clone())
            .collect();
        assert!(names.contains(&json!("Bob")), "{names:?}");

        let report = supatype_engine::inspect::doctor(&pool, &ast, "public", false)
            .await
            .expect("doctor");
        let item = report
            .unmanaged_drift
            .iter()
            .find(|i| i.name == "hand_written")
            .unwrap_or_else(|| panic!("not reported: {:?}", report.unmanaged_drift));
        assert!(
            item.message.contains("no longer applies through them")
                && item.message.contains("RESTRICTIVE"),
            "{}",
            item.message
        );
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// F64: GraphQL reflects the views, and its mutations disclose nothing
// ---------------------------------------------------------------------------------------------

/// `graphql.resolve` as `caller`, with the search path the stack gives pg_graphql under tier 2.
async fn gql(pool: &sqlx::PgPool, caller: Caller, query: &str) -> Value {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(caller.claims().to_string())
        .execute(&mut *tx)
        .await
        .expect("claims");
    sqlx::raw_sql(&format!(
        "SET LOCAL ROLE {}; SET LOCAL search_path = api, graphql_public",
        caller.role()
    ))
    .execute(&mut *tx)
    .await
    .expect("role");
    let answer: Value = sqlx::query_scalar("SELECT graphql.resolve($1)")
        .bind(query)
        .fetch_one(&mut *tx)
        .await
        .expect("resolve");
    let _ = tx.rollback().await;
    answer
}

/// The rows of a `t2_employeeCollection` answer, by name.
fn gql_nodes(answer: &Value) -> Vec<Value> {
    let mut out: Vec<Value> = answer["data"]["t2_employeeCollection"]["edges"]
        .as_array()
        .unwrap_or_else(|| panic!("no rows: {answer}"))
        .iter()
        .map(|e| e["node"].clone())
        .collect();
    out.sort_by_key(|n| n["name"].to_string());
    out
}

/// `updatet2_employeeCollection` of A's row, setting `name`.
fn gql_rename_a(name: &str) -> String {
    format!(
        "mutation {{ updatet2_employeeCollection(set: {{name: \"{name}\"}}, \
         filter: {{id: {{eq: \"{A}\"}}}}) {{ affectedCount records {{ name salary ssn }} }} }}"
    )
}

#[tokio::test]
async fn graphql_serves_the_views_masked_and_its_mutations_disclose_nothing() {
    common::with_integration_pool(|pool| async move {
        pushed(&pool).await;
        if !install_pg_graphql(&pool).await {
            return;
        }
        let read = "{ t2_employeeCollection { edges { node { name salary ssn } } } }";
        assert_eq!(
            gql_nodes(&gql(&pool, Caller::B, read).await),
            vec![
                json!({ "name": "Ada", "salary": null, "ssn": null }),
                json!({ "name": "Alice", "salary": null, "ssn": null }),
                json!({ "name": "Bob", "salary": null, "ssn": "B-SSN-222" }),
            ]
        );
        assert_eq!(
            gql_nodes(&gql(&pool, Caller::Service, read).await)[0],
            json!({ "name": "Ada", "salary": 150000, "ssn": "ADM-SSN-999" })
        );
        let filtered = gql(
            &pool,
            Caller::B,
            "{ t2_employeeCollection(filter: {salary: {gt: 80000}}) { edges { node { name } } } }",
        )
        .await;
        assert_eq!(
            gql_nodes(&filtered),
            Vec::<Value>::new(),
            "a filter on a masked column is an oracle"
        );

        // T2-N1 over GraphQL: B renaming A touches nothing and returns nothing.
        let refused = gql(&pool, Caller::B, &gql_rename_a("gql")).await;
        assert_eq!(
            refused["data"]["updatet2_employeeCollection"],
            json!({ "affectedCount": 0, "records": [] }),
            "{refused}"
        );
        // A renaming their own row gets it back masked.
        let own = gql(&pool, Caller::A, &gql_rename_a("Alice2")).await;
        assert_eq!(
            own["data"]["updatet2_employeeCollection"]["records"],
            json!([{ "name": "Alice2", "salary": null, "ssn": "A-SSN-111" }]),
            "{own}"
        );
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// A rule that reads a junction table as its membership source
// ---------------------------------------------------------------------------------------------

/// `Member` and `Project` joined many-to-many through `t2_project_members`, both readable by any
/// signed-in user, so the junction is too; and `Task`, readable by the members of its project.
fn membership_fixture() -> SchemaAst {
    let uuid = || column("uuid", "UUID", true);
    let member = model(
        "Member",
        "t2_members",
        json!({ "id": uuid_key(false), "name": column("text", "TEXT", false) }),
        json!({ "read": logged_in() }),
    );
    let project = model(
        "Project",
        "t2_projects",
        json!({
            "id": uuid_key(false),
            "members": { "kind": "relation", "cardinality": "manyToMany", "target": "Member",
                         "through": "t2_project_members" }
        }),
        json!({ "read": logged_in() }),
    );
    let in_my_projects = json!({
        "type": "in", "column": "project_id",
        "source": { "kind": "rows", "table": "t2_project_members", "column": "project_id",
                    "where": { "type": "compare", "op": "eq",
                               "left": { "kind": "column", "name": "member_id" },
                               "right": { "kind": "authUid" } } }
    });
    let task = model(
        "Task",
        "t2_tasks",
        json!({ "id": uuid_key(false), "project_id": uuid(),
                "title": column("text", "TEXT", false),
                "estimate": column("integer", "INTEGER", false) }),
        json!({ "read": in_my_projects, "fields": { "estimate": { "read": admin() } } }),
    );
    let doc = json!({ "astVersion": 2, "models": [member, project, task] }).to_string();
    parser::parse(&doc).expect("the membership fixture parses")
}

/// Under tier 2 a view reads a membership source with its owner's rights, so the owner needs on a
/// junction what an API role has there. Without it a member's read of `api.t2_tasks` failed with
/// permission denied on the junction, where tier 1 returns the member's own tasks.
#[tokio::test]
async fn a_rule_reading_a_junction_works_through_the_views() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        let ast = membership_fixture();
        push_fixture(&pool, &ast).await;
        let p1 = "22222222-2222-2222-2222-222222222222";
        let p2 = "33333333-3333-3333-3333-333333333333";
        sqlx::raw_sql(&format!(
            "INSERT INTO public.t2_members (id, name) VALUES ('{A}', 'Alice'), ('{B}', 'Bob');
             INSERT INTO public.t2_projects (id) VALUES ('{p1}'), ('{p2}');
             INSERT INTO public.t2_project_members (project_id, member_id) VALUES ('{p1}', '{A}');
             INSERT INTO public.t2_tasks (id, project_id, title, estimate) VALUES
               (gen_random_uuid(), '{p1}', 'mine', 3), (gen_random_uuid(), '{p2}', 'theirs', 8);"
        ))
        .execute(&pool)
        .await
        .expect("seed");

        assert_eq!(task_titles(&pool, Caller::A).await.unwrap(), ["mine"]);
        assert_eq!(
            task_titles(&pool, Caller::B).await.unwrap(),
            Vec::<String>::new()
        );
        let again = push_fixture(&pool, &ast).await;
        assert!(matches!(again, push::Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

/// The task titles `caller` reads through `api.t2_tasks`, as PostgREST would ask, or the error.
async fn task_titles(pool: &sqlx::PgPool, caller: Caller) -> Result<Vec<String>, String> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(caller.claims().to_string())
        .execute(&mut *tx)
        .await
        .expect("set the claims");
    sqlx::raw_sql(&format!("SET LOCAL ROLE {}", caller.role()))
        .execute(&mut *tx)
        .await
        .expect("assume the API role");
    let titles = sqlx::query_scalar("SELECT title FROM api.t2_tasks ORDER BY title")
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| e.to_string());
    let _ = tx.rollback().await;
    titles
}

// ---------------------------------------------------------------------------------------------
// F64 (TRAIN-FIX-N1): GraphQL relations between the views
// ---------------------------------------------------------------------------------------------

/// Every relation kind the engine makes a foreign key for, across masked tables: `Staff` refers to
/// itself (`manager`) and joins `Project` many-to-many; `Payslip` belongs to its staff member, who
/// alone may read it; `Badge` belongs to one staff member one-to-one. `salary` and `budget` are
/// admin-only, so a nested read shows whether the mask holds through a relation.
fn relations_fixture() -> SchemaAst {
    let belongs_to = |target: &str, unique: bool| {
        json!({ "kind": "relation", "cardinality": "belongsTo", "target": target,
                "uniqueFk": unique, "required": false })
    };
    // A staff member is keyed by their auth user id, which the CLI marks (O1): a payslip's owner
    // relation reaches them.
    let mut staff_id = uuid_key(false);
    staff_id["annotations"]["db"]["authUserId"] = json!(true);
    let staff = model(
        "Staff",
        "staff",
        json!({
            "id": staff_id,
            "name": column("text", "TEXT", true),
            "salary": column("integer", "INTEGER", false),
            "manager": belongs_to("Staff", false),
            "payslips": { "kind": "relation", "cardinality": "hasMany", "target": "Payslip" },
            "badge": { "kind": "relation", "cardinality": "hasOne", "target": "Badge" },
            "projects": { "kind": "relation", "cardinality": "manyToMany", "target": "Project",
                          "through": "staff_project" }
        }),
        json!({ "read": logged_in(), "fields": { "salary": { "read": admin() } } }),
    );
    let payslip = model(
        "Payslip",
        "payslip",
        json!({
            "ref": uuid_key(true),
            "staff": belongs_to("Staff", false),
            "month": column("text", "TEXT", true),
            "amount": column("integer", "INTEGER", false),
        }),
        json!({ "read": owner("staff"), "fields": { "amount": { "read": owner("staff") } } }),
    );
    let badge = model(
        "Badge",
        "badge",
        json!({ "id": uuid_key(true), "holder": belongs_to("Staff", true),
                "code": column("text", "TEXT", true) }),
        json!({ "read": logged_in() }),
    );
    let project = model(
        "Project",
        "project",
        json!({ "id": uuid_key(false), "title": column("text", "TEXT", true),
                "budget": column("integer", "INTEGER", false) }),
        json!({ "read": logged_in(), "fields": { "budget": { "read": admin() } } }),
    );
    let doc = json!({ "astVersion": 2, "models": [staff, payslip, badge, project] }).to_string();
    parser::parse(&doc).expect("the relations fixture parses")
}

const P1: &str = "44444444-4444-4444-4444-444444444444";

/// Ada manages Alice and Bob; each has a payslip and a badge, and Alice works on project P1.
async fn seed_relations(pool: &sqlx::PgPool) {
    sqlx::raw_sql(&format!(
        "INSERT INTO public.staff (id, name, salary) VALUES ('{ADMIN}', 'Ada', 150000);
         INSERT INTO public.staff (id, name, salary, manager_id) VALUES
           ('{A}', 'Alice', 50000, '{ADMIN}'), ('{B}', 'Bob', 90000, '{ADMIN}');
         INSERT INTO public.payslip (staff_id, month, amount) VALUES
           ('{A}', '2026-09', 4100), ('{B}', '2026-09', 7500), ('{ADMIN}', '2026-09', 12500);
         INSERT INTO public.badge (holder_id, code) VALUES
           ('{A}', 'A-1'), ('{B}', 'B-1'), ('{ADMIN}', 'ADM-1');
         INSERT INTO public.project (id, title, budget) VALUES ('{P1}', 'Apollo', 999);
         INSERT INTO public.staff_project (staff_id, project_id) VALUES ('{A}', '{P1}');"
    ))
    .execute(pool)
    .await
    .expect("seed the relations fixture");
}

/// pg_graphql, granted to the API roles as the stack grants it. False when the image has none.
async fn install_pg_graphql(pool: &sqlx::PgPool) -> bool {
    let installed = sqlx::raw_sql(
        "CREATE SCHEMA IF NOT EXISTS graphql_public; \
         CREATE EXTENSION IF NOT EXISTS pg_graphql; \
         GRANT USAGE ON SCHEMA graphql, graphql_public TO anon, authenticated, service_role; \
         GRANT SELECT ON ALL TABLES IN SCHEMA graphql TO anon, authenticated, service_role; \
         GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA graphql TO anon, authenticated, service_role;",
    )
    .execute(pool)
    .await;
    match installed {
        Ok(_) => true,
        Err(e) => {
            assert!(
                !common::force_integration_tests(),
                "this image cannot provide pg_graphql: {e}"
            );
            eprintln!("SKIP: no pg_graphql here ({e})");
            false
        }
    }
}

/// The nodes of the top-level connection `field` in a GraphQL answer, failing on an error.
fn connection(answer: &Value, field: &str) -> Vec<Value> {
    assert_eq!(answer.get("errors"), None, "{answer}");
    answer["data"][field]["edges"]
        .as_array()
        .unwrap_or_else(|| panic!("no connection {field}: {answer}"))
        .iter()
        .map(|e| e["node"].clone())
        .collect()
}

/// One staff node by name.
fn staff_named<'a>(nodes: &'a [Value], name: &str) -> &'a Value {
    nodes
        .iter()
        .find(|n| n["name"] == name)
        .unwrap_or_else(|| panic!("no {name} among {nodes:?}"))
}

/// The names in a nested staff connection, sorted.
fn names_in(node: &Value, field: &str) -> Vec<String> {
    let mut names: Vec<String> = node[field]["edges"]
        .as_array()
        .unwrap_or_else(|| panic!("no {field} on {node}"))
        .iter()
        .map(|e| e["node"]["name"].as_str().unwrap_or_default().to_string())
        .collect();
    names.sort();
    names
}

const STAFF_WITH_RELATIONS: &str = "{ staffCollection { edges { node { name salary \
     manager { name salary } \
     staffCollection { edges { node { name } } } \
     payslips { edges { node { month amount } } } \
     badgeCollection { edges { node { code } } } \
     staff_projectCollection { edges { node { project { title budget } } } } } } } }";

/// pg_graphql reads a view's foreign keys from its comment, as it reads the primary key, so under
/// tier 2 the views offer the relations tier 1's tables do, under the same names: each end the
/// schema names by its field (`manager`, `payslips`, `holder`), an end it does not name by
/// pg_graphql's own (`staffCollection` for the managed staff), a self-reference both ways, and a
/// many-to-many through its junction. A one-to-one key's reverse is the one shape that differs:
/// pg_graphql finds no unique index on a view, so it is `badgeCollection` where tier 1 offers
/// `badge`. Read as user A, every nested row is one A may see and every nested value is masked as
/// A's own read of that table would mask it.
#[tokio::test]
async fn graphql_offers_the_relations_between_the_views_masked_for_the_caller() {
    common::with_integration_pool(|pool| async move {
        prepare(&pool).await;
        let ast = relations_fixture();
        push_fixture(&pool, &ast).await;
        seed_relations(&pool).await;
        if !install_pg_graphql(&pool).await {
            return;
        }

        a_reads_down_the_relations(&pool).await;
        a_reads_up_the_relations(&pool).await;
        service_role_reads_the_relations_unmasked(&pool).await;

        let again = push_fixture(&pool, &ast).await;
        assert!(matches!(again, push::Outcome::UpToDate { .. }), "{again:?}");
    })
    .await;
}

/// From each staff member to what refers to them: masked as A sees it, and only rows A may see.
async fn a_reads_down_the_relations(pool: &sqlx::PgPool) {
    let answer = gql(pool, Caller::A, STAFF_WITH_RELATIONS).await;
    let staff = connection(&answer, "staffCollection");
    assert_eq!(staff.len(), 3, "{answer}");
    assert!(staff.iter().all(|s| s["salary"].is_null()), "{answer}");

    let alice = staff_named(&staff, "Alice");
    assert_eq!(alice["manager"], json!({ "name": "Ada", "salary": null }));
    assert_eq!(
        alice["badgeCollection"]["edges"],
        json!([{ "node": { "code": "A-1" } }])
    );
    assert_eq!(
        alice["payslips"]["edges"],
        json!([{ "node": { "month": "2026-09", "amount": 4100 } }])
    );
    assert_eq!(
        alice["staff_projectCollection"]["edges"],
        json!([{ "node": { "project": { "title": "Apollo", "budget": null } } }])
    );

    let ada = staff_named(&staff, "Ada");
    assert_eq!(names_in(ada, "staffCollection"), ["Alice", "Bob"]);
    assert_eq!(ada["manager"], Value::Null);
    // Nothing A may not read: neither Ada's nor Bob's payslip appears under them.
    assert_eq!(ada["payslips"]["edges"], json!([]), "{answer}");
    let bob = staff_named(&staff, "Bob");
    assert_eq!(bob["payslips"]["edges"], json!([]), "{answer}");
    assert_eq!(bob["staff_projectCollection"]["edges"], json!([]));
}

/// The to-one direction from each referencing view, the junction's included, masked the same way.
async fn a_reads_up_the_relations(pool: &sqlx::PgPool) {
    let cases = [
        (
            "payslipCollection",
            "{ payslipCollection { edges { node { amount staff { name salary } } } } }",
            json!({ "amount": 4100, "staff": { "name": "Alice", "salary": null } }),
        ),
        (
            "badgeCollection",
            "{ badgeCollection(filter: {code: {eq: \"B-1\"}}) { edges { node { holder { name } } } } }",
            json!({ "holder": { "name": "Bob" } }),
        ),
        (
            "staff_projectCollection",
            "{ staff_projectCollection { edges { node { staff { name } project { title } } } } }",
            json!({ "staff": { "name": "Alice" }, "project": { "title": "Apollo" } }),
        ),
    ];
    for (collection, query, want) in cases {
        let answer = gql(pool, Caller::A, query).await;
        assert_eq!(connection(&answer, collection), [want], "{query}");
    }
}

/// service_role, unmasked as in tier 1, sees every row and value through the same relations.
async fn service_role_reads_the_relations_unmasked(pool: &sqlx::PgPool) {
    let answer = gql(pool, Caller::Service, STAFF_WITH_RELATIONS).await;
    let staff = connection(&answer, "staffCollection");
    assert_eq!(
        staff_named(&staff, "Bob")["payslips"]["edges"],
        json!([{ "node": { "month": "2026-09", "amount": 7500 } }])
    );
    assert_eq!(staff_named(&staff, "Ada")["salary"], 150000);
    assert_eq!(
        staff_named(&staff, "Alice")["staff_projectCollection"]["edges"],
        json!([{ "node": { "project": { "title": "Apollo", "budget": 999 } } }])
    );
}
