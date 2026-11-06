//! Access rules that read each other's tables in a loop are refused before they reach the database.
//!
//! A rule that reads another table's rows is a subquery inside the policy, and the subquery runs
//! under that table's own read policy. When the policies lead back to a table already being
//! expanded, Postgres refuses the query at run time with `infinite recursion detected in policy
//! for relation`, so a push that created them would leave every query on those tables failing. The
//! plan names the loop instead.

mod common;

use serde_json::{json, Value};
use supatype_engine::parser::{self, ast::SchemaAst};
use supatype_engine::push;

fn uuid() -> Value {
    json!({ "kind": "uuid", "required": false,
            "annotations": { "db": { "pgType": "UUID", "unique": false } } })
}

fn model(name: &str, table: &str, columns: &[&str], access: Value) -> Value {
    let mut fields = serde_json::Map::new();
    fields.insert(
        "id".into(),
        json!({ "kind": "uuid", "primaryKey": true, "required": true,
                "default": { "kind": "genRandomUuid" },
                "annotations": { "db": { "pgType": "UUID", "unique": false } } }),
    );
    for column in columns {
        fields.insert((*column).into(), uuid());
    }
    fields.insert(
        "published_at".into(),
        json!({ "kind": "datetime", "required": false,
                "annotations": { "db": { "pgType": "TIMESTAMPTZ", "unique": false } } }),
    );
    json!({
        "name": name,
        "fields": fields,
        "options": { "timestamps": false, "softDelete": false },
        "annotations": { "db": { "tableName": table, "indexes": [] },
                         "platform": { "access": access } }
    })
}

fn published() -> Value {
    json!({ "type": "nullCheck", "operand": { "kind": "column", "name": "published_at" },
            "isNull": false })
}

fn caller_owns() -> Value {
    json!({ "type": "compare", "op": "eq",
            "left": { "kind": "column", "name": "user_id" }, "right": { "kind": "authUid" } })
}

/// `In<column, Rows<table, "id", filter>>`.
fn rows_in(column: &str, table: &str, filter: Option<Value>) -> Value {
    let mut source = json!({ "kind": "rows", "table": table, "column": "id" });
    if let Some(filter) = filter {
        source["where"] = filter;
    }
    json!({ "type": "in", "column": column, "source": source })
}

fn any(rules: Vec<Value>) -> Value {
    json!({ "type": "any", "rules": rules })
}

fn schema(models: Vec<Value>) -> SchemaAst {
    let doc = json!({ "astVersion": 2, "models": models });
    parser::parse(&doc.to_string()).expect("the schema parses")
}

/// formflow's rules: a form is read by its owner or once published, a question through its form,
/// and anyone may answer a published form.
fn formflow() -> SchemaAst {
    schema(vec![
        model(
            "Form",
            "form",
            &["user_id"],
            json!({ "read": any(vec![json!({ "type": "owner", "field": "user_id" }), published()]),
                    "create": { "type": "authenticated" } }),
        ),
        model(
            "Question",
            "question",
            &["form_id"],
            json!({ "read": any(vec![
                rows_in("form_id", "form", Some(caller_owns())),
                rows_in("form_id", "form", Some(published())),
            ]) }),
        ),
        model(
            "Response",
            "response",
            &["form_id"],
            json!({ "create": rows_in("form_id", "form", Some(published())),
                    "read": rows_in("form_id", "form", Some(caller_owns())) }),
        ),
    ])
}

/// `a.read` reads `b`, whose read reads `a` back.
fn two_table_loop() -> SchemaAst {
    schema(vec![
        model(
            "A",
            "loop_a",
            &["b_id"],
            json!({ "read": any(vec![published(), rows_in("b_id", "loop_b", None)]) }),
        ),
        model(
            "B",
            "loop_b",
            &["a_id"],
            json!({ "read": any(vec![published(), rows_in("a_id", "loop_a", None)]) }),
        ),
    ])
}

/// `node.read` reads `node`.
fn self_loop() -> SchemaAst {
    schema(vec![model(
        "Node",
        "loop_node",
        &["parent_id"],
        json!({ "read": rows_in("parent_id", "loop_node", Some(published())) }),
    )])
}

fn refusal(ast: &SchemaAst) -> String {
    match push::fresh_migration(ast, "public", false) {
        Ok(_) => panic!("the plan was made, but the rules loop"),
        Err(e) => format!("{e:#}"),
    }
}

#[test]
fn rules_that_read_another_table_without_looping_are_planned() {
    push::fresh_migration(&formflow(), "public", false).expect("formflow's rules plan");
}

#[test]
fn two_tables_whose_reads_read_each_other_are_refused() {
    let err = refusal(&two_table_loop());
    assert!(
        err.contains("Access rules loop: loop_a.read -> loop_b.read -> loop_a.read"),
        "{err}"
    );
    assert!(
        err.contains("Postgres refuses to run looping rules"),
        "{err}"
    );
}

#[test]
fn a_read_that_reads_its_own_table_is_refused() {
    let err = refusal(&self_loop());
    assert!(
        err.contains("Access rules loop: loop_node.read -> loop_node.read"),
        "{err}"
    );
}

/// `w.create` reads `wb`, whose read reads `w` back. `w.read` is `a_read`: Postgres only refuses
/// the revisit when the policy it would expand there reads another table itself.
fn write_loop(a_read: Value) -> SchemaAst {
    schema(vec![
        model(
            "W",
            "loop_w",
            &["b_id", "c_id"],
            json!({ "read": a_read, "create": rows_in("b_id", "loop_wb", None) }),
        ),
        model(
            "WB",
            "loop_wb",
            &["w_id"],
            json!({ "read": rows_in("w_id", "loop_w", None) }),
        ),
        model("WC", "loop_wc", &[], json!({ "read": published() })),
    ])
}

/// A write that reads a table whose read reads the writer back loops too: the writer's table is
/// still being expanded when the subquery reaches it and its read policy reads `loop_wc`.
#[test]
fn a_write_rule_that_leads_back_to_its_own_table_is_refused() {
    let err = refusal(&write_loop(rows_in("c_id", "loop_wc", None)));
    assert!(
        err.contains("Access rules loop: loop_w.create -> loop_wb.read -> loop_w.read"),
        "{err}"
    );
}

/// The same path back to `loop_w` is no loop when `loop_w`'s read reads no table: Postgres has no
/// subquery left to expand there.
#[test]
fn a_path_back_to_a_read_that_reads_nothing_is_planned() {
    push::fresh_migration(&write_loop(published()), "public", false).expect("plans");
}

/// `layers` layers of two tables each, every table's read reading both tables of the next layer:
/// no loop, but twice as many paths through it with every layer.
fn diamonds(layers: usize) -> SchemaAst {
    let table = |layer: usize, side: &str| format!("dia_{layer}_{side}");
    let models = (0..layers)
        .flat_map(|layer| ["a", "b"].map(|side| (layer, side)))
        .map(|(layer, side)| {
            let read = if layer + 1 == layers {
                published()
            } else {
                any(vec![
                    rows_in("next_a", &table(layer + 1, "a"), None),
                    rows_in("next_b", &table(layer + 1, "b"), None),
                ])
            };
            let name = format!("Dia{layer}{side}");
            model(
                &name,
                &table(layer, side),
                &["next_a", "next_b"],
                json!({ "read": read }),
            )
        })
        .collect();
    schema(models)
}

/// A table met again along a second path is not met again in the search: each is followed once,
/// so a schema whose reads fan out and rejoin layer after layer plans at once rather than walking
/// every one of its 2^23 paths.
#[test]
fn reads_that_fan_out_and_rejoin_are_checked_once_per_table() {
    let started = std::time::Instant::now();
    push::fresh_migration(&diamonds(24), "public", false).expect("the diamonds plan");
    let took = started.elapsed();
    assert!(
        took < std::time::Duration::from_secs(30),
        "the loop check walked every path: {took:?}"
    );
}

/// Two models linked many-to-many, `junction_rows` (when given) the read of the first one, which
/// then reads the link table as its membership source.
fn linked(junction_rows: Option<Value>) -> SchemaAst {
    let member = model(
        "Member",
        "members",
        &[],
        json!({ "read": { "type": "authenticated" } }),
    );
    let mut project = model(
        "Project",
        "projects",
        &[],
        json!({ "read": junction_rows.unwrap_or_else(published), "update": published() }),
    );
    project["fields"]["members"] = json!({ "kind": "relation", "cardinality": "manyToMany",
                                           "target": "Member", "through": "project_members" });
    schema(vec![member, project])
}

/// A linked junction's policies read both ends, and neither end reads the junction: no loop.
#[test]
fn a_junction_reading_its_ends_is_not_a_loop() {
    push::fresh_migration(&linked(None), "public", false).expect("the linked junction plans");
}

/// An end that reads its junction as a membership source makes the junction take the ends'
/// intersected rules instead of reading them back, so the pair does not loop.
#[test]
fn a_rule_reading_its_own_junction_is_not_a_loop() {
    let mine = json!({
        "type": "in", "column": "id",
        "source": { "kind": "rows", "table": "project_members", "column": "project_id",
                    "where": { "type": "compare", "op": "eq",
                               "left": { "kind": "column", "name": "member_id" },
                               "right": { "kind": "authUid" } } }
    });
    push::fresh_migration(&linked(Some(mine)), "public", false).expect("the junction plans");
}

// ─── Against Postgres ────────────────────────────────────────────────────────

/// A role that row-level security applies to: a superuser bypasses it, and with it the error.
const READER: &str = "loop_reader";

async fn read_as(pool: &sqlx::PgPool, role: &str, table: &str) -> Result<(), sqlx::Error> {
    as_role(pool, role, &format!("SELECT count(*) FROM public.{table}")).await
}

/// `sql` run as `role`, in a transaction rolled back after.
async fn as_role(pool: &sqlx::PgPool, role: &str, sql: &str) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(&format!("SET LOCAL ROLE {role}"))
        .execute(&mut *tx)
        .await?;
    sqlx::query(sql).execute(&mut *tx).await?;
    tx.rollback().await
}

/// An insert into `loop_w` as the reader.
async fn insert_w(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    as_role(
        pool,
        READER,
        "INSERT INTO public.loop_w (id) VALUES (gen_random_uuid())",
    )
    .await
}

/// The tables of `ast` and its policies as the generator writes them, made without the push, so a
/// schema the check refuses can still be put in front of Postgres.
async fn create_by_hand(pool: &sqlx::PgPool, ast: &SchemaAst) {
    for model in &ast.models {
        let table = model.table_name();
        let columns: Vec<String> = model
            .fields
            .keys()
            .map(|c| {
                let ty = if c == "published_at" {
                    "timestamptz"
                } else {
                    "uuid"
                };
                format!("\"{c}\" {ty}")
            })
            .collect();
        common::exec(
            pool,
            &format!(
                "CREATE TABLE public.{table} ({}); GRANT SELECT, INSERT ON public.{table} TO {READER};",
                columns.join(", ")
            ),
        )
        .await
        .expect("table");
    }
    let policies = supatype_engine::generator::sql::rls::generate(ast, "public").expect("policies");
    common::exec(pool, &policies).await.expect("policies apply");
}

async fn reader_role(pool: &sqlx::PgPool) {
    common::exec(
        pool,
        &format!(
            "DO $$ BEGIN CREATE ROLE {READER}; EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL; END $$; \
             GRANT USAGE ON SCHEMA public TO {READER};"
        ),
    )
    .await
    .expect("reader role");
}

/// What the check refuses, Postgres refuses: both loops fail with its recursion error.
#[tokio::test(flavor = "multi_thread")]
async fn postgres_refuses_what_the_check_refuses() {
    common::with_integration_pool(|pool| async move {
        reader_role(&pool).await;
        create_by_hand(&pool, &two_table_loop()).await;
        create_by_hand(&pool, &self_loop()).await;
        for table in ["loop_a", "loop_b", "loop_node"] {
            let err = read_as(&pool, READER, table)
                .await
                .expect_err("a looping rule must fail in Postgres");
            assert!(
                err.to_string().contains("infinite recursion"),
                "{table}: {err}"
            );
        }
        create_by_hand(&pool, &write_loop(rows_in("c_id", "loop_wc", None))).await;
        let err = insert_w(&pool).await.expect_err("the write loop must fail");
        assert!(err.to_string().contains("infinite recursion"), "{err}");
    })
    .await;
}

/// The write path the check accepts, Postgres runs: `loop_w`'s read reads nothing, so the insert
/// meets no recursion (it is refused by the rule, not by Postgres's rewriter).
#[tokio::test(flavor = "multi_thread")]
async fn postgres_runs_a_path_back_to_a_read_that_reads_nothing() {
    common::with_integration_pool(|pool| async move {
        reader_role(&pool).await;
        create_by_hand(&pool, &write_loop(published())).await;
        let err = insert_w(&pool)
            .await
            .expect_err("the rule admits no such row");
        assert!(err.to_string().contains("row-level security"), "{err}");
    })
    .await;
}

/// What the check accepts, Postgres runs: formflow, pushed for real, reads cleanly on every table
/// as either API role.
#[tokio::test(flavor = "multi_thread")]
async fn postgres_runs_what_the_check_accepts() {
    common::with_integration_pool(|pool| async move {
        common::push(&pool, &formflow()).await.expect("push");
        for role in ["anon", "authenticated"] {
            for table in ["form", "question"] {
                read_as(&pool, role, table)
                    .await
                    .unwrap_or_else(|e| panic!("{role} on {table}: {e}"));
            }
        }
        read_as(&pool, "authenticated", "response")
            .await
            .unwrap_or_else(|e| panic!("authenticated on response: {e}"));
    })
    .await;
}
