//! An `Owner` rule through a relation, inside the `where` of a `Rows` membership source.
//!
//! The owner test reads the related model's table, and named it unqualified. A tier 2 set helper
//! runs with an empty `search_path`, so the table could not be found and every read of the masked
//! column failed; under any other `search_path` the name could resolve to another schema's table.
//! These tests push such a rule in both tiers and read through it as two team owners.

mod common;

use serde_json::{json, Value};
use supatype_engine::parser::{self, ast::SchemaAst};

const A: &str = "bbbbbbbb-0000-0000-0000-0000000000a1";
const B: &str = "bbbbbbbb-0000-0000-0000-0000000000b2";

fn uuid_key() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "annotations": { "db": { "pgType": "UUID", "unique": false } } })
}

fn column(kind: &str, pg_type: &str) -> Value {
    json!({ "kind": kind, "required": false,
            "annotations": { "db": { "pgType": pg_type, "unique": false } } })
}

fn model(name: &str, table: &str, fields: Value, access: Value) -> Value {
    json!({ "name": name, "fields": fields,
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": { "tableName": table, "indexes": [] },
                             "platform": { "access": access } } })
}

/// A team its owner reads; a project owned through its team (`Owner<"team">`); and a task whose
/// `secret` is readable where its project is one of the caller's: `In<project_id, Rows<ow_project,
/// id, where: Owner<"team">>>`.
fn fixture() -> SchemaAst {
    let owner_id = json!({ "kind": "uuid", "required": true,
                           "annotations": { "db": { "pgType": "UUID", "unique": false,
                                                     "authUserId": true } } });
    let team = model(
        "OwTeam",
        "ow_team",
        json!({ "id": uuid_key(), "owner_id": owner_id }),
        json!({ "read": { "type": "owner", "field": "owner_id" } }),
    );
    let project = model(
        "OwProject",
        "ow_project",
        json!({ "id": uuid_key(), "name": column("text", "TEXT"),
                "team": { "kind": "relation", "cardinality": "belongsTo", "target": "OwTeam",
                          "annotations": { "db": { "foreignKey": "team_id" } } } }),
        json!({ "read": { "type": "owner", "field": "team" } }),
    );
    let mine = json!({ "type": "in", "column": "project_id", "source": {
        "kind": "rows", "table": "ow_project", "column": "id",
        "where": { "type": "owner", "field": "team" } } });
    let task = model(
        "OwTask",
        "ow_task",
        json!({ "id": uuid_key(), "project_id": column("uuid", "UUID"),
                "secret": column("text", "TEXT") }),
        json!({ "read": { "type": "public" }, "fields": { "secret": { "read": mine } } }),
    );
    let doc = json!({ "astVersion": 2, "models": [team, project, task] }).to_string();
    parser::parse(&doc).expect("the fixture parses")
}

/// Pushes the fixture and gives A and B a team, a project and a task each.
async fn pushed(pool: &sqlx::PgPool) {
    common::push(pool, &fixture())
        .await
        .unwrap_or_else(|e| panic!("the push applies: {e:#}"));
    sqlx::raw_sql(&format!(
        "INSERT INTO public.ow_team (id, owner_id) VALUES
           ('{A}', '{A}'), ('{B}', '{B}');
         INSERT INTO public.ow_project (id, name, team_id) VALUES
           ('{A}', 'pa', '{A}'), ('{B}', 'pb', '{B}');
         INSERT INTO public.ow_task (id, project_id, secret) VALUES
           (gen_random_uuid(), '{A}', 'sa'), (gen_random_uuid(), '{B}', 'sb');"
    ))
    .execute(pool)
    .await
    .expect("seed");
}

/// Runs `sql` as `authenticated` with `sub`, as PostgREST does, under PostgREST's own
/// `search_path`, and returns its rows, rolled back.
async fn as_caller(pool: &sqlx::PgPool, sub: &str, sql: &str) -> Result<Vec<Value>, String> {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('request.jwt.claims', $1, true)")
        .bind(json!({ "role": "authenticated", "sub": sub }).to_string())
        .execute(&mut *tx)
        .await
        .expect("set the claims");
    sqlx::raw_sql("SET LOCAL ROLE authenticated")
        .execute(&mut *tx)
        .await
        .expect("assume authenticated");
    let wrapped = format!("WITH q AS ({sql}) SELECT coalesce(json_agg(q), '[]')::text FROM q");
    let rows = sqlx::query_scalar::<_, String>(&wrapped)
        .fetch_one(&mut *tx)
        .await
        .map(|text| serde_json::from_str(&text).expect("json rows"))
        .map_err(|e| e.to_string());
    let _ = tx.rollback().await;
    rows
}

/// What A and B each read of the tasks' secrets and the projects, through `tasks` and `projects`.
async fn reads_as_owners(pool: &sqlx::PgPool, tasks: &str, projects: &str) {
    let secrets = format!("SELECT secret FROM {tasks} ORDER BY secret NULLS LAST");
    let names = format!("SELECT name FROM {projects} ORDER BY name");
    for (sub, secret, project) in [(A, "sa", "pa"), (B, "sb", "pb")] {
        let read = as_caller(pool, sub, &secrets)
            .await
            .unwrap_or_else(|e| panic!("{sub}: the masked column could not be read: {e}"));
        assert_eq!(
            read,
            [json!({ "secret": secret }), json!({ "secret": null })],
            "{sub} reads their own task's secret only"
        );
        let read = as_caller(pool, sub, &names)
            .await
            .expect("read the projects");
        assert_eq!(
            read,
            [json!({ "name": project })],
            "{sub} reads their own project only"
        );
    }
}

/// A second push of the fixture plans nothing: the qualified table is not read back as a change.
async fn converged(pool: &sqlx::PgPool) {
    let ast = fixture();
    let plan = supatype_engine::push::prepare(pool, &ast, "public")
        .await
        .expect("plan");
    assert!(
        !plan.reconcile.has_changes(),
        "{:?}",
        plan.reconcile.actions
    );
}

#[tokio::test]
async fn an_owner_through_relation_filter_masks_under_tier_two() {
    common::with_integration_pool(|pool| async move {
        pushed(&pool).await;
        reads_as_owners(&pool, "api.ow_task", "api.ow_project").await;
        converged(&pool).await;
    })
    .await;
}

#[tokio::test]
async fn an_owner_through_relation_filter_masks_under_tier_one() {
    common::with_integration_pool(|pool| async move {
        if !common::mask_extension_available(&pool).await {
            eprintln!("SKIP: this image cannot load supatype_mask, so there is no tier 1");
            return;
        }
        pushed(&pool).await;
        reads_as_owners(&pool, "public.ow_task", "public.ow_project").await;
        converged(&pool).await;
    })
    .await;
}
