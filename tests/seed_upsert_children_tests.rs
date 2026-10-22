//! A nested `create` under an `upsert` is safe to re-run (C5).
//!
//! `upsert` promises a seed can run again, and its own row kept that promise while the children
//! nested in it did not: every run inserted them again, so a second `supatype seed` left two copies
//! of every comment. A child under an upsert is now written only when no row under the same parent
//! already holds every value the seed gives it. These run each seed twice against a real Postgres,
//! because the claim is about what is in the table after the second run.

mod common;

use supatype_engine::parser;
use supatype_engine::parser::ast::SchemaAst;
use supatype_engine::seed::errors::constraint_index_for;
use supatype_engine::seed::execute::{execute, Context, Report};
use supatype_engine::seed::plan::plan;
use supatype_engine::seed::SeedIr;

/// An organiser with events, an event with ticket types and tags, and a junction model for the
/// tags: the shapes a nested create under an upsert reaches.
const SCHEMA: &str = r#"{
    "astVersion": 2,
    "models": [
        {"name": "Organiser",
         "fields": {
            "id": {"kind": "uuid", "required": true, "primaryKey": true,
                   "default": {"kind": "genRandomUuid"}},
            "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}},
            "name": {"kind": "text", "required": true},
            "events": {"kind": "relation", "cardinality": "hasMany", "target": "Event"}},
         "annotations": {"db": {"tableName": "uc_organiser"}}},
        {"name": "Event",
         "fields": {
            "id": {"kind": "uuid", "required": true, "primaryKey": true,
                   "default": {"kind": "genRandomUuid"}},
            "title": {"kind": "text", "required": true},
            "notes": {"kind": "text", "required": false},
            "capacity": {"kind": "integer", "required": false},
            "body": {"kind": "richText", "required": false},
            "created_at": {"kind": "datetime", "required": false},
            "organiser": {"kind": "relation", "cardinality": "belongsTo", "target": "Organiser",
                          "required": false, "annotations": {"db": {"foreignKey": "organiser_id"}}},
            "ticket_types": {"kind": "relation", "cardinality": "hasMany", "target": "TicketType"},
            "tags": {"kind": "relation", "cardinality": "hasMany", "target": "EventTag"}},
         "annotations": {"db": {"tableName": "uc_event"}}},
        {"name": "TicketType",
         "fields": {
            "id": {"kind": "uuid", "required": true, "primaryKey": true,
                   "default": {"kind": "genRandomUuid"}},
            "name": {"kind": "text", "required": true},
            "quantity": {"kind": "integer", "required": false, "default": {"kind": "value", "value": 0}},
            "event": {"kind": "relation", "cardinality": "belongsTo", "target": "Event",
                      "required": false, "annotations": {"db": {"foreignKey": "event_id"}}}},
         "annotations": {"db": {"tableName": "uc_ticket_type"}}},
        {"name": "Tag",
         "fields": {
            "id": {"kind": "uuid", "required": true, "primaryKey": true,
                   "default": {"kind": "genRandomUuid"}},
            "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}}},
         "annotations": {"db": {"tableName": "uc_tag"}}},
        {"name": "EventTag",
         "fields": {
            "id": {"kind": "uuid", "required": true, "primaryKey": true,
                   "default": {"kind": "genRandomUuid"}},
            "event": {"kind": "relation", "cardinality": "belongsTo", "target": "Event",
                      "required": false, "annotations": {"db": {"foreignKey": "event_id"}}},
            "tag": {"kind": "relation", "cardinality": "belongsTo", "target": "Tag",
                    "required": false, "annotations": {"db": {"foreignKey": "tag_id"}}}},
         "annotations": {"db": {"tableName": "uc_event_tag"}}}
    ]
}"#;

async fn seed(pool: &sqlx::PgPool, ast: &SchemaAst, operations: &str) -> Report {
    let document =
        format!(r#"{{"irVersion":1,"schemaFingerprint":"sha256:x","operations":{operations}}}"#);
    let ir: SeedIr = serde_json::from_str(&document).expect("the IR fixture parses");
    let planned = plan(&ir, ast).expect("plans");
    let cx = Context {
        ast,
        constraints: &constraint_index_for(ast),
        schema: "public",
        environment: None,
    };
    execute(pool, &planned, cx).await.expect("the seed runs")
}

async fn count(pool: &sqlx::PgPool, table: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(pool)
        .await
        .expect("counts")
}

async fn with_schema<F, Fut>(f: F)
where
    F: FnOnce(sqlx::PgPool, SchemaAst) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    common::with_integration_pool(|pool| async move {
        let ast = parser::parse(SCHEMA).expect("the schema fixture parses");
        common::push(&pool, &ast).await.expect("the schema pushes");
        f(pool, ast).await;
    })
    .await;
}

/// An upsert of organiser `o` whose `events` are `events`, a JSON array of nested rows.
fn organiser_with(events: &str) -> String {
    format!(
        r#"[{{"op":"upsert","model":"Organiser","where":{{"slug":"o"}},
            "data":{{"name":"O","events":{{"create":{events}}}}}}}]"#
    )
}

/// Run `operations` twice, returning the second run's report.
async fn twice(pool: &sqlx::PgPool, ast: &SchemaAst, operations: &str) -> Report {
    seed(pool, ast, operations).await;
    seed(pool, ast, operations).await
}

fn written(report: &Report, model: &str) -> usize {
    report.written.get(model).copied().unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread")]
async fn running_the_same_seed_twice_leaves_one_copy_of_each_child() {
    with_schema(|pool, ast| async move {
        let ops = organiser_with(r#"[{"title":"Conf"},{"title":"Meetup"}]"#);
        let second = twice(&pool, &ast, &ops).await;
        assert_eq!(count(&pool, "uc_organiser").await, 1);
        assert_eq!(count(&pool, "uc_event").await, 2, "one copy of each event");
        assert_eq!(
            written(&second, "Event"),
            0,
            "the second run wrote no event"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_changed_child_value_adds_a_new_child() {
    with_schema(|pool, ast| async move {
        seed(&pool, &ast, &organiser_with(r#"[{"title":"Conf"}]"#)).await;
        let changed = seed(&pool, &ast, &organiser_with(r#"[{"title":"Conf 2"}]"#)).await;
        assert_eq!(
            count(&pool, "uc_event").await,
            2,
            "a new value is a new child"
        );
        assert_eq!(written(&changed, "Event"), 1);
    })
    .await;
}

/// The same child under another parent is not a match: the parent link is part of the match.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_child_under_another_parent_is_written() {
    with_schema(|pool, ast| async move {
        seed(&pool, &ast, &organiser_with(r#"[{"title":"Conf"}]"#)).await;
        let other = r#"[{"op":"upsert","model":"Organiser","where":{"slug":"p"},
            "data":{"name":"P","events":{"create":[{"title":"Conf"}]}}}]"#;
        seed(&pool, &ast, other).await;
        assert_eq!(count(&pool, "uc_event").await, 2);
    })
    .await;
}

/// Prose is stored as the document the trigger wraps it in, and still matches on the next run.
#[tokio::test(flavor = "multi_thread")]
async fn a_rich_text_plain_string_matches_what_the_trigger_stored() {
    with_schema(|pool, ast| async move {
        let ops = organiser_with(r#"[{"title":"Conf","body":"Hello there."}]"#);
        twice(&pool, &ast, &ops).await;
        assert_eq!(count(&pool, "uc_event").await, 1);
        let edited = organiser_with(r#"[{"title":"Conf","body":"Goodbye."}]"#);
        seed(&pool, &ast, &edited).await;
        assert_eq!(
            count(&pool, "uc_event").await,
            2,
            "different prose is a different child"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_null_field_matches_a_null_column() {
    with_schema(|pool, ast| async move {
        let ops = organiser_with(r#"[{"title":"Conf","notes":null,"capacity":null}]"#);
        twice(&pool, &ast, &ops).await;
        assert_eq!(count(&pool, "uc_event").await, 1);
    })
    .await;
}

/// A child of a child follows the same rule, under the row the first level matched.
#[tokio::test(flavor = "multi_thread")]
async fn a_child_two_levels_down_is_matched_too() {
    with_schema(|pool, ast| async move {
        let tickets =
            r#"[{"title":"Conf","ticket_types":{"createMany":[{"name":"Early"},{"name":"Std"}]}}]"#;
        twice(&pool, &ast, &organiser_with(tickets)).await;
        assert_eq!(count(&pool, "uc_event").await, 1);
        assert_eq!(count(&pool, "uc_ticket_type").await, 2);

        let more =
            r#"[{"title":"Conf","ticket_types":{"createMany":[{"name":"Early"},{"name":"VIP"}]}}]"#;
        seed(&pool, &ast, &organiser_with(more)).await;
        assert_eq!(count(&pool, "uc_event").await, 1, "the event was matched");
        assert_eq!(
            count(&pool, "uc_ticket_type").await,
            3,
            "VIP joins the matched event"
        );
        let linked: i64 = sqlx::query_scalar(
            "SELECT count(DISTINCT event_id) FROM uc_ticket_type WHERE event_id IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .expect("counts");
        assert_eq!(linked, 1, "every ticket type hangs off the one event");
    })
    .await;
}

/// Junction rows connected by a natural key are matched on the id the key resolves to.
#[tokio::test(flavor = "multi_thread")]
async fn a_many_to_many_link_under_an_upsert_is_not_duplicated() {
    with_schema(|pool, ast| async move {
        let ops = r#"[{"op":"upsert","model":"Tag","where":{"slug":"rust"},"data":{}},
            {"op":"upsert","model":"Organiser","where":{"slug":"o"},"data":{"name":"O",
             "events":{"create":[{"title":"Conf",
               "tags":{"create":[{"tag":{"connect":{"slug":"rust"}}}]}}]}}}]"#;
        twice(&pool, &ast, ops).await;
        assert_eq!(count(&pool, "uc_event").await, 1);
        assert_eq!(count(&pool, "uc_event_tag").await, 1);
        let unlinked: i64 =
            sqlx::query_scalar("SELECT count(*) FROM uc_event_tag WHERE tag_id IS NULL")
                .fetch_one(&pool)
                .await
                .expect("counts");
        assert_eq!(unlinked, 0, "the link names the tag");
    })
    .await;
}

/// A column the seed leaves to its default is not compared, so a later edit to it does not
/// make the child look new.
#[tokio::test(flavor = "multi_thread")]
async fn a_defaulted_column_the_seed_omits_is_not_compared() {
    with_schema(|pool, ast| async move {
        let ops =
            organiser_with(r#"[{"title":"Conf","ticket_types":{"create":[{"name":"Early"}]}}]"#);
        seed(&pool, &ast, &ops).await;
        sqlx::query("UPDATE uc_ticket_type SET quantity = 5 WHERE name = 'Early'")
            .execute(&pool)
            .await
            .expect("edits");
        seed(&pool, &ast, &ops).await;
        assert_eq!(count(&pool, "uc_ticket_type").await, 1);
    })
    .await;
}

/// `now()` is a different value on every run, so a time the database computes is not compared:
/// were it, a child carrying one would be added again on every run.
#[tokio::test(flavor = "multi_thread")]
async fn a_time_the_database_computes_is_not_compared() {
    with_schema(|pool, ast| async move {
        let ops = organiser_with(r#"[{"title":"Conf","created_at":{"kind":"now"}}]"#);
        twice(&pool, &ast, &ops).await;
        assert_eq!(count(&pool, "uc_event").await, 1);
    })
    .await;
}

/// Two identical children in one seed are one child: the second matches the first.
#[tokio::test(flavor = "multi_thread")]
async fn identical_children_in_one_seed_collapse_to_one() {
    with_schema(|pool, ast| async move {
        seed(
            &pool,
            &ast,
            &organiser_with(r#"[{"title":"Conf"},{"title":"Conf"}]"#),
        )
        .await;
        assert_eq!(count(&pool, "uc_event").await, 1);
    })
    .await;
}

/// A row that gives no value at all is every column's default. The insert used to name an
/// empty column list, `INSERT INTO t () ...`, which Postgres refuses as a syntax error.
#[tokio::test(flavor = "multi_thread")]
async fn a_row_with_no_values_is_written_with_its_defaults() {
    with_schema(|pool, ast| async move {
        seed(
            &pool,
            &ast,
            r#"[{"op":"create","model":"EventTag","data":{}}]"#,
        )
        .await;
        assert_eq!(count(&pool, "uc_event_tag").await, 1);
    })
    .await;
}

/// A plain `create` makes a new parent every run, so its children are written as they were.
#[tokio::test(flavor = "multi_thread")]
async fn a_nested_create_under_a_plain_create_is_unchanged() {
    with_schema(|pool, ast| async move {
        let ops = r#"[{"op":"create","model":"Organiser","data":{"slug":"c","name":"C",
            "events":{"create":[{"title":"Conf"},{"title":"Conf"}]}}}]"#;
        let report = seed(&pool, &ast, ops).await;
        assert_eq!(count(&pool, "uc_event").await, 2, "no match is looked for");
        assert_eq!(written(&report, "Event"), 2);
    })
    .await;
}
