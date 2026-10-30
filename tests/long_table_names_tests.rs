//! Table names past Postgres's identifier limit.
//!
//! Postgres cuts an identifier past 63 bytes to its first 63, on a character boundary, with only a
//! notice. A model whose table name ran past that, or a many-to-many whose junction name (the two
//! tables joined) did, was created under the cut name and then looked up under the full one, so
//! the push failed after applying it. Every table the schema names, and every table derived from
//! one, is now the name Postgres keeps, and two that would be cut to one refuse the schema.

mod common;

use common::up_to_date;
use serde_json::{json, Value};
use supatype_engine::generator::typescript::{admin, types};
use supatype_engine::parser::{self, ast::SchemaAst};
use supatype_engine::push;

/// 69 bytes, so Postgres keeps its first 63.
const LONG_TABLE: &str = "conference_attendee_registration_dietary_preferences_and_requirements";

/// 46 bytes each: either is a legal table name, and the two joined (93 bytes) are not.
const LEFT: &str = "conference_attendee_registration_dietary_notes";
const RIGHT: &str = "conference_session_speaker_availability_window";

fn id_field() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" },
            "annotations": { "db": { "pgType": "UUID", "unique": false } } })
}

fn text() -> Value {
    json!({ "kind": "text", "annotations": { "db": { "pgType": "TEXT", "unique": false } } })
}

/// A model `name` stored in `table` (derived from `name` when empty), with `fields` besides its id
/// and a title, readable by anyone.
fn model(name: &str, table: &str, fields: Value) -> Value {
    let mut all = json!({ "id": id_field(), "title": text() });
    for (key, field) in fields.as_object().unwrap() {
        all[key] = field.clone();
    }
    let mut db = json!({ "indexes": [] });
    if !table.is_empty() {
        db["tableName"] = json!(table);
    }
    json!({ "name": name, "fields": all,
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": db,
                             "platform": { "access": { "read": { "type": "public" } } } } })
}

fn doc(models: Vec<Value>) -> Value {
    json!({ "astVersion": 2, "models": models })
}

fn parse(doc: &Value) -> SchemaAst {
    parser::parse(&doc.to_string()).expect("the fixture parses")
}

fn refusal(doc: &Value) -> String {
    parser::parse(&doc.to_string())
        .expect_err("the schema is refused")
        .to_string()
}

/// Tag and Note, Tag holding a many-to-many to Note, each in a 46-byte table.
fn long_junction() -> SchemaAst {
    let tags = json!({ "notes": { "kind": "relation", "cardinality": "manyToMany",
                                  "target": "Note" } });
    parse(&doc(vec![
        model("Tag", RIGHT, tags),
        model("Note", LEFT, json!({})),
    ]))
}

/// One model with drafts in `LONG_TABLE`, editable by an editor.
fn long_drafts() -> SchemaAst {
    let mut post = model("Post", LONG_TABLE, json!({}));
    post["options"]["versions"] = json!({ "drafts": true, "keep": 5 });
    post["annotations"]["platform"]["access"]["update"] =
        json!({ "type": "role", "roles": ["editor"] });
    let mut doc = doc(vec![post]);
    doc["publishing"] = json!({ "draftVisibility": ["editor"], "previewDefaultTtl": 900,
                                "previewMaxRecordTtl": 604800, "previewMaxProjectTtl": 86400,
                                "previewAllowProjectScope": true });
    parse(&doc)
}

// ── What the parser gives every later step ────────────────────────────────────

#[test]
fn a_declared_table_name_past_the_limit_is_kept_as_postgres_keeps_it() {
    let ast = parse(&doc(vec![model("Post", LONG_TABLE, json!({}))]));
    assert_eq!(ast.models[0].table_name(), &LONG_TABLE[..63]);
}

/// A multibyte name is cut on a character boundary: 40 two-byte characters are 80 bytes, and
/// Postgres keeps 31 of them, 62 bytes, rather than half of the 32nd.
#[test]
fn a_multibyte_table_name_is_cut_on_a_character_boundary() {
    let table = "\u{e9}".repeat(40);
    let ast = parse(&doc(vec![model("Post", &table, json!({}))]));
    assert_eq!(ast.models[0].table_name(), "\u{e9}".repeat(31));
}

#[test]
fn a_junction_name_past_the_limit_is_kept_as_postgres_keeps_it() {
    let joined = format!("{LEFT}_{RIGHT}");
    let ast = long_junction();
    let junction = &ast.junction_tables[0];
    assert_eq!(junction.name, &joined[..63]);
    assert_eq!(junction.fk_a, "note_id");
}

/// A junction's key columns are named from its models and kept as Postgres keeps them too.
#[test]
fn a_junction_key_column_past_the_limit_is_kept_as_postgres_keeps_it() {
    let name = "ConferenceAttendeeRegistrationDietaryPreferencesAndRequirements";
    let many = json!({ "tags": { "kind": "relation", "cardinality": "manyToMany",
                                 "target": "Tag" } });
    let ast = parse(&doc(vec![
        model(name, "regs", many),
        model("Tag", "tags", json!({})),
    ]));
    let junction = &ast.junction_tables[0];
    assert_eq!(junction.name, "regs_tags");
    assert_eq!(junction.fk_a, &format!("{LONG_TABLE}_id")[..63]);
}

#[test]
fn two_tables_postgres_would_cut_to_one_are_refused_naming_both() {
    let (a, b) = (format!("{LONG_TABLE}_a"), format!("{LONG_TABLE}_b"));
    let refused = refusal(&doc(vec![
        model("First", &a, json!({})),
        model("Second", &b, json!({})),
    ]));
    assert!(refused.contains(&a) && refused.contains(&b), "{refused}");
    assert!(refused.contains("63"), "{refused}");
}

/// A model's versions table and another model's table are both tables in one schema.
#[test]
fn a_table_and_another_models_versions_table_cut_to_one_are_refused_naming_both() {
    let mut versioned = model("Post", LONG_TABLE, json!({}));
    versioned["options"]["versions"] = json!({ "drafts": false, "keep": 5 });
    let versions = format!("{}_versions", &LONG_TABLE[..54]);
    let other = format!("{versions}_archive");
    let refused = refusal(&doc(vec![versioned, model("Archive", &other, json!({}))]));
    assert!(
        refused.contains(&versions) && refused.contains(&other),
        "{refused}"
    );
}

#[test]
fn a_junction_and_a_table_cut_to_one_are_refused_naming_both() {
    let joined = format!("{LEFT}_{RIGHT}");
    let other = format!("{}_links", &joined[..63]);
    let tags = json!({ "notes": { "kind": "relation", "cardinality": "manyToMany",
                                  "target": "Note" } });
    let refused = refusal(&doc(vec![
        model("Tag", RIGHT, tags),
        model("Note", LEFT, json!({})),
        model("Link", &other, json!({})),
    ]));
    assert!(
        refused.contains(&joined) && refused.contains(&other),
        "{refused}"
    );
}

/// The generated client types and Studio's config name the table Postgres holds.
#[test]
fn generated_types_and_the_admin_config_name_the_kept_table() {
    let ast = long_junction();
    let joined = format!("{LEFT}_{RIGHT}");
    let generated = types::generate(&ast).expect("types generate");
    assert!(generated.contains(&joined[..63]), "{generated}");
    assert!(!generated.contains(&joined), "{generated}");

    let ast = parse(&doc(vec![model("Post", LONG_TABLE, json!({}))]));
    let config = admin::generate(&ast).expect("the admin config generates");
    let text = config.to_string();
    assert!(text.contains(&LONG_TABLE[..63]), "{text}");
    assert!(!text.contains(LONG_TABLE), "{text}");
}

// ── Against a database ────────────────────────────────────────────────────────

/// Pushes `ast` twice: the first applies it and the second finds nothing to do.
async fn push_twice(pool: &sqlx::PgPool, ast: &SchemaAst) {
    let outcome = common::push(pool, ast).await.expect("the push applies");
    assert!(
        matches!(outcome, push::Outcome::Applied { .. }),
        "{outcome:?}"
    );
    let again = common::push(pool, ast).await.expect("the second push runs");
    assert!(up_to_date(&again), "{again:?}");
}

/// The relations named `name` in `schema`.
async fn relations(pool: &sqlx::PgPool, schema: &str, name: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = $1 AND c.relname = $2",
    )
    .bind(schema)
    .bind(name)
    .fetch_one(pool)
    .await
    .expect("count relations")
}

#[tokio::test]
async fn a_table_named_past_the_limit_pushes_and_is_then_up_to_date() {
    common::with_integration_pool(|pool| async move {
        let ast = parse(&doc(vec![model("Post", LONG_TABLE, json!({}))]));
        push_twice(&pool, &ast).await;
        assert_eq!(relations(&pool, "public", &LONG_TABLE[..63]).await, 1);
    })
    .await;
}

#[tokio::test]
async fn a_multibyte_table_name_pushes_and_is_then_up_to_date() {
    common::with_integration_pool(|pool| async move {
        let table = "\u{e9}".repeat(40);
        let ast = parse(&doc(vec![model("Post", &table, json!({}))]));
        push_twice(&pool, &ast).await;
        assert_eq!(relations(&pool, "public", &"\u{e9}".repeat(31)).await, 1);
    })
    .await;
}

#[tokio::test]
async fn a_drafts_model_named_past_the_limit_pushes_with_its_versions_and_draft_view() {
    common::with_integration_pool(|pool| async move {
        push_twice(&pool, &long_drafts()).await;
        let versions = format!("{}_versions", &LONG_TABLE[..54]);
        assert_eq!(relations(&pool, "public", &versions).await, 1);
        assert_eq!(relations(&pool, "draft", &LONG_TABLE[..63]).await, 1);
    })
    .await;
}

#[tokio::test]
async fn a_junction_named_past_the_limit_pushes_and_is_then_up_to_date() {
    common::with_integration_pool(|pool| async move {
        push_twice(&pool, &long_junction()).await;
        let joined = format!("{LEFT}_{RIGHT}");
        assert_eq!(relations(&pool, "public", &joined[..63]).await, 1);
    })
    .await;
}

/// A relation from one long-named table to another: its key, its constraint (named from the
/// table) and its target all name the tables Postgres holds.
#[tokio::test]
async fn a_relation_between_tables_named_past_the_limit_pushes_and_is_then_up_to_date() {
    common::with_integration_pool(|pool| async move {
        let key = json!({ "note": { "kind": "relation", "cardinality": "belongsTo",
                                    "target": "Note", "onDelete": "cascade" } });
        let joined = format!("{LEFT}_{RIGHT}");
        let ast = parse(&doc(vec![
            model("Post", LONG_TABLE, key),
            model("Note", &joined, json!({})),
        ]));
        push_twice(&pool, &ast).await;
        let keys: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_constraint
              WHERE contype = 'f' AND conrelid = format('public.%I', $1::text)::regclass
                AND confrelid = format('public.%I', $2::text)::regclass",
        )
        .bind(&LONG_TABLE[..63])
        .bind(&joined[..63])
        .fetch_one(&pool)
        .await
        .expect("count foreign keys");
        assert_eq!(keys, 1);
    })
    .await;
}

/// Two models whose names agree well past 63 bytes give a junction two key columns Postgres
/// would keep as one.
#[test]
fn a_junction_whose_key_columns_cut_to_one_is_refused_naming_both() {
    let stem = "ConferenceAttendeeRegistrationDietaryPreferencesAndRequirement";
    let (a, b) = (format!("{stem}A"), format!("{stem}B"));
    let many = json!({ "others": { "kind": "relation", "cardinality": "manyToMany",
                                   "target": &b } });
    let refused = refusal(&doc(vec![
        model(&a, "first_side", many),
        model(&b, "second_side", json!({})),
    ]));
    assert!(
        refused.contains("_a_id") && refused.contains("_b_id"),
        "{refused}"
    );
}
