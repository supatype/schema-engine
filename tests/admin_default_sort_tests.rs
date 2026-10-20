//! The order a Studio list opens in, `defaultSort` in `admin-config.json`.
//!
//! Newest first is the order people expect of a list, and the engine can only send it when it can
//! tell which column grows over time. These pin each rule in the order the generator tries them,
//! and a golden over every fixture records the order each fixture's models open in, so a change to
//! the rules is a diff a reviewer reads. Studio appends every key column as a tie-breaker itself, so
//! the engine sends only the primary sort.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use supatype_engine::generator::typescript::admin;
use supatype_engine::parser::{self, v2::deserialize_schema};

fn default_sort(fields: Value, options: Value) -> Value {
    default_sort_annotated(fields, options, json!({}))
}

fn default_sort_annotated(fields: Value, options: Value, annotations: Value) -> Value {
    let ast = deserialize_schema(&json!({
        "astVersion": 2,
        "models": [{
            "name": "Thing",
            "fields": fields,
            "options": options,
            "annotations": annotations,
        }],
    }))
    .unwrap();
    admin::generate(&ast).unwrap()["models"][0]["defaultSort"].clone()
}

fn sort(field: &str, direction: &str) -> Value {
    json!({ "field": field, "direction": direction })
}

fn uuid_key() -> Value {
    json!({ "kind": "uuid", "required": true, "primaryKey": true, "default": { "kind": "genRandomUuid" } })
}

fn kind(kind: &str) -> Value {
    json!({ "kind": kind })
}

fn now_default(kind: &str) -> Value {
    json!({ "kind": kind, "default": { "kind": "now" } })
}

fn key_with_expression_default(kind: &str, expr: &str) -> Value {
    json!({
        "kind": kind,
        "required": true,
        "primaryKey": true,
        "default": { "kind": "expression", "expr": expr },
    })
}

// ─── Rule 1: the `timestamps` option ──────────────────────────────────────────

#[test]
fn timestamps_sort_newest_first_even_beside_a_creation_field() {
    let got = default_sort(
        json!({ "id": uuid_key(), "inserted_at": now_default("datetime") }),
        json!({ "timestamps": true }),
    );
    assert_eq!(got, sort("created_at", "desc"));
}

// ─── Rule 2: a field that records creation ────────────────────────────────────

#[test]
fn a_timestamp_named_created_at_sorts_newest_first() {
    let got = default_sort(
        json!({ "id": uuid_key(), "body": kind("text"), "created_at": kind("timestamp") }),
        json!({}),
    );
    assert_eq!(got, sort("created_at", "desc"));
}

#[test]
fn camel_case_and_inserted_names_count_as_creation_fields() {
    for name in ["createdAt", "inserted_at", "insertedAt"] {
        let got = default_sort(
            json!({ "id": uuid_key(), "title": kind("text"), name: kind("datetime") }),
            json!({}),
        );
        assert_eq!(got, sort(name, "desc"), "{name}");
    }
}

#[test]
fn a_creation_name_beats_an_earlier_now_default() {
    let got = default_sort(
        json!({
            "id": uuid_key(),
            "seen_at": now_default("datetime"),
            "created_at": kind("timestamp"),
        }),
        json!({}),
    );
    assert_eq!(got, sort("created_at", "desc"));
}

#[test]
fn a_date_time_field_defaulting_to_now_sorts_newest_first() {
    let got = default_sort(
        json!({ "id": uuid_key(), "title": kind("text"), "posted": now_default("datetime") }),
        json!({}),
    );
    assert_eq!(got, sort("posted", "desc"));
}

#[test]
fn a_now_expression_default_counts_as_now() {
    let got = default_sort(
        json!({
            "id": uuid_key(),
            "title": kind("text"),
            "logged": { "kind": "timestamp", "default": { "kind": "expression", "expr": "CURRENT_TIMESTAMP" } },
        }),
        json!({}),
    );
    assert_eq!(got, sort("logged", "desc"));
}

#[test]
fn a_creation_name_on_a_non_date_time_column_is_not_a_creation_field() {
    // A `created_at` stored as text sorts as text, which is not time order.
    let got = default_sort(
        json!({ "id": uuid_key(), "created_at": kind("text") }),
        json!({}),
    );
    assert_eq!(
        got,
        sort("created_at", "asc"),
        "falls to rule 4, not rule 2"
    );
}

// ─── Rule 3: a key that grows over time ───────────────────────────────────────

#[test]
fn a_serial_key_sorts_newest_first() {
    for k in ["serial", "bigSerial"] {
        let got = default_sort(
            json!({ "num": { "kind": k, "required": true, "primaryKey": true }, "title": kind("text") }),
            json!({}),
        );
        assert_eq!(got, sort("num", "desc"), "{k}");
    }
}

#[test]
fn an_identity_key_sorts_newest_first() {
    let got = default_sort(
        json!({
            "num": { "kind": "bigInt", "required": true, "primaryKey": true, "identity": "always" },
            "title": kind("text"),
        }),
        json!({}),
    );
    assert_eq!(got, sort("num", "desc"));
}

#[test]
fn an_integer_key_drawn_from_a_sequence_sorts_newest_first() {
    let got = default_sort(
        json!({
            "num": key_with_expression_default("integer", "nextval('things_num_seq'::regclass)"),
            "title": kind("text"),
        }),
        json!({}),
    );
    assert_eq!(got, sort("num", "desc"));
}

#[test]
fn a_uuid_v7_key_sorts_newest_first() {
    for expr in ["uuidv7()", "uuid_generate_v7()"] {
        let got = default_sort(
            json!({ "id": key_with_expression_default("uuid", expr), "title": kind("text") }),
            json!({}),
        );
        assert_eq!(got, sort("id", "desc"), "{expr}");
    }
}

// ─── Rule 4: a key with no order, so the first searchable text column ─────────

#[test]
fn a_random_uuid_key_sorts_by_the_first_text_column_ascending() {
    let got = default_sort(
        json!({ "id": uuid_key(), "count": kind("integer"), "name": kind("text"), "note": kind("text") }),
        json!({}),
    );
    assert_eq!(got, sort("name", "asc"));
}

#[test]
fn a_declared_search_field_is_the_title_the_list_sorts_by() {
    let got = default_sort_annotated(
        json!({ "id": uuid_key(), "summary": kind("text"), "headline": kind("text") }),
        json!({}),
        json!({ "platform": { "searchFields": ["headline", "summary"] } }),
    );
    assert_eq!(got, sort("headline", "asc"));
}

#[test]
fn a_localized_text_column_is_not_a_sort_column() {
    let got = default_sort(
        json!({
            "id": uuid_key(),
            "title": { "kind": "text", "localized": true },
            "code": kind("text"),
        }),
        json!({}),
    );
    assert_eq!(got, sort("code", "asc"));
}

#[test]
fn a_text_key_sorts_by_the_first_text_column_ascending() {
    let got = default_sort(
        json!({ "code": { "kind": "text", "required": true, "primaryKey": true }, "title": kind("text") }),
        json!({}),
    );
    assert_eq!(got, sort("code", "asc"));
}

#[test]
fn with_nothing_to_go_on_the_key_sorts_descending() {
    let got = default_sort(
        json!({ "id": uuid_key(), "count": kind("integer") }),
        json!({}),
    );
    assert_eq!(got, sort("id", "desc"));
}

// ─── Golden: every fixture's models ───────────────────────────────────────────

/// Every fixture the current parser accepts, as `golden_tests` lists them.
const FIXTURES: &[&str] = &[
    "basic_blog",
    "cms_content",
    "conformance_matrix",
    "ecommerce",
    "five_model_blog",
    "geospatial",
    "kitchen_sink",
    "kitchen_sink_example",
    "many_to_many",
    "rls_access_rules",
    "rls_field_rules",
    "self_referential",
    "standup_relations",
    "vector_search",
    "versioned_blog",
];

fn tests_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// Each model's `defaultSort`, keyed by table.
fn fixture_sorts(name: &str) -> Value {
    let path = tests_dir().join("fixtures").join(format!("{name}.json"));
    let source =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let ast = parser::parse(&source).unwrap_or_else(|e| panic!("{name} parses: {e}"));
    let config = admin::generate(&ast).unwrap_or_else(|e| panic!("{name} generates: {e}"));
    let sorts: Map<String, Value> = config["models"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|model| {
            let table = model["tableName"]
                .as_str()
                .expect("a model has a table name");
            (table.to_string(), model["defaultSort"].clone())
        })
        .collect();
    Value::Object(sorts)
}

#[test]
fn every_fixture_opens_in_its_golden_order() {
    let all: Map<String, Value> = FIXTURES
        .iter()
        .map(|name| ((*name).to_string(), fixture_sorts(name)))
        .collect();
    let actual = format!(
        "{}\n",
        serde_json::to_string_pretty(&Value::Object(all)).unwrap()
    );
    let path = tests_dir().join("golden").join("admin_default_sort.json");
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        fs::write(&path, &actual).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        return;
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|e| {
            panic!(
                "no golden at {} ({e}); run with UPDATE_GOLDEN=1",
                path.display()
            )
        })
        .replace("\r\n", "\n");
    assert!(
        expected == actual,
        "default sorts differ from {}. If intended, run with UPDATE_GOLDEN=1 and review the diff.\n{actual}",
        path.display()
    );
}
