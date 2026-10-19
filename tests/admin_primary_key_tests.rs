//! A model's primary key in `admin-config.json`.
//!
//! Studio pages through a list with `order=...` and needs a unique last column so two rows with the
//! same sort value never swap places between pages. It used to assume `id`, which is wrong for a
//! model keyed on another column and incomplete for a composite key. These pin that the engine
//! names the key columns itself, in declaration order, and that the default sort of a model
//! without timestamps uses its real key rather than a column it may not have.

use serde_json::{json, Value};
use supatype_engine::generator::typescript::admin;
use supatype_engine::parser::v2::deserialize_schema;

fn model_with(fields: Value, options: Value) -> Value {
    let ast = deserialize_schema(&json!({
        "astVersion": 2,
        "models": [{ "name": "Thing", "fields": fields, "options": options }],
    }))
    .unwrap();
    admin::generate(&ast).unwrap()["models"][0].clone()
}

fn key(kind: &str) -> Value {
    json!({ "kind": kind, "required": true, "primaryKey": true })
}

#[test]
fn a_model_keyed_on_id_sends_id_as_its_primary_key() {
    let thing = model_with(json!({ "id": key("uuid") }), json!({}));
    assert_eq!(thing["primaryKey"], json!(["id"]));
}

#[test]
fn a_model_keyed_on_another_column_sends_that_column() {
    let thing = model_with(
        json!({ "code": key("text"), "title": { "kind": "text" } }),
        json!({}),
    );
    assert_eq!(thing["primaryKey"], json!(["code"]));
}

#[test]
fn a_composite_key_sends_every_column_in_declaration_order() {
    let thing = model_with(
        json!({ "tenant": key("uuid"), "slug": key("text") }),
        json!({}),
    );
    assert_eq!(thing["primaryKey"], json!(["tenant", "slug"]));
}

#[test]
fn a_model_without_timestamps_sorts_by_its_own_key_not_by_id() {
    let thing = model_with(json!({ "code": key("text") }), json!({}));
    assert_eq!(
        thing["defaultSort"],
        json!({ "field": "code", "direction": "desc" })
    );
}

#[test]
fn a_model_with_timestamps_still_sorts_newest_first() {
    let thing = model_with(json!({ "id": key("uuid") }), json!({ "timestamps": true }));
    assert_eq!(
        thing["defaultSort"],
        json!({ "field": "created_at", "direction": "desc" })
    );
}
