//! The columns a Studio list shows, `listColumns` in `admin-config.json`.
//!
//! A list row has to say which record it is. The rule is the record's key first (the first key
//! column of a composite key), then the first two fields in declaration order that read in a table
//! cell, skipping any that do not (rich text, JSON, blocks, binary, arrays of objects, other bare
//! keys such as UUIDs and relation foreign keys) and taking the next one instead. A chat message
//! used to list only its room, so every message in the lobby read the same.

use serde_json::{json, Value};
use supatype_engine::generator::typescript::admin;
use supatype_engine::parser::v2::deserialize_schema;

fn list_columns(fields: Value, options: Value) -> Value {
    let ast = deserialize_schema(&json!({
        "astVersion": 2,
        "models": [
            { "name": "Thing", "fields": fields, "options": options },
            { "name": "Other", "fields": { "id": uuid_key() } },
        ],
    }))
    .unwrap();
    admin::generate(&ast).unwrap()["models"][0]["listColumns"].clone()
}

fn uuid_key() -> Value {
    json!({ "kind": "uuid", "required": true, "primaryKey": true, "default": { "kind": "genRandomUuid" } })
}

fn kind(kind: &str) -> Value {
    json!({ "kind": kind })
}

fn belongs_to(target: &str) -> Value {
    json!({ "kind": "relation", "cardinality": "belongsTo", "target": target })
}

#[test]
fn a_chat_message_lists_its_key_then_what_it_says() {
    let got = list_columns(
        json!({
            "id": uuid_key(),
            "room": kind("text"),
            "body": kind("text"),
            "authUser": belongs_to("Other"),
            "authorName": kind("text"),
            "created_at": kind("timestamp"),
        }),
        json!({}),
    );
    assert_eq!(got, json!(["id", "room", "body"]));
}

#[test]
fn fields_that_do_not_read_in_a_cell_are_skipped_for_the_next_one() {
    let got = list_columns(
        json!({
            "id": uuid_key(),
            "content": kind("richText"),
            "meta": kind("json"),
            "photo": kind("bytes"),
            "title": kind("text"),
            "rating": kind("integer"),
            "published": kind("boolean"),
            "views": kind("integer"),
        }),
        json!({}),
    );
    assert_eq!(got, json!(["id", "title", "rating"]));
}

#[test]
fn an_array_of_objects_is_skipped_and_an_array_of_words_is_not() {
    let objects = json!({ "kind": "array", "annotations": { "db": { "elementType": "JSONB" } } });
    let got = list_columns(
        json!({ "id": uuid_key(), "items": objects, "tags": kind("array") }),
        json!({}),
    );
    assert_eq!(got, json!(["id", "tags"]));
}

#[test]
fn timestamps_fill_the_list_where_they_are_declared() {
    let got = list_columns(
        json!({ "id": uuid_key(), "name": kind("text"), "timestamps": kind("timestamps") }),
        json!({}),
    );
    assert_eq!(got, json!(["id", "name", "created_at"]));
}

#[test]
fn a_model_with_nothing_to_show_lists_its_key() {
    let got = list_columns(json!({ "id": uuid_key(), "meta": kind("json") }), json!({}));
    assert_eq!(got, json!(["id"]));
}

#[test]
fn the_key_comes_first_even_when_declared_last() {
    let got = list_columns(
        json!({ "title": kind("text"), "rating": kind("integer"), "views": kind("integer"), "id": uuid_key() }),
        json!({}),
    );
    assert_eq!(got, json!(["id", "title", "rating"]));
}

#[test]
fn a_composite_key_shows_its_first_column() {
    let key = |k: &str| json!({ "kind": k, "required": true, "primaryKey": true });
    let got = list_columns(
        json!({ "tenant": key("text"), "code": key("text"), "label": kind("text"), "rank": kind("integer"), "note": kind("text") }),
        json!({}),
    );
    assert_eq!(got, json!(["tenant", "label", "rank"]));
}

#[test]
fn a_uuid_that_is_not_the_key_is_still_skipped() {
    let got = list_columns(
        json!({ "id": uuid_key(), "ref": kind("uuid"), "owner": belongs_to("Other"), "name": kind("text"), "size": kind("integer") }),
        json!({}),
    );
    assert_eq!(got, json!(["id", "name", "size"]));
}
