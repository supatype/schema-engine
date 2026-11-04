//! A field's `Default<>` reaches the column it creates, whatever kind the field is (issue 17).
//!
//! Only the scalar kinds read `default` from the AST. JSON, button, decimal, geo and vector fields
//! dropped it without a word, so `Default<JSON<string[]>, "[]">` created `options jsonb NOT NULL`
//! with no DEFAULT and every insert that left the column out failed. A kind with nowhere sensible
//! to put a default now refuses the AST instead of dropping it.

use serde_json::{json, Value};
use supatype_engine::{parser, push};

/// A schema of one model, `fd_form`, whose `options` field is `field`.
fn schema(field: Value) -> String {
    json!({
        "astVersion": 2,
        "models": [{
            "name": "Form",
            "fields": {
                "id": { "kind": "uuid", "primaryKey": true, "required": true,
                        "default": { "kind": "genRandomUuid" },
                        "annotations": { "db": { "pgType": "UUID", "unique": false } } },
                "title": { "kind": "text", "required": true,
                           "annotations": { "db": { "pgType": "TEXT", "unique": false } } },
                "options": field
            },
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": { "tableName": "fd_form", "indexes": [] },
                             "platform": { "access": { "read": { "type": "public" } } } }
        }]
    })
    .to_string()
}

fn with_default(mut field: Value, default: Value) -> Value {
    field["default"] = default;
    field
}

fn value(v: Value) -> Value {
    json!({ "kind": "value", "value": v })
}

fn json_field() -> Value {
    json!({ "kind": "json", "required": true, "jsonArray": true,
            "annotations": { "db": { "pgType": "JSONB", "unique": false } } })
}

/// The migration a fresh push of `field` writes.
fn create_table(field: Value) -> String {
    let ast = parser::parse(&schema(field)).expect("the schema parses");
    push::fresh_migration(&ast, "public", false)
        .expect("the schema renders")
        .up_script()
}

fn parse_error(field: Value) -> String {
    match parser::parse(&schema(field)) {
        Ok(_) => panic!("the schema parsed, but it should have been refused"),
        Err(e) => format!("{e:#}"),
    }
}

/// The issue as reported: the CLI's AST for `Default<JSON<string[]>, "[]">`.
#[test]
fn a_json_default_reaches_the_created_column() {
    let sql = create_table(with_default(json_field(), value(json!("[]"))));
    assert!(
        sql.contains(r#""options" JSONB NOT NULL DEFAULT '[]'::jsonb"#),
        "{sql}"
    );
}

/// A default that is not a string is JSON already, and is written as its JSON text.
#[test]
fn a_json_default_that_is_not_a_string_is_written_as_json() {
    let sql = create_table(with_default(json_field(), value(json!(0))));
    assert!(
        sql.contains(r#""options" JSONB NOT NULL DEFAULT '0'::jsonb"#),
        "{sql}"
    );
}

/// A quote in the JSON text is doubled, so it cannot end the literal.
#[test]
fn a_quote_in_a_json_default_is_escaped() {
    let sql = create_table(with_default(
        json_field(),
        value(json!(r#"{"note":"it's"}"#)),
    ));
    assert!(
        sql.contains(r#"DEFAULT '{"note":"it''s"}'::jsonb"#),
        "{sql}"
    );
}

/// `Default<string, "it's">`: the same for a text column.
#[test]
fn a_quote_in_a_text_default_is_escaped() {
    let text = json!({ "kind": "text", "required": false,
                       "annotations": { "db": { "pgType": "TEXT", "unique": false } } });
    let sql = create_table(with_default(text, value(json!("it's"))));
    assert!(sql.contains(r#""options" TEXT DEFAULT 'it''s'"#), "{sql}");
}

/// JSON text that does not parse would fail the push with a cast error naming no field: refused
/// while the schema is read instead, with the field's text in the message.
#[test]
fn a_json_default_that_does_not_parse_is_refused() {
    let err = parse_error(with_default(json_field(), value(json!("[1, 2"))));
    assert!(err.contains("not valid JSON"), "{err}");
    assert!(err.contains("[1, 2"), "{err}");
}

/// `now()` and `gen_random_uuid()` are not JSON.
#[test]
fn a_generated_json_default_is_refused() {
    let err = parse_error(with_default(json_field(), json!({ "kind": "now" })));
    assert!(err.contains("JSON"), "{err}");
}

#[test]
fn a_decimal_default_reaches_the_created_column() {
    let decimal = json!({ "kind": "decimal", "required": true, "precision": 10, "scale": 2,
                          "annotations": { "db": { "pgType": "NUMERIC", "unique": false } } });
    let sql = create_table(with_default(decimal, value(json!(0))));
    assert!(
        sql.contains(r#""options" NUMERIC(10, 2) NOT NULL DEFAULT 0"#),
        "{sql}"
    );
}

#[test]
fn an_array_default_reaches_the_created_column() {
    let array = json!({ "kind": "array", "required": true,
                        "annotations": { "db": { "pgType": "TEXT[]", "elementType": "TEXT",
                                                 "unique": false } } });
    let sql = create_table(with_default(array, value(json!("{}"))));
    assert!(
        sql.contains(r#""options" TEXT[] NOT NULL DEFAULT '{}'"#),
        "{sql}"
    );
}

#[test]
fn a_vector_default_reaches_the_created_column() {
    let vector = json!({ "kind": "vector", "required": false, "dimensions": 3,
                         "annotations": { "db": { "pgType": "VECTOR(3)", "unique": false } } });
    let sql = create_table(with_default(vector, value(json!("[0,0,0]"))));
    assert!(
        sql.contains(r#""options" vector(3) DEFAULT '[0,0,0]'"#),
        "{sql}"
    );
}

#[test]
fn a_geo_default_reaches_the_created_column() {
    let geo = json!({ "kind": "geo", "required": false, "geoType": "point",
                      "annotations": { "db": { "pgType": "GEOGRAPHY", "unique": false } } });
    let sql = create_table(with_default(geo, value(json!("SRID=4326;POINT(0 0)"))));
    assert!(
        sql.contains(
            r#""options" GEOGRAPHY(POINT, 4326) DEFAULT ST_GeogFromText('SRID=4326;POINT(0 0)')"#
        ),
        "{sql}"
    );
}

/// A slug is filled from its source only while it is empty, so a default would stop it ever being
/// generated. Refused rather than dropped.
#[test]
fn a_slug_default_is_refused() {
    let slug = json!({ "kind": "slug", "required": true, "from": "title",
                       "annotations": { "db": { "pgType": "TEXT", "unique": true } } });
    let err = parse_error(with_default(slug, value(json!("untitled"))));
    assert!(err.contains("'slug'"), "{err}");
    assert!(err.contains("default"), "{err}");
}

/// A storage reference names an object that was uploaded, which a schema cannot know in advance.
#[test]
fn an_image_default_is_refused() {
    let image = json!({ "kind": "image", "required": false, "bucket": "covers",
                        "annotations": { "db": { "pgType": "JSONB", "unique": false } } });
    let err = parse_error(with_default(image, value(json!("{}"))));
    assert!(err.contains("'image'"), "{err}");
}

/// A JSON column with a default may be left out of an insert, so its `Insert` key is optional.
#[test]
fn a_json_default_makes_the_insert_key_optional() {
    let ast = parser::parse(&schema(with_default(json_field(), value(json!("[]")))))
        .expect("the schema parses");
    let ts = supatype_engine::generator::typescript::types::generate(&ast).expect("types");
    let insert = ts
        .split("Insert")
        .nth(1)
        .unwrap_or_else(|| panic!("no Insert type in {ts}"));
    let insert = insert.split('}').next().unwrap_or_default();
    assert!(insert.contains("options?:"), "{insert}");
}
