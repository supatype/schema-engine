//! Model labels in `admin-config.json`.
//!
//! Studio derives a model's label from its type name, which is a guess: "Places of Interest" has
//! its noun first and no inflection rule finds it. A project can say the words itself in the model
//! meta, and these pin that the words reach Studio unchanged, and that leaving them out still sends
//! nothing Studio would mistake for an override.

use serde_json::{json, Value};
use supatype_engine::generator::typescript::admin;
use supatype_engine::parser::v2::deserialize_schema;

fn first_model(options: Value) -> Value {
    let ast = deserialize_schema(&json!({
        "astVersion": 2,
        "models": [{ "name": "PlacesOfInterest", "fields": {}, "options": options }],
    }))
    .unwrap();
    admin::generate(&ast).unwrap()["models"][0].clone()
}

#[test]
fn a_model_with_its_own_labels_carries_them_to_studio() {
    let places = first_model(json!({
        "label": "Place of Interest",
        "labelPlural": "Places of Interest",
    }));
    assert_eq!(places["label"], json!("Place of Interest"));
    assert_eq!(places["labelPlural"], json!("Places of Interest"));
}

#[test]
fn a_model_without_labels_sends_null_so_studio_derives_them() {
    let places = first_model(json!({}));
    assert!(places["label"].is_null(), "got {}", places["label"]);
    assert!(
        places["labelPlural"].is_null(),
        "got {}",
        places["labelPlural"]
    );
}
