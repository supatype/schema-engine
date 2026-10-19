//! The Studio widget for a `GeoPoint` field in `admin-config.json`.
//!
//! A point column used to get widget `"text"`, so Studio showed the column's hex EWKB and took
//! whatever was typed, which PostGIS either refused with a 500 or wrapped round the globe. A WGS 84
//! point now gets `"geopoint"`: latitude and longitude boxes with range checks. Any other geometry,
//! or a point in another SRID, keeps `"text"`, since latitude and longitude would not describe it.

use serde_json::{json, Value};
use supatype_engine::generator::typescript::admin;
use supatype_engine::parser::v2::deserialize_schema;

fn widget_of(field: Value) -> String {
    let ast = deserialize_schema(&json!({
        "astVersion": 2,
        "models": [{
            "name": "Room",
            "fields": { "location": field },
            "options": { "timestamps": false, "softDelete": false },
        }],
    }))
    .unwrap();
    let config = admin::generate(&ast).unwrap();
    let fields = config["models"][0]["fields"].as_array().unwrap().clone();
    let location = fields
        .iter()
        .find(|f| f["name"] == "location")
        .expect("location missing from admin config");
    location["widget"].as_str().unwrap().to_string()
}

#[test]
fn a_wgs84_point_is_edited_as_a_geopoint() {
    let field = json!({ "kind": "geo", "required": false, "geoType": "point", "srid": 4326 });
    assert_eq!(widget_of(field), "geopoint");
}

#[test]
fn a_point_with_no_srid_is_wgs84_and_a_geopoint() {
    // The migration writes GEOGRAPHY(POINT, 4326) when no SRID is given.
    let field = json!({ "kind": "geo", "required": true, "geoType": "point" });
    assert_eq!(widget_of(field), "geopoint");
}

#[test]
fn the_geo_type_is_matched_without_regard_to_case() {
    let field = json!({ "kind": "geo", "required": false, "geoType": "POINT", "srid": 4326 });
    assert_eq!(widget_of(field), "geopoint");
}

#[test]
fn other_geometries_keep_the_text_widget() {
    for geo_type in ["polygon", "linestring"] {
        let field = json!({ "kind": "geo", "required": false, "geoType": geo_type, "srid": 4326 });
        assert_eq!(widget_of(field), "text", "{geo_type}");
    }
}

#[test]
fn a_point_in_another_srid_keeps_the_text_widget() {
    let field = json!({ "kind": "geo", "required": false, "geoType": "point", "srid": 3857 });
    assert_eq!(widget_of(field), "text");
}
