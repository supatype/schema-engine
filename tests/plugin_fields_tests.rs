//! Plugin field types and composites, from the AST the CLI writes to the database and to Studio.
//!
//! A plugin field type's CHECK used to be dropped (the custom field had nowhere to hold one), and
//! Studio could not tell a plugin field or a composite's columns from any other, because the admin
//! config said `widget: "text"` and nothing else. These pin both: the check is a named bounds
//! constraint the ledger reconciles like any other, and the admin config names the plugin.

mod common;

use common::{applied, exec, push, up_to_date};
use serde_json::{json, Value};
use supatype_engine::generator::typescript::admin;
use supatype_engine::parser::v2::{deserialize_schema, serialize_schema};
use supatype_engine::parser::{self, ast::SchemaAst};

const PHONE_CHECK: &str = "\"{name}\" ~ '^\\+[0-9]{7,15}$'";

fn phone_field(check: Option<&str>) -> Value {
    let mut field = json!({
        "kind": "custom", "required": false,
        "plugin": "@supatype/plugin-phone-field", "fieldType": "phone", "tsType": "string",
        "annotations": { "db": { "pgType": "TEXT", "unique": false } }
    });
    if let Some(check) = check {
        field["check"] = json!(check);
    }
    field
}

fn seo_column(kind: &str, pg_type: &str) -> Value {
    json!({
        "kind": kind, "required": false,
        "annotations": {
            "db": { "pgType": pg_type, "unique": false },
            "platform": { "composite": {
                "plugin": "@supatype/plugin-seo", "name": "seo", "label": "SEO Meta",
                "collapsible": true, "defaultCollapsed": true
            } }
        }
    })
}

fn schema_doc(phone_check: Option<&str>) -> Value {
    json!({
        "astVersion": 2,
        "models": [{
            "name": "Contact",
            "fields": {
                "id": { "kind": "integer", "primaryKey": true, "required": true,
                        "annotations": { "db": { "pgType": "INTEGER", "unique": false } } },
                "phone": phone_field(phone_check),
                "meta_title": seo_column("text", "TEXT"),
                "no_index": seo_column("boolean", "BOOLEAN")
            },
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": { "tableName": "contacts", "indexes": [] }, "platform": {} }
        }]
    })
}

fn schema(phone_check: Option<&str>) -> SchemaAst {
    parser::parse(&schema_doc(phone_check).to_string()).expect("fixture parses")
}

fn admin_model(ast: &SchemaAst) -> Value {
    admin::generate(ast).unwrap()["models"][0].clone()
}

fn admin_field(model: &Value, name: &str) -> Value {
    model["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == json!(name))
        .cloned()
        .unwrap()
}

#[test]
fn the_admin_config_names_a_plugin_field_and_keeps_its_built_in_editor() {
    let model = admin_model(&schema(None));
    let phone = admin_field(&model, "phone");
    assert_eq!(
        phone["widget"],
        json!("text"),
        "a Studio without plugin widgets still edits it"
    );
    assert_eq!(
        phone["plugin"],
        json!({ "plugin": "@supatype/plugin-phone-field", "fieldType": "phone" })
    );
    assert!(admin_field(&model, "meta_title").get("plugin").is_none());
}

#[test]
fn a_required_plugin_field_is_required_in_studio_as_its_column_is_not_null() {
    let mut doc = schema_doc(None);
    doc["models"][0]["fields"]["phone"]["required"] = json!(true);
    let ast = parser::parse(&doc.to_string()).expect("fixture parses");
    assert_eq!(
        admin_field(&admin_model(&ast), "phone")["required"],
        json!(true)
    );
    assert_eq!(
        admin_field(&admin_model(&schema(None)), "phone")["required"],
        json!(false)
    );
}

#[test]
fn the_admin_config_groups_a_composites_columns_in_declaration_order() {
    let model = admin_model(&schema(None));
    assert_eq!(
        model["compositeGroups"],
        json!([{
            "plugin": "@supatype/plugin-seo", "composite": "seo",
            "label": "SEO Meta", "collapsible": true, "defaultCollapsed": true,
            "fields": ["meta_title", "no_index"]
        }])
    );
}

#[test]
fn a_model_without_a_composite_has_no_composite_groups_key() {
    let ast = deserialize_schema(&json!({
        "astVersion": 2,
        "models": [{ "name": "Plain", "fields": {}, "options": {} }],
    }))
    .unwrap();
    assert!(admin_model(&ast).get("compositeGroups").is_none());
}

#[test]
fn a_plugin_fields_check_and_composite_membership_survive_the_ast_round_trip() {
    let again = deserialize_schema(&serialize_schema(&schema(Some(PHONE_CHECK)))).unwrap();
    let doc = serialize_schema(&again);
    let fields = &doc["models"][0]["fields"];
    assert_eq!(fields["phone"]["check"], json!(PHONE_CHECK));
    assert_eq!(
        fields["meta_title"]["annotations"]["platform"]["composite"]["name"],
        json!("seo")
    );
}

#[tokio::test]
async fn a_plugin_check_is_enforced_recorded_and_left_alone_on_a_second_push() {
    common::with_integration_pool(|pool| async move {
        let ast = schema(Some(PHONE_CHECK));
        assert!(applied(&push(&pool, &ast).await.unwrap()));

        exec(
            &pool,
            "INSERT INTO contacts (id, phone) VALUES (1, '+447700900123')",
        )
        .await
        .expect("a valid number is accepted");
        let refused = exec(
            &pool,
            "INSERT INTO contacts (id, phone) VALUES (2, '07700 900123')",
        )
        .await;
        assert!(
            refused.is_err(),
            "the plugin's check refuses a non-E.164 number"
        );

        let again = push(&pool, &ast).await.unwrap();
        assert!(up_to_date(&again), "{again:?}");
    })
    .await;
}

#[tokio::test]
async fn a_plugin_check_added_to_an_existing_column_is_created_and_one_removed_is_dropped() {
    common::with_integration_pool(|pool| async move {
        assert!(applied(&push(&pool, &schema(None)).await.unwrap()));
        assert!(applied(
            &push(&pool, &schema(Some(PHONE_CHECK))).await.unwrap()
        ));
        let refused = exec(&pool, "INSERT INTO contacts (id, phone) VALUES (3, 'nope')").await;
        assert!(
            refused.is_err(),
            "the check added on the second push is enforced"
        );

        assert!(applied(&push(&pool, &schema(None)).await.unwrap()));
        exec(&pool, "INSERT INTO contacts (id, phone) VALUES (4, 'nope')")
            .await
            .expect("the check the schema stopped asking for is gone");
    })
    .await;
}
