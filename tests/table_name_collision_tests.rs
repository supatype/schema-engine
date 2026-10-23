//! Two sources naming the same table.
//!
//! A schema makes tables from more than its models: a versioned model's snapshot table
//! (`posts_versions`) and a many-to-many's junction (`post_tag`, or its `through`). A model whose
//! own table carried one of those names was accepted, and the push then made one table for both,
//! so one source silently wrote into the other's rows. Each is refused when the schema is read,
//! naming both sources.

use serde_json::{json, Value};
use supatype_engine::parser;

fn id_field() -> Value {
    json!({ "kind": "uuid", "primaryKey": true, "required": true,
            "default": { "kind": "genRandomUuid" },
            "annotations": { "db": { "pgType": "UUID", "unique": false } } })
}

/// A model `name` stored in `table`, with `fields` besides its id, readable by anyone.
fn model(name: &str, table: &str, fields: Value) -> Value {
    let mut all = json!({ "id": id_field() });
    for (key, field) in fields.as_object().unwrap() {
        all[key] = field.clone();
    }
    json!({ "name": name, "fields": all,
            "options": { "timestamps": false, "softDelete": false },
            "annotations": { "db": { "tableName": table, "indexes": [] },
                             "platform": { "access": { "read": { "type": "public" } } } } })
}

fn versioned(name: &str, table: &str) -> Value {
    let mut versioned = model(name, table, json!({}));
    versioned["options"]["versions"] = json!({ "drafts": false, "keep": 5 });
    versioned
}

fn many_to_many(target: &str, through: Option<&str>) -> Value {
    let mut rel = json!({ "kind": "relation", "cardinality": "manyToMany", "target": target });
    if let Some(through) = through {
        rel["through"] = json!(through);
    }
    json!({ "links": rel })
}

fn refusal(models: Vec<Value>) -> String {
    let doc = json!({ "astVersion": 2, "models": models });
    parser::parse(&doc.to_string())
        .expect_err("the schema is refused")
        .to_string()
}

fn assert_names_both(refused: &str, sources: [&str; 2], table: &str) {
    for source in sources {
        assert!(refused.contains(source), "{source} not in: {refused}");
    }
    assert!(refused.contains(&format!("\"{table}\"")), "{refused}");
}

#[test]
fn a_model_table_named_like_another_models_versions_table_is_refused() {
    let refused = refusal(vec![
        versioned("Post", "posts"),
        model("PostArchive", "posts_versions", json!({})),
    ]);
    assert_names_both(&refused, ["'Post'", "'PostArchive'"], "posts_versions");
}

#[test]
fn a_model_table_named_like_a_derived_junction_is_refused() {
    let refused = refusal(vec![
        model("Post", "post", many_to_many("Tag", None)),
        model("Tag", "tag", json!({})),
        model("PostTag", "post_tag", json!({})),
    ]);
    assert_names_both(&refused, ["'PostTag'", "'Post' and 'Tag'"], "post_tag");
}

#[test]
fn a_model_table_named_like_a_through_junction_is_refused() {
    let refused = refusal(vec![
        model(
            "Student",
            "students",
            many_to_many("Course", Some("enrollments")),
        ),
        model("Course", "courses", json!({})),
        model("Enrollment", "enrollments", json!({})),
    ]);
    assert_names_both(
        &refused,
        ["'Enrollment'", "'Student' and 'Course'"],
        "enrollments",
    );
}

#[test]
fn a_junction_named_like_a_versions_table_is_refused() {
    let refused = refusal(vec![
        versioned("Post", "posts"),
        model("Tag", "tags", many_to_many("Post", Some("posts_versions"))),
    ]);
    assert_names_both(&refused, ["'Post'", "'Tag' and 'Post'"], "posts_versions");
}

#[test]
fn two_models_sharing_one_table_are_refused() {
    let refused = refusal(vec![
        model("Post", "posts", json!({})),
        model("Article", "posts", json!({})),
    ]);
    assert_names_both(&refused, ["'Post'", "'Article'"], "posts");
}

/// Both ends of one many-to-many name one junction: one table, not a clash.
#[test]
fn a_many_to_many_declared_from_both_ends_is_one_junction() {
    let doc = json!({ "astVersion": 2, "models": [
        model("Post", "post", many_to_many("Tag", None)),
        model("Tag", "tag", many_to_many("Post", None)),
    ] });
    let ast = parser::parse(&doc.to_string()).expect("one junction parses");
    assert_eq!(ast.junction_tables.len(), 1);
}
