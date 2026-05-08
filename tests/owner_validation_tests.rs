use supatype_engine::parser;

#[test]
fn owner_rule_accepts_relation_fk_and_normalizes_camel_case() {
    let schema = r#"{
        "models": [
            {
                "name": "User",
                "tableName": "users",
                "fields": {
                    "email": { "kind": "text", "pgType": "TEXT", "required": true, "unique": true }
                },
                "access": {},
                "indexes": [],
                "options": {}
            },
            {
                "name": "Post",
                "tableName": "posts",
                "fields": {
                    "author": { "kind": "relation", "cardinality": "belongsTo", "target": "User", "onDelete": "cascade" },
                    "title": { "kind": "text", "pgType": "TEXT", "required": true, "unique": false }
                },
                "access": {
                    "update": { "type": "owner", "field": "authorId" }
                },
                "indexes": [],
                "options": {}
            }
        ]
    }"#;

    let ast = parser::parse(schema).expect("schema must parse");
    let post = ast
        .models
        .iter()
        .find(|m| m.name == "Post")
        .expect("Post model must exist");
    let rule = post.access.update.as_ref().expect("update rule must exist");
    let serialized = serde_json::to_string(rule).expect("rule must serialize");
    assert!(
        serialized.contains("\"field\":\"author_id\""),
        "owner field should normalize to author_id, got: {serialized}"
    );
}

#[test]
fn owner_rule_rejects_non_relation_fields_with_actionable_message() {
    let schema = r#"{
        "models": [
            {
                "name": "Post",
                "tableName": "posts",
                "fields": {
                    "title": { "kind": "text", "pgType": "TEXT", "required": true, "unique": false }
                },
                "access": {
                    "update": { "type": "owner", "field": "title" }
                },
                "indexes": [],
                "options": {}
            }
        ]
    }"#;

    let err = parser::parse(schema).expect_err("schema should fail owner validation");
    let message = err.to_string();
    assert!(
        message.contains("Owner<\"title\"> is invalid"),
        "error should mention invalid owner field, got: {message}"
    );
    assert!(
        message.contains("relation foreign keys"),
        "error should explain constraint, got: {message}"
    );
}

#[test]
fn owner_rule_allows_self_id_without_relations() {
    let schema = r#"{
        "models": [
            {
                "name": "Todo",
                "tableName": "todos",
                "fields": {
                    "title": { "kind": "text", "pgType": "TEXT", "required": true, "unique": false }
                },
                "access": {
                    "update": { "type": "owner", "field": "id" }
                },
                "indexes": [],
                "options": {}
            }
        ]
    }"#;

    let ast = parser::parse(schema).expect("schema should accept self-id owner rule");
    let todo = ast
        .models
        .iter()
        .find(|m| m.name == "Todo")
        .expect("Todo model must exist");
    assert!(todo.access.update.is_some(), "update rule should be preserved");
}
