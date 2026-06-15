use supatype_engine::generator::sql::rls::access_rule_to_expr;
use supatype_engine::parser;

#[test]
fn owner_rule_accepts_kernel_relation_field_name() {
    let schema = r#"{
        "astVersion": 2,
        "models": [
            {
                "name": "User",
                "fields": {
                    "email": {
                        "kind": "text",
                        "required": true,
                        "annotations": { "db": { "pgType": "TEXT", "unique": true } }
                    }
                },
                "options": {},
                "annotations": {
                    "db": { "tableName": "users", "indexes": [] },
                    "platform": { "access": {} }
                }
            },
            {
                "name": "Post",
                "fields": {
                    "author": {
                        "kind": "relation",
                        "cardinality": "belongsTo",
                        "target": "User",
                        "annotations": { "db": { "foreignKey": "author_id" } }
                    },
                    "title": {
                        "kind": "text",
                        "required": true,
                        "annotations": { "db": { "pgType": "TEXT" } }
                    }
                },
                "options": {},
                "annotations": {
                    "db": { "tableName": "posts", "indexes": [] },
                    "platform": {
                        "access": {
                            "update": { "type": "owner", "field": "author" }
                        }
                    }
                }
            }
        ]
    }"#;

    let ast = parser::parse(schema).expect("schema must parse");
    let post = ast
        .models
        .iter()
        .find(|m| m.name == "Post")
        .expect("Post model must exist");
    let rule = post
        .access()
        .update
        .as_ref()
        .expect("update rule must exist");
    let serialized = serde_json::to_string(rule).expect("rule must serialize");
    assert!(
        serialized.contains("\"field\":\"author\""),
        "owner field should keep kernel name author, got: {serialized}"
    );
    let expr = access_rule_to_expr(post, rule);
    assert!(
        expr.contains("auth.uid() = author_id"),
        "RLS should resolve author to author_id column, got: {expr}"
    );
}

#[test]
fn owner_rule_rejects_non_relation_fields_with_actionable_message() {
    let schema = r#"{
        "astVersion": 2,
        "models": [
            {
                "name": "Post",
                "fields": {
                    "title": {
                        "kind": "text",
                        "required": true,
                        "annotations": { "db": { "pgType": "TEXT" } }
                    }
                },
                "options": {},
                "annotations": {
                    "db": { "tableName": "posts", "indexes": [] },
                    "platform": {
                        "access": {
                            "update": { "type": "owner", "field": "title" }
                        }
                    }
                }
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
        message.contains("kernel field names"),
        "error should explain constraint, got: {message}"
    );
}

#[test]
fn owner_rule_allows_self_id_without_relations() {
    let schema = r#"{
        "astVersion": 2,
        "models": [
            {
                "name": "Todo",
                "fields": {
                    "title": {
                        "kind": "text",
                        "required": true,
                        "annotations": { "db": { "pgType": "TEXT" } }
                    }
                },
                "options": {},
                "annotations": {
                    "db": { "tableName": "todos", "indexes": [] },
                    "platform": {
                        "access": {
                            "update": { "type": "owner", "field": "id" }
                        }
                    }
                }
            }
        ]
    }"#;

    let ast = parser::parse(schema).expect("schema should accept self-id owner rule");
    let todo = ast
        .models
        .iter()
        .find(|m| m.name == "Todo")
        .expect("Todo model must exist");
    assert!(
        todo.access().update.is_some(),
        "update rule should be preserved"
    );
}
