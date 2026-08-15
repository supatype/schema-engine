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
    // The point of the assertion is the column resolution — `author` becomes
    // `author_id`. The auth call is wrapped in a scalar subquery so the planner
    // evaluates it once per query, so match on the parts rather than one literal
    // rendering of them.
    let expr = access_rule_to_expr(&ast, post, rule, "public");
    // Columns are quoted so `qualify_bare_columns` can find them when the same
    // expression is reused inside a `can_*` affordance function.
    assert!(
        expr.contains("auth.uid()") && expr.ends_with("= \"author_id\""),
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

#[test]
fn owner_from_nested_relation_generates_exists_subquery() {
    let schema = r#"{
        "astVersion": 2,
        "models": [
            {
                "name": "Profile",
                "fields": {
                    "id": {
                        "kind": "uuid",
                        "primaryKey": true,
                        "required": true,
                        "annotations": { "db": { "pgType": "UUID" } }
                    }
                },
                "options": {},
                "annotations": {
                    "db": { "tableName": "profile", "indexes": [] },
                    "platform": { "access": {} }
                }
            },
            {
                "name": "Album",
                "fields": {
                    "id": {
                        "kind": "uuid",
                        "primaryKey": true,
                        "required": true,
                        "default": { "kind": "genRandomUuid" },
                        "annotations": { "db": { "pgType": "UUID" } }
                    },
                    "owner": {
                        "kind": "relation",
                        "cardinality": "belongsTo",
                        "target": "Profile",
                        "annotations": { "db": { "foreignKey": "owner_id" } }
                    }
                },
                "options": {},
                "annotations": {
                    "db": { "tableName": "album", "indexes": [] },
                    "platform": {
                        "access": {
                            "read": { "type": "owner", "field": "owner" }
                        }
                    }
                }
            },
            {
                "name": "Photo",
                "fields": {
                    "album": {
                        "kind": "relation",
                        "cardinality": "belongsTo",
                        "target": "Album",
                        "annotations": { "db": { "foreignKey": "album_id" } }
                    }
                },
                "options": {},
                "annotations": {
                    "db": { "tableName": "photo", "indexes": [] },
                    "platform": {
                        "access": {
                            "read": { "type": "owner", "field": "album" }
                        }
                    }
                }
            }
        ]
    }"#;

    let ast = parser::parse(schema).expect("schema must parse");
    let photo = ast
        .models
        .iter()
        .find(|m| m.name == "Photo")
        .expect("Photo model must exist");
    let rule = photo.access().read.as_ref().expect("read rule must exist");
    let expr = access_rule_to_expr(&ast, photo, rule, "public");
    assert!(
        expr.contains("EXISTS (SELECT 1 FROM \"album\""),
        "OwnerFrom<album> must check ownership via album table, got: {expr}"
    );
    assert!(
        expr.contains("owner_id"),
        "must compare album owner_id to auth.uid(), got: {expr}"
    );
    assert!(
        !expr.contains("auth.uid() = album_id"),
        "must not compare uid() directly to album_id, got: {expr}"
    );
}

#[test]
fn owner_rule_accepts_fk_column_name_and_normalizes_to_field_name() {
    // Users write Owner<"created_by_id"> (the FK column) instead of Owner<"created_by">
    // (the field name). The validator should accept the _id-suffix form and normalize it.
    let schema = r#"{
        "astVersion": 2,
        "models": [
            {
                "name": "Profile",
                "fields": {},
                "options": {},
                "annotations": {
                    "db": { "tableName": "profile", "indexes": [] },
                    "platform": { "access": {} }
                }
            },
            {
                "name": "Room",
                "fields": {
                    "created_by": {
                        "kind": "relation",
                        "cardinality": "belongsTo",
                        "target": "Profile",
                        "annotations": { "db": { "foreignKey": "created_by_id" } }
                    }
                },
                "options": {},
                "annotations": {
                    "db": { "tableName": "room", "indexes": [] },
                    "platform": {
                        "access": {
                            "read": { "type": "public" },
                            "create": { "type": "authenticated" },
                            "update": { "type": "owner", "field": "created_by_id" },
                            "delete": { "type": "owner", "field": "created_by_id" }
                        }
                    }
                }
            }
        ]
    }"#;

    let ast = parser::parse(schema).expect("schema must parse when FK column name used in Owner");
    let room = ast.models.iter().find(|m| m.name == "Room").unwrap();
    let update_rule = room
        .access()
        .update
        .as_ref()
        .expect("update rule must exist");
    let serialized = serde_json::to_string(update_rule).unwrap();
    assert!(
        serialized.contains("\"field\":\"created_by\""),
        "Owner field must be normalized from created_by_id to created_by, got: {serialized}"
    );
}

#[test]
fn owner_rule_fk_column_name_generates_correct_rls() {
    use supatype_engine::generator::sql::rls::access_rule_to_expr;

    let schema = r#"{
        "astVersion": 2,
        "models": [
            {
                "name": "Profile",
                "fields": {},
                "options": {},
                "annotations": {
                    "db": { "tableName": "profile", "indexes": [] },
                    "platform": { "access": {} }
                }
            },
            {
                "name": "Message",
                "fields": {
                    "author": {
                        "kind": "relation",
                        "cardinality": "belongsTo",
                        "target": "Profile",
                        "annotations": { "db": { "foreignKey": "author_id" } }
                    }
                },
                "options": {},
                "annotations": {
                    "db": { "tableName": "message", "indexes": [] },
                    "platform": {
                        "access": {
                            "read": { "type": "public" },
                            "create": { "type": "authenticated" },
                            "update": { "type": "owner", "field": "author_id" },
                            "delete": { "type": "owner", "field": "author_id" }
                        }
                    }
                }
            }
        ]
    }"#;

    let ast = parser::parse(schema).expect("schema with FK-column Owner must parse");
    let message = ast.models.iter().find(|m| m.name == "Message").unwrap();
    let delete_rule = message.access().delete.as_ref().expect("delete rule");
    let expr = access_rule_to_expr(&ast, message, delete_rule);
    assert!(
        expr.contains("auth.uid() = author_id"),
        "RLS must compare auth.uid() to the author_id FK column, got: {expr}"
    );
}
