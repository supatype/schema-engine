use crate::parser::ast::{FieldAst, RelationCardinality, SchemaAst};
use anyhow::Result;
use serde_json::{json, Value};

/// Generate an OpenAPI 3.0 specification from the schema AST.
///
/// The output follows the PostgREST-compatible REST convention:
///   GET    /{table}      — list records
///   POST   /{table}      — create record
///   GET    /{table}/{id} — get single record
///   PATCH  /{table}/{id} — update record
///   DELETE /{table}/{id} — delete record
///
/// Components.schemas contains a JSON Schema for each model.
pub fn generate(ast: &SchemaAst) -> Result<Value> {
    let mut paths: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut schemas: serde_json::Map<String, Value> = serde_json::Map::new();

    for model in &ast.models {
        let table = &model.table_name();
        let schema_name = &model.name;

        // ─── Component schema ─────────────────────────────────────────────────
        let schema = build_model_schema(model);
        schemas.insert(schema_name.clone(), schema);

        // ─── List + create path ───────────────────────────────────────────────
        let collection_path = format!("/{table}");
        let collection_ops = json!({
            "get": {
                "summary": format!("List {}", model.name),
                "operationId": format!("list_{table}"),
                "tags": [model.name],
                "parameters": [
                    { "name": "limit", "in": "query", "schema": { "type": "integer" } },
                    { "name": "offset", "in": "query", "schema": { "type": "integer" } },
                    { "name": "order", "in": "query", "schema": { "type": "string" } },
                ],
                "responses": {
                    "200": {
                        "description": format!("Array of {}", model.name),
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": { "$ref": format!("#/components/schemas/{schema_name}") }
                                }
                            }
                        }
                    }
                }
            },
            "post": {
                "summary": format!("Create {}", model.name),
                "operationId": format!("create_{table}"),
                "tags": [model.name],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": { "$ref": format!("#/components/schemas/{schema_name}") }
                        }
                    }
                },
                "responses": {
                    "201": {
                        "description": format!("Created {}", model.name),
                        "content": {
                            "application/json": {
                                "schema": { "$ref": format!("#/components/schemas/{schema_name}") }
                            }
                        }
                    }
                }
            }
        });
        paths.insert(collection_path, collection_ops);

        // ─── Single record path ───────────────────────────────────────────────
        let item_path = format!("/{table}/{{id}}");
        let item_ops = json!({
            "get": {
                "summary": format!("Get {} by ID", model.name),
                "operationId": format!("get_{table}_by_id"),
                "tags": [model.name],
                "parameters": [
                    { "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
                ],
                "responses": {
                    "200": {
                        "description": model.name,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": format!("#/components/schemas/{schema_name}") }
                            }
                        }
                    },
                    "404": { "description": "Not found" }
                }
            },
            "patch": {
                "summary": format!("Update {}", model.name),
                "operationId": format!("update_{table}"),
                "tags": [model.name],
                "parameters": [
                    { "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
                ],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": { "$ref": format!("#/components/schemas/{schema_name}") }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": format!("Updated {}", model.name),
                        "content": {
                            "application/json": {
                                "schema": { "$ref": format!("#/components/schemas/{schema_name}") }
                            }
                        }
                    }
                }
            },
            "delete": {
                "summary": format!("Delete {}", model.name),
                "operationId": format!("delete_{table}"),
                "tags": [model.name],
                "parameters": [
                    { "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
                ],
                "responses": {
                    "204": { "description": "Deleted" }
                }
            }
        });
        paths.insert(item_path, item_ops);
    }

    Ok(json!({
        "openapi": "3.0.0",
        "info": {
            "title": "Supatype API",
            "version": "1.0.0",
            "description": "Auto-generated API documentation from Supatype schema"
        },
        "paths": paths,
        "components": {
            "schemas": schemas,
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
        },
        "security": [{ "BearerAuth": [] }]
    }))
}

// ─── Schema builder ───────────────────────────────────────────────────────────

fn build_model_schema(model: &crate::parser::ast::ModelAst) -> Value {
    let mut properties: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut required_fields: Vec<String> = Vec::new();

    for (name, field) in &model.fields {
        // Skip composite/virtual fields that expand at SQL level
        match field {
            FieldAst::Timestamps => {
                properties.insert(
                    "created_at".into(),
                    json!({ "type": "string", "format": "date-time", "readOnly": true }),
                );
                properties.insert(
                    "updated_at".into(),
                    json!({ "type": "string", "format": "date-time", "readOnly": true }),
                );
                continue;
            }
            FieldAst::Publishable => {
                properties.insert(
                    "status".into(),
                    json!({
                        "type": "string",
                        "enum": ["draft", "published", "scheduled", "archived"]
                    }),
                );
                properties.insert(
                    "published_at".into(),
                    json!({ "type": "string", "format": "date-time", "nullable": true }),
                );
                properties.insert(
                    "scheduled_at".into(),
                    json!({ "type": "string", "format": "date-time", "nullable": true }),
                );
                continue;
            }
            FieldAst::SoftDelete => {
                properties.insert(
                    "deleted_at".into(),
                    json!({ "type": "string", "format": "date-time", "nullable": true }),
                );
                continue;
            }
            FieldAst::Relation(rel) => {
                // Only BelongsTo owns a column here, and this must agree with the migration
                // generator or the document describes a table that does not exist. It used to
                // include HasOne, which `generator/sql/migration.rs` explicitly does not emit a
                // column for — HasOne is the *inverse* side, and the foreign key (with its UNIQUE)
                // belongs to whichever model declares the RelatedTo. So the spec advertised an
                // `<name>_id` that was never created, and a client generated from it sent a column
                // PostgREST rejects.
                match rel.cardinality {
                    RelationCardinality::BelongsTo => {
                        let fk_default = format!("{name}_id");
                        let fk_col = rel.foreign_key.as_deref().unwrap_or(&fk_default);
                        properties.insert(
                            fk_col.to_string(),
                            json!({
                                "type": "string",
                                "format": "uuid",
                                "nullable": true,
                                "description": format!("FK -> {}", rel.target)
                            }),
                        );
                    }
                    _ => {} // HasOne / HasMany / ManyToMany hold no column on this table
                }
                continue;
            }
            _ => {}
        }

        let prop = field_to_schema(field);
        let is_required = field_is_required(field);
        properties.insert(name.clone(), prop);
        if is_required {
            required_fields.push(name.clone());
        }
    }

    let mut schema = json!({
        "type": "object",
        "properties": properties,
    });

    if !required_fields.is_empty() {
        schema["required"] = json!(required_fields);
    }

    schema
}

fn field_to_schema(field: &FieldAst) -> Value {
    match field {
        FieldAst::Text(_)
        | FieldAst::RichText(_)
        | FieldAst::Url(_)
        | FieldAst::Xml(_)
        | FieldAst::Ip(_)
        | FieldAst::Cidr(_)
        | FieldAst::Macaddr(_)
        | FieldAst::Interval(_)
        | FieldAst::TsQuery(_)
        | FieldAst::TsVector(_)
        | FieldAst::Bytes(_) => {
            json!({ "type": "string" })
        }
        FieldAst::Email(_) => json!({ "type": "string", "format": "email" }),
        FieldAst::Slug(_) => json!({ "type": "string", "pattern": "^[a-z0-9-]+$" }),
        FieldAst::Uuid(_) => json!({ "type": "string", "format": "uuid" }),
        FieldAst::Integer(_) | FieldAst::SmallInt(_) | FieldAst::Serial(_) => {
            json!({ "type": "integer", "format": "int32" })
        }
        FieldAst::BigInt(_) | FieldAst::BigSerial(_) => {
            json!({ "type": "integer", "format": "int64" })
        }
        FieldAst::Float(_) | FieldAst::Decimal(_) | FieldAst::Money(_) => {
            json!({ "type": "number" })
        }
        FieldAst::Boolean(_) => json!({ "type": "boolean" }),
        FieldAst::Datetime(_) | FieldAst::Timestamp(_) => {
            json!({ "type": "string", "format": "date-time" })
        }
        FieldAst::Date(_) => json!({ "type": "string", "format": "date" }),
        FieldAst::Enum(e) => json!({
            "type": "string",
            "enum": e.values,
        }),
        FieldAst::Json(_) | FieldAst::Image(_) | FieldAst::File(_) => {
            json!({ "type": "object" })
        }
        FieldAst::Geo(_) => json!({
            "type": "object",
            "description": "GeoJSON geometry"
        }),
        FieldAst::Vector(v) => json!({
            "type": "array",
            "items": { "type": "number" },
            "description": format!("Vector({} dimensions)", v.dimensions)
        }),
        FieldAst::Blocks(_) => json!({
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": { "type": "string" },
                    "data": { "type": "object" }
                }
            }
        }),
        FieldAst::Array(a) => json!({
            "type": "array",
            "items": { "type": array_element_openapi_type(&a.element_type) }
        }),
        // Custom plugin field — emit the ts_type as a description hint; fall back to string type
        FieldAst::Custom(c) => json!({
            "type": "string",
            "description": format!("Custom field type '{}' from plugin '{}'", c.field_type, c.plugin),
            "x-supatype-plugin": c.plugin,
            "x-supatype-field-type": c.field_type,
        }),
        _ => json!({ "type": "string" }),
    }
}

fn array_element_openapi_type(element_type: &str) -> &'static str {
    match element_type.to_uppercase().as_str() {
        "INTEGER" | "INT" | "INT4" | "SMALLINT" | "BIGINT" => "integer",
        "FLOAT" | "FLOAT8" | "NUMERIC" | "DECIMAL" => "number",
        "BOOLEAN" | "BOOL" => "boolean",
        _ => "string",
    }
}

fn field_is_required(field: &FieldAst) -> bool {
    match field {
        FieldAst::Text(f)
        | FieldAst::RichText(f)
        | FieldAst::Integer(f)
        | FieldAst::Float(f)
        | FieldAst::Boolean(f)
        | FieldAst::Datetime(f)
        | FieldAst::Uuid(f)
        | FieldAst::Email(f)
        | FieldAst::BigInt(f)
        | FieldAst::Bytes(f)
        | FieldAst::SmallInt(f)
        | FieldAst::Date(f)
        | FieldAst::Timestamp(f)
        | FieldAst::Serial(f)
        | FieldAst::BigSerial(f)
        | FieldAst::Money(f)
        | FieldAst::Url(f)
        | FieldAst::Ip(f)
        | FieldAst::Cidr(f)
        | FieldAst::Macaddr(f)
        | FieldAst::Interval(f)
        | FieldAst::TsQuery(f)
        | FieldAst::TsVector(f)
        | FieldAst::Xml(f) => f.required,
        FieldAst::Slug(f) => f.required,
        FieldAst::Enum(f) => f.required,
        FieldAst::Json(f) => f.required,
        FieldAst::Decimal(f) => f.required,
        FieldAst::Image(f) | FieldAst::File(f) => f.required,
        FieldAst::Geo(f) => f.required,
        FieldAst::Vector(f) => f.required,
        FieldAst::Blocks(f) => f.required,
        FieldAst::Custom(f) => f.required,
        _ => false,
    }
}
