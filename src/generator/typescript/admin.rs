use anyhow::Result;
use serde_json::{json, Value};
use crate::parser::ast::{FieldAst, SchemaAst};

/// Generate admin panel configuration JSON consumed by the admin panel React app.
pub fn generate(ast: &SchemaAst) -> Result<Value> {
    let models: Vec<Value> = ast.models.iter().map(|model| {
        let fields: Vec<Value> = model.fields.iter()
            .filter(|(_, f)| !matches!(f, FieldAst::Relation(_)))
            .map(|(name, field)| {
                json!({
                    "name": name,
                    "type": field_type_label(field),
                    "required": field_required(field),
                })
            })
            .collect();

        json!({
            "name": model.name,
            "tableName": model.table_name,
            "fields": fields,
        })
    }).collect();

    Ok(json!({ "models": models }))
}

fn field_type_label(field: &FieldAst) -> &'static str {
    match field {
        FieldAst::Text(_) => "text",
        FieldAst::RichText(_) => "richText",
        FieldAst::Integer(_) | FieldAst::Float(_) | FieldAst::BigInt(_) | FieldAst::Decimal(_) => "number",
        FieldAst::Boolean(_) => "boolean",
        FieldAst::Datetime(_) => "datetime",
        FieldAst::Uuid(_) => "uuid",
        FieldAst::Email(_) => "email",
        FieldAst::Slug(_) => "slug",
        FieldAst::Enum(_) => "enum",
        FieldAst::Json(_) => "json",
        FieldAst::Image(_) => "image",
        FieldAst::File(_) => "file",
        FieldAst::Geo(_) => "geo",
        FieldAst::Vector(_) => "vector",
        _ => "unknown",
    }
}

fn field_required(field: &FieldAst) -> bool {
    match field {
        FieldAst::Text(f) | FieldAst::Email(f) | FieldAst::Bytes(f)
        | FieldAst::RichText(f) | FieldAst::Integer(f) | FieldAst::Float(f)
        | FieldAst::BigInt(f) | FieldAst::Boolean(f) | FieldAst::Datetime(f)
        | FieldAst::Uuid(f) => f.required,
        FieldAst::Slug(f) => f.required,
        FieldAst::Enum(f) => f.required,
        FieldAst::Json(f) => f.required,
        FieldAst::Decimal(f) => f.required,
        FieldAst::Image(f) | FieldAst::File(f) => f.required,
        FieldAst::Geo(f) => f.required,
        FieldAst::Vector(f) => f.required,
        _ => false,
    }
}
