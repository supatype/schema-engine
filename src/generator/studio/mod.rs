use crate::parser::ast::{FieldAst, RelationCardinality, SchemaAst};
use anyhow::Result;
use serde_json::{json, Value};

/// Generate Studio metadata JSON consumed by the Studio frontend.
///
/// Output shape:
/// ```json
/// {
///   "version": 1,
///   "models": [ { "name": "Post", "tableName": "posts", "fields": [...], ... } ],
///   "junctionTables": [...],
///   "storageBuckets": [...],
///   "locales": [...],
///   "stats": { "modelCount": 1, "fieldCount": 5, "relationCount": 1, ... }
/// }
/// ```
pub fn generate(ast: &SchemaAst) -> Result<Value> {
    let models: Vec<Value> = ast
        .models
        .iter()
        .map(|model| {
            let mut fields: Vec<Value> = Vec::new();

            for (name, field) in &model.fields {
                let entry = field_to_json(name, field);
                fields.push(entry);
            }

            json!({
                "name": model.name,
                "tableName": model.table_name(),
                "singleton": model.options.singleton,
                "softDelete": model.options.soft_delete,
                "timestamps": model.options.timestamps,
                "access": model.access(),
                "indexes": model.indexes(),
                "fields": fields,
            })
        })
        .collect();

    let junction_tables: Vec<Value> = ast
        .junction_tables
        .iter()
        .map(|jt| {
            json!({
                "name": jt.name,
                "modelA": jt.model_a,
                "modelB": jt.model_b,
                "fkA": jt.fk_a,
                "fkB": jt.fk_b,
            })
        })
        .collect();

    let storage_buckets: Vec<Value> = ast
        .storage_buckets
        .iter()
        .map(|b| {
            json!({
                "id": b.id,
                "public": b.public,
                "allowedMimeTypes": b.allowed_mime_types,
                "fileSizeLimit": b.file_size_limit,
            })
        })
        .collect();

    // ─── Stats ────────────────────────────────────────────────────────────────
    let model_count = ast.models.len();
    let field_count: usize = ast.models.iter().map(|m| m.fields.len()).sum();
    let relation_count: usize = ast
        .models
        .iter()
        .flat_map(|m| m.fields.values())
        .filter(|f| matches!(f, FieldAst::Relation(_)))
        .count();
    let junction_table_count = ast.junction_tables.len();
    let bucket_count = ast.storage_buckets.len();

    Ok(json!({
        "version": 1,
        "models": models,
        "junctionTables": junction_tables,
        "storageBuckets": storage_buckets,
        "locales": ast.locales,
        "defaultLocale": ast.default_locale,
        "stats": {
            "modelCount": model_count,
            "fieldCount": field_count,
            "relationCount": relation_count,
            "junctionTableCount": junction_table_count,
            "bucketCount": bucket_count,
        },
    }))
}

fn field_to_json(name: &str, field: &FieldAst) -> Value {
    match field {
        FieldAst::Relation(rel) => {
            let cardinality = match rel.cardinality {
                RelationCardinality::BelongsTo => "belongsTo",
                RelationCardinality::HasOne => "hasOne",
                RelationCardinality::HasMany => "hasMany",
                RelationCardinality::ManyToMany => "manyToMany",
            };
            json!({
                "name": name,
                "kind": "relation",
                "cardinality": cardinality,
                "target": rel.target,
                "foreignKey": rel.foreign_key,
                "references": rel.references,
                "through": rel.through,
                "onDelete": rel.on_delete,
                "uniqueFk": rel.unique_fk,
            })
        }
        FieldAst::Enum(e) => json!({
            "name": name,
            "kind": "enum",
            "pgType": e.pg_type,
            "required": e.required,
            "unique": e.unique,
            "localized": e.localized,
            "default": e.default,
            "values": e.values,
        }),
        FieldAst::Slug(s) => json!({
            "name": name,
            "kind": "slug",
            "pgType": s.pg_type,
            "required": s.required,
            "unique": s.unique,
            "localized": s.localized,
            "from": s.from,
        }),
        FieldAst::Json(j) => json!({
            "name": name,
            "kind": "json",
            "pgType": j.pg_type,
            "required": j.required,
            "localized": j.localized,
        }),
        FieldAst::Decimal(d) => json!({
            "name": name,
            "kind": "decimal",
            "pgType": d.pg_type,
            "required": d.required,
            "localized": d.localized,
            "precision": d.precision,
            "scale": d.scale,
        }),
        FieldAst::Image(s) | FieldAst::File(s) => {
            let kind = if matches!(field, FieldAst::Image(_)) {
                "image"
            } else {
                "file"
            };
            json!({
                "name": name,
                "kind": kind,
                "pgType": s.pg_type,
                "required": s.required,
                "bucket": s.bucket,
            })
        }
        FieldAst::Geo(g) => json!({
            "name": name,
            "kind": "geo",
            "pgType": g.pg_type,
            "required": g.required,
            "geoType": g.geo_type,
            "srid": g.srid,
        }),
        FieldAst::Vector(v) => json!({
            "name": name,
            "kind": "vector",
            "pgType": v.pg_type,
            "required": v.required,
            "dimensions": v.dimensions,
        }),
        FieldAst::Array(a) => json!({
            "name": name,
            "kind": "array",
            "elementType": a.element_type,
            "required": a.required,
            "unique": a.unique,
        }),
        FieldAst::Blocks(b) => {
            let block_defs: Vec<Value> = b
                .blocks
                .iter()
                .map(|bd| {
                    json!({
                        "name": bd.name,
                        "label": bd.label,
                        "icon": bd.icon,
                    })
                })
                .collect();
            json!({
                "name": name,
                "kind": "blocks",
                "required": b.required,
                "index": b.index,
                "blocks": block_defs,
            })
        }
        FieldAst::Custom(c) => json!({
            "name": name,
            "kind": "custom",
            "fieldType": c.field_type,
            "plugin": c.plugin,
            "pgType": c.pg_type,
            "tsType": c.ts_type,
            "required": c.required,
            "unique": c.unique,
            "index": c.index,
        }),
        FieldAst::Timestamps => json!({ "name": name, "kind": "timestamps" }),
        FieldAst::Publishable => json!({ "name": name, "kind": "publishable" }),
        FieldAst::SoftDelete => json!({ "name": name, "kind": "softDelete" }),
        // All ScalarFieldAst variants
        other => {
            let kind = scalar_kind(other);
            let pg_type = scalar_pg_type(other);
            let required = scalar_required(other);
            let unique = scalar_unique(other);
            let primary_key = scalar_primary_key(other);
            let index = scalar_index(other);
            let localized = scalar_localized(other);
            let default = scalar_default(other);
            json!({
                "name": name,
                "kind": kind,
                "pgType": pg_type,
                "required": required,
                "unique": unique,
                "primaryKey": primary_key,
                "index": index,
                "localized": localized,
                "default": default,
            })
        }
    }
}

fn scalar_kind(field: &FieldAst) -> &'static str {
    match field {
        FieldAst::Text(_) => "text",
        FieldAst::RichText(_) => "richText",
        FieldAst::Integer(_) => "integer",
        FieldAst::Float(_) => "float",
        FieldAst::Boolean(_) => "boolean",
        FieldAst::Datetime(_) => "datetime",
        FieldAst::Uuid(_) => "uuid",
        FieldAst::Email(_) => "email",
        FieldAst::BigInt(_) => "bigInt",
        FieldAst::Bytes(_) => "bytes",
        FieldAst::SmallInt(_) => "smallInt",
        FieldAst::Date(_) => "date",
        FieldAst::Timestamp(_) => "timestamp",
        FieldAst::Serial(_) => "serial",
        FieldAst::BigSerial(_) => "bigSerial",
        FieldAst::Money(_) => "money",
        FieldAst::Url(_) => "url",
        FieldAst::Ip(_) => "ip",
        FieldAst::Cidr(_) => "cidr",
        FieldAst::Macaddr(_) => "macaddr",
        FieldAst::Interval(_) => "interval",
        FieldAst::TsQuery(_) => "tsQuery",
        FieldAst::TsVector(_) => "tsVector",
        FieldAst::Xml(_) => "xml",
        _ => "text",
    }
}

fn scalar_pg_type(field: &FieldAst) -> &str {
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
        | FieldAst::Xml(f) => &f.pg_type,
        _ => "",
    }
}

fn scalar_required(field: &FieldAst) -> bool {
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
        _ => false,
    }
}

fn scalar_unique(field: &FieldAst) -> bool {
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
        | FieldAst::Xml(f) => f.unique,
        _ => false,
    }
}

fn scalar_primary_key(field: &FieldAst) -> bool {
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
        | FieldAst::Xml(f) => f.primary_key,
        _ => false,
    }
}

fn scalar_index(field: &FieldAst) -> bool {
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
        | FieldAst::Xml(f) => f.index,
        _ => false,
    }
}

fn scalar_localized(field: &FieldAst) -> bool {
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
        | FieldAst::Xml(f) => f.localized,
        _ => false,
    }
}

fn scalar_default(field: &FieldAst) -> Value {
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
        | FieldAst::Xml(f) => serde_json::to_value(&f.default).unwrap_or(Value::Null),
        _ => Value::Null,
    }
}
