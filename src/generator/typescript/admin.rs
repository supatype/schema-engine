use crate::parser::ast::{FieldAst, ModelAst, RelationCardinality, SchemaAst};
use anyhow::Result;
use serde_json::{json, Value};

/// Generate admin panel configuration JSON consumed by the admin panel React app.
///
/// Output shape:
/// ```json
/// {
///   "version": 1,
///   "localization": { "locales": ["en"], "defaultLocale": "en" },
///   "navigation": [ { "group": "Content", "items": [...] } ],
///   "models": [ { "name": "Post", "tableName": "posts", "fields": [...], ... } ],
///   "globals": [ { "name": "SiteSettings", "tableName": "site_settings", "fields": [...] } ]
/// }
/// ```
pub fn generate(ast: &SchemaAst) -> Result<Value> {
    let default_locale = ast.effective_default_locale().to_string();

    // ─── Localization config ──────────────────────────────────────────────────
    let localization = if ast.locales.is_empty() {
        json!({ "locales": ["en"], "defaultLocale": "en" })
    } else {
        json!({ "locales": ast.locales, "defaultLocale": default_locale })
    };

    // ─── Separate singletons (globals) from collections ───────────────────────
    let (singletons, collections): (Vec<&ModelAst>, Vec<&ModelAst>) =
        ast.models.iter().partition(|m| m.options.singleton);

    // ─── Navigation ───────────────────────────────────────────────────────────
    let content_items: Vec<Value> = collections
        .iter()
        .map(|m| json!({ "label": m.name.clone(), "model": m.table_name.clone() }))
        .collect();

    let settings_items: Vec<Value> = singletons
        .iter()
        .map(|m| json!({ "label": m.name.clone(), "global": m.table_name.clone() }))
        .collect();

    let mut navigation: Vec<Value> = Vec::new();
    if !content_items.is_empty() {
        navigation.push(json!({ "group": "Content", "items": content_items }));
    }
    if !settings_items.is_empty() {
        navigation.push(json!({ "group": "Settings", "items": settings_items }));
    }

    // ─── Models ───────────────────────────────────────────────────────────────
    let models: Vec<Value> = collections
        .iter()
        .map(|model| build_model_config(model, &default_locale))
        .collect();

    // ─── Globals ──────────────────────────────────────────────────────────────
    let globals: Vec<Value> = singletons
        .iter()
        .map(|model| build_model_config(model, &default_locale))
        .collect();

    Ok(json!({
        "version": 1,
        "localization": localization,
        "navigation": navigation,
        "models": models,
        "globals": globals,
    }))
}

// ─── Model config builder ─────────────────────────────────────────────────────

fn build_model_config(model: &ModelAst, default_locale: &str) -> Value {
    let has_timestamps = has_composite(model, "timestamps") || model.options.timestamps;
    let has_publishing = has_composite(model, "publishable");
    let has_soft_delete = has_composite(model, "softDelete") || model.options.soft_delete;

    let fields = build_fields_config(model, default_locale);
    let list_columns = derive_list_columns(model, has_publishing, has_timestamps);
    let search_fields = derive_search_fields(model);
    let default_sort = if has_timestamps {
        json!({ "field": "created_at", "direction": "desc" })
    } else {
        json!({ "field": "id", "direction": "desc" })
    };

    json!({
        "name": model.name,
        "tableName": model.table_name,
        "singleton": model.options.singleton,
        "publishing": has_publishing,
        "softDelete": has_soft_delete,
        "timestamps": has_timestamps,
        "listColumns": list_columns,
        "searchFields": search_fields,
        "defaultSort": default_sort,
        "fields": fields,
    })
}

fn has_composite(model: &ModelAst, key: &str) -> bool {
    model.fields.contains_key(key)
}

fn derive_list_columns(
    model: &ModelAst,
    has_publishing: bool,
    has_timestamps: bool,
) -> Vec<String> {
    let mut cols: Vec<String> = Vec::new();

    // First text-like field (name, title, slug, email)
    for (name, field) in &model.fields {
        if matches!(
            field,
            FieldAst::Text(_) | FieldAst::Email(_) | FieldAst::Slug(_)
        ) {
            cols.push(name.clone());
            break;
        }
    }

    if has_publishing {
        cols.push("status".into());
    }

    for (name, field) in &model.fields {
        if let FieldAst::Enum(e) = field {
            if e.values.len() <= 8 && !cols.contains(name) {
                cols.push(name.clone());
            }
        }
    }

    if has_timestamps {
        cols.push("created_at".into());
    }

    if cols.is_empty() {
        cols.push("id".into());
    }

    cols
}

fn derive_search_fields(model: &ModelAst) -> Vec<String> {
    model
        .fields
        .iter()
        .filter_map(|(name, field)| match field {
            FieldAst::Text(_) | FieldAst::Email(_) | FieldAst::Slug(_) => Some(name.clone()),
            _ => None,
        })
        .collect()
}

// ─── Field config builders ────────────────────────────────────────────────────

fn build_fields_config(model: &ModelAst, default_locale: &str) -> Vec<Value> {
    let mut fields: Vec<Value> = Vec::new();

    for (name, field) in &model.fields {
        match field {
            FieldAst::Timestamps => {
                fields.push(datetime_field("created_at", false, true, false));
                fields.push(datetime_field("updated_at", false, true, false));
            }
            FieldAst::Publishable => {
                fields.push(json!({
                    "name": "status",
                    "label": "Status",
                    "widget": "publishStatus",
                    "required": true,
                    "showInList": true,
                    "filterable": true,
                    "sortable": false,
                    "localized": false,
                }));
                fields.push(datetime_field("published_at", false, false, true));
                fields.push(datetime_field("scheduled_at", false, false, false));
            }
            FieldAst::SoftDelete => {
                fields.push(datetime_field("deleted_at", false, false, false));
            }
            FieldAst::Relation(rel) => {
                let (widget, show_in_list) = match rel.cardinality {
                    RelationCardinality::BelongsTo | RelationCardinality::HasOne => {
                        ("relationPicker", true)
                    }
                    RelationCardinality::HasMany | RelationCardinality::ManyToMany => {
                        ("multiRelationPicker", false)
                    }
                };
                let cardinality = match rel.cardinality {
                    RelationCardinality::BelongsTo => "belongsTo",
                    RelationCardinality::HasOne => "hasOne",
                    RelationCardinality::HasMany => "hasMany",
                    RelationCardinality::ManyToMany => "manyToMany",
                };
                fields.push(json!({
                    "name": name,
                    "label": to_label(name),
                    "widget": widget,
                    "target": rel.target,
                    "cardinality": cardinality,
                    "required": false,
                    "showInList": show_in_list,
                    "filterable": show_in_list,
                    "sortable": false,
                    "localized": false,
                }));
            }
            FieldAst::Blocks(b) => {
                let block_defs: Vec<Value> = b
                    .blocks
                    .iter()
                    .map(|bd| {
                        let block_fields: Vec<Value> = bd
                            .fields
                            .iter()
                            .map(|(fname, ffield)| {
                                json!({
                                    "name": fname,
                                    "label": to_label(fname),
                                    "widget": field_widget(ffield),
                                })
                            })
                            .collect();
                        json!({
                            "name": bd.name,
                            "label": bd.label.as_deref().unwrap_or(&to_label(&bd.name)),
                            "icon": bd.icon,
                            "fields": block_fields,
                        })
                    })
                    .collect();
                fields.push(json!({
                    "name": name,
                    "label": to_label(name),
                    "widget": "blockEditor",
                    "required": b.required,
                    "blocks": block_defs,
                    "showInList": false,
                    "filterable": false,
                    "sortable": false,
                    "localized": false,
                }));
            }
            other => {
                let localized = field_is_localized(other);
                let show_in_list = field_show_in_list(other);
                let filterable = field_filterable(other);
                let sortable = field_sortable(other);
                let widget = field_widget(other);

                let mut entry = json!({
                    "name": name,
                    "label": to_label(name),
                    "widget": widget,
                    "required": field_required_flag(other),
                    "showInList": show_in_list,
                    "filterable": filterable,
                    "sortable": sortable,
                    "localized": localized,
                });

                if let FieldAst::Enum(e) = other {
                    entry["enumValues"] = json!(e.values);
                }
                if let FieldAst::Image(s) | FieldAst::File(s) = other {
                    entry["bucket"] = json!(s.bucket);
                }
                if localized {
                    entry["defaultLocale"] = json!(default_locale);
                }

                fields.push(entry);
            }
        }
    }

    fields
}

fn datetime_field(name: &str, required: bool, show_in_list: bool, filterable: bool) -> Value {
    json!({
        "name": name,
        "label": to_label(name),
        "widget": "datetime",
        "required": required,
        "showInList": show_in_list,
        "filterable": filterable,
        "sortable": true,
        "localized": false,
    })
}

// ─── Field attribute helpers ──────────────────────────────────────────────────

fn field_widget(field: &FieldAst) -> &'static str {
    match field {
        FieldAst::Text(_) => "text",
        FieldAst::RichText(_) => "richText",
        FieldAst::Integer(_)
        | FieldAst::Float(_)
        | FieldAst::BigInt(_)
        | FieldAst::SmallInt(_)
        | FieldAst::Decimal(_)
        | FieldAst::Money(_) => "number",
        FieldAst::Boolean(_) => "boolean",
        FieldAst::Datetime(_) => "datetime",
        FieldAst::Date(_) => "date",
        FieldAst::Timestamp(_) => "datetime",
        FieldAst::Uuid(_) => "uuid",
        FieldAst::Email(_) => "email",
        FieldAst::Slug(_) => "slug",
        FieldAst::Enum(_) => "select",
        FieldAst::Json(_) => "json",
        FieldAst::Image(_) => "image",
        FieldAst::File(_) => "file",
        FieldAst::Geo(_) => "geo",
        FieldAst::Vector(_) => "vector",
        FieldAst::Blocks(_) => "blockEditor",
        FieldAst::Url(_) => "url",
        FieldAst::Ip(_) | FieldAst::Cidr(_) | FieldAst::Macaddr(_) => "text",
        FieldAst::Interval(_) | FieldAst::TsQuery(_) | FieldAst::TsVector(_) | FieldAst::Xml(_) => {
            "text"
        }
        FieldAst::Array(_) => "json",
        FieldAst::BigSerial(_) | FieldAst::Serial(_) => "number",
        FieldAst::Bytes(_) => "text",
        _ => "text",
    }
}

fn field_show_in_list(field: &FieldAst) -> bool {
    matches!(
        field,
        FieldAst::Text(_)
            | FieldAst::Email(_)
            | FieldAst::Slug(_)
            | FieldAst::Enum(_)
            | FieldAst::Boolean(_)
            | FieldAst::Integer(_)
            | FieldAst::Float(_)
            | FieldAst::Datetime(_)
            | FieldAst::Date(_)
            | FieldAst::SmallInt(_)
            | FieldAst::BigInt(_)
            | FieldAst::Money(_)
            | FieldAst::Url(_)
    )
}

fn field_filterable(field: &FieldAst) -> bool {
    matches!(
        field,
        FieldAst::Text(_)
            | FieldAst::Email(_)
            | FieldAst::Slug(_)
            | FieldAst::Enum(_)
            | FieldAst::Boolean(_)
            | FieldAst::Integer(_)
            | FieldAst::Float(_)
            | FieldAst::Datetime(_)
            | FieldAst::Date(_)
            | FieldAst::Uuid(_)
            | FieldAst::SmallInt(_)
            | FieldAst::BigInt(_)
            | FieldAst::Decimal(_)
            | FieldAst::Money(_)
    )
}

fn field_sortable(field: &FieldAst) -> bool {
    matches!(
        field,
        FieldAst::Text(_)
            | FieldAst::Email(_)
            | FieldAst::Slug(_)
            | FieldAst::Enum(_)
            | FieldAst::Boolean(_)
            | FieldAst::Integer(_)
            | FieldAst::Float(_)
            | FieldAst::Datetime(_)
            | FieldAst::Date(_)
            | FieldAst::Uuid(_)
            | FieldAst::SmallInt(_)
            | FieldAst::BigInt(_)
            | FieldAst::Decimal(_)
            | FieldAst::Money(_)
            | FieldAst::Serial(_)
            | FieldAst::BigSerial(_)
    )
}

fn field_required_flag(field: &FieldAst) -> bool {
    match field {
        FieldAst::Text(f)
        | FieldAst::Email(f)
        | FieldAst::Bytes(f)
        | FieldAst::RichText(f)
        | FieldAst::Integer(f)
        | FieldAst::Float(f)
        | FieldAst::BigInt(f)
        | FieldAst::Boolean(f)
        | FieldAst::Datetime(f)
        | FieldAst::Uuid(f)
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
        _ => false,
    }
}

fn field_is_localized(field: &FieldAst) -> bool {
    match field {
        FieldAst::Text(f)
        | FieldAst::RichText(f)
        | FieldAst::Email(f)
        | FieldAst::Url(f)
        | FieldAst::Xml(f)
        | FieldAst::Bytes(f)
        | FieldAst::Integer(f)
        | FieldAst::Float(f)
        | FieldAst::BigInt(f)
        | FieldAst::SmallInt(f)
        | FieldAst::Boolean(f)
        | FieldAst::Datetime(f)
        | FieldAst::Date(f)
        | FieldAst::Timestamp(f)
        | FieldAst::Uuid(f) => f.localized,
        FieldAst::Slug(f) => f.localized,
        FieldAst::Enum(f) => f.localized,
        FieldAst::Json(f) => f.localized,
        FieldAst::Decimal(f) => f.localized,
        _ => false,
    }
}

// ─── Label helper ─────────────────────────────────────────────────────────────

/// Converts a camelCase or snake_case field name to a human-readable label.
pub fn to_label(name: &str) -> String {
    if name.contains('_') {
        name.split('_')
            .enumerate()
            .map(|(i, w)| if i == 0 { capitalise(w) } else { w.to_string() })
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        let mut parts: Vec<String> = Vec::new();
        let mut current = String::new();
        for ch in name.chars() {
            if ch.is_uppercase() && !current.is_empty() {
                parts.push(current.clone());
                current.clear();
            }
            current.push(ch.to_lowercase().next().unwrap());
        }
        if !current.is_empty() {
            parts.push(current);
        }
        parts
            .iter()
            .enumerate()
            .map(|(i, w)| if i == 0 { capitalise(w) } else { w.clone() })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}
