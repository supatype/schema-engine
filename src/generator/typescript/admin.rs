use crate::parser::accessors::field_annotations;
use crate::parser::ast::{
    scalar_of, DefaultValueAst, FieldAst, ModelAst, RelationCardinality, RelationFieldAst,
    ScalarFieldAst, SchemaAst,
};
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
        .map(|m| json!({ "label": m.name.clone(), "model": m.table_name().to_string() }))
        .collect();

    let settings_items: Vec<Value> = singletons
        .iter()
        .map(|m| json!({ "label": m.name.clone(), "global": m.table_name().to_string() }))
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
        .map(|model| build_model_config(model, &default_locale, ast))
        .collect();

    // ─── Globals ──────────────────────────────────────────────────────────────
    let globals: Vec<Value> = singletons
        .iter()
        .map(|model| build_model_config(model, &default_locale, ast))
        .collect();

    let storage_buckets = serde_json::to_value(&ast.storage_buckets).unwrap_or_else(|_| json!([]));

    Ok(json!({
        "version": 1,
        "localization": localization,
        "navigation": navigation,
        "models": models,
        "globals": globals,
        "storageBuckets": storage_buckets,
        // Draft visibility and the bounds on a preview link, carried through from the project
        // config so the API server can read them without a second delivery path. It already reads
        // `adminRoles` from this file; this is the same journey for settings that arrive the same
        // way. Absent for a schema with no versioned model.
        "publishing": match ast.publishing.as_ref() {
            Some(p) if crate::parser::accessors::has_versions(ast) => json!({
                "draftVisibility": p.draft_visibility,
                "previewDefaultTtl": p.preview_default_ttl,
                "previewMaxRecordTtl": p.preview_max_record_ttl,
                "previewMaxProjectTtl": p.preview_max_project_ttl,
                "previewAllowProjectScope": p.preview_allow_project_scope,
            }),
            _ => Value::Null,
        },
    }))
}

// ─── Model config builder ─────────────────────────────────────────────────────

fn build_model_config(model: &ModelAst, default_locale: &str, ast: &SchemaAst) -> Value {
    let has_timestamps = has_composite(model, "timestamps") || model.options.timestamps;
    // From the model's `versions` declaration, not from a field literally named `publishable`.
    //
    // That is the regression this replaces. `has_composite(model, "publishable")` was true only when
    // a model had a *field* called `publishable`, which nothing but the deleted builder API ever
    // emitted, so a `WithPublishable<…>` model got its `published_at` column and no publish widget:
    // the feature read as present in the schema and was absent from the UI. A model declaring
    // `versions` is publishable, and one that does not is not.
    let versioning = crate::parser::accessors::versions_of(model);
    let has_publishing = versioning.is_some();
    let has_soft_delete = has_composite(model, "softDelete") || model.options.soft_delete;

    let fields = build_fields_config(model, default_locale, ast);
    let list_columns = derive_list_columns(model);
    let search_fields = derive_search_fields(model);
    // Every key column, so Studio can end each list order on something unique: two rows with the
    // same sort value otherwise trade places between pages. Studio assumed `id` before this was sent.
    let primary_key = crate::parser::accessors::primary_key_columns(model);
    let default_sort = default_sort(model, has_timestamps, &primary_key, &search_fields);

    // Model constraints travel to Studio as the node the CLI parsed, not as SQL.
    //
    // Studio evaluates them against the form's values, which is only possible while they stay a
    // structure it can walk. Sending the rendered `CHECK` would be sending SQL to a browser and
    // giving up the ability to say which rule failed and on which field: the payoff for refusing raw
    // SQL, spent.
    let names = crate::managed::ObjectNames::for_schema(ast);
    let constraints: Vec<Value> = model
        .annotations
        .db
        .constraints
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            let mut columns = Vec::new();
            crate::parser::ast::columns_in(rule, &mut columns);
            json!({
                "name": names.model_constraint(model.table_name(), index, rule),
                "columns": columns,
                "rule": rule,
            })
        })
        .collect();

    // Declared indexes, so Studio can show what this model is indexed by.
    //
    // Only the ones the schema declares. Indexes the engine creates on its own (a relation's foreign
    // key, a blocks GIN, a unique constraint's backing index) are consequences of other declarations
    // and listing them here would read as things an author chose.
    let indexes: Vec<Value> = model
        .indexes()
        .iter()
        .map(|index| {
            json!({
                "name": names.index(model.table_name(), index),
                "fields": index.fields,
                "unique": index.unique,
                "using": index.using,
            })
        })
        .collect();

    let config = json!({
        "name": model.name,
        "tableName": model.table_name(),
        // The project's own words for the model, null when it left them to Studio, which then
        // derives both from `name`.
        "label": model.options.label,
        "labelPlural": model.options.label_plural,
        "constraints": constraints,
        "indexes": indexes,
        "singleton": model.options.singleton,
        "publishing": has_publishing,
        // The shape Studio needs to build a publish control, not just whether to show one. Its
        // editor has to know that drafts are withheld (or that this is an audit model, where they
        // are not), which columns are per locale, and where the versions live.
        "versions": match versioning {
            Some(options) => json!({
                "drafts": options.drafts,
                "keep": options.keep,
                "versionsTable": crate::parser::accessors::versions_table_name(
                    model.table_name()
                ),
                "localizedColumns": localized_column_names(model),
            }),
            None => Value::Null,
        },
        "softDelete": has_soft_delete,
        "timestamps": has_timestamps,
        "listColumns": list_columns,
        "searchFields": search_fields,
        "defaultSort": default_sort,
        "primaryKey": primary_key,
        "fields": fields,
    });
    super::admin_plugins::with_composite_groups(config, model)
}

/// The order a Studio list opens in: the first of these rules that applies.
///
/// 1. The model declares `timestamps`: `created_at` descending, newest first.
/// 2. A date-time field records when the row was made: the first of [`CREATION_FIELD_NAMES`] the
///    model has as a date-time column, else the first date-time column, in declaration order,
///    whose default is the current time. Descending.
/// 3. The first key column grows over time: a serial, an identity, an integer drawn from a
///    sequence, or a UUID defaulting to a version 7 generator. Descending.
/// 4. The key says nothing about age (a random UUID, text): the first searchable text column,
///    ascending, so the list reads alphabetically by what a row is called. A declared search
///    field comes first there, which makes it the model's title; the engine has no other title
///    declaration.
/// 5. Nothing else applies: the first key column descending. The key, not `id`: a model keyed on
///    another column has no `id`, and sorting on it was an error from PostgREST on every list load.
///
/// Every rule reads declaration order, so a schema always opens in the same order. Studio ends
/// each order with the key columns to break ties, so only the primary sort is sent.
fn default_sort(
    model: &ModelAst,
    has_timestamps: bool,
    primary_key: &[String],
    search_fields: &[String],
) -> Value {
    let key = primary_key.first().map_or("id", String::as_str);
    let (field, direction) = if has_timestamps {
        ("created_at", "desc")
    } else if let Some(created) = creation_field(model) {
        (created, "desc")
    } else if key_grows(model) {
        (key, "desc")
    } else if let Some(title) = title_column(model, search_fields) {
        (title, "asc")
    } else {
        (key, "desc")
    };
    json!({ "field": field, "direction": direction })
}

/// Names a project gives the column that records when a row was made, in the order they win.
/// `created_at` is the engine's own (`timestamps`); the rest are the common alternatives, in both
/// casings a field name arrives in.
const CREATION_FIELD_NAMES: [&str; 4] = ["created_at", "createdAt", "inserted_at", "insertedAt"];

/// Default expressions that stamp the current time, lowercased.
const NOW_EXPRESSIONS: [&str; 6] = [
    "now()",
    "current_timestamp",
    "localtimestamp",
    "clock_timestamp()",
    "statement_timestamp()",
    "transaction_timestamp()",
];

/// Calls that make a version 7 UUID, which is time ordered: Postgres 18's own and `pg_uuidv7`'s.
const UUID_V7_GENERATORS: [&str; 2] = ["uuidv7(", "uuid_generate_v7("];

/// A date-time column holding one value per row. A localized one is JSONB and does not sort by time.
fn date_time_of(field: &FieldAst) -> Option<&ScalarFieldAst> {
    match field {
        FieldAst::Datetime(f) | FieldAst::Timestamp(f) if !f.localized => Some(f),
        _ => None,
    }
}

fn creation_field(model: &ModelAst) -> Option<&str> {
    let named = CREATION_FIELD_NAMES
        .into_iter()
        .find(|name| model.fields.get(*name).and_then(date_time_of).is_some());
    named.or_else(|| {
        model
            .fields
            .iter()
            .find(|(_, field)| {
                date_time_of(field).is_some_and(|f| defaults_to_now(f.default.as_ref()))
            })
            .map(|(name, _)| name.as_str())
    })
}

fn defaults_to_now(default: Option<&DefaultValueAst>) -> bool {
    match default {
        Some(DefaultValueAst::Now) => true,
        Some(DefaultValueAst::Expression { expr }) => {
            NOW_EXPRESSIONS.contains(&expr.trim().to_ascii_lowercase().as_str())
        }
        _ => false,
    }
}

fn expression_default(field: &ScalarFieldAst) -> Option<String> {
    match &field.default {
        Some(DefaultValueAst::Expression { expr }) => Some(expr.trim().to_ascii_lowercase()),
        _ => None,
    }
}

/// Whether the model's first key column takes larger values for newer rows.
fn key_grows(model: &ModelAst) -> bool {
    let Some((_, key)) = model
        .fields
        .iter()
        .find(|(_, field)| crate::parser::accessors::is_primary_key(field))
    else {
        return false;
    };
    let expr = scalar_of(key).and_then(expression_default);
    match key {
        _ if crate::parser::accessors::owns_sequence(key) => true,
        FieldAst::Integer(_) | FieldAst::SmallInt(_) | FieldAst::BigInt(_) => {
            expr.is_some_and(|e| e.starts_with("nextval("))
        }
        FieldAst::Uuid(_) => {
            expr.is_some_and(|e| UUID_V7_GENERATORS.iter().any(|g| e.starts_with(g)))
        }
        _ => false,
    }
}

/// The first search field that is plain text in its own column, which sorts the way it reads.
fn title_column<'a>(model: &ModelAst, search_fields: &'a [String]) -> Option<&'a str> {
    search_fields
        .iter()
        .find(|name| match model.fields.get(name.as_str()) {
            Some(FieldAst::Text(f) | FieldAst::Email(f)) => !f.localized,
            Some(FieldAst::Slug(f)) => !f.localized,
            _ => false,
        })
        .map(String::as_str)
}

fn has_composite(model: &ModelAst, key: &str) -> bool {
    model.fields.contains_key(key)
}

/// How many columns a Studio list shows when nothing else decides, the key included.
const LIST_COLUMN_COUNT: usize = 3;

/// The columns a Studio list opens with: the record's key first, then the first fields, in
/// declaration order, that read in a table cell, up to [`LIST_COLUMN_COUNT`] in all. A field that
/// does not read in a cell is skipped and the next one taken.
///
/// The rule used to be the first text field, a publish status, short enums and `created_at`, which
/// left a model of plain text columns with one column: every chat message in a room read the same.
/// The key says which record a row is even when its other values repeat; a composite key shows its
/// first column. Other keys (UUIDs, relation foreign keys) stay out of the remaining places. A
/// composite field stands for the columns it adds, where it is declared, so `timestamps` last in a
/// short model fills the list and costs a longer one nothing.
fn derive_list_columns(model: &ModelAst) -> Vec<String> {
    let key = crate::parser::accessors::primary_key_columns(model)
        .into_iter()
        .next();
    let mut cols: Vec<String> = key.into_iter().collect();
    let room = LIST_COLUMN_COUNT - cols.len();
    cols.extend(
        model
            .fields
            .iter()
            .flat_map(|(name, field)| list_candidates(name, field))
            .take(room),
    );
    if cols.is_empty() {
        cols.push("id".into());
    }
    cols
}

/// The list columns one declared field contributes: none, its own, or a composite's.
fn list_candidates(name: &str, field: &FieldAst) -> Vec<String> {
    match field {
        FieldAst::Timestamps => vec!["created_at".into(), "updated_at".into()],
        FieldAst::Publishable => vec!["status".into()],
        _ if reads_in_a_cell(field) => vec![name.to_string()],
        _ => Vec::new(),
    }
}

/// Whether a field's value reads as a short line in a list cell.
///
/// Not rich text, JSON, blocks, binary, geometry, vectors or search documents, which come out as
/// markup or noise; not an array of objects; and not a bare key (a UUID, a relation's foreign key),
/// which is an identifier rather than something a person knows a row by. The primary key is left
/// out here because [`derive_list_columns`] puts it first itself.
fn reads_in_a_cell(field: &FieldAst) -> bool {
    if crate::parser::accessors::is_primary_key(field) {
        return false;
    }
    match field {
        FieldAst::Array(a) => !is_object_element(&a.element_type),
        FieldAst::Uuid(_) | FieldAst::Relation(_) => false,
        other => field_show_in_list(other),
    }
}

/// An array whose elements are documents, which a cell can only show as raw JSON.
fn is_object_element(element_type: &str) -> bool {
    matches!(
        element_type.trim().to_ascii_uppercase().as_str(),
        "JSON" | "JSONB"
    )
}

/// The columns Studio's list view searches.
///
/// A declaration wins outright. Studio filters on the **first** entry, so which column is first is
/// the whole decision, and guessing it from field order meant a model whose first text column was a
/// slug searched slugs while the author's `Searchable<string>` on `title` did nothing. Order here is
/// the order the schema wrote.
///
/// With nothing declared, every text-like column stays searchable, which is what every existing
/// schema already gets: this is an opt-in narrowing, not a new requirement. A declared name that
/// matches no field is dropped rather than trusted. The CLI refuses those, so one arriving here
/// means a hand-written AST, and searching a column that does not exist is an error from PostgREST
/// on every keystroke.
fn derive_search_fields(model: &ModelAst) -> Vec<String> {
    let declared: Vec<String> = model
        .annotations
        .platform
        .search_fields
        .iter()
        .filter(|name| model.fields.contains_key(*name))
        .cloned()
        .collect();

    if !declared.is_empty() {
        return declared;
    }

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

fn build_fields_config(model: &ModelAst, default_locale: &str, ast: &SchemaAst) -> Vec<Value> {
    let mut fields: Vec<Value> = Vec::new();

    for (name, field) in &model.fields {
        match field {
            FieldAst::Timestamps => {
                fields.push(datetime_field("created_at", false, true, false, true));
                fields.push(datetime_field("updated_at", false, true, false, true));
            }
            FieldAst::Publishable => {
                fields.push(json!({
                    "name": "status",
                    "label": "Status",
                    "widget": "publish",
                    "required": true,
                    "showInList": true,
                    "filterable": true,
                    "sortable": false,
                    "localized": false,
                }));
                fields.push(datetime_field("published_at", false, false, true, false));
                fields.push(datetime_field("scheduled_at", false, false, false, false));
            }
            FieldAst::SoftDelete => {
                fields.push(datetime_field("deleted_at", false, false, false, false));
            }
            FieldAst::Relation(rel) => {
                let (widget, show_in_list) = match rel.cardinality {
                    RelationCardinality::BelongsTo | RelationCardinality::HasOne => {
                        ("relation", true)
                    }
                    RelationCardinality::HasMany | RelationCardinality::ManyToMany => {
                        ("multirelation", false)
                    }
                };
                let cardinality = match rel.cardinality {
                    RelationCardinality::BelongsTo => "belongsTo",
                    RelationCardinality::HasOne => "hasOne",
                    RelationCardinality::HasMany => "hasMany",
                    RelationCardinality::ManyToMany => "manyToMany",
                };
                let target_table = resolve_relation_target(rel, ast);
                let fk_col = rel.foreign_key.clone().unwrap_or_else(|| {
                    format!("{}_id", crate::parser::resolver::to_snake_case(name))
                });
                let mut options = json!({
                    "target": target_table,
                    "cardinality": cardinality,
                });
                if matches!(rel.cardinality, RelationCardinality::BelongsTo) {
                    options["foreignKey"] = json!(fk_col);
                }
                // For manyToMany, include junction table metadata for the relation widget.
                if matches!(rel.cardinality, RelationCardinality::ManyToMany) {
                    if let Some(jt) = ast.junction_tables.iter().find(|jt| {
                        (jt.model_a == model.name && jt.model_b == rel.target)
                            || (jt.model_b == model.name && jt.model_a == rel.target)
                    }) {
                        let (local_key, foreign_key) = if jt.model_a == model.name {
                            (jt.fk_a.as_str(), jt.fk_b.as_str())
                        } else {
                            (jt.fk_b.as_str(), jt.fk_a.as_str())
                        };
                        options["junctionTable"] = json!(jt.name);
                        options["localKey"] = json!(local_key);
                        options["foreignKey"] = json!(foreign_key);
                    }
                }
                let column_name = if matches!(rel.cardinality, RelationCardinality::BelongsTo) {
                    fk_col.as_str()
                } else {
                    name
                };
                let mut entry = json!({
                    "name": column_name,
                    "label": to_label(name),
                    "widget": widget,
                    "required": false,
                    "showInList": show_in_list,
                    "filterable": show_in_list,
                    "sortable": false,
                    "localized": false,
                    "options": options,
                });
                if rel.read_only {
                    entry["readOnly"] = json!(true);
                }
                fields.push(entry);
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
                                let localized = field_is_localized(ffield);
                                let mut field = json!({
                                    "name": fname,
                                    "label": to_label(fname),
                                    "widget": field_widget_named(ffield, fname),
                                    "required": false,
                                    "localized": localized,
                                });
                                let options: Option<Value> = match ffield {
                                    FieldAst::Image(s) | FieldAst::File(s) => {
                                        Some(json!({ "bucket": s.bucket }))
                                    }
                                    FieldAst::Enum(e) => Some(json!({ "values": e.values })),
                                    FieldAst::Money(_) => {
                                        Some(json!({ "currency": true, "step": "0.01" }))
                                    }
                                    FieldAst::Vector(v) => {
                                        Some(json!({ "dimensions": v.dimensions }))
                                    }
                                    _ => None,
                                };
                                if let Some(opts) = options {
                                    field["options"] = opts;
                                }
                                if localized {
                                    field["defaultLocale"] = json!(default_locale);
                                }
                                field
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
                let mut entry = json!({
                    "name": name,
                    "label": to_label(name),
                    "widget": "blocks",
                    "required": b.required,
                    "showInList": false,
                    "filterable": false,
                    "sortable": false,
                    "localized": b.localized,
                    "options": { "blockTypes": block_defs },
                });
                if let Some(v) = field_validation(field) {
                    entry["validation"] = v;
                }
                if b.localized {
                    entry["defaultLocale"] = json!(default_locale);
                }
                fields.push(entry);
            }
            other => {
                let localized = field_is_localized(other);
                let show_in_list = field_show_in_list(other);
                let filterable = field_filterable(other);
                let sortable = field_sortable(other);
                let widget = field_widget_named(other, name);

                // Fields that store computed/binary data are read-only in the UI.
                let read_only = field_is_read_only(other)
                    || matches!(
                        other,
                        FieldAst::Vector(_) | FieldAst::TsVector(_) | FieldAst::TsQuery(_)
                    )
                    || field_is_server_managed(other);

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

                if read_only {
                    entry["readOnly"] = json!(true);
                }
                if let Some(plugin) = super::admin_plugins::plugin_field(other) {
                    entry["plugin"] = plugin;
                }

                // Build per-kind options object (all field-specific data lives here so the
                // studio widget can read it from config.options without knowing the root keys).
                let options: Option<Value> = match other {
                    FieldAst::Enum(e) => Some(json!({ "values": e.values })),
                    FieldAst::Image(s) | FieldAst::File(s) => Some(json!({ "bucket": s.bucket })),
                    FieldAst::Slug(s) => Some(json!({ "from": s.from })),
                    FieldAst::Text(t) if !t.sources.is_empty() || t.template.is_some() => {
                        let multiline = name.to_ascii_lowercase().contains("excerpt")
                            || name.to_ascii_lowercase().contains("summary")
                            || t.template.as_deref().is_some_and(|tpl| tpl.contains('\n'));
                        let mut m = serde_json::Map::new();
                        if !t.sources.is_empty() {
                            m.insert("sources".into(), json!(t.sources));
                        }
                        m.insert("multiline".into(), json!(multiline));
                        if let Some(ref tpl) = t.template {
                            m.insert("template".into(), json!(tpl));
                        }
                        Some(Value::Object(m))
                    }
                    FieldAst::Datetime(f) | FieldAst::Timestamp(f) | FieldAst::Date(f)
                        if matches!(&f.default, Some(DefaultValueAst::Now)) =>
                    {
                        Some(json!({ "studioTimestampDefault": "now" }))
                    }
                    FieldAst::Money(_) => Some(json!({ "currency": true, "step": "0.01" })),
                    FieldAst::Vector(v) => Some(json!({ "dimensions": v.dimensions })),
                    _ => None,
                };
                if let Some(opts) = options {
                    entry["options"] = opts;
                }

                if let Some(v) = field_validation(other) {
                    entry["validation"] = v;
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

/// Resolve a relation's target to the PostgREST table name (public schema).
/// System refs like "supatype:user" resolve to their canonical table names.
fn resolve_relation_target(rel: &RelationFieldAst, ast: &SchemaAst) -> String {
    if let Some((_sys_schema, sys_table)) = crate::parser::resolver::resolve_system_ref(&rel.target)
    {
        return sys_table.to_string();
    }
    ast.models
        .iter()
        .find(|m| m.name == rel.target)
        .map(|m| m.table_name().to_string())
        .unwrap_or_else(|| crate::parser::resolver::to_snake_case(&rel.target))
}

fn datetime_field(
    name: &str,
    required: bool,
    show_in_list: bool,
    filterable: bool,
    server_now_studio: bool,
) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("name".into(), json!(name));
    m.insert("label".into(), json!(to_label(name)));
    m.insert("widget".into(), json!("datetime"));
    m.insert("required".into(), json!(required));
    m.insert("showInList".into(), json!(show_in_list));
    m.insert("filterable".into(), json!(filterable));
    m.insert("sortable".into(), json!(true));
    m.insert("localized".into(), json!(false));
    if server_now_studio {
        m.insert("options".into(), json!({ "studioTimestampDefault": "now" }));
        m.insert("readOnly".into(), json!(true));
    }
    Value::Object(m)
}

// ─── Field attribute helpers ──────────────────────────────────────────────────

/// A point in WGS 84, the one geometry Studio edits as latitude and longitude. No SRID is WGS 84,
/// because the migration writes `GEOGRAPHY(POINT, 4326)` when none is given.
fn is_wgs84_point(geo: &crate::parser::ast::GeoFieldAst) -> bool {
    geo.geo_type.eq_ignore_ascii_case("point") && geo.srid.is_none_or(|srid| srid == 4326)
}

fn field_widget(field: &FieldAst) -> &'static str {
    match field {
        FieldAst::Text(s) if !s.sources.is_empty() || s.template.is_some() => "derivedText",
        FieldAst::Text(_) => "text",
        FieldAst::Color(_) => "color",
        FieldAst::RichText(_) => "richtext",
        FieldAst::Integer(_)
        | FieldAst::Float(_)
        | FieldAst::BigInt(_)
        | FieldAst::SmallInt(_)
        | FieldAst::Decimal(_) => "number",
        FieldAst::Money(_) => "number",
        FieldAst::Boolean(_) => "boolean",
        FieldAst::Datetime(_) => "datetime",
        FieldAst::Date(_) => "date",
        FieldAst::Timestamp(_) => "datetime",
        FieldAst::Uuid(_) => "uuid",
        FieldAst::Email(_) => "email",
        FieldAst::Slug(_) => "slug",
        FieldAst::Enum(_) => "select",
        FieldAst::Json(_) => "json",
        FieldAst::Button(_) => "button",
        FieldAst::Image(_) => "image",
        FieldAst::File(_) => "file",
        FieldAst::Geo(g) if is_wgs84_point(g) => "geopoint",
        FieldAst::Geo(_) => "text",
        FieldAst::Vector(_) => "text",
        FieldAst::Blocks(_) => "blocks",
        FieldAst::Url(_) => "url",
        FieldAst::Ip(_) | FieldAst::Cidr(_) | FieldAst::Macaddr(_) => "text",
        FieldAst::Interval(_) | FieldAst::TsQuery(_) | FieldAst::TsVector(_) => "text",
        FieldAst::Xml(_) => "xml",
        FieldAst::Array(_) => "json",
        FieldAst::BigSerial(_) | FieldAst::Serial(_) => "number",
        FieldAst::Bytes(_) => "text",
        _ => "text",
    }
}

/// A widget named by the schema, overriding the kind-based choice.
///
/// `annotations.platform.editor` has been parsed by this engine and read by nothing. It is the right
/// hook for a presentation choice the column type cannot express: `Code<"sql">` and
/// `Currency<"USD">` are both JSONB, so a widget picked from the kind alone gives them both the raw
/// JSON editor. An unknown value is ignored rather than trusted, since a widget name that Studio
/// cannot render would leave the field with no editor at all.
fn declared_widget(field: &FieldAst) -> Option<&'static str> {
    match field_annotations(field).platform.editor.as_deref() {
        Some("code") => Some("code"),
        Some("currency") => Some("currency"),
        Some("duration") => Some("duration"),
        Some("rich") => Some("richtext"),
        _ => None,
    }
}

/// Like `field_widget` but also applies name-based heuristics (e.g. colour picker).
fn field_widget_named(field: &FieldAst, name: &str) -> &'static str {
    if let Some(widget) = declared_widget(field) {
        return widget;
    }
    if let FieldAst::Text(s) = field {
        if !s.sources.is_empty() || s.template.is_some() {
            return "derivedText";
        }
    }
    if let FieldAst::Text(_) | FieldAst::Color(_) = field {
        let lower = name.to_lowercase();
        if lower.contains("color") || lower.contains("colour") {
            return "color";
        }
    }
    field_widget(field)
}

/// A scalar whose value reads as a short line in a list cell. The field config's `showInList` and
/// the model's `listColumns` both read this, so the two never disagree about a kind.
fn field_show_in_list(field: &FieldAst) -> bool {
    matches!(
        field,
        FieldAst::Text(_)
            | FieldAst::Color(_)
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
            | FieldAst::Decimal(_)
            | FieldAst::Timestamp(_)
            | FieldAst::Serial(_)
            | FieldAst::BigSerial(_)
            | FieldAst::Interval(_)
            | FieldAst::Ip(_)
            | FieldAst::Cidr(_)
            | FieldAst::Macaddr(_)
    )
}

fn field_filterable(field: &FieldAst) -> bool {
    matches!(
        field,
        FieldAst::Text(_)
            | FieldAst::Color(_)
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
            | FieldAst::Color(_)
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

/// Studio-facing bounds for a field, or `None` when it declares no constraint modifier.
///
/// Studio widgets have read `config.validation` since the admin panel was built; until this existed
/// nothing wrote the key, so a `MaxLength<string, 120>` reached the editor as an unbounded input and
/// surfaced only as a database error on save.
fn field_validation(field: &FieldAst) -> Option<Value> {
    let validation = match field {
        FieldAst::Slug(f) => f.validation.as_ref(),
        FieldAst::Decimal(f) => f.validation.as_ref(),
        FieldAst::Json(f) | FieldAst::Button(f) => f.validation.as_ref(),
        FieldAst::Array(f) => f.validation.as_ref(),
        FieldAst::Blocks(f) => f.validation.as_ref(),
        other => scalar_of(other).and_then(|f| f.validation.as_ref()),
    }?;

    if validation.is_empty() {
        return None;
    }

    let mut m = serde_json::Map::new();
    if let Some(v) = validation.max_length {
        m.insert("maxLength".into(), json!(v));
    }
    if let Some(v) = validation.min_length {
        m.insert("minLength".into(), json!(v));
    }
    if let Some(v) = validation.max_items {
        m.insert("maxItems".into(), json!(v));
    }
    if let Some(v) = validation.min_items {
        m.insert("minItems".into(), json!(v));
    }
    if let Some(v) = validation.min.as_ref() {
        m.insert("min".into(), v.clone());
    }
    if let Some(v) = validation.max.as_ref() {
        m.insert("max".into(), v.clone());
    }
    Some(Value::Object(m))
}

fn field_required_flag(field: &FieldAst) -> bool {
    match field {
        FieldAst::Datetime(f) | FieldAst::Timestamp(f) | FieldAst::Date(f) => {
            if matches!(&f.default, Some(DefaultValueAst::Now)) {
                // DB fills NOT NULL timestamps; Studio skips required + can pre-fill preview.
                return false;
            }
            f.required
        }
        FieldAst::Text(f)
        | FieldAst::Color(f)
        | FieldAst::Email(f)
        | FieldAst::Bytes(f)
        | FieldAst::RichText(f)
        | FieldAst::Integer(f)
        | FieldAst::Float(f)
        | FieldAst::BigInt(f)
        | FieldAst::Boolean(f)
        | FieldAst::Uuid(f)
        | FieldAst::SmallInt(f)
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
        FieldAst::Button(f) => f.required,
        FieldAst::Decimal(f) => f.required,
        FieldAst::Image(f) | FieldAst::File(f) => f.required,
        FieldAst::Geo(f) => f.required,
        FieldAst::Vector(f) => f.required,
        FieldAst::Blocks(f) => f.required,
        // A plugin field's column is NOT NULL when required, so Studio must ask for it rather than
        // send a blank the database refuses.
        FieldAst::Custom(f) => f.required,
        _ => false,
    }
}

fn field_is_localized(field: &FieldAst) -> bool {
    match field {
        FieldAst::Text(f)
        | FieldAst::Color(f)
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
        FieldAst::Button(f) => f.localized,
        FieldAst::Decimal(f) => f.localized,
        FieldAst::Money(f) => f.localized,
        FieldAst::Image(f) | FieldAst::File(f) => f.localized,
        FieldAst::Blocks(f) => f.localized,
        _ => false,
    }
}

fn field_is_read_only(field: &FieldAst) -> bool {
    match field {
        FieldAst::Text(f)
        | FieldAst::Color(f)
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
        | FieldAst::Xml(f) => f.read_only,
        FieldAst::Slug(f) => f.read_only,
        FieldAst::Enum(f) => f.read_only,
        FieldAst::Json(f) => f.read_only,
        FieldAst::Button(f) => f.read_only,
        FieldAst::Decimal(f) => f.read_only,
        FieldAst::Image(f) | FieldAst::File(f) => f.read_only,
        FieldAst::Geo(f) => f.read_only,
        FieldAst::Vector(f) => f.read_only,
        FieldAst::Blocks(f) => f.read_only,
        FieldAst::Relation(f) => f.read_only,
        FieldAst::Array(f) => f.read_only,
        FieldAst::Custom(f) => f.read_only,
        _ => false,
    }
}

/// DB-assigned columns (defaults, sequences, audit timestamps), read-only in Studio.
fn field_is_server_managed(field: &FieldAst) -> bool {
    match field {
        FieldAst::Datetime(f) | FieldAst::Timestamp(f) | FieldAst::Date(f) => {
            matches!(f.default, Some(DefaultValueAst::Now)) || f.annotations.db.server_generated
        }
        FieldAst::Uuid(f) => {
            f.primary_key || matches!(f.default, Some(DefaultValueAst::GenRandomUuid))
        }
        FieldAst::Serial(_) | FieldAst::BigSerial(_) => true,
        other => crate::parser::accessors::database_fills(other),
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

/// The model's columns that hold one value per locale.
///
/// Studio needs these to offer publishing per locale: a control that says "publish English" has to
/// know which columns English is a key of.
fn localized_column_names(model: &ModelAst) -> Vec<String> {
    model
        .fields
        .iter()
        .filter(|(_, field)| crate::parser::accessors::is_localized(field))
        .flat_map(|(name, field)| crate::parser::accessors::column_names_for(name, field))
        .filter(|name| !name.is_empty())
        .collect()
}
