use super::{Operation, Risk};
use crate::introspector::tables::{DbColumn, DbTable};
use crate::parser::ast::{FieldAst, IndexAst, IndexMethod, ModelAst, RelationCardinality};
use anyhow::Result;
use serde_json::json;
use strsim::jaro_winkler;

const RENAME_THRESHOLD: f64 = 0.7;

/// Returns the effective column name(s) produced by a field.
/// Relations produce a FK column name; composites produce multiple.
fn column_names_for(field_name: &str, field: &FieldAst) -> Vec<String> {
    match field {
        FieldAst::Relation(rel) => match rel.cardinality {
            RelationCardinality::BelongsTo => {
                vec![rel
                    .foreign_key
                    .clone()
                    .unwrap_or_else(|| format!("{field_name}_id"))]
            }
            _ => vec![],
        },
        FieldAst::Timestamps => vec!["created_at".into(), "updated_at".into()],
        FieldAst::Publishable => vec![
            "status".into(),
            "published_at".into(),
            "scheduled_at".into(),
        ],
        FieldAst::SoftDelete => vec!["deleted_at".into()],
        _ => vec![field_name.to_string()],
    }
}

/// Returns true if the field has `index: true` set.
fn has_index_flag(field: &FieldAst) -> bool {
    match field {
        FieldAst::Text(f)
        | FieldAst::Email(f)
        | FieldAst::Uuid(f)
        | FieldAst::Integer(f)
        | FieldAst::Float(f)
        | FieldAst::Boolean(f)
        | FieldAst::Datetime(f)
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
        | FieldAst::Xml(f)
        | FieldAst::RichText(f)
        | FieldAst::Color(f) => f.index,
        FieldAst::Custom(f) => f.index,
        _ => false,
    }
}

/// Returns whether the schema field requires the DB column to be NOT NULL.
fn field_required(field: &FieldAst) -> Option<bool> {
    match field {
        FieldAst::Text(f)
        | FieldAst::Email(f)
        | FieldAst::Url(f)
        | FieldAst::Uuid(f)
        | FieldAst::Integer(f)
        | FieldAst::Float(f)
        | FieldAst::Boolean(f)
        | FieldAst::Datetime(f)
        | FieldAst::BigInt(f)
        | FieldAst::SmallInt(f)
        | FieldAst::Date(f)
        | FieldAst::Timestamp(f)
        | FieldAst::Serial(f)
        | FieldAst::BigSerial(f)
        | FieldAst::Money(f)
        | FieldAst::Ip(f)
        | FieldAst::Cidr(f)
        | FieldAst::Macaddr(f)
        | FieldAst::Interval(f)
        | FieldAst::TsQuery(f)
        | FieldAst::TsVector(f)
        | FieldAst::Xml(f)
        | FieldAst::RichText(f)
        | FieldAst::Bytes(f)
        | FieldAst::Color(f) => Some(f.required),
        FieldAst::Slug(f) => Some(f.required),
        FieldAst::Enum(f) => Some(f.required),
        FieldAst::Json(f) => Some(f.required),
        FieldAst::Decimal(f) => Some(f.required),
        FieldAst::Geo(f) => Some(f.required),
        FieldAst::Vector(f) => Some(f.required),
        FieldAst::Array(f) => Some(f.required),
        FieldAst::Image(f) | FieldAst::File(f) => Some(f.required),
        FieldAst::Custom(f) => Some(f.required),
        // Composites / relations don't map directly to a single column required flag
        _ => None,
    }
}

/// Returns true if a scalar field has `localized: true`.
fn is_localized(field: &FieldAst) -> bool {
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
        | FieldAst::Uuid(f)
        | FieldAst::Color(f) => f.localized,
        FieldAst::Slug(f) => f.localized,
        FieldAst::Enum(f) => f.localized,
        FieldAst::Json(f) => f.localized,
        FieldAst::Decimal(f) => f.localized,
        FieldAst::Money(f) => f.localized,
        _ => false,
    }
}

/// Returns true if the field is text-like (meaning a JSONB DB column is likely a localized version).
fn is_text_like(field: &FieldAst) -> bool {
    matches!(
        field,
        FieldAst::Text(_)
            | FieldAst::Color(_)
            | FieldAst::Email(_)
            | FieldAst::Url(_)
            | FieldAst::Slug(_)
            | FieldAst::Xml(_)
            | FieldAst::Enum(_)
            | FieldAst::Integer(_)
            | FieldAst::Float(_)
            | FieldAst::BigInt(_)
            | FieldAst::SmallInt(_)
            | FieldAst::Boolean(_)
            | FieldAst::Datetime(_)
            | FieldAst::Date(_)
            | FieldAst::Decimal(_)
    )
}

/// Returns the expected Postgres udt_name for a schema field.
/// Returns None for fields where type comparison is not straightforward (Decimal, Money, Geo, Vector, Array).
fn expected_udt(field: &FieldAst) -> Option<&'static str> {
    // Localized fields are always JSONB in the DB.
    if is_localized(field) {
        return Some("jsonb");
    }
    match field {
        FieldAst::Text(f) if f.pg_type.is_empty() => Some("text"),
        FieldAst::Text(_) => None, // custom pg_type — skip comparison
        FieldAst::Color(_)
        | FieldAst::Email(_)
        | FieldAst::Url(_)
        | FieldAst::Slug(_)
        | FieldAst::Xml(_)
        | FieldAst::Enum(_) => Some("text"),
        FieldAst::RichText(_)
        | FieldAst::Json(_)
        | FieldAst::Image(_)
        | FieldAst::File(_)
        | FieldAst::Blocks(_) => Some("jsonb"),
        FieldAst::Bytes(_) => Some("bytea"),
        FieldAst::Integer(_) | FieldAst::Serial(_) => Some("int4"),
        FieldAst::SmallInt(_) => Some("int2"),
        FieldAst::BigInt(_) | FieldAst::BigSerial(_) => Some("int8"),
        FieldAst::Float(_) => Some("float8"),
        FieldAst::Boolean(_) => Some("bool"),
        FieldAst::Uuid(_) => Some("uuid"),
        FieldAst::Datetime(_) => Some("timestamptz"),
        FieldAst::Date(_) => Some("date"),
        FieldAst::Timestamp(_) => Some("timestamp"),
        FieldAst::Ip(_) => Some("inet"),
        FieldAst::Cidr(_) => Some("cidr"),
        FieldAst::Macaddr(_) => Some("macaddr"),
        FieldAst::Interval(_) => Some("interval"),
        FieldAst::TsQuery(_) => Some("tsquery"),
        FieldAst::TsVector(_) => Some("tsvector"),
        // These use complex types — skip udt comparison
        _ => None,
    }
}

/// Returns the Postgres type keyword for ALTER COLUMN TYPE ... USING casts.
fn field_pg_type(field: &FieldAst) -> &'static str {
    if is_localized(field) {
        return "JSONB";
    }
    match field {
        FieldAst::Text(_)
        | FieldAst::Color(_)
        | FieldAst::Email(_)
        | FieldAst::Url(_)
        | FieldAst::Slug(_)
        | FieldAst::Xml(_)
        | FieldAst::Enum(_) => "TEXT",
        FieldAst::RichText(_)
        | FieldAst::Json(_)
        | FieldAst::Image(_)
        | FieldAst::File(_)
        | FieldAst::Blocks(_) => "JSONB",
        FieldAst::Bytes(_) => "BYTEA",
        FieldAst::Integer(_) | FieldAst::Serial(_) => "INTEGER",
        FieldAst::SmallInt(_) => "SMALLINT",
        FieldAst::BigInt(_) | FieldAst::BigSerial(_) => "BIGINT",
        FieldAst::Float(_) => "DOUBLE PRECISION",
        FieldAst::Boolean(_) => "BOOLEAN",
        FieldAst::Uuid(_) => "UUID",
        FieldAst::Datetime(_) => "TIMESTAMPTZ",
        FieldAst::Date(_) => "DATE",
        FieldAst::Timestamp(_) => "TIMESTAMP",
        FieldAst::Ip(_) => "INET",
        FieldAst::Cidr(_) => "CIDR",
        FieldAst::Macaddr(_) => "MACADDR",
        FieldAst::Interval(_) => "INTERVAL",
        FieldAst::TsQuery(_) => "TSQUERY",
        FieldAst::TsVector(_) => "TSVECTOR",
        _ => "TEXT",
    }
}

/// Returns true if changing from `from_udt` to `to_pg_type` is a safe widening
/// that Postgres will accept without a USING cast and without data loss.
fn is_safe_widening(from_udt: &str, to_pg: &str) -> bool {
    matches!(
        (from_udt, to_pg.to_uppercase().as_str()),
        ("int2", "INTEGER")
            | ("int2", "BIGINT")
            | ("int4", "BIGINT")
            | ("float4", "DOUBLE PRECISION")
            | ("varchar", "TEXT")
            | ("bpchar", "TEXT")
    )
}

/// Compares a schema field against the live DB column and returns a JSON object
/// describing the changes needed, or serde_json::Value::Null if nothing changed.
fn detect_changes(field: &FieldAst, db_col: &DbColumn, default_locale: &str) -> serde_json::Value {
    let mut changes = serde_json::Map::new();

    // Nullability change
    if let Some(required) = field_required(field) {
        let schema_nullable = !required;
        let db_nullable = db_col.nullable;
        if schema_nullable != db_nullable {
            changes.insert(
                "nullability".into(),
                json!({
                    "from": if db_nullable { "nullable" } else { "not_null" },
                    "to": if schema_nullable { "nullable" } else { "not_null" }
                }),
            );
        }
    }

    // Type change
    if let Some(expected) = expected_udt(field) {
        let actual = db_col.udt_name.as_str();
        if expected != actual {
            let pg_type = field_pg_type(field);
            let safe = is_safe_widening(actual, pg_type);
            changes.insert(
                "type".into(),
                json!({
                    "from_udt": actual,
                    "to_pg": pg_type,
                    "safe_widening": safe
                }),
            );

            // Localization metadata — used by migration.rs to choose the right USING clause.
            if is_localized(field) && actual != "jsonb" {
                // Adding localization: text-like → JSONB
                changes.insert(
                    "localization".into(),
                    json!({
                        "direction": "add",
                        "default_locale": default_locale
                    }),
                );
            } else if !is_localized(field) && actual == "jsonb" && is_text_like(field) {
                // Removing localization: JSONB → text-like (destructive — translations lost)
                changes.insert(
                    "localization".into(),
                    json!({
                        "direction": "remove",
                        "default_locale": default_locale
                    }),
                );
            }
        }
    }

    if changes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Object(changes)
    }
}

/// Classifies the risk of an AlterColumn operation.
fn changes_risk(changes: &serde_json::Value) -> Risk {
    // NULL → NOT NULL is cautious (may fail if NULLs exist)
    if let Some(null_change) = changes.get("nullability") {
        if null_change.get("to").and_then(|v| v.as_str()) == Some("not_null") {
            return Risk::Cautious;
        }
    }
    // Type change
    if let Some(type_change) = changes.get("type") {
        // Removing localization (JSONB → text) is destructive — translations are lost
        if let Some(loc) = changes.get("localization") {
            if loc.get("direction").and_then(|v| v.as_str()) == Some("remove") {
                return Risk::Destructive;
            }
            // Adding localization (text → JSONB) is cautious — data transformation
            return Risk::Cautious;
        }
        if type_change.get("safe_widening").and_then(|v| v.as_bool()) == Some(true) {
            return Risk::Safe;
        }
        return Risk::Cautious; // potentially lossy
    }
    Risk::Safe
}

/// Generates a human-readable warning for an AlterColumn operation.
fn changes_warning(table: &str, column: &str, changes: &serde_json::Value) -> Option<String> {
    let mut parts = Vec::new();

    if let Some(null_change) = changes.get("nullability") {
        if null_change.get("to").and_then(|v| v.as_str()) == Some("not_null") {
            parts.push(format!(
                "{table}.{column}: setting NOT NULL — migration will fail if NULL values exist"
            ));
        }
    }

    if let Some(_type_change) = changes.get("type") {
        if let Some(loc) = changes.get("localization") {
            let locale = loc
                .get("default_locale")
                .and_then(|v| v.as_str())
                .unwrap_or("en");
            let direction = loc
                .get("direction")
                .and_then(|v| v.as_str())
                .unwrap_or("add");
            if direction == "add" {
                parts.push(format!(
                    "{table}.{column}: converting to localized field — existing values will be \
                     assigned to locale '{locale}'. No data loss (cautious)."
                ));
            } else {
                parts.push(format!(
                    "{table}.{column}: REMOVING localization — only the '{locale}' locale value \
                     will be preserved. Translations in other locales will be permanently lost. \
                     Use --force to proceed (destructive)."
                ));
            }
        } else {
            let from = _type_change
                .get("from_udt")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let to = _type_change
                .get("to_pg")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let safe = _type_change
                .get("safe_widening")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if safe {
                parts.push(format!(
                    "{table}.{column}: safe type widening {from} → {to}"
                ));
            } else {
                parts.push(format!(
                    "{table}.{column}: type change {from} → {to} may be lossy — verify data before applying"
                ));
            }
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

pub fn diff(
    model: &ModelAst,
    db_table: &DbTable,
    ops: &mut Vec<Operation>,
    warnings: &mut Vec<String>,
    default_locale: &str,
) -> Result<()> {
    let db_col_names: std::collections::HashSet<String> =
        db_table.columns.iter().map(|c| c.name.clone()).collect();

    // Expand schema fields to the actual DB columns they produce
    let schema_columns: std::collections::HashMap<String, (&str, &FieldAst)> = model
        .fields
        .iter()
        .flat_map(|(name, field)| {
            column_names_for(name, field)
                .into_iter()
                .map(move |col| (col, (name.as_str(), field)))
        })
        .collect();

    // Columns added by model options (not explicit fields) must not be treated as dropped.
    let mut options_cols: std::collections::HashSet<String> = std::collections::HashSet::new();
    if model.options.timestamps && !model.fields.contains_key("timestamps") {
        options_cols.insert("created_at".into());
        options_cols.insert("updated_at".into());
    }
    if model.options.soft_delete && !model.fields.contains_key("softDelete") {
        options_cols.insert("deleted_at".into());
    }

    let schema_col_names: std::collections::HashSet<&str> =
        schema_columns.keys().map(|s| s.as_str()).collect();

    let added: Vec<&str> = schema_columns
        .keys()
        .filter(|n| !db_col_names.contains(*n))
        .map(|s| s.as_str())
        .collect();

    let dropped: Vec<&str> = db_table
        .columns
        .iter()
        .filter(|c| !schema_col_names.contains(c.name.as_str()) && !options_cols.contains(&c.name))
        .map(|c| c.name.as_str())
        .collect();

    // ─── Rename detection ───────────────────────────────────────────────────

    let mut renamed_dropped = std::collections::HashSet::new();
    let mut renamed_added = std::collections::HashSet::new();

    for &drop in &dropped {
        if let Some(&add) = added
            .iter()
            .filter(|&&a| !renamed_added.contains(a))
            .max_by(|&&a, &&b| {
                jaro_winkler(drop, a)
                    .partial_cmp(&jaro_winkler(drop, b))
                    .unwrap()
            })
        {
            if jaro_winkler(drop, add) >= RENAME_THRESHOLD {
                ops.push(Operation::RenameColumn {
                    table: model.table_name.clone(),
                    from: drop.to_string(),
                    to: add.to_string(),
                    risk: Risk::Safe,
                });
                warnings.push(format!(
                    "Column '{drop}' removed and '{add}' added on table '{}'. Treating as rename. \
                     Specify in platform.renames.json to suppress this warning.",
                    model.table_name
                ));
                renamed_dropped.insert(drop);
                renamed_added.insert(add);
            }
        }
    }

    // ─── Added columns ──────────────────────────────────────────────────────

    for col in &added {
        if !renamed_added.contains(*col) {
            if let Some((_, field)) = schema_columns.get(*col) {
                ops.push(Operation::AddColumn {
                    table: model.table_name.clone(),
                    column: col.to_string(),
                    field: Box::new((*field).clone()),
                    risk: Risk::Safe,
                });

                // If the field has `index: true` and it's a new column, also emit AddIndex.
                if has_index_flag(field) {
                    ops.push(Operation::AddIndex {
                        table: model.table_name.clone(),
                        index: Box::new(IndexAst {
                            name: None,
                            fields: vec![col.to_string()],
                            unique: false,
                            using: IndexMethod::Btree,
                        }),
                        risk: Risk::Safe,
                    });
                }
            }
        }
    }

    // ─── Dropped columns ────────────────────────────────────────────────────

    for col in &dropped {
        if !renamed_dropped.contains(*col) {
            ops.push(Operation::DropColumn {
                table: model.table_name.clone(),
                column: col.to_string(),
                risk: Risk::Destructive,
            });
        }
    }

    // ─── Modified columns (AlterColumn detection) ───────────────────────────

    // Only consider columns that exist in both schema and DB and were not renamed.
    let db_col_map: std::collections::HashMap<&str, &DbColumn> = db_table
        .columns
        .iter()
        .map(|c| (c.name.as_str(), c))
        .collect();

    for (col_name, (_, field)) in &schema_columns {
        // Skip composite / relation pseudo-columns and options columns
        if options_cols.contains(col_name.as_str()) {
            continue;
        }
        // Skip if this column was renamed, added, or dropped
        if renamed_added.contains(col_name.as_str()) {
            continue;
        }
        if !db_col_names.contains(col_name) {
            continue;
        }

        if let Some(db_col) = db_col_map.get(col_name.as_str()) {
            let changes = detect_changes(field, db_col, default_locale);
            if !changes.is_null() {
                let risk = changes_risk(&changes);
                let warning = changes_warning(&model.table_name, col_name, &changes);
                if let Some(ref w) = warning {
                    warnings.push(w.clone());
                }
                ops.push(Operation::AlterColumn {
                    table: model.table_name.clone(),
                    column: col_name.clone(),
                    changes,
                    risk,
                    warning,
                });
            }
        }
    }

    Ok(())
}
