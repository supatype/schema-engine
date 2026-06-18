use super::{ColumnDependencySnapshot, Operation, Risk};
use crate::generator::sql::column_conversion::{
    self, add_column_backfill_default, plan_type_conversion, required_field_existing_table_warning,
    supports_kind_data_migration, ConversionStrategyKind,
};
use crate::introspector::constraints::DbConstraintType;
use crate::introspector::tables::{DbColumn, DbTable};
use crate::parser::ast::{FieldAst, IndexAst, IndexMethod, ModelAst, RelationCardinality};
use crate::state::database_state::DatabaseState;
use anyhow::{bail, Result};
use serde_json::json;
use strsim::jaro_winkler;

const RENAME_THRESHOLD: f64 = 0.7;

pub fn column_names_for(field_name: &str, field: &FieldAst) -> Vec<String> {
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
        _ => None,
    }
}

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
        FieldAst::Button(f) => f.localized,
        FieldAst::Decimal(f) => f.localized,
        FieldAst::Money(f) => f.localized,
        FieldAst::Image(f) | FieldAst::File(f) => f.localized,
        FieldAst::Blocks(f) => f.localized,
        _ => false,
    }
}

pub fn field_kind(field: &FieldAst) -> Option<&'static str> {
    match field {
        FieldAst::Text(_) => Some("text"),
        FieldAst::RichText(_) => Some("richText"),
        FieldAst::Json(_) => Some("json"),
        FieldAst::Button(_) => Some("button"),
        FieldAst::Blocks(_) => Some("blocks"),
        FieldAst::Image(_) => Some("image"),
        FieldAst::File(_) => Some("file"),
        FieldAst::Email(_) => Some("email"),
        FieldAst::Url(_) => Some("url"),
        FieldAst::Slug(_) => Some("slug"),
        FieldAst::Xml(_) => Some("xml"),
        FieldAst::Enum(_) => Some("enum"),
        FieldAst::Integer(_) => Some("integer"),
        FieldAst::Float(_) => Some("float"),
        FieldAst::Boolean(_) => Some("boolean"),
        FieldAst::Uuid(_) => Some("uuid"),
        FieldAst::Datetime(_) => Some("datetime"),
        FieldAst::Date(_) => Some("date"),
        FieldAst::Timestamp(_) => Some("timestamp"),
        FieldAst::BigInt(_) => Some("bigInt"),
        FieldAst::SmallInt(_) => Some("smallInt"),
        FieldAst::Bytes(_) => Some("bytes"),
        FieldAst::Color(_) => Some("color"),
        FieldAst::Decimal(_) => Some("decimal"),
        FieldAst::Money(_) => Some("money"),
        FieldAst::Geo(_) => Some("geo"),
        FieldAst::Vector(_) => Some("vector"),
        FieldAst::Array(_) => Some("array"),
        FieldAst::Custom(_) => None,
        _ => None,
    }
}

fn field_for_column<'a>(model: &'a ModelAst, col_name: &str) -> Option<&'a FieldAst> {
    for (name, field) in &model.fields {
        if column_names_for(name, field).iter().any(|c| c == col_name) {
            return Some(field);
        }
    }
    None
}

fn field_migration_kind(field: &FieldAst) -> Option<&'static str> {
    match field {
        FieldAst::RichText(_) => Some("richText"),
        FieldAst::Json(_) => Some("json"),
        FieldAst::Button(_) => Some("button"),
        FieldAst::Blocks(_) => Some("blocks"),
        FieldAst::Image(_) => Some("image"),
        FieldAst::File(_) => Some("file"),
        _ => None,
    }
}

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

fn array_element_udt(element_type: &str) -> &'static str {
    match element_type.to_uppercase().as_str() {
        "TEXT" | "VARCHAR" | "CHARACTER VARYING" => "_text",
        "INTEGER" | "INT" | "INT4" => "_int4",
        "BIGINT" | "INT8" => "_int8",
        "SMALLINT" | "INT2" => "_int2",
        "UUID" => "_uuid",
        "BOOLEAN" | "BOOL" => "_bool",
        "DOUBLE PRECISION" | "FLOAT8" => "_float8",
        "REAL" | "FLOAT4" => "_float4",
        _ => "_text",
    }
}

fn expected_udt(field: &FieldAst) -> Option<String> {
    if is_localized(field) {
        return Some("jsonb".into());
    }
    match field {
        FieldAst::Text(f) if !f.pg_type.is_empty() => Some(f.pg_type.to_lowercase()),
        FieldAst::Text(_) => Some("text".into()),
        FieldAst::Color(_)
        | FieldAst::Email(_)
        | FieldAst::Url(_)
        | FieldAst::Slug(_)
        | FieldAst::Xml(_)
        | FieldAst::Enum(_) => Some("text".into()),
        FieldAst::RichText(_)
        | FieldAst::Json(_)
        | FieldAst::Image(_)
        | FieldAst::File(_)
        | FieldAst::Blocks(_) => Some("jsonb".into()),
        FieldAst::Bytes(_) => Some("bytea".into()),
        FieldAst::Integer(_) | FieldAst::Serial(_) => Some("int4".into()),
        FieldAst::SmallInt(_) => Some("int2".into()),
        FieldAst::BigInt(_) | FieldAst::BigSerial(_) => Some("int8".into()),
        FieldAst::Float(_) => Some("float8".into()),
        FieldAst::Boolean(_) => Some("bool".into()),
        FieldAst::Uuid(_) => Some("uuid".into()),
        FieldAst::Datetime(_) => Some("timestamptz".into()),
        FieldAst::Date(_) => Some("date".into()),
        FieldAst::Timestamp(_) => Some("timestamp".into()),
        FieldAst::Ip(_) => Some("inet".into()),
        FieldAst::Cidr(_) => Some("cidr".into()),
        FieldAst::Macaddr(_) => Some("macaddr".into()),
        FieldAst::Interval(_) => Some("interval".into()),
        FieldAst::TsQuery(_) => Some("tsquery".into()),
        FieldAst::TsVector(_) => Some("tsvector".into()),
        FieldAst::Decimal(_) | FieldAst::Money(_) => Some("numeric".into()),
        FieldAst::Array(a) => Some(array_element_udt(&a.element_type).into()),
        FieldAst::Geo(_) => Some("geography".into()),
        FieldAst::Vector(_) => Some("vector".into()),
        FieldAst::Custom(c) => Some(c.pg_type.to_lowercase()),
        _ => None,
    }
}

fn column_type_matches(field: &FieldAst, db_col: &DbColumn) -> bool {
    let Some(expected) = expected_udt(field) else {
        return true;
    };
    if db_col.udt_name != expected {
        return false;
    }
    match field {
        FieldAst::Decimal(d) => {
            let want = match (d.precision, d.scale) {
                (Some(p), Some(s)) => format!("numeric({p},{s})"),
                (Some(p), None) => format!("numeric({p})"),
                _ => "numeric".into(),
            };
            db_col.data_type.to_lowercase().replace(' ', "") == want.replace(' ', "")
        }
        FieldAst::Vector(v) => db_col
            .data_type
            .to_lowercase()
            .contains(&format!("vector({})", v.dimensions)),
        FieldAst::Geo(g) => db_col
            .data_type
            .to_lowercase()
            .contains(&g.geo_type.to_lowercase()),
        _ => true,
    }
}

fn field_pg_type(field: &FieldAst) -> String {
    if is_localized(field) {
        return "JSONB".into();
    }
    match field {
        FieldAst::Text(f) if !f.pg_type.is_empty() => f.pg_type.to_uppercase(),
        FieldAst::Text(_)
        | FieldAst::Color(_)
        | FieldAst::Email(_)
        | FieldAst::Url(_)
        | FieldAst::Slug(_)
        | FieldAst::Xml(_)
        | FieldAst::Enum(_) => "TEXT".into(),
        FieldAst::RichText(_)
        | FieldAst::Json(_)
        | FieldAst::Image(_)
        | FieldAst::File(_)
        | FieldAst::Blocks(_) => "JSONB".into(),
        FieldAst::Bytes(_) => "BYTEA".into(),
        FieldAst::Integer(_) | FieldAst::Serial(_) => "INTEGER".into(),
        FieldAst::SmallInt(_) => "SMALLINT".into(),
        FieldAst::BigInt(_) | FieldAst::BigSerial(_) => "BIGINT".into(),
        FieldAst::Float(_) => "DOUBLE PRECISION".into(),
        FieldAst::Boolean(_) => "BOOLEAN".into(),
        FieldAst::Uuid(_) => "UUID".into(),
        FieldAst::Datetime(_) => "TIMESTAMPTZ".into(),
        FieldAst::Date(_) => "DATE".into(),
        FieldAst::Timestamp(_) => "TIMESTAMP".into(),
        FieldAst::Ip(_) => "INET".into(),
        FieldAst::Cidr(_) => "CIDR".into(),
        FieldAst::Macaddr(_) => "MACADDR".into(),
        FieldAst::Interval(_) => "INTERVAL".into(),
        FieldAst::TsQuery(_) => "TSQUERY".into(),
        FieldAst::TsVector(_) => "TSVECTOR".into(),
        FieldAst::Decimal(d) => match (d.precision, d.scale) {
            (Some(p), Some(s)) => format!("NUMERIC({p}, {s})"),
            (Some(p), None) => format!("NUMERIC({p})"),
            _ => "NUMERIC".into(),
        },
        FieldAst::Money(_) => "NUMERIC(19,4)".into(),
        FieldAst::Array(a) => format!("{}[]", a.element_type.to_uppercase()),
        FieldAst::Geo(g) => {
            let srid = g.srid.unwrap_or(4326);
            format!("GEOGRAPHY({}, {})", g.geo_type.to_uppercase(), srid)
        }
        FieldAst::Vector(v) => format!("vector({})", v.dimensions),
        FieldAst::Custom(c) => c.pg_type.to_uppercase(),
        _ => "TEXT".into(),
    }
}

pub fn discover_column_dependencies(
    table: &str,
    column: &str,
    db: &DatabaseState,
) -> Vec<ColumnDependencySnapshot> {
    let mut deps = Vec::new();

    for c in &db.constraints {
        if c.constraint_type != DbConstraintType::ForeignKey {
            continue;
        }
        let is_outgoing = c.table == table && c.columns.iter().any(|col| col == column);
        let is_incoming = c.foreign_table.as_deref() == Some(table)
            && c.foreign_columns
                .as_ref()
                .is_some_and(|cols| cols.iter().any(|col| col == column));
        if is_outgoing || is_incoming {
            deps.push(ColumnDependencySnapshot {
                kind: "foreign_key".into(),
                table: c.table.clone(),
                name: c.name.clone(),
                columns: Some(c.columns.clone()),
                foreign_table: c.foreign_table.clone(),
                foreign_columns: c.foreign_columns.clone(),
                on_delete: c.on_delete.clone(),
                unique: false,
                index_method: None,
            });
        }
    }

    for idx in &db.indexes {
        if idx.table == table && idx.columns.iter().any(|c| c == column) && !idx.is_primary {
            deps.push(ColumnDependencySnapshot {
                kind: "index".into(),
                table: idx.table.clone(),
                name: idx.name.clone(),
                columns: Some(idx.columns.clone()),
                foreign_table: None,
                foreign_columns: None,
                on_delete: None,
                unique: idx.unique,
                index_method: Some(idx.method.clone()),
            });
        }
    }

    deps
}

fn detect_changes(
    field: &FieldAst,
    db_col: &DbColumn,
    default_locale: &str,
    previous_field: Option<&FieldAst>,
    table: &str,
    schema: &str,
) -> serde_json::Value {
    let mut changes = serde_json::Map::new();

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

    let type_changed = !column_type_matches(field, db_col);

    if type_changed {
        let pg_type = field_pg_type(field);
        let actual = db_col.udt_name.as_str();
        let safe = column_conversion::is_safe_widening(actual, &pg_type);
        let from_kind = previous_field.and_then(field_kind);
        let to_kind = field_migration_kind(field).or_else(|| field_kind(field));

        let mut type_change = json!({
            "from_udt": actual,
            "to_pg": pg_type,
            "safe_widening": safe
        });
        if let Some(k) = to_kind {
            type_change["to_kind"] = json!(k);
        }
        if let Some(k) = from_kind {
            type_change["from_kind"] = json!(k);
        }
        changes.insert("type".into(), type_change);

        if is_localized(field) && actual != "jsonb" {
            changes.insert(
                "localization".into(),
                json!({
                    "direction": "add",
                    "default_locale": default_locale
                }),
            );
        } else if !is_localized(field)
            && actual == "jsonb"
            && is_text_like(field)
            && previous_field.map(is_localized).unwrap_or(false)
        {
            changes.insert(
                "localization".into(),
                json!({
                    "direction": "remove",
                    "default_locale": default_locale
                }),
            );
        }
    } else if let Some(prev) = previous_field {
        if let (Some(from), Some(to)) = (field_kind(prev), field_kind(field)) {
            if from != to && supports_kind_data_migration(from, to) {
                changes.insert("kind_change".into(), json!({ "from": from, "to": to }));
            }
        }
    }

    if changes.is_empty() {
        return serde_json::Value::Null;
    }

    let changes_val = serde_json::Value::Object(changes.clone());
    if changes.contains_key("type") || changes.contains_key("kind_change") {
        let from_udt = changes
            .get("type")
            .and_then(|t| t.get("from_udt"))
            .and_then(|v| v.as_str())
            .unwrap_or(db_col.udt_name.as_str());
        let to_pg = changes
            .get("type")
            .and_then(|t| t.get("to_pg"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| field_pg_type(field));
        let from_kind = changes
            .get("type")
            .and_then(|t| t.get("from_kind"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                changes
                    .get("kind_change")
                    .and_then(|k| k.get("from"))
                    .and_then(|v| v.as_str())
            });
        let to_kind = changes
            .get("type")
            .and_then(|t| t.get("to_kind"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                changes
                    .get("kind_change")
                    .and_then(|k| k.get("to"))
                    .and_then(|v| v.as_str())
            });

        let strategy = if changes.contains_key("kind_change") && !changes.contains_key("type") {
            column_conversion::ConversionStrategy {
                kind: ConversionStrategyKind::KindMigrate,
                using_expr: None,
                pre_update: None,
                blocked_reason: None,
            }
        } else {
            plan_type_conversion(
                table,
                &db_col.name,
                schema,
                from_udt,
                &to_pg,
                from_kind,
                to_kind,
                &changes_val,
                field,
            )
        };

        if strategy.kind == ConversionStrategyKind::Blocked {
            changes.insert(
                "blocked".into(),
                json!(strategy.blocked_reason.unwrap_or_default()),
            );
        } else {
            changes.insert(
                "conversion".into(),
                json!({
                    "strategy": match strategy.kind {
                        ConversionStrategyKind::SafeCast => "safe_cast",
                        ConversionStrategyKind::TransformCast => "transform_cast",
                        ConversionStrategyKind::KindMigrate => "kind_migrate",
                        ConversionStrategyKind::RecreateColumn => "recreate_column",
                        ConversionStrategyKind::Blocked => "blocked",
                    },
                    "usingExpr": strategy.using_expr,
                    "preUpdate": strategy.pre_update,
                }),
            );
        }
    }

    serde_json::Value::Object(changes)
}

fn changes_risk(changes: &serde_json::Value, field: &FieldAst, column: &str) -> Risk {
    if changes.get("blocked").is_some() {
        return Risk::Destructive;
    }

    if let Some(null_change) = changes.get("nullability") {
        if null_change.get("to").and_then(|v| v.as_str()) == Some("not_null") {
            return Risk::Cautious;
        }
    }

    if let Some(conv) = changes.get("conversion") {
        let strategy = conv.get("strategy").and_then(|v| v.as_str()).unwrap_or("");
        return match strategy {
            "safe_cast" => Risk::Safe,
            "recreate_column" => Risk::Destructive,
            "transform_cast" | "kind_migrate" => {
                if let Some(loc) = changes.get("localization") {
                    if loc.get("direction").and_then(|v| v.as_str()) == Some("remove") {
                        return Risk::Destructive;
                    }
                }
                Risk::Cautious
            }
            _ => Risk::Cautious,
        };
    }

    if changes.get("kind_change").is_some() {
        return Risk::Cautious;
    }

    if changes.get("type").is_some() {
        if let Some(loc) = changes.get("localization") {
            if loc.get("direction").and_then(|v| v.as_str()) == Some("remove") {
                return Risk::Destructive;
            }
            return Risk::Cautious;
        }
        let _ = (field, column);
        return Risk::Cautious;
    }

    Risk::Safe
}

fn changes_warning(table: &str, column: &str, changes: &serde_json::Value) -> Option<String> {
    let mut parts = Vec::new();

    if let Some(blocked) = changes.get("blocked").and_then(|v| v.as_str()) {
        parts.push(format!("{table}.{column}: blocked — {blocked}"));
    }

    if let Some(conv) = changes.get("conversion") {
        if conv.get("strategy").and_then(|v| v.as_str()) == Some("recreate_column") {
            let from = changes
                .get("type")
                .and_then(|t| t.get("from_udt"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let to = changes
                .get("type")
                .and_then(|t| t.get("to_pg"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            parts.push(format!(
                "{table}.{column}: cannot cast {from} → {to} — column will be dropped and recreated empty (destructive, data loss)"
            ));
        }
    }

    if let Some(null_change) = changes.get("nullability") {
        if null_change.get("to").and_then(|v| v.as_str()) == Some("not_null") {
            parts.push(format!(
                "{table}.{column}: setting NOT NULL — migration will fail if NULL values exist"
            ));
        }
    }

    if let Some(kc) = changes.get("kind_change") {
        let from = kc.get("from").and_then(|v| v.as_str()).unwrap_or("?");
        let to = kc.get("to").and_then(|v| v.as_str()).unwrap_or("?");
        parts.push(format!(
            "{table}.{column}: field kind {from} → {to} — existing rows will be converted (cautious)."
        ));
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
        } else if changes
            .get("conversion")
            .and_then(|c| c.get("strategy"))
            .and_then(|v| v.as_str())
            != Some("recreate_column")
        {
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

fn conversion_strategy_name(changes: &serde_json::Value) -> Option<&str> {
    changes
        .get("conversion")
        .and_then(|c| c.get("strategy"))
        .and_then(|v| v.as_str())
}

pub fn diff(
    model: &ModelAst,
    db_table: &DbTable,
    db: &DatabaseState,
    ops: &mut Vec<Operation>,
    warnings: &mut Vec<String>,
    default_locale: &str,
    previous_model: Option<&ModelAst>,
) -> Result<()> {
    let db_col_names: std::collections::HashSet<String> =
        db_table.columns.iter().map(|c| c.name.clone()).collect();

    let schema_columns: std::collections::HashMap<String, (&str, &FieldAst)> = model
        .fields
        .iter()
        .flat_map(|(name, field)| {
            column_names_for(name, field)
                .into_iter()
                .map(move |col| (col, (name.as_str(), field)))
        })
        .collect();

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
                    table: model.table_name().to_string(),
                    from: drop.to_string(),
                    to: add.to_string(),
                    risk: Risk::Safe,
                });
                warnings.push(format!(
                    "Column '{drop}' removed and '{add}' added on table '{}'. Treating as rename. \
                     Specify in platform.renames.json to suppress this warning.",
                    model.table_name()
                ));
                renamed_dropped.insert(drop);
                renamed_added.insert(add);
            }
        }
    }

    for col in &added {
        if !renamed_added.contains(*col) {
            if let Some((_, field)) = schema_columns.get(*col) {
                if field_required(field) == Some(true)
                    && add_column_backfill_default(field).is_none()
                {
                    warnings.push(required_field_existing_table_warning(
                        model.table_name(),
                        col,
                    ));
                }
                ops.push(Operation::AddColumn {
                    table: model.table_name().to_string(),
                    column: col.to_string(),
                    field: Box::new((*field).clone()),
                    risk: Risk::Safe,
                });

                if has_index_flag(field) {
                    ops.push(Operation::AddIndex {
                        table: model.table_name().to_string(),
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

    for col in &dropped {
        if !renamed_dropped.contains(*col) {
            ops.push(Operation::DropColumn {
                table: model.table_name().to_string(),
                column: col.to_string(),
                risk: Risk::Destructive,
            });
        }
    }

    let db_col_map: std::collections::HashMap<&str, &DbColumn> = db_table
        .columns
        .iter()
        .map(|c| (c.name.as_str(), c))
        .collect();

    for (col_name, (_, field)) in &schema_columns {
        if options_cols.contains(col_name.as_str()) {
            continue;
        }
        if renamed_added.contains(col_name.as_str()) {
            continue;
        }
        if !db_col_names.contains(col_name) {
            continue;
        }

        if let Some(db_col) = db_col_map.get(col_name.as_str()) {
            let previous_field = previous_model.and_then(|m| field_for_column(m, col_name));
            let changes = detect_changes(
                field,
                db_col,
                default_locale,
                previous_field,
                model.table_name(),
                &db_table.schema,
            );

            if changes.is_null() {
                continue;
            }

            if changes.get("blocked").is_some() {
                let msg =
                    changes_warning(model.table_name(), col_name, &changes).unwrap_or_else(|| {
                        format!("{}.{}: blocked conversion", model.table_name(), col_name)
                    });
                bail!(msg);
            }

            let risk = changes_risk(&changes, field, col_name);
            let warning = changes_warning(model.table_name(), col_name, &changes);
            if let Some(ref w) = warning {
                warnings.push(w.clone());
            }
            if changes
                .get("nullability")
                .and_then(|n| n.get("to"))
                .and_then(|v| v.as_str())
                == Some("not_null")
                && field_required(field) == Some(true)
                && add_column_backfill_default(field).is_none()
            {
                warnings.push(required_field_existing_table_warning(
                    model.table_name(),
                    col_name,
                ));
            }

            if conversion_strategy_name(&changes) == Some("recreate_column") {
                let dependencies = discover_column_dependencies(model.table_name(), col_name, db);
                ops.push(Operation::RecreateColumn {
                    table: model.table_name().to_string(),
                    column: col_name.clone(),
                    field: Box::new((*field).clone()),
                    changes,
                    dependencies,
                    risk,
                    warning,
                });
            } else {
                ops.push(Operation::AlterColumn {
                    table: model.table_name().to_string(),
                    column: col_name.clone(),
                    field: Box::new((*field).clone()),
                    changes,
                    risk,
                    warning,
                });
            }
        }
    }

    Ok(())
}
