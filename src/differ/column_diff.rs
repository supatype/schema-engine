use super::{ColumnDependencySnapshot, Operation, Risk};
use crate::generator::sql::column_conversion::{
    self, add_column_backfill_default, plan_type_conversion, required_field_existing_table_warning,
    supports_kind_data_migration, ConversionStrategyKind,
};
use crate::introspector::constraints::DbConstraintType;
use crate::introspector::tables::{DbColumn, DbTable};
use crate::parser::accessors::{column_names_for, is_localized};
use crate::parser::ast::{FieldAst, IdentityGeneration, ModelAst, RelationCardinality};
use crate::state::database_state::DatabaseState;
use anyhow::{bail, Result};
use serde_json::json;
use strsim::jaro_winkler;

const RENAME_THRESHOLD: f64 = 0.7;

pub(crate) fn field_is_required(field: &FieldAst) -> Option<bool> {
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
        // `SERIAL` is `NOT NULL` whatever the field says: Postgres declares it so, and the
        // generator writes it bare. Reading `required` here asked for `DROP NOT NULL` on the push
        // after every optional serial was created, so it converged one push late.
        FieldAst::Serial(_) | FieldAst::BigSerial(_) => Some(true),
        FieldAst::Slug(f) => Some(f.required),
        FieldAst::Enum(f) => Some(f.required),
        FieldAst::Json(f) => Some(f.required),
        FieldAst::Decimal(f) => Some(f.required),
        FieldAst::Geo(f) => Some(f.required),
        FieldAst::Vector(f) => Some(f.required),
        FieldAst::Array(f) => Some(f.required),
        FieldAst::Image(f) | FieldAst::File(f) => Some(f.required),
        FieldAst::Custom(f) => Some(f.required),
        FieldAst::Relation(rel) if matches!(rel.cardinality, RelationCardinality::BelongsTo) => {
            Some(rel.required)
        }
        _ => None,
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

/// Whether `model` (the last push's, when there was one) declares `column`, by a field or by an
/// option. What says a column with no ledger row is the engine's: an older engine created it.
pub(crate) fn declared_by(model: Option<&ModelAst>, column: &str) -> bool {
    model.is_some_and(|m| {
        field_for_column(m, column).is_some()
            || crate::generator::sql::migration::option_columns(m)
                .iter()
                .any(|(c, _)| *c == column)
    })
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

pub(crate) fn expected_udt(field: &FieldAst) -> Option<String> {
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
        | FieldAst::Enum(_) => Some("text".into()),
        // `xml`, because that is what the column is. `migration.rs` creates it with `XML` and this
        // side expected `text`, so every push after the first proposed converting the column the
        // engine had just created: "type change xml -> TEXT may be lossy", flagged caution, and a
        // user who accepted the prompt lost the type. Confirmed on a live database.
        FieldAst::Xml(_) => Some("xml".into()),
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
            // Compared against `numeric_precision` / `numeric_scale`, not against `data_type`.
            //
            // `information_schema.columns.data_type` for `NUMERIC(5, 2)` is the bare string
            // `numeric`; the precision and the scale are separate columns. This used to render
            // `numeric(5,2)` and compare it to `data_type`, which cannot match for any decimal
            // that declares either - so `Decimal<5, 2>` reported a type change on a column that
            // already had exactly that type, on every diff, forever.
            //
            // The generated `ALTER` is one Postgres would accept and ignore, which is why this
            // stayed invisible: it only bites where something depends on the column, and then it
            // is fatal rather than noisy (`cannot alter type of a column used by a view or rule`).
            // A model pairing `Decimal` with `versions: { drafts: true }` gets a `draft.<table>`
            // view over the column, so it could be pushed once and never again.
            //
            // Unknown precision on the database side is treated as matching. A column the server
            // does not report these for is one this cannot say anything about, and guessing
            // "different" there is what produced the bug in the first place.
            match (d.precision, d.scale) {
                (Some(p), Some(sc)) => {
                    db_col.numeric_precision.is_none_or(|dp| dp == p as i32)
                        && db_col.numeric_scale.is_none_or(|ds| ds == sc as i32)
                }
                (Some(p), None) => db_col.numeric_precision.is_none_or(|dp| dp == p as i32),
                // The schema asked for an unconstrained numeric, so any precision satisfies it.
                _ => true,
            }
        }
        FieldAst::Vector(v) => {
            let dt = db_col.data_type.to_lowercase();
            // pgvector reports USER-DEFINED in information_schema; udt_name is "vector".
            if dt == "user-defined" {
                return true;
            }
            dt.contains(&format!("vector({})", v.dimensions))
        }
        FieldAst::Geo(g) => {
            let dt = db_col.data_type.to_lowercase();
            // PostGIS types report USER-DEFINED in information_schema; udt_name is "geography".
            if dt == "user-defined" {
                return true;
            }
            if matches!(dt.as_str(), "geography" | "geometry") {
                return true;
            }
            dt.contains(&g.geo_type.to_lowercase())
        }
        _ => true,
    }
}

/// True when a live Postgres column (from `information_schema`) already matches `field`.
pub fn column_type_matches_introspected(field: &FieldAst, db_col: &DbColumn) -> bool {
    column_type_matches(field, db_col)
}

/// Postgres type used for columns / FK references (SERIAL → INTEGER, etc.).
pub(crate) fn field_pg_type(field: &FieldAst) -> String {
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
        | FieldAst::Enum(_) => "TEXT".into(),
        // Matches `migration.rs`, which renders this column as XML. See `expected_udt` above.
        FieldAst::Xml(_) => "XML".into(),
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

    if let Some(required) = field_is_required(field) {
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

    if changes.get("identity").is_some() || changes.get("generated").is_some() {
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
        parts.push(format!("{table}.{column}: blocked: {blocked}"));
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
                "{table}.{column}: cannot cast {from} → {to}, so the column will be dropped and recreated empty (destructive, data loss)"
            ));
        }
    }

    if let Some(null_change) = changes.get("nullability") {
        if null_change.get("to").and_then(|v| v.as_str()) == Some("not_null") {
            parts.push(format!(
                "{table}.{column}: setting NOT NULL, which fails if NULL values exist"
            ));
        }
    }

    if let Some(kc) = changes.get("kind_change") {
        let from = kc.get("from").and_then(|v| v.as_str()).unwrap_or("?");
        let to = kc.get("to").and_then(|v| v.as_str()).unwrap_or("?");
        parts.push(format!(
            "{table}.{column}: field kind {from} → {to}: existing rows will be converted (cautious)."
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
                    "{table}.{column}: converting to localized field: existing values will be \
                     assigned to locale '{locale}'. No data loss (cautious)."
                ));
            } else {
                parts.push(format!(
                    "{table}.{column}: REMOVING localization: only the '{locale}' locale value \
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
                    "{table}.{column}: type change {from} → {to} may be lossy; verify data before applying"
                ));
            }
        }
    }

    if let Some(identity) = changes.get("identity") {
        let action = identity
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let text = |key: &str| {
            identity
                .get(key)
                .and_then(|v| v.as_str())
                .map(|v| if v == "byDefault" { "by default" } else { v })
                .unwrap_or("?")
                .to_string()
        };
        parts.push(match action {
            "add" => format!(
                "{table}.{column}: becomes an identity column (generated {}), numbered on from the rows there",
                text("to")
            ),
            "drop" => format!(
                "{table}.{column}: is no longer an identity column; an insert must now give it a value"
            ),
            _ => format!(
                "{table}.{column}: identity changes from generated {} to generated {}",
                text("from"),
                text("to")
            ),
        });
    }

    if changes.get("generated").is_some() {
        parts.push(format!(
            "{table}.{column}: is no longer a generated column; it keeps its values and can be written"
        ));
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

/// What changes how the database fills a column (identity-contract): the entries an
/// `AlterColumn` carries (`identity`, `generated`), a generated column to recreate instead, and a
/// warning for what is left as it is.
#[derive(Debug, Default)]
struct GenerationDiff {
    alter: serde_json::Map<String, serde_json::Value>,
    recreate: Option<serde_json::Value>,
    warning: Option<String>,
}

/// The expression a recorded column statement generates the column with, as it was declared.
fn recorded_expression(sql: &str) -> Option<&str> {
    let start = sql.find("GENERATED ALWAYS AS (")? + "GENERATED ALWAYS AS (".len();
    let end = sql.rfind(") STORED")?;
    (end >= start).then(|| sql[start..end].trim())
}

/// An expression with what deparsing adds or moves taken out (space, parentheses, case), for
/// comparing a declared expression with one the ledger has no record of.
fn loose_expression(expression: &str) -> String {
    expression
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '(' && *c != ')')
        .flat_map(char::to_lowercase)
        .collect()
}

/// How the schema's identity and generation for `field` differ from `db_col`'s.
///
/// - Identity is compared with the catalog: added (`ADD GENERATED ... AS IDENTITY`, the sequence
///   started past the rows there), removed (`DROP IDENTITY`) or switched (`SET GENERATED`). A
///   `SERIAL` column the schema now declares as identity is left as it is, with a warning saying
///   how to convert it: renumbering a key column is a change to ask for, not to infer.
/// - A generated column's expression cannot be compared with the catalog's text, which Postgres
///   rewrites on the way in, so it is compared with the statement the ledger records (the last
///   push's declaration), or loosely with the live text where there is no record. A change is a
///   `SET EXPRESSION` (Postgres 17) or the column made again (16); a plain column becoming
///   generated is made again (its values are replaced); a generated one becoming plain keeps its
///   values (`DROP EXPRESSION`).
fn generation_diff(
    table: &str,
    schema: &str,
    field: &FieldAst,
    db_col: &DbColumn,
    recorded: Option<&str>,
) -> GenerationDiff {
    let mut out = GenerationDiff::default();
    // A serial declares its own sequence and is never converted either way here.
    if matches!(field, FieldAst::Serial(_) | FieldAst::BigSerial(_)) {
        return out;
    }
    let Some(declared) = crate::parser::ast::scalar_of(field) else {
        return out;
    };
    let column = db_col.name.as_str();
    let live_identity = db_col
        .identity_generation
        .as_deref()
        .and_then(IdentityGeneration::from_catalog)
        .filter(|_| db_col.is_identity);
    let serial_default = db_col
        .default
        .as_deref()
        .filter(|d| d.starts_with("nextval("));
    match (declared.identity, live_identity) {
        (Some(to), Some(from)) if to != from => {
            out.alter.insert(
                "identity".into(),
                json!({ "action": "set", "from": from, "to": to }),
            );
        }
        (Some(to), None) => {
            if let Some(default) = serial_default {
                out.warning = Some(serial_kept_warning(schema, table, column, to, default));
            } else {
                out.alter.insert(
                    "identity".into(),
                    json!({ "action": "add", "to": to, "dropDefault": db_col.default.is_some() }),
                );
            }
        }
        (None, Some(from)) => {
            out.alter
                .insert("identity".into(), json!({ "action": "drop", "from": from }));
        }
        _ => {}
    }
    let live_expression = db_col
        .generation_expression
        .as_deref()
        .filter(|_| db_col.is_generated);
    match (&declared.generated, live_expression) {
        (Some(g), Some(live)) => {
            let changed = match recorded.and_then(recorded_expression) {
                Some(was) => was != g.expression.trim(),
                None => loose_expression(live) != loose_expression(&g.expression),
            };
            if changed {
                out.recreate = Some(json!({
                    "action": "set_expression",
                    "expression": g.expression,
                    "from": recorded.and_then(recorded_expression).unwrap_or(live),
                }));
            }
        }
        (Some(g), None) => {
            out.recreate = Some(json!({ "action": "add", "expression": g.expression }));
        }
        (None, Some(live)) => {
            out.alter.insert(
                "generated".into(),
                json!({ "action": "drop_expression", "from": live }),
            );
        }
        (None, None) => {}
    }
    out
}

/// What the push says of a `SERIAL` column the schema declares as an identity column, which it
/// leaves as it is: the statements that convert it, to run deliberately.
fn serial_kept_warning(
    schema: &str,
    table: &str,
    column: &str,
    to: IdentityGeneration,
    default: &str,
) -> String {
    let sequence = default
        .strip_prefix("nextval('")
        .and_then(|rest| rest.split_once("'::regclass)"))
        .map(|(name, _)| name.to_string())
        .unwrap_or_else(|| format!("\"{schema}\".\"{table}_{column}_seq\""));
    let target = format!("\"{schema}\".\"{table}\"");
    format!(
        "{table}.{column} is a serial column and the schema declares it an identity column: it is \
         left as a serial, since changing how a key is numbered is a change to make deliberately. \
         To convert it, run: ALTER TABLE {target} ALTER COLUMN \"{column}\" DROP DEFAULT; \
         DROP SEQUENCE {sequence}; ALTER TABLE {target} ALTER COLUMN \"{column}\" ADD GENERATED \
         {} AS IDENTITY; SELECT setval(pg_get_serial_sequence('{target}', '{column}'), \
         COALESCE(MAX(\"{column}\"), 0) + 1, false) FROM {target};",
        to.as_sql()
    )
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

    let options_cols: std::collections::HashSet<String> =
        crate::generator::sql::migration::option_columns(model)
            .into_iter()
            .map(|(column, _)| column.to_string())
            .collect();

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

    // Only a column that is ours is renamed (D4): one the ledger records, or, where it has no row
    // (an upgraded database), one the last push's schema declared on this table. A rename is a
    // similarity guess, so a column someone added (`nickname`) would otherwise be renamed into a
    // declared one (`nick_name`) and taken over with its data. Not one recorded as adopted: that is
    // someone else's column Supatype was told about (`adopt --key column:...`), never its own.
    let ours = |column: &str| {
        !db.column_adopted(&db_table.name, column)
            && db
                .column_owned(&db_table.name, column)
                .unwrap_or_else(|| declared_by(previous_model, column))
    };

    for &drop in dropped.iter().filter(|c| ours(c)) {
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
                // A serial or identity column fills existing rows from its own sequence, and a
                // generated one from its expression, so they need no backfill.
                let fills_itself = crate::parser::accessors::database_fills(field);
                if field_is_required(field) == Some(true)
                    && add_column_backfill_default(field).is_none()
                    && !fills_itself
                {
                    warnings.push(required_field_existing_table_warning(
                        model.table_name(),
                        col,
                    ));
                }
                // An indexed field's index is the reconcile's (Phase 4.3), created after this.
                ops.push(Operation::AddColumn {
                    table: model.table_name().to_string(),
                    column: col.to_string(),
                    field: Box::new((*field).clone()),
                    risk: Risk::Safe,
                });
            }
        }
    }

    // The columns the model's options add, which `CREATE TABLE` writes beside the fields. A table
    // that predates the option (`timestamps` turned on later), or one whose column was dropped by
    // hand, gets it here, with the definition `CREATE TABLE` would have given it: the composite
    // field the option stands for renders exactly that.
    for (column, _) in crate::generator::sql::migration::option_columns(model) {
        if db_col_names.contains(column) {
            continue;
        }
        let field = if column == "deleted_at" {
            FieldAst::SoftDelete
        } else {
            FieldAst::Timestamps
        };
        ops.push(Operation::AddColumn {
            table: model.table_name().to_string(),
            column: column.to_string(),
            field: Box::new(field),
            risk: Risk::Safe,
        });
    }

    // Dropping a column from a table Supatype did not create is the same class of data loss as
    // dropping the table: smaller, and easier to miss. Gated on the table being ours, and
    // reported rather than skipped quietly. Additive changes are deliberately still allowed: a
    // table you do not own may gain a column, it may not lose one.
    let managed = db.owns_table(db_table);
    for col in &dropped {
        if !renamed_dropped.contains(*col) {
            if !managed {
                warnings.push(format!(
                    "Column \"{}\".\"{}\" is gone from your schema, but the table is not managed by \
                     Supatype, so it is left alone. Run `supatype adopt` to \
                     bring the table under management, or drop the column by hand.",
                    db_table.name, col
                ));
                continue;
            }
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
            let mut changes = detect_changes(
                field,
                db_col,
                default_locale,
                previous_field,
                model.table_name(),
                &db_table.schema,
            );
            let generation = generation_diff(
                model.table_name(),
                &db_table.schema,
                field,
                db_col,
                db.recorded_column_sql(model.table_name(), col_name),
            );
            if let Some(w) = &generation.warning {
                warnings.push(w.clone());
            }
            if !generation.alter.is_empty() {
                if changes.is_null() {
                    changes = json!({});
                }
                if let Some(map) = changes.as_object_mut() {
                    map.extend(generation.alter.clone());
                }
            }

            // A generated column whose expression changes, or a plain one that becomes generated,
            // is made again by its own operation (a type change on it would be moot).
            if let Some(generated) = generation.recreate {
                if !managed {
                    warnings.push(format!(
                        "Column \"{}\".\"{}\" differs from your schema, but the table is not managed by Supatype, so it is left alone. Run `supatype adopt` to bring the table under management, or point the model at a different table with `tableName`.",
                        db_table.name, col_name
                    ));
                    continue;
                }
                let adds = generated.get("action").and_then(|v| v.as_str()) == Some("add");
                let warning = Some(if adds {
                    format!(
                        "{}.{col_name}: becomes a generated column, so it is dropped and added again and its values are replaced by the expression's (destructive, data loss)",
                        model.table_name()
                    )
                } else {
                    format!(
                        "{}.{col_name}: generated expression changes; its values are computed again",
                        model.table_name()
                    )
                });
                warnings.push(warning.clone().unwrap_or_default());
                let dependencies = discover_column_dependencies(model.table_name(), col_name, db);
                ops.push(Operation::RecreateColumn {
                    table: model.table_name().to_string(),
                    column: col_name.clone(),
                    field: Box::new((*field).clone()),
                    changes: json!({ "generated": generated }),
                    dependencies,
                    risk: if adds {
                        Risk::Destructive
                    } else {
                        Risk::Cautious
                    },
                    warning,
                });
                continue;
            }

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
                && field_is_required(field) == Some(true)
                && add_column_backfill_default(field).is_none()
            {
                warnings.push(required_field_existing_table_warning(
                    model.table_name(),
                    col_name,
                ));
            }

            // Modifying a column on a table Supatype did not create is the same class of loss as
            // dropping one. `RecreateColumn` literally drops and re-adds the column, and an
            // `AlterColumn` type change either rewrites the operator's data or fails outright,
            // which is how this was found: a model declaring `id: UUID` against an existing
            // `id serial` produced `cannot cast type integer to uuid` mid-migration, from a table
            // the gate was supposed to be protecting.
            //
            // Additive stays allowed, as for `DropColumn` above: a table you do not own may gain a
            // column; it may not have one changed underneath it.
            if !managed {
                warnings.push(format!(
                    "Column \"{}\".\"{}\" differs from your schema, but the table is not managed by Supatype, so it is left alone. Run `supatype adopt` to bring the table under management, or point the model at a different table with `tableName`.",
                    db_table.name, col_name
                ));
                continue;
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

/// Whether a field declares itself the primary key.
///
/// Lives here beside [`field_pg_type`] because both answer questions about a declared field that
/// several layers need: the migration renderer needs the key to build a foreign key, and the differ
/// needs it to type the `record_id` on a snapshot table. It was private to the migration renderer,
/// which is why `field_views.rs` reaches for the serialised form instead, a workaround for a helper
/// that existed and could not be seen.
pub(crate) fn field_is_primary_key(field: &FieldAst) -> bool {
    match field {
        FieldAst::Text(s)
        | FieldAst::RichText(s)
        | FieldAst::Integer(s)
        | FieldAst::Float(s)
        | FieldAst::Boolean(s)
        | FieldAst::Datetime(s)
        | FieldAst::Uuid(s)
        | FieldAst::Email(s)
        | FieldAst::BigInt(s)
        | FieldAst::Bytes(s)
        | FieldAst::SmallInt(s)
        | FieldAst::Date(s)
        | FieldAst::Timestamp(s)
        | FieldAst::Serial(s)
        | FieldAst::BigSerial(s)
        | FieldAst::Money(s)
        | FieldAst::Url(s)
        | FieldAst::Ip(s)
        | FieldAst::Cidr(s)
        | FieldAst::Macaddr(s)
        | FieldAst::Interval(s)
        | FieldAst::TsQuery(s)
        | FieldAst::TsVector(s)
        | FieldAst::Xml(s)
        | FieldAst::Color(s) => s.primary_key,
        _ => false,
    }
}
