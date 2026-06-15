use super::annotations::FieldAnnotations;
use super::ast::{AccessAst, FieldAst, ModelAst, RelationCardinality};
use super::resolver::to_snake_case;

pub fn db_table_name(model: &ModelAst) -> &str {
    &model.annotations.db.table_name
}

pub fn db_table_name_mut(model: &mut ModelAst) -> &mut String {
    &mut model.annotations.db.table_name
}

pub fn platform_access(model: &ModelAst) -> &AccessAst {
    &model.annotations.platform.access
}

pub fn platform_access_mut(model: &mut ModelAst) -> &mut AccessAst {
    &mut model.annotations.platform.access
}

pub fn db_indexes(model: &ModelAst) -> &[super::ast::IndexAst] {
    &model.annotations.db.indexes
}

pub fn field_annotations(field: &FieldAst) -> &FieldAnnotations {
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
        | FieldAst::Color(s) => &s.annotations,
        FieldAst::Slug(s) => &s.annotations,
        FieldAst::Enum(s) => &s.annotations,
        FieldAst::Json(s) => &s.annotations,
        FieldAst::Button(s) => &s.annotations,
        FieldAst::Decimal(s) => &s.annotations,
        FieldAst::Array(s) => &s.annotations,
        FieldAst::Image(s) | FieldAst::File(s) => &s.annotations,
        FieldAst::Geo(s) => &s.annotations,
        FieldAst::Vector(s) => &s.annotations,
        FieldAst::Blocks(s) => &s.annotations,
        FieldAst::Custom(s) => &s.annotations,
        FieldAst::Relation(s) => &s.annotations,
        FieldAst::Timestamps | FieldAst::Publishable | FieldAst::SoftDelete => {
            static EMPTY: std::sync::LazyLock<FieldAnnotations> =
                std::sync::LazyLock::new(FieldAnnotations::default);
            &EMPTY
        }
    }
}

pub fn db_pg_type(field: &FieldAst) -> &str {
    let ann = field_annotations(field);
    if !ann.db.pg_type.is_empty() {
        return &ann.db.pg_type;
    }
    match field {
        FieldAst::Array(a) if !a.element_type.is_empty() => "ARRAY",
        FieldAst::Relation(_) => "",
        _ => "",
    }
}

pub fn db_foreign_key(field: &FieldAst, field_name: &str) -> Option<String> {
    let ann = field_annotations(field);
    if let Some(fk) = &ann.db.foreign_key {
        if !fk.is_empty() {
            return Some(fk.clone());
        }
    }
    if matches!(field, FieldAst::Relation(_)) {
        return Some(default_foreign_key_column(field_name));
    }
    None
}

pub fn db_read_only(field: &FieldAst) -> bool {
    field_annotations(field).platform.read_only
}

pub fn db_unique(field: &FieldAst) -> bool {
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
        | FieldAst::Color(s) => s.unique,
        FieldAst::Slug(s) => s.unique,
        FieldAst::Enum(s) => s.unique,
        FieldAst::Array(s) => s.unique,
        FieldAst::Custom(s) => s.unique,
        _ => field_annotations(field).db.unique,
    }
}

pub fn db_index(field: &FieldAst) -> bool {
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
        | FieldAst::Color(s) => s.index,
        FieldAst::Blocks(b) => b.index,
        FieldAst::Custom(s) => s.index,
        _ => field_annotations(field).db.index,
    }
}

/// Resolve a kernel field name from platform access rules to the SQL column used in RLS.
pub fn resolve_owner_column(model: &ModelAst, kernel_field: &str) -> String {
    if kernel_field == "id" {
        return "id".to_string();
    }
    if let Some((field_name, field)) = model.fields.get_key_value(kernel_field) {
        if let FieldAst::Relation(rel) = field {
            let is_owning = matches!(
                rel.cardinality,
                RelationCardinality::BelongsTo | RelationCardinality::ManyToMany
            );
            if is_owning {
                return db_foreign_key(field, field_name)
                    .unwrap_or_else(|| default_foreign_key_column(field_name));
            }
        }
        return to_snake_case(kernel_field);
    }
    to_snake_case(kernel_field)
}

pub fn default_foreign_key_column(field_name: &str) -> String {
    let snake = field_name
        .replace(' ', "_")
        .chars()
        .fold(String::new(), |mut acc, c| {
            if c.is_uppercase() {
                if !acc.is_empty() {
                    acc.push('_');
                }
                acc.push(c.to_ascii_lowercase());
            } else {
                acc.push(c);
            }
            acc
        });
    let base = snake.trim_end_matches("_id");
    format!("{base}_id")
}
