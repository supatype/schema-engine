use super::annotations::{AuthUserOnDelete, FieldAnnotations};
use super::ast::{
    AccessAst, FieldAst, IndexAst, IndexMethod, ModelAst, RelationCardinality, SchemaAst,
    VersionsAst,
};
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
        // A primary-key column is implicitly unique via its `<table>_pkey`
        // constraint and never gets a separate `<table>_<col>_key` UNIQUE
        // constraint emitted (see column definition in the SQL generator).
        // Reporting it as a standalone unique here makes the constraint differ,
        // doctor, and managed-comment stamping reference a constraint that was
        // never created (e.g. `COMMENT ON CONSTRAINT "profile_id_key"`).
        | FieldAst::Color(s) => s.unique && !s.primary_key,
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
    if let Some((field_name, field @ FieldAst::Relation(rel))) =
        model.fields.get_key_value(kernel_field)
    {
        if rel.is_owning() {
            return db_foreign_key(field, field_name)
                .unwrap_or_else(|| default_foreign_key_column(field_name));
        }
    }
    to_snake_case(kernel_field)
}

/// Whether `model` is a user's own: keyed by an `id` the CLI marked as an `auth.users` id
/// (`SupatypeAuthUserId`). An owner relation to it compares the caller's id with the key directly.
///
/// The marker is the only evidence. A UUID key the database does not generate was once taken for
/// one, but nothing in a schema said so, and the CLI generates every UUID key anyway (O1).
pub fn is_user_identity_model(model: &ModelAst) -> bool {
    matches!(
        model.fields.get("id"),
        Some(field @ FieldAst::Uuid(_)) if field_annotations(field).db.auth_user_id
    )
}

/// What deleting the user does to a row, when `field` is a `SupatypeAuthUserId` linked to
/// `auth.users` (`SupatypeAuthUserId<{ onDelete }>`). `None` for every other field, an auth user id
/// without the option included: it has no foreign key.
pub fn auth_user_link(field: &FieldAst) -> Option<AuthUserOnDelete> {
    let db = &field_annotations(field).db;
    match field {
        FieldAst::Uuid(_) if db.auth_user_id => db.auth_user_on_delete,
        _ => None,
    }
}

/// The field a model is owned through: the first `Owner` among its read, update, delete and create
/// rules, looking inside `any` and `all`. A rule that names no owner (`Public`, a role) is passed
/// over rather than ending the search, so `read: Public` beside `update: Owner<"user_id">` is owned
/// through `user_id` (O3).
pub fn owner_field_on_model(model: &ModelAst) -> Option<&str> {
    let access = platform_access(model);
    [&access.read, &access.update, &access.delete, &access.create]
        .into_iter()
        .flatten()
        .find_map(owner_in_rule)
}

fn owner_in_rule(rule: &super::ast::AccessRule) -> Option<&str> {
    use super::ast::AccessRule;
    match rule {
        AccessRule::Owner { field } => Some(field.as_str()),
        AccessRule::Any { rules } | AccessRule::All { rules } => {
            rules.iter().find_map(owner_in_rule)
        }
        _ => None,
    }
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

// ─── Schema facts the generators need without a database ──────────────────────
//
// These read the AST and nothing else. They live here rather than beside the SQL generator and the
// differ that also use them because the TypeScript admin generator needs them too, and that
// generator is compiled to WASM, where `generator::sql` and `differ` are both gated out for pulling
// in sqlx and tokio. A WASM-visible module reaching into a gated one builds fine on the host and
// fails only on the wasm32 target, which is not a build anybody runs by hand.

/// Suffix on a versioned model's snapshot table.
pub const VERSIONS_SUFFIX: &str = "_versions";

/// The snapshot table for a model's table: `{table}_versions`, fitted to the identifier limit as
/// Postgres fits the names it chooses ([`crate::managed::make_object_name`]), so a long table's
/// snapshot table is created under the name everything else looks for.
pub fn versions_table_name(table: &str) -> String {
    crate::managed::make_object_name(table, None, &VERSIONS_SUFFIX[1..])
}

/// A model's `versions` declaration, when it has one.
pub fn versions_of(model: &ModelAst) -> Option<&VersionsAst> {
    model.options.versions.as_ref()
}

/// True when this schema needs the versions layer at all.
pub fn has_versions(ast: &SchemaAst) -> bool {
    ast.models.iter().any(|m| versions_of(m).is_some())
}

/// True when this field holds one value per locale rather than one value.
///
/// A localized field is stored as JSONB keyed by locale whatever its declared type, so this decides
/// the column type, what the draft views reconstruct, and what the admin config tells Studio to
/// render as a per-locale input.
pub(crate) fn is_localized(field: &FieldAst) -> bool {
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

/// The database columns one declared field occupies.
///
/// Most fields are one column of the same name, but a `belongs_to` relation is its foreign key,
/// `timestamps` and `publishable` expand to several, and a relation with no local column has none.
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

/// Returns Some(true) if the field has an `index: true` flag, None otherwise.
/// The indexes a model gets without declaring any.
///
/// Three rules, all of which emit a managed comment: a btree for a field marked `index`, a btree
/// on `deleted_at` for a soft-deleting model, and a GIN for an indexed `Blocks` column.
///
/// Public to the crate because the differ needs the identical list. It previously expected only
/// the indexes a schema *declares*, so each of these read as a managed index nothing accounted
/// for, and the differ proposed dropping it. The push dropped it, recreated it from the rules
/// above, and the next diff proposed dropping it again: `supatype push` was never idempotent for
/// any model with an indexed Blocks column. One definition, read by both, is the only version of
/// this that stays true.
pub fn implicit_model_indexes(model: &ModelAst) -> Vec<IndexAst> {
    let table = model.table_name();
    let mut indexes = Vec::new();

    for (field_name, field) in &model.fields {
        if let Some(true) = field_index_flag(field) {
            indexes.push(IndexAst {
                name: None,
                fields: vec![field_name.clone()],
                unique: false,
                using: IndexMethod::Btree,
                distance: None,
            });
        }
    }

    // Either spelling asks for the same index, and only one is emitted. The guard reads as a
    // plain `or` now that both branches live here; it was two blocks, and the second excluded the
    // first to avoid adding the index twice.
    if model.fields.contains_key("softDelete") || model.options.soft_delete {
        indexes.push(IndexAst {
            name: None,
            fields: vec!["deleted_at".into()],
            unique: false,
            using: IndexMethod::Btree,
            distance: None,
        });
    }

    for (field_name, field) in &model.fields {
        if let FieldAst::Blocks(b) = field {
            if b.index {
                indexes.push(IndexAst {
                    name: Some(crate::managed::make_object_name(
                        table,
                        Some(field_name),
                        "gin_idx",
                    )),
                    fields: vec![field_name.clone()],
                    unique: false,
                    using: IndexMethod::Gin,
                    distance: None,
                });
            }
        }
    }

    indexes
}

pub fn field_index_flag(field: &FieldAst) -> Option<bool> {
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
        | FieldAst::Color(f) => {
            if f.index {
                Some(true)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Whether the column owns a sequence its database made for it: a `SERIAL` / `BIGSERIAL`, or an
/// identity column, whose sequence Postgres names the same way (`{table}_{column}_seq`).
pub fn owns_sequence(field: &FieldAst) -> bool {
    matches!(field, FieldAst::Serial(_) | FieldAst::BigSerial(_))
        || super::ast::scalar_of(field).is_some_and(|f| f.identity.is_some())
}

/// Whether the database fills the column itself, so an insert may leave it out: a serial, an
/// identity column, or a generated one.
pub fn database_fills(field: &FieldAst) -> bool {
    owns_sequence(field) || super::ast::scalar_of(field).is_some_and(|f| f.generated.is_some())
}

/// Whether no caller writes the column: a generated one, which Postgres refuses to write, or a
/// `GENERATED ALWAYS` identity, which it refuses short of `OVERRIDING SYSTEM VALUE`.
pub fn never_written(field: &FieldAst) -> bool {
    super::ast::scalar_of(field).is_some_and(|f| {
        f.generated.is_some() || f.identity == Some(super::ast::IdentityGeneration::Always)
    })
}

/// Whether a field declares itself the primary key.
pub(crate) fn is_primary_key(field: &FieldAst) -> bool {
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

/// The columns of a model's primary key, in the order the schema declares them.
///
/// One list for every consumer: the DDL that creates the key and the admin config that tells Studio
/// which columns make a row unique. Empty when no field claims the role; the normaliser gives a
/// model with no key and no `id` field an `id` key, so that takes a model with an unkeyed `id`.
pub fn primary_key_columns(model: &ModelAst) -> Vec<String> {
    model
        .fields
        .iter()
        .filter(|(_, field)| is_primary_key(field))
        .flat_map(|(name, field)| column_names_for(name, field))
        .collect()
}
