use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level schema AST as produced by @supatype/schema and consumed by the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaAst {
    pub models: Vec<ModelAst>,
    /// Junction tables inferred by the resolver (not present in user input).
    #[serde(default)]
    pub junction_tables: Vec<JunctionTableAst>,
    /// Storage buckets inferred from image/file fields.
    #[serde(default)]
    pub storage_buckets: Vec<StorageBucketAst>,
    /// Active locales for localized fields, e.g. ["en", "fr", "de"].
    #[serde(default)]
    pub locales: Vec<String>,
    /// The default/fallback locale. Defaults to "en" when locales is non-empty.
    #[serde(default)]
    pub default_locale: Option<String>,
    /// Plugins registered for this schema (field type, composite, provider, widget).
    #[serde(default)]
    pub plugins: Vec<PluginRegistrationAst>,
    /// Warnings from parse/validation.
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl SchemaAst {
    /// Returns the effective default locale (first of `locales`, or "en").
    pub fn effective_default_locale(&self) -> &str {
        self.default_locale
            .as_deref()
            .or_else(|| self.locales.first().map(|s| s.as_str()))
            .unwrap_or("en")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelAst {
    pub name: String,
    pub table_name: String,
    /// Fields keyed by field name.
    pub fields: HashMap<String, FieldAst>,
    #[serde(default)]
    pub access: AccessAst,
    #[serde(default)]
    pub indexes: Vec<IndexAst>,
    #[serde(default)]
    pub options: ModelOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum FieldAst {
    // Scalar fields
    Text(ScalarFieldAst),
    RichText(ScalarFieldAst),
    Integer(ScalarFieldAst),
    Float(ScalarFieldAst),
    Boolean(ScalarFieldAst),
    Datetime(ScalarFieldAst),
    Uuid(ScalarFieldAst),
    Email(ScalarFieldAst),
    Slug(SlugFieldAst),
    Enum(EnumFieldAst),
    Json(JsonFieldAst),
    Decimal(DecimalFieldAst),
    BigInt(ScalarFieldAst),
    Bytes(ScalarFieldAst),
    // Extended numeric / date types
    SmallInt(ScalarFieldAst),
    Date(ScalarFieldAst),
    Timestamp(ScalarFieldAst),  // TIMESTAMP (without time zone)
    Serial(ScalarFieldAst),
    BigSerial(ScalarFieldAst),
    Money(ScalarFieldAst),
    // Network / system types
    Url(ScalarFieldAst),
    Ip(ScalarFieldAst),
    Cidr(ScalarFieldAst),
    Macaddr(ScalarFieldAst),
    // Text-search / interval / xml
    Interval(ScalarFieldAst),
    TsQuery(ScalarFieldAst),
    TsVector(ScalarFieldAst),
    Xml(ScalarFieldAst),
    // Array
    Array(ArrayFieldAst),
    // Storage fields
    Image(StorageFieldAst),
    File(StorageFieldAst),
    // Geo / vector
    Geo(GeoFieldAst),
    Vector(VectorFieldAst),
    // Repeatable blocks — stored as JSONB array with type discriminator.
    Blocks(BlocksFieldAst),
    // Plugin-defined custom field type
    Custom(CustomFieldAst),
    // Relations
    Relation(RelationFieldAst),
    // Composite fields (expanded by resolver into real columns)
    Timestamps,
    Publishable,
    SoftDelete,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScalarFieldAst {
    pub pg_type: String,
    pub required: bool,
    pub unique: bool,
    #[serde(default)]
    pub primary_key: bool,
    #[serde(default)]
    pub index: bool,
    pub default: Option<DefaultValueAst>,
    pub check: Option<String>,
    /// When true the field is stored as JSONB with locale keys, e.g. {"en": "Hello", "fr": "Bonjour"}.
    #[serde(default)]
    pub localized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlugFieldAst {
    pub pg_type: String,
    pub required: bool,
    pub unique: bool,
    /// Source field name for slug generation trigger.
    pub from: String,
    #[serde(default)]
    pub localized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnumFieldAst {
    pub pg_type: String,
    pub values: Vec<String>,
    pub required: bool,
    pub unique: bool,
    pub default: Option<String>,
    #[serde(default)]
    pub localized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonFieldAst {
    pub pg_type: String,
    pub required: bool,
    #[serde(default)]
    pub localized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecimalFieldAst {
    pub pg_type: String,
    pub required: bool,
    pub precision: Option<u32>,
    pub scale: Option<u32>,
    #[serde(default)]
    pub localized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageFieldAst {
    pub pg_type: String,   // JSONB — stores storage reference
    pub required: bool,
    pub bucket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoFieldAst {
    pub pg_type: String,   // GEOGRAPHY(...)
    pub required: bool,
    pub geo_type: String,  // point | polygon | linestring
    pub srid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VectorFieldAst {
    pub pg_type: String,   // VECTOR(n)
    pub required: bool,
    pub dimensions: u32,
}

/// A repeatable-blocks field — stored as a JSONB array where each entry has a
/// `"type"` discriminator key and a `"data"` object with the block's fields.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BlocksFieldAst {
    pub required: bool,
    /// Block type definitions. Each defines a named block with its own fields.
    pub blocks: Vec<BlockDefinitionAst>,
    /// When true a GIN index is automatically created (recommended for querying).
    #[serde(default = "default_true")]
    pub index: bool,
}

fn default_true() -> bool { true }

/// Defines one block type within a `blocks` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockDefinitionAst {
    /// Machine-readable block type name, e.g. "hero".
    pub name: String,
    /// Human-readable label shown in the admin block picker.
    pub label: Option<String>,
    /// Icon identifier for the admin block picker, e.g. "image".
    pub icon: Option<String>,
    /// Fields within this block, keyed by field name.
    #[serde(default)]
    pub fields: HashMap<String, FieldAst>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationFieldAst {
    pub cardinality: RelationCardinality,
    pub target: String,
    pub foreign_key: Option<String>,
    pub references: Option<String>,  // referenced column, default "id"
    pub through: Option<String>,     // junction table for manyToMany
    pub on_delete: Option<String>,
    pub on_update: Option<String>,
    /// True when the corresponding hasOne on the other side requires the FK to be UNIQUE.
    #[serde(default)]
    pub unique_fk: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ArrayFieldAst {
    /// The Postgres element type, e.g. "TEXT", "INTEGER", "UUID".
    pub element_type: String,
    pub required: bool,
    #[serde(default)]
    pub unique: bool,
    pub default: Option<DefaultValueAst>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RelationCardinality {
    BelongsTo,
    HasMany,
    HasOne,
    ManyToMany,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum DefaultValueAst {
    Value { value: serde_json::Value },
    Expression { expr: String },
    Now,
    GenRandomUuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AccessAst {
    pub read: Option<AccessRule>,
    pub create: Option<AccessRule>,
    pub update: Option<AccessRule>,
    pub delete: Option<AccessRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum AccessRule {
    Public,
    Private,
    Authenticated,
    Owner { field: String },
    Role { roles: Vec<String> },
    Custom { expression: String },
    /// OR-join of multiple rules — any one matching grants access.
    Any { rules: Vec<AccessRule> },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ModelOptions {
    #[serde(default)]
    pub timestamps: bool,
    #[serde(default)]
    pub soft_delete: bool,
    /// When true the model is a singleton (global config) — exactly one row enforced.
    #[serde(default)]
    pub singleton: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexAst {
    pub name: Option<String>,
    pub fields: Vec<String>,
    pub unique: bool,
    pub using: IndexMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum IndexMethod {
    #[default]
    Btree,
    Gin,
    Gist,
    Hnsw,
    Brin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JunctionTableAst {
    pub name: String,
    pub model_a: String,
    pub model_b: String,
    pub fk_a: String,
    pub fk_b: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageBucketAst {
    pub id: String,
    pub public: bool,
    pub allowed_mime_types: Option<Vec<String>>,
    pub file_size_limit: Option<u64>,
}

/// A plugin-defined custom field type. The Postgres column uses `pg_type`;
/// the TypeScript client uses `ts_type`. The engine treats it like a scalar
/// for all diff, migration, and type-generation purposes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldAst {
    /// npm package name of the plugin, e.g. "@supatype/plugin-phone-field".
    pub plugin: String,
    /// The custom field type name declared by the plugin, e.g. "phone".
    pub field_type: String,
    /// Postgres column type to use, e.g. "TEXT".
    pub pg_type: String,
    /// TypeScript type for the generated client, e.g. "string".
    pub ts_type: String,
    pub required: bool,
    pub unique: bool,
    #[serde(default)]
    pub index: bool,
    pub default: Option<DefaultValueAst>,
}

/// A plugin registered for this schema via supatype.config.ts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginRegistrationAst {
    /// npm package name, e.g. "@supatype/plugin-phone-field".
    pub name: String,
    /// Installed semver version, e.g. "1.0.3".
    pub version: String,
    /// Plugin API version declared by the plugin. Engine supports API version 1.
    pub plugin_api: u32,
    /// Plugin type: "fieldType" | "composite" | "provider" | "widget".
    pub plugin_type: String,
}
