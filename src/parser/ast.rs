use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level schema AST as produced by @definatype/schema and consumed by the engine.
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
    /// Warnings from parse/validation.
    #[serde(default)]
    pub warnings: Vec<String>,
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
    // Storage fields
    Image(StorageFieldAst),
    File(StorageFieldAst),
    // Geo / vector
    Geo(GeoFieldAst),
    Vector(VectorFieldAst),
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlugFieldAst {
    pub pg_type: String,
    pub required: bool,
    pub unique: bool,
    /// Source field name for slug generation trigger.
    pub from: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnumFieldAst {
    pub pg_type: String,
    pub values: Vec<String>,
    pub required: bool,
    pub unique: bool,
    pub default: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonFieldAst {
    pub pg_type: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecimalFieldAst {
    pub pg_type: String,
    pub required: bool,
    pub precision: Option<u32>,
    pub scale: Option<u32>,
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
    Owner { field: String },
    Role { roles: Vec<String> },
    Custom { expression: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ModelOptions {
    #[serde(default)]
    pub timestamps: bool,
    #[serde(default)]
    pub soft_delete: bool,
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
