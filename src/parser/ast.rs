use super::annotations::{FieldAnnotations, ModelAnnotations};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Top-level schema AST as produced by @supatype/schema and consumed by the engine.
#[derive(Debug, Clone)]
pub struct SchemaAst {
    pub ast_version: u32,
    pub models: Vec<ModelAst>,
    /// Junction tables inferred by the resolver (not present in user input).
    pub junction_tables: Vec<JunctionTableAst>,
    /// Storage buckets inferred from image/file fields.
    pub storage_buckets: Vec<StorageBucketAst>,
    /// Active locales for localized fields, e.g. ["en", "fr", "de"].
    pub locales: Vec<String>,
    /// The default/fallback locale. Defaults to "en" when locales is non-empty.
    pub default_locale: Option<String>,
    /// Plugins registered for this schema (field type, composite, provider, widget).
    pub plugins: Vec<PluginRegistrationAst>,
    /// SSO / OIDC provider configuration.
    pub sso: Option<SsoConfigAst>,
    /// Warnings from parse/validation.
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

impl serde::Serialize for SchemaAst {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        super::v2::serialize_schema(self).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SchemaAst {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        super::v2::deserialize_schema(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelAst {
    pub name: String,
    /// Fields keyed by field name.
    pub fields: IndexMap<String, FieldAst>,
    #[serde(default)]
    pub options: ModelOptions,
    #[serde(default)]
    pub annotations: ModelAnnotations,
}

impl ModelAst {
    pub fn table_name(&self) -> &str {
        &self.annotations.db.table_name
    }

    pub fn table_name_mut(&mut self) -> &mut String {
        &mut self.annotations.db.table_name
    }

    pub fn access(&self) -> &AccessAst {
        &self.annotations.platform.access
    }

    pub fn access_mut(&mut self) -> &mut AccessAst {
        &mut self.annotations.platform.access
    }

    pub fn indexes(&self) -> &[IndexAst] {
        &self.annotations.db.indexes
    }

    pub fn indexes_mut(&mut self) -> &mut Vec<IndexAst> {
        &mut self.annotations.db.indexes
    }
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
    Button(JsonFieldAst),
    Decimal(DecimalFieldAst),
    BigInt(ScalarFieldAst),
    Bytes(ScalarFieldAst),
    // Extended numeric / date types
    SmallInt(ScalarFieldAst),
    Date(ScalarFieldAst),
    Timestamp(ScalarFieldAst), // TIMESTAMP (without time zone)
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
    // Color (stored as TEXT hex string)
    Color(ScalarFieldAst),
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
    #[serde(default)]
    pub read_only: bool,
    /// When non-empty (`ComputedFrom` in `@supatype/types`), Studio derives a TEXT preview from these fields until the author edits (create UX).
    #[serde(default)]
    pub sources: Vec<String>,
    /// Optional `ComputedFrom` template: `{field}` and `{truncate(field, max)}` (see `@supatype/types` JSDoc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default)]
    pub annotations: FieldAnnotations,
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
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub annotations: FieldAnnotations,
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
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub annotations: FieldAnnotations,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonFieldAst {
    pub pg_type: String,
    pub required: bool,
    #[serde(default)]
    pub localized: bool,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub annotations: FieldAnnotations,
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
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub annotations: FieldAnnotations,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum StorageAccessMode {
    Public,
    Private,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageFieldAst {
    pub pg_type: String, // JSONB — stores storage reference
    pub required: bool,
    pub bucket: String,
    #[serde(default)]
    pub access_mode: Option<StorageAccessMode>,
    #[serde(default)]
    pub read_only: bool,
    /// When true, column stores locale-keyed storage refs, e.g. `{"en":"path/a.jpg","de":"path/b.jpg"}`.
    #[serde(default)]
    pub localized: bool,
    #[serde(default)]
    pub annotations: FieldAnnotations,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoFieldAst {
    pub pg_type: String, // GEOGRAPHY(...)
    pub required: bool,
    pub geo_type: String, // point | polygon | linestring
    pub srid: Option<u32>,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub annotations: FieldAnnotations,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VectorFieldAst {
    pub pg_type: String, // VECTOR(n)
    pub required: bool,
    pub dimensions: u32,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub annotations: FieldAnnotations,
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
    #[serde(default)]
    pub read_only: bool,
    /// When true, the whole blocks array is stored per locale: `{"en":[...],"de":[...]}`.
    #[serde(default)]
    pub localized: bool,
    #[serde(default)]
    pub annotations: FieldAnnotations,
}

fn default_true() -> bool {
    true
}

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
    pub fields: IndexMap<String, FieldAst>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationFieldAst {
    pub cardinality: RelationCardinality,
    pub target: String,
    pub foreign_key: Option<String>,
    pub references: Option<String>, // referenced column, default "id"
    pub through: Option<String>,    // junction table for manyToMany
    pub on_delete: Option<String>,
    pub on_update: Option<String>,
    /// True when the corresponding hasOne on the other side requires the FK to be UNIQUE.
    #[serde(default)]
    pub unique_fk: bool,
    /// When true, belongsTo FK columns are NOT NULL.
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub annotations: FieldAnnotations,
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
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub annotations: FieldAnnotations,
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
    /// The `USING` clause of the update policy: which existing rows the caller
    /// may modify.
    pub update: Option<AccessRule>,
    /// The `WITH CHECK` clause, when it differs from `update`.
    ///
    /// An update policy has both: `USING` picks the rows that may be changed and
    /// `WITH CHECK` constrains what they may be changed *into*. With one rule for
    /// both, "you may edit your own posts" also silently means "you may reassign
    /// one to somebody else" is refused — usually right, but it makes rules like
    /// "an editor may move a post between their own sites" inexpressible. When
    /// absent, `update` is used for both, which is the safe default and what every
    /// existing schema means.
    #[serde(default)]
    pub update_check: Option<AccessRule>,
    pub delete: Option<AccessRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum AccessRule {
    Public,
    Private,
    Authenticated,
    Owner {
        field: String,
    },
    Role {
        roles: Vec<String>,
    },
    /// OR-join of multiple rules — any one matching grants access.
    Any {
        rules: Vec<AccessRule>,
    },
    /// AND-join — every rule must match.
    All {
        rules: Vec<AccessRule>,
    },
    /// Negation of a rule.
    Not {
        rule: Box<AccessRule>,
    },
    /// A binary comparison between two operands.
    Compare {
        left: Operand,
        op: CompareOp,
        right: Operand,
    },
    /// Membership: the column's value appears in a set.
    ///
    /// This is what makes "the sites this user belongs to" expressible. Compiles
    /// to a semi-join (`EXISTS`), not `IN (SELECT ...)`, so the planner can stop
    /// at the first match per row instead of materialising the whole set.
    In {
        column: String,
        source: MembershipSource,
    },
    /// `IS NULL` / `IS NOT NULL` on an operand.
    ///
    /// Its own variant rather than a `CompareOp`, because SQL null comparison is
    /// not an equality: `col = NULL` is null, never true, so rendering it through
    /// the comparison path would produce a policy that silently denies everything.
    NullCheck {
        operand: Operand,
        /// true for `IS NULL`, false for `IS NOT NULL`.
        ///
        /// Renamed explicitly: `rename_all` on an enum renames its *variants*, not
        /// the fields inside them, and the AST JSON the CLI emits is camelCase
        /// throughout.
        #[serde(rename = "isNull")]
        is_null: bool,
    },
}

/// Where the set on the right of an `In` comes from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum MembershipSource {
    /// A JWT claim holding an array, e.g. `app_metadata.sites`.
    Claim { path: String },
    /// Rows of another table — a join table, typically. `where` narrows it to the
    /// caller's own rows, which is what makes it a membership check rather than a
    /// lookup of everything.
    Rows {
        table: String,
        column: String,
        #[serde(default, rename = "where")]
        filter: Option<Box<AccessRule>>,
    },
    /// A fixed list written in the schema.
    Literal { values: Vec<LiteralValue> },
}

/// One side of a comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Operand {
    /// A column on the model the policy is attached to.
    Column { name: String },
    /// `auth.uid()`, wrapped so the planner evaluates it once per query.
    AuthUid,
    /// `auth.role()`, wrapped for the same reason.
    AuthRole,
    /// A nested JWT claim by dotted path, e.g. `app_metadata.tier`.
    Claim { path: String },
    /// A constant supplied in the schema.
    Literal { value: LiteralValue },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum LiteralValue {
    Bool(bool),
    Number(f64),
    Text(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CompareOp {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    Like,
}

impl CompareOp {
    pub fn sql(self) -> &'static str {
        match self {
            CompareOp::Eq => "=",
            CompareOp::Neq => "<>",
            CompareOp::Gt => ">",
            CompareOp::Gte => ">=",
            CompareOp::Lt => "<",
            CompareOp::Lte => "<=",
            CompareOp::Like => "LIKE",
        }
    }
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
    /// Correlates with `storage.buckets.access_mode` and S3 provisioning (`public` | `private` | `custom`).
    #[serde(default)]
    pub access_mode: Option<StorageAccessMode>,
    /// Bucket-scoped RLS on `storage.objects`; when set, overrides model-derived policies for this bucket id.
    #[serde(default)]
    pub access: Option<AccessAst>,
    /// Raw S3 bucket policy JSON; overrides default public-read policy when supplied.
    #[serde(default)]
    pub s3_bucket_policy: Option<String>,
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
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub annotations: FieldAnnotations,
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

/// SSO / OIDC provider configuration (Phase 11).
/// When `enabled` is true the engine creates the `_sso` schema and all
/// `oauth_*` tables on the next `push`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsoConfigAst {
    pub enabled: bool,
    /// Lifetime of access tokens in seconds (default 3600 = 1 hour).
    #[serde(default = "SsoConfigAst::default_access_token_expiry_secs")]
    pub access_token_expiry_secs: u32,
    /// Lifetime of refresh tokens in days (default 30).
    #[serde(default = "SsoConfigAst::default_refresh_token_expiry_days")]
    pub refresh_token_expiry_days: u32,
    /// RSA signing key rotation interval in days (default 90).
    #[serde(default = "SsoConfigAst::default_key_rotation_days")]
    pub key_rotation_days: u32,
}

impl SsoConfigAst {
    fn default_access_token_expiry_secs() -> u32 {
        3600
    }
    fn default_refresh_token_expiry_days() -> u32 {
        30
    }
    fn default_key_rotation_days() -> u32 {
        90
    }
}
