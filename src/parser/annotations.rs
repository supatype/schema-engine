use super::ast::{AccessAst, AccessRule, IndexAst};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelAnnotations {
    #[serde(default)]
    pub db: DbModelAnnotations,
    #[serde(default)]
    pub platform: PlatformModelAnnotations,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbModelAnnotations {
    #[serde(default)]
    pub table_name: String,
    #[serde(default)]
    pub indexes: Vec<IndexAst>,
    /// Model-level `CHECK` rules, in the same node vocabulary as access rules but with a narrower
    /// operand set. Beside `indexes` because both are things Postgres holds, unlike `access`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<AccessRule>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformModelAnnotations {
    #[serde(default)]
    pub access: AccessAst,
    /// Columns Studio's list view searches, in the order the schema asked for.
    ///
    /// The CLI merges both spellings — `Searchable<T>` on a field and `searchable: [...]` on the
    /// model — into this one list, so there is nothing per-field to read here. Empty means the
    /// schema said nothing, not that search is off: see `derive_search_fields`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search_fields: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldAnnotations {
    #[serde(default)]
    pub db: DbFieldAnnotations,
    #[serde(default)]
    pub platform: PlatformFieldAnnotations,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DbFieldAnnotations {
    #[serde(default)]
    pub pg_type: String,
    #[serde(default)]
    pub unique: bool,
    #[serde(default)]
    pub index: bool,
    #[serde(default)]
    pub foreign_key: Option<String>,
    #[serde(default)]
    pub server_generated: bool,
    /// Array element type (kind `array`).
    #[serde(default)]
    pub element_type: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformFieldAnnotations {
    #[serde(default)]
    pub editor: Option<String>,
    #[serde(default)]
    pub read_only: bool,
}
