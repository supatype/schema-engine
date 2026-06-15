use super::ast::{AccessAst, IndexAst};
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformModelAnnotations {
    #[serde(default)]
    pub access: AccessAst,
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
