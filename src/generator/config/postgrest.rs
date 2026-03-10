use crate::parser::ast::SchemaAst;
use anyhow::Result;
use serde_json::{json, Value};

/// Generate PostgREST configuration from the schema.
/// PostgREST reads from the database directly but we generate
/// the schema exposure config and any custom overrides.
pub fn generate(ast: &SchemaAst) -> Result<Value> {
    let exposed_schemas = vec!["public"];

    let tables: Vec<Value> = ast
        .models
        .iter()
        .map(|m| {
            json!({
                "schema": "public",
                "table": m.table_name,
            })
        })
        .collect();

    Ok(json!({
        "db-schemas": exposed_schemas,
        "db-extra-search-path": "public, extensions",
        "tables": tables,
    }))
}
