pub mod accessors;
pub mod annotations;
pub mod ast;
pub mod normaliser;
pub mod resolver;
pub mod validator;
pub mod v2;

use anyhow::Result;
use ast::SchemaAst;

pub fn parse(input: &str) -> Result<SchemaAst> {
    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|e| anyhow::anyhow!("Invalid schema AST JSON: {e}"))?;
    let raw = v2::deserialize_schema(&value)?;
    let validated = validator::validate(raw)?;
    let resolved = resolver::resolve(validated)?;
    Ok(normaliser::normalise(resolved))
}
