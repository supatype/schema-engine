use super::ast::SchemaAst;
use anyhow::{bail, Result};

pub fn validate(ast: SchemaAst) -> Result<SchemaAst> {
    let _model_names: std::collections::HashSet<&str> =
        ast.models.iter().map(|m| m.name.as_str()).collect();

    for model in &ast.models {
        if model.name.is_empty() {
            bail!("Model name cannot be empty");
        }
        if model.table_name.is_empty() {
            bail!("Model '{}' has an empty table name", model.name);
        }
    }

    // TODO: validate relation targets exist, slug source fields exist, etc.

    Ok(ast)
}
