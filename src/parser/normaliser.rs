use super::ast::SchemaAst;
use super::resolver::to_snake_case;

/// Apply naming conventions and fill in defaults.
pub fn normalise(mut ast: SchemaAst) -> SchemaAst {
    for model in &mut ast.models {
        // Ensure table_name follows snake_case convention
        if model.table_name.is_empty() {
            model.table_name = to_snake_case(&model.name);
        }
    }
    ast
}
