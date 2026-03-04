// The desired state — derived from the parsed SchemaAst.
// Used as the left-hand side of the diff computation.
// Re-exported from parser::ast for now; will be a separate projection when needed.
pub use crate::parser::ast::SchemaAst as TargetState;
