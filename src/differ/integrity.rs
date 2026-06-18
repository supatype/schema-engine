use super::doctor::{has_strict_issues, report};
use crate::parser::ast::SchemaAst;
use crate::state::database_state::DatabaseState;

/// Post-push check: AST desired state vs fresh introspection.
/// Returns warning messages when managed-object drift remains.
pub fn post_push_warnings(ast: &SchemaAst, db: &DatabaseState) -> Vec<String> {
    let doctor = report(ast, db);
    let mut warnings = Vec::new();

    for item in &doctor.missing {
        warnings.push(format!("Post-push drift (missing): {}", item.message));
    }
    for item in &doctor.stale_managed {
        warnings.push(format!("Post-push drift (stale managed): {}", item.message));
    }

    warnings
}

pub fn post_push_ok(ast: &SchemaAst, db: &DatabaseState, strict: bool) -> bool {
    let doctor = report(ast, db);
    if strict {
        !has_strict_issues(&doctor)
    } else {
        doctor.missing.is_empty()
    }
}
