use super::doctor::{report, DoctorReport};
use crate::introspector::catalog::CatalogState;
use crate::parser::ast::SchemaAst;
use crate::state::database_state::DatabaseState;

/// The doctor's view of the database just pushed. A doctor that cannot even build its expectations
/// is itself a finding, so the failure is reported as one rather than swallowed.
fn post_push_report(
    ast: &SchemaAst,
    db: &DatabaseState,
    catalog: &CatalogState,
) -> Result<DoctorReport, String> {
    // No ledger: the checks it classifies only ever reach `unmanaged_drift`, which the post-push
    // gate does not read.
    report(ast, db, catalog, &[]).map_err(|e| format!("doctor could not run after the push: {e:#}"))
}

/// Post-push check: AST desired state vs fresh introspection.
/// Returns warning messages when managed-object drift remains.
pub fn post_push_warnings(
    ast: &SchemaAst,
    db: &DatabaseState,
    catalog: &CatalogState,
) -> Vec<String> {
    let doctor = match post_push_report(ast, db, catalog) {
        Ok(report) => report,
        Err(message) => return vec![message],
    };
    let mut warnings = Vec::new();

    for item in &doctor.missing {
        warnings.push(format!("Post-push drift (missing): {}", item.message));
    }
    for item in &doctor.stale_managed {
        warnings.push(format!("Post-push drift (stale managed): {}", item.message));
    }

    warnings
}

pub fn post_push_ok(
    ast: &SchemaAst,
    db: &DatabaseState,
    catalog: &CatalogState,
    strict: bool,
) -> bool {
    let Ok(doctor) = post_push_report(ast, db, catalog) else {
        return false;
    };
    // Missing and stale only. The report runs with no ledger, before this push records its rows,
    // so an unstamped check the push just created reads as conflicting and a hand edit cannot have
    // happened yet: neither means the push failed.
    if strict {
        doctor.missing.is_empty() && doctor.stale_managed.is_empty()
    } else {
        doctor.missing.is_empty()
    }
}
