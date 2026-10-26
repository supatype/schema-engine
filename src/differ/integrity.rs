//! The check after a push: what doctor reports on the database just pushed, read with the ledger
//! rows the push has just written, so it sees exactly what the next push would. Anything a push
//! would still change or refuse there (missing, stale, drifted or conflicting) is something this
//! push should have settled and did not.

use super::doctor::{report_of, DoctorItem};
use crate::parser::ast::SchemaAst;
use crate::push::{decide, State};

/// What the check found: a warning for each object a push would still act on, and whether there
/// was any (what `--strict` rolls the push back for). A doctor that cannot run is itself a finding.
pub struct PostPush {
    pub warnings: Vec<String>,
    pub settled: bool,
}

pub fn post_push(ast: &SchemaAst, state: &State) -> PostPush {
    let report = match decide(ast, state, None) {
        Ok(decision) => report_of(ast, state, &decision),
        Err(e) => {
            return PostPush {
                warnings: vec![format!("doctor could not run after the push: {e:#}")],
                settled: false,
            }
        }
    };
    let sections: [(&str, &[DoctorItem]); 4] = [
        ("missing", &report.missing),
        ("stale managed", &report.stale_managed),
        ("drifted", &report.drifted),
        ("conflicting", &report.conflicting),
    ];
    PostPush {
        warnings: sections
            .iter()
            .flat_map(|(what, items)| {
                items
                    .iter()
                    .map(move |item| format!("Post-push drift ({what}): {}", item.message))
            })
            .collect(),
        settled: !report.blocking,
    }
}
