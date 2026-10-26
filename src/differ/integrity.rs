//! The check after a push: what doctor reports on the database just pushed, read with the ledger
//! rows the push has just written, so it sees exactly what the next push would. Anything a push
//! would still change or refuse there (missing, stale, drifted or conflicting) is something this
//! push should have settled and did not. What the push itself finishes after its commit (an index
//! built concurrently, a key or check validated) is not yet there, and is not counted (IN-C 2).

use std::collections::BTreeSet;

use super::doctor::{report_of, DoctorItem};
use crate::desired::ObjectKey;
use crate::parser::ast::SchemaAst;
use crate::push::{decide, State};

/// What the check found: a warning for each object a push would still act on, and whether there
/// was any (what `--strict` rolls the push back for). A doctor that cannot run is itself a finding.
pub struct PostPush {
    pub warnings: Vec<String>,
    pub settled: bool,
}

/// The check, with `after_commit` (the objects this push puts in place once it commits) left out
/// of every finding.
pub fn post_push(ast: &SchemaAst, state: &State, after_commit: &BTreeSet<ObjectKey>) -> PostPush {
    let mut report = match decide(ast, state, None) {
        Ok(decision) => report_of(ast, state, &decision),
        Err(e) => {
            return PostPush {
                warnings: vec![format!("doctor could not run after the push: {e:#}")],
                settled: false,
            }
        }
    };
    let finished_later = |item: &DoctorItem| {
        after_commit
            .iter()
            .any(|k| k.kind.as_str() == item.kind && k.parent == item.table && k.name == item.name)
    };
    for items in [
        &mut report.missing,
        &mut report.stale_managed,
        &mut report.drifted,
    ] {
        items.retain(|item| !finished_later(item));
    }
    let sections: [(&str, &[DoctorItem]); 4] = [
        ("missing", &report.missing),
        ("stale managed", &report.stale_managed),
        ("drifted", &report.drifted),
        ("conflicting", &report.conflicting),
    ];
    let warnings: Vec<String> = sections
        .iter()
        .flat_map(|(what, items)| {
            items
                .iter()
                .map(move |item| format!("Post-push drift ({what}): {}", item.message))
        })
        .collect();
    PostPush {
        settled: warnings.is_empty(),
        warnings,
    }
}
