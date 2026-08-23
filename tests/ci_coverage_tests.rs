//! Guards the CI workflow's test allowlist against drift.
//!
//! `cargo test --test X` builds only the targets it names, so a suite absent from every list in
//! `.github/workflows/ci.yml` never executes. That is not hypothetical: 15 of 24 suites were in
//! that state on main, including every field-level-access suite written for the access-control
//! work stream. `cargo check --all-targets` kept them compiling, which is why it went unnoticed.
//!
//! This test fails when a file in `tests/` is not named in the workflow. Adding a suite means
//! adding it to a job, and choosing which one: the unit job has no database, the integration job
//! has Postgres and `DATABASE_URL`.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `tests/*.rs` suite, by target name. `common/` is a module, not a target.
fn suite_names() -> BTreeSet<String> {
    let dir = repo_root().join("tests");
    fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("read dir entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .map(|path| {
            path.file_stem()
                .expect("test file has a stem")
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

fn workflow_source() -> String {
    let path = repo_root().join(".github/workflows/ci.yml");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn every_test_suite_runs_in_ci() {
    let workflow = workflow_source();

    // `--test <name>` is the only form that runs a suite. Matching the bare name instead would
    // count a mention in a comment, which is exactly the false green this test exists to prevent.
    let orphaned: Vec<String> = suite_names()
        .into_iter()
        .filter(|name| !workflow.contains(&format!("--test {name}")))
        .collect();

    assert!(
        orphaned.is_empty(),
        "these suites are in tests/ but named in no CI job, so they never run: {}.\n\
         Add each to a job in .github/workflows/ci.yml: the unit job for suites needing no \
         database, the integration job for suites using `mod common`.",
        orphaned.join(", ")
    );
}

/// Whether a suite declares the shared Postgres harness.
///
/// Matched as a declaration at the start of a line, not as a substring: this file mentions
/// `mod common` in its own assertion messages, and an unanchored search classified *itself* as
/// needing a database. A guard that miscounts is worse than no guard.
fn declares_common_module(source: &str) -> bool {
    source
        .lines()
        .any(|line| line.trim_start().starts_with("mod common;"))
}

/// The integration job is the only one with a database, so it is the only place the force flag
/// does anything. A suite using `mod common` listed in the unit job would skip there for want of
/// `DATABASE_URL`, and report green.
#[test]
fn database_suites_run_in_the_integration_job() {
    let workflow = workflow_source();
    let integration_job = workflow
        .split_once("  integration:")
        .expect("ci.yml has an `integration:` job")
        .1;

    let mut misplaced = Vec::new();
    for name in suite_names() {
        let source = fs::read_to_string(repo_root().join("tests").join(format!("{name}.rs")))
            .unwrap_or_else(|e| panic!("read suite {name}: {e}"));
        let needs_db = declares_common_module(&source);
        let in_integration_job = integration_job.contains(&format!("--test {name}"));
        if needs_db && !in_integration_job {
            misplaced.push(name);
        }
    }

    assert!(
        misplaced.is_empty(),
        "these suites use `mod common`, so they need the integration job's Postgres, but are \
         not listed there: {}",
        misplaced.join(", ")
    );
}

/// A skip that reports green is the failure mode this whole file guards, so the flag that turns
/// skips into failures must actually be set on the job that can skip.
#[test]
fn the_integration_job_forces_skips_to_fail() {
    let workflow = workflow_source();
    let integration_job = workflow
        .split_once("  integration:")
        .expect("ci.yml has an `integration:` job")
        .1;

    assert!(
        integration_job.contains("SUPATYPE_FORCE_INTEGRATION_TESTS"),
        "the integration job must set SUPATYPE_FORCE_INTEGRATION_TESTS, or a suite that cannot \
         reach the database passes without asserting anything"
    );
}
