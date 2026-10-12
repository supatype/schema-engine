//! The engine carries its licence.
//!
//! The Business Source License asks the Licensor to "conspicuously display this License on each
//! original or modified copy of the Licensed Work". A binary on its own, downloaded by the CLI or
//! copied out of the image, is such a copy, so it embeds the repository's `LICENSE` and prints it
//! on `supatype-engine licence`. `--help` names the licence, and `--version` keeps the one-line
//! format the release workflow and the CLI parse.
//!
//! The licence-key flag that once sat beside it is gone: it validated nothing, and every key read
//! as the free tier.

use std::path::PathBuf;
use std::process::{Command, Output};

fn engine(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_supatype-engine"))
        .args(args)
        .env_remove("DATABASE_URL")
        .output()
        .expect("run the engine")
}

fn stdout(out: &Output) -> String {
    assert!(
        out.status.success(),
        "the engine failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn license_file() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("LICENSE");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The value of one Parameters line, `Name:   value`, from the licence text.
fn parameter(text: &str, name: &str) -> String {
    let prefix = format!("{name}:");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("the licence has no `{name}:` line"))
        .trim()
        .to_string()
}

#[test]
fn licence_prints_the_business_source_license() {
    let printed = stdout(&engine(&["licence"]));
    assert!(
        printed.starts_with("Business Source License 1.1"),
        "{printed}"
    );
    assert_eq!(parameter(&printed, "Licensor"), "Supatype Ltd");
    assert_eq!(
        parameter(&printed, "Change License"),
        "Apache License, Version 2.0"
    );
    assert!(printed.contains("The Licensed Work is (c) 2026 Supatype Ltd."));
    assert!(printed.contains("Not to modify this License in any other way."));
}

/// Both spellings print the repository's LICENSE exactly.
#[test]
fn licence_prints_the_repository_licence_word_for_word() {
    let expected = license_file();
    for spelling in ["licence", "license"] {
        assert_eq!(stdout(&engine(&[spelling])), expected, "`{spelling}`");
    }
}

#[test]
fn help_names_the_licence() {
    let help = stdout(&engine(&["--help"]));
    assert!(
        help.contains("Licensed under the Business Source License 1.1"),
        "{help}"
    );
}

#[test]
fn the_licence_names_this_version() {
    assert_eq!(
        parameter(&license_file(), "Licensed Work"),
        format!("Supatype Schema Engine {}", env!("CARGO_PKG_VERSION"))
    );
}

/// `capabilities` needs nothing else, so the flag is the only thing that can fail it.
#[test]
fn there_is_no_licence_key_flag() {
    let out = engine(&["--license", "any-key", "capabilities"]);
    assert!(!out.status.success(), "--license is still accepted");
}
