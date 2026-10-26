//! Embeds the engine's version and build target at compile time.
//!
//! ENGINE_VERSION is what `--version`, `capabilities`, the server's health route and every row of
//! `_supatype.migrations` report, so it has to name the build, not just the crate:
//!
//! * a release build sets `SUPATYPE_ENGINE_RELEASE` to the version it is releasing, which must be
//!   the crate version, and reports exactly that;
//! * every other build (CI, the release train, a local `cargo build`) reports a pre-release of the
//!   next minor, `<major>.<minor + 1>.0-dev`, plus the commit as build metadata when it is known:
//!   `SUPATYPE_ENGINE_BUILD_SHA`, else `git rev-parse` in the checkout. A Docker build has no
//!   `.git`, so its callers pass the commit as a build argument.
//!
//! Release-please stays the only writer of `Cargo.toml`: nothing here edits the crate version.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SUPATYPE_ENGINE_RELEASE");
    println!("cargo:rerun-if-env-changed=SUPATYPE_ENGINE_BUILD_SHA");
    let crate_version = std::env::var("CARGO_PKG_VERSION").unwrap();
    println!(
        "cargo:rustc-env=ENGINE_VERSION={}",
        engine_version(&crate_version)
    );
    println!(
        "cargo:rustc-env=BUILD_TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn engine_version(crate_version: &str) -> String {
    if let Some(release) = non_empty_env("SUPATYPE_ENGINE_RELEASE") {
        assert!(
            release == crate_version,
            "SUPATYPE_ENGINE_RELEASE is {release} but Cargo.toml is {crate_version}: \
             a release build must be built from the release commit"
        );
        return release;
    }
    let pre = next_minor_dev(crate_version);
    match build_sha() {
        Some(sha) => format!("{pre}+{sha}"),
        None => pre,
    }
}

/// `0.6.0` -> `0.7.0-dev`: after the last release and before the next one in semver order.
fn next_minor_dev(crate_version: &str) -> String {
    let core = crate_version
        .split(['-', '+'])
        .next()
        .unwrap_or(crate_version);
    let mut parts = core.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    format!("{major}.{}.0-dev", minor + 1)
}

/// The commit being built, as twelve hex digits: the one the caller names, else the checkout's.
fn build_sha() -> Option<String> {
    if let Some(given) = non_empty_env("SUPATYPE_ENGINE_BUILD_SHA") {
        let sha = short_sha(&given);
        assert!(
            sha.is_some(),
            "SUPATYPE_ENGINE_BUILD_SHA must be a hex commit, got {given:?}"
        );
        return sha;
    }
    watch_git_head();
    git(&["rev-parse", "HEAD"]).and_then(|head| short_sha(&head))
}

fn short_sha(raw: &str) -> Option<String> {
    let sha = raw.trim().to_ascii_lowercase();
    let valid = sha.len() >= 7 && sha.chars().all(|c| c.is_ascii_hexdigit());
    valid.then(|| sha.chars().take(12).collect())
}

/// Rebuild when the checkout moves to another commit, so the version never names a stale one.
/// Only files that exist are watched: Cargo reruns the script on every build for a missing one.
fn watch_git_head() {
    let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") else {
        return;
    };
    let mut watched = vec!["HEAD".to_string(), "packed-refs".to_string()];
    watched.extend(git(&["symbolic-ref", "-q", "HEAD"]));
    for name in watched {
        let Some(path) = git(&["rev-parse", "--git-path", &name]) else {
            continue;
        };
        if Path::new(&dir).join(&path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
}

/// Runs git in the crate's directory: its trimmed stdout, or None when git or the checkout is
/// missing (a Docker build context, a source tarball).
fn git(args: &[&str]) -> Option<String> {
    let dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let out = Command::new("git")
        .args(args)
        .current_dir(Path::new(&dir))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!text.is_empty()).then_some(text)
}
