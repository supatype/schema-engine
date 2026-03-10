//! SDK execution tests — Phase 10 requirement.
//!
//! Each test generates typed client code for a language, writes it to a temp
//! file, and invokes the real compiler/interpreter to verify the output is
//! syntactically valid and type-correct.
//!
//! Tests skip gracefully (print a message and return) when the required
//! toolchain is not installed. Set `SUPATYPE_FORCE_EXEC_TESTS=1` to
//! hard-fail instead of skipping.
//!
//! WASM build test: requires `rustup target add wasm32-unknown-unknown`.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use supatype_engine::{generator::sdk, parser};

// ─── Shared test schema ────────────────────────────────────────────────────────

/// A small but representative schema covering: uuid PK, required text, optional int,
/// required bool, enum field, and a timestamps composite — enough to exercise all
/// major type-mapping branches in every SDK generator.
const TEST_SCHEMA: &str = r#"{
    "models": [{
        "name": "Article",
        "tableName": "articles",
        "fields": {
            "id":           { "kind": "uuid",    "pgType": "UUID",    "primaryKey": true, "required": true,  "unique": false, "default": { "kind": "genRandomUuid" } },
            "title":        { "kind": "text",    "pgType": "TEXT",    "required": true,  "unique": false },
            "viewCount":    { "kind": "integer", "pgType": "INTEGER", "required": false, "unique": false },
            "published":    { "kind": "boolean", "pgType": "BOOLEAN", "required": true,  "unique": false },
            "status":       { "kind": "enum",    "pgType": "TEXT",    "required": true,  "unique": false, "values": ["draft", "published", "archived"], "default": "draft" },
            "_timestamps":  { "kind": "timestamps" }
        },
        "access": {}, "indexes": [], "options": { "timestamps": true, "softDelete": false, "singleton": false }
    }]
}"#;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join("supatype_sdk_tests")
}

fn write_temp(filename: &str, content: &str) -> PathBuf {
    let dir = temp_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join(filename);
    fs::write(&path, content).expect("write temp file");
    path
}

/// Returns Some(binary_name) if any candidate is on PATH, or None if none found.
fn find_bin(candidates: &[&str]) -> Option<String> {
    for name in candidates {
        let ok = Command::new(name)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Some(name.to_string());
        }
    }
    None
}

/// Returns Some(bin) if available, None to signal skip.
/// Panics if `SUPATYPE_FORCE_EXEC_TESTS=1` and bin not found.
fn try_bin(candidates: &[&str]) -> Option<String> {
    match find_bin(candidates) {
        Some(b) => Some(b),
        None => {
            if std::env::var("SUPATYPE_FORCE_EXEC_TESTS").is_ok() {
                panic!(
                    "Required binary not found: {}. \
                     Install it or unset SUPATYPE_FORCE_EXEC_TESTS.",
                    candidates.join(" / ")
                );
            }
            None
        }
    }
}

fn assert_command_success(cmd: &mut Command, description: &str) {
    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("{} failed to spawn: {}", description, e));
    if !output.status.success() {
        panic!(
            "{} exited with {}\nstdout:\n{}\nstderr:\n{}",
            description,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn generate(lang: &str) -> String {
    let ast = parser::parse(TEST_SCHEMA).expect("parse test schema");
    sdk::generate(&ast, lang).expect("generate SDK code")
}

// ─── Python ────────────────────────────────────────────────────────────────────

#[test]
fn test_sdk_exec_python() {
    let Some(python) = try_bin(&["python3", "python"]) else {
        eprintln!("[sdk_exec] SKIP python — python3/python not found on PATH");
        return;
    };
    let code = generate("python");
    let path = write_temp("supatype_test.py", &code);

    assert_command_success(
        Command::new(&python).arg(&path),
        "python interpreter on generated types",
    );
}

// ─── Go ───────────────────────────────────────────────────────────────────────

#[test]
fn test_sdk_exec_go() {
    let Some(go) = try_bin(&["go"]) else {
        eprintln!("[sdk_exec] SKIP go — go not found on PATH");
        return;
    };
    let code = generate("go");

    // Go requires a proper module structure: temp dir + go.mod + types.go
    let dir = temp_dir().join("go_sdk");
    fs::create_dir_all(&dir).expect("create go temp dir");
    fs::write(dir.join("types.go"), &code).expect("write types.go");
    fs::write(dir.join("go.mod"), "module supatype_test\n\ngo 1.21\n").expect("write go.mod");

    assert_command_success(
        Command::new(&go).args(["vet", "./..."]).current_dir(&dir),
        "go vet on generated types",
    );
}

// ─── PHP ──────────────────────────────────────────────────────────────────────

#[test]
fn test_sdk_exec_php() {
    let Some(php) = try_bin(&["php"]) else {
        eprintln!("[sdk_exec] SKIP php — php not found on PATH");
        return;
    };
    let code = generate("php");
    let path = write_temp("supatype_test.php", &code);

    // `php -l` performs a syntax check without executing the file
    assert_command_success(
        Command::new(&php).args(["-l", path.to_str().unwrap()]),
        "php -l syntax check on generated types",
    );
}

// ─── Swift ────────────────────────────────────────────────────────────────────

#[test]
fn test_sdk_exec_swift() {
    let Some(swiftc) = try_bin(&["swiftc"]) else {
        eprintln!(
            "[sdk_exec] SKIP swift — swiftc not found on PATH (install Xcode or Swift toolchain)"
        );
        return;
    };
    let code = generate("swift");
    let path = write_temp("supatype_test.swift", &code);

    // -typecheck verifies type correctness without linking
    assert_command_success(
        Command::new(&swiftc).args(["-typecheck", path.to_str().unwrap()]),
        "swiftc -typecheck on generated types",
    );
}

// ─── Kotlin ───────────────────────────────────────────────────────────────────

#[test]
fn test_sdk_exec_kotlin() {
    let Some(kotlinc) = try_bin(&["kotlinc", "kotlinc-jvm"]) else {
        eprintln!("[sdk_exec] SKIP kotlin — kotlinc not found on PATH (install Kotlin or SDKMAN)");
        return;
    };
    let code = generate("kotlin");
    let path = write_temp("SupatypeTest.kt", &code);
    let jar_path = temp_dir().join("supatype_test_kotlin.jar");

    assert_command_success(
        Command::new(&kotlinc).args([
            path.to_str().unwrap(),
            "-include-runtime",
            "-d",
            jar_path.to_str().unwrap(),
        ]),
        "kotlinc compile on generated types",
    );
}

// ─── Dart ─────────────────────────────────────────────────────────────────────

#[test]
fn test_sdk_exec_dart() {
    let Some(dart) = try_bin(&["dart"]) else {
        eprintln!("[sdk_exec] SKIP dart — dart not found on PATH (install Dart SDK or Flutter)");
        return;
    };
    let code = generate("dart");
    let path = write_temp("supatype_test.dart", &code);

    // `dart analyze` performs static type analysis
    assert_command_success(
        Command::new(&dart).args(["analyze", path.to_str().unwrap()]),
        "dart analyze on generated types",
    );
}

// ─── WASM build ───────────────────────────────────────────────────────────────

#[test]
fn test_wasm_build() {
    // Verify the library crate compiles to wasm32-unknown-unknown.
    // DB-dependent modules (sql generator, introspector, state, differ) are
    // cfg-gated out for wasm32 in lib.rs and generator/mod.rs.
    //
    // Install the target with: rustup target add wasm32-unknown-unknown

    let target_installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("wasm32-unknown-unknown"))
        .unwrap_or(false);

    if !target_installed {
        if std::env::var("SUPATYPE_FORCE_EXEC_TESTS").is_ok() {
            panic!(
                "wasm32-unknown-unknown target not installed. \
                 Run: rustup target add wasm32-unknown-unknown"
            );
        }
        eprintln!(
            "[sdk_exec] SKIP wasm build — wasm32-unknown-unknown not installed. \
             Run `rustup target add wasm32-unknown-unknown` then re-run."
        );
        return;
    }

    assert_command_success(
        Command::new("cargo")
            .args(["build", "--lib", "--target", "wasm32-unknown-unknown"])
            .current_dir(env!("CARGO_MANIFEST_DIR")),
        "cargo build --lib --target wasm32-unknown-unknown",
    );
}
