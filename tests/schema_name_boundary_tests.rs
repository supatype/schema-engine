//! A schema name the engine is given must be a plain identifier (Q1, Q3).
//!
//! The project schema is written unquoted in places, the masking labels among them, and a `$` in a
//! name can end a dollar-quoted function body early. Rather than quote every such place and hope
//! none is missed, a name that is not `^[a-z_][a-z0-9_]*$` and at most 63 bytes is refused where it
//! enters: the binary's `--schema` and `--auth-schema`, and the HTTP server's `schema` and
//! `auth_schema`. The CLI refuses the same names when it reads the config.

use std::process::Command;

use serde_json::json;
use supatype_engine::server::types::{AuthFunctionsRequest, DbRequest};
use supatype_engine::sql_quote::plain_schema_name;

const REFUSED: &[&str] = &[
    "a$b",
    "Public",
    "my-app",
    "1app",
    "app;drop",
    "x\"y",
    "",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
];

#[test]
fn only_plain_identifiers_are_schema_names() {
    for name in ["public", "app", "_private", "tenant_42", &"a".repeat(63)] {
        assert!(
            plain_schema_name(name).is_ok(),
            "{name} is a plain identifier"
        );
    }
    for name in REFUSED {
        let err = plain_schema_name(name).expect_err(name);
        assert!(err.contains("^[a-z_][a-z0-9_]*$"), "{err}");
    }
}

fn engine() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_supatype-engine"));
    cmd.env_remove("DATABASE_URL");
    cmd
}

/// Refused by the argument parser, before the engine reads any input or connects anywhere.
#[test]
fn the_binary_refuses_a_schema_name_with_a_dollar() {
    let out = engine()
        .args([
            "diff",
            "--database-url",
            "postgres://nobody@127.0.0.1:1/none",
            "--schema",
            "a$b",
        ])
        .output()
        .expect("run the engine");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--schema"), "{stderr}");
    assert!(stderr.contains("plain identifier"), "{stderr}");
}

#[test]
fn the_binary_refuses_an_auth_schema_that_is_not_plain() {
    let out = engine()
        .args(["auth-functions", "--auth-schema", "Auth"])
        .output()
        .expect("run the engine");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("plain identifier"), "{stderr}");
}

#[test]
fn the_server_refuses_a_schema_name_that_is_not_plain() {
    let err = serde_json::from_value::<DbRequest>(json!({ "schema": "a$b" }))
        .err()
        .expect("a `$` in the schema is refused");
    assert!(err.to_string().contains("plain identifier"), "{err}");
    let ok = serde_json::from_value::<DbRequest>(json!({ "schema": "app" }));
    assert!(ok.is_ok(), "a plain name is accepted");
    let defaulted = serde_json::from_value::<DbRequest>(json!({})).expect("schema defaults");
    assert_eq!(defaulted.schema, "public");

    let err = serde_json::from_value::<AuthFunctionsRequest>(json!({ "auth_schema": "my-auth" }))
        .err()
        .expect("a hyphen in the auth schema is refused");
    assert!(err.to_string().contains("plain identifier"), "{err}");
}
