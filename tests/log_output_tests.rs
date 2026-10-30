//! The engine's log goes to stderr, and only a terminal gets colour.
//!
//! The CLI and the tests read that stderr through a pipe. Colour codes written into it reach a
//! log file or an error message as raw escape bytes, and anything that parses a line (its
//! timestamp, say) has to strip them first.

use std::process::Command;

#[test]
fn piped_log_lines_carry_no_colour_codes() {
    let out = Command::new(env!("CARGO_BIN_EXE_supatype-engine"))
        .args(["licence", "--log", "info"])
        .env_remove("DATABASE_URL")
        .env_remove("NO_COLOR")
        .output()
        .expect("run the engine");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("supatype-engine starting"),
        "the engine logged no start line: {stderr}"
    );
    assert!(
        !stderr.contains('\u{1b}'),
        "piped stderr carries colour codes: {stderr:?}"
    );
}
