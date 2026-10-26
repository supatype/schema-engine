//! Every build says which build it is.
//!
//! A candidate built from the stack tip used to report `0.6.0`, the same as the 0.6.0 release, so
//! `--version`, `capabilities` and the `engine_version` each push records in `_supatype.migrations`
//! could not tell the two apart (A2-N5). Only a release build (`SUPATYPE_ENGINE_RELEASE` set to the
//! crate version at compile time) reports the crate version; every other build reports a
//! pre-release of the next minor, `<major>.<minor + 1>.0-dev`, with the commit as build metadata
//! when it is known (`0.7.0-dev+1a2b3c4d5e6f`).

mod common;

use std::process::Command;

const ONE_MODEL: &str = r#"{
  "astVersion": 2,
  "models": [{
    "name": "Gadget",
    "fields": {
      "id": { "kind": "integer", "primaryKey": true, "required": true,
              "annotations": { "db": { "pgType": "INTEGER", "unique": false } } }
    },
    "options": {},
    "annotations": { "db": { "tableName": "gadget", "indexes": [] }, "platform": {} }
  }]
}"#;

/// Whether this test binary was compiled as part of a release build.
fn release_build() -> bool {
    option_env!("SUPATYPE_ENGINE_RELEASE").is_some_and(|v| !v.is_empty())
}

/// The version this build must report: the crate version for a release, otherwise a pre-release
/// of the next minor. Checked by shape, since the commit is not known here.
fn assert_build_version(version: &str) {
    let crate_version = env!("CARGO_PKG_VERSION");
    if release_build() {
        assert_eq!(
            version, crate_version,
            "a release build reports the crate version"
        );
        return;
    }
    let mut parts = crate_version.split('.').map(|p| p.parse::<u64>().unwrap());
    let (major, minor) = (parts.next().unwrap(), parts.next().unwrap());
    let next = format!("{major}.{}.0-dev", minor + 1);
    let metadata = version
        .strip_prefix(&next)
        .unwrap_or_else(|| panic!("a non-release build reports {next}[+<commit>], got {version}"));
    let commit = metadata.strip_prefix('+').unwrap_or(metadata);
    assert!(
        metadata.is_empty() || (metadata.starts_with('+') && is_commit(commit)),
        "build metadata after {next} must be +<hex commit>, got {version}"
    );
}

fn is_commit(s: &str) -> bool {
    (7..=40).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn engine() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_supatype-engine"));
    cmd.env_remove("DATABASE_URL");
    cmd
}

/// What `--version` prints after the binary's name.
fn reported_version() -> String {
    let out = engine().arg("--version").output().expect("run the engine");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .trim()
        .strip_prefix("supatype-engine ")
        .unwrap_or_else(|| panic!("unexpected --version output: {stdout}"))
        .to_string()
}

#[test]
fn version_flag_reports_which_build_this_is() {
    assert_build_version(&reported_version());
}

#[test]
fn capabilities_reports_the_same_version_as_the_version_flag() {
    let out = engine()
        .arg("capabilities")
        .output()
        .expect("run the engine");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let version = body["version"]
        .as_str()
        .unwrap_or_else(|| panic!("capabilities has no version: {body}"));
    assert_build_version(version);
    assert_eq!(version, reported_version());
}

#[tokio::test]
async fn a_push_records_the_version_of_the_engine_that_ran_it() {
    common::with_integration_url(|url| async move {
        let input = std::env::temp_dir().join(format!(
            "engine-version-{}-{}.json",
            std::process::id(),
            common::EPHEMERAL_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::write(&input, ONE_MODEL).expect("write the AST");
        let out = engine()
            .arg("-i")
            .arg(&input)
            .args([
                "push",
                "--force",
                "--non-interactive",
                "--database-url",
                &url,
            ])
            .output()
            .expect("run the engine");
        let _ = std::fs::remove_file(&input);
        assert!(
            out.status.success(),
            "push: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        let pool = sqlx::PgPool::connect(&url).await.expect("connect");
        let recorded: Vec<String> =
            sqlx::query_scalar("SELECT engine_version FROM _supatype.migrations ORDER BY id")
                .fetch_all(&pool)
                .await
                .expect("read the migration history");
        pool.close().await;

        assert!(!recorded.is_empty(), "the push recorded no migration");
        let version = reported_version();
        for row in &recorded {
            assert_eq!(row, &version, "every row names the engine that pushed it");
        }
        assert_build_version(&version);
    })
    .await;
}
