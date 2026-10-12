//! What this engine supports of the ownership contract, for a caller (the CLI, a control plane)
//! to ask before it relies on a flag: `GET /capabilities` and `supatype-engine capabilities` both
//! answer `{"features": [...]}`. A caller refuses a feature that is not listed rather than
//! dropping its flag, since an engine that does not know a field ignores it.

/// Each feature, as the contract names it.
pub const FEATURES: &[&str] = &[
    // `adopt` with `keys` / `--key`: adopt only the named conflicts.
    "adopt_keys",
    // `adopt` with `keys: []` / `--adopt-none`: release or reclaim without adopting anything.
    "adopt_none",
    // `adopt` with `release` / `--release`.
    "release",
    // `adopt` with `reclaim` / `--reclaim`.
    "reclaim",
    // `doctor` with `rebaseline` / `--rebaseline`.
    "rebaseline",
    // `doctor --rebaseline` with `accept_access_drift` / `--accept-access-drift`.
    "accept_access_drift",
    // `doctor --rebaseline` with `keys` / `--key`: record only the drift the preview listed, or
    // refuse with HTTP 409 `drift_changed` (the binary's `{"status":"refused","reason":
    // "drift_changed"}` line) naming what is `unseen` and what is `gone`.
    "rebaseline_keys",
    // `push` with `overwrite_drift` / `--overwrite-drift`.
    "overwrite_drift",
    // A writer refused while another holds the engine's lock: HTTP 409 `engine_busy`, and the
    // binary's `{"status":"refused","reason":"engine_busy"}` line.
    "engine_busy",
    // A field's `identity` and `generated` (identity-contract): identity and stored generated
    // columns, created, changed and introspected (`isIdentity`, `generationExpression`, ...). An
    // engine without it parses neither key and makes a plain column.
    "identity_columns",
    // `push` with the audit trail: `pushed_by`, `pushed_via`, `pushed_from` and
    // `pushed_by_verified` (`--pushed-by`, ...), recorded on the migration row with the renames
    // the push applied from the schema's rename journal (`renameJournal`).
    "push_audit",
];

/// The capabilities document. `version` is the build's own (`build.rs`): the crate version for a
/// release, a `-dev` pre-release with the commit otherwise, so a caller can tell builds apart.
pub fn capabilities() -> serde_json::Value {
    serde_json::json!({ "version": env!("ENGINE_VERSION"), "features": FEATURES })
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_document_lists_every_feature_this_engine_supports() {
        assert_eq!(
            super::capabilities().to_string(),
            format!(
                r#"{{"version":"{}","features":["adopt_keys","adopt_none","release","reclaim","rebaseline","accept_access_drift","rebaseline_keys","overwrite_drift","engine_busy","identity_columns","push_audit"]}}"#,
                env!("ENGINE_VERSION")
            )
        );
    }
}
