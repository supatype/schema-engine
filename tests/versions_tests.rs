//! Drafts, version history and the draft read path.
//!
//! Every assertion here is about the SQL a push would apply. The behaviours that matter are:
//! the snapshot table exists and is never dropped by the next push; nothing reaches a draft without
//! credentials; the visibility the project stated is the visibility compiled in; and a schema that
//! states none is refused rather than defaulted.

use supatype_engine::{
    differ, differ::Operation, generator::sql::migration, generator::sql::versions, parser,
    state::database_state::DatabaseState,
};

fn versioned_ast() -> supatype_engine::parser::ast::SchemaAst {
    parser::parse(include_str!("fixtures/versioned_blog.json")).unwrap()
}

fn forward_sql() -> String {
    let ast = versioned_ast();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    migration::forward_sql(&diff, false, "public", &ast).unwrap()
}

/// An introspected table, as the differ would have found it.
fn db_table(name: &str, managed: bool) -> supatype_engine::introspector::tables::DbTable {
    supatype_engine::introspector::tables::DbTable {
        schema: "public".to_string(),
        name: name.to_string(),
        columns: Vec::new(),
        comment: managed.then(|| format!("supatype:managed;kind=table;table={name};fields=;v=1")),
    }
}

// ─── The snapshot table ───────────────────────────────────────────────────────

#[test]
fn emits_a_snapshot_table_and_its_index_per_versioned_model() {
    let sql = forward_sql();
    for table in ["posts_versions", "ledger_versions"] {
        assert!(
            sql.contains(&format!(
                "CREATE TABLE IF NOT EXISTS \"public\".\"{table}\""
            )),
            "expected a snapshot table for {table}; got:\n{sql}"
        );
        assert!(
            sql.contains(&format!("\"{table}_record_idx\"")),
            "the newest-version lookup is an index scan or it is a sequential scan of every \
             version ever written; missing index on {table}"
        );
    }
    assert!(
        !sql.contains("tags_versions"),
        "a model that does not declare `versions` must not get a snapshot table"
    );
}

#[test]
fn the_snapshot_table_cascades_from_its_record() {
    let sql = forward_sql();
    assert!(
        sql.contains("REFERENCES \"public\".\"posts\" (\"id\") ON DELETE CASCADE"),
        "a version of a deleted record is a snapshot of something that no longer exists; got:\n{sql}"
    );
}

#[test]
fn a_snapshot_table_that_already_exists_is_not_created_again() {
    // The operation only ever creates, which is what makes its rollback safe: a rollback then drops
    // a table this migration made, never history that predates it.
    let ast = versioned_ast();
    let mut db = DatabaseState::default();
    db.tables.push(db_table("posts_versions", true));
    let diff = differ::diff(&ast, &db).unwrap();
    let created: Vec<&str> = diff
        .operations
        .iter()
        .filter_map(|op| match op {
            Operation::CreateVersionsTable { versions_table, .. } => Some(versions_table.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(created, vec!["ledger_versions"]);
}

#[test]
fn a_snapshot_table_survives_the_next_push() {
    // It carries the managed marker, so the ownership gate is no protection: absent from the
    // differ's known-table set it would be dropped as an orphan, taking every version with it.
    let ast = versioned_ast();
    let mut db = DatabaseState::default();
    for name in [
        "posts",
        "posts_versions",
        "ledger",
        "ledger_versions",
        "tags",
    ] {
        db.tables.push(db_table(name, true));
    }
    let diff = differ::diff(&ast, &db).unwrap();
    let dropped: Vec<&str> = diff
        .operations
        .iter()
        .filter_map(|op| match op {
            Operation::DropTable { table, .. } => Some(table.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        dropped.is_empty(),
        "a steady-state push dropped {dropped:?}, which is version history"
    );
}

// ─── Who can reach a draft ────────────────────────────────────────────────────

#[test]
fn anon_reaches_neither_the_draft_schema_nor_the_snapshot_table() {
    // The whole feature rests on this. A draft schema readable without credentials would make every
    // unpublished edit world-readable on a model whose `read` rule is `Public`, and publishing would
    // stop meaning anything.
    let sql = forward_sql();
    assert!(
        sql.contains("REVOKE ALL ON SCHEMA \"draft\" FROM anon;"),
        "expected the draft schema to be taken off anon explicitly; got:\n{sql}"
    );
    assert!(
        !sql.contains("ON SCHEMA \"draft\" TO anon"),
        "the draft schema must never be granted to anon"
    );
    assert!(
        sql.contains("REVOKE ALL PRIVILEGES ON \"public\".\"posts_versions\" FROM anon;"),
        "expected the snapshot table to be taken off anon; got:\n{sql}"
    );
    assert!(
        !sql.contains("ON \"public\".\"posts_versions\" TO anon"),
        "the snapshot table must never be granted to anon"
    );
}

#[test]
fn the_snapshot_table_is_readable_and_not_writable_through_the_api() {
    // Drafts are written through the generated functions. A privilege that is not held cannot be
    // reasoned around, so `authenticated` gets SELECT and nothing else.
    let sql = forward_sql();
    assert!(sql.contains("GRANT SELECT ON \"public\".\"posts_versions\" TO authenticated;"));
    assert!(
        !sql.contains("GRANT INSERT ON \"public\".\"posts_versions\" TO authenticated"),
        "a direct POST to the versions table must not be possible"
    );
    assert!(
        !sql.contains("GRANT ALL ON \"public\".\"posts_versions\" TO authenticated"),
        "a direct write to the versions table must not be possible"
    );
}

#[test]
fn the_snapshot_policy_admits_the_creator_the_elevated_and_a_preview_link() {
    let sql = forward_sql();
    assert!(sql.contains("CREATE POLICY \"posts_versions_select\""));
    assert!(
        sql.contains("(\"created_by\" IS NOT NULL AND \"created_by\" = _supatype.caller_id())"),
        "a creator must be able to read back the draft they just saved"
    );
    assert!(
        !sql.contains("\"created_by\" = auth.uid()"),
        "`auth.uid()` falls back to the nil UUID when a request has no subject, and a \
         `service_role` write is stamped with whatever this returns: comparing against it would let \
         every subject-less caller read every draft Studio saved"
    );
    assert!(
        sql.contains("OR (SELECT _supatype.sees_all_drafts())"),
        "the elevated-role clause must be wrapped in a SELECT so it evaluates once per statement"
    );
    assert!(
        sql.contains("_supatype.preview_allows('posts', \"record_id\"::text)"),
        "the preview clause must name the model, or a record link for one model would open another"
    );
}

#[test]
fn the_snapshot_policy_names_no_other_table() {
    // The obvious phrasing, "whoever can see the record", joins the model's table, whose own policy
    // would want to join back here: Postgres answers that with `infinite recursion detected in
    // policy for relation`. Everything the policy needs is on the version row.
    let sql = forward_sql();
    let policy = sql
        .split("CREATE POLICY \"posts_versions_select\"")
        .nth(1)
        .expect("policy present")
        .split(");")
        .next()
        .expect("policy body");
    assert!(
        !policy.contains("FROM \"public\".\"posts\""),
        "the snapshot policy must not read the model's table; got:\n{policy}"
    );
}

// ─── The draft view ───────────────────────────────────────────────────────────

#[test]
fn a_draft_view_is_generated_for_a_model_that_withholds_writes() {
    let sql = forward_sql();
    assert!(sql.contains("CREATE VIEW \"draft\".\"posts\" WITH (security_invoker = true)"));
    assert!(
        sql.contains("jsonb_populate_record(NULL::\"public\".\"posts\""),
        "the draft must carry the model's own row type, or the client stops being typed"
    );
    assert!(sql.contains("GRANT SELECT ON \"draft\".\"posts\" TO authenticated, service_role;"));
}

#[test]
fn no_draft_view_for_a_model_that_only_keeps_history() {
    // `drafts: false` is the audit-trail case: every change recorded, nothing withheld from readers,
    // so there is never a pending version to preview.
    let sql = forward_sql();
    assert!(
        !sql.contains("\"draft\".\"ledger\""),
        "a model with drafts off has no pending version and needs no draft view"
    );
    assert!(
        sql.contains("CREATE TABLE IF NOT EXISTS \"public\".\"ledger_versions\""),
        "it still keeps history"
    );
}

#[test]
fn the_draft_view_does_not_join_the_model_table() {
    // The design note had it joining so that "a draft cannot be read by someone who could not read
    // the record", which is wrong in exactly the case the feature exists for: on a blog whose read
    // rule is `published_at <= now()`, an unpublished record is unreadable, so the join returns
    // nothing for every draft anyone wanted to preview.
    let sql = forward_sql();
    let view = sql
        .split("CREATE VIEW \"draft\".\"posts\"")
        .nth(1)
        .expect("view present")
        .split(';')
        .next()
        .expect("view body");
    assert!(
        !view.contains("FROM \"public\".\"posts\""),
        "the draft view must read the snapshot table alone; got:\n{view}"
    );
    assert!(view.contains("FROM \"public\".\"posts_versions\""));
}

// ─── The visibility setting ───────────────────────────────────────────────────

#[test]
fn the_configured_visibility_is_what_gets_compiled_in() {
    let sql = forward_sql();
    assert!(
        sql.contains(
            "SET \"configured_visibility\" = ARRAY['admin', 'developer', 'editor']::text[]"
        ),
        "the project's stated roles must reach the database; got:\n{sql}"
    );
}

#[test]
fn a_studio_override_wins_over_the_pushed_config() {
    // Two columns, not one: a single column would mean each writer clobbering the other, so a push
    // would silently undo an operator's override or an override would make the file in git a lie.
    let sql = forward_sql();
    assert!(sql.contains("SELECT COALESCE(s.\"override_visibility\", s.\"configured_visibility\")"));
}

#[test]
fn a_steady_state_push_does_not_touch_the_settings_row() {
    let sql = forward_sql();
    assert!(
        sql.contains("IS DISTINCT FROM ARRAY['admin', 'developer', 'editor']::text[]"),
        "the update must be conditional, or every push looks like a settings change"
    );
}

#[test]
fn a_versioned_schema_with_no_publishing_config_is_refused() {
    // Not defaulted. The visibility list is a security boundary, and a default applied silently is
    // how a project that widened its setting gets the narrow policy anyway.
    let mut ast = versioned_ast();
    ast.publishing = None;
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let err = migration::forward_sql(&diff, false, "public", &ast)
        .expect_err("a versioned schema with no visibility setting must not be applied");
    let message = format!("{err:#}");
    assert!(
        message.contains("no `publishing` config"),
        "the error has to name what is missing; got: {message}"
    );
}

#[test]
fn a_schema_with_no_versioned_model_needs_no_publishing_config() {
    // The refusal must not spread to every project that has never asked for drafts.
    let ast = parser::parse(include_str!("fixtures/basic_blog.json")).unwrap();
    assert!(ast.publishing.is_none());
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::forward_sql(&diff, false, "public", &ast).unwrap();
    assert!(!sql.contains("_versions"));
    assert!(!sql.contains("CREATE SCHEMA IF NOT EXISTS \"draft\""));
}

// ─── Versions against field rules ─────────────────────────────────────────────

#[test]
fn versions_and_per_column_rules_are_refused_together() {
    // A snapshot is opaque JSONB, so neither masking tier can see inside it and a masked value would
    // sit in plain sight for anyone who can read a draft.
    let mut ast = versioned_ast();
    let post = ast
        .models
        .iter_mut()
        .find(|m| m.name == "Post")
        .expect("Post model");
    post.annotations.platform.access.fields.insert(
        "title".to_string(),
        supatype_engine::parser::ast::FieldAccessAst {
            read: Some(supatype_engine::parser::ast::AccessRule::Authenticated),
            write: None,
        },
    );

    let err = versions::assert_no_versions_with_field_rules(&ast)
        .expect_err("a masked column inside a snapshot cannot be enforced");
    let message = format!("{err:#}");
    assert!(
        message.contains("Post"),
        "the error must name the model: {message}"
    );
}

#[test]
fn a_masked_model_and_a_versioned_model_can_share_a_schema() {
    // Per model, not per project. The refusal is about one model being both, not about a project
    // holding one of each.
    let ast = versioned_ast();
    assert!(versions::assert_no_versions_with_field_rules(&ast).is_ok());
    assert!(parser::accessors::has_versions(&ast));
}

// ─── The admin config's publishing flag ───────────────────────────────────────

#[test]
fn studio_learns_publishing_from_versions_not_from_a_field_named_publishable() {
    // The regression this replaces: `has_composite(model, "publishable")` was true only when a
    // model had a *field* called `publishable`, which nothing but the deleted builder API emitted.
    // So a model got its `published_at` column and no publish widget, and the feature read as
    // present in the schema while being absent from the UI.
    let ast = versioned_ast();
    let config = supatype_engine::generator::typescript::admin::generate(&ast).unwrap();
    let models = config["models"].as_array().expect("models");

    let post = models.iter().find(|m| m["name"] == "Post").expect("Post");
    assert_eq!(post["publishing"], serde_json::json!(true));
    assert_eq!(post["versions"]["drafts"], serde_json::json!(true));
    assert_eq!(post["versions"]["keep"], serde_json::json!(5));
    assert_eq!(
        post["versions"]["versionsTable"],
        serde_json::json!("posts_versions")
    );
    assert_eq!(
        post["versions"]["localizedColumns"],
        serde_json::json!(["body"]),
        "a control that says `publish English` has to know which columns English is a key of"
    );

    let ledger = models
        .iter()
        .find(|m| m["name"] == "Ledger")
        .expect("Ledger");
    assert_eq!(
        ledger["versions"]["drafts"],
        serde_json::json!(false),
        "an audit model keeps history and withholds nothing, so its editor must not offer a draft"
    );

    let tag = models.iter().find(|m| m["name"] == "Tag").expect("Tag");
    assert_eq!(tag["publishing"], serde_json::json!(false));
    assert!(
        tag["versions"].is_null(),
        "an unversioned model gets no publish control"
    );
}

#[test]
fn the_admin_config_carries_the_preview_bounds_to_the_api_server() {
    // The server already reads `adminRoles` from this file, so settings that arrive the same way
    // travel the same way. A second delivery path is a second thing to forget.
    let config = supatype_engine::generator::typescript::admin::generate(&versioned_ast()).unwrap();
    let publishing = &config["publishing"];
    assert_eq!(
        publishing["draftVisibility"],
        serde_json::json!(["admin", "developer", "editor"])
    );
    assert_eq!(publishing["previewDefaultTtl"], serde_json::json!(900));
    assert_eq!(publishing["previewMaxRecordTtl"], serde_json::json!(604800));
    assert_eq!(publishing["previewMaxProjectTtl"], serde_json::json!(86400));
    assert_eq!(
        publishing["previewAllowProjectScope"],
        serde_json::json!(true)
    );
}

#[test]
fn a_schema_with_no_versioned_model_carries_no_preview_bounds() {
    // A project that never asked for drafts must not gain a preview-link endpoint's settings.
    let ast = parser::parse(include_str!("fixtures/basic_blog.json")).unwrap();
    let config = supatype_engine::generator::typescript::admin::generate(&ast).unwrap();
    assert!(config["publishing"].is_null());
}

#[test]
fn what_a_push_applies_carries_the_same_layer_as_the_migration_file() {
    // These are two renderers over the same steps, and they drifted: the drafts and publishing
    // layer was added to the file and not to the push, so a push created the snapshot tables and
    // none of the views, functions or policies that make them mean anything — and reported success.
    // Every test rendered the file, so every test passed. Only a real database showed it.
    let ast = versioned_ast();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();

    let file = migration::forward_sql(&diff, false, "public", &ast).unwrap();
    let applied =
        migration::push_storage_and_model_apply_body("", &diff, false, "public", &ast).unwrap();

    for marker in [
        "CREATE SCHEMA IF NOT EXISTS \"draft\"",
        "_supatype.versioned_models",
        "\"supatype\".create_draft",
        "\"supatype\".publish",
        "CREATE VIEW \"draft\".\"posts\"",
        "CREATE POLICY \"posts_versions_select\"",
        "_supatype.caller_id()",
    ] {
        assert!(
            file.contains(marker),
            "the migration file is missing {marker}"
        );
        assert!(
            applied.contains(marker),
            "what a push applies is missing {marker}, so the file and the push disagree"
        );
    }
}
