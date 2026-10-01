//! Bucket rules on `storage.objects`: four operations, each its own rule, refused when left out.
//!
//! Buckets used to fill any rule they did not declare with "any signed-in user". For `delete` that
//! meant any signed-in user could remove anyone's files (supatype#82), and a bucket with no rules at
//! all got no policies, which the storage service read as "anyone with a token may write"
//! (supatype#81). Models have been deny-by-default since the policy-ownership change; these tests
//! hold buckets to the same rule.

use supatype_engine::generator::sql::storage;
use supatype_engine::parser::{self, ast::SchemaAst};

fn ast_for(buckets: &str, models: &str) -> SchemaAst {
    let src =
        format!(r#"{{ "astVersion": 2, "models": [{models}], "storageBuckets": [{buckets}] }}"#);
    parser::parse(&src).expect("schema parses")
}

fn sql_for(buckets: &str, models: &str) -> String {
    storage::generate(&ast_for(buckets, models)).expect("storage sql generates")
}

fn warnings_for(buckets: &str, models: &str) -> Vec<String> {
    storage::rule_warnings(&ast_for(buckets, models))
}

const AVATARS_READ_CREATE: &str = r#"{
  "id": "avatars", "public": true, "accessMode": "public",
  "access": { "read": { "type": "public" }, "create": { "type": "authenticated" } }
}"#;

const AVATARS_CRUD: &str = r#"{
  "id": "avatars", "public": true, "accessMode": "public",
  "access": {
    "read": { "type": "public" },
    "create": { "type": "authenticated" },
    "update": { "type": "owner", "field": "owner" },
    "delete": { "type": "owner", "field": "owner" }
  }
}"#;

const NO_RULES: &str = r#"{ "id": "loose", "public": false, "accessMode": "private" }"#;

const DOC_MODEL_NO_RULES: &str = r#"{
  "name": "doc",
  "annotations": { "db": { "tableName": "doc" } },
  "fields": {
    "id": { "kind": "uuid", "required": true },
    "file": { "kind": "image", "required": false, "bucket": "shared" }
  }
}"#;

const SHARED_UNDECLARED: &str = r#"{ "id": "shared", "public": false, "accessMode": "private" }"#;

#[test]
fn a_delete_rule_left_out_creates_no_delete_policy() {
    let sql = sql_for(AVATARS_READ_CREATE, "");
    assert!(
        !sql.contains("CREATE POLICY \"storage_avatars_del\""),
        "a missing delete rule must be refused, not filled with a default, got:\n{sql}"
    );
}

#[test]
fn a_rule_left_out_still_drops_the_policy_an_earlier_push_created() {
    // Otherwise the default an older engine wrote for it keeps granting.
    let sql = sql_for(AVATARS_READ_CREATE, "");
    for suffix in ["upd", "del"] {
        assert!(
            sql.contains(&format!(
                "DROP POLICY IF EXISTS \"storage_avatars_{suffix}\""
            )),
            "expected the {suffix} policy to be dropped, got:\n{sql}"
        );
    }
}

#[test]
fn an_update_rule_creates_an_update_policy_with_the_rule_on_both_sides() {
    let sql = sql_for(AVATARS_CRUD, "");
    let expected = "CREATE POLICY \"storage_avatars_upd\" ON storage.objects\n  \
                    FOR UPDATE USING (\n    bucket_id = 'avatars' AND (auth.uid() = owner)\n  ) \
                    WITH CHECK (\n    bucket_id = 'avatars' AND (auth.uid() = owner)\n  );";
    assert!(
        sql.contains(expected),
        "expected an owner-only update policy, got:\n{sql}"
    );
}

#[test]
fn every_declared_rule_becomes_its_own_policy() {
    let sql = sql_for(AVATARS_CRUD, "");
    for (suffix, command) in [
        ("sel", "SELECT"),
        ("ins", "INSERT"),
        ("upd", "UPDATE"),
        ("del", "DELETE"),
    ] {
        assert!(
            sql.contains(&format!(
                "CREATE POLICY \"storage_avatars_{suffix}\" ON storage.objects\n  FOR {command}"
            )),
            "expected a {command} policy, got:\n{sql}"
        );
    }
}

#[test]
fn the_caller_roles_hold_every_grant_the_service_writes_with() {
    let sql = sql_for(AVATARS_CRUD, "");
    assert!(
        sql.contains(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON storage.objects TO anon, authenticated;"
        ),
        "writes run as the caller, so the caller needs the grants, got:\n{sql}"
    );
}

#[test]
fn a_bucket_with_no_rules_and_no_model_still_gets_row_level_security() {
    // With nothing enabled the service's caller-role writes would be decided by grants alone.
    let sql = sql_for(NO_RULES, "");
    assert!(
        sql.contains("ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;"),
        "expected RLS on, got:\n{sql}"
    );
    assert!(
        !sql.contains("CREATE POLICY"),
        "a bucket with no rules allows nothing, got:\n{sql}"
    );
}

#[test]
fn a_model_with_no_rules_grants_nothing_on_the_bucket_it_uses() {
    let sql = sql_for(SHARED_UNDECLARED, DOC_MODEL_NO_RULES);
    assert!(
        !sql.contains("CREATE POLICY \"doc_shared_"),
        "a model that declares no rules must not lend the bucket a default, got:\n{sql}"
    );
}

#[test]
fn a_bucket_that_declares_rules_retires_the_policies_a_model_gave_it() {
    // Permissive policies are ORed, so a leftover model policy would widen the bucket's rules.
    let declared = r#"{
      "id": "shared", "public": false, "accessMode": "private",
      "access": { "read": { "type": "authenticated" } }
    }"#;
    let sql = sql_for(declared, DOC_MODEL_NO_RULES);
    for suffix in ["sel", "ins", "upd", "del"] {
        assert!(
            sql.contains(&format!("DROP POLICY IF EXISTS \"doc_shared_{suffix}\"")),
            "expected the model's {suffix} policy to be dropped, got:\n{sql}"
        );
        assert!(
            !sql.contains(&format!("CREATE POLICY \"doc_shared_{suffix}\"")),
            "the model must not grant on a bucket with its own rules, got:\n{sql}"
        );
    }
}

#[test]
fn every_operation_no_rule_allows_is_warned_about() {
    let warnings = warnings_for(AVATARS_READ_CREATE, "");
    let joined = warnings.join("\n");
    assert!(
        joined.contains("Bucket \"avatars\" declares no update rule: overwrites are refused"),
        "{joined}"
    );
    assert!(
        joined.contains("Bucket \"avatars\" declares no delete rule: deletes are refused"),
        "{joined}"
    );
    assert_eq!(
        warnings.len(),
        2,
        "read and create are declared, got:\n{joined}"
    );
}

#[test]
fn a_fully_declared_bucket_has_no_warnings() {
    assert!(warnings_for(AVATARS_CRUD, "").is_empty());
}

#[test]
fn a_public_bucket_is_not_warned_about_reads() {
    // Its public URL serves files without consulting the read policy, so "reads are refused" is false.
    let only_create = r#"{
      "id": "media", "public": true, "accessMode": "public",
      "access": { "create": { "type": "authenticated" } }
    }"#;
    let joined = warnings_for(only_create, "").join("\n");
    assert!(!joined.contains("no read rule"), "{joined}");
}

#[test]
fn the_warnings_reach_the_diff_push_reports_from() {
    // `push` prints the diff's warnings, so this is what puts them in front of whoever pushes.
    use supatype_engine::differ;
    use supatype_engine::state::database_state::DatabaseState;

    let ast = ast_for(AVATARS_READ_CREATE, "");
    let diff = differ::diff(&ast, &DatabaseState::default()).expect("diff computes");
    assert!(
        diff.warnings
            .iter()
            .any(|w| w.contains("Bucket \"avatars\" declares no delete rule")),
        "got: {:?}",
        diff.warnings
    );
}

#[test]
fn every_created_policy_carries_the_managed_marker() {
    let sql = sql_for(AVATARS_CRUD, "");
    for suffix in ["sel", "ins", "upd", "del"] {
        let marker = format!(
            "COMMENT ON POLICY \"storage_avatars_{suffix}\" ON storage.objects IS \
             'supatype:managed;kind=storage_policy;table=objects;fields=storage_avatars_{suffix};v=1';"
        );
        assert!(sql.contains(&marker), "expected {marker}, got:\n{sql}");
    }
}

#[test]
fn marked_policies_the_schema_no_longer_names_are_retired() {
    // A removed bucket or renamed model leaves policies no set can spell. The sweep drops every
    // marked one that is not expected, and only marked ones.
    let sql = sql_for(AVATARS_READ_CREATE, "");
    assert!(
        sql.contains(
            "obj_description(oid, 'pg_policy') LIKE 'supatype:managed;kind=storage_policy;%'"
        ),
        "{sql}"
    );
    assert!(
        sql.contains(
            "AND polname <> ALL (ARRAY['storage_avatars_sel', 'storage_avatars_ins']::text[])"
        ),
        "only the policies this push creates are kept, got:\n{sql}"
    );
}

#[test]
fn objects_carry_the_version_their_bytes_are_stored_under() {
    // The storage service writes each upload to a fresh key, `name/<version>`, and the row says
    // which one is live. Added to an existing table too, where it starts out null.
    let sql = sql_for(AVATARS_CRUD, "");
    assert!(
        sql.contains("ALTER TABLE storage.objects ADD COLUMN IF NOT EXISTS version TEXT;"),
        "got:\n{sql}"
    );
}
