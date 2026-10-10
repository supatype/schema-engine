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

/// What a push applies for storage: the storage layer, then the policies the reconcile creates
/// (Phase 4.7b).
fn sql_for(buckets: &str, models: &str) -> String {
    let ast = ast_for(buckets, models);
    storage::generate(&ast).expect("storage sql generates") + &storage::bucket_policies_sql(&ast)
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
fn an_update_rule_creates_an_update_policy_with_the_rule_on_both_sides() {
    let sql = sql_for(AVATARS_CRUD, "");
    let expected = "CREATE POLICY \"storage_avatars_upd\" ON \"storage\".\"objects\"\n  \
                    FOR UPDATE USING (\n    bucket_id = 'avatars' AND ((SELECT _supatype.jwt_uid()) = owner)\n  ) \
                    WITH CHECK (\n    bucket_id = 'avatars' AND ((SELECT _supatype.jwt_uid()) = owner)\n  );";
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
                "CREATE POLICY \"storage_avatars_{suffix}\" ON \"storage\".\"objects\"\n  FOR {command}"
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
    // Permissive policies are ORed, so a leftover model policy would widen the bucket's rules. Not
    // created, so not desired: the reconcile drops one an earlier push recorded.
    let declared = r#"{
      "id": "shared", "public": false, "accessMode": "private",
      "access": { "read": { "type": "authenticated" } }
    }"#;
    let sql = sql_for(declared, DOC_MODEL_NO_RULES);
    for suffix in ["sel", "ins", "upd", "del"] {
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
fn no_policy_is_stamped_or_swept() {
    // Which policies are ours is the ledger's record since Phase 4.7b: no comment marks them, and
    // no sweep retires them, since the reconcile drops what nothing desires
    // (`storage_policy_sweep_tests`).
    let sql = sql_for(AVATARS_CRUD, "");
    assert!(!sql.contains("COMMENT ON POLICY"), "{sql}");
    assert!(!sql.contains("DROP POLICY"), "{sql}");
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

#[test]
fn only_the_shape_older_engines_gave_bucket_policies_is_ours_by_name() {
    // Older engines wrote `storage_<label>_sel|ins|del` with no marker. Left behind, they now take
    // effect, because the caller roles hold INSERT, UPDATE and DELETE, so the reconcile takes them
    // as its own and drops one nothing desires.
    for name in [
        "storage_avatars_sel",
        "storage_user_avatars_ins",
        "storage_x_del",
    ] {
        assert!(
            storage::is_unmarked_bucket_policy("storage", "objects", name),
            "{name}"
        );
    }
    for (schema, table, name) in [
        ("storage", "objects", "team_rule"),
        ("storage", "objects", "storage__sel"),
        ("storage", "objects", "storage_avatars_upd"),
        ("storage", "objects", "storage_a-b_sel"),
        ("storage", "buckets", "storage_avatars_sel"),
        ("public", "objects", "storage_avatars_sel"),
    ] {
        assert!(
            !storage::is_unmarked_bucket_policy(schema, table, name),
            "{schema}.{table}.{name}"
        );
    }
}

#[test]
fn an_update_or_delete_rule_without_a_read_rule_is_warned_about_even_on_a_public_bucket() {
    // Postgres only lets a caller change rows it can read, so with no read policy these rules
    // match nothing, silently.
    let public_delete_only = r#"{
      "id": "drop", "public": true, "accessMode": "public",
      "access": { "create": { "type": "authenticated" }, "delete": { "type": "owner", "field": "owner_id" } }
    }"#;
    let joined = warnings_for(public_delete_only, "").join("\n");
    assert!(
        joined.contains("Bucket \"drop\" declares delete but no read rule"),
        "{joined}"
    );
}

#[test]
fn two_bucket_ids_with_the_same_policy_names_are_refused() {
    // `user-avatars` and `user_avatars` both become `storage_user_avatars_*`, so one bucket's
    // drops would remove the other's policies.
    let two = r#"{ "id": "user-avatars", "public": false, "accessMode": "private" },
                 { "id": "user_avatars", "public": false, "accessMode": "private" }"#;
    let err = storage::generate(&ast_for(two, "")).expect_err("must refuse");
    let msg = err.to_string();
    assert!(
        msg.contains("user-avatars") && msg.contains("user_avatars"),
        "{msg}"
    );
}

#[test]
fn colliding_bucket_ids_are_refused_on_the_migrate_path_too() {
    // `supatype migrate` and `diff` never rendered the storage layer, which is where the refusal
    // lived, so the desired set kept the first bucket's policies and dropped the second's silently.
    let two = r#"{ "id": "user-avatars", "public": false, "accessMode": "private" },
                 { "id": "user_avatars", "public": false, "accessMode": "private" }"#;
    let ast = ast_for(two, "");
    let err = supatype_engine::push::fresh_migration(&ast, "public", false)
        .err()
        .expect("the migration must refuse");
    let msg = err.to_string();
    assert!(
        msg.contains("user-avatars") && msg.contains("user_avatars"),
        "{msg}"
    );
    let err = supatype_engine::desired::desired_objects(&ast, "public")
        .expect_err("the desired set must refuse");
    assert!(err.to_string().contains("user_avatars"), "{err}");
}

#[test]
fn the_migration_file_creates_storage_objects_before_its_bucket_policies() {
    // The bucket policies are the reconcile's, so they are in the migration; `storage.objects` is
    // the storage layer's. The file `supatype migrate` prints, and the `sql_up` the history keeps,
    // have to carry both, in that order, or they fail on a database without `storage.objects`.
    let ast = ast_for(AVATARS_READ_CREATE, "");
    let migration = supatype_engine::push::fresh_migration(&ast, "public", false).unwrap();
    for (what, sql) in [
        ("file", migration.file()),
        ("apply body", migration.apply_body()),
    ] {
        let table = sql
            .find("CREATE TABLE IF NOT EXISTS storage.objects")
            .unwrap_or_else(|| panic!("the {what} creates storage.objects:\n{sql}"));
        let policy = sql
            .find("CREATE POLICY \"storage_avatars_sel\"")
            .unwrap_or_else(|| panic!("the {what} creates the bucket's policy:\n{sql}"));
        assert!(table < policy, "{what}: the table comes first:\n{sql}");
    }
    let file = migration.file();
    let begin = file.find("BEGIN;").unwrap();
    assert!(
        file.find("CREATE TABLE IF NOT EXISTS storage.objects")
            .unwrap()
            > begin,
        "the storage layer is inside the forward transaction"
    );
}
