use supatype_engine::{
    differ, generator::sql::migration, parser, state::database_state::DatabaseState,
};

#[test]
fn test_migration_generated_for_new_schema() {
    let input = include_str!("fixtures/basic_blog.json");
    let ast = parser::parse(input).unwrap();
    let empty_db = DatabaseState::default();
    let diff = differ::diff(&ast, &empty_db).unwrap();
    let sql = migration::generate(&diff, false, "public", &ast).unwrap();

    assert!(sql.contains("BEGIN;"));
    assert!(sql.contains("COMMIT;"));
    assert!(sql.contains("FORWARD MIGRATION"));
}

#[test]
fn test_forward_sql_emits_create_policy_for_access_rules() {
    // basic_blog has access rules; five_model_blog uses empty access {} (no RLS ops).
    let input = include_str!("fixtures/basic_blog.json");
    let ast = parser::parse(input).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let forward = migration::forward_sql(&diff, false, "public", &ast).unwrap();
    assert!(
        forward.contains("CREATE POLICY"),
        "CreateRlsPolicy ops must render as CREATE POLICY DDL; got:\n{forward}"
    );
    assert!(
        forward.contains("DROP POLICY IF EXISTS"),
        "expected DROP POLICY IF EXISTS before each CREATE POLICY"
    );
}

// Fix: "setNull" must render as "SET NULL", not "SETNULL".
#[test]
fn test_fk_action_set_null_renders_correctly() {
    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::generate(&diff, false, "public", &ast).unwrap();

    assert!(sql.contains("SET NULL"), "expected 'SET NULL' in FK action");
    assert!(
        !sql.contains("SETNULL"),
        "must not contain 'SETNULL' (one word)"
    );
}

// Fix: schemas with UUID genRandomUuid defaults must emit the pgcrypto extension.
#[test]
fn test_pgcrypto_extension_emitted_for_uuid_defaults() {
    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::generate(&diff, false, "public", &ast).unwrap();

    assert!(
        sql.contains("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\""),
        "migration must emit pgcrypto for gen_random_uuid() defaults"
    );
    // Extension must appear before BEGIN so it can run outside the transaction.
    let ext_pos = sql
        .find("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"")
        .unwrap();
    let begin_pos = sql.find("BEGIN;").unwrap();
    assert!(
        ext_pos < begin_pos,
        "pgcrypto extension must appear before BEGIN"
    );
}

#[test]
fn test_push_storage_and_model_batch_single_begin_commit() {
    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let batch = migration::push_storage_and_model_batch_sql(
        "-- storage preamble\n",
        &diff,
        false,
        "public",
        &ast,
    )
    .unwrap();
    assert_eq!(
        batch.matches("BEGIN;").count(),
        1,
        "expected exactly one outer BEGIN;\ngot:\n{batch}"
    );
    assert_eq!(batch.matches("COMMIT;").count(), 1);
}

// Fix: generated index SQL must not use CONCURRENTLY (cannot run inside a transaction).
#[test]
fn test_index_sql_has_no_concurrently() {
    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::generate(&diff, false, "public", &ast).unwrap();

    assert!(
        !sql.contains("CONCURRENTLY"),
        "migration SQL must not contain CONCURRENTLY — cannot run inside a transaction"
    );
}

// Fix: FK REFERENCES must use the model's tableName ("users"), not snake_case of the
// model name ("user"). Regression for target="User" tableName="users".
#[test]
fn test_fk_references_correct_table_name() {
    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::generate(&diff, false, "public", &ast).unwrap();

    // posts.author_id → users (tableName), not user (snake_case of "User")
    assert!(
        sql.contains("REFERENCES \"public\".\"users\""),
        "FK must reference 'users' (tableName), not 'user'"
    );
    assert!(
        !sql.contains("REFERENCES \"public\".\"user\""),
        "FK must not reference 'user' (snake_case of model name)"
    );

    // posts.category_id → categories (tableName), not category
    assert!(
        sql.contains("REFERENCES \"public\".\"categories\""),
        "FK must reference 'categories' (tableName), not 'category'"
    );
    assert!(
        !sql.contains("REFERENCES \"public\".\"category\""),
        "FK must not reference 'category' (snake_case of model name)"
    );
}

// Fix: all CreateTable ops must appear before any AddForeignKey ops in the migration.
#[test]
fn test_fk_ops_ordered_after_create_table_ops() {
    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();

    let last_create = diff
        .operations
        .iter()
        .rposition(|op| matches!(op, differ::Operation::CreateTable { .. }));
    let first_fk = diff
        .operations
        .iter()
        .position(|op| matches!(op, differ::Operation::AddForeignKey { .. }));

    if let (Some(last_c), Some(first_fk)) = (last_create, first_fk) {
        assert!(
            last_c < first_fk,
            "all CreateTable ops must come before any AddForeignKey op"
        );
    }
}

#[test]
fn test_postgis_extension_emitted_for_geo_fields() {
    let input = include_str!("fixtures/geospatial.json");
    let ast = parser::parse(input).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::generate(&diff, false, "public", &ast).unwrap();

    assert!(
        sql.contains("CREATE EXTENSION IF NOT EXISTS \"postgis\""),
        "migration must emit postgis for GEOGRAPHY columns"
    );
    let ext_pos = sql
        .find("CREATE EXTENSION IF NOT EXISTS \"postgis\"")
        .unwrap();
    let begin_pos = sql.find("BEGIN;").unwrap();
    assert!(
        ext_pos < begin_pos,
        "postgis extension must appear before BEGIN"
    );
}

#[test]
fn test_vector_extension_emitted_for_vector_fields() {
    let input = include_str!("fixtures/vector_search.json");
    let ast = parser::parse(input).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::generate(&diff, false, "public", &ast).unwrap();

    assert!(
        sql.contains("CREATE EXTENSION IF NOT EXISTS \"vector\""),
        "migration must emit vector for pgvector columns"
    );
    let ext_pos = sql
        .find("CREATE EXTENSION IF NOT EXISTS \"vector\"")
        .unwrap();
    let begin_pos = sql.find("BEGIN;").unwrap();
    assert!(
        ext_pos < begin_pos,
        "vector extension must appear before BEGIN"
    );
}

/// The auth helpers are re-asserted on every push, not only on pushes that touch RLS.
///
/// They were gated on the diff carrying an `EnableRls` / `CreateRlsPolicy` / `DropRlsPolicy`
/// operation. A policy calls `auth.uid()`, so a definition that is only refreshed when a policy
/// happens to change drifts from the policies that call it, and nothing notices until one evaluates
/// against a stale helper. Grants and security labels already re-assert unconditionally; this makes
/// the helpers behave the same way.
///
/// A steady-state push is the case that matters: same schema, same database, nothing to do.
#[test]
fn auth_helpers_are_emitted_on_a_push_that_touches_no_policy() {
    let input = include_str!("fixtures/basic_blog.json");
    let ast = parser::parse(input).unwrap();

    // Apply once, then diff the same schema against the state it produced: no RLS operations left.
    let first = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let rls_ops = first.operations.iter().any(|op| {
        matches!(
            op,
            differ::Operation::EnableRls { .. }
                | differ::Operation::CreateRlsPolicy { .. }
                | differ::Operation::DropRlsPolicy { .. }
        )
    });
    assert!(rls_ops, "the fixture must carry RLS ops, or the contrast is empty");

    // The same push once its policies are already in place: everything else still to do, no RLS
    // operation left to hang the helpers off.
    let mut steady = first.clone();
    steady.operations.retain(|op| {
        !matches!(
            op,
            differ::Operation::EnableRls { .. }
                | differ::Operation::CreateRlsPolicy { .. }
                | differ::Operation::DropRlsPolicy { .. }
        )
    });
    assert!(
        !steady.operations.is_empty(),
        "the steady-state diff must still do something, or the preamble is all there is"
    );

    let forward = migration::forward_sql(&steady, false, "public", &ast).unwrap();
    assert!(
        forward.contains("CREATE OR REPLACE FUNCTION auth.uid()"),
        "a push with no RLS operation must still assert the helpers its policies call:\n{forward}"
    );
    assert!(
        forward.contains("CREATE SCHEMA IF NOT EXISTS auth;"),
        "and the schema they live in:\n{forward}"
    );
}

/// The `auth` schema grant is emitted once, from the preamble.
///
/// It used to be emitted twice: once in the preamble, and again from the field-masking block,
/// because the preamble's copy was gated and a steady-state push would otherwise check a privilege
/// nothing in that push had established. With the gate gone the second copy is redundant, and two
/// emitters of one grant is how the two drift apart.
#[test]
fn the_auth_schema_grant_has_a_single_emitter() {
    // A fixture with **field** rules: the second emitter lived in the field-masking block, so a
    // schema without one never reached it and the test would pass either way.
    let input = include_str!("fixtures/rls_field_rules.json");
    let ast = parser::parse(input).unwrap();
    // With `supatype_mask` present the differ picks the extension tier, which is the tier whose
    // masking block held the second emitter. Without it the tier is `Views` and the block never
    // runs, so the test would pass whether or not the duplicate was there.
    let db = DatabaseState {
        extensions: vec![supatype_engine::generator::sql::rls::MASK_EXTENSION.to_string()],
        ..DatabaseState::default()
    };
    let diff = differ::diff(&ast, &db).unwrap();
    let forward = migration::forward_sql(&diff, false, "public", &ast).unwrap();
    assert_eq!(
        diff.field_masking,
        differ::FieldMaskingTier::Extension,
        "the fixture must reach the extension tier, or the second emitter is unreachable"
    );

    // One `DO $auth_schema_usage$` block is one emitter. Counting the GRANT statements would
    // count the per-role lines inside the block instead.
    let emitters = forward.matches("DO $auth_schema_usage$").count();
    assert_eq!(
        emitters, 1,
        "expected exactly one auth-schema grant emitter, found {emitters}:\n{forward}"
    );
}
