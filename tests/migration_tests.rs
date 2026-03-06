use supatype_engine::{differ, generator::sql::migration, parser, state::database_state::DatabaseState};

#[test]
fn test_migration_generated_for_new_schema() {
    let input = include_str!("fixtures/basic_blog.json");
    let ast = parser::parse(input).unwrap();
    let empty_db = DatabaseState::default();
    let diff = differ::diff(&ast, &empty_db).unwrap();
    let sql = migration::generate(&diff, false).unwrap();

    assert!(sql.contains("BEGIN;"));
    assert!(sql.contains("COMMIT;"));
    assert!(sql.contains("FORWARD MIGRATION"));
}

// Fix: "setNull" must render as "SET NULL", not "SETNULL".
#[test]
fn test_fk_action_set_null_renders_correctly() {
    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::generate(&diff, false).unwrap();

    assert!(sql.contains("SET NULL"), "expected 'SET NULL' in FK action");
    assert!(!sql.contains("SETNULL"), "must not contain 'SETNULL' (one word)");
}

// Fix: schemas with UUID genRandomUuid defaults must emit the pgcrypto extension.
#[test]
fn test_pgcrypto_extension_emitted_for_uuid_defaults() {
    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::generate(&diff, false).unwrap();

    assert!(
        sql.contains("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\""),
        "migration must emit pgcrypto for gen_random_uuid() defaults"
    );
    // Extension must appear before BEGIN so it can run outside the transaction.
    let ext_pos = sql.find("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"").unwrap();
    let begin_pos = sql.find("BEGIN;").unwrap();
    assert!(ext_pos < begin_pos, "pgcrypto extension must appear before BEGIN");
}

// Fix: generated index SQL must not use CONCURRENTLY (cannot run inside a transaction).
#[test]
fn test_index_sql_has_no_concurrently() {
    let input = include_str!("fixtures/five_model_blog.json");
    let ast = parser::parse(input).unwrap();
    let diff = differ::diff(&ast, &DatabaseState::default()).unwrap();
    let sql = migration::generate(&diff, false).unwrap();

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
    let sql = migration::generate(&diff, false).unwrap();

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

    let last_create = diff.operations.iter().rposition(|op| {
        matches!(op, differ::Operation::CreateTable { .. })
    });
    let first_fk = diff.operations.iter().position(|op| {
        matches!(op, differ::Operation::AddForeignKey { .. })
    });

    if let (Some(last_c), Some(first_fk)) = (last_create, first_fk) {
        assert!(
            last_c < first_fk,
            "all CreateTable ops must come before any AddForeignKey op"
        );
    }
}
