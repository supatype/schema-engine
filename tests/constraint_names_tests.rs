//! The names a push gives the objects it creates.
//!
//! Every generated name is the one Postgres would have chosen for an unnamed constraint, emitted
//! explicitly so that no object is ever named by anyone but us, and trimmed to the identifier
//! limit the way Prisma trims: before the suffix, so the part that says what the object is
//! survives. Postgres silently truncates a long identifier to 63 bytes, so a name built in full
//! here and truncated there is a name nothing can find again.

use supatype_engine::managed::{
    expected_check_constraint_name, expected_model_constraint_name, expected_model_index_name,
    expected_unique_constraint_name, foreign_key_name, primary_key_name, truncate_identifier,
    type_check_name, MAX_IDENTIFIER_BYTES,
};

#[test]
fn the_defaults_are_postgres_defaults() {
    assert_eq!(primary_key_name("posts"), "posts_pkey");
    assert_eq!(
        foreign_key_name("posts", "author_id"),
        "posts_author_id_fkey"
    );
    assert_eq!(
        expected_unique_constraint_name("users", "email"),
        "users_email_key"
    );
    assert_eq!(type_check_name("users", "email"), "users_email_check");
    assert_eq!(
        expected_check_constraint_name("users", "name"),
        "users_name_bounds"
    );
    assert_eq!(expected_model_constraint_name("talk", 0), "talk_check_1");
    assert_eq!(
        expected_model_index_name("talk", &["day".into(), "starts_at".into()]),
        "talk_day_starts_at_idx"
    );
}

#[test]
fn a_short_name_is_untouched() {
    assert_eq!(
        truncate_identifier("posts_author_id", "_fkey"),
        "posts_author_id_fkey"
    );
}

#[test]
fn a_long_name_is_trimmed_before_its_suffix_to_the_limit() {
    let table = "a".repeat(40);
    let column = "b".repeat(40);
    let name = expected_unique_constraint_name(&table, &column);
    assert_eq!(name.len(), MAX_IDENTIFIER_BYTES);
    assert!(name.ends_with("_key"), "{name}");
    assert!(name.starts_with(&table), "the table part survives: {name}");
}

#[test]
fn trimming_never_splits_a_multibyte_character() {
    let base = "é".repeat(40); // 80 bytes
    let name = truncate_identifier(&base, "_idx");
    assert!(name.len() <= MAX_IDENTIFIER_BYTES);
    assert!(name.ends_with("_idx"));
    assert!(std::str::from_utf8(name.as_bytes()).is_ok());
}

#[test]
fn every_helper_respects_the_limit() {
    let long = "x".repeat(100);
    for name in [
        primary_key_name(&long),
        foreign_key_name(&long, &long),
        expected_unique_constraint_name(&long, &long),
        type_check_name(&long, &long),
        expected_check_constraint_name(&long, &long),
        expected_model_constraint_name(&long, 9),
        expected_model_index_name(&long, &[long.clone(), long.clone()]),
    ] {
        assert!(name.len() <= MAX_IDENTIFIER_BYTES, "{name}");
    }
}
