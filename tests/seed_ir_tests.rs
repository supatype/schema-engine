//! The golden IR document, and what it is for.
//!
//! `tests/fixtures/seed_golden_ir.json` is written by hand from the IR specification, not
//! captured from the engine's own output. That distinction is the whole point: a captured
//! fixture only proves the code agrees with itself, and would be regenerated the moment it
//! disagreed. Written by hand, it is a contract every SDK is held to, and the first
//! non-TypeScript builder is checked against the same file rather than against whatever
//! the TypeScript one happened to emit.
//!
//! Until a second SDK exists this is the only thing keeping the boundary honest.

use supatype_engine::seed::{Condition, Operation, SeedIr, Value, IR_VERSION};

const GOLDEN: &str = include_str!("fixtures/seed_golden_ir.json");

fn golden() -> SeedIr {
    serde_json::from_str(GOLDEN).expect("the golden IR parses")
}

#[test]
fn the_golden_document_parses() {
    let ir = golden();
    assert_eq!(ir.ir_version, IR_VERSION);
    assert!(ir.schema_fingerprint.starts_with("sha256:"));
    assert_eq!(ir.operations.len(), 6, "the fixture covers six operations");
}

/// Recursively sort every object's keys, so two documents that differ only in key order
/// compare equal.
fn canonical(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for key in keys {
                sorted.insert(key.clone(), canonical(&map[key]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonical).collect())
        }
        other => other.clone(),
    }
}

/// Re-serialising must reproduce the document, compared canonically.
///
/// This is what makes the fixture a contract rather than a sample: a renamed field, a
/// dropped field, a changed shape or a changed value all diverge and fail here with the
/// difference visible.
///
/// **Keys are sorted before comparing, and array order is preserved.** Key order is not
/// part of the contract, for a reason the product already demonstrates: the engine writes
/// a comparison as `type, left, op, right` because that is its struct's declaration order,
/// while the CLI writes `type, op, left, right` for the identical rule. Both are the same
/// document. Holding six future SDKs to Rust's field order would make a Python dict or a
/// Go struct fail for a difference that means nothing, and would turn any later field
/// reorder into a break for every one of them.
///
/// Array order *is* compared, because an operation list is a sequence and reordering it
/// changes what the seed does.
#[test]
fn the_golden_document_round_trips() {
    let ir = golden();
    let written = serde_json::to_value(&ir).expect("serialises");
    let original: serde_json::Value = serde_json::from_str(GOLDEN).expect("the fixture is JSON");

    assert_eq!(
        canonical(&written),
        canonical(&original),
        "the IR did not round trip; the engine writes something other than the contract"
    );
}

/// The canonicaliser must not be the reason the test passes.
#[test]
fn canonical_comparison_still_notices_a_real_difference() {
    let original: serde_json::Value = serde_json::from_str(GOLDEN).expect("the fixture is JSON");

    // Same keys, different order: equal.
    let reordered: serde_json::Value = serde_json::from_str(r#"{"b": 1, "a": 2}"#).expect("parses");
    let forwards: serde_json::Value = serde_json::from_str(r#"{"a": 2, "b": 1}"#).expect("parses");
    assert_eq!(canonical(&reordered), canonical(&forwards));

    // A changed value: not equal.
    let mut altered = original.clone();
    altered["irVersion"] = serde_json::json!(99);
    assert_ne!(canonical(&altered), canonical(&original));

    // A dropped operation: not equal. Array order is a sequence, not a set.
    let mut truncated = original.clone();
    truncated["operations"].as_array_mut().expect("array").pop();
    assert_ne!(canonical(&truncated), canonical(&original));

    let mut swapped = original.clone();
    swapped["operations"]
        .as_array_mut()
        .expect("array")
        .swap(0, 1);
    assert_ne!(
        canonical(&swapped),
        canonical(&original),
        "reordering operations changes what the seed does"
    );
}

#[test]
fn it_covers_every_operation_kind() {
    let ir = golden();
    let kinds: Vec<&str> = ir
        .operations
        .iter()
        .map(|op| match op {
            Operation::Create { .. } => "create",
            Operation::CreateMany { .. } => "createMany",
            Operation::Upsert { .. } => "upsert",
            Operation::Sql { .. } => "sql",
            Operation::Group { .. } => "group",
        })
        .collect();

    for expected in ["upsert", "createMany", "group", "sql"] {
        assert!(
            kinds.contains(&expected),
            "the fixture must exercise `{expected}`, got {kinds:?}"
        );
    }
}

/// The value shapes that only mean something in a seed, each reached through the fixture
/// rather than constructed, so the file is what proves them.
#[test]
fn it_covers_every_value_shape() {
    let ir = golden();

    let Operation::Upsert { data, .. } = &ir.operations[1] else {
        panic!("the second operation is the organiser upsert");
    };

    assert!(
        matches!(data.get("owner"), Some(Value::Connect { .. })),
        "a relation named by unique key"
    );

    let Some(Value::NestedCreate { create }) = data.get("events") else {
        panic!("events is a nested create");
    };
    let event = &create[0];

    // An operand, imported from the schema's own language rather than redefined.
    assert!(
        matches!(event.get("starts_at"), Some(Value::Operand(_))),
        "a composed time operand"
    );
    assert!(
        matches!(event.get("created_at"), Some(Value::Operand(_))),
        "a bare now()"
    );
    assert!(
        matches!(event.get("title"), Some(Value::Scalar(_))),
        "a plain scalar"
    );

    let Some(Value::NestedCreateMany { create_many }) = event.get("ticket_types") else {
        panic!("ticket_types is a nested createMany");
    };
    assert!(
        matches!(create_many[0].get("price"), Some(Value::Numeric { .. })),
        "money stays a decimal string, never an f64"
    );

    let Operation::CreateMany { rows, .. } = &ir.operations[2] else {
        panic!("the third operation is the venue createMany");
    };
    assert!(
        matches!(rows[0].get("country"), Some(Value::Default { .. })),
        "an explicit column default, which absence cannot spell"
    );
}

/// Money must survive the round trip as text.
///
/// The failure this guards is silent: a `serde_json::Number` deserialises happily and
/// prints `75.0` instead of `75.0000`, losing the scale `NUMERIC(19,4)` exists to give,
/// in the one place it is least acceptable.
#[test]
fn money_never_becomes_a_float() {
    let ir = golden();
    let Operation::Upsert { data, .. } = &ir.operations[1] else {
        panic!("expected the organiser upsert");
    };
    let Some(Value::NestedCreate { create }) = data.get("events") else {
        panic!("expected nested events");
    };
    let Some(Value::NestedCreateMany { create_many }) = create[0].get("ticket_types") else {
        panic!("expected nested ticket types");
    };

    match create_many[0].get("price") {
        Some(Value::Numeric { numeric }) => assert_eq!(numeric, "75.0000"),
        other => panic!("price must be a Numeric, got {other:?}"),
    }
}

/// Both condition shapes, including the bare one that asks "is this table empty".
#[test]
fn it_covers_both_condition_shapes() {
    let ir = golden();

    let Operation::Group { if_: bare, .. } = &ir.operations[3] else {
        panic!("the fourth operation is the guarded settings group");
    };
    match bare {
        Some(Condition::NotExists { model, filter }) => {
            assert_eq!(model, "SiteSettings");
            assert!(
                filter.is_none(),
                "an absent filter means the table is empty"
            );
        }
        other => panic!("expected a bare notExists, got {other:?}"),
    }

    let Operation::Group { if_: filtered, .. } = &ir.operations[4] else {
        panic!("the fifth operation is the filtered promo group");
    };
    match filtered {
        Some(Condition::Exists {
            model,
            filter: Some(_),
        }) => assert_eq!(model, "Event"),
        other => panic!("expected a filtered exists, got {other:?}"),
    }
}

/// A condition's filter is the schema's own rule tree.
///
/// If this ever stops being an `AccessRule`, the seed IR has grown a second predicate
/// language and needs a second validator and a second SQL renderer to go with it.
#[test]
fn a_condition_filter_is_a_schema_access_rule() {
    use supatype_engine::parser::ast::{AccessRule, Operand};

    let ir = golden();
    let Operation::Group {
        if_: Some(Condition::Exists {
            filter: Some(rule), ..
        }),
        ..
    } = &ir.operations[4]
    else {
        panic!("expected the filtered group");
    };

    match rule {
        AccessRule::Compare { left, right, .. } => {
            assert!(matches!(left, Operand::Column { .. }));
            assert!(matches!(right, Operand::Literal { .. }));
        }
        other => panic!("expected a compare, got {other:?}"),
    }
}

/// The golden IR is vendored into supatype/supatype, and this hash is how the two stay one file.
///
/// The CLI's builder is checked against the same hand-written document, because a builder checked
/// against whatever the engine happens to emit is checked against itself. That used to work by
/// reading this file across a sibling checkout, which does not exist in that repository's CI, so
/// the test had never run there.
///
/// Both repositories now assert this hash. Editing this file turns this test red until the hash is
/// updated, and updating the hash turns the other repository red until its copy follows. Neither
/// copy can drift quietly, which is the only thing the shared path was ever buying.
///
/// Other side: `packages/cli/tests/seed-ir.test.ts`, same constant.
#[test]
fn the_golden_ir_matches_the_copy_vendored_into_the_cli() {
    use sha2::{Digest, Sha256};

    const GOLDEN_SHA256: &str = "6ec5e51820868e0e303abe3c5aa57e034ff27c53374998d760d425863e538ea6";

    // Line endings normalised first. git hands this file out as CRLF on Windows and LF on Linux,
    // so hashing the bytes as checked out pins the platform rather than the content, and the two
    // repositories would disagree depending on who ran the test.
    let raw = include_str!("fixtures/seed_golden_ir.json");
    let normalised = raw.replace("\r\n", "\n");
    let digest = format!("{:x}", Sha256::digest(normalised.as_bytes()));
    assert_eq!(
        digest, GOLDEN_SHA256,
        "the golden IR changed. Update supatype/supatype's copy at \
         packages/cli/tests/fixtures/seed_golden_ir.json and the constant in both repositories, \
         or the two builders are no longer checked against the same document."
    );
}
