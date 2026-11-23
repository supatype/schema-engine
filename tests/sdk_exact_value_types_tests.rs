//! What each generated SDK declares for the exact-value kinds.
//!
//! `money` and `decimal` are both NUMERIC. Every generator declared `money` as the language's
//! binary float, and Go, Python and Swift declared `decimal` correctly as an exact type in the
//! very next line, so one NUMERIC column was exact and the other was a float in the same struct.
//!
//! The rule asserted here is that the two map to the same exact type in every language. `float`
//! is the control: it is an IEEE-754 double by definition and must not be swept up by a fix that
//! moved every numeric kind to an exact type.

use supatype_engine::generator::sdk;
use supatype_engine::parser;

fn schema() -> &'static str {
    r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "ledger",
      "annotations": { "db": { "tableName": "ledger" } },
      "fields": {
        "id": { "kind": "uuid", "required": true },
        "views": { "kind": "bigInt", "required": true },
        "ratio": { "kind": "decimal", "required": true },
        "balance": { "kind": "money", "required": true },
        "rate": { "kind": "float", "required": true },
        "hits": { "kind": "integer", "required": true }
      }
    }
  ]
}"#
}

fn generated(lang: &str) -> String {
    let ast = parser::parse(schema()).expect("schema parses");
    sdk::generate(&ast, lang).expect("sdk generates")
}

/// Assert a declaration is present, printing the whole file when it is not.
fn has(src: &str, needle: &str, lang: &str) {
    assert!(
        src.contains(needle),
        "{lang}: expected `{needle}`, got:\n{src}"
    );
}

/// Assert a declaration is absent, printing the whole file when it is present.
fn lacks(src: &str, needle: &str, lang: &str) {
    assert!(
        !src.contains(needle),
        "{lang}: `{needle}` should be gone, got:\n{src}"
    );
}

#[test]
fn go_money_and_decimal_are_exact() {
    let src = generated("go");
    has(&src, "Balance string", "go");
    has(&src, "Ratio string", "go");
    lacks(&src, "Balance float64", "go");
    // Controls: a real float stays a float, and bigInt keeps the exact 64-bit integer type.
    has(&src, "Rate float64", "go");
    has(&src, "Views int64", "go");
}

#[test]
fn python_money_and_decimal_are_exact() {
    let src = generated("python");
    has(&src, "balance: Decimal", "python");
    has(&src, "ratio: Decimal", "python");
    lacks(&src, "balance: float", "python");
    has(&src, "rate: float", "python");
    // The import is emitted unconditionally, but assert it so a later tidy cannot strip it.
    has(&src, "from decimal import Decimal", "python");
}

#[test]
fn swift_money_and_decimal_are_exact() {
    let src = generated("swift");
    has(&src, "balance: Decimal", "swift");
    has(&src, "ratio: Decimal", "swift");
    lacks(&src, "balance: Double", "swift");
    has(&src, "rate: Double", "swift");
    has(&src, "import Foundation", "swift");
}

#[test]
fn kotlin_money_and_decimal_are_exact() {
    let src = generated("kotlin");
    has(&src, "balance: BigDecimal", "kotlin");
    has(&src, "ratio: BigDecimal", "kotlin");
    lacks(&src, "balance: Double", "kotlin");
    has(&src, "rate: Double", "kotlin");
    // Unlike python and swift, this generator emitted no imports at all, so BigDecimal would be
    // an undefined symbol in every generated file without one.
    has(&src, "import java.math.BigDecimal", "kotlin");
}

#[test]
fn dart_money_and_decimal_are_exact() {
    let src = generated("dart");
    has(&src, "String balance", "dart");
    has(&src, "String ratio", "dart");
    lacks(&src, "double balance", "dart");
    has(&src, "double rate", "dart");
}

#[test]
fn php_money_and_decimal_are_exact() {
    let src = generated("php");
    has(&src, "string $balance", "php");
    has(&src, "string $ratio", "php");
    lacks(&src, "float $balance", "php");
    has(&src, "float $rate", "php");
}

#[test]
fn no_generated_header_uses_an_em_dash() {
    // House style, and these headers are the first line of every file the product writes into a
    // user's repo.
    for lang in ["go", "python", "swift", "kotlin", "dart", "php"] {
        let src = generated(lang);
        lacks(&src, "\u{2014}", lang);
    }
}

#[test]
fn dart_from_json_converts_rather_than_casting() {
    // `dart_from_json` falls through to the declared type, so moving money to String turned the
    // decode into `json['balance'] as String` against a JSON number, which throws at runtime.
    // `.toString()` is correct whichever the wire sends: exact when it sends the digits as a
    // string, and lossy-but-not-fatal while it still sends a number.
    let src = generated("dart");
    has(&src, "json['balance'].toString()", "dart");
    has(&src, "json['ratio'].toString()", "dart");
    lacks(&src, "json['balance'] as String", "dart");
}

/// One model with an array column for every element type the exact-value rule has to sort.
fn array_schema() -> &'static str {
    r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "ledger",
      "annotations": { "db": { "tableName": "ledger" } },
      "fields": {
        "id": { "kind": "uuid", "required": true },
        "big_ids": { "kind": "array", "required": true, "annotations": { "db": { "elementType": "BIGINT" } } },
        "int8_ids": { "kind": "array", "required": true, "annotations": { "db": { "elementType": "int8" } } },
        "serial_ids": { "kind": "array", "required": true, "annotations": { "db": { "elementType": "BIGSERIAL" } } },
        "rates": { "kind": "array", "required": true, "annotations": { "db": { "elementType": "NUMERIC" } } },
        "scaled": { "kind": "array", "required": true, "annotations": { "db": { "elementType": "NUMERIC(19,4)" } } },
        "decimals": { "kind": "array", "required": true, "annotations": { "db": { "elementType": "decimal" } } },
        "amounts": { "kind": "array", "required": true, "annotations": { "db": { "elementType": "MONEY" } } },
        "small": { "kind": "array", "required": true, "annotations": { "db": { "elementType": "INTEGER" } } },
        "floats": { "kind": "array", "required": true, "annotations": { "db": { "elementType": "DOUBLE PRECISION" } } },
        "flags": { "kind": "array", "required": true, "annotations": { "db": { "elementType": "BOOLEAN" } } },
        "tags": { "kind": "array", "required": true, "annotations": { "db": { "elementType": "TEXT" } } },
        "maybe_ids": { "kind": "array", "required": false, "annotations": { "db": { "elementType": "BIGINT" } } }
      }
    }
  ]
}"#
}

fn generated_arrays(lang: &str) -> String {
    let ast = parser::parse(array_schema()).expect("schema parses");
    sdk::generate(&ast, lang).expect("sdk generates")
}

/// Assert every needle is present. The exact-element columns are the point: BIGINT elements in
/// the language's 64-bit integer, NUMERIC, DECIMAL and MONEY elements in its exact decimal, as the
/// single `bigInt`, `decimal` and `money` kinds are. `small`, `floats`, `flags` and `tags` are the
/// controls that must not move.
fn has_all(src: &str, lang: &str, needles: &[&str]) {
    for needle in needles {
        has(src, needle, lang);
    }
}

#[test]
fn go_array_elements_follow_the_single_values() {
    let src = generated_arrays("go");
    has_all(
        &src,
        "go",
        &[
            "BigIds []int64 ",
            "Int8Ids []int64 ",
            "SerialIds []int64 ",
            "Rates []string ",
            "Scaled []string ",
            "Decimals []string ",
            "Amounts []string ",
            "Small []int32 ",
            "Floats []float64 ",
            "Flags []bool ",
            "Tags []string ",
            "MaybeIds *[]int64 ",
        ],
    );
    lacks(&src, "[]float64 `json:\"rates\"", "go");
}

#[test]
fn python_array_elements_follow_the_single_values() {
    let src = generated_arrays("python");
    has_all(
        &src,
        "python",
        &[
            "big_ids: list[int]",
            "int8_ids: list[int]",
            "serial_ids: list[int]",
            "rates: list[Decimal]",
            "scaled: list[Decimal]",
            "decimals: list[Decimal]",
            "amounts: list[Decimal]",
            "small: list[int]",
            "floats: list[float]",
            "flags: list[bool]",
            "tags: list[str]",
        ],
    );
}

#[test]
fn kotlin_array_elements_follow_the_single_values() {
    let src = generated_arrays("kotlin");
    has_all(
        &src,
        "kotlin",
        &[
            "bigIds: List<Long>",
            "int8Ids: List<Long>",
            "serialIds: List<Long>",
            "rates: List<BigDecimal>",
            "scaled: List<BigDecimal>",
            "decimals: List<BigDecimal>",
            "amounts: List<BigDecimal>",
            "small: List<Int>",
            "floats: List<Double>",
            "flags: List<Boolean>",
            "tags: List<String>",
        ],
    );
}

#[test]
fn swift_array_elements_follow_the_single_values() {
    let src = generated_arrays("swift");
    has_all(
        &src,
        "swift",
        &[
            "bigIds: [Int64]",
            "int8Ids: [Int64]",
            "serialIds: [Int64]",
            "rates: [Decimal]",
            "scaled: [Decimal]",
            "decimals: [Decimal]",
            "amounts: [Decimal]",
            "small: [Int]",
            "floats: [Double]",
            "flags: [Bool]",
            "tags: [String]",
        ],
    );
}

#[test]
fn dart_array_elements_follow_the_single_values() {
    let src = generated_arrays("dart");
    has_all(
        &src,
        "dart",
        &[
            "final List<int> bigIds;",
            "final List<int> int8Ids;",
            "final List<int> serialIds;",
            "final List<String> rates;",
            "final List<String> scaled;",
            "final List<String> decimals;",
            "final List<String> amounts;",
            "final List<int> small;",
            "final List<double> floats;",
            "final List<bool> flags;",
            "final List<String> tags;",
        ],
    );
}

#[test]
fn dart_array_decode_converts_rather_than_casting() {
    // `json['x'] as List<int>` throws on every real payload: `jsonDecode` builds a `List<dynamic>`,
    // and a `List<dynamic>` is not a `List<int>` whatever it holds. The same cast on a NUMERIC
    // column was also a `double`, which rounds. Exact columns are converted element by element.
    let src = generated_arrays("dart");
    lacks(&src, " as List<int>", "dart");
    lacks(&src, " as List<double>", "dart");
    lacks(&src, " as List<String>", "dart");
    has_all(
        &src,
        "dart",
        &[
            "bigIds: (json['big_ids'] as List<dynamic>).cast<int>(),",
            "rates: (json['rates'] as List<dynamic>).map((e) => (e as Object).toString()).toList(),",
            "scaled: (json['scaled'] as List<dynamic>).map((e) => (e as Object).toString()).toList(),",
            "floats: (json['floats'] as List<dynamic>).map((e) => (e as num).toDouble()).toList(),",
            "tags: (json['tags'] as List<dynamic>).cast<String>(),",
            "maybeIds: json['maybe_ids'] == null ? null : (json['maybe_ids'] as List<dynamic>).cast<int>(),",
        ],
    );
}

#[test]
fn php_array_elements_follow_the_single_values() {
    // The PHP type of every array column stays `array`. The element type is PHPDoc only, following
    // the PHP single-value rule: a single bigint is `int` and a single numeric is `string`.
    let src = generated_arrays("php");
    for (column, elem) in [
        ("big_ids", "int"),
        ("int8_ids", "int"),
        ("serial_ids", "int"),
        ("rates", "string"),
        ("scaled", "string"),
        ("decimals", "string"),
        ("amounts", "string"),
        ("small", "int"),
        ("floats", "float"),
        ("flags", "bool"),
        ("tags", "string"),
        ("maybe_ids", "int"),
    ] {
        let needle = format!("/** @var list<{elem}> */\n        public readonly array ${column}");
        has(&src, &needle, "php");
    }
    lacks(&src, "?array", "php");
}

#[test]
fn openapi_array_items_follow_the_single_values() {
    // A bigint column is `integer` with format `int64`, and its array's items were a bare
    // `integer`, so a generated client was free to pick a 32-bit integer for the elements. NUMERIC
    // is `number` for the single kinds, and the items are the same.
    let ast = parser::parse(array_schema()).expect("schema parses");
    let spec = supatype_engine::generator::openapi::generate(&ast).expect("openapi generates");
    let props = &spec["components"]["schemas"]["ledger"]["properties"];
    for column in ["big_ids", "int8_ids", "serial_ids", "maybe_ids"] {
        assert_eq!(
            props[column]["items"],
            serde_json::json!({ "type": "integer", "format": "int64" }),
            "{column}: {props}"
        );
    }
    for column in ["rates", "scaled", "decimals", "amounts", "floats"] {
        assert_eq!(
            props[column]["items"],
            serde_json::json!({ "type": "number" }),
            "{column}"
        );
    }
    assert_eq!(props["small"]["items"]["format"], "int32");
    assert_eq!(
        props["tags"]["items"],
        serde_json::json!({ "type": "string" })
    );
}
