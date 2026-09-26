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
