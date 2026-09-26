//! What `database.ts` promises for the exact-value kinds, against what `@supatype/types` declares.
//!
//! `bigInt`, `decimal` and `money` exist because a binary float cannot hold their values. The
//! generated types disagreed with the package that defines them, in two directions at once:
//! `bigInt` was emitted as `string` where the source of truth says `bigint`, and `money` as
//! `number`, which is the one representation the kind exists to avoid. `decimal`, declared
//! `string` in both places, is the control that shows the assertion is capable of passing.
//!
//! This is not cosmetic. The runtime value is lost before any of it is visible: Postgres holds
//! 9007199254740993 exactly and PostgREST puts those digits on the wire, and `JSON.parse` returns
//! 9007199254740992. A type saying `number` over that column documents the corruption as intended.

use supatype_engine::generator::typescript::types;
use supatype_engine::parser;

/// One model carrying every exact-value kind, so a single generate covers all of them.
fn schema() -> &'static str {
    r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "ledger",
      "annotations": { "db": { "tableName": "ledger" } },
      "fields": {
        "id": { "kind": "uuid", "required": true },
        "seq": { "kind": "bigSerial", "required": true },
        "views": { "kind": "bigInt", "required": true },
        "ratio": { "kind": "decimal", "required": true, "precision": 30, "scale": 10 },
        "balance": { "kind": "money", "required": true },
        "hits": { "kind": "integer", "required": true }
      }
    }
  ]
}"#
}

fn generated() -> String {
    let ast = parser::parse(schema()).expect("schema parses");
    types::generate(&ast).expect("types generate")
}

/// The `Row` block of `ledger`, so an assertion cannot match `Insert` or `Update`.
fn row_block(src: &str) -> String {
    let start = src.find("      ledger: {").expect("ledger table in output");
    let rest = &src[start..];
    let row = rest.find("Row: {").expect("Row block");
    let end = rest[row..]
        .find("Insert: {")
        .expect("Insert block after Row");
    rest[row..row + end].to_string()
}

#[test]
fn big_int_is_a_native_bigint() {
    // `@supatype/types` declares `BigInt = Primitive<"BigInt", bigint>`. Emitting `string` means
    // every consumer of a bigInt column was told the wrong type by the generator, for every value,
    // not only those past 2^53.
    let row = row_block(&generated());
    assert!(
        row.contains("views: bigint\n"),
        "bigInt should be emitted as bigint, got:\n{row}"
    );
}

#[test]
fn big_serial_is_a_native_bigint() {
    // Shares the generator arm with bigInt, so it shares the bug. Asserted separately because a
    // fix that splits the arm could correct one and leave the other.
    let row = row_block(&generated());
    assert!(
        row.contains("seq: bigint\n"),
        "bigSerial should be emitted as bigint, got:\n{row}"
    );
}

#[test]
fn money_is_an_exact_string() {
    // `Money = Primitive<"Money", string>`. It was emitted as `number`, grouped with integer and
    // float, which is how a currency amount ends up in an IEEE-754 double.
    let row = row_block(&generated());
    assert!(
        row.contains("balance: string\n"),
        "money should be emitted as string, got:\n{row}"
    );
    assert!(
        !row.contains("balance: number"),
        "money must not be a number, got:\n{row}"
    );
}

#[test]
fn decimal_is_an_exact_string() {
    // The control. Already correct, and it has to stay correct: a fix that moved every numeric
    // kind to `string` would pass the three assertions above and break ordinary integers.
    let row = row_block(&generated());
    assert!(
        row.contains("ratio: string\n"),
        "decimal should be emitted as string, got:\n{row}"
    );
}

#[test]
fn an_ordinary_integer_is_still_a_number() {
    // The other half of the control. `integer` fits a double exactly and must not be swept up.
    let row = row_block(&generated());
    assert!(
        row.contains("hits: number\n"),
        "integer should stay a number, got:\n{row}"
    );
}
