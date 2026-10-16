//! What `database.ts` and the client augmentation say a `Blocks` column holds.
//!
//! Studio's block editor writes one `{ "type": <block name>, "data": { <the block's fields> } }`
//! entry per block, which is also what the AST documents and what a JSON column converted to blocks
//! is rewritten into. The generated row has to describe that value: a block's fields sit under
//! `data`, a localized one is a locale map there as it is on a column, and the aliases a block's
//! fields name (`Button`, `LocalizedValue`) have to be declared even when no column uses them.

use supatype_engine::generator::typescript::{augmentation, types};
use supatype_engine::parser;

fn schema() -> &'static str {
    r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Speaker",
      "annotations": { "db": { "tableName": "speaker" } },
      "fields": {
        "id": { "kind": "uuid", "required": true, "primaryKey": true },
        "links": {
          "kind": "blocks", "required": false,
          "blocks": [
            {
              "name": "link",
              "fields": {
                "label": { "kind": "text", "pgType": "TEXT", "required": true, "unique": false },
                "href": { "kind": "text", "pgType": "TEXT", "required": true, "unique": false }
              }
            }
          ]
        },
        "body": {
          "kind": "blocks", "required": true,
          "blocks": [
            {
              "name": "hero",
              "fields": {
                "heading": { "kind": "text", "pgType": "JSONB", "required": true, "unique": false, "localized": true },
                "cta": { "kind": "button", "pgType": "JSONB", "required": false, "unique": false },
                "my-key": { "kind": "integer", "pgType": "INTEGER", "required": false, "unique": false }
              }
            },
            { "name": "divider", "fields": {} }
          ]
        },
        "loose": { "kind": "blocks", "required": false, "blocks": [] }
      }
    }
  ]
}"#
}

fn both() -> [String; 2] {
    let ast = parser::parse(schema()).expect("schema parses");
    [
        types::generate(&ast).expect("types generate"),
        augmentation::generate(&ast).expect("augmentation generates"),
    ]
}

const LINKS: &str = "({ type: \"link\"; data: { label: string; href: string } })[]";
const BODY: &str = "({ type: \"hero\"; data: { heading: LocalizedValue<string>; cta?: Button; \
                    \"my-key\"?: number } } | { type: \"divider\"; data: {} })[]";
const LOOSE: &str = "{ type: string; data: { [key: string]: unknown } }[]";

#[test]
fn a_block_keeps_its_fields_under_data_and_an_optional_column_is_nullable() {
    for src in both() {
        for line in [
            format!("links: {LINKS} | null\n"),
            format!("links?: {LINKS} | null\n"),
        ] {
            assert!(src.contains(&line), "missing `{}` in:\n{src}", line.trim());
        }
    }
}

#[test]
fn a_required_column_is_not_nullable_and_a_block_field_is_typed_as_a_column_would_be() {
    for src in both() {
        assert!(src.contains(&format!("body: {BODY}\n")), "{src}");
        assert!(
            !src.contains(&format!("body: {BODY} | null")),
            "a required column is never null:\n{src}"
        );
    }
}

#[test]
fn a_blocks_column_with_no_declared_blocks_still_says_type_and_data() {
    for src in both() {
        assert!(src.contains(&format!("loose: {LOOSE} | null\n")), "{src}");
    }
}

/// `Button` and `LocalizedValue` are named only inside a block here, so the file has to declare
/// them on the block's account or it does not compile.
#[test]
fn the_aliases_a_block_names_are_declared() {
    let [db, _] = both();
    assert!(db.contains("export type Button = {"), "{db}");
    assert!(db.contains("export type LocalizedValue<T> ="), "{db}");
}
