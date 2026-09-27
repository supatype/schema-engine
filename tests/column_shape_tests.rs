//! What `database.ts` promises for the two column shapes that nothing ever checked.
//!
//! Both were wrong against live data in the kitchen-sink example:
//!
//!   page.title    is jsonb holding {"en": "...", "fr": "..."}, and the type said `string`
//!   speaker.headshot  declared three different ways in three places, and written by nothing
//!
//! The asset case is the sharper lesson. `Image` and `File` were declared in `@supatype/types` as
//! `{ bucket, path, mimeType?, size? }`, by this generator as `{ bucket, path, url }`, and by the
//! CLI as `Record<string, unknown>`, while `storage.upload()` returns `{ path }` and no code path
//! in the repo ever wrote one. Three definitions drifted precisely because nothing exercised them.
//! The shape asserted here is what `upload()` actually produces plus the bucket it went to; a URL
//! is derived, not stored, because a stored one goes stale and bakes in the storage host.

use supatype_engine::generator::typescript::types;
use supatype_engine::parser;

fn schema() -> &'static str {
    r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "page",
      "annotations": { "db": { "tableName": "page" } },
      "fields": {
        "id": { "kind": "uuid", "required": true },
        "title": { "kind": "text", "required": true, "localized": true },
        "slug": { "kind": "text", "required": true },
        "headshot": { "kind": "image", "required": false },
        "attachment": { "kind": "file", "required": false }
      }
    }
  ]
}"#
}

fn generated() -> String {
    let ast = parser::parse(schema()).expect("schema parses");
    types::generate(&ast).expect("types generate")
}

/// The `Row` block of `page`, so an assertion cannot match `Insert` or `Update`.
fn row_block(src: &str) -> String {
    let start = src.find("      page: {").expect("page table in output");
    let rest = &src[start..];
    let row = rest.find("Row: {").expect("Row block");
    let end = rest[row..].find("Insert: {").expect("Insert after Row");
    rest[row..row + end].to_string()
}

#[test]
fn a_localized_column_is_a_locale_map() {
    // The column is jsonb and holds {"en": "...", "fr": "..."}. Typing it `string` invites
    // `.toUpperCase()` on an object, which the compiler happily allows and the browser does not.
    let row = row_block(&generated());
    assert!(
        row.contains("title: LocalizedValue<string>"),
        "localized column should be a locale map, got:\n{row}"
    );
}

#[test]
fn a_plain_column_of_the_same_kind_is_untouched() {
    // The control. `slug` is the same kind and is not localized, so a fix that wrapped every
    // string would pass the assertion above and be wrong everywhere else.
    let row = row_block(&generated());
    assert!(
        row.contains("slug: string\n"),
        "non-localized string should stay a string, got:\n{row}"
    );
}

#[test]
fn the_locale_map_helper_is_declared() {
    let src = generated();
    assert!(
        src.contains("export type LocalizedValue<T> = { [locale: string]: T }"),
        "the helper the row type names must be declared, got:\n{src}"
    );
}

#[test]
fn a_storage_reference_is_what_upload_returns() {
    // `storage.upload()` yields `{ path }`, and the bucket is known by the caller. A `url` is
    // derived rather than stored: storing one goes stale and hard-codes the storage host.
    let src = generated();
    assert!(
        src.contains("export type StorageReference = {\n  bucket: string\n  path: string\n}"),
        "storage reference should be bucket and path only, got:\n{src}"
    );
    assert!(
        !src.contains("url: string\n}"),
        "a stored url is not part of the shape, got:\n{src}"
    );
}

#[test]
fn image_and_file_both_use_it() {
    let row = row_block(&generated());
    assert!(
        row.contains("headshot: StorageReference | null"),
        "got:\n{row}"
    );
    assert!(
        row.contains("attachment: StorageReference | null"),
        "got:\n{row}"
    );
}
