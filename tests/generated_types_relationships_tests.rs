//! What `database.ts` and the client augmentation say about JSON shapes and about the keys
//! between tables.
//!
//! Typing Cloud's content project with these files found both gaps: a `JSON<T>` column came out as
//! untyped `Json` although the schema declared `T`, and every table said `Relationships: []`, with
//! no junction tables at all, so `@supatype/client` could not type an embedded select and the
//! project declared every joined shape by hand.

use supatype_engine::generator::typescript::{augmentation, types};
use supatype_engine::parser;

fn schema() -> &'static str {
    r#"{
  "astVersion": 2,
  "models": [
    {
      "name": "Author",
      "annotations": { "db": { "tableName": "authors" } },
      "fields": {
        "id": { "kind": "uuid", "required": true, "primaryKey": true },
        "posts": { "kind": "relation", "cardinality": "hasMany", "target": "BlogPost" }
      }
    },
    {
      "name": "Tag",
      "annotations": { "db": { "tableName": "tags" } },
      "fields": {
        "id": { "kind": "serial", "required": true, "primaryKey": true },
        "posts": {
          "kind": "relation", "cardinality": "manyToMany", "target": "BlogPost",
          "through": "post_tags"
        }
      }
    },
    {
      "name": "BlogPost",
      "annotations": { "db": { "tableName": "blog_posts" } },
      "fields": {
        "id": { "kind": "uuid", "required": true, "primaryKey": true },
        "author": {
          "kind": "relation", "cardinality": "belongsTo", "target": "Author", "required": true
        },
        "features": {
          "kind": "json", "required": false, "localized": true,
          "tsType": "{ title: string; icon: string }[]"
        },
        "untyped": { "kind": "json", "required": false },
        "tags": {
          "kind": "relation", "cardinality": "manyToMany", "target": "Tag", "through": "post_tags"
        }
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

/// The body of `table`'s entry, up to the next table, so an assertion cannot match a neighbour.
fn table<'a>(src: &'a str, name: &str) -> &'a str {
    let start = src
        .find(&format!(" {name}: {{\n"))
        .unwrap_or_else(|| panic!("no {name} table in:\n{src}"));
    let rest = &src[start..];
    let end = rest[1..]
        .find("\n    }\n")
        .or_else(|| rest[1..].find("\n      }\n"))
        .unwrap_or(rest.len() - 1);
    &rest[..end + 1]
}

#[test]
fn a_json_column_keeps_the_shape_the_schema_declared() {
    let [db, aug] = both();
    assert!(
        db.contains("features: LocalizedValue<{ title: string; icon: string }[]> | null"),
        "{db}"
    );
    assert!(
        aug.contains("features: LocalizedValue<{ title: string; icon: string }[]> | null"),
        "{aug}"
    );
    assert!(
        db.contains("untyped: Json | null"),
        "no tsType is any JSON:\n{db}"
    );
}

#[test]
fn a_belongs_to_is_a_relationship_on_the_table_holding_the_key() {
    for src in both() {
        let posts = table(&src, "blog_posts");
        assert!(posts.contains("columns: [\"author_id\"]"), "{posts}");
        assert!(posts.contains("referencedRelation: \"authors\""), "{posts}");
        assert!(posts.contains("referencedColumns: [\"id\"]"), "{posts}");
        assert!(posts.contains("isOneToOne: false"), "{posts}");
        assert!(
            table(&src, "authors").contains("Relationships: []"),
            "a hasMany holds no key:\n{src}"
        );
    }
}

/// The junction is a table PostgREST serves, and the one `tags:post_tags(tag:tags(*))` reads.
/// Its keys are typed like the primary keys they reference: `Tag` is keyed by a serial.
#[test]
fn a_many_to_many_emits_its_junction_table_once() {
    for src in both() {
        assert_eq!(src.matches(" post_tags: {").count(), 1, "{src}");
        let junction = table(&src, "post_tags");
        assert!(junction.contains("tag_id: number"), "{junction}");
        assert!(junction.contains("blog_post_id: string"), "{junction}");
        assert!(
            junction.contains("tag_id?: number"),
            "Update is optional:\n{junction}"
        );
        assert!(
            junction.contains("referencedRelation: \"tags\""),
            "{junction}"
        );
        assert!(
            junction.contains("referencedRelation: \"blog_posts\""),
            "{junction}"
        );
    }
}

/// A JSON column's declared shape survives the AST's own round trip, as `localized` does.
#[test]
fn json_shape_and_localization_survive_serialisation() {
    let ast = parser::parse(schema()).expect("schema parses");
    let json = serde_json::to_string(&ast).expect("serialises");
    let again = parser::parse(&json).expect("reparses");
    let out = types::generate(&again).expect("types generate");
    assert!(
        out.contains("features: LocalizedValue<{ title: string; icon: string }[]> | null"),
        "{out}"
    );
}
