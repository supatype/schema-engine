//! A stable identifier for the shape of a schema.
//!
//! An IR is built against a generated builder, and the builder is generated from a
//! schema. If the schema has moved on since, the IR describes columns that may no longer
//! exist. Catching that by fingerprint means the run is refused with the remedy named,
//! rather than failing partway through with a Postgres error about a column, which reads
//! like a bug in the seed rather than a stale build.
//!
//! **Order independence is the whole difficulty.** A fingerprint over the AST as written
//! would change when someone moves a model down the file or adds a field in the middle,
//! and every existing IR would be refused for a change that altered nothing. So the
//! digest is taken over a normalised projection: models sorted by name, fields sorted by
//! name, and only the parts an IR can actually depend on.
//!
//! **What it deliberately excludes** is as important. Access rules, indexes, and storage
//! buckets do not change what a seed may write, so including them would invalidate every
//! IR when a policy changed. What a seed depends on is: which models exist, what they are
//! called in the database, which columns they have, each column's kind, whether it is
//! required, whether it has a default, and which columns are unique enough to be an
//! `ON CONFLICT` target.

use crate::parser::ast::{FieldAst, ModelAst, SchemaAst};
use sha2::{Digest, Sha256};

/// The parts of a field an IR can depend on, as one line.
///
/// Read from the serialised form rather than by matching [`FieldAst`]'s thirty-odd
/// variants. Two reasons, and the second is the one that matters: a match would need an
/// arm per variant and per wrapper struct, and a new field kind added later would either
/// fail to compile here or, if a catch-all were used, be silently left out of the digest.
/// Reading the serialised shape means a new kind is included the day it exists.
fn field_line(name: &str, field: &FieldAst) -> String {
    let value = serde_json::to_value(field).unwrap_or(serde_json::Value::Null);
    let text = |key: &str| {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let flag = |key: &str| value.get(key).and_then(|v| v.as_bool()).unwrap_or(false);

    let kind = {
        let named = text("kind");
        if named.is_empty() {
            "unknown".to_string()
        } else {
            named
        }
    };
    let required = flag("required");
    let unique = flag("unique");
    let primary_key = flag("primaryKey");
    let has_default = value.get("default").is_some_and(|d| !d.is_null());

    // A relation's target and its foreign key decide what an IR may `connect` to, so they
    // belong here too. Absent for a scalar, which is why they are read and not matched.
    let target = text("target");
    let cardinality = text("cardinality");

    format!("{name}:{kind}:{required}:{unique}:{primary_key}:{has_default}:{target}:{cardinality}")
}

/// One model, normalised: its name, its table, and its fields sorted by name.
fn model_line(model: &ModelAst) -> String {
    let mut fields: Vec<String> = model
        .fields
        .iter()
        .map(|(name, field)| field_line(name, field))
        .collect();
    fields.sort();
    format!(
        "{}|{}|{}",
        model.name,
        model.annotations.db.table_name,
        fields.join(",")
    )
}

/// A stable digest of the parts of `ast` that a seed IR can depend on.
///
/// Prefixed with the algorithm so a future change to what is hashed can be told apart
/// from a schema that genuinely differs, rather than looking like drift to every project
/// at once.
pub fn fingerprint(ast: &SchemaAst) -> String {
    let mut lines: Vec<String> = ast.models.iter().map(model_line).collect();
    lines.sort();

    let mut hasher = Sha256::new();
    hasher.update(b"supatype-seed-fingerprint-v1\n");
    for line in lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ast::SchemaAst;

    fn schema_from(json: &str) -> SchemaAst {
        serde_json::from_str(json).expect("fixture parses")
    }

    const TWO_MODELS: &str = r#"{
        "astVersion": 2,
        "models": [
            {
                "name": "Organiser",
                "fields": {
                    "id": {"kind": "uuid", "required": true, "annotations": {"db": {"unique": true}}},
                    "slug": {"kind": "text", "required": true, "annotations": {"db": {"unique": true}}}
                },
                "annotations": {"db": {"tableName": "organiser"}}
            },
            {
                "name": "Event",
                "fields": {
                    "id": {"kind": "uuid", "required": true, "annotations": {"db": {"unique": true}}},
                    "title": {"kind": "text", "required": true}
                },
                "annotations": {"db": {"tableName": "event"}}
            }
        ]
    }"#;

    // The same schema written in a different order is the same schema. Without this, a
    // reordered `schema/index.ts` would refuse every IR built before it, for a change
    // that altered nothing.
    #[test]
    fn is_independent_of_model_order() {
        let forwards = schema_from(TWO_MODELS);
        let mut backwards = forwards.clone();
        backwards.models.reverse();
        assert_eq!(fingerprint(&forwards), fingerprint(&backwards));
    }

    #[test]
    fn is_independent_of_field_order() {
        let original = schema_from(TWO_MODELS);
        let reordered = schema_from(
            &TWO_MODELS
                .replace(
                    r#""id": {"kind": "uuid", "required": true, "annotations": {"db": {"unique": true}}},
                    "title": {"kind": "text", "required": true}"#,
                    r#""title": {"kind": "text", "required": true},
                    "id": {"kind": "uuid", "required": true, "annotations": {"db": {"unique": true}}}"#,
                ),
        );
        assert_eq!(fingerprint(&original), fingerprint(&reordered));
    }

    // And it must still notice a real change, or it is only a constant.
    #[test]
    fn changes_when_a_field_is_added() {
        let before = schema_from(TWO_MODELS);
        let after = schema_from(&TWO_MODELS.replace(
            r#""title": {"kind": "text", "required": true}"#,
            r#""title": {"kind": "text", "required": true},
               "summary": {"kind": "text", "required": false}"#,
        ));
        assert_ne!(fingerprint(&before), fingerprint(&after));
    }

    #[test]
    fn changes_when_a_field_kind_changes() {
        let before = schema_from(TWO_MODELS);
        let after = schema_from(&TWO_MODELS.replace(
            r#""title": {"kind": "text", "required": true}"#,
            r#""title": {"kind": "integer", "required": true}"#,
        ));
        assert_ne!(fingerprint(&before), fingerprint(&after));
    }

    // Required and unique both decide what an IR may write or upsert on, so both belong
    // in the digest even though neither renames anything.
    #[test]
    fn changes_when_required_changes() {
        let before = schema_from(TWO_MODELS);
        let after = schema_from(&TWO_MODELS.replace(
            r#""title": {"kind": "text", "required": true}"#,
            r#""title": {"kind": "text", "required": false}"#,
        ));
        assert_ne!(fingerprint(&before), fingerprint(&after));
    }

    #[test]
    fn changes_when_the_table_name_changes() {
        let before = schema_from(TWO_MODELS);
        let after =
            schema_from(&TWO_MODELS.replace(r#""tableName": "event""#, r#""tableName": "events""#));
        assert_ne!(fingerprint(&before), fingerprint(&after));
    }

    #[test]
    fn is_stable_across_calls() {
        let ast = schema_from(TWO_MODELS);
        assert_eq!(fingerprint(&ast), fingerprint(&ast));
    }

    #[test]
    fn names_its_algorithm() {
        let ast = schema_from(TWO_MODELS);
        assert!(fingerprint(&ast).starts_with("sha256:"));
    }
}
