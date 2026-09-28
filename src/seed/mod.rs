//! The seed IR: a second AST, describing writes rather than schema.
//!
//! A language SDK builds one of these and never connects to Postgres. The engine
//! validates it against the schema, plans it, executes it in one transaction, and maps
//! failures back to schema terms. That split is what lets one implementation of the hard
//! parts serve every language the SDK generator targets, rather than seven.
//!
//! Versioned independently of the schema AST, because the two change for different
//! reasons and a seed document outlives the run that produced it.

pub mod errors;
#[cfg(not(target_arch = "wasm32"))]
pub mod execute;
pub mod fingerprint;
pub mod plan;
pub mod validate;

use crate::parser::ast::{AccessRule, Operand};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// The only IR version this engine understands.
///
/// Checked rather than assumed: a newer document read as if it were this one would fail
/// somewhere deeper, with an error about a field rather than about the version.
pub const IR_VERSION: u32 = 1;

/// One seed document, as a language SDK emits it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SeedIr {
    pub ir_version: u32,
    /// The fingerprint of the schema the builder was generated from.
    ///
    /// Lets a stale IR be refused with the remedy named, rather than failing later with a
    /// column error that reads like a bug in the seed.
    pub schema_fingerprint: String,
    pub operations: Vec<Operation>,
}

/// A row's worth of values, keyed by field, relation or foreign-key column.
///
/// `IndexMap` rather than a `HashMap`: insertion order is what makes a batch's column
/// list, and therefore its SQL, stable between runs. A `HashMap` would reorder columns
/// per process and make the golden IR fixture untestable.
pub type DataMap = IndexMap<String, Value>;

/// What a seed does, in the order it is written.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum Operation {
    /// Insert one row.
    Create {
        model: String,
        /// A label local to this document, for a later `$ref` to point at. Not a
        /// database id: the row's real id may not exist until the insert returns.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        data: DataMap,
    },

    /// Insert many rows of one model, in one statement.
    ///
    /// Not sugar for repeated `Create`: a per-row API is how a seed of a few thousand
    /// rows becomes a few thousand round trips.
    CreateMany { model: String, rows: Vec<DataMap> },

    /// Insert, or update on conflict with the `where` columns.
    ///
    /// The primary operation for seeds. Seeds get re-run, and idempotency is the thing
    /// every hand-written seed gets wrong. It is also what removes hardcoded ids: a
    /// natural key means the row identifies itself.
    Upsert {
        model: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(rename = "where")]
        where_: DataMap,
        data: DataMap,
    },

    /// A raw statement with bound parameters.
    ///
    /// Kept inside the IR rather than offered as a side channel, so a seed mixing typed
    /// operations and raw SQL still executes in one transaction in the right order,
    /// instead of the author opening a second connection the engine knows nothing about.
    Sql {
        text: String,
        #[serde(default)]
        params: Vec<Value>,
    },

    /// A block of operations, run only when the condition holds.
    Group {
        #[serde(default, rename = "if", skip_serializing_if = "Option::is_none")]
        if_: Option<Condition>,
        operations: Vec<Operation>,
    },
}

/// A condition on database state, evaluated by the engine at the group's position.
///
/// The builder cannot round-trip, because it is pure and ships in every language. The
/// engine is already connected and already inside a transaction, so evaluating this costs
/// it one statement and no architecture.
///
/// `filter` is the existing [`AccessRule`] tree, reused whole rather than reinvented:
/// every operator, `any`/`all`/`not`, `in`, and the same vocabulary the author already
/// writes in their schema's access rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Condition {
    /// At least one matching row.
    Exists {
        model: String,
        #[serde(default, rename = "where", skip_serializing_if = "Option::is_none")]
        filter: Option<AccessRule>,
    },
    /// No matching row. Omit `where` for "is this table empty".
    NotExists {
        model: String,
        #[serde(default, rename = "where", skip_serializing_if = "Option::is_none")]
        filter: Option<AccessRule>,
    },
    /// The environment this run targets, for one document applied to several.
    Environment { name: String },
}

/// One value in a row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Value {
    /// `{"$numeric": "75.0000"}`.
    ///
    /// Its own variant, and a `String`, because JSON has no decimal type. A
    /// `serde_json::Number` for a money column round-trips through `f64` and loses the
    /// guarantee `NUMERIC(19,4)` exists to give, in the one place it is least acceptable.
    /// Listed first so it is matched before the untagged fallbacks.
    Numeric {
        #[serde(rename = "$numeric")]
        numeric: String,
    },

    /// `{"$ref": "alex.id"}`: a value produced by an earlier operation.
    Ref {
        #[serde(rename = "$ref")]
        reference: String,
    },

    /// `{"$default": true}`: the column's own default.
    ///
    /// Distinct from omitting the field. Omission means "do not write this column", which
    /// on the update half of an upsert leaves the existing value; this means "reset it to
    /// the default". Both are wanted and only one can be spelled by absence.
    ///
    /// New rather than reused: a policy predicate never needs to write `DEFAULT`, so
    /// [`Operand`] has no such variant.
    Default {
        #[serde(rename = "$default")]
        default: bool,
    },

    /// `{"connect": {...}}`: a relation target named by a unique key.
    Connect { connect: IndexMap<String, Value> },

    /// `{"create": [...]}` on the inverse side of a relation.
    NestedCreate { create: Vec<DataMap> },

    /// `{"createMany": [...]}` on the inverse side of a relation.
    ///
    /// Renamed explicitly: `untagged` carries no `rename_all`, so without this the field
    /// is read and written as `create_many` while every SDK emits `createMany`, and an
    /// untagged enum reports that as "no variant matched" rather than as a typo.
    NestedCreateMany {
        #[serde(rename = "createMany")]
        create_many: Vec<DataMap>,
    },

    /// Anything the schema's own operand language already describes: a literal, `now`,
    /// `ago`, `fromNow`, `startOf`, `after`, `before`.
    ///
    /// Imported rather than redefined. Forking a second expression vocabulary for seeds
    /// would need a second validator and a second SQL renderer, and would re-litigate the
    /// `clock_timestamp()` decision the engine documents on `Operand::Now`.
    Operand(Operand),

    /// A bare JSON scalar, the common case: `"Alex Rivera"`, `42`, `true`, `null`.
    ///
    /// Last, so every tagged shape above is tried first. An untagged enum takes the first
    /// variant that deserialises, and this one accepts almost anything.
    Scalar(serde_json::Value),
}

impl Value {
    /// True when this value is a plain scalar or a schema operand, rather than one of the
    /// shapes that only mean something in a seed.
    pub fn is_simple(&self) -> bool {
        matches!(
            self,
            Value::Scalar(_) | Value::Operand(_) | Value::Numeric { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(json: &str) -> Value {
        serde_json::from_str(json).unwrap_or_else(|e| panic!("{json} did not parse: {e}"))
    }

    // `Value` is `untagged`, which takes the first variant that deserialises. That makes
    // variant order load-bearing and the failure silent: a money string landing in
    // `Scalar` instead of `Numeric` does not error, it just stops being a decimal. Every
    // shape is pinned here for that reason.

    #[test]
    fn a_numeric_is_not_read_as_a_scalar_string() {
        assert_eq!(
            value(r#"{"$numeric": "75.0000"}"#),
            Value::Numeric {
                numeric: "75.0000".to_string()
            }
        );
    }

    #[test]
    fn a_ref_is_its_own_shape() {
        assert_eq!(
            value(r#"{"$ref": "alex.id"}"#),
            Value::Ref {
                reference: "alex.id".to_string()
            }
        );
    }

    #[test]
    fn a_default_is_its_own_shape() {
        assert_eq!(
            value(r#"{"$default": true}"#),
            Value::Default { default: true }
        );
    }

    // The point of importing `Operand` rather than redefining it: the schema's own
    // expression vocabulary arrives unchanged.
    #[test]
    fn a_schema_operand_round_trips() {
        assert_eq!(value(r#"{"kind": "now"}"#), Value::Operand(Operand::Now));

        let after = value(
            r#"{"kind":"after","base":{"kind":"startOf","unit":"day"},"interval":{"days":30,"hours":9}}"#,
        );
        match after {
            Value::Operand(Operand::After { base, interval }) => {
                assert!(matches!(*base, Operand::StartOf { .. }));
                assert_eq!(interval.days, 30);
                assert_eq!(interval.hours, 9);
            }
            other => panic!("expected an After operand, got {other:?}"),
        }
    }

    #[test]
    fn plain_scalars_stay_scalars() {
        assert_eq!(
            value(r#""Alex Rivera""#),
            Value::Scalar(serde_json::json!("Alex Rivera"))
        );
        assert_eq!(value("42"), Value::Scalar(serde_json::json!(42)));
        assert_eq!(value("true"), Value::Scalar(serde_json::json!(true)));
        assert_eq!(value("null"), Value::Scalar(serde_json::json!(null)));
    }

    #[test]
    fn nested_writes_are_their_own_shapes() {
        assert!(matches!(
            value(r#"{"connect": {"id": "x"}}"#),
            Value::Connect { .. }
        ));
        assert!(matches!(
            value(r#"{"create": [{"title": "x"}]}"#),
            Value::NestedCreate { .. }
        ));
        assert!(matches!(
            value(r#"{"createMany": [{"title": "x"}]}"#),
            Value::NestedCreateMany { .. }
        ));
    }

    // Round trip, because the golden fixture (E18) compares text: a value that
    // deserialises correctly but serialises differently would fail there instead of here,
    // where the message is about the value rather than about a whole document.
    #[test]
    fn every_value_shape_round_trips_through_json() {
        for original in [
            r#"{"$numeric":"75.0000"}"#,
            r#"{"$ref":"alex.id"}"#,
            r#"{"$default":true}"#,
            r#"{"kind":"now"}"#,
            r#""Alex Rivera""#,
            r#"42"#,
            r#"true"#,
        ] {
            let parsed: Value = serde_json::from_str(original).expect("parses");
            let written = serde_json::to_string(&parsed).expect("serialises");
            assert_eq!(written, original, "round trip changed {original}");
        }
    }

    #[test]
    fn operations_carry_their_tag() {
        let create: Operation = serde_json::from_str(
            r#"{"op":"create","model":"Event","id":"conference","data":{"title":"x"}}"#,
        )
        .expect("parses");
        match create {
            Operation::Create { model, id, data } => {
                assert_eq!(model, "Event");
                assert_eq!(id.as_deref(), Some("conference"));
                assert!(data.contains_key("title"));
            }
            other => panic!("expected Create, got {other:?}"),
        }
    }

    // `where` is a Rust keyword, so the field is `where_`. The rename is what the IR
    // actually says, and getting it wrong would be invisible until a document failed to
    // parse.
    #[test]
    fn upsert_uses_where_not_where_underscore() {
        let upsert: Operation = serde_json::from_str(
            r#"{"op":"upsert","model":"Organiser","where":{"slug":"n"},"data":{"name":"N"}}"#,
        )
        .expect("parses");
        match &upsert {
            Operation::Upsert { where_, .. } => assert!(where_.contains_key("slug")),
            other => panic!("expected Upsert, got {other:?}"),
        }

        let written = serde_json::to_string(&upsert).expect("serialises");
        assert!(written.contains(r#""where""#), "serialised as: {written}");
        assert!(!written.contains("where_"), "serialised as: {written}");
    }

    #[test]
    fn a_group_carries_an_optional_condition() {
        let bare: Operation =
            serde_json::from_str(r#"{"op":"group","operations":[]}"#).expect("parses");
        assert!(matches!(bare, Operation::Group { if_: None, .. }));

        let guarded: Operation = serde_json::from_str(
            r#"{"op":"group","if":{"kind":"notExists","model":"Organiser"},"operations":[]}"#,
        )
        .expect("parses");
        match guarded {
            Operation::Group {
                if_: Some(Condition::NotExists { model, filter }),
                ..
            } => {
                assert_eq!(model, "Organiser");
                assert!(
                    filter.is_none(),
                    "an absent filter means the table is empty"
                );
            }
            other => panic!("expected a guarded group, got {other:?}"),
        }
    }

    // A condition's filter is the schema's own rule tree, not a second language.
    #[test]
    fn a_condition_filter_is_an_access_rule() {
        let condition: Condition = serde_json::from_str(
            r#"{"kind":"exists","model":"Event","where":{"type":"compare","op":"eq",
                "left":{"kind":"column","name":"status"},
                "right":{"kind":"literal","value":"published"}}}"#,
        )
        .expect("parses");
        match condition {
            Condition::Exists {
                filter: Some(AccessRule::Compare { .. }),
                ..
            } => {}
            other => panic!("expected a compare filter, got {other:?}"),
        }
    }

    #[test]
    fn the_document_names_its_version() {
        let ir: SeedIr = serde_json::from_str(
            r#"{"irVersion":1,"schemaFingerprint":"sha256:abc","operations":[]}"#,
        )
        .expect("parses");
        assert_eq!(ir.ir_version, IR_VERSION);
        assert_eq!(ir.schema_fingerprint, "sha256:abc");
    }
}
