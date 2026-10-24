//! A raw `$sql` statement's parameters, bound by their JSON type.
//!
//! Each value binds as the Postgres type its JSON shape names: a string as `text`, a whole
//! number as `bigint`, any other number as `double precision`, a boolean as `boolean`, and
//! an object or array as `jsonb`. A statement that needs another type casts the
//! placeholder, as in `$1::uuid`. A `null` declares no type at all, so Postgres takes the
//! one the statement implies and a null fits any column.

use super::{reference_parts, Value};
use crate::parser::ast::Operand;
use sqlx::encode::IsNull;
use sqlx::error::BoxDynError;
use sqlx::postgres::types::Oid;
use sqlx::postgres::{PgArgumentBuffer, PgArguments, PgTypeInfo, Postgres};
use std::collections::HashMap;

/// A statement with its parameters bound, ready to run.
pub type BoundQuery<'q> = sqlx::query::Query<'q, Postgres, PgArguments>;

/// Columns earlier statements read back, by the label of the write that read them, then by
/// the column's name as Postgres keeps it. `None` is a column that holds NULL.
pub type Resolved = HashMap<String, HashMap<String, Option<String>>>;

/// One parameter, in the type it binds as.
#[derive(Debug, Clone, PartialEq)]
enum Param {
    Null,
    Text(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Json(serde_json::Value),
}

/// A `NULL` whose type Postgres infers from the statement.
///
/// Declared with OID 0, which the protocol reads as "unspecified". A typed null would
/// make `INSERT INTO t (n) VALUES ($1)` fail on an integer column with "expression is of
/// type text", although nothing about a null is text.
struct UntypedNull;

impl sqlx::Type<Postgres> for UntypedNull {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_oid(Oid(0))
    }
}

impl sqlx::Encode<'_, Postgres> for UntypedNull {
    fn encode_by_ref(&self, _buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        Ok(IsNull::Yes)
    }
}

/// `text` with every one of `params` bound, or why one of them cannot be.
///
/// Never cached as a prepared statement: the types are the params' rather than the
/// statement's, so the same text run again with a `null` where a number was would meet a
/// statement prepared for the number.
pub fn bind_all<'q>(
    text: &'q str,
    params: &[Value],
    resolved: &Resolved,
) -> Result<BoundQuery<'q>, String> {
    params.iter().enumerate().try_fold(
        sqlx::query(text).persistent(false),
        |query, (position, value)| {
            let param = param_for(value, resolved)
                .map_err(|reason| format!("parameter ${} {reason}", position + 1))?;
            Ok(bind(query, param))
        },
    )
}

fn bind(query: BoundQuery<'_>, param: Param) -> BoundQuery<'_> {
    match param {
        Param::Null => query.bind(UntypedNull),
        Param::Text(text) => query.bind(text),
        Param::Int(number) => query.bind(number),
        Param::Float(number) => query.bind(number),
        Param::Bool(flag) => query.bind(flag),
        Param::Json(json) => query.bind(sqlx::types::Json(json)),
    }
}

/// The parameter one IR value binds as.
///
/// A `$numeric` binds as text: it exists to keep a decimal exact, and a double would not.
fn param_for(value: &Value, resolved: &Resolved) -> Result<Param, String> {
    match value {
        Value::Scalar(scalar) => Ok(from_json(scalar)),
        Value::Numeric { numeric } => Ok(Param::Text(numeric.clone())),
        Value::Operand(Operand::Literal { value }) => serde_json::to_value(value)
            .map(|json| from_json(&json))
            .map_err(|e| format!("could not be read: {e}")),
        Value::Ref { reference } => {
            resolve(reference, resolved).map(|column| column.map_or(Param::Null, Param::Text))
        }
        _ => Err("is not a value a placeholder can carry".to_string()),
    }
}

fn from_json(json: &serde_json::Value) -> Param {
    match json {
        serde_json::Value::Null => Param::Null,
        serde_json::Value::Bool(flag) => Param::Bool(*flag),
        serde_json::Value::Number(number) => match (number.as_i64(), number.as_f64()) {
            (Some(whole), _) => Param::Int(whole),
            (None, Some(fraction)) => Param::Float(fraction),
            (None, None) => Param::Text(number.to_string()),
        },
        serde_json::Value::String(text) => Param::Text(text.clone()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => Param::Json(json.clone()),
    }
}

/// The column a `$ref` names, which an earlier write in the same run read back.
pub fn resolve(reference: &str, resolved: &Resolved) -> Result<Option<String>, String> {
    reference_parts(reference)
        .and_then(|(label, column)| resolved.get(label)?.get(&column))
        .cloned()
        .ok_or_else(|| format!("references `{reference}`, which no earlier write produced"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(json: &str) -> Value {
        serde_json::from_str(json).unwrap_or_else(|e| panic!("{json} did not parse: {e}"))
    }

    fn param(json: &str) -> Param {
        param_for(&value(json), &Resolved::new()).expect("binds")
    }

    #[test]
    fn each_json_shape_binds_as_its_own_type() {
        assert_eq!(param(r#""news""#), Param::Text("news".into()));
        assert_eq!(param("42"), Param::Int(42));
        assert_eq!(param("-7"), Param::Int(-7));
        assert_eq!(param("2.5"), Param::Float(2.5));
        assert_eq!(param("true"), Param::Bool(true));
        assert_eq!(param("null"), Param::Null);
        assert_eq!(
            param(r#"[1, "a"]"#),
            Param::Json(serde_json::json!([1, "a"]))
        );
        assert_eq!(
            param(r#"{"k": 1}"#),
            Param::Json(serde_json::json!({"k": 1}))
        );
    }

    #[test]
    fn a_number_too_large_for_bigint_binds_as_a_double() {
        assert_eq!(
            param("18446744073709551615"),
            Param::Float(18_446_744_073_709_551_615.0)
        );
    }

    #[test]
    fn a_numeric_binds_as_its_exact_text() {
        assert_eq!(
            param(r#"{"$numeric": "75.0010"}"#),
            Param::Text("75.0010".into())
        );
    }

    #[test]
    fn a_ref_binds_the_id_an_earlier_write_returned() {
        let mut resolved = Resolved::new();
        resolved.insert(
            "post".into(),
            HashMap::from([("id".into(), Some("abc".into()))]),
        );
        let bound = param_for(&value(r#"{"$ref": "post.id"}"#), &resolved);
        assert_eq!(bound, Ok(Param::Text("abc".into())));
    }

    #[test]
    fn a_ref_to_any_column_binds_what_was_read_back() {
        let mut resolved = Resolved::new();
        resolved.insert(
            "alex".into(),
            HashMap::from([("slug".into(), Some("alex".into())), ("bio".into(), None)]),
        );
        let slug = param_for(&value(r#"{"$ref": "alex.slug"}"#), &resolved);
        assert_eq!(slug, Ok(Param::Text("alex".into())));
        let bio = param_for(&value(r#"{"$ref": "alex.bio"}"#), &resolved);
        assert_eq!(bio, Ok(Param::Null), "a column holding NULL binds NULL");
    }

    #[test]
    fn an_unresolved_ref_names_itself() {
        let error = param_for(&value(r#"{"$ref": "nope.id"}"#), &Resolved::new())
            .expect_err("nothing produced it");
        assert!(error.contains("`nope.id`"), "{error}");
    }

    #[test]
    fn a_default_cannot_be_bound() {
        let error = param_for(&value(r#"{"$default": true}"#), &Resolved::new())
            .expect_err("a default is not a value");
        assert!(error.contains("placeholder"), "{error}");
    }
}
