pub mod dart;
pub mod go;
pub mod kotlin;
pub mod php;
pub mod python;
pub mod swift;

use crate::parser::ast::SchemaAst;
use anyhow::{anyhow, Result};

/// What an array column's elements are, for choosing a language's element type.
///
/// Decided in one place so no language can map an element differently from the single value of
/// the same Postgres type: BIGINT elements are 64-bit integers and NUMERIC, DECIMAL and MONEY
/// elements are exact decimals, as the single `bigInt`, `decimal` and `money` kinds are. A
/// precision or a spelling (`NUMERIC(19,4)`, `int8`) does not change the choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArrayElement {
    Int32,
    BigInt,
    Float,
    Decimal,
    Bool,
    Text,
}

pub(crate) fn array_element(element_type: &str) -> ArrayElement {
    let lowered = element_type.to_lowercase();
    let base = lowered.split('(').next().unwrap_or("").trim();
    match base {
        "integer" | "int" | "int4" | "smallint" | "int2" | "serial" | "serial4" => {
            ArrayElement::Int32
        }
        "bigint" | "int8" | "bigserial" | "serial8" => ArrayElement::BigInt,
        "float" | "float8" | "float4" | "real" | "double precision" => ArrayElement::Float,
        "numeric" | "decimal" | "money" => ArrayElement::Decimal,
        "boolean" | "bool" => ArrayElement::Bool,
        _ => ArrayElement::Text,
    }
}

pub fn generate(ast: &SchemaAst, lang: &str) -> Result<String> {
    match lang {
        "python" => python::generate(ast),
        "go" => go::generate(ast),
        "php" => php::generate(ast),
        "swift" => swift::generate(ast),
        "kotlin" => kotlin::generate(ast),
        "dart" => dart::generate(ast),
        other => Err(anyhow!(
            "Unknown SDK language '{}'. Supported: python, go, php, swift, kotlin, dart",
            other
        )),
    }
}
