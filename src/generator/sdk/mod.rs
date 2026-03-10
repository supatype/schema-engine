pub mod python;
pub mod go;
pub mod php;
pub mod swift;
pub mod kotlin;
pub mod dart;

use anyhow::{anyhow, Result};
use crate::parser::ast::SchemaAst;

pub fn generate(ast: &SchemaAst, lang: &str) -> Result<String> {
    match lang {
        "python" => python::generate(ast),
        "go"     => go::generate(ast),
        "php"    => php::generate(ast),
        "swift"  => swift::generate(ast),
        "kotlin" => kotlin::generate(ast),
        "dart"   => dart::generate(ast),
        other    => Err(anyhow!("Unknown SDK language '{}'. Supported: python, go, php, swift, kotlin, dart", other)),
    }
}
