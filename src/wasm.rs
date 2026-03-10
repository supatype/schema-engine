/// WASM entry points for supatype-engine.
///
/// Each function is annotated with `#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]`
/// so it compiles to a wasm_bindgen export when targeting WASM, and is a plain Rust
/// function in all other contexts (unit tests, native CLI).
///
/// All functions follow a JSON-in / string-out convention compatible with both the
/// browser (JS interop) and the CLI (stdin/stdout).

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::parser::parse;
use crate::generator::{typescript, openapi, sdk};

/// Parse a JSON SchemaAst and return the resolved AST back as JSON.
/// Returns an error JSON string `{"error": "..."}` on failure.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn wasm_parse(input: &str) -> String {
    match parse(input) {
        Ok(ast) => serde_json::to_string(&ast).unwrap_or_else(|e| error_json(&e.to_string())),
        Err(e) => error_json(&e.to_string()),
    }
}

/// Parse a JSON SchemaAst and generate TypeScript type definitions.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn wasm_generate_typescript(input: &str) -> String {
    match parse(input) {
        Ok(ast) => typescript::types::generate(&ast)
            .unwrap_or_else(|e| error_json(&e.to_string())),
        Err(e) => error_json(&e.to_string()),
    }
}

/// Parse a JSON SchemaAst and generate an OpenAPI 3.0 specification as JSON.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn wasm_generate_openapi(input: &str) -> String {
    match parse(input) {
        Ok(ast) => openapi::generate(&ast)
            .and_then(|v| Ok(serde_json::to_string_pretty(&v)?))
            .unwrap_or_else(|e| error_json(&e.to_string())),
        Err(e) => error_json(&e.to_string()),
    }
}

/// Parse a JSON SchemaAst and generate a typed SDK for the given language.
/// `lang` must be one of: python, go, php, swift, kotlin, dart.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn wasm_generate_sdk(input: &str, lang: &str) -> String {
    match parse(input) {
        Ok(ast) => sdk::generate(&ast, lang)
            .unwrap_or_else(|e| error_json(&e.to_string())),
        Err(e) => error_json(&e.to_string()),
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn error_json(msg: &str) -> String {
    format!("{{\"error\":{}}}", serde_json::to_string(msg).unwrap_or_else(|_| "\"unknown error\"".into()))
}
