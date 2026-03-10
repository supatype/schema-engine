// SQL generators depend on the differ crate (for DiffOutput) — not needed in WASM
#[cfg(not(target_arch = "wasm32"))]
pub mod sql;

pub mod typescript;
pub mod config;
pub mod studio;
pub mod openapi;
pub mod sdk;
