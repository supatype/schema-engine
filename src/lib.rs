// Library root — exposes all modules so the engine logic can be reused
// in WASM builds and tests without the CLI layer.
//
// Modules that depend on sqlx/tokio (introspector, state, differ) are gated
// from the wasm32 target so the library can be compiled to WASM cleanly.

pub mod parser;
pub mod generator;
pub mod licensing;
pub mod wasm;

// DB-dependent modules — not needed in WASM context
#[cfg(not(target_arch = "wasm32"))]
pub mod introspector;
#[cfg(not(target_arch = "wasm32"))]
pub mod state;
#[cfg(not(target_arch = "wasm32"))]
pub mod differ;
