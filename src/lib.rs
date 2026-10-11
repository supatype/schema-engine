// Library root: exposes all modules so the engine logic can be reused
// in WASM builds and tests without the CLI layer.
//
// Modules that depend on sqlx/tokio (introspector, state, differ) are gated
// from the wasm32 target so the library can be compiled to WASM cleanly.

pub mod capabilities;
pub mod generator;
pub mod licensing;
pub mod parser;
pub mod seed;
pub mod wasm;

pub mod managed;
pub mod sql_quote;

// DB-dependent modules, not needed in WASM context
#[cfg(not(target_arch = "wasm32"))]
pub mod adopt;
#[cfg(not(target_arch = "wasm32"))]
pub mod desired;
#[cfg(not(target_arch = "wasm32"))]
pub mod differ;
#[cfg(not(target_arch = "wasm32"))]
pub mod inspect;
#[cfg(not(target_arch = "wasm32"))]
pub mod introspector;
#[cfg(not(target_arch = "wasm32"))]
pub mod ledger;
#[cfg(not(target_arch = "wasm32"))]
pub mod legacy_names;
#[cfg(not(target_arch = "wasm32"))]
pub mod push;
#[cfg(not(target_arch = "wasm32"))]
pub mod state;

// HTTP server module, only used by the server binary, not WASM
#[cfg(not(target_arch = "wasm32"))]
pub mod server;
