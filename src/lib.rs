// Library root — exposes all modules so the engine logic can be reused
// in future WASM builds without the CLI layer.

pub mod parser;
pub mod introspector;
pub mod differ;
pub mod generator;
pub mod state;
pub mod licensing;
