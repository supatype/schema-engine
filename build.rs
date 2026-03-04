fn main() {
    // Embed version and build metadata into the binary at compile time.
    println!(
        "cargo:rustc-env=ENGINE_VERSION={}",
        std::env::var("CARGO_PKG_VERSION").unwrap()
    );
    println!(
        "cargo:rustc-env=BUILD_TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );
}
