FROM rust:1-bookworm AS builder

WORKDIR /app

# Copy manifests and build script first for layer caching
COPY Cargo.toml Cargo.lock build.rs ./

# Create dummy src to cache dependency compilation
RUN mkdir src && \
    echo "pub mod generator; pub mod licensing; pub mod parser; pub mod wasm; pub mod differ; pub mod introspector; pub mod state; pub mod server;" > src/lib.rs && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/server_main.rs && \
    mkdir -p src/generator src/licensing src/parser src/server src/differ src/introspector src/state && \
    touch src/generator/mod.rs src/licensing/mod.rs src/parser/mod.rs src/wasm.rs src/server/mod.rs src/differ/mod.rs src/introspector/mod.rs src/state/mod.rs && \
    cargo build --release --bin supatype-engine-server 2>/dev/null || true

# Copy real source and build
COPY src/ src/
RUN cargo build --release --bin supatype-engine-server

# ── Runtime ──────────────────────────────────────────────────────────────────

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/supatype-engine-server /usr/local/bin/

EXPOSE 7500

ENV ENGINE_PORT=7500
ENV RUST_LOG=info

ENTRYPOINT ["supatype-engine-server"]
