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
    cargo build --release --bin supatype-engine-server --bin supatype-engine 2>/dev/null || true

# What the binaries report as their version (build.rs). There is no .git in this context, so the
# caller names the build: the release workflow passes SUPATYPE_ENGINE_RELEASE (the crate version),
# and any other build passes SUPATYPE_ENGINE_BUILD_SHA (its commit) to report <next minor>-dev+<sha>.
# Declared after the dependency layer so a new commit does not rebuild every dependency.
ARG SUPATYPE_ENGINE_RELEASE=""
ARG SUPATYPE_ENGINE_BUILD_SHA=""

# Copy real source and build
COPY src/ src/
RUN cargo build --release --bin supatype-engine-server --bin supatype-engine

# ── Runtime ──────────────────────────────────────────────────────────────────

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/supatype-engine-server /usr/local/bin/
COPY --from=builder /app/target/release/supatype-engine /usr/local/bin/

EXPOSE 7500

ENV ENGINE_PORT=7500
ENV ENGINE_BIND=127.0.0.1
ENV RUST_LOG=info

ENTRYPOINT ["supatype-engine-server"]
