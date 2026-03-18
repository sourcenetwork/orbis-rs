# syntax=docker/dockerfile:1

# Build stage
FROM rust:latest AS builder

# Install build dependencies
# - protobuf-compiler: required for tonic-build
# - cmake, golang, build-essential, libclang-dev: required for boring-sys (BoringSSL bindings)
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    cmake \
    golang \
    build-essential \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy all workspace source in one layer so that any change — whether in
# crates/ or bin/ — invalidates this layer atomically. Splitting into
# separate COPY layers risks pairing a cached (stale) crates layer with a
# fresh bin layer, which confuses cargo's incremental compilation. See
# .dockerignore for what is excluded (target/, .git/, etc.).
COPY . .

# Build argument to conditionally enable integration-test feature
ARG ENABLE_INTEGRATION_TEST=false
# Build argument to select crypto implementation: bls12-381 (default) or decaf377
ARG CRYPTO_FEATURE=bls12-381

# Build release binary, using BuildKit cache mounts so that incremental rebuilds
# only recompile changed files rather than the entire workspace from scratch.
# The cargo registry cache persists downloaded crates across builds.
# The target cache persists compiled artifacts so only changed crates are recompiled.
# The binary is copied to /orbis-node-bin before the RUN layer exits because cache
# mounts are not accessible to COPY --from=builder in the next stage.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    if [ "$ENABLE_INTEGRATION_TEST" = "true" ]; then \
        cargo build --release --bin orbis-node --no-default-features \
            --features "redb,integration-test,${CRYPTO_FEATURE}"; \
    else \
        cargo build --release --bin orbis-node; \
    fi && \
    cp /app/target/release/orbis-node /orbis-node-bin

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create data directory for database and keys
RUN mkdir -p /data/dbs

# Copy the compiled binary from builder
COPY --from=builder /orbis-node-bin /usr/local/bin/orbis-node

# Expose default ports (adjust as needed)
EXPOSE 50051

ENTRYPOINT ["orbis-node"]
