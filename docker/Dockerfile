# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Base builder image + cargo-chef
# ---------------------------------------------------------------------------
# cargo-chef splits the build so the *dependency* compile becomes a Docker layer
# keyed only on Cargo.toml/Cargo.lock. A source-only change then rebuilds just
# the ~dozen workspace crates instead of the ~500-crate dependency tree.
ARG RUST_IMAGE=rust:latest
FROM ${RUST_IMAGE} AS chef
# - protobuf-compiler: tonic-build
# - cmake, golang, build-essential, libclang-dev: boring-sys (BoringSSL bindings)
RUN apt-get update && apt-get install -y \
    protobuf-compiler cmake golang build-essential libclang-dev \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked --version ^0.1
WORKDIR /app

# ---------------------------------------------------------------------------
# Plan: capture the dependency graph
# ---------------------------------------------------------------------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
FROM chef AS builder

# false ⇒ production feature set; true ⇒ integration-test feature set.
ARG ENABLE_INTEGRATION_TEST=false
# bls12-381 (default) | jubjub
ARG CRYPTO_FEATURE=bls12-381
ARG BACKEND=cosmos
ARG BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${BUILD_JOBS}
# The two branches must use identical feature flags in `cook` and `build` or the
# cooked dependency artifacts don't match and get rebuilt.
RUN case "$BACKEND" in \
      cosmos) features="redb,authz-vera,bulletin-vera,iroh,${CRYPTO_FEATURE}"; \
        if [ "$ENABLE_INTEGRATION_TEST" = "true" ]; then features="redb,integration-test-cosmos,${CRYPTO_FEATURE}"; fi ;; \
      native) features="native,redb,iroh,${CRYPTO_FEATURE}"; \
        if [ "$ENABLE_INTEGRATION_TEST" = "true" ]; then features="$features,unsafe-testing"; fi ;; \
      *) echo 'Unsupported integration backend' >&2; exit 1 ;; \
    esac && printf '%s' "$features" > /orbis-features

# 1. Cook dependencies only — this layer is cached across builds whenever
#    Cargo.toml/Cargo.lock are unchanged. NB: no `target/` cache mount here;
#    a (CI-ephemeral) cache mount would shadow the cooked artifacts.
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json \
      --bin orbis-node --no-default-features --features "$(cat /orbis-features)"

# 2. Build the workspace against the cooked deps. Only this layer re-runs on a
#    source change, and it recompiles just the workspace crates.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo build --release --locked --bin orbis-node --no-default-features \
      --features "$(cat /orbis-features)" && \
    if [ "$BACKEND" = "native" ]; then \
      cargo tree --locked -p orbis-node --no-default-features --features "$(cat /orbis-features)" \
        --edges normal,build --prefix none > /native-dependencies.txt && \
      if grep -E '^(cosmrs|tendermint(-rpc|-config|-proto)?|cosmos-sdk-proto) v' /native-dependencies.txt; then exit 1; fi; \
    fi && cp /app/target/release/orbis-node /orbis-node-bin

# Reuse the normal native build's Cargo artifacts for the fault-report fixture.
FROM builder AS native-diagnostic-builder
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    test "$BACKEND" = "native" && test "$ENABLE_INTEGRATION_TEST" = "false" && \
    features="$(cat /orbis-features),unsafe-testing" && \
    cargo build --release --locked --bin orbis-node --no-default-features --features "$features" && \
    cargo tree --locked -p orbis-node --no-default-features --features "$features" \
      --edges normal,build --prefix none > /native-diagnostic-dependencies.txt && \
    if grep -E '^(cosmrs|tendermint(-rpc|-config|-proto)?|cosmos-sdk-proto) v' /native-diagnostic-dependencies.txt; then exit 1; fi && \
    cp /app/target/release/orbis-node /orbis-node-bin

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime-base

RUN apt-get update && apt-get install -y ca-certificates libstdc++6 netcat-openbsd && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir -p /data/dbs

EXPOSE 50051

ENTRYPOINT ["orbis-node"]

FROM runtime-base AS native-diagnostic
COPY --from=native-diagnostic-builder /orbis-node-bin /usr/local/bin/orbis-node

# Keep the normal runtime last so existing builds retain their default target.
FROM runtime-base AS runtime
COPY --from=builder /orbis-node-bin /usr/local/bin/orbis-node
