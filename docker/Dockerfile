# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Base builder image + cargo-chef
# ---------------------------------------------------------------------------
# cargo-chef splits the build so the *dependency* compile becomes a Docker layer
# keyed only on Cargo.toml/Cargo.lock. A source-only change then rebuilds just
# the ~dozen workspace crates instead of the ~500-crate dependency tree.
FROM rust:latest AS chef
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
# bls12-381 (default) | decaf377
ARG CRYPTO_FEATURE=bls12-381
# The two branches must use identical feature flags in `cook` and `build` or the
# cooked dependency artifacts don't match and get rebuilt.
ENV ORBIS_FEATURES_PROD="redb,authz-vera,bulletin-vera,iroh,${CRYPTO_FEATURE}"
ENV ORBIS_FEATURES_INTEG="redb,integration-test,${CRYPTO_FEATURE}"

# 1. Cook dependencies only — this layer is cached across builds whenever
#    Cargo.toml/Cargo.lock are unchanged. NB: no `target/` cache mount here;
#    a (CI-ephemeral) cache mount would shadow the cooked artifacts.
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    if [ "$ENABLE_INTEGRATION_TEST" = "true" ]; then \
        cargo chef cook --release --recipe-path recipe.json \
            --bin orbis-node --no-default-features --features "$ORBIS_FEATURES_INTEG"; \
    else \
        cargo chef cook --release --recipe-path recipe.json \
            --bin orbis-node --no-default-features --features "$ORBIS_FEATURES_PROD"; \
    fi

# 2. Build the workspace against the cooked deps. Only this layer re-runs on a
#    source change, and it recompiles just the workspace crates.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    if [ "$ENABLE_INTEGRATION_TEST" = "true" ]; then \
        cargo build --release --bin orbis-node --no-default-features --features "$ORBIS_FEATURES_INTEG"; \
    else \
        cargo build --release --bin orbis-node --no-default-features --features "$ORBIS_FEATURES_PROD"; \
    fi && \
    cp /app/target/release/orbis-node /orbis-node-bin

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN mkdir -p /data/dbs

COPY --from=builder /orbis-node-bin /usr/local/bin/orbis-node

EXPOSE 50051

ENTRYPOINT ["orbis-node"]
