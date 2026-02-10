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

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY bin ./bin

# Build argument to conditionally enable integration-test feature
ARG ENABLE_INTEGRATION_TEST=false
# Build argument to select crypto implementation: bls12-381 (default) or decaf377
ARG CRYPTO_FEATURE=bls12-381

# Build release binary. With integration-test: use CRYPTO_FEATURE and no default features.
RUN if [ "$ENABLE_INTEGRATION_TEST" = "true" ]; then \
        cargo build --release --bin orbis-node --no-default-features \
            --features "redb,integration-test,${CRYPTO_FEATURE}"; \
    else \
        cargo build --release --bin orbis-node; \
    fi

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create data directory for database and keys
RUN mkdir -p /data/dbs

# Copy the compiled binary from builder
COPY --from=builder /app/target/release/orbis-node /usr/local/bin/orbis-node

# Expose default ports (adjust as needed)
EXPOSE 50051

ENTRYPOINT ["orbis-node"]
