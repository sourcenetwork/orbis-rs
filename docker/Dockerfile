# Build stage
FROM rust:1.85-bookworm AS builder

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

# Build release binary
RUN cargo build --release --bin orbis-node

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from builder
COPY --from=builder /app/target/release/orbis-node /usr/local/bin/orbis-node

# Expose default ports (adjust as needed)
EXPOSE 50051

ENTRYPOINT ["orbis-node"]
