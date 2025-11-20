ARG RUST_VERSION=1.91.1
# Build stage
FROM rust:${RUST_VERSION}-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    perl \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY tap-mcp-bridge/Cargo.toml tap-mcp-bridge/Cargo.toml
COPY tap-mcp-server/Cargo.toml tap-mcp-server/Cargo.toml

# Create dummy source files to build dependencies
RUN mkdir -p tap-mcp-bridge/src tap-mcp-bridge/benches && \
    echo "pub fn dummy() {}" > tap-mcp-bridge/src/lib.rs && \
    echo "fn main() {}" > tap-mcp-bridge/benches/observability_overhead.rs && \
    mkdir -p tap-mcp-server/src && \
    echo "fn main() {}" > tap-mcp-server/src/main.rs

# Build dependencies
RUN cargo build --release --bin tap-mcp-server

# Remove dummy files
RUN rm -rf tap-mcp-bridge/src tap-mcp-bridge/benches tap-mcp-server/src

# Copy actual source code
COPY tap-mcp-bridge/src tap-mcp-bridge/src
COPY tap-mcp-bridge/benches tap-mcp-bridge/benches
COPY tap-mcp-server/src tap-mcp-server/src

# Build the actual application
# Touch main.rs and lib.rs to force rebuild
RUN touch tap-mcp-server/src/main.rs tap-mcp-bridge/src/lib.rs && \
    cargo build --release --bin tap-mcp-server

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/tap-mcp-server /usr/local/bin/tap-mcp-server

# Create non-root user
RUN useradd -m -u 1000 -U appuser && \
    chown -R appuser:appuser /app

USER appuser

# Expose stdio (not network port as this is an MCP server over stdio)
# But we might want to expose a port if we add HTTP transport later
# EXPOSE 8080

# Set environment variables
ENV RUST_LOG=info

# Run the server
CMD ["tap-mcp-server"]
