# Runtime-only image — expects the tap-mcp-server binary to be staged into the
# build context (e.g. by CI after a `cargo nextest archive` run). The base
# image matches the ubuntu-latest GHA runner glibc to avoid loader mismatches.
FROM ubuntu:24.04

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG BINARY_PATH=tap-mcp-server
COPY ${BINARY_PATH} /usr/local/bin/tap-mcp-server
RUN chmod +x /usr/local/bin/tap-mcp-server

# Ubuntu 24.04 ships a default `ubuntu` user at UID 1000 — drop it and reuse
# UID 1000 for the app user so volume permissions stay predictable.
RUN userdel -r ubuntu 2>/dev/null || true \
    && useradd -m -u 1000 -U appuser \
    && chown -R appuser:appuser /app

USER appuser

ENV RUST_LOG=info

CMD ["tap-mcp-server"]
