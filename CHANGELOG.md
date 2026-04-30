# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-05-01

### Added

#### MCP E-Commerce Flow (#21)

- Full cart-and-order MCP tool suite: `get_products`, `get_product`, `add_to_cart`, `get_cart`, `update_cart_item`, `remove_from_cart`, `create_order`, `get_order`, `process_payment`
- End-to-end checkout flow from product browsing to APC-encrypted payment

#### Merchant Abstraction Layer (#22)

- `MerchantApi` trait for pluggable merchant integrations
- `DefaultMerchant` with TOML-based configuration
- Field mapping for adapting non-standard merchant APIs (request/response key remapping)
- `examples/merchants/` with reference TOML configurations

#### Transport Abstraction Layer (#23)

- `HttpTransport` with `HttpConfig` (timeout, pool sizing, HTTP version selection)
- HTTP/1.1 and HTTP/2 support with multiplexing
- Hooks reserved for future HTTP/3, gRPC, and JSON-RPC transports

#### Subscription Management (#24)

- Recurring payment / subscription management primitives

#### CI/CD

- Dependabot auto-merge workflow for patch and minor dependency updates
- `softprops/action-gh-release` v3 (Node 24 runtime) for GitHub releases
- `dependabot/fetch-metadata` v3 (Node 24 runtime)
- `actions/checkout` v5 → v6, `actions/labeler` v5 → v6
- `docker/build-push-action` v6 → v7, `docker/setup-buildx-action` v3 → v4

### Changed

#### Dependencies

- `rmcp` 0.11 → 0.17 (multiple major bumps)
- `clap` 4.5 → 4.6
- `tempfile` 3.23 → 3.27
- `rust_decimal` 1.39 → 1.40
- `uuid` 1.19 → 1.22
- `jsonwebtoken` 10.2 → 10.3
- `schemars` 1.1 → 1.2
- `toml` 0.9 → 1.0
- `aws-lc-rs` 1.15 → 1.16
- Numerous transitive bumps across `tokio`, `serde`, `reqwest`, `hyper`, `rkyv`, `bytes`, and security-update groups

### Fixed

#### Security

- RUSTSEC-2026-0049 — `rustls-webpki` bumped to 0.103.13 (CRL distribution-point matching)
- GHSA-cq8v-f236-94qc — `rand` bumped to 0.9.4 (unsound `rand::rng()` with custom logger)
- `openssl` 0.10.77 → 0.10.78

## [0.2.0] - 2025-12-10

### Added

#### Phase 7: Enhanced Observability

- `Metrics` struct with atomic counters for Prometheus-format metrics
- `MetricsSnapshot` for point-in-time metrics capture
- `to_prometheus()` method for Prometheus text format export
- Request/response tracking for checkout, browse, verify operations
- Error categorization and counting by type
- Health check integration with metrics reporting

#### Phase 8: Reliability Patterns

- **Retry with exponential backoff** (`reliability::retry`)
  - `RetryPolicy` with configurable max attempts, delays, and multiplier
  - `retry_with_backoff()` async wrapper function
  - `is_retryable()` helper for error classification
  - Jitter support for thundering herd prevention
- **Circuit breaker** (`reliability::circuit_breaker`)
  - `CircuitBreaker` with three states: Closed, Open, HalfOpen
  - `CircuitBreakerConfig` with configurable thresholds
  - Automatic recovery with half-open probing
  - `CircuitBreakerError` for state-specific errors

#### Phase 9: Security Hardening

- **Token bucket rate limiting** (`security::rate_limit`)
  - `RateLimiter` with configurable RPS and burst size
  - `RateLimitedSigner` wrapper for `TapSigner`
  - Async `acquire()` and blocking `acquire_blocking()` methods
- **Structured audit logging** (`security::audit`)
  - `AuditEventType` enum for security events
  - `AuditEvent` with builder pattern and metadata
  - Sensitive data redaction (credit cards, CVV, SSN)
  - Tracing target "audit" for log filtering

#### New Error Variants

- `BridgeError::RateLimitExceeded` - Rate limit exceeded
- `BridgeError::CircuitOpen` - Circuit breaker is open

### Changed

#### Dependencies

- Upgraded `rmcp` from 0.10 to 0.11
- Reorganized workspace dependencies (versions in root, features in crates)
- Sorted all dependencies alphabetically

#### Documentation

- Updated README with production features section
- Added all 8 examples to README
- Updated lib.rs with new modules and test count (200+)
- Improved error handling documentation

### Fixed

- Removed redundant `Future` imports (Rust 2024 prelude)
- Fixed rmcp 0.11 compatibility (added `meta` field to `ListToolsResult`)

## [0.1.2] - 2025-12-08

### Changed

#### Dependencies

- Upgraded `rmcp` from 0.9.0 to 0.10.0
- Upgraded `criterion` from 0.7 to 0.8
- Upgraded `uuid` from 1.18 to 1.19
- Bumped security updates across 17 dependencies
- Centralized all dependency versions in workspace `Cargo.toml`
- Sorted dependencies alphabetically for better maintainability

#### CI/CD

- Added GitHub Actions labeler for automatic PR labeling
- Added release workflow for automated crates.io publishing on version tags
- Moved Miri to separate weekly workflow (reduces CI time)
- Upgraded `actions/checkout` from v5 to v6
- Upgraded `docker/build-push-action` from v5 to v6
- Removed sccache, simplified to Swatinem/rust-cache only
- Use nextest for Miri with 6 parallel jobs

#### Testing

- Skip OpenSSL-dependent tests under Miri (FFI limitation)

## [0.1.1] - 2025-11-20

### Added

#### TapVerifier Implementation

- `TapVerifier` for RFC 9421 HTTP Message Signatures verification
- Replay attack prevention using LRU-based nonce cache with 8-minute window
- Property-based testing with `proptest` for signature verification
- Clock skew tolerance (60 seconds) per RFC 9421 Section 2.3
- Comprehensive test coverage for verification logic (128 tests passing)

#### New Dependencies

- `lru` 0.16 - LRU cache for efficient replay protection
- `proptest` 1.9 - Property-based testing framework (dev dependency)

### Changed

#### Code Quality & Maintainability

- Extracted `TAP_MAX_VALIDITY_WINDOW_SECS` constant (480 seconds) for consistency
- Extracted `CLOCK_SKEW_TOLERANCE_SECS` constant (60 seconds) for RFC compliance
- Changed `build_signature_base` visibility to `pub(crate)` to keep API surface minimal
- Improved `Cargo.toml` formatting and dependency documentation

### Fixed

#### Security & Reliability

- Smart nonce cache eviction: expired nonces are now properly removed
- Prevents unbounded memory growth from stale cache entries
- Clock drift handling prevents false rejections due to time differences
- Fixed `clippy::string_slice` warning with safe UTF-8 string handling

### Documentation

- Added comprehensive API documentation for `TapVerifier`
- Documented replay protection strategy and clock skew tolerance
- Added examples for signature verification workflow
- Security considerations for production deployments

## [0.1.0] - 2025-11-18

### Added

#### Core TAP Protocol Implementation

- RFC 9421 HTTP Message Signatures with Ed25519
- JWK Thumbprints per RFC 7638
- Content-Digest computation per RFC 9530
- ID Token (JWT) generation for consumer authentication
- ACRO (Agentic Consumer Recognition Object) with contextual data
- APC (Agentic Payment Container) with JWE encryption (RFC 7516)
- Signature expiration (8-minute validity window)
- Replay protection via UUID v4 nonce

#### MCP Integration

- MCP tools: `checkout_with_tap`, `browse_merchant`, `verify_agent_identity`
- JSON-RPC 2.0 protocol support
- Stdio transport for MCP clients

#### MCP Server Binary (`tap-mcp-server`)

- Standalone binary for AI agent integration
- Environment-based configuration (TAP_AGENT_ID, TAP_AGENT_DIRECTORY, TAP_SIGNING_KEY)
- Graceful shutdown (SIGINT/SIGTERM)
- Comprehensive input validation with clear error messages

#### Observability (Phase 7)

- Structured logging (JSON and Pretty formats)
- Health check system via `verify_agent_identity` tool
- Request instrumentation with `#[instrument]` macros
- Log format configuration via LOG_FORMAT environment variable

#### Security

- Custom `Debug` implementations for payment data (PCI-DSS compliance)
- PAN masking (show only last 4 digits)
- CVV complete redaction
- Routing number redaction
- Account holder name redaction in examples
- CI workflow permissions (principle of least privilege)

#### Documentation

- Comprehensive README with Quick Start guide
- TAP Specification guide (`docs/TAP_SPECIFICATION.md`)
- MCP Integration guide (`docs/MCP_INTEGRATION.md`)
- Observability guide (`docs/OBSERVABILITY.md`)
- API documentation with examples

#### Testing

- 124 automated tests (unit, integration, binary configuration)
- 51 documentation tests
- Performance benchmarks with Criterion
- RFC test vectors validation (RFC 7638)

#### Development Infrastructure

- Cargo workspace structure (library + binary)
- cargo-make tasks for development workflow
- cargo-deny for security and license compliance
- GitHub Actions CI/CD pipeline
- sccache integration for faster builds

### Security

- PCI-DSS 3.2.1 compliant payment data handling
- GDPR-compliant PII redaction
- No sensitive data in logs or error messages
- HTTPS-only merchant URLs
- Input validation for consumer IDs and URLs

### Performance

- <0.1% overhead from observability instrumentation
- <1ms health check latency
- Sub-microsecond span creation
- JSON log formatting: 3.59 µs average

---

[Unreleased]: https://github.com/bug-ops/tap-mcp-bridge/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/bug-ops/tap-mcp-bridge/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/bug-ops/tap-mcp-bridge/releases/tag/v0.2.0
[0.1.2]: https://github.com/bug-ops/tap-mcp-bridge/releases/tag/v0.1.2
[0.1.1]: https://github.com/bug-ops/tap-mcp-bridge/releases/tag/v0.1.1
[0.1.0]: https://github.com/bug-ops/tap-mcp-bridge/releases/tag/v0.1.0
