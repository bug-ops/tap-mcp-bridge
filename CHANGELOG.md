# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `TAP_ALLOW_LOOPBACK=1` developer escape hatch in `parse_merchant_url`: when set, the function accepts `http://localhost`, `http://127.0.0.1`, and their `https` counterparts so wiremock-style harnesses can drive the full request-response loop end to end. The override is scoped to loopback hosts — non-loopback `http://` URLs are still rejected — and is documented as dev-only; it must never be set in production (#126)
- `tap::jwe` module — JWE compact serialization (RFC 7516) implemented directly on top of `aws-lc-rs`: `RSA-OAEP-256` key wrap from `aws_lc_rs::rsa::OaepPublicEncryptingKey` and `A256GCM` content encryption from `aws_lc_rs::aead`. `RsaPublicKey` lives in this module and continues to be re-exported from `tap::apc` for source-compatible callers (#129)

### Changed

- Drop `josekit` and the entire OpenSSL stack (`openssl`, `openssl-sys`, `openssl-src`, `openssl-macros`, `openssl-probe`) from the `tap-mcp-bridge` dependency graph. Payment-data JWE encryption now runs against the same `aws-lc-rs` backend `jsonwebtoken` already uses, removing the only call site that pulled OpenSSL into the build. Cold builds drop ~30s on Linux/macOS and significantly more on Windows where vendored OpenSSL was previously unavoidable. The `[target.'cfg(windows)'.dependencies]` `josekit` `vendored` override is gone, and CI no longer needs `OPENSSL_DIR=$(brew --prefix openssl@3)` on macOS (#129)
- **Breaking:** `RsaPublicKey::from_pem` now accepts only X.509 `SubjectPublicKeyInfo` PEM (`-----BEGIN PUBLIC KEY-----`). PKCS#1 (`-----BEGIN RSA PUBLIC KEY-----`) and other headers are rejected with a clear error. `josekit`'s implicit dual-format acceptance was undocumented and unused inside this workspace — TAP and the example fixtures all use SPKI (#129)
- CI overhaul (`.github/workflows/ci.yml`): unified test build via `cargo nextest archive` (built once with `sccache`, replayed by the `test` matrix from the uploaded artifact); added a `coverage` job using `cargo-llvm-cov nextest` with Codecov upload on master pushes; dropped the dedicated release-build job — only debug builds remain. `Swatinem/rust-cache` is now per-job (`ci-check`, `ci-deny`, `ci-msrv`, `ci-features`, `ci-udeps`, `ci-build-${os}`, `ci-coverage`) and runs with `cache-targets: false` on sccache-enabled jobs to keep the two caches from clashing on `target/`.
- New `[profile.ci]` (inherits `dev`, `debug = 0`, `codegen-units = 16`) and `.github/nextest.toml` (`ci`, `ci-partition` profiles with slow-test surfacing) drive the archive workflow.
- Docker job (`docker-build-and-scan`) reuses the `tap-mcp-server` binary produced by `build-tests` instead of rebuilding from source. New `docker/Dockerfile` is a runtime-only image (Ubuntu 24.04 to match the GHA runner glibc) that copies the prebuilt binary; the legacy root-level multi-stage `Dockerfile` is kept for ad-hoc end-to-end builds. Trivy now scans the built image and uploads SARIF findings to the GitHub Security tab (CRITICAL/HIGH severities).
- `josekit` `vendored` feature is now scoped to Windows only (`[target.'cfg(windows)'.dependencies]`). On Linux/macOS the crate links against system OpenSSL (libssl-dev preinstalled on `ubuntu-latest`; `OPENSSL_DIR=$(brew --prefix openssl@3)` set by CI on `macos-latest`), avoiding the ~50 second cold `openssl-src` compile that previously dominated the build profile.
- `build-tests` and `coverage` jobs now install the `mold` linker on Linux via `rui314/setup-mold@v1`, shaving a few seconds off the final link step for binaries and tests.
- `tap-mcp-server` production binary is now built by a dedicated `build-binary` job (Linux only) instead of an in-matrix conditional step, keeping the matrix uniform across OSes. `docker-build-and-scan` consumes its `tap-mcp-server-binary` artifact; both jobs run in parallel against shared sccache.

### Fixed

- All MCP tool functions that embed a caller-supplied id field into a URL path (`update_cart_item`, `remove_from_cart`, `get_product`, `get_order`, `get_subscription_plan`, `get_subscription`, `update_subscription`, `cancel_subscription`, `pause_subscription`, `resume_subscription`, `report_usage`, `get_usage`, `update_payment_method`, `preview_proration`) now validate the id at entry through a new `validate_path_id` helper (ASCII alphanumeric, `-`, `_`, max 64 chars — same allowlist as `validate_consumer_id` and the typed `SubscriptionId`/`PlanId` constructors). Previously the id was concatenated verbatim via `format!("/.../{id}")`, and any value containing `..` segments caused the wire path produced by `reqwest`/`url::Url` to collapse to an arbitrary endpoint while the RFC 9421 signature was bound to the original verbatim `@path`. Strict (RFC 9421 §2.2.6 conformant) merchants rejected the divergent signature, breaking legitimate calls; loose merchants executed the request against the collapsed path, exposing the bridge as an oracle for caller-controlled endpoint targeting via 14 distinct tool surfaces. As defense in depth, `execute_tap_request_with_acro` and `execute_tap_request_with_custom_nonce` now reject any request path whose path component contains `.` or `..` segments before signing — future code paths bypassing the entry-point validation cannot reintroduce the gap (#142)
- `process_payment_rate_limited` now enforces the per-consumer scope its docs always claimed. The previous implementation kept a single process-global `RateLimiter` behind a static `Mutex<Option<Arc<RateLimiter>>>` and ignored `params.consumer_id` entirely, so any one caller draining the bucket denied service to every other consumer in the same process — a multi-tenant DoS surface. The static is replaced by a new `KeyedRateLimiter` (in `security::rate_limit`) that maintains an independent token bucket per `consumer_id` inside an LRU map bounded at 10 000 keys; eviction is acceptable since the evicted bucket is simply re-created full on next use. Doc comments on both `process_payment_rate_limited` and the static now describe the actual configuration (1 req/sec, burst 3) instead of the old, never-implemented "5 per minute". A regression test in `mcp::payment` drives the production static with two distinct `consumer_id`s and asserts that exhausting one does not throttle the other (#140)
- `update_cart_item` and `remove_from_cart` silently dropped the required `cart_id` parameter: the field was declared on `UpdateCartItemParams`/`RemoveFromCartParams` and advertised as required in the MCP `tools/list` schema, but the value never reached the merchant. Both functions now append `cart_id` to the query string alongside `consumer_id`, mirroring the `get_cart` convention; the `#[instrument]` field list is updated accordingly so traces capture cart context. Multi-cart-per-consumer flows are now disambiguated on the wire (#131)
- Restore source-declaration key order for every `serde_json::json!{}` call site by enabling `serde_json/preserve_order` at the workspace level. PR #130 silently dropped the `preserve_order` feature when it removed `josekit` (whose dep tree had transitively activated it via `indexmap`), causing `verify_agent_identity` MCP responses, `PaymentMethod::to_json` plaintext (which is encrypted into the APC), and any other `json!{}` output to switch to `BTreeMap`-backed alphabetical ordering. The change is invisible to RFC-8259 JSON parsers but shifts the ciphertext bytes downstream consumers may have built snapshots/hashes around. Regression tests now pin the byte layout of `HealthReport::to_json` and all `PaymentMethod::to_json` variants (#138)
- `tap-mcp-server` exited immediately after responding to `initialize`, dropping every subsequent request. Under rmcp 1.5, `Service::serve(transport)` resolves at initialization and returns a `RunningService` whose background task drives the request loop; the server now awaits `RunningService::waiting()` so the connection lives for its full lifetime (#118)
- Merchant request URLs no longer contain a duplicated separator (`https://host//checkout`) when the configured `merchant_url` has no trailing slash. `Url::Display` always emits a trailing `/` for an origin with an empty path, and the previous `format!("{url}{path}")` concatenation produced the wrong wire path on every checkout/browse call. The wire path now matches the `@path` value used to build the RFC 9421 signature base, fixing verification against strict merchants. Introduces `compose_request_url` which preserves the base URL's path prefix and ensures exactly one slash between segments (#116)
- `tap-mcp-server` advertised itself as `rmcp/1.5.0` in the `initialize` response because rmcp's default `Implementation::from_build_env` captures `env!("CARGO_*")` inside the rmcp crate. `ServerHandler::get_info` is now overridden on `TapMcpServer` to return `tap-mcp-server` and the workspace version, giving MCP clients the correct identity (#117)
- `verify_agent_identity` was uncallable from any MCP client. `Parameters<()>` made rmcp publish the input schema as `{"type":"null"}`, but rmcp 1.5's dispatcher feeds `{}` to the deserializer regardless of the client-sent argument shape, so `{}`, `null`, and omitted-arguments all failed with `-32602 invalid type: map, expected unit`. The tool now uses an empty `EmptyRequest` struct, producing `{"type":"object","properties":{}}` which deserializes happily from `{}` (#120)

### Added

- `tap-mcp-server` now exposes the full e-commerce flow as MCP tools, mirroring the library's public functions: `get_products`, `get_product`, `add_to_cart`, `get_cart`, `update_cart_item`, `remove_from_cart`, `create_order`, `get_order`, `process_payment`. Together with the existing `checkout_with_tap`, `browse_merchant`, `verify_agent_identity` the server now lists 12 tools (#121)

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
