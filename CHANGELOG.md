# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [Unreleased]

### Planned
- Phase 8: Reliability Patterns (retry, circuit breaker)
- Phase 9: Security Hardening
- Phase 10: Performance Optimization

---

[0.1.0]: https://github.com/bug-ops/tap-mcp-bridge/releases/tag/v0.1.0
[Unreleased]: https://github.com/bug-ops/tap-mcp-bridge/compare/v0.1.0...HEAD
