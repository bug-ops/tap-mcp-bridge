# TAP-MCP Bridge

A Rust library that bridges Visa's Trusted Agent Protocol (TAP) with Anthropic's Model Context Protocol (MCP), enabling AI agents like Claude to securely authenticate with merchants and execute payment transactions.

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://www.rust-lang.org)

## Overview

The TAP-MCP Bridge acts as a protocol adapter, translating between:

- **MCP layer**: Application-layer tool calls (JSON-RPC 2.0 over stdio/HTTP)
- **TAP layer**: Transport-layer cryptographic authentication (RFC 9421 HTTP Message Signatures)

This enables AI agents to:
- Authenticate with TAP-protected merchants using cryptographic signatures
- Execute secure payment transactions on behalf of consumers
- Browse merchant catalogs with verified agent identity
- Maintain session state across multi-step interactions

## Architecture

```
┌─────────────────┐
│   AI Agent      │  Claude or other MCP-compatible agent
│   (Claude)      │
└────────┬────────┘
         │ MCP Protocol (JSON-RPC 2.0)
         │
┌────────▼──────────────────────────────────────┐
│           TAP-MCP Bridge (this crate)         │
│  ┌──────────────┐      ┌──────────────────┐   │
│  │  MCP Tools   │──────│  TAP Signatures  │   │
│  │  (checkout,  │      │  (RFC 9421 +     │   │
│  │   browse)    │      │   Ed25519)       │   │
│  └──────────────┘      └──────────────────┘   │
└────────┬──────────────────────────────────────┘
         │ HTTPS + Cryptographic Signatures
         │
┌────────▼────────┐
│  TAP Merchant   │  E-commerce merchant with TAP support
└─────────────────┘
```

### Key Components

1. **MCP Server Wrapper** - Exposes TAP operations as MCP tools (`checkout_with_tap`, `browse_merchant`, `verify_agent_identity`)
2. **Protocol Adapter** - Translates MCP tool calls to TAP requests and converts responses
3. **TAP Client** - Generates RFC 9421 HTTP Message Signatures using Ed25519, manages agent identity
4. **Session Manager** - Tracks merchant interactions, payment contexts, handles error recovery

## Features

- **TAP Protocol Compliance**: Implements Visa's Trusted Agent Protocol specification
- **Cryptographic Authentication**: Ed25519 signatures per RFC 9421 HTTP Message Signatures
- **Replay Attack Prevention**: Unique nonce (UUID v4) generation per request
- **Signature Expiration**: 8-minute maximum validity window (TAP requirement)
- **Interaction Type Tags**: Automatic `agent-browser-auth` and `agent-payer-auth` handling
- **JWK Thumbprints**: RFC 7638 compliant agent identity verification
- **Async/Await**: Built on Tokio for efficient concurrent operations
- **Type Safety**: Strong typing with comprehensive error handling via `thiserror`
- **Comprehensive Documentation**: Rustdoc with examples for all public APIs
- **Security First**: Input validation, HTTPS-only, secure key management

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
tap-mcp-bridge = "0.1.0"
```

## Quick Start

### Basic Checkout

```rust
use ed25519_dalek::SigningKey;
use tap_mcp_bridge::{
    mcp::{checkout_with_tap, CheckoutParams},
    tap::TapSigner,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize TAP signer with agent credentials
    let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    let signer = TapSigner::new(
        signing_key,
        "agent-123",
        "https://agent.example.com"
    );

    // Configure checkout parameters
    let params = CheckoutParams {
        merchant_url: "https://merchant.example.com".to_string(),
        consumer_id: "user-456".to_string(),
        intent: "payment".to_string(),
    };

    // Execute checkout with TAP authentication
    let result = checkout_with_tap(&signer, params).await?;
    println!("Status: {}", result.status);

    Ok(())
}
```

### Browse Merchant Catalog

```rust
use tap_mcp_bridge::{
    mcp::{browse_merchant, BrowseParams},
    tap::TapSigner,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = TapSigner::new(/* ... */);

    let params = BrowseParams {
        merchant_url: "https://merchant.example.com".to_string(),
        consumer_id: "user-456".to_string(),
    };

    let result = browse_merchant(&signer, params).await?;
    println!("Catalog: {}", result.data);

    Ok(())
}
```

## Examples

The [`examples/`](examples/) directory contains complete working examples:

- **[basic_checkout.rs](examples/basic_checkout.rs)** - Simple checkout flow with error handling
- **[browse_catalog.rs](examples/browse_catalog.rs)** - Browsing multiple merchant catalogs
- **[error_handling.rs](examples/error_handling.rs)** - Comprehensive error recovery strategies
- **[signature_generation.rs](examples/signature_generation.rs)** - Low-level TAP signature generation

Run examples with:

```bash
cargo run --example basic_checkout
cargo run --example browse_catalog
cargo run --example error_handling
cargo run --example signature_generation
```

## Documentation

Generate and view the full API documentation:

```bash
cargo doc --no-deps --all-features --open
```

Key documentation sections:

- **[Main Library Docs](src/lib.rs)** - Architecture overview and integration guide
- **[Error Types](src/error.rs)** - All error variants with recovery strategies
- **[MCP Integration](src/mcp/mod.rs)** - MCP protocol implementation details
- **[TAP Protocol](src/tap/mod.rs)** - TAP signature generation and verification

## Development

### Prerequisites

- Rust 1.75+ (Edition 2024)
- Cargo
- Optional: `cargo-make`, `cargo-nextest`, `cargo-deny`

### Setup

```bash
# Clone the repository
git clone https://github.com/example/tap-mcp-bridge.git
cd tap-mcp-bridge

# Install development tools (optional but recommended)
cargo install cargo-make cargo-nextest cargo-deny
```

### Common Commands

**Using cargo-make** (recommended):

```bash
# Quick pre-commit checks (format, clippy, test, deny)
cargo make pre-commit

# Full verification suite
cargo make verify

# Complete verification including security checks
cargo make verify-all

# Individual tasks
cargo make format        # Format code with nightly rustfmt
cargo make clippy        # Run clippy with strict warnings
cargo make test          # Run tests with nextest
cargo make doc-open      # Build and open documentation
```

**Direct cargo commands**:

```bash
# Build the library
cargo build

# Run tests
cargo nextest run --all-features

# Check code quality
cargo clippy --all-targets --all-features -- -D warnings

# Format code
cargo +nightly fmt --all

# Security checks
cargo deny check
```

### Testing

```bash
# Run all tests with nextest (fast, parallel)
cargo nextest run

# Run doc tests
cargo test --doc

# Build and run all examples
cargo build --examples
```

### Code Quality

This project follows the [Microsoft Rust Guidelines](https://microsoft.github.io/rust-guidelines/) for soundness and idiomatic design.

Key principles:
- **Unsafe code is strictly regulated** - Only when absolutely necessary, with plain-text safety reasoning
- **Strong types over primitives** - Domain-specific types instead of strings/numbers
- **Comprehensive error handling** - Context-rich errors with recovery guidance
- **API Guidelines compliance** - Following [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)

## Security Considerations

This library handles sensitive payment data and cryptographic operations:

1. **Secrets Management**: Never log or expose private keys
2. **Input Validation**: All merchant URLs and consumer IDs are validated
3. **Replay Attack Prevention**: Unique nonce per request, merchants must track duplicates
4. **Signature Expiration**: Requests expire after 8 minutes (TAP requirement)
5. **Timestamp Validation**: Both `created` and `expires` parameters enforce time windows
6. **Signature Generation**: Ed25519 signatures with RFC 9421 and TAP compliance
7. **HTTPS Only**: All requests validated to use HTTPS, no localhost allowed

### TAP Protocol Compliance

**Current Implementation** (Phase 2):
- ✅ RFC 9421 HTTP Message Signatures with Ed25519
- ✅ Interaction type tags (`agent-browser-auth`, `agent-payer-auth`)
- ✅ Unique nonce generation (UUID v4) for replay protection
- ✅ Signature expiration (`created` + 480 seconds max)
- ✅ JWK Thumbprint key identifiers (RFC 7638)
- ⏳ Agentic Consumer Recognition Object (planned Phase 3)
- ⏳ Agentic Payment Container (planned Phase 3)

**Compliance Score**: 14/18 requirements (78%)

## Project Status

**Current Phase**: Phase 2 (Core Validation) - TAP Compliance Complete

- ✅ Phase 1: MVP with basic TAP signature generation
- ✅ Phase 2: Core validation with error handling and multiple tools
- ✅ TAP Compliance: Critical security parameters (tag, nonce, expires) implemented
- 🔄 Stabilization: API documentation ✅, usage examples ✅, test coverage in progress
- ⏳ Phase 3: Production readiness (Agentic Consumer/Payment objects, full TAP spec)

**Latest Updates**:
- **2025-11-10**: Implemented critical TAP specification parameters (tag, nonce, expires)
- **2025-11-10**: Added comprehensive API documentation and 4 usage examples
- **2025-11-10**: TAP compliance improved from 61% to 78% (14/18 requirements)

## Contributing

Contributions are welcome! Before contributing:

1. Review the project architecture in the [library documentation](src/lib.rs)
2. Ensure all tests pass: `cargo nextest run`
3. Run code quality checks: `cargo clippy -- -D warnings`
4. Format code: `cargo +nightly fmt`
5. Run security checks: `cargo deny check`

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Resources

- **[TAP Specification](https://developer.visa.com/capabilities/trusted-agent-protocol/trusted-agent-protocol-specifications)**: Visa's Trusted Agent Protocol
- **[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)**: HTTP Message Signatures
- **[RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html)**: JWK Thumbprint
- **[MCP Documentation](https://modelcontextprotocol.io/)**: Anthropic's Model Context Protocol
- **[Microsoft Rust Guidelines](https://microsoft.github.io/rust-guidelines/)**: Rust best practices for soundness
