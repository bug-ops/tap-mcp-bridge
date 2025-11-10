# GitHub Copilot Instructions for tap-mcp-bridge

## Project Overview

**tap-mcp-bridge** is a Rust library (Edition 2024) that bridges Visa's Trusted Agent Protocol (TAP) with Anthropic's Model Context Protocol (MCP), enabling AI agents to securely authenticate with TAP-protected merchants.

**Current Status**: Production-ready with 100% TAP compliance (18/18 requirements)

## Core Development Philosophy

### Compact Solutions Only
- Implement minimal functionality to validate hypotheses
- No convenience features, syntactic sugar, or "nice-to-have" additions
- Every feature must directly test a core assumption
- Defer optimization and abstraction
- MVP mindset: ship smallest working solution

### Language Requirements
- All code, documentation, comments, and commit messages MUST be in English
- No co-authorship attribution in commit messages

### Guidelines Compliance
- Follow Microsoft Rust Guidelines: https://microsoft.github.io/rust-guidelines/agents/all.txt
- Follow Rust API Guidelines: https://rust-lang.github.io/api-guidelines/

## Type System & API Design

### Strong Types Over Primitives
```rust
// Good: Strong types
pub struct AgentId(String);
pub struct MerchantUrl(Url);

// Bad: Primitive types
pub fn checkout(agent_id: String, merchant_url: String) -> Result<()>
```

### Hide Complexity
```rust
// Good: Clean API exposing &T, &mut T, or T
pub struct TapSigner {
    signing_key: SigningKey, // Internal Arc hidden
}

// Bad: Infectious complexity
pub struct TapSigner {
    signing_key: Arc<SigningKey>,
}
```

### Type Hierarchy for Dependencies
1. Concrete Types (preferred)
2. Generics (when multiple concrete types needed)
3. `dyn Trait` (only when absolutely necessary)

### Avoid Weasel Words
No "Service", "Manager", "Helper", "Utility" in type names. Use descriptive, domain-specific names.

## Error Handling

### Use thiserror for Library Errors
```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("TAP signature generation failed: {0}")]
    SignatureError(String),

    #[error("MCP protocol error: {0}")]
    McpError(#[from] rmcp::Error),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, BridgeError>;
```

### Error Handling Principles
- **Never panic for recoverable errors** - panics indicate programming errors only
- Implement `Display` and `std::error::Error` for all error types
- Include backtraces and upstream causes
- Redact sensitive data from error messages
- Valid panic reasons: programming errors, const contexts, poisoned locks

## Soundness & Unsafe Code

### Unsafe Code Rules
- Only use `unsafe` when absolutely necessary (novel abstractions, FFI, performance-critical)
- All `unsafe` blocks MUST include plain-text safety reasoning
- Unsound code is NEVER acceptable
- All unsafe code MUST pass Miri validation: `cargo +nightly miri test`

```rust
// Good: Documented safety reasoning
unsafe {
    // SAFETY: The pointer is guaranteed to be valid because we allocated
    // it above and haven't freed it yet. The alignment is correct because
    // we used Layout::new::<T>(). The size is correct for the same reason.
    ptr::write(ptr, value);
}
```

## Testing Strategy

### MVP Testing Approach
- Happy path only: One integration test proving end-to-end flow
- Critical failures: Test signature generation correctness (security risk)
- Defer edge cases, error branches, property tests until core value proven
- No mocks until multiple implementations exist
- Doc tests only for public APIs that stabilize

### Test Execution
```bash
# Use nextest for faster, more reliable tests
cargo nextest run

# Run doc tests separately
cargo test --doc --all-features
```

## Security Requirements

### Secrets Management
- Never log or expose private keys
- Redact sensitive data from error messages and logs
- Use `secrecy::Secret` for in-memory secrets (when implemented)

### Input Validation
```rust
// Good: Validate and sanitize
pub fn checkout(merchant_url: &str) -> Result<()> {
    let url = Url::parse(merchant_url)?;
    if url.scheme() != "https" {
        return Err(BridgeError::InvalidMerchantUrl("must use HTTPS".into()));
    }
    // ...
}
```

### Signature Generation
- Use Ed25519 for TAP signatures (RFC 9421)
- Include required components: `@method`, `@authority`, `@path`, `content-digest`
- Compute JWK thumbprints per RFC 7638
- Add `Signature-Agent` header with agent directory URL

## Development Workflow

### Pre-Commit Checks
1. `cargo +nightly fmt` - Format code (uses nightly)
2. `cargo clippy -- -D warnings` - No clippy warnings
3. `cargo nextest run` - All tests pass
4. `cargo deny check` - No security vulnerabilities, license issues
5. `cargo +nightly miri test` - Unsafe code validated (if applicable)

### Code Quality Tools
```bash
# Format (enforced, uses nightly)
cargo +nightly fmt

# Lint
cargo clippy -- -D warnings

# Test
cargo nextest run

# Security checks
cargo deny check
cargo audit

# Check unused dependencies
cargo udeps

# Feature combinations
cargo hack check --feature-powerset

# Validate unsafe code
cargo +nightly miri test
```

## Module Organization

### Start Minimal
```
src/
├── lib.rs              # Public API surface
├── error.rs            # Error types (add variants as needed)
├── tap/                # TAP protocol (implement only what's needed)
│   ├── mod.rs
│   └── signer.rs       # RFC 9421 signature generation
└── mcp/                # MCP server (minimal tool set)
    ├── mod.rs
    └── tools.rs        # Single critical tool first
```

### Growth Principle
- Start with single-file modules
- Split only when >500 lines or clear boundary emerges
- Extract traits only when multiple implementations emerge

## Documentation Standards

### Public API Documentation
```rust
/// Generates RFC 9421 HTTP Message Signature for TAP request.
///
/// Creates an Ed25519 signature over HTTP request components
/// including method, authority, path, and content digest.
///
/// # Examples
///
/// use tap_mcp_bridge::TapSigner;
///
/// let signer = TapSigner::new(signing_key, "agent-123");
/// let signature = signer.sign_request(&request)?;
///
/// # Errors
///
/// Returns `BridgeError::SignatureError` if signing fails.
pub fn sign_request(&self, request: &HttpRequest) -> Result<TapSignature> {
    // Implementation
}
```

### Documentation Requirements
- First sentence MUST be one-line summary (≤15 words)
- Provide comprehensive examples for all public APIs
- Document all error conditions
- Include plain-text safety reasoning for unsafe code

## Common Anti-Patterns

### Avoid
```rust
// Bad: Primitive types
fn process(id: String, url: String) -> Result<()>

// Bad: Weasel words
struct PaymentService { }
struct RequestHelper { }

// Bad: Infectious complexity
pub fn checkout(signer: Arc<Mutex<TapSigner>>) -> Result<()>

// Bad: Premature abstraction
trait Signer {
    fn sign(&self, data: &[u8]) -> Result<Signature>;
}

// Bad: Undocumented unsafe
unsafe { ptr::write(ptr, value); }
```

### Prefer
```rust
// Good: Strong types
struct AgentId(String);
struct MerchantUrl(Url);
fn process(id: AgentId, url: MerchantUrl) -> Result<()>

// Good: Domain-specific names
struct TapSigner { }
struct CheckoutRequest { }

// Good: Clean API
pub fn checkout(signer: &TapSigner) -> Result<()>

// Good: Concrete implementation first
struct Ed25519Signer {
    signing_key: SigningKey,
}

// Good: Documented unsafe with reasoning
unsafe {
    // SAFETY: Pointer is valid because...
    ptr::write(ptr, value);
}
```

## Performance Guidelines

### MVP Approach
- Ignore performance until it becomes a validated problem
- No premature optimization
- No benchmarking infrastructure until bottleneck identified
- Simple, readable code over clever optimizations

### When Performance Matters
- Profile first: `cargo build --timings`
- Optimize identified bottlenecks only
- Add benchmarks for critical paths

## Logging and Observability

### MVP Logging
```rust
// Basic logging only
use tracing::{info, error};

info!("Generating TAP signature for agent {}", agent_id);
error!("Signature generation failed: {}", err);
```

### Defer
- Metrics, spans, OpenTelemetry integration
- Log aggregation
- Performance monitoring

## Dependency Strategy

### Current Dependencies
- `rmcp` - MCP Server implementation
- `ed25519-dalek` - Ed25519 signing
- `sha2` - Content-Digest, JWK thumbprints
- `reqwest` - HTTP Client
- `tokio` - Async Runtime
- `serde`, `serde_json` - Serialization
- `thiserror` - Error Handling
- `tracing` - Logging
- `jsonwebtoken` - JWT/JWK support for TAP
- `secrecy` - Sensitive data handling for ACRO/APC
- `hex` - SHA-256 hash encoding
- `zeroize` - Memory zeroization (PCI-DSS compliance)

### Selection Criteria
1. Actively maintained (last commit <6 months)
2. Well-documented
3. Widely used (>100k downloads preferred)
4. Clean `cargo audit`
5. Compatible license (MIT, Apache-2.0, BSD)
6. Minimal dependency tree

## Project-Specific Context

### TAP Protocol
- Authentication via RFC 9421 HTTP Message Signatures
- Ed25519 signatures on HTTP requests
- Required headers: `Signature`, `Signature-Input`, `Signature-Agent`
- Parameters: `consumer_id`, `intent`, `location` (query params)

### MCP Integration
- Expose TAP operations as MCP tools
- JSON-RPC 2.0 over stdio/HTTP
- Implements: `checkout_with_tap`, `browse_merchant`

### Security-Critical Components
1. **TapSigner** - RFC 9421 signature generation (core security risk)
2. **Agent Registry** - Public key management
3. **Input validation** - Sanitize merchant URLs, consumer IDs

## Resources

- **Microsoft Rust Guidelines**: https://microsoft.github.io/rust-guidelines/agents/all.txt
- **Rust API Guidelines**: https://rust-lang.github.io/api-guidelines/
- **RFC 9421 (HTTP Message Signatures)**: https://www.rfc-editor.org/rfc/rfc9421.html
- **RFC 7638 (JWK Thumbprint)**: https://www.rfc-editor.org/rfc/rfc7638.html
- **Edition 2024 Guide**: https://doc.rust-lang.org/edition-guide/rust-2024/

## Summary for AI Assistants

When assisting with tap-mcp-bridge:

1. **Minimal viable solutions only** - no convenience features
2. **Strong types over primitives** - use newtype wrappers
3. **English only** - all text in English
4. **Error handling with thiserror** - contextual error variants
5. **Document unsafe code** - plain-text safety reasoning required
6. **Test with nextest** - `cargo nextest run`
7. **Security first** - validate inputs, redact secrets, cryptographic correctness
8. **Defer complexity** - concrete implementations before abstractions
9. **Follow Microsoft Rust Guidelines** - soundness and idiomatic patterns
10. **MVP mindset** - ship smallest working solution
