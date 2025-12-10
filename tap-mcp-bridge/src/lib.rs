//! TAP-MCP Bridge: Secure AI Agent Authentication for E-Commerce
//!
//! A Rust library that bridges Visa's Trusted Agent Protocol (TAP) with
//! Anthropic's Model Context Protocol (MCP), enabling AI agents like Claude
//! to securely authenticate with merchants and execute payment transactions.
//!
//! # What is TAP-MCP Bridge?
//!
//! This library solves a critical problem: how can AI agents autonomously transact
//! with merchants while maintaining security and trust? TAP-MCP Bridge provides:
//!
//! - **Cryptographic Authentication**: RFC 9421 HTTP Message Signatures with Ed25519
//! - **MCP Integration**: Expose TAP operations as MCP tools for AI agents
//! - **Security by Default**: HTTPS-only, input validation, timeout protection
//! - **RFC Compliance**: Implements RFC 9421 (HTTP Signatures) and RFC 7638 (JWK Thumbprints)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐
//! │   AI Agent      │  Claude or other MCP-compatible agent
//! │   (Claude)      │
//! └────────┬────────┘
//!          │ MCP Protocol (JSON-RPC 2.0)
//!          │
//! ┌────────▼────────────────────────────────────────┐
//! │           TAP-MCP Bridge (this crate)           │
//! │  ┌──────────────┐      ┌──────────────────┐    │
//! │  │  MCP Tools   │──────│  TAP Signatures  │    │
//! │  │  (checkout,  │      │  (RFC 9421 +     │    │
//! │  │   browse)    │      │   Ed25519)       │    │
//! │  └──────────────┘      └──────────────────┘    │
//! └────────┬───────────────────────────────────────┘
//!          │ HTTPS + TAP Signatures
//!          │
//! ┌────────▼────────┐
//! │  TAP Merchant   │  Visa-protected merchant
//! │  (e.g., Store)  │
//! └─────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ## 1. Execute a Checkout
//!
//! ```rust,no_run
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::{
//!     mcp::{CheckoutParams, checkout_with_tap},
//!     tap::TapSigner,
//! };
//!
//! # async fn example() -> tap_mcp_bridge::error::Result<()> {
//! // Create agent signing key (in production, load from secure storage)
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
//!
//! // Define checkout parameters
//! let params = CheckoutParams {
//!     merchant_url: "https://merchant.example.com/checkout".to_string(),
//!     consumer_id: "user-456".to_string(),
//!     intent: "payment".to_string(),
//!     country_code: "US".to_string(),
//!     zip: "94025".to_string(),
//!     ip_address: "192.168.1.100".to_string(),
//!     user_agent: "Mozilla/5.0".to_string(),
//!     platform: "macOS".to_string(),
//! };
//!
//! // Execute TAP-authenticated checkout
//! let result = checkout_with_tap(&signer, params).await?;
//!
//! println!("Status: {}", result.status);
//! println!("Message: {}", result.message);
//! # Ok(())
//! # }
//! ```
//!
//! ## 2. Browse Merchant Catalog
//!
//! ```rust,no_run
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::{
//!     mcp::{BrowseParams, browse_merchant},
//!     tap::TapSigner,
//! };
//!
//! # async fn example() -> tap_mcp_bridge::error::Result<()> {
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
//!
//! let params = BrowseParams {
//!     merchant_url: "https://merchant.example.com".to_string(),
//!     consumer_id: "user-456".to_string(),
//!     country_code: "US".to_string(),
//!     zip: "94025".to_string(),
//!     ip_address: "192.168.1.100".to_string(),
//!     user_agent: "Mozilla/5.0".to_string(),
//!     platform: "macOS".to_string(),
//! };
//!
//! let result = browse_merchant(&signer, params).await?;
//! println!("Status: {}", result.status);
//! println!("Data: {}", result.data);
//! # Ok(())
//! # }
//! ```
//!
//! ## 3. Generate TAP Signatures Directly
//!
//! ```rust
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::tap::{InteractionType, TapSigner};
//!
//! # fn example() -> tap_mcp_bridge::error::Result<()> {
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent-directory.example.com");
//!
//! // Sign an HTTP request per RFC 9421 with TAP parameters
//! let signature = signer.sign_request(
//!     "POST",
//!     "merchant.example.com",
//!     "/api/checkout",
//!     b"{\"amount\":99.99}",
//!     InteractionType::Checkout,
//! )?;
//!
//! // Use signature headers in HTTP request
//! println!("Signature: {}", signature.signature);
//! println!("Signature-Input: {}", signature.signature_input);
//! println!("Signature-Agent: {}", signature.agent_directory);
//! println!("Nonce: {}", signature.nonce);
//! # Ok(())
//! # }
//! ```
//!
//! ## 4. Generate JWKS for Agent Directory
//!
//! ```rust
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::tap::TapSigner;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
//!
//! // Generate JWKS for public key distribution
//! let jwks = signer.generate_jwks();
//! let json = jwks.to_json()?;
//!
//! // Serve this at /.well-known/http-message-signatures-directory
//! println!("{}", json);
//! # Ok(())
//! # }
//! ```
//!
//! # Module Organization
//!
//! - [`tap`]: TAP protocol implementation (RFC 9421 signatures, Ed25519 signing)
//! - [`mcp`]: MCP tools for AI agent integration (checkout, browse)
//! - [`transport`]: Transport protocol abstraction (HTTP/1.1, HTTP/2, future: HTTP/3, gRPC)
//! - [`error`]: Error types with recovery guidance
//! - [`reliability`]: Production reliability patterns (retry, circuit breaker)
//! - [`security`]: Security hardening (rate limiting, audit logging)
//!
//! # Security Considerations
//!
//! ## Key Management
//!
//! - **Never hardcode keys**: Load from environment variables or secure key stores
//! - **Use HSM in production**: Hardware Security Modules for key protection
//! - **Unique keys per merchant**: Recommended for key rotation and isolation
//!
//! ## Input Validation
//!
//! The library automatically validates:
//! - **URLs**: Must be HTTPS, no localhost/loopback addresses
//! - **Consumer IDs**: Alphanumeric + hyphens/underscores, 1-64 characters
//! - **Request bodies**: Content-Digest prevents tampering
//!
//! ## Network Security
//!
//! - **HTTPS only**: All TAP requests require TLS encryption
//! - **30-second timeout**: Prevents hanging connections
//! - **Signature expiration**: Requests expire after 8 minutes (TAP requirement)
//! - **Replay attack prevention**: Unique nonce (UUID v4) per request
//! - **Nonce tracking**: Merchants must reject duplicate nonces within 8-minute window
//!
//! # Standards Compliance
//!
//! This library implements:
//! - [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
//! - [RFC 7638: JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)
//! - [RFC 3986: URI Syntax](https://www.rfc-editor.org/rfc/rfc3986.html)
//!
//! # Features
//!
//! This implementation provides complete TAP protocol compliance:
//!
//! **Core Capabilities**:
//! - ✅ Two MCP tools: `checkout_with_tap`, `browse_merchant`
//! - ✅ RFC 9421 signature generation with Ed25519
//! - ✅ TAP required parameters: `tag`, `nonce`, `expires`, `created`, `keyid`, `alg`
//! - ✅ Replay attack prevention (unique nonce per request)
//! - ✅ Signature expiration (8-minute maximum window)
//! - ✅ Interaction type tags (browser-auth, payer-auth)
//! - ✅ Network error handling with 30-second timeout
//! - ✅ Input validation (URL sanitization, consumer ID format)
//!
//! **TAP Components**:
//! - ✅ RFC 9421 HTTP Message Signatures with Ed25519
//! - ✅ Public Key Directory (JWKS at `/.well-known/http-message-signatures-directory`)
//! - ✅ ID Token (JWT) generation for consumer authentication
//! - ✅ Agentic Consumer Recognition Object (ACRO)
//! - ✅ Agentic Payment Container (APC)
//!
//! **Production Features**:
//! - ✅ Prometheus-format metrics (`observability` module in tap-mcp-server)
//! - ✅ Retry with exponential backoff (`reliability::retry`)
//! - ✅ Circuit breaker pattern (`reliability::circuit_breaker`)
//! - ✅ Token bucket rate limiting (`security::rate_limit`)
//! - ✅ Structured audit logging (`security::audit`)
//!
//! **TAP Compliance**: 100% (18/18 requirements)
//!
//! **Test Coverage**: 200+ tests (unit, integration, property-based, documentation)
//!
//! # Examples
//!
//! See the `examples/` directory for complete usage examples:
//! - `basic_checkout.rs`: Simple checkout flow
//! - `browse_catalog.rs`: Browsing merchant catalogs
//! - `error_handling.rs`: Handling common errors
//! - `signature_generation.rs`: RFC 9421 signature generation
//! - `jwks_generation.rs`: Generating JWKS for agent directory
//! - `id_token_generation.rs`: JWT token creation
//! - `acro_generation.rs`: ACRO object creation
//! - `apc_generation.rs`: APC encryption/decryption
//!
//! # Error Handling
//!
//! All operations return [`Result<T, BridgeError>`](error::Result). Errors include
//! recovery guidance:
//!
//! ```rust
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::{
//!     BridgeError,
//!     mcp::{CheckoutParams, checkout_with_tap},
//!     tap::TapSigner,
//! };
//!
//! # async fn example() {
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
//!
//! let params = CheckoutParams {
//!     merchant_url: "https://merchant.example.com/checkout".to_string(),
//!     consumer_id: "user-123".to_string(),
//!     intent: "payment".to_string(),
//!     country_code: "US".to_string(),
//!     zip: "94025".to_string(),
//!     ip_address: "192.168.1.100".to_string(),
//!     user_agent: "Mozilla/5.0".to_string(),
//!     platform: "macOS".to_string(),
//! };
//!
//! match checkout_with_tap(&signer, params).await {
//!     Ok(result) => println!("Success: {}", result.status),
//!     Err(BridgeError::InvalidMerchantUrl(msg)) => {
//!         eprintln!("Invalid URL: {}", msg);
//!         // Fix URL and retry
//!     }
//!     Err(BridgeError::HttpError(e)) => {
//!         eprintln!("Network error: {}", e);
//!         // Retry with exponential backoff using reliability::retry_with_backoff
//!     }
//!     Err(BridgeError::RateLimitExceeded) => {
//!         eprintln!("Rate limit exceeded");
//!         // Wait and retry after backoff
//!     }
//!     Err(BridgeError::CircuitOpen) => {
//!         eprintln!("Circuit breaker is open");
//!         // Wait for circuit recovery
//!     }
//!     Err(e) => eprintln!("Other error: {}", e),
//! }
//! # }
//! ```

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "transitive dependencies from rmcp and reqwest"
)]

pub mod error;
pub mod mcp;
pub mod merchant;
pub mod reliability;
pub mod security;
pub mod tap;
pub mod transport;

pub use error::{BridgeError, Result};
pub use merchant::{DefaultMerchant, MerchantApi, MerchantConfig};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_exports() {
        // Verify public API is accessible
        let _ = std::marker::PhantomData::<BridgeError>;
    }
}
