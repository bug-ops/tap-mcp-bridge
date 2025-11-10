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
//! use tap_mcp_bridge::tap::TapSigner;
//!
//! # fn example() -> tap_mcp_bridge::error::Result<()> {
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent-directory.example.com");
//!
//! // Sign an HTTP request per RFC 9421
//! let signature = signer.sign_request(
//!     "POST",
//!     "merchant.example.com",
//!     "/api/checkout",
//!     b"{\"amount\":99.99}",
//! )?;
//!
//! // Use signature headers in HTTP request
//! println!("Signature: {}", signature.signature);
//! println!("Signature-Input: {}", signature.signature_input);
//! println!("Signature-Agent: {}", signature.agent_directory);
//! # Ok(())
//! # }
//! ```
//!
//! # Module Organization
//!
//! - [`tap`]: TAP protocol implementation (RFC 9421 signatures, Ed25519 signing)
//! - [`mcp`]: MCP tools for AI agent integration (checkout, browse)
//! - [`error`]: Error types with recovery guidance
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
//! - **Signature timestamps**: Included in signatures to aid replay detection
//!
//! # Standards Compliance
//!
//! This library implements:
//! - [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
//! - [RFC 7638: JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html)
//! - [RFC 3986: URI Syntax](https://www.rfc-editor.org/rfc/rfc3986.html)
//!
//! # Current Status: Phase 2 - Core Validation
//!
//! This implementation provides core functionality to validate pattern reuse
//! and basic security measures:
//!
//! **Features**:
//! - ✅ Two MCP tools: `checkout_with_tap`, `browse_merchant`
//! - ✅ RFC 9421 signature generation with Ed25519
//! - ✅ Network error handling with 30-second timeout
//! - ✅ Input validation (URL sanitization, consumer ID format)
//! - ✅ Comprehensive test suite (39 tests)
//!
//! **Future Phases**:
//! - Phase 3: Production readiness (replay protection, circuit breakers, metrics)
//! - Phase 4: Production deployment (monitoring, alerts, runbooks)
//!
//! # Examples
//!
//! See the `examples/` directory for complete usage examples:
//! - `basic_checkout.rs`: Simple checkout flow
//! - `error_handling.rs`: Handling common errors
//! - `multi_merchant.rs`: Working with multiple merchants
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
//!         // Retry with exponential backoff
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
pub mod tap;

pub use error::{BridgeError, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_exports() {
        // Verify public API is accessible
        let _ = std::marker::PhantomData::<BridgeError>;
    }
}
