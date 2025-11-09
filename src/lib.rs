//! TAP-MCP Bridge Library
//!
//! A bridge library that integrates Visa's Trusted Agent Protocol (TAP)
//! with Anthropic's Model Context Protocol (MCP), enabling AI agents
//! to securely authenticate with TAP-protected merchants.
//!
//! # Overview
//!
//! This library provides cryptographic signature generation per RFC 9421
//! HTTP Message Signatures using Ed25519, enabling AI agents to execute
//! authenticated payment transactions via MCP tools.
//!
//! # Phase 1: MVP
//!
//! The current implementation provides minimal functionality to validate
//! the TAP-MCP integration hypothesis:
//!
//! - Single MCP tool: `checkout_with_tap`
//! - RFC 9421 signature generation with Ed25519
//! - Basic error handling
//!
//! # Examples
//!
//! ```no_run
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::{
//!     mcp::{CheckoutParams, checkout_with_tap},
//!     tap::TapSigner,
//! };
//!
//! # async fn example() -> tap_mcp_bridge::error::Result<()> {
//! // Create agent signing key
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//!
//! // Create TAP signer
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
//!
//! // Execute checkout
//! let params = CheckoutParams {
//!     merchant_url: "https://merchant.com".into(),
//!     consumer_id: "user-123".into(),
//!     intent: "payment".into(),
//! };
//!
//! let result = checkout_with_tap(&signer, params).await?;
//! # Ok(())
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
        let _error_type: std::marker::PhantomData<BridgeError> = std::marker::PhantomData;
    }
}
