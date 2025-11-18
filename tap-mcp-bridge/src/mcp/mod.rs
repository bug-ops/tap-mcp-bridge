//! Model Context Protocol (MCP) integration.
//!
//! This module implements MCP tools that expose TAP operations to AI agents.
//! The MCP layer handles tool registration, parameter validation, and response formatting.
//!
//! # Available Tools
//!
//! - [`checkout_with_tap`]: Execute a payment checkout with TAP authentication
//! - [`browse_merchant`]: Browse merchant catalog with verified agent identity
//!
//! # Architecture
//!
//! ```text
//! AI Agent (Claude)
//!     │
//!     │ MCP Protocol (JSON-RPC 2.0)
//!     ▼
//! MCP Tools (this module)
//!     │
//!     │ Parameters validation
//!     ▼
//! TAP Client (tap module)
//!     │
//!     │ RFC 9421 signatures
//!     ▼
//! Merchant (HTTPS)
//! ```
//!
//! # Examples
//!
//! ```rust,no_run
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::{
//!     mcp::{CheckoutParams, checkout_with_tap},
//!     tap::TapSigner,
//! };
//!
//! # async fn example() -> tap_mcp_bridge::error::Result<()> {
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
//! let result = checkout_with_tap(&signer, params).await?;
//! println!("Status: {}", result.status);
//! # Ok(())
//! # }
//! ```

pub mod tools;

pub use tools::{
    BrowseParams, BrowseResult, CheckoutParams, CheckoutResult, browse_merchant, checkout_with_tap,
};
