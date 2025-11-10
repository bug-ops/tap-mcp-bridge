//! Trusted Agent Protocol (TAP) implementation.
//!
//! This module implements Visa's Trusted Agent Protocol, which enables AI agents
//! to securely authenticate with merchants using cryptographic signatures.
//!
//! # Protocol Overview
//!
//! TAP uses [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
//! with Ed25519 keys to authenticate requests. Each request includes:
//!
//! - **Signature**: Base64-encoded Ed25519 signature
//! - **Signature-Input**: Metadata about signed components and parameters
//! - **Signature-Agent**: URL of agent directory (for public key discovery)
//! - **Content-Digest**: SHA-256 hash of request body
//!
//! # Key Components
//!
//! - [`TapSigner`]: Generates RFC 9421 signatures for HTTP requests
//! - [`TapSignature`](signer::TapSignature): Signature output (headers ready for HTTP)
//!
//! # Signature Components
//!
//! Per TAP specification, signatures cover these components:
//! - `@method`: HTTP method (e.g., POST, GET)
//! - `@authority`: Target merchant domain
//! - `@path`: Request path
//! - `content-digest`: SHA-256 hash of request body
//!
//! # Examples
//!
//! ## Basic Signature Generation
//!
//! ```rust
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::tap::TapSigner;
//!
//! # fn example() -> tap_mcp_bridge::error::Result<()> {
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
//!
//! let signature = signer.sign_request("POST", "merchant.com", "/checkout", b"request body")?;
//!
//! println!("Signature: {}", signature.signature);
//! println!("Signature-Input: {}", signature.signature_input);
//! # Ok(())
//! # }
//! ```
//!
//! ## JWK Thumbprint Computation
//!
//! TAP uses [RFC 7638 JWK Thumbprints](https://www.rfc-editor.org/rfc/rfc7638.html)
//! as key identifiers:
//!
//! ```text
//! JWK = {"crv":"Ed25519","kty":"OKP","x":"<base64url-public-key>"}
//! thumbprint = base64url(SHA-256(canonical_jwk))
//! ```
//!
//! # Security Considerations
//!
//! - **Key Management**: Protect Ed25519 private keys (use HSM in production)
//! - **Timestamp Validation**: Signatures include creation timestamp to prevent replay
//! - **HTTPS Only**: TAP signatures MUST be sent over HTTPS
//! - **No Key Reuse**: Each agent should have unique keys per merchant (recommended)

pub mod signer;

pub use signer::{InteractionType, TapSigner};
