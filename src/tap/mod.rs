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
//! - [`InteractionType`]: Specifies signature tag (browsing vs checkout)
//!
//! # Signature Components
//!
//! Per TAP specification, signatures cover these components:
//! - `@method`: HTTP method (e.g., POST, GET)
//! - `@authority`: Target merchant domain
//! - `@path`: Request path
//! - `content-digest`: SHA-256 hash of request body
//!
//! # TAP Required Parameters
//!
//! Each signature includes TAP-specific parameters:
//! - `created`: Unix timestamp when signature was generated
//! - `expires`: Signature expiration (created + 480 seconds max)
//! - `nonce`: Unique UUID v4 for replay attack prevention
//! - `keyid`: JWK thumbprint (RFC 7638) for public key identification
//! - `alg`: Signature algorithm (ed25519)
//! - `tag`: Interaction type (`agent-browser-auth` or `agent-payer-auth`)
//!
//! # Examples
//!
//! ## Basic Signature Generation
//!
//! ```rust
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::tap::{InteractionType, TapSigner};
//!
//! # fn example() -> tap_mcp_bridge::error::Result<()> {
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
//!
//! // Generate signature for checkout operation
//! let signature = signer.sign_request(
//!     "POST",
//!     "merchant.com",
//!     "/checkout",
//!     b"request body",
//!     InteractionType::Checkout,
//! )?;
//!
//! println!("Signature: {}", signature.signature);
//! println!("Signature-Input: {}", signature.signature_input);
//! println!("Nonce: {}", signature.nonce);
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
//! - **Replay Attack Prevention**: Each signature includes unique nonce (UUID v4)
//! - **Timestamp Validation**: Signatures expire after 8 minutes (TAP requirement)
//! - **Nonce Tracking**: Merchants must reject duplicate nonces within 8-minute window
//! - **HTTPS Only**: TAP signatures MUST be sent over HTTPS
//! - **No Key Reuse**: Each agent should have unique keys per merchant (recommended)
//!
//! # Public Key Distribution
//!
//! TAP agents must expose their public keys at
//! `/.well-known/http-message-signatures-directory` in JWKS format
//! to enable merchants to verify agent signatures.
//!
//! Use [`TapSigner::generate_jwks`] to create a JWKS for your agent:
//!
//! ```rust
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::tap::TapSigner;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
//!
//! // Generate JWKS for agent directory
//! let jwks = signer.generate_jwks();
//! let json = jwks.to_json()?;
//!
//! // Serve this JSON at /.well-known/http-message-signatures-directory
//! println!("{}", json);
//! # Ok(())
//! # }
//! ```
//!
//! See also:
//! - [RFC 7517 (JSON Web Key)](https://www.rfc-editor.org/rfc/rfc7517.html)
//! - [RFC 7638 (JWK Thumbprint)](https://www.rfc-editor.org/rfc/rfc7638.html)
//!
//! # ID Token (JWT) Generation
//!
//! TAP agents generate JWT ID tokens to authenticate consumers:
//!
//! ```rust
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::tap::TapSigner;
//!
//! # fn example() -> tap_mcp_bridge::error::Result<()> {
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
//!
//! // Generate ID token with consumer claims
//! let token =
//!     signer.generate_id_token("user-456", "https://merchant.example.com", "nonce-unique-123")?;
//!
//! println!("ID Token: {}", token.token);
//! println!("Consumer: {}", token.claims.sub);
//! println!("Expires: {}", token.claims.exp);
//! # Ok(())
//! # }
//! ```
//!
//! The ID token includes standard JWT claims (iss, sub, aud, exp, iat, nonce)
//! and can be verified by merchants using the agent's public key.
//!
//! # TAP Compliance
//!
//! This implementation satisfies the following TAP specification requirements:
//! - ✅ RFC 9421 HTTP Message Signatures with Ed25519
//! - ✅ Interaction type tags (agent-browser-auth, agent-payer-auth)
//! - ✅ Nonce generation for replay protection
//! - ✅ Timestamp expiration (8-minute maximum window)
//! - ✅ JWK Thumbprint key identifiers (RFC 7638)
//! - ✅ Public Key Directory (JWKS at `/.well-known/http-message-signatures-directory`)
//! - ✅ ID Token (JWT) generation for consumer authentication
//! - ✅ Agentic Consumer Recognition Object (ACRO) - Phase 4D complete
//! - ⏳ Agentic Payment Container (APC) - planned Phase 4E

pub mod acro;
pub mod jwk;
pub mod jwt;
pub mod signer;

pub use signer::{InteractionType, TapSigner};
