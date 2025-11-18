//! JWT ID Token generation for TAP agent authentication.
//!
//! This module implements [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html)
//! JSON Web Token (JWT) generation for TAP ID tokens. ID tokens authenticate
//! the agent and delegate consumer authority to the agent for TAP-protected operations.
//!
//! # TAP Requirement
//!
//! TAP agents must generate signed JWT ID tokens containing consumer identity
//! and agent metadata. The token is signed with the same Ed25519 key used for
//! HTTP Message Signatures (RFC 9421).
//!
//! # Required Claims
//!
//! - `sub`: Consumer identifier (subject)
//! - `iss`: Agent identifier (issuer)
//! - `aud`: Merchant URL (audience)
//! - `exp`: Expiration timestamp (Unix time)
//! - `iat`: Issued-at timestamp (Unix time)
//! - `nonce`: Unique nonce for replay protection (matches HTTP signature nonce)
//!
//! # Token Lifetime
//!
//! ID tokens expire after 8 minutes (480 seconds) from creation, matching the
//! HTTP Message Signature expiration per TAP specification.
//!
//! # Examples
//!
//! ```
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::tap::jwt::{IdToken, IdTokenClaims};
//!
//! # fn example() -> tap_mcp_bridge::error::Result<()> {
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//!
//! // Create claims for consumer authentication
//! let claims = IdTokenClaims::new(
//!     "user-123",
//!     "agent-456",
//!     "https://merchant.example.com",
//!     "nonce-789",
//!     Some("https://agent.example.com"),
//! );
//!
//! // Sign the token with Ed25519
//! let token = IdToken::create(&claims, &signing_key)?;
//!
//! // Use token in TAP requests
//! println!("ID Token: {}", token.token);
//! # Ok(())
//! # }
//! ```

use std::time::SystemTime;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use signature::Signer;

use crate::error::{BridgeError, Result};

/// JWT claims for TAP ID token.
///
/// ID tokens authenticate the agent and delegate consumer authority
/// to the agent for TAP-protected operations. Claims follow RFC 7519
/// with TAP-specific extensions.
///
/// # Lifetime
///
/// Tokens expire 8 minutes (480 seconds) after creation per TAP specification.
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::tap::jwt::IdTokenClaims;
///
/// let claims = IdTokenClaims::new(
///     "user-123",
///     "agent-456",
///     "https://merchant.example.com",
///     "nonce-789",
///     Some("https://agent.example.com"),
/// );
///
/// assert_eq!(claims.sub, "user-123");
/// assert_eq!(claims.iss, "agent-456");
/// assert_eq!(claims.aud, "https://merchant.example.com");
/// assert_eq!(claims.nonce, "nonce-789");
/// assert!(claims.exp > claims.iat);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdTokenClaims {
    /// Subject - consumer identifier.
    ///
    /// Identifies the consumer on whose behalf the agent is acting.
    /// Per RFC 7519, this must be a locally unique and never reassigned
    /// identifier within the issuer's scope.
    pub sub: String,

    /// Issuer - agent identifier.
    ///
    /// Identifies the agent creating this token. This should match
    /// the agent ID used in HTTP Message Signatures.
    pub iss: String,

    /// Audience - merchant URL or identifier.
    ///
    /// Identifies the intended recipient of this token. Merchants
    /// must validate that the audience matches their identifier.
    pub aud: String,

    /// Expiration time (Unix timestamp).
    ///
    /// Tokens expire 8 minutes (480 seconds) after creation.
    /// Merchants must reject expired tokens.
    pub exp: u64,

    /// Issued at (Unix timestamp).
    ///
    /// The time when this token was created. Used to validate
    /// token age and expiration.
    pub iat: u64,

    /// Nonce for replay protection.
    ///
    /// This nonce should match the nonce used in the HTTP Message Signature
    /// for the same request, enabling correlation between the authentication
    /// token and the request signature.
    pub nonce: String,

    /// Agent directory URL (optional).
    ///
    /// URL where the agent serves its JWKS endpoint for public key verification.
    /// Typically at `https://agent.example.com/.well-known/http-message-signatures-directory`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_directory: Option<String>,
}

impl IdTokenClaims {
    /// Creates ID token claims for a TAP request.
    ///
    /// The token will expire 8 minutes (480 seconds) from creation,
    /// matching TAP HTTP Message Signature expiration requirements.
    ///
    /// # Arguments
    ///
    /// * `consumer_id` - Consumer identifier (subject)
    /// * `agent_id` - Agent identifier (issuer)
    /// * `merchant_url` - Merchant URL (audience)
    /// * `nonce` - Nonce for replay protection (should match HTTP signature nonce)
    /// * `agent_directory` - Optional agent directory URL for key verification
    ///
    /// # Panics
    ///
    /// Panics if system time is before Unix epoch (1970-01-01 00:00:00 UTC).
    /// This indicates a system configuration error.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::tap::jwt::IdTokenClaims;
    ///
    /// let claims = IdTokenClaims::new(
    ///     "user-123",
    ///     "agent-456",
    ///     "https://merchant.example.com",
    ///     "nonce-789",
    ///     Some("https://agent.example.com"),
    /// );
    ///
    /// assert_eq!(claims.sub, "user-123");
    /// assert_eq!(claims.iss, "agent-456");
    /// assert_eq!(claims.aud, "https://merchant.example.com");
    /// assert_eq!(claims.nonce, "nonce-789");
    /// assert_eq!(claims.exp - claims.iat, 480); // 8 minutes
    /// ```
    #[must_use]
    pub fn new(
        consumer_id: &str,
        agent_id: &str,
        merchant_url: &str,
        nonce: &str,
        agent_directory: Option<&str>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time must be after Unix epoch")
            .as_secs();

        // ID tokens expire after 8 minutes (480 seconds) per TAP spec
        let exp = now + 480;

        Self {
            sub: consumer_id.to_owned(),
            iss: agent_id.to_owned(),
            aud: merchant_url.to_owned(),
            exp,
            iat: now,
            nonce: nonce.to_owned(),
            agent_directory: agent_directory.map(str::to_owned),
        }
    }
}

/// TAP ID token (JWT).
///
/// A signed JWT token containing identity claims for TAP agent authentication.
/// The token is signed using Ed25519 (`EdDSA` algorithm) with the same key used
/// for HTTP Message Signatures.
///
/// # Format
///
/// JWT tokens have three parts separated by dots: `header.payload.signature`
///
/// - Header: `{"alg":"EdDSA","typ":"JWT"}`
/// - Payload: JSON-encoded [`IdTokenClaims`]
/// - Signature: Ed25519 signature of `header.payload`
///
/// # Examples
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use tap_mcp_bridge::tap::jwt::{IdToken, IdTokenClaims};
///
/// # fn example() -> tap_mcp_bridge::error::Result<()> {
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let claims = IdTokenClaims::new(
///     "user-123",
///     "agent-456",
///     "https://merchant.example.com",
///     "nonce-789",
///     None,
/// );
///
/// let token = IdToken::create(&claims, &signing_key)?;
/// assert!(token.token.starts_with("eyJ")); // JWT base64url format
/// //
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct IdToken {
    /// JWT string (signed token).
    ///
    /// This is the complete JWT in the format `header.payload.signature`,
    /// ready to be transmitted to merchants in the Authorization header
    /// or request body.
    pub token: String,

    /// Claims contained in the token.
    ///
    /// These are the decoded claims from the JWT payload, provided
    /// for convenience without needing to decode the token.
    pub claims: IdTokenClaims,
}

impl IdToken {
    /// Creates and signs an ID token.
    ///
    /// Generates a JWT with `EdDSA` (Ed25519) signature. The token format follows
    /// RFC 7519 with three base64url-encoded parts: header, payload, signature.
    ///
    /// # Arguments
    ///
    /// * `claims` - Token claims to encode
    /// * `signing_key` - Ed25519 signing key (same key used for HTTP signatures)
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CryptoError`] if JWT encoding or signing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::tap::jwt::{IdToken, IdTokenClaims};
    ///
    /// # fn example() -> tap_mcp_bridge::error::Result<()> {
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let claims = IdTokenClaims::new(
    ///     "user-123",
    ///     "agent-456",
    ///     "https://merchant.example.com",
    ///     "nonce-789",
    ///     None,
    /// );
    ///
    /// let token = IdToken::create(&claims, &signing_key)?;
    ///
    /// // JWT has three parts: header.payload.signature
    /// let parts: Vec<&str> = token.token.split('.').collect();
    /// assert_eq!(parts.len(), 3);
    /// # Ok(())
    /// # }
    /// ```
    pub fn create(claims: &IdTokenClaims, signing_key: &SigningKey) -> Result<Self> {
        // Manual JWT construction since jsonwebtoken's EdDSA support is limited
        // JWT format: base64url(header).base64url(payload).base64url(signature)

        // 1. Create JWT header
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "JWT"
        });
        let header_json = serde_json::to_string(&header)
            .map_err(|e| BridgeError::CryptoError(format!("JWT header encoding failed: {e}")))?;
        let header_b64 = base64_url_encode(header_json.as_bytes());

        // 2. Encode claims as payload
        let payload_json = serde_json::to_string(claims)
            .map_err(|e| BridgeError::CryptoError(format!("JWT payload encoding failed: {e}")))?;
        let payload_b64 = base64_url_encode(payload_json.as_bytes());

        // 3. Create signature input: header.payload
        let signing_input = format!("{header_b64}.{payload_b64}");

        // 4. Sign with Ed25519
        let signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = base64_url_encode(&signature.to_bytes());

        // 5. Construct final JWT: header.payload.signature
        let token = format!("{signing_input}.{signature_b64}");

        Ok(Self { token, claims: claims.clone() })
    }
}

/// Encodes bytes as base64url (RFC 4648) without padding.
///
/// JWT uses base64url encoding per RFC 7515 Section 2, which is URL-safe
/// and omits padding characters.
fn base64_url_encode(data: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_token_claims_creation() {
        let claims = IdTokenClaims::new(
            "user-123",
            "agent-456",
            "https://merchant.example.com",
            "nonce-789",
            Some("https://agent.example.com"),
        );

        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.iss, "agent-456");
        assert_eq!(claims.aud, "https://merchant.example.com");
        assert_eq!(claims.nonce, "nonce-789");
        assert!(claims.exp > claims.iat);
        assert_eq!(claims.exp - claims.iat, 480); // 8 minutes
        assert_eq!(claims.agent_directory, Some("https://agent.example.com".to_owned()));
    }

    #[test]
    fn test_id_token_claims_creation_without_agent_directory() {
        let claims = IdTokenClaims::new(
            "user-123",
            "agent-456",
            "https://merchant.example.com",
            "nonce-789",
            None,
        );

        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.iss, "agent-456");
        assert_eq!(claims.aud, "https://merchant.example.com");
        assert_eq!(claims.nonce, "nonce-789");
        assert_eq!(claims.agent_directory, None);
    }

    #[test]
    fn test_id_token_creation() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let claims = IdTokenClaims::new(
            "user-123",
            "agent-456",
            "https://merchant.example.com",
            "nonce-789",
            None,
        );

        let token = IdToken::create(&claims, &signing_key);
        assert!(token.is_ok());

        let id_token = token.unwrap();
        assert!(id_token.token.starts_with("eyJ")); // JWT base64url format
        assert_eq!(id_token.claims.sub, "user-123");
        assert_eq!(id_token.claims.iss, "agent-456");
        assert_eq!(id_token.claims.aud, "https://merchant.example.com");
        assert_eq!(id_token.claims.nonce, "nonce-789");
    }

    #[test]
    fn test_id_token_format() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let claims = IdTokenClaims::new("consumer", "agent", "https://merchant.com", "nonce", None);

        let token = IdToken::create(&claims, &signing_key).unwrap();

        // JWT has 3 parts: header.payload.signature
        let parts: Vec<&str> = token.token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");

        // Each part should be base64url encoded
        assert!(!parts[0].is_empty(), "header must not be empty");
        assert!(!parts[1].is_empty(), "payload must not be empty");
        assert!(!parts[2].is_empty(), "signature must not be empty");

        // Verify no padding characters (base64url uses no padding)
        assert!(!token.token.contains('='), "base64url must not contain padding");
    }

    #[test]
    fn test_different_keys_different_signatures() {
        let claims = IdTokenClaims::new("user", "agent", "https://m.com", "n", None);

        let key1 = SigningKey::from_bytes(&[0u8; 32]);
        let key2 = SigningKey::from_bytes(&[1u8; 32]);

        let token1 = IdToken::create(&claims, &key1).unwrap();
        let token2 = IdToken::create(&claims, &key2).unwrap();

        assert_ne!(token1.token, token2.token, "different keys must produce different tokens");

        // Headers and payloads should be the same, only signatures differ
        let parts1: Vec<&str> = token1.token.split('.').collect();
        let parts2: Vec<&str> = token2.token.split('.').collect();

        assert_eq!(parts1[0], parts2[0], "headers should match");
        assert_eq!(parts1[1], parts2[1], "payloads should match");
        assert_ne!(parts1[2], parts2[2], "signatures must differ");
    }

    #[test]
    fn test_different_claims_different_tokens() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);

        let claims1 = IdTokenClaims::new("user1", "agent", "https://m.com", "n", None);
        let claims2 = IdTokenClaims::new("user2", "agent", "https://m.com", "n", None);

        let token1 = IdToken::create(&claims1, &signing_key).unwrap();
        let token2 = IdToken::create(&claims2, &signing_key).unwrap();

        assert_ne!(token1.token, token2.token, "different claims must produce different tokens");
    }

    #[test]
    fn test_jwt_header_format() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let claims = IdTokenClaims::new("user", "agent", "https://m.com", "n", None);

        let token = IdToken::create(&claims, &signing_key).unwrap();
        let parts: Vec<&str> = token.token.split('.').collect();

        // Decode header
        let header_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[0])
                .expect("header should be valid base64url");
        let header: serde_json::Value =
            serde_json::from_slice(&header_bytes).expect("header should be valid JSON");

        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");
    }

    #[test]
    fn test_jwt_payload_format() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let claims = IdTokenClaims::new(
            "user-123",
            "agent-456",
            "https://merchant.com",
            "nonce-789",
            Some("https://agent.com"),
        );

        let token = IdToken::create(&claims, &signing_key).unwrap();
        let parts: Vec<&str> = token.token.split('.').collect();

        // Decode payload
        let payload_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
                .expect("payload should be valid base64url");
        let payload: serde_json::Value =
            serde_json::from_slice(&payload_bytes).expect("payload should be valid JSON");

        assert_eq!(payload["sub"], "user-123");
        assert_eq!(payload["iss"], "agent-456");
        assert_eq!(payload["aud"], "https://merchant.com");
        assert_eq!(payload["nonce"], "nonce-789");
        assert_eq!(payload["agent_directory"], "https://agent.com");
        assert!(payload["exp"].is_number());
        assert!(payload["iat"].is_number());
    }

    #[test]
    fn test_jwt_signature_length() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let claims = IdTokenClaims::new("user", "agent", "https://m.com", "n", None);

        let token = IdToken::create(&claims, &signing_key).unwrap();
        let parts: Vec<&str> = token.token.split('.').collect();

        // Decode signature
        let signature_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[2])
                .expect("signature should be valid base64url");

        // Ed25519 signatures are always 64 bytes
        assert_eq!(signature_bytes.len(), 64, "Ed25519 signature must be 64 bytes");
    }

    #[test]
    fn test_jwt_signature_verifiable() {
        use ed25519_dalek::{Signature, Verifier};

        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let claims = IdTokenClaims::new("user", "agent", "https://m.com", "n", None);

        let token = IdToken::create(&claims, &signing_key).unwrap();
        let parts: Vec<&str> = token.token.split('.').collect();

        // Reconstruct signing input
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        // Decode signature
        let signature_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[2])
                .expect("signature should be valid base64url");

        let signature = Signature::from_bytes(
            &signature_bytes.try_into().expect("signature should be 64 bytes"),
        );

        // Verify signature
        assert!(
            verifying_key.verify(signing_input.as_bytes(), &signature).is_ok(),
            "JWT signature must be verifiable with Ed25519"
        );
    }

    #[test]
    fn test_base64_url_encode() {
        // Test basic encoding
        let result = base64_url_encode(b"hello");
        assert_eq!(result, "aGVsbG8");

        // Verify no padding
        let result = base64_url_encode(b"hello!");
        assert!(!result.contains('='), "base64url must not contain padding");

        // Verify URL-safe characters (no +, no /)
        let result = base64_url_encode(&[0xff, 0xfe, 0xfd]);
        assert!(!result.contains('+'), "base64url must not contain +");
        assert!(!result.contains('/'), "base64url must not contain /");
    }

    #[test]
    fn test_claims_serialization() {
        let claims = IdTokenClaims::new("user", "agent", "https://m.com", "nonce", None);

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"sub\":\"user\""));
        assert!(json.contains("\"iss\":\"agent\""));
        assert!(json.contains("\"aud\":\"https://m.com\""));
        assert!(json.contains("\"nonce\":\"nonce\""));
        assert!(!json.contains("agent_directory"), "None fields should be omitted");
    }

    #[test]
    fn test_claims_with_agent_directory_serialization() {
        let claims = IdTokenClaims::new(
            "user",
            "agent",
            "https://m.com",
            "nonce",
            Some("https://agent.com"),
        );

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"agent_directory\":\"https://agent.com\""));
    }

    #[test]
    fn test_token_expiration_time() {
        let claims = IdTokenClaims::new("user", "agent", "https://m.com", "n", None);

        // Verify expiration is exactly 8 minutes (480 seconds) from creation
        assert_eq!(claims.exp - claims.iat, 480);

        // Verify iat is reasonable (within last minute)
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert!(now >= claims.iat, "iat should not be in the future");
        assert!(now - claims.iat < 60, "iat should be within last 60 seconds");
    }
}
