//! JSON Web Key (JWK) and JWK Set (JWKS) generation for TAP agent directory.
//!
//! This module implements [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html)
//! JSON Web Key (JWK) format and [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html)
//! JWK Thumbprint computation for Ed25519 public keys.
//!
//! # TAP Requirement
//!
//! TAP agents MUST expose their public keys at
//! `/.well-known/http-message-signatures-directory` in JWKS format
//! to enable merchants to verify agent signatures.
//!
//! # JWK Format
//!
//! Ed25519 public keys are represented as OKP (Octet Key Pair) JWKs:
//!
//! ```json
//! {
//!   "kty": "OKP",
//!   "crv": "Ed25519",
//!   "x": "<base64url-encoded-public-key>",
//!   "kid": "<jwk-thumbprint>",
//!   "alg": "EdDSA",
//!   "use": "verify"
//! }
//! ```
//!
//! # JWK Thumbprint
//!
//! Per RFC 7638, the JWK thumbprint is computed as:
//!
//! 1. Create canonical JWK JSON (lexicographic field ordering):
//!    `{"crv":"Ed25519","kty":"OKP","x":"..."}`
//! 2. Compute SHA-256 hash of the canonical JSON
//! 3. Base64url-encode the hash (no padding)
//!
//! The thumbprint is used as:
//! - `kid` field in the JWK
//! - `keyid` parameter in HTTP Message Signatures
//!
//! **Critical**: The JWK thumbprint MUST match the `keyid` used in HTTP signatures
//! to enable merchant verification.
//!
//! # Examples
//!
//! ## Generating a JWK
//!
//! ```rust
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::tap::jwk::Jwk;
//!
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let verifying_key = signing_key.verifying_key();
//! let jwk = Jwk::from_verifying_key(&verifying_key);
//!
//! assert_eq!(jwk.kty, "OKP");
//! assert_eq!(jwk.crv, "Ed25519");
//! assert_eq!(jwk.alg, "EdDSA");
//! assert_eq!(jwk.key_use, "verify");
//! ```
//!
//! ## Generating a JWKS
//!
//! ```rust
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::tap::jwk::{Jwk, Jwks};
//!
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let verifying_key = signing_key.verifying_key();
//! let jwk = Jwk::from_verifying_key(&verifying_key);
//! let jwks = Jwks::new(jwk);
//!
//! let json = jwks.to_json().expect("serialization should succeed");
//! assert!(json.contains("\"keys\""));
//! ```

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// JSON Web Key (JWK) for Ed25519 public key.
///
/// Represents an Ed25519 public key in JWK format per RFC 7517.
/// The `kid` field contains the JWK thumbprint (RFC 7638), which
/// MUST match the `keyid` used in HTTP Message Signatures.
///
/// # Examples
///
/// ```
/// # use ed25519_dalek::SigningKey;
/// use tap_mcp_bridge::tap::jwk::Jwk;
///
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let verifying_key = signing_key.verifying_key();
/// let jwk = Jwk::from_verifying_key(&verifying_key);
///
/// assert_eq!(jwk.kty, "OKP");
/// assert_eq!(jwk.crv, "Ed25519");
/// assert_eq!(jwk.alg, "EdDSA");
/// assert_eq!(jwk.key_use, "verify");
/// assert!(!jwk.x.is_empty());
/// assert!(!jwk.kid.is_empty());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    /// Key type (always "OKP" for Ed25519).
    pub kty: String,
    /// Curve (always "Ed25519").
    pub crv: String,
    /// Public key coordinate (base64url-encoded, no padding).
    pub x: String,
    /// Key ID (JWK thumbprint per RFC 7638).
    pub kid: String,
    /// Algorithm (always `"EdDSA"`).
    pub alg: String,
    /// Key usage (always "verify" for public keys).
    #[serde(rename = "use")]
    pub key_use: String,
}

impl Jwk {
    /// Creates a JWK from an Ed25519 `VerifyingKey`.
    ///
    /// Generates a JWK with all required fields populated:
    /// - `kty`: "OKP" (Octet Key Pair)
    /// - `crv`: "Ed25519"
    /// - `x`: Base64url-encoded public key (no padding)
    /// - `kid`: JWK thumbprint (RFC 7638)
    /// - `alg`: `"EdDSA"`
    /// - `use`: "verify"
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::tap::jwk::Jwk;
    ///
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let verifying_key = signing_key.verifying_key();
    /// let jwk = Jwk::from_verifying_key(&verifying_key);
    ///
    /// assert_eq!(jwk.kty, "OKP");
    /// assert_eq!(jwk.crv, "Ed25519");
    /// assert_eq!(jwk.alg, "EdDSA");
    /// assert_eq!(jwk.key_use, "verify");
    /// ```
    #[must_use]
    pub fn from_verifying_key(verifying_key: &VerifyingKey) -> Self {
        // Encode public key as base64url (no padding)
        let x = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            verifying_key.as_bytes(),
        );

        // Create JWK for thumbprint computation
        let jwk = Self {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x,
            kid: String::new(), // Will be computed below
            alg: "EdDSA".to_owned(),
            key_use: "verify".to_owned(),
        };

        // Compute JWK thumbprint for kid
        let kid = jwk.compute_thumbprint();

        Self { kid, ..jwk }
    }

    /// Computes JWK thumbprint per RFC 7638.
    ///
    /// The thumbprint is computed as:
    /// 1. Create canonical JWK JSON (lexicographic field ordering):
    ///    `{"crv":"Ed25519","kty":"OKP","x":"..."}`
    /// 2. Compute SHA-256 hash of the canonical JSON
    /// 3. Base64url-encode the hash (no padding)
    ///
    /// **Critical**: This thumbprint MUST match the `keyid` used in HTTP signatures.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::tap::jwk::Jwk;
    ///
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let verifying_key = signing_key.verifying_key();
    /// let jwk = Jwk::from_verifying_key(&verifying_key);
    ///
    /// let thumbprint = jwk.compute_thumbprint();
    /// assert!(!thumbprint.is_empty());
    /// assert_eq!(thumbprint.len(), 43); // SHA-256 base64url is 43 chars
    /// ```
    #[must_use]
    pub fn compute_thumbprint(&self) -> String {
        // RFC 7638 requires canonical JSON with lexicographic field ordering
        // For Ed25519 OKP keys: {"crv":"Ed25519","kty":"OKP","x":"..."}
        let canonical_jwk =
            format!(r#"{{"crv":"{}","kty":"{}","x":"{}"}}"#, self.crv, self.kty, self.x);

        // Compute SHA-256 hash
        let hash = Sha256::digest(canonical_jwk.as_bytes());

        // Base64url-encode (no padding)
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash)
    }
}

/// JSON Web Key Set (JWKS) containing agent public keys.
///
/// A JWKS is a collection of JWKs that can be served at
/// `/.well-known/http-message-signatures-directory` to enable
/// merchant verification of agent signatures.
///
/// # Examples
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use tap_mcp_bridge::tap::jwk::{Jwk, Jwks};
///
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let verifying_key = signing_key.verifying_key();
/// let jwk = Jwk::from_verifying_key(&verifying_key);
/// let jwks = Jwks::new(jwk);
///
/// let json = jwks.to_json().expect("serialization should succeed");
/// assert!(json.contains("\"keys\""));
/// assert!(json.contains("\"kty\": \"OKP\""));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwks {
    /// Array of JWKs.
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Creates a JWKS with a single key.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::tap::jwk::{Jwk, Jwks};
    ///
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let verifying_key = signing_key.verifying_key();
    /// let jwk = Jwk::from_verifying_key(&verifying_key);
    /// let jwks = Jwks::new(jwk);
    ///
    /// assert_eq!(jwks.keys.len(), 1);
    /// ```
    #[must_use]
    pub fn new(jwk: Jwk) -> Self {
        Self { keys: vec![jwk] }
    }

    /// Serializes JWKS to JSON string.
    ///
    /// # Errors
    ///
    /// Returns error if serialization fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::tap::jwk::{Jwk, Jwks};
    ///
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let verifying_key = signing_key.verifying_key();
    /// let jwk = Jwk::from_verifying_key(&verifying_key);
    /// let jwks = Jwks::new(jwk);
    ///
    /// let json = jwks.to_json().expect("serialization should succeed");
    /// assert!(json.contains("\"keys\""));
    /// ```
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn test_jwk_from_verifying_key() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let jwk = Jwk::from_verifying_key(&verifying_key);

        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.alg, "EdDSA");
        assert_eq!(jwk.key_use, "verify");
        assert!(!jwk.x.is_empty());
        assert!(!jwk.kid.is_empty());
        assert_eq!(jwk.kid.len(), 43, "SHA-256 base64url is 43 chars");
    }

    #[test]
    fn test_jwk_thumbprint_matches_keyid() {
        // Verify that JWK thumbprint matches TapSigner::compute_keyid
        use crate::tap::TapSigner;

        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let signer = TapSigner::new(signing_key, "test", "https://test.com");

        let jwk = Jwk::from_verifying_key(&verifying_key);

        // TapSigner::compute_keyid is private, so we verify via signature generation
        let signature = signer
            .sign_request("POST", "test.com", "/test", b"test", crate::tap::InteractionType::Browse)
            .expect("signature generation should succeed");

        // Extract keyid from signature_input
        let keyid_start =
            signature.signature_input.find("keyid=\"").expect("keyid should be present");
        let keyid_str = signature
            .signature_input
            .get(keyid_start + 7..)
            .expect("keyid string should be valid");
        let keyid_end = keyid_str.find('"').expect("keyid should be quoted");
        let keyid = keyid_str.get(..keyid_end).expect("keyid should be valid");

        assert_eq!(jwk.kid, keyid, "JWK kid must match signature keyid");
    }

    #[test]
    fn test_jwk_compute_thumbprint() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let jwk = Jwk::from_verifying_key(&verifying_key);

        let thumbprint = jwk.compute_thumbprint();
        assert!(!thumbprint.is_empty());
        assert_eq!(thumbprint.len(), 43, "SHA-256 base64url is 43 chars");

        // Verify thumbprint matches kid
        assert_eq!(thumbprint, jwk.kid);
    }

    #[test]
    fn test_jwk_thumbprint_canonical_json() {
        // Verify that thumbprint uses canonical JSON ordering
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let jwk = Jwk::from_verifying_key(&verifying_key);

        // Manually compute thumbprint to verify canonical JSON
        let x_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            verifying_key.as_bytes(),
        );
        let canonical_jwk = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x_b64}"}}"#);
        let hash = Sha256::digest(canonical_jwk.as_bytes());
        let expected_thumbprint =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash);

        assert_eq!(jwk.kid, expected_thumbprint, "thumbprint must use canonical JSON");
    }

    #[test]
    fn test_jwks_serialization() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let jwk = Jwk::from_verifying_key(&verifying_key);
        let jwks = Jwks::new(jwk);

        let json = jwks.to_json().expect("serialization should succeed");
        assert!(json.contains("\"keys\""));
        assert!(json.contains("\"kty\": \"OKP\""));
        assert!(json.contains("\"crv\": \"Ed25519\""));
        assert!(json.contains("\"alg\": \"EdDSA\""));
        assert!(json.contains("\"use\": \"verify\""));
    }

    #[test]
    fn test_jwks_deserialization() {
        let json = r#"{
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "test",
                "kid": "test-kid",
                "alg": "EdDSA",
                "use": "verify"
            }]
        }"#;

        let jwks: Jwks = serde_json::from_str(json).expect("deserialization should succeed");
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "OKP");
        assert_eq!(jwks.keys[0].crv, "Ed25519");
        assert_eq!(jwks.keys[0].x, "test");
        assert_eq!(jwks.keys[0].kid, "test-kid");
        assert_eq!(jwks.keys[0].alg, "EdDSA");
        assert_eq!(jwks.keys[0].key_use, "verify");
    }

    #[test]
    fn test_jwks_roundtrip() {
        let signing_key = SigningKey::from_bytes(&[2u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let jwk = Jwk::from_verifying_key(&verifying_key);
        let jwks = Jwks::new(jwk.clone());

        let json = jwks.to_json().expect("serialization should succeed");
        let deserialized: Jwks =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(deserialized.keys.len(), 1);
        assert_eq!(deserialized.keys[0], jwk);
    }

    #[test]
    fn test_different_keys_different_thumbprints() {
        let key1 = SigningKey::from_bytes(&[0u8; 32]);
        let key2 = SigningKey::from_bytes(&[1u8; 32]);

        let jwk1 = Jwk::from_verifying_key(&key1.verifying_key());
        let jwk2 = Jwk::from_verifying_key(&key2.verifying_key());

        assert_ne!(jwk1.kid, jwk2.kid, "different keys must have different thumbprints");
        assert_ne!(jwk1.x, jwk2.x, "different keys must have different public key values");
    }

    #[test]
    fn test_same_key_same_thumbprint() {
        let signing_key = SigningKey::from_bytes(&[5u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let jwk1 = Jwk::from_verifying_key(&verifying_key);
        let jwk2 = Jwk::from_verifying_key(&verifying_key);

        assert_eq!(jwk1.kid, jwk2.kid, "same key must produce same thumbprint");
        assert_eq!(jwk1.x, jwk2.x, "same key must produce same public key value");
    }
}
