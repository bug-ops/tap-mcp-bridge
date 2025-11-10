//! TAP signature generation using RFC 9421 HTTP Message Signatures.

use std::{sync::Arc, time::SystemTime};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{BridgeError, Result};

/// TAP interaction type determining the signature tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionType {
    /// Browsing interaction (catalog, product details).
    Browse,
    /// Payment interaction (checkout, payment processing).
    Checkout,
}

impl InteractionType {
    /// Returns the TAP tag value for this interaction type.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Browse => "agent-browser-auth",
            Self::Checkout => "agent-payer-auth",
        }
    }
}

/// TAP signature for HTTP requests.
#[derive(Debug, Clone)]
pub struct TapSignature {
    /// Signature header value.
    pub signature: String,
    /// Signature-Input header value.
    pub signature_input: String,
    /// Agent directory URL (shared reference to avoid cloning).
    pub agent_directory: Arc<str>,
    /// Nonce used in this signature (for replay protection).
    pub nonce: String,
}

/// Generates TAP signatures for HTTP requests.
#[derive(Debug)]
pub struct TapSigner {
    signing_key: SigningKey,
    #[allow(dead_code, reason = "reserved for future use in Phase 2")]
    agent_id: String,
    agent_directory: Arc<str>,
}

impl TapSigner {
    /// Creates a new TAP signer.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::tap::TapSigner;
    ///
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
    /// ```
    #[must_use]
    pub fn new(signing_key: SigningKey, agent_id: &str, agent_directory: &str) -> Self {
        Self {
            signing_key,
            agent_id: agent_id.to_owned(),
            agent_directory: Arc::from(agent_directory),
        }
    }

    /// Signs an HTTP request with TAP signature.
    ///
    /// Generates RFC 9421 HTTP Message Signatures with Ed25519, including
    /// required TAP parameters: `tag`, `nonce`, `created`, and `expires`.
    ///
    /// # Errors
    ///
    /// Returns error if signature generation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// # use tap_mcp_bridge::tap::{TapSigner, InteractionType};
    /// # use ed25519_dalek::SigningKey;
    /// # fn example() -> tap_mcp_bridge::error::Result<()> {
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
    ///
    /// let signature = signer.sign_request(
    ///     "POST",
    ///     "merchant.com",
    ///     "/checkout",
    ///     b"request body",
    ///     InteractionType::Checkout,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn sign_request(
        &self,
        method: &str,
        authority: &str,
        path: &str,
        body: &[u8],
        interaction_type: InteractionType,
    ) -> Result<TapSignature> {
        let content_digest = Self::compute_content_digest(body);
        let created = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| BridgeError::CryptoError(format!("system time error: {e}")))?
            .as_secs();

        // TAP requirement: expires must be within 8 minutes (480 seconds) of created
        let expires = created + 480;

        // Generate unique nonce for replay protection (TAP requirement)
        let nonce = Uuid::new_v4().to_string();

        let keyid = self.compute_keyid();
        let tag = interaction_type.tag();

        let signature_base = Self::build_signature_base(
            method,
            authority,
            path,
            &content_digest,
            created,
            expires,
            &nonce,
            &keyid,
            tag,
        );

        let signature = self.signing_key.sign(signature_base.as_bytes());
        let signature_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            signature.to_bytes(),
        );

        let signature_input = format!(
            "sig1=(\"@method\" \"@authority\" \"@path\" \
             \"content-digest\");created={created};expires={expires};keyid=\"{keyid}\";alg=\"\
             ed25519\";nonce=\"{nonce}\";tag=\"{tag}\""
        );

        Ok(TapSignature {
            signature: format!("sig1=:{signature_b64}:"),
            signature_input,
            agent_directory: Arc::clone(&self.agent_directory),
            nonce,
        })
    }

    /// Computes Content-Digest header value per RFC 9530.
    ///
    /// Generates a SHA-256 digest of the request body in the format required
    /// by the Content-Digest HTTP header field.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::tap::TapSigner;
    ///
    /// let digest = TapSigner::compute_content_digest(b"test body");
    /// assert!(digest.starts_with("sha-256=:"));
    /// assert!(digest.ends_with(':'));
    /// ```
    #[must_use]
    pub fn compute_content_digest(body: &[u8]) -> String {
        let hash = Sha256::digest(body);
        let hash_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash);
        format!("sha-256=:{hash_b64}:")
    }

    /// Computes JWK thumbprint for keyid.
    fn compute_keyid(&self) -> String {
        let verifying_key = self.signing_key.verifying_key();
        let x_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            verifying_key.as_bytes(),
        );

        let jwk_json = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x_b64}"}}"#);

        let hash = Sha256::digest(jwk_json.as_bytes());
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash)
    }

    /// Builds signature base string per RFC 9421 with TAP extensions.
    #[allow(
        clippy::too_many_arguments,
        reason = "RFC 9421 requires all parameters"
    )]
    fn build_signature_base(
        method: &str,
        authority: &str,
        path: &str,
        content_digest: &str,
        created: u64,
        expires: u64,
        nonce: &str,
        keyid: &str,
        tag: &str,
    ) -> String {
        format!(
            "\"@method\": {method}\n\"@authority\": {authority}\n\"@path\": \
             {path}\n\"content-digest\": {content_digest}\n\"@signature-params\": (\"@method\" \
             \"@authority\" \"@path\" \
             \"content-digest\");created={created};expires={expires};keyid=\"{keyid}\";alg=\"\
             ed25519\";nonce=\"{nonce}\";tag=\"{tag}\""
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_content_digest() {
        let digest = TapSigner::compute_content_digest(b"test body");
        assert!(digest.starts_with("sha-256=:"));
        assert!(digest.ends_with(':'));
    }

    #[test]
    fn test_compute_content_digest_empty_body() {
        let digest = TapSigner::compute_content_digest(b"");
        // SHA-256 of empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(digest, "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:");
    }

    #[test]
    fn test_compute_content_digest_known_value() {
        // RFC 9421 test vector: "test body" should produce consistent hash
        let digest = TapSigner::compute_content_digest(b"test body");
        let expected_hash = Sha256::digest(b"test body");
        let expected_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, expected_hash);
        assert_eq!(digest, format!("sha-256=:{expected_b64}:"));
    }

    #[test]
    fn test_compute_keyid() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "test-agent", "https://test.com");

        let keyid = signer.compute_keyid();
        assert!(!keyid.is_empty());
        assert_eq!(keyid.len(), 43);
    }

    #[test]
    fn test_compute_keyid_rfc7638_test_vector() {
        // Test vector from RFC 7638 adapted for Ed25519
        // Using a known key to verify JWK thumbprint computation
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let signer = TapSigner::new(signing_key, "test-agent", "https://test.com");

        let x_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            verifying_key.as_bytes(),
        );

        // Verify JWK JSON construction (must be canonical order: crv, kty, x)
        let expected_jwk = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x_b64}"}}"#);
        let expected_hash = Sha256::digest(expected_jwk.as_bytes());
        let expected_thumbprint = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            expected_hash,
        );

        assert_eq!(signer.compute_keyid(), expected_thumbprint);
    }

    #[test]
    fn test_compute_keyid_different_keys_different_thumbprints() {
        let key1 = SigningKey::from_bytes(&[0u8; 32]);
        let key2 = SigningKey::from_bytes(&[1u8; 32]);

        let signer1 = TapSigner::new(key1, "agent1", "https://test.com");
        let signer2 = TapSigner::new(key2, "agent2", "https://test.com");

        assert_ne!(
            signer1.compute_keyid(),
            signer2.compute_keyid(),
            "different keys must produce different thumbprints"
        );
    }

    #[test]
    fn test_build_signature_base_format() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "test-agent", "https://test.com");
        let keyid = signer.compute_keyid();

        let base = TapSigner::build_signature_base(
            "POST",
            "merchant.com",
            "/checkout",
            "sha-256=:xyz123=:",
            1_234_567_890,
            1_234_568_370, // expires = created + 480
            "test-nonce-uuid",
            &keyid,
            "agent-payer-auth",
        );

        // Verify RFC 9421 signature base string format with TAP parameters
        assert!(base.contains("\"@method\": POST"));
        assert!(base.contains("\"@authority\": merchant.com"));
        assert!(base.contains("\"@path\": /checkout"));
        assert!(base.contains("\"content-digest\": sha-256=:xyz123=:"));
        assert!(base.contains("\"@signature-params\":"));
        assert!(base.contains("created=1234567890"));
        assert!(base.contains("expires=1234568370"));
        assert!(base.contains("nonce=\"test-nonce-uuid\""));
        assert!(base.contains("tag=\"agent-payer-auth\""));
        assert!(base.contains("alg=\"ed25519\""));
    }

    #[test]
    fn test_build_signature_base_component_order() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "test-agent", "https://test.com");
        let keyid = signer.compute_keyid();

        let base = TapSigner::build_signature_base(
            "POST",
            "merchant.com",
            "/checkout",
            "sha-256=:xyz=:",
            1_234_567_890,
            1_234_568_370,
            "test-nonce",
            &keyid,
            "agent-payer-auth",
        );

        // Verify component order matches RFC 9421 requirements
        let method_pos = base.find("\"@method\"").unwrap();
        let authority_pos = base.find("\"@authority\"").unwrap();
        let path_pos = base.find("\"@path\"").unwrap();
        let digest_pos = base.find("\"content-digest\"").unwrap();

        assert!(method_pos < authority_pos);
        assert!(authority_pos < path_pos);
        assert!(path_pos < digest_pos);
    }

    #[test]
    fn test_sign_request() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "test-agent", "https://test.com");

        let result = signer.sign_request(
            "POST",
            "merchant.com",
            "/checkout",
            b"test body",
            InteractionType::Checkout,
        );

        assert!(result.is_ok());
        let signature = result.unwrap();
        assert!(signature.signature.starts_with("sig1=:"));
        assert!(signature.signature_input.contains("created="));
        assert!(signature.signature_input.contains("expires="));
        assert!(signature.signature_input.contains("nonce="));
        assert!(signature.signature_input.contains("tag=\"agent-payer-auth\""));
        assert_eq!(signature.agent_directory.as_ref(), "https://test.com");
    }

    #[test]
    fn test_sign_request_signature_format() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "test-agent", "https://test.com");

        let result = signer.sign_request(
            "POST",
            "merchant.com",
            "/checkout",
            b"test body",
            InteractionType::Checkout,
        );
        assert!(result.is_ok());

        let sig = result.unwrap();

        // Verify signature format (sig1=:base64:)
        assert!(sig.signature.starts_with("sig1=:"));
        assert!(sig.signature.ends_with(':'));

        // Extract base64 signature
        let sig_b64 = sig.signature.strip_prefix("sig1=:").unwrap().strip_suffix(':').unwrap();
        let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
            .expect("signature should be valid base64");

        // Ed25519 signatures are always 64 bytes
        assert_eq!(sig_bytes.len(), 64);
    }

    #[test]
    fn test_sign_request_signature_verifiable() {
        use ed25519_dalek::{Signature, Verifier};

        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let signer = TapSigner::new(signing_key, "test-agent", "https://test.com");

        let method = "POST";
        let authority = "merchant.com";
        let path = "/checkout";
        let body = b"test body";

        let result = signer.sign_request(method, authority, path, body, InteractionType::Checkout);
        assert!(result.is_ok());

        let tap_sig = result.unwrap();

        // Extract signature bytes
        let sig_b64 = tap_sig.signature.strip_prefix("sig1=:").unwrap().strip_suffix(':').unwrap();
        let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
            .expect("valid base64");

        // Reconstruct signature base string
        let content_digest = TapSigner::compute_content_digest(body);

        // Extract parameters from signature_input
        let created_str = tap_sig
            .signature_input
            .split("created=")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let created: u64 = created_str.parse().unwrap();

        let expires_str = tap_sig
            .signature_input
            .split("expires=")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let expires: u64 = expires_str.parse().unwrap();

        let nonce = &tap_sig.nonce;
        let keyid = signer.compute_keyid();

        let signature_base = TapSigner::build_signature_base(
            method,
            authority,
            path,
            &content_digest,
            created,
            expires,
            nonce,
            &keyid,
            "agent-payer-auth",
        );

        // Verify signature
        let signature =
            Signature::from_bytes(&sig_bytes.try_into().expect("signature should be 64 bytes"));

        assert!(
            verifying_key.verify(signature_base.as_bytes(), &signature).is_ok(),
            "generated signature must be verifiable"
        );
    }

    #[test]
    fn test_sign_request_keyid_consistent() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "test-agent", "https://test.com");

        let sig1 = signer
            .sign_request(
                "POST",
                "merchant.com",
                "/checkout",
                b"test body",
                InteractionType::Checkout,
            )
            .unwrap();
        let sig2 = signer
            .sign_request(
                "POST",
                "merchant.com",
                "/checkout",
                b"test body",
                InteractionType::Checkout,
            )
            .unwrap();

        // Keyid should be the same across all requests
        let keyid = signer.compute_keyid();
        assert!(sig1.signature_input.contains(&keyid));
        assert!(sig2.signature_input.contains(&keyid));

        // Agent directory should be consistent
        assert_eq!(sig1.agent_directory.as_ref(), "https://test.com");
        assert_eq!(sig2.agent_directory.as_ref(), "https://test.com");

        // Nonces should be different (replay protection)
        assert_ne!(sig1.nonce, sig2.nonce);
    }

    #[test]
    fn test_signature_input_format() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "test-agent", "https://test.com");

        let result = signer.sign_request(
            "POST",
            "merchant.com",
            "/checkout",
            b"test body",
            InteractionType::Checkout,
        );
        assert!(result.is_ok());

        let sig = result.unwrap();

        // Verify signature_input format per RFC 9421 with TAP extensions
        assert!(sig.signature_input.starts_with("sig1=("));
        assert!(sig.signature_input.contains("\"@method\""));
        assert!(sig.signature_input.contains("\"@authority\""));
        assert!(sig.signature_input.contains("\"@path\""));
        assert!(sig.signature_input.contains("\"content-digest\""));
        assert!(sig.signature_input.contains(");created="));
        assert!(sig.signature_input.contains(";expires="));
        assert!(sig.signature_input.contains(";keyid=\""));
        assert!(sig.signature_input.contains(";alg=\"ed25519\""));
        assert!(sig.signature_input.contains(";nonce=\""));
        assert!(sig.signature_input.contains(";tag=\"agent-payer-auth\""));
    }

    #[test]
    fn test_different_requests_produce_different_signatures() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "test-agent", "https://test.com");

        let sig1 = signer
            .sign_request("POST", "merchant.com", "/checkout", b"body1", InteractionType::Checkout)
            .unwrap();
        let sig2 = signer
            .sign_request("POST", "merchant.com", "/checkout", b"body2", InteractionType::Checkout)
            .unwrap();
        let sig3 = signer
            .sign_request("GET", "merchant.com", "/checkout", b"body1", InteractionType::Browse)
            .unwrap();

        // Different bodies should produce different signatures
        assert_ne!(sig1.signature, sig2.signature);

        // Different methods should produce different signatures
        assert_ne!(sig1.signature, sig3.signature);

        // Different interaction types should produce different tags
        assert!(sig1.signature_input.contains("agent-payer-auth"));
        assert!(sig3.signature_input.contains("agent-browser-auth"));
    }
}
