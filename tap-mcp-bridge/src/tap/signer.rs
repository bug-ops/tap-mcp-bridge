//! TAP signature generation using RFC 9421 HTTP Message Signatures.

use std::{sync::Arc, time::SystemTime};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use signature::Signer;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    error::{BridgeError, Result},
    tap::TAP_MAX_VALIDITY_WINDOW_SECS,
};

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
    /// use ed25519_dalek::SigningKey;
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
    #[instrument(skip(self, body), fields(method, authority, path, body_len = body.len(), interaction_type = ?interaction_type))]
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

        // TAP requirement: expires must be within 8 minutes of created
        let expires = created + TAP_MAX_VALIDITY_WINDOW_SECS;

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

    /// Generates a JWKS containing this signer's public key.
    ///
    /// The JWKS can be served at `/.well-known/http-message-signatures-directory`
    /// to enable merchants to verify agent signatures.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::tap::TapSigner;
    ///
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
    ///
    /// let jwks = signer.generate_jwks();
    /// let json = jwks.to_json().unwrap();
    /// assert!(json.contains("\"kty\": \"OKP\""));
    /// ```
    #[must_use]
    pub fn generate_jwks(&self) -> crate::tap::jwk::Jwks {
        let verifying_key = self.signing_key.verifying_key();
        let jwk = crate::tap::jwk::Jwk::from_verifying_key(&verifying_key);
        crate::tap::jwk::Jwks::new(jwk)
    }

    /// Generates an ID token for TAP authentication.
    ///
    /// The ID token authenticates the agent and delegates consumer authority.
    /// It uses the same Ed25519 key as HTTP signatures and shares the same nonce
    /// for correlation between the authentication token and request signature.
    ///
    /// # Arguments
    ///
    /// * `consumer_id` - Consumer identifier (subject of the token)
    /// * `merchant_url` - Merchant URL (audience of the token)
    /// * `nonce` - Nonce for replay protection (should match HTTP signature nonce)
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CryptoError`] if token generation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::tap::TapSigner;
    ///
    /// # fn example() -> tap_mcp_bridge::error::Result<()> {
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
    ///
    /// let token =
    ///     signer.generate_id_token("user-456", "https://merchant.example.com", "nonce-789")?;
    ///
    /// assert!(token.token.starts_with("eyJ")); // JWT format
    /// assert_eq!(token.claims.sub, "user-456");
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(consumer_id, merchant_url, nonce))]
    pub fn generate_id_token(
        &self,
        consumer_id: &str,
        merchant_url: &str,
        nonce: &str,
    ) -> Result<crate::tap::jwt::IdToken> {
        let claims = crate::tap::jwt::IdTokenClaims::new(
            consumer_id,
            &self.agent_id,
            merchant_url,
            nonce,
            Some(self.agent_directory.as_ref()),
        );

        crate::tap::jwt::IdToken::create(&claims, &self.signing_key)
    }

    /// Generates an ACRO for TAP authentication.
    ///
    /// The ACRO (Agentic Consumer Recognition Object) identifies the consumer
    /// on whose behalf the agent is acting and provides verification of consumer
    /// identity with contextual data.
    ///
    /// # Arguments
    ///
    /// * `nonce` - Nonce (should match HTTP signature nonce)
    /// * `id_token` - JWT ID token string
    /// * `contextual_data` - Consumer location and device data
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CryptoError`] if ACRO generation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::tap::{
    ///     TapSigner,
    ///     acro::{ContextualData, DeviceData},
    /// };
    ///
    /// # fn example() -> tap_mcp_bridge::error::Result<()> {
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
    ///
    /// // Generate ID token first
    /// let id_token = signer.generate_id_token("user-456", "https://merchant.com", "nonce-123")?;
    ///
    /// // Create contextual data
    /// let contextual_data = ContextualData {
    ///     country_code: "US".to_owned(),
    ///     zip: "94103".to_owned(),
    ///     ip_address: "192.168.1.100".to_owned(),
    ///     device_data: DeviceData {
    ///         user_agent: "Mozilla/5.0".to_owned(),
    ///         platform: "Linux".to_owned(),
    ///     },
    /// };
    ///
    /// // Generate ACRO
    /// let acro = signer.generate_acro("nonce-123", &id_token.token, contextual_data)?;
    /// assert_eq!(acro.nonce, "nonce-123");
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, id_token, contextual_data), fields(nonce, id_token_len = id_token.len()))]
    pub fn generate_acro(
        &self,
        nonce: &str,
        id_token: &str,
        contextual_data: crate::tap::acro::ContextualData,
    ) -> Result<crate::tap::acro::Acro> {
        let kid = self.compute_keyid();
        crate::tap::acro::Acro::create(nonce, id_token, contextual_data, &kid, &self.signing_key)
    }

    /// Generates an APC for TAP payment transactions.
    ///
    /// The APC (Agentic Payment Container) contains encrypted payment credentials
    /// and authorization for transaction processing. Payment data is encrypted
    /// before transmission per PCI-DSS requirements.
    ///
    /// # Arguments
    ///
    /// * `nonce` - Nonce (should match HTTP signature nonce)
    /// * `payment_method` - Payment method with credentials
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CryptoError`] if APC generation or encryption fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::tap::{
    ///     TapSigner,
    ///     apc::{CardData, PaymentMethod, RsaPublicKey},
    /// };
    ///
    /// # fn example() -> tap_mcp_bridge::error::Result<()> {
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
    ///
    /// // Create card payment method
    /// let card = CardData {
    ///     number: "4111111111111111".to_owned(),
    ///     exp_month: "12".to_owned(),
    ///     exp_year: "25".to_owned(),
    ///     cvv: "123".to_owned(),
    ///     cardholder_name: "John Doe".to_owned(),
    /// };
    /// let payment_method = PaymentMethod::Card(card);
    ///
    /// // Load merchant's public key (in production, fetch from merchant's JWKS endpoint)
    /// let pem = b"-----BEGIN PUBLIC KEY-----
    /// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
    /// 4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
    /// +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
    /// kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
    /// 0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
    /// cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
    /// mwIDAQAB
    /// -----END PUBLIC KEY-----";
    /// let merchant_key = RsaPublicKey::from_pem(pem)?;
    ///
    /// // Generate APC
    /// let apc = signer.generate_apc("nonce-123", &payment_method, &merchant_key)?;
    /// assert_eq!(apc.nonce, "nonce-123");
    /// assert_eq!(apc.alg, "ed25519");
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, payment_method, merchant_public_key), fields(nonce))]
    pub fn generate_apc(
        &self,
        nonce: &str,
        payment_method: &crate::tap::apc::PaymentMethod,
        merchant_public_key: &crate::tap::apc::RsaPublicKey,
    ) -> Result<crate::tap::apc::Apc> {
        // Encrypt payment method data with merchant's public key
        let encrypted_payment_data = payment_method.encrypt(merchant_public_key)?;

        // Generate APC with signature
        let kid = self.compute_keyid();
        crate::tap::apc::Apc::create(nonce, &encrypted_payment_data, &kid, &self.signing_key)
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
    ///
    /// This function is `pub(crate)` to allow `TapVerifier` to reconstruct
    /// the signature base for verification without exposing it as a public API.
    #[allow(
        clippy::too_many_arguments,
        reason = "RFC 9421 requires all parameters"
    )]
    #[must_use]
    pub(crate) fn build_signature_base(
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
    use ed25519_dalek::Signature;
    use signature::Verifier;

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
    fn test_generate_jwks() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "test-agent", "https://test.com");

        let jwks = signer.generate_jwks();
        assert_eq!(jwks.keys.len(), 1);

        let jwk = &jwks.keys[0];
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.alg, "EdDSA");
        assert_eq!(jwk.key_use, "verify");

        // Verify JSON serialization
        let json = jwks.to_json().expect("serialization should succeed");
        assert!(json.contains("\"kty\": \"OKP\""));
        assert!(json.contains("\"crv\": \"Ed25519\""));
    }

    #[test]
    fn test_generate_jwks_kid_matches_signature_keyid() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "test-agent", "https://test.com");

        // Generate JWKS
        let jwks = signer.generate_jwks();
        let jwk_kid = &jwks.keys[0].kid;

        // Generate signature to get keyid
        let signature = signer
            .sign_request("POST", "test.com", "/test", b"test", InteractionType::Browse)
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

        assert_eq!(jwk_kid, keyid, "JWK kid must match signature keyid");
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

    #[test]
    fn test_generate_id_token() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let token =
            signer.generate_id_token("user-456", "https://merchant.example.com", "nonce-789");

        assert!(token.is_ok());
        let id_token = token.unwrap();
        assert_eq!(id_token.claims.sub, "user-456");
        assert_eq!(id_token.claims.iss, "agent-123");
        assert_eq!(id_token.claims.aud, "https://merchant.example.com");
        assert_eq!(id_token.claims.nonce, "nonce-789");
        assert_eq!(id_token.claims.agent_directory, Some("https://agent.example.com".to_owned()));
        assert!(id_token.token.starts_with("eyJ"));
    }

    #[test]
    fn test_generate_id_token_format() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let token = signer
            .generate_id_token("consumer", "https://merchant.com", "nonce-unique")
            .unwrap();

        // Verify JWT format
        let parts: Vec<&str> = token.token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");
    }

    #[test]
    fn test_generate_id_token_nonce_matches_signature() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        // Generate HTTP signature
        let signature = signer
            .sign_request("POST", "merchant.com", "/checkout", b"test", InteractionType::Checkout)
            .unwrap();

        // Generate ID token with same nonce
        let token = signer
            .generate_id_token("user", "https://merchant.com", &signature.nonce)
            .unwrap();

        // Verify nonces match (enables correlation)
        assert_eq!(token.claims.nonce, signature.nonce);
    }

    #[test]
    fn test_generate_acro() {
        use crate::tap::acro::{ContextualData, DeviceData};

        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        // Generate ID token
        let id_token = signer
            .generate_id_token("user-456", "https://merchant.com", "nonce-789")
            .unwrap();

        // Create contextual data
        let contextual_data = ContextualData {
            country_code: "US".to_owned(),
            zip: "94103".to_owned(),
            ip_address: "192.168.1.100".to_owned(),
            device_data: DeviceData {
                user_agent: "Mozilla/5.0".to_owned(),
                platform: "Linux".to_owned(),
            },
        };

        // Generate ACRO
        let acro = signer.generate_acro("nonce-789", &id_token.token, contextual_data);

        assert!(acro.is_ok());
        let acro = acro.unwrap();
        assert_eq!(acro.nonce, "nonce-789");
        assert_eq!(acro.id_token, id_token.token);
        assert_eq!(acro.alg, "ed25519");
        assert!(!acro.signature.is_empty());
    }

    #[test]
    fn test_generate_acro_kid_matches_signature_keyid() {
        use crate::tap::acro::{ContextualData, DeviceData};

        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        // Generate HTTP signature to get keyid
        let signature = signer
            .sign_request("POST", "merchant.com", "/checkout", b"test", InteractionType::Checkout)
            .unwrap();

        // Extract keyid from signature_input
        let keyid_start = signature.signature_input.find("keyid=\"").unwrap();
        let keyid_str = signature.signature_input.get(keyid_start + 7..).unwrap();
        let keyid_end = keyid_str.find('"').unwrap();
        let keyid = keyid_str.get(..keyid_end).unwrap();

        // Generate ACRO
        let id_token = signer.generate_id_token("user", "https://m.com", "nonce").unwrap();
        let contextual_data = ContextualData {
            country_code: "US".to_owned(),
            zip: "12345".to_owned(),
            ip_address: "1.2.3.4".to_owned(),
            device_data: DeviceData { user_agent: "Test".to_owned(), platform: "Test".to_owned() },
        };
        let acro = signer.generate_acro("nonce", &id_token.token, contextual_data).unwrap();

        // Verify ACRO kid matches signature keyid
        assert_eq!(acro.kid, keyid, "ACRO kid must match HTTP signature keyid");
    }

    #[test]
    fn test_generate_acro_nonce_correlation() {
        use crate::tap::acro::{ContextualData, DeviceData};

        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        // Generate HTTP signature with nonce
        let signature = signer
            .sign_request("POST", "merchant.com", "/checkout", b"test", InteractionType::Checkout)
            .unwrap();

        // Generate ID token with same nonce
        let id_token = signer
            .generate_id_token("user", "https://merchant.com", &signature.nonce)
            .unwrap();

        // Generate ACRO with same nonce
        let contextual_data = ContextualData {
            country_code: "US".to_owned(),
            zip: "12345".to_owned(),
            ip_address: "1.2.3.4".to_owned(),
            device_data: DeviceData { user_agent: "Test".to_owned(), platform: "Test".to_owned() },
        };
        let acro = signer
            .generate_acro(&signature.nonce, &id_token.token, contextual_data)
            .unwrap();

        // Verify all three share the same nonce
        assert_eq!(signature.nonce, id_token.claims.nonce);
        assert_eq!(signature.nonce, acro.nonce);
    }
}
