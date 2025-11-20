//! TAP signature verification using RFC 9421 HTTP Message Signatures.

use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signature, VerifyingKey};
use lru::LruCache;
use signature::Verifier;
use tracing::{debug, instrument, warn};

use crate::{
    error::{BridgeError, Result},
    tap::signer::TapSigner,
};

/// Verifies TAP signatures on HTTP requests.
///
/// Implements RFC 9421 signature verification with TAP-specific requirements:
/// - Ed25519 signature validation
/// - Replay protection using nonces (8-minute window)
/// - Expiration validation
/// - Required component verification
#[derive(Debug, Clone)]
pub struct TapVerifier {
    /// Cache of recently seen nonces to prevent replay attacks.
    /// Wrapped in Mutex for thread safety.
    nonce_cache: Arc<Mutex<LruCache<String, u64>>>,
}

impl TapVerifier {
    /// Creates a new TAP verifier.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of nonces to store for replay protection.
    ///   Recommended: 10,000+ for high-traffic services.
    ///
    /// # Panics
    ///
    /// Panics if the default capacity (1000) is invalid (should never happen).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1000).expect("1000 is non-zero"));
        Self { nonce_cache: Arc::new(Mutex::new(LruCache::new(cap))) }
    }

    /// Verifies an HTTP request signature.
    ///
    /// # Arguments
    ///
    /// * `method` - HTTP method (e.g., "POST")
    /// * `authority` - HTTP authority (e.g., "merchant.com")
    /// * `path` - HTTP path (e.g., "/checkout")
    /// * `body` - Request body
    /// * `signature_header` - `Signature` header value
    /// * `signature_input_header` - `Signature-Input` header value
    /// * `verifying_key` - Ed25519 public key of the signer
    ///
    /// # Errors
    ///
    /// Returns error if verification fails for any reason (invalid signature,
    /// expired, replay detected, etc.).
    #[allow(clippy::too_many_arguments, reason = "RFC 9421 verification requires many parameters")]
    #[instrument(skip(self, body, verifying_key), fields(method, authority, path))]
    pub fn verify_request(
        &self,
        method: &str,
        authority: &str,
        path: &str,
        body: &[u8],
        signature_header: &str,
        signature_input_header: &str,
        verifying_key: &VerifyingKey,
    ) -> Result<()> {
        // 1. Parse Signature-Input
        // Format: sig1=("@method" "@authority" "@path" "content-digest");created=...;expires=...;nonce=...;tag=...
        let input = signature_input_header.trim();
        if !input.starts_with("sig1=(") {
            return Err(BridgeError::CryptoError(
                "Invalid Signature-Input: must start with sig1=".to_owned(),
            ));
        }

        // Extract parameters
        let params_str = input.split(')').nth(1).ok_or_else(|| {
            BridgeError::CryptoError("Invalid Signature-Input format".to_owned())
        })?;

        let created = Self::extract_param(params_str, "created")?
            .parse::<u64>()
            .map_err(|_| BridgeError::CryptoError("Invalid created timestamp".to_owned()))?;

        let expires = Self::extract_param(params_str, "expires")?
            .parse::<u64>()
            .map_err(|_| BridgeError::CryptoError("Invalid expires timestamp".to_owned()))?;

        let nonce = Self::extract_param(params_str, "nonce")?.trim_matches('"').to_owned();
        let tag = Self::extract_param(params_str, "tag")?.trim_matches('"');
        let keyid = Self::extract_param(params_str, "keyid")?.trim_matches('"');

        // 2. Validate timestamps
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| BridgeError::CryptoError(format!("System time error: {e}")))?
            .as_secs();

        if now > expires {
            return Err(BridgeError::RequestTooOld(
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(expires),
            ));
        }

        // TAP requires 8-minute window
        if expires.saturating_sub(created) > 480 {
            return Err(BridgeError::CryptoError(
                "Signature validity window exceeds 8 minutes".to_owned(),
            ));
        }

        // 3. Check replay protection
        {
            let mut cache = self.nonce_cache.lock().map_err(|_| {
                BridgeError::CryptoError("Failed to acquire nonce cache lock".to_owned())
            })?;

            if cache.contains(&nonce) {
                warn!(nonce, "Replay attack detected");
                return Err(BridgeError::ReplayAttack);
            }

            cache.put(nonce.clone(), expires)
        };

        // 4. Reconstruct signature base
        let content_digest = TapSigner::compute_content_digest(body);

        // Verify content-digest matches if present in input (it should be)
        // Note: In a full implementation we would parse the list of covered components.
        // For TAP, we enforce specific components.

        let signature_base = TapSigner::build_signature_base(
            method,
            authority,
            path,
            &content_digest,
            created,
            expires,
            &nonce,
            keyid,
            tag,
        );

        // 5. Verify signature
        // Extract base64 signature from header: sig1=:...:
        let sig_b64 = signature_header
            .trim()
            .strip_prefix("sig1=:")
            .and_then(|s| s.strip_suffix(':'))
            .ok_or_else(|| {
                BridgeError::CryptoError("Invalid Signature header format".to_owned())
            })?;

        let sig_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64)
            .map_err(|e| BridgeError::CryptoError(format!("Invalid base64 signature: {e}")))?;

        let signature = Signature::from_bytes(
            &sig_bytes
                .try_into()
                .map_err(|_| BridgeError::CryptoError("Invalid signature length".to_owned()))?,
        );

        verifying_key.verify(signature_base.as_bytes(), &signature).map_err(|e| {
            warn!(error = %e, "Signature verification failed");
            BridgeError::CryptoError(format!("Signature verification failed: {e}"))
        })?;

        debug!("Signature verified successfully");
        Ok(())
    }

    /// Helper to extract parameter value from Signature-Input string
    fn extract_param<'a>(input: &'a str, param: &str) -> Result<&'a str> {
        input
            .split(';')
            .find(|p| p.trim().starts_with(param))
            .and_then(|p| p.split('=').nth(1))
            .ok_or_else(|| BridgeError::CryptoError(format!("Missing parameter: {param}")))
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::tap::signer::InteractionType;

    #[test]
    fn test_verify_valid_signature() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let signer = TapSigner::new(signing_key, "agent-1", "https://agent.com");
        let verifier = TapVerifier::new(100);

        let method = "POST";
        let authority = "merchant.com";
        let path = "/checkout";
        let body = b"test";

        let sig = signer
            .sign_request(method, authority, path, body, InteractionType::Checkout)
            .unwrap();

        let result = verifier.verify_request(
            method,
            authority,
            path,
            body,
            &sig.signature,
            &sig.signature_input,
            &verifying_key,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_replay_protection() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let signer = TapSigner::new(signing_key, "agent-1", "https://agent.com");
        let verifier = TapVerifier::new(100);

        let sig = signer
            .sign_request("POST", "merchant.com", "/checkout", b"test", InteractionType::Checkout)
            .unwrap();

        // First verification should succeed
        assert!(
            verifier
                .verify_request(
                    "POST",
                    "merchant.com",
                    "/checkout",
                    b"test",
                    &sig.signature,
                    &sig.signature_input,
                    &verifying_key,
                )
                .is_ok()
        );

        // Second verification with same nonce should fail
        let result = verifier.verify_request(
            "POST",
            "merchant.com",
            "/checkout",
            b"test",
            &sig.signature,
            &sig.signature_input,
            &verifying_key,
        );

        assert!(matches!(result, Err(BridgeError::ReplayAttack)));
    }
}
