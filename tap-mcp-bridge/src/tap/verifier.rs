//! TAP signature verification using RFC 9421 HTTP Message Signatures.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signature, VerifyingKey};
use signature::Verifier;
use tracing::{debug, instrument, warn};

use crate::{
    error::{BridgeError, Result},
    tap::{CLOCK_SKEW_TOLERANCE_SECS, TAP_MAX_VALIDITY_WINDOW_SECS, signer::TapSigner},
};

/// Default replay-cache capacity when the caller passes `0`.
const DEFAULT_NONCE_CACHE_CAPACITY: usize = 1000;

/// Replay-protection nonce cache state.
///
/// Eviction is **TTL-driven**: a nonce is held until its signature's `expires`
/// (plus [`CLOCK_SKEW_TOLERANCE_SECS`]) has passed, at which point the underlying
/// signature would also fail timestamp validation in [`TapVerifier::verify_request`].
///
/// When the cache is at capacity and contains only still-valid entries, fresh
/// requests are refused with [`BridgeError::ReplayCacheSaturated`] (fail-closed)
/// rather than evicting an unexpired nonce — silently dropping a valid entry
/// would create a replay-protection bypass.
#[derive(Debug)]
struct NonceCache {
    /// Nonce → signature `expires` timestamp (seconds since UNIX epoch).
    entries: HashMap<String, u64>,
    /// Hard ceiling on `entries.len()`.
    capacity: usize,
}

impl NonceCache {
    fn new(capacity: usize) -> Self {
        let capacity = if capacity == 0 {
            DEFAULT_NONCE_CACHE_CAPACITY
        } else {
            capacity
        };
        Self { entries: HashMap::new(), capacity }
    }

    /// TTL-driven sweep: drop every nonce whose signature is no longer
    /// acceptable to [`TapVerifier::verify_request`] (i.e. `expires + skew < now`).
    fn sweep_expired(&mut self, now: u64) {
        let cutoff = now.saturating_sub(CLOCK_SKEW_TOLERANCE_SECS);
        self.entries.retain(|_, expires| *expires >= cutoff);
    }

    /// Records `nonce` as seen. Caller MUST have called [`Self::sweep_expired`]
    /// for the same `now` first; this keeps the saturation check meaningful.
    ///
    /// Returns:
    /// - `Err(ReplayAttack)` if `nonce` is already cached and still valid.
    /// - `Err(ReplayCacheSaturated)` if the cache is full of unexpired entries.
    /// - `Ok(())` once `nonce` has been inserted.
    fn check_and_insert(&mut self, nonce: &str, expires: u64) -> Result<()> {
        if self.entries.contains_key(nonce) {
            return Err(BridgeError::ReplayAttack);
        }
        if self.entries.len() >= self.capacity {
            warn!(
                len = self.entries.len(),
                capacity = self.capacity,
                "Replay-protection cache saturated with unexpired nonces; rejecting fresh request"
            );
            return Err(BridgeError::ReplayCacheSaturated);
        }
        self.entries.insert(nonce.to_owned(), expires);
        Ok(())
    }
}

/// Verifies TAP signatures on HTTP requests.
///
/// Implements RFC 9421 signature verification with TAP-specific requirements:
/// - Ed25519 signature validation
/// - Replay protection using nonces (8-minute window)
/// - Expiration validation
/// - Required component verification
///
/// # Replay-Protection Sizing
///
/// The verifier retains every accepted nonce until its signature's `expires`
/// timestamp has passed. Capacity should therefore be at least
/// `peak_requests_per_second × (TAP_MAX_VALIDITY_WINDOW_SECS + CLOCK_SKEW_TOLERANCE_SECS)`
/// — i.e. `peak_RPS × 540` for the 8-minute TAP window plus the 60-second skew
/// tolerance. Under-sizing causes legitimate fresh requests to fail with
/// [`BridgeError::ReplayCacheSaturated`] rather than silently weakening the
/// replay-protection window.
#[derive(Debug, Clone)]
pub struct TapVerifier {
    /// Replay-protection cache, wrapped in `Mutex` for thread safety.
    nonce_cache: Arc<Mutex<NonceCache>>,
}

impl TapVerifier {
    /// Creates a new TAP verifier.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of unexpired nonces to store for replay protection. Size for
    ///   `peak_RPS × 540` to comfortably cover the TAP 8-minute validity window plus clock-skew
    ///   tolerance; recommended floor is 10,000 for general-purpose deployments. A value of `0` is
    ///   replaced by an internal default of 1000.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self { nonce_cache: Arc::new(Mutex::new(NonceCache::new(capacity))) }
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
    #[allow(
        clippy::too_many_arguments,
        reason = "RFC 9421 verification requires many parameters"
    )]
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
        // Format: sig1=("@method" "@authority" "@path"
        // "content-digest");created=...;expires=...;nonce=...;tag=...
        let input = signature_input_header.trim();
        if !input.starts_with("sig1=(") {
            return Err(BridgeError::CryptoError(
                "Invalid Signature-Input: must start with sig1=".to_owned(),
            ));
        }

        // Extract parameters
        // Find the opening parenthesis after "sig1="
        let open_paren = input.find('(').ok_or_else(|| {
            BridgeError::CryptoError("Invalid Signature-Input: missing '('".to_owned())
        })?;
        let close_paren = input
            .get(open_paren..)
            .and_then(|s| s.find(')').map(|i| open_paren + i))
            .ok_or_else(|| {
                BridgeError::CryptoError("Invalid Signature-Input: missing ')'".to_owned())
            })?;
        // Covered components: input[(open_paren+1)..close_paren]
        // Parameters: input[(close_paren+1)..]
        let params_str = input
            .get((close_paren + 1)..)
            .ok_or_else(|| BridgeError::CryptoError("Invalid Signature-Input format".to_owned()))?;

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

        // Allow grace period for clock skew per RFC 9421 Section 2.3
        if now > expires + CLOCK_SKEW_TOLERANCE_SECS {
            return Err(BridgeError::RequestTooOld(
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(expires),
            ));
        }

        // TAP requires maximum 8-minute validity window
        if expires.saturating_sub(created) > TAP_MAX_VALIDITY_WINDOW_SECS {
            return Err(BridgeError::CryptoError(
                "Signature validity window exceeds TAP maximum".to_owned(),
            ));
        }

        // 3. Check replay protection (TTL-driven, fail-closed on saturation).
        {
            let mut cache = self.nonce_cache.lock().map_err(|_| {
                BridgeError::CryptoError("Failed to acquire nonce cache lock".to_owned())
            })?;

            cache.sweep_expired(now);
            match cache.check_and_insert(&nonce, expires) {
                Ok(()) => {}
                Err(BridgeError::ReplayAttack) => {
                    warn!(nonce, "Replay attack detected");
                    return Err(BridgeError::ReplayAttack);
                }
                Err(e) => return Err(e),
            }
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
            .find_map(|p| {
                let p = p.trim();
                if p.starts_with(param) {
                    p.split_once('=').map(|(_, v)| v.trim())
                } else {
                    None
                }
            })
            .ok_or_else(|| BridgeError::CryptoError(format!("Missing parameter: {param}")))
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    reason = "test code uses panic for assertion on unexpected errors"
)]
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

    /// Regression for issue #153: under LRU eviction, capacity+1 fresh nonces
    /// silently dropped the oldest still-valid entry, letting an attacker
    /// replay it within the 8-minute validity window.
    ///
    /// The TTL-driven cache must instead either keep the original nonce (so
    /// replay is detected) or fail-closed on the flooding request. Either
    /// outcome closes the bypass; LRU eviction does neither.
    #[test]
    fn test_replay_cache_does_not_drop_unexpired_nonces_under_flood() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let signer = TapSigner::new(signing_key, "agent-1", "https://agent.com");
        let capacity: usize = 8;
        let verifier = TapVerifier::new(capacity);

        let verify = |sig: &crate::tap::signer::TapSignature| {
            verifier.verify_request(
                "POST",
                "merchant.com",
                "/checkout",
                b"test",
                &sig.signature,
                &sig.signature_input,
                &verifying_key,
            )
        };

        // 1. Legitimate request, accepted.
        let original = signer
            .sign_request("POST", "merchant.com", "/checkout", b"test", InteractionType::Checkout)
            .unwrap();
        verify(&original).expect("legitimate request must verify");

        // 2. Flood the verifier with `capacity` more distinct nonces. Some MAY be rejected with
        //    ReplayCacheSaturated once the cache fills — that is the fail-closed outcome — but none
        //    must dislodge `original`.
        for _ in 0..capacity {
            let flood_sig = signer
                .sign_request(
                    "POST",
                    "merchant.com",
                    "/checkout",
                    b"test",
                    InteractionType::Checkout,
                )
                .unwrap();
            match verify(&flood_sig) {
                Ok(()) | Err(BridgeError::ReplayCacheSaturated) => {}
                Err(other) => panic!("unexpected verification error during flood: {other:?}"),
            }
        }

        // 3. Replay the original nonce. It MUST be detected as a replay; the LRU bug returned Ok
        //    here.
        let replayed = verify(&original);
        assert!(
            matches!(replayed, Err(BridgeError::ReplayAttack)),
            "post-flood replay must be rejected, got {replayed:?}"
        );
    }

    /// When the cache is full of unexpired nonces, fresh requests must be
    /// refused fail-closed rather than evicting a still-valid entry.
    #[test]
    fn test_replay_cache_fails_closed_when_saturated() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let signer = TapSigner::new(signing_key, "agent-1", "https://agent.com");
        let capacity: usize = 4;
        let verifier = TapVerifier::new(capacity);

        let verify = |sig: &crate::tap::signer::TapSignature| {
            verifier.verify_request(
                "POST",
                "merchant.com",
                "/checkout",
                b"test",
                &sig.signature,
                &sig.signature_input,
                &verifying_key,
            )
        };

        for _ in 0..capacity {
            let sig = signer
                .sign_request(
                    "POST",
                    "merchant.com",
                    "/checkout",
                    b"test",
                    InteractionType::Checkout,
                )
                .unwrap();
            verify(&sig).expect("first `capacity` requests fit in the cache");
        }

        let overflow = signer
            .sign_request("POST", "merchant.com", "/checkout", b"test", InteractionType::Checkout)
            .unwrap();
        let result = verify(&overflow);
        assert!(
            matches!(result, Err(BridgeError::ReplayCacheSaturated)),
            "saturated cache must reject fresh requests, got {result:?}"
        );
    }

    /// Once an entry's signature would itself fail timestamp validation, the
    /// TTL sweep is allowed to drop it and a re-use of that nonce becomes
    /// indistinguishable from a fresh signature. The signature timestamp guard
    /// catches the actual replay before this matters in practice.
    #[test]
    fn test_replay_cache_sweep_drops_expired_entries() {
        let mut cache = NonceCache::new(2);
        // Synthetic now=1000; entry expires at 100, well outside the
        // CLOCK_SKEW_TOLERANCE_SECS window.
        cache.entries.insert("stale".to_owned(), 100);
        cache.entries.insert("fresh".to_owned(), 1500);

        cache.sweep_expired(1000);

        assert!(!cache.entries.contains_key("stale"), "expired nonce must be evicted");
        assert!(cache.entries.contains_key("fresh"), "unexpired nonce must be retained");
    }
}
