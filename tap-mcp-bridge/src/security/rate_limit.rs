//! Token bucket rate limiting implementation.
//!
//! Provides rate limiting to prevent abuse and `DoS` attacks against TAP operations.
//! The token bucket algorithm allows bursts while maintaining a maximum average rate.
//!
//! # Token Bucket Algorithm
//!
//! The token bucket algorithm works as follows:
//! 1. Tokens are added to the bucket at a constant rate (`requests_per_second`)
//! 2. The bucket has a maximum capacity (`burst_size`)
//! 3. Each request consumes one token
//! 4. If no tokens available, the request is either rejected or waits
//!
//! # Examples
//!
//! ## Basic Rate Limiting
//!
//! ```rust
//! use tap_mcp_bridge::security::{RateLimitConfig, RateLimiter};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = RateLimitConfig::default();
//! let limiter = RateLimiter::new(config);
//!
//! // Try to acquire a token
//! match limiter.acquire().await {
//!     Ok(()) => println!("Request allowed"),
//!     Err(_) => println!("Rate limit exceeded"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Rate-Limited Signer
//!
//! ```rust,no_run
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::{
//!     security::{RateLimitConfig, RateLimitedSigner},
//!     tap::{InteractionType, TapSigner},
//! };
//!
//! # async fn example() -> tap_mcp_bridge::error::Result<()> {
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
//!
//! let config = RateLimitConfig { requests_per_second: 10, burst_size: 5 };
//!
//! let rate_limited_signer = RateLimitedSigner::new(signer, config);
//!
//! // This will automatically rate limit
//! let signature = rate_limited_signer
//!     .sign_request("POST", "merchant.com", "/checkout", b"body", InteractionType::Checkout)
//!     .await?;
//! # Ok(())
//! # }
//! ```

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::sync::Mutex;
use tracing::{debug, instrument, warn};

use crate::{
    error::{BridgeError, Result},
    tap::{InteractionType, TapSigner, signer::TapSignature},
};

/// Configuration for rate limiting.
///
/// Defines the maximum request rate and burst capacity for the token bucket algorithm.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Maximum number of requests per second.
    ///
    /// This is the rate at which tokens are added to the bucket.
    /// Default: 10 requests/second
    pub requests_per_second: u32,

    /// Maximum burst size.
    ///
    /// This is the maximum number of tokens the bucket can hold,
    /// allowing short bursts above the sustained rate.
    /// Default: 5 tokens
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self { requests_per_second: 10, burst_size: 5 }
    }
}

/// Token bucket rate limiter.
///
/// Thread-safe rate limiter using atomic operations for token tracking.
/// Tokens are represented as fixed-point integers (multiplied by 1000)
/// for precision in fractional token calculations.
///
/// # Thread Safety
///
/// This implementation is thread-safe:
/// - Token count uses atomic operations
/// - Last update time is protected by a mutex
/// - Safe to share across multiple threads using `Arc`
///
/// # Examples
///
/// ```rust
/// use tap_mcp_bridge::security::{RateLimitConfig, RateLimiter};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = RateLimitConfig { requests_per_second: 10, burst_size: 5 };
///
/// let limiter = RateLimiter::new(config);
///
/// // Non-blocking acquire (fails if no tokens)
/// limiter.acquire().await?;
///
/// // Blocking acquire (waits until token available)
/// limiter.acquire_blocking().await;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Current token count multiplied by 1000 for precision.
    tokens: AtomicU64,
    /// Last time tokens were refilled.
    last_update: Mutex<Instant>,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given configuration.
    ///
    /// The bucket starts full (with `burst_size` tokens available).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tap_mcp_bridge::security::{RateLimitConfig, RateLimiter};
    ///
    /// let config = RateLimitConfig::default();
    /// let limiter = RateLimiter::new(config);
    /// ```
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            // Start with full bucket (burst_size tokens * 1000 for precision)
            tokens: AtomicU64::new(u64::from(config.burst_size) * 1000),
            last_update: Mutex::new(Instant::now()),
        }
    }

    /// Attempts to acquire a token.
    ///
    /// Returns immediately with success if a token is available,
    /// or returns [`BridgeError::RateLimitExceeded`] if no tokens available.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::RateLimitExceeded`] if the rate limit is exceeded.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tap_mcp_bridge::security::{RateLimitConfig, RateLimiter};
    ///
    /// # async fn example() -> tap_mcp_bridge::error::Result<()> {
    /// let limiter = RateLimiter::new(RateLimitConfig::default());
    ///
    /// match limiter.acquire().await {
    ///     Ok(()) => println!("Request allowed"),
    ///     Err(_) => println!("Rate limited"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), level = "debug")]
    pub async fn acquire(&self) -> Result<()> {
        self.refill().await;

        let current_tokens = self.tokens.load(Ordering::Acquire);
        let required_tokens = 1000; // 1 token * 1000

        if current_tokens >= required_tokens {
            // Try to atomically subtract tokens
            if self
                .tokens
                .compare_exchange(
                    current_tokens,
                    current_tokens - required_tokens,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                debug!(
                    tokens_remaining = (current_tokens - required_tokens) / 1000,
                    "Token acquired"
                );
                Ok(())
            } else {
                // Another thread acquired the token first, retry
                warn!("Token acquisition race, rate limit exceeded");
                Err(BridgeError::RateLimitExceeded)
            }
        } else {
            warn!(tokens_available = current_tokens / 1000, "Rate limit exceeded");
            Err(BridgeError::RateLimitExceeded)
        }
    }

    /// Waits until a token is available and acquires it.
    ///
    /// Unlike [`acquire`](Self::acquire), this method blocks until a token
    /// becomes available rather than returning an error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tap_mcp_bridge::security::{RateLimitConfig, RateLimiter};
    ///
    /// # async fn example() {
    /// let limiter = RateLimiter::new(RateLimitConfig::default());
    ///
    /// // This will wait if necessary
    /// limiter.acquire_blocking().await;
    /// println!("Token acquired");
    /// # }
    /// ```
    #[instrument(skip(self), level = "debug")]
    pub async fn acquire_blocking(&self) {
        loop {
            if self.acquire().await.is_ok() {
                debug!("Token acquired (blocking)");
                return;
            }

            // Calculate wait time until next token
            let wait_duration = Duration::from_secs(1) / self.config.requests_per_second;
            debug!(?wait_duration, "Waiting for token");
            tokio::time::sleep(wait_duration).await;
        }
    }

    /// Refills tokens based on elapsed time since last update.
    ///
    /// This method is called automatically by [`acquire`](Self::acquire)
    /// and [`acquire_blocking`](Self::acquire_blocking).
    ///
    /// Tokens are added at the configured `requests_per_second` rate,
    /// up to the maximum `burst_size`.
    async fn refill(&self) {
        let mut last_update = self.last_update.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*last_update);

        // Calculate tokens to add (fractional tokens supported via * 1000)
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "elapsed time is always non-negative and result is bounded by burst_size"
        )]
        let tokens_to_add =
            (elapsed.as_secs_f64() * f64::from(self.config.requests_per_second) * 1000.0) as u64;

        if tokens_to_add > 0 {
            let max_tokens = u64::from(self.config.burst_size) * 1000;

            // Add tokens up to the maximum
            self.tokens
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    Some(current.saturating_add(tokens_to_add).min(max_tokens))
                })
                .expect("fetch_update always succeeds with Some");

            *last_update = now;

            debug!(
                tokens_added = tokens_to_add / 1000,
                current_tokens = self.tokens.load(Ordering::Acquire) / 1000,
                "Tokens refilled"
            );
        }
    }
}

/// Rate-limited wrapper for [`TapSigner`].
///
/// Wraps a [`TapSigner`] with automatic rate limiting to prevent
/// excessive signature generation.
///
/// # Examples
///
/// ```rust,no_run
/// use ed25519_dalek::SigningKey;
/// use tap_mcp_bridge::{
///     security::{RateLimitConfig, RateLimitedSigner},
///     tap::{InteractionType, TapSigner},
/// };
///
/// # async fn example() -> tap_mcp_bridge::error::Result<()> {
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
///
/// let config = RateLimitConfig { requests_per_second: 10, burst_size: 5 };
///
/// let rate_limited = RateLimitedSigner::new(signer, config);
///
/// // Rate-limited signing
/// let signature = rate_limited
///     .sign_request("POST", "merchant.com", "/checkout", b"body", InteractionType::Checkout)
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct RateLimitedSigner {
    signer: TapSigner,
    limiter: Arc<RateLimiter>,
}

impl RateLimitedSigner {
    /// Creates a new rate-limited signer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::{
    ///     security::{RateLimitConfig, RateLimitedSigner},
    ///     tap::TapSigner,
    /// };
    ///
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
    /// let config = RateLimitConfig::default();
    ///
    /// let rate_limited = RateLimitedSigner::new(signer, config);
    /// ```
    #[must_use]
    pub fn new(signer: TapSigner, config: RateLimitConfig) -> Self {
        Self { signer, limiter: Arc::new(RateLimiter::new(config)) }
    }

    /// Signs an HTTP request with rate limiting.
    ///
    /// Acquires a rate limit token before generating the signature.
    /// If the rate limit is exceeded, returns [`BridgeError::RateLimitExceeded`].
    ///
    /// # Errors
    ///
    /// Returns error if rate limit is exceeded or signature generation fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::{
    ///     security::{RateLimitConfig, RateLimitedSigner},
    ///     tap::{InteractionType, TapSigner},
    /// };
    ///
    /// # async fn example() -> tap_mcp_bridge::error::Result<()> {
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
    /// let rate_limited = RateLimitedSigner::new(signer, RateLimitConfig::default());
    ///
    /// let signature = rate_limited
    ///     .sign_request("POST", "merchant.com", "/checkout", b"body", InteractionType::Checkout)
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, body), fields(method, authority, path), level = "debug")]
    pub async fn sign_request(
        &self,
        method: &str,
        authority: &str,
        path: &str,
        body: &[u8],
        interaction_type: InteractionType,
    ) -> Result<TapSignature> {
        // Acquire rate limit token
        self.limiter.acquire().await?;

        debug!("Rate limit token acquired, generating signature");

        // Generate signature
        self.signer.sign_request(method, authority, path, body, interaction_type)
    }

    /// Signs an HTTP request, blocking until rate limit allows.
    ///
    /// Unlike [`sign_request`](Self::sign_request), this method waits
    /// for a rate limit token to become available rather than returning
    /// an error if the limit is exceeded.
    ///
    /// # Errors
    ///
    /// Returns error if signature generation fails (not for rate limiting).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::{
    ///     security::{RateLimitConfig, RateLimitedSigner},
    ///     tap::{InteractionType, TapSigner},
    /// };
    ///
    /// # async fn example() -> tap_mcp_bridge::error::Result<()> {
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
    /// let rate_limited = RateLimitedSigner::new(signer, RateLimitConfig::default());
    ///
    /// // This will wait if rate limit exceeded
    /// let signature = rate_limited
    ///     .sign_request_blocking(
    ///         "POST",
    ///         "merchant.com",
    ///         "/checkout",
    ///         b"body",
    ///         InteractionType::Checkout,
    ///     )
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self, body), fields(method, authority, path), level = "debug")]
    pub async fn sign_request_blocking(
        &self,
        method: &str,
        authority: &str,
        path: &str,
        body: &[u8],
        interaction_type: InteractionType,
    ) -> Result<TapSignature> {
        // Wait for rate limit token
        self.limiter.acquire_blocking().await;

        debug!("Rate limit token acquired (blocking), generating signature");

        // Generate signature
        self.signer.sign_request(method, authority, path, body, interaction_type)
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    reason = "test code uses panic for assertion on unexpected errors"
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_allows_requests_within_limit() {
        let config = RateLimitConfig { requests_per_second: 10, burst_size: 5 };

        let limiter = RateLimiter::new(config);

        // Should allow burst_size requests immediately
        for i in 0..config.burst_size {
            assert!(limiter.acquire().await.is_ok(), "Request {i} should be allowed");
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_rejects_excess_requests() {
        let config = RateLimitConfig { requests_per_second: 10, burst_size: 2 };

        let limiter = RateLimiter::new(config);

        // Exhaust burst capacity
        assert!(limiter.acquire().await.is_ok());
        assert!(limiter.acquire().await.is_ok());

        // Next request should be rate limited
        assert!(
            matches!(limiter.acquire().await, Err(BridgeError::RateLimitExceeded)),
            "Should be rate limited after burst exhausted"
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_refills_over_time() {
        let config = RateLimitConfig { requests_per_second: 10, burst_size: 1 };

        let limiter = RateLimiter::new(config);

        // Consume initial token
        assert!(limiter.acquire().await.is_ok());

        // Should be rate limited immediately
        assert!(limiter.acquire().await.is_err());

        // Wait for refill (100ms = 0.1s * 10 req/s = 1 token)
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should now have a token available
        assert!(limiter.acquire().await.is_ok(), "Token should be refilled after waiting");
    }

    #[tokio::test]
    async fn test_rate_limiter_caps_at_burst_size() {
        let config = RateLimitConfig { requests_per_second: 100, burst_size: 2 };

        let limiter = RateLimiter::new(config);

        // Wait long enough to generate many tokens
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Should only allow burst_size requests (bucket capacity)
        assert!(limiter.acquire().await.is_ok());
        assert!(limiter.acquire().await.is_ok());
        assert!(limiter.acquire().await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_blocking_waits() {
        let config = RateLimitConfig { requests_per_second: 10, burst_size: 1 };

        let limiter = RateLimiter::new(config);

        // Consume initial token
        assert!(limiter.acquire().await.is_ok());

        // This should block briefly then succeed
        let start = Instant::now();
        limiter.acquire_blocking().await;
        let elapsed = start.elapsed();

        // Should have waited at least some time (less than 200ms for 10 req/s)
        assert!(elapsed >= Duration::from_millis(50), "Should wait for token refill");
        assert!(elapsed < Duration::from_millis(300), "Should not wait too long");
    }

    #[tokio::test]
    async fn test_rate_limiter_concurrent_access() {
        use std::sync::Arc;

        let config = RateLimitConfig { requests_per_second: 10, burst_size: 3 };

        let limiter = Arc::new(RateLimiter::new(config));
        let mut handles = vec![];

        // Spawn 5 concurrent tasks trying to acquire tokens
        for _ in 0..5 {
            let limiter_clone = Arc::clone(&limiter);
            let handle = tokio::spawn(async move { limiter_clone.acquire().await });
            handles.push(handle);
        }

        // Collect results
        let mut successes = 0;
        let mut failures = 0;

        for handle in handles {
            match handle.await.unwrap() {
                Ok(()) => successes += 1,
                Err(BridgeError::RateLimitExceeded) => failures += 1,
                Err(e) => panic!("Unexpected error: {e:?}"),
            }
        }

        // Should allow exactly burst_size requests
        assert_eq!(successes, 3, "Should allow burst_size requests");
        assert_eq!(failures, 2, "Should reject excess requests");
    }

    #[tokio::test]
    async fn test_rate_limited_signer_enforces_limit() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let config = RateLimitConfig { requests_per_second: 10, burst_size: 2 };

        let rate_limited = RateLimitedSigner::new(signer, config);

        // First two requests should succeed
        assert!(
            rate_limited
                .sign_request("POST", "merchant.com", "/api", b"body", InteractionType::Checkout)
                .await
                .is_ok()
        );
        assert!(
            rate_limited
                .sign_request("POST", "merchant.com", "/api", b"body", InteractionType::Checkout)
                .await
                .is_ok()
        );

        // Third should be rate limited
        assert!(matches!(
            rate_limited
                .sign_request("POST", "merchant.com", "/api", b"body", InteractionType::Checkout)
                .await,
            Err(BridgeError::RateLimitExceeded)
        ));
    }

    #[tokio::test]
    async fn test_rate_limited_signer_blocking_waits() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let config = RateLimitConfig { requests_per_second: 10, burst_size: 1 };

        let rate_limited = RateLimitedSigner::new(signer, config);

        // Consume initial token
        assert!(
            rate_limited
                .sign_request("POST", "merchant.com", "/api", b"body", InteractionType::Checkout)
                .await
                .is_ok()
        );

        // Blocking request should wait and succeed
        let start = Instant::now();
        assert!(
            rate_limited
                .sign_request_blocking(
                    "POST",
                    "merchant.com",
                    "/api",
                    b"body",
                    InteractionType::Checkout
                )
                .await
                .is_ok()
        );
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_millis(50), "Should wait for token");
    }

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.requests_per_second, 10);
        assert_eq!(config.burst_size, 5);
    }

    #[tokio::test]
    async fn test_rate_limiter_with_burst_size_one() {
        let config = RateLimitConfig { requests_per_second: 10, burst_size: 1 };

        let limiter = RateLimiter::new(config);

        // Should allow exactly one request
        assert!(limiter.acquire().await.is_ok());

        // Second request should be rate limited
        assert!(matches!(limiter.acquire().await, Err(BridgeError::RateLimitExceeded)));
    }

    #[tokio::test]
    async fn test_rate_limiter_very_high_rate() {
        let config = RateLimitConfig { requests_per_second: 1000, burst_size: 10 };

        let limiter = RateLimiter::new(config);

        // Should allow burst_size requests immediately
        for i in 0..config.burst_size {
            assert!(limiter.acquire().await.is_ok(), "Request {i} should be allowed");
        }

        // Next should be rate limited
        assert!(matches!(limiter.acquire().await, Err(BridgeError::RateLimitExceeded)));
    }

    #[tokio::test]
    async fn test_rate_limiter_fractional_refill() {
        let config = RateLimitConfig {
            requests_per_second: 2, // 0.5 seconds per token
            burst_size: 1,
        };

        let limiter = RateLimiter::new(config);

        // Consume initial token
        assert!(limiter.acquire().await.is_ok());

        // Wait for partial refill (250ms = 0.5 tokens at 2 req/s)
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Should still be rate limited (need full token)
        assert!(matches!(limiter.acquire().await, Err(BridgeError::RateLimitExceeded)));

        // Wait another 250ms (total 500ms = 1 token)
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Now should have a full token
        assert!(limiter.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_precision_with_small_intervals() {
        let config = RateLimitConfig {
            requests_per_second: 100, // 10ms per token
            burst_size: 2,
        };

        let limiter = RateLimiter::new(config);

        // Use up burst
        assert!(limiter.acquire().await.is_ok());
        assert!(limiter.acquire().await.is_ok());
        assert!(matches!(limiter.acquire().await, Err(BridgeError::RateLimitExceeded)));

        // Wait for exactly one token refill
        tokio::time::sleep(Duration::from_millis(15)).await;

        // Should have one token available
        assert!(limiter.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limited_signer_preserves_signature_correctness() {
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let config = RateLimitConfig { requests_per_second: 100, burst_size: 10 };

        let rate_limited = RateLimitedSigner::new(signer, config);

        // Generate two signatures for same input
        let sig1 = rate_limited
            .sign_request("POST", "merchant.com", "/api", b"test body", InteractionType::Checkout)
            .await
            .unwrap();

        let sig2 = rate_limited
            .sign_request("POST", "merchant.com", "/api", b"test body", InteractionType::Checkout)
            .await
            .unwrap();

        // Signatures should be different (different nonces)
        assert_ne!(sig1.signature, sig2.signature);

        // But both should be valid signatures
        assert!(!sig1.signature.is_empty());
        assert!(!sig2.signature.is_empty());
    }
}
