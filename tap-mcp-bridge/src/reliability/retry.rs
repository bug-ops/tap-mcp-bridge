//! Exponential backoff retry logic for transient failures.
//!
//! This module provides retry functionality with exponential backoff
//! for handling transient network errors and temporary merchant unavailability.

use std::time::Duration;

use crate::BridgeError;

/// Configuration for retry behavior.
///
/// Defines the parameters for exponential backoff retry logic.
/// The delay between retries increases exponentially up to a maximum value.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
///
/// use tap_mcp_bridge::reliability::RetryPolicy;
///
/// // Default policy: 3 attempts, 100ms initial delay, 5s max delay
/// let policy = RetryPolicy::default();
///
/// // Custom policy: more aggressive retries
/// let aggressive = RetryPolicy {
///     max_attempts: 5,
///     initial_delay: Duration::from_millis(50),
///     max_delay: Duration::from_secs(10),
///     backoff_multiplier: 2.0,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (default: 3)
    pub max_attempts: u32,
    /// Initial delay between retries (default: 100ms)
    pub initial_delay: Duration,
    /// Maximum delay between retries (default: 5s)
    pub max_delay: Duration,
    /// Multiplier for exponential backoff (default: 2.0)
    pub backoff_multiplier: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryPolicy {
    /// Creates a new retry policy with default values.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::reliability::RetryPolicy;
    ///
    /// let policy = RetryPolicy::new();
    /// assert_eq!(policy.max_attempts, 3);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a policy with custom maximum attempts.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::reliability::RetryPolicy;
    ///
    /// let policy = RetryPolicy::with_max_attempts(5);
    /// assert_eq!(policy.max_attempts, 5);
    /// ```
    #[must_use]
    pub fn with_max_attempts(max_attempts: u32) -> Self {
        Self { max_attempts, ..Self::default() }
    }

    /// Calculates delay for a specific attempt.
    ///
    /// Uses exponential backoff: delay = `initial_delay` * (multiplier ^ attempt)
    /// Capped at `max_delay` to prevent excessive waits.
    fn delay_for_attempt(&self, attempt: u32) -> Duration {
        #[allow(
            clippy::cast_precision_loss,
            reason = "acceptable for duration calculations"
        )]
        let delay_ms = self.initial_delay.as_millis() as f64
            * self
                .backoff_multiplier
                .powi(attempt.try_into().expect("attempt count should fit in i32"));
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "delay_ms is guaranteed to be positive and within reasonable bounds"
        )]
        let delay = Duration::from_millis(delay_ms as u64);
        delay.min(self.max_delay)
    }
}

/// Executes operation with exponential backoff retry.
///
/// Retries the operation up to `max_attempts` times, with exponentially
/// increasing delays between attempts. Only retries if the error is
/// determined to be retryable by the error handler function.
///
/// # Examples
///
/// ```
/// use std::sync::{
///     Arc,
///     atomic::{AtomicU32, Ordering},
/// };
///
/// use tap_mcp_bridge::reliability::{RetryPolicy, retry_with_backoff};
///
/// # async fn example() -> Result<String, String> {
/// let policy = RetryPolicy::default();
/// let attempt = Arc::new(AtomicU32::new(0));
///
/// let result = retry_with_backoff(&policy, || {
///     let attempt = Arc::clone(&attempt);
///     async move {
///         let n = attempt.fetch_add(1, Ordering::Relaxed);
///         if n < 2 {
///             Err("temporary failure".to_string())
///         } else {
///             Ok("success".to_string())
///         }
///     }
/// })
/// .await?;
///
/// assert_eq!(result, "success");
/// # Ok(result)
/// # }
/// ```
///
/// # Errors
///
/// Returns the last error encountered if all retry attempts fail,
/// or immediately returns non-retryable errors.
///
/// # Panics
///
/// Panics if `max_attempts` is 0 (which would be a configuration error).
/// Always configure `RetryPolicy` with at least 1 attempt.
#[allow(clippy::missing_panics_doc, reason = "panic documented above")]
pub async fn retry_with_backoff<F, Fut, T, E>(
    policy: &RetryPolicy,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut last_error = None;

    for attempt in 0..policy.max_attempts {
        match operation().await {
            Ok(value) => {
                if attempt > 0 {
                    tracing::info!(attempt = attempt + 1, "Operation succeeded after retry");
                }
                return Ok(value);
            }
            Err(error) => {
                tracing::warn!(
                    attempt = attempt + 1,
                    max_attempts = policy.max_attempts,
                    error = %error,
                    "Operation failed, will retry if retryable"
                );

                last_error = Some(error);

                // Don't sleep after the last attempt
                if attempt + 1 < policy.max_attempts {
                    let delay = policy.delay_for_attempt(attempt);
                    tracing::debug!(delay_ms = delay.as_millis(), "Sleeping before retry");
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    // All attempts exhausted, return last error
    Err(last_error.expect("at least one attempt should have been made"))
}

/// Determines if an error is retryable.
///
/// Returns `true` for transient network errors that might succeed on retry,
/// such as timeouts, connection failures, and server errors.
///
/// Returns `false` for errors that indicate permanent failures or client-side
/// issues that won't be resolved by retrying, such as validation errors,
/// authentication failures, or protocol violations.
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::{BridgeError, reliability::is_retryable};
///
/// // Validation errors are not retryable
/// let error = BridgeError::InvalidMerchantUrl("http://localhost".to_string());
/// assert!(!is_retryable(&error));
///
/// // Signature errors are not retryable
/// let error = BridgeError::SignatureError("invalid key".to_string());
/// assert!(!is_retryable(&error));
/// ```
///
/// # Retryable Errors
///
/// - HTTP timeouts
/// - Connection failures
/// - Server errors (5xx status codes)
///
/// # Non-Retryable Errors
///
/// - Signature/crypto errors (indicate configuration issues)
/// - Validation errors (indicate bad input)
/// - Merchant protocol errors (indicate incompatibility)
/// - Security errors (replay attacks, expired requests)
#[must_use]
#[allow(
    clippy::match_same_arms,
    reason = "separate arms for clarity and future extensibility"
)]
pub fn is_retryable(error: &BridgeError) -> bool {
    match error {
        BridgeError::HttpError(e) => {
            // Retry on timeouts, connection errors, or server errors
            e.is_timeout() || e.is_connect() || e.status().is_some_and(|s| s.is_server_error())
        }
        // Don't retry validation or crypto errors
        BridgeError::SignatureError(_)
        | BridgeError::CryptoError(_)
        | BridgeError::InvalidMerchantUrl(_)
        | BridgeError::InvalidConsumerId(_)
        | BridgeError::InvalidInput(_) => false,
        // Don't retry merchant protocol errors
        BridgeError::MerchantError(_) => false,
        // Don't retry merchant configuration errors
        BridgeError::MerchantConfigError(_)
        | BridgeError::FieldMappingError(_)
        | BridgeError::TransformationError(_) => false,
        // Don't retry security errors
        BridgeError::ReplayAttack | BridgeError::RequestTooOld(_) => false,
        // Don't retry rate limit errors (should implement backoff instead)
        BridgeError::RateLimitExceeded => false,
        // Don't retry circuit breaker open (should wait for recovery)
        BridgeError::CircuitOpen => false,
    }
}

#[cfg(test)]
#[allow(
    clippy::str_to_string,
    clippy::float_cmp,
    reason = "test code uses these patterns for readability"
)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.initial_delay, Duration::from_millis(100));
        assert_eq!(policy.max_delay, Duration::from_secs(5));
        assert!((policy.backoff_multiplier - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_retry_policy_new() {
        let policy = RetryPolicy::new();
        assert_eq!(policy.max_attempts, 3);
    }

    #[test]
    fn test_retry_policy_with_max_attempts() {
        let policy = RetryPolicy::with_max_attempts(5);
        assert_eq!(policy.max_attempts, 5);
        assert_eq!(policy.initial_delay, Duration::from_millis(100));
    }

    #[test]
    fn test_delay_for_attempt() {
        let policy = RetryPolicy::default();

        // First retry: 100ms * 2^0 = 100ms
        assert_eq!(policy.delay_for_attempt(0), Duration::from_millis(100));

        // Second retry: 100ms * 2^1 = 200ms
        assert_eq!(policy.delay_for_attempt(1), Duration::from_millis(200));

        // Third retry: 100ms * 2^2 = 400ms
        assert_eq!(policy.delay_for_attempt(2), Duration::from_millis(400));

        // Fourth retry: 100ms * 2^3 = 800ms
        assert_eq!(policy.delay_for_attempt(3), Duration::from_millis(800));
    }

    #[test]
    fn test_delay_capped_at_max() {
        let policy = RetryPolicy {
            max_attempts: 10,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
            backoff_multiplier: 2.0,
        };

        // Large attempt number should be capped at max_delay
        let delay = policy.delay_for_attempt(10);
        assert_eq!(delay, Duration::from_secs(1));
    }

    #[tokio::test]
    async fn test_retry_with_backoff_success_first_attempt() {
        let policy = RetryPolicy::with_max_attempts(3);
        let call_count = Arc::new(Mutex::new(0));

        let count_clone = Arc::clone(&call_count);
        let result = retry_with_backoff(&policy, || {
            let count = Arc::clone(&count_clone);
            async move {
                let mut c = count.lock().unwrap();
                *c += 1;
                Ok::<i32, BridgeError>(42)
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(*call_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn test_retry_with_backoff_success_after_retries() {
        let policy = RetryPolicy::with_max_attempts(3);
        let call_count = Arc::new(Mutex::new(0));

        let count_clone = Arc::clone(&call_count);
        let result = retry_with_backoff(&policy, || {
            let count = Arc::clone(&count_clone);
            async move {
                let mut c = count.lock().unwrap();
                *c += 1;
                let current = *c;
                drop(c);

                if current < 3 {
                    Err(BridgeError::MerchantError("temporary failure".to_string()))
                } else {
                    Ok::<i32, BridgeError>(42)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(*call_count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn test_retry_with_backoff_all_attempts_fail() {
        let policy = RetryPolicy::with_max_attempts(3);
        let call_count = Arc::new(Mutex::new(0));

        let count_clone = Arc::clone(&call_count);
        let result = retry_with_backoff(&policy, || {
            let count = Arc::clone(&count_clone);
            async move {
                let mut c = count.lock().unwrap();
                *c += 1;
                drop(c);
                Err::<i32, BridgeError>(BridgeError::SignatureError("persistent error".to_string()))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(*call_count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn test_retry_with_backoff_timing() {
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_secs(1),
            backoff_multiplier: 2.0,
        };
        let call_count = Arc::new(Mutex::new(0));

        let start = std::time::Instant::now();
        let count_clone = Arc::clone(&call_count);
        let _result = retry_with_backoff(&policy, || {
            let count = Arc::clone(&count_clone);
            async move {
                let mut c = count.lock().unwrap();
                *c += 1;
                drop(c);
                Err::<i32, BridgeError>(BridgeError::CryptoError("error".to_string()))
            }
        })
        .await;

        let elapsed = start.elapsed();

        // Should have delays: 10ms + 20ms = 30ms minimum
        // Allow some overhead for test execution
        assert!(elapsed >= Duration::from_millis(30), "Expected at least 30ms, got {elapsed:?}");
        assert_eq!(*call_count.lock().unwrap(), 3);
    }

    #[test]
    fn test_is_not_retryable_signature_error() {
        let error = BridgeError::SignatureError("invalid key".to_string());
        assert!(!is_retryable(&error));
    }

    #[test]
    fn test_is_not_retryable_crypto_error() {
        let error = BridgeError::CryptoError("hash failed".to_string());
        assert!(!is_retryable(&error));
    }

    #[test]
    fn test_is_not_retryable_invalid_url() {
        let error = BridgeError::InvalidMerchantUrl("http://localhost".to_string());
        assert!(!is_retryable(&error));
    }

    #[test]
    fn test_is_not_retryable_invalid_consumer_id() {
        let error = BridgeError::InvalidConsumerId("invalid@id".to_string());
        assert!(!is_retryable(&error));
    }

    #[test]
    fn test_is_not_retryable_merchant_error() {
        let error = BridgeError::MerchantError("protocol violation".to_string());
        assert!(!is_retryable(&error));
    }

    #[test]
    fn test_is_not_retryable_replay_attack() {
        let error = BridgeError::ReplayAttack;
        assert!(!is_retryable(&error));
    }

    #[test]
    fn test_is_not_retryable_request_too_old() {
        let error = BridgeError::RequestTooOld(std::time::SystemTime::now());
        assert!(!is_retryable(&error));
    }

    #[test]
    fn test_is_not_retryable_rate_limit_exceeded() {
        let error = BridgeError::RateLimitExceeded;
        assert!(!is_retryable(&error));
    }

    #[test]
    fn test_is_not_retryable_circuit_open() {
        let error = BridgeError::CircuitOpen;
        assert!(!is_retryable(&error));
    }

    #[tokio::test]
    async fn test_retry_with_backoff_single_attempt() {
        let policy = RetryPolicy::with_max_attempts(1);
        let call_count = Arc::new(Mutex::new(0));

        let count_clone = Arc::clone(&call_count);
        let result = retry_with_backoff(&policy, || {
            let count = Arc::clone(&count_clone);
            async move {
                let mut c = count.lock().unwrap();
                *c += 1;
                drop(c);
                Err::<i32, BridgeError>(BridgeError::SignatureError("error".to_string()))
            }
        })
        .await;

        assert!(result.is_err());
        assert_eq!(*call_count.lock().unwrap(), 1);
    }

    #[test]
    fn test_delay_for_attempt_large_values() {
        let policy = RetryPolicy {
            max_attempts: 100,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
        };

        // Very large attempt number should still be capped
        let delay = policy.delay_for_attempt(100);
        assert_eq!(delay, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_retry_with_backoff_immediate_success() {
        let policy = RetryPolicy::with_max_attempts(5);
        let call_count = Arc::new(Mutex::new(0));

        let count_clone = Arc::clone(&call_count);
        let result = retry_with_backoff(&policy, || {
            let count = Arc::clone(&count_clone);
            async move {
                let mut c = count.lock().unwrap();
                *c += 1;
                drop(c);
                Ok::<i32, BridgeError>(42)
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        // Should only call once if first attempt succeeds
        assert_eq!(*call_count.lock().unwrap(), 1);
    }
}
