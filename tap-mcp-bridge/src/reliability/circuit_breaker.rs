//! Circuit breaker pattern for protecting against cascading failures.
//!
//! The circuit breaker prevents repeated calls to a failing service, allowing it time
//! to recover while protecting the system from resource exhaustion. It acts like an
//! electrical circuit breaker that trips when too many errors occur.
//!
//! # States
//!
//! - **Closed**: Normal operation, requests flow through
//! - **Open**: Too many failures, requests are immediately rejected
//! - **`HalfOpen`**: Testing recovery, limited requests allowed
//!
//! # State Transitions
//!
//! ```text
//! Closed ──[failure_threshold failures]──> Open
//!   ▲                                        │
//!   │                                        │ [reset_timeout expires]
//!   │                                        ▼
//!   └──[success_threshold successes]── HalfOpen
//!          [any failure] ──────────────────> Open
//! ```
//!
//! # Examples
//!
//! ```rust
//! use std::time::Duration;
//!
//! use tap_mcp_bridge::reliability::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = CircuitBreakerConfig {
//!     failure_threshold: 5,
//!     success_threshold: 2,
//!     reset_timeout: Duration::from_secs(60),
//! };
//!
//! let breaker = CircuitBreaker::new(config);
//!
//! // Normal operation
//! let result = breaker.call(|| async { Ok::<_, String>("success".to_string()) }).await;
//!
//! assert!(result.is_ok());
//! assert_eq!(breaker.state(), CircuitState::Closed);
//! # Ok(())
//! # }
//! ```

use std::{
    sync::atomic::{AtomicU8, AtomicU64, Ordering},
    time::{Duration, Instant},
};

use thiserror::Error;
use tokio::sync::RwLock;

/// Circuit breaker state.
///
/// The circuit breaker transitions between states based on operation success/failure rates:
///
/// - **Closed (0)**: Normal operation, all requests allowed
/// - **Open (1)**: Circuit is tripped, all requests rejected immediately
/// - **`HalfOpen` (2)**: Testing recovery, limited requests allowed
///
/// State values are numeric (u8) for atomic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CircuitState {
    /// Normal operation - all requests allowed.
    ///
    /// The circuit starts in this state. It remains closed as long as the failure
    /// rate stays below the threshold.
    Closed = 0,

    /// Circuit is open - all requests rejected immediately.
    ///
    /// After reaching the failure threshold, the circuit opens to prevent further
    /// damage. Requests are rejected without calling the underlying operation.
    Open = 1,

    /// Testing recovery - limited requests allowed.
    ///
    /// After the reset timeout expires, the circuit enters half-open state to test
    /// if the underlying service has recovered. A few successful requests will close
    /// the circuit; any failure will reopen it.
    HalfOpen = 2,
}

/// Configuration for circuit breaker.
///
/// These parameters control when the circuit breaker opens, how long it stays open,
/// and what constitutes recovery.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
///
/// use tap_mcp_bridge::reliability::CircuitBreakerConfig;
///
/// // Conservative settings - trip quickly, recover slowly
/// let conservative = CircuitBreakerConfig {
///     failure_threshold: 3,
///     success_threshold: 5,
///     reset_timeout: Duration::from_secs(120),
/// };
///
/// // Aggressive settings - tolerate more failures, recover quickly
/// let aggressive = CircuitBreakerConfig {
///     failure_threshold: 10,
///     success_threshold: 2,
///     reset_timeout: Duration::from_secs(30),
/// };
///
/// // Default settings (balanced)
/// let default = CircuitBreakerConfig::default();
/// assert_eq!(default.failure_threshold, 5);
/// ```
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    ///
    /// Once this many failures occur in the Closed state, the circuit transitions
    /// to Open. Lower values make the circuit more sensitive to failures.
    ///
    /// Default: 5
    pub failure_threshold: u64,

    /// Number of consecutive successes in `HalfOpen` state to close the circuit.
    ///
    /// After the circuit enters `HalfOpen`, this many successful operations are required
    /// before returning to Closed state. Higher values require stronger evidence of
    /// recovery.
    ///
    /// Default: 2
    pub success_threshold: u64,

    /// Time to wait before transitioning from Open to `HalfOpen`.
    ///
    /// After the circuit opens, it waits this duration before attempting recovery.
    /// Longer timeouts give the underlying service more time to recover.
    ///
    /// Default: 60 seconds
    pub reset_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    /// Creates a circuit breaker configuration with balanced defaults.
    ///
    /// Default values:
    /// - `failure_threshold`: 5 consecutive failures
    /// - `success_threshold`: 2 consecutive successes
    /// - `reset_timeout`: 60 seconds
    ///
    /// These defaults provide reasonable protection for most use cases.
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            reset_timeout: Duration::from_secs(60),
        }
    }
}

/// Circuit breaker for protecting against cascading failures.
///
/// The circuit breaker wraps operations that might fail and automatically stops
/// calling them when the failure rate exceeds a threshold. This prevents:
///
/// - Resource exhaustion from repeated failed requests
/// - Cascading failures across system components
/// - Slow recovery due to constant load on failing services
///
/// # Thread Safety
///
/// `CircuitBreaker` is thread-safe and can be safely shared across threads using `Arc`.
/// All internal state uses atomic operations and `RwLock` for synchronization.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
///
/// use tap_mcp_bridge::reliability::{CircuitBreaker, CircuitBreakerConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let breaker = CircuitBreaker::new(CircuitBreakerConfig::default());
///
/// // Successful operation
/// let result = breaker.call(|| async { Ok::<_, String>("data".to_string()) }).await;
///
/// assert!(result.is_ok());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Current circuit state (Closed=0, Open=1, HalfOpen=2).
    ///
    /// Uses `AtomicU8` for lock-free state checks. The value corresponds to the
    /// discriminant of `CircuitState` enum.
    state: AtomicU8,

    /// Count of consecutive failures in current state.
    ///
    /// Reset to 0 when transitioning to `HalfOpen` or Closed states.
    failure_count: AtomicU64,

    /// Count of consecutive successes in `HalfOpen` state.
    ///
    /// Only used in `HalfOpen` state to track recovery progress.
    success_count: AtomicU64,

    /// Timestamp of the last failure.
    ///
    /// Used to determine when `reset_timeout` has expired for Open -> `HalfOpen` transition.
    /// `RwLock` is used because `Instant` is not atomic.
    last_failure: RwLock<Option<Instant>>,

    /// Circuit breaker configuration.
    config: CircuitBreakerConfig,
}

impl CircuitBreaker {
    /// Creates a new circuit breaker with the given configuration.
    ///
    /// The circuit starts in the Closed state with zero failure/success counts.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::time::Duration;
    ///
    /// use tap_mcp_bridge::reliability::{CircuitBreaker, CircuitBreakerConfig};
    ///
    /// let config = CircuitBreakerConfig {
    ///     failure_threshold: 5,
    ///     success_threshold: 2,
    ///     reset_timeout: Duration::from_secs(60),
    /// };
    ///
    /// let breaker = CircuitBreaker::new(config);
    /// ```
    #[must_use]
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: AtomicU8::new(CircuitState::Closed as u8),
            failure_count: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            last_failure: RwLock::new(None),
            config,
        }
    }

    /// Returns the current state of the circuit breaker.
    ///
    /// This is a fast, lock-free read of the current state.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tap_mcp_bridge::reliability::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
    ///
    /// let breaker = CircuitBreaker::new(CircuitBreakerConfig::default());
    /// assert_eq!(breaker.state(), CircuitState::Closed);
    /// ```
    #[allow(
        clippy::unreachable,
        reason = "state values are tightly controlled to 0-2 range"
    )]
    pub fn state(&self) -> CircuitState {
        match self.state.load(Ordering::Relaxed) {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => unreachable!("invalid circuit state"),
        }
    }

    /// Executes an operation through the circuit breaker.
    ///
    /// This method wraps the given operation with circuit breaker logic:
    ///
    /// 1. **If Open**: Check if reset timeout expired -> transition to `HalfOpen` if yes, reject if
    ///    no
    /// 2. **If `HalfOpen` or Closed**: Execute operation
    /// 3. **On success**: Record success, possibly close circuit
    /// 4. **On failure**: Record failure, possibly open circuit
    ///
    /// # Type Parameters
    ///
    /// - `F`: Closure that returns a future
    /// - `Fut`: Future type returned by the closure
    /// - `T`: Success type
    /// - `E`: Error type from the operation
    ///
    /// # Errors
    ///
    /// Returns [`CircuitBreakerError::Open`] if the circuit is open and reset timeout
    /// has not expired. Returns [`CircuitBreakerError::Inner`] if the operation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use tap_mcp_bridge::reliability::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let breaker = CircuitBreaker::new(CircuitBreakerConfig::default());
    ///
    /// // Successful operation
    /// let result = breaker.call(|| async { Ok::<_, String>("success".to_string()) }).await;
    ///
    /// match result {
    ///     Ok(value) => println!("Got: {}", value),
    ///     Err(CircuitBreakerError::Open) => println!("Circuit is open"),
    ///     Err(CircuitBreakerError::Inner(e)) => println!("Operation failed: {}", e),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn call<F, Fut, T, E>(&self, operation: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        // Check if circuit should transition from Open to HalfOpen
        if self.state() == CircuitState::Open {
            let last_failure = self.last_failure.read().await;
            if let Some(time) = *last_failure {
                if time.elapsed() >= self.config.reset_timeout {
                    drop(last_failure);
                    self.transition_to_half_open();
                } else {
                    return Err(CircuitBreakerError::Open);
                }
            }
        }

        // Reject if circuit is still open after timeout check
        if self.state() == CircuitState::Open {
            return Err(CircuitBreakerError::Open);
        }

        // Execute operation and record result
        match operation().await {
            Ok(result) => {
                self.record_success();
                Ok(result)
            }
            Err(e) => {
                self.record_failure().await;
                Err(CircuitBreakerError::Inner(e))
            }
        }
    }

    /// Records a successful operation.
    ///
    /// In `HalfOpen` state, increments success count and transitions to Closed
    /// if success threshold is reached. In other states, this is a no-op.
    fn record_success(&self) {
        self.success_count.fetch_add(1, Ordering::Relaxed);

        if self.state() == CircuitState::HalfOpen
            && self.success_count.load(Ordering::Relaxed) >= self.config.success_threshold
        {
            self.transition_to_closed();
        }
    }

    /// Records a failed operation.
    ///
    /// Increments failure count and updates `last_failure` timestamp.
    /// In `HalfOpen` state, any failure immediately reopens the circuit.
    /// In Closed state, opens circuit if failure threshold is reached.
    async fn record_failure(&self) {
        self.failure_count.fetch_add(1, Ordering::Relaxed);
        *self.last_failure.write().await = Some(Instant::now());

        // Open circuit if in HalfOpen state (any failure reopens) or if threshold reached
        let should_open = self.state() == CircuitState::HalfOpen
            || self.failure_count.load(Ordering::Relaxed) >= self.config.failure_threshold;

        if should_open {
            self.transition_to_open();
        }
    }

    /// Transitions the circuit to Open state.
    ///
    /// Logs a warning and sets state to Open. This happens when:
    /// - Failure threshold is reached in Closed state
    /// - Any failure occurs in `HalfOpen` state
    fn transition_to_open(&self) {
        self.state.store(CircuitState::Open as u8, Ordering::Relaxed);
        tracing::warn!("Circuit breaker opened due to failures");
    }

    /// Transitions the circuit to `HalfOpen` state.
    ///
    /// Resets success count and logs info message. This happens when:
    /// - Reset timeout expires in Open state
    fn transition_to_half_open(&self) {
        self.state.store(CircuitState::HalfOpen as u8, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
        tracing::info!("Circuit breaker half-open, testing recovery");
    }

    /// Transitions the circuit to Closed state.
    ///
    /// Resets all counters and logs info message. This happens when:
    /// - Success threshold is reached in `HalfOpen` state
    fn transition_to_closed(&self) {
        self.state.store(CircuitState::Closed as u8, Ordering::Relaxed);
        self.failure_count.store(0, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
        tracing::info!("Circuit breaker closed, normal operation resumed");
    }
}

/// Error returned by circuit breaker.
///
/// This error type distinguishes between:
/// - Circuit being open (operation not attempted)
/// - Inner operation failure (operation attempted but failed)
///
/// # Examples
///
/// ```rust
/// use tap_mcp_bridge::reliability::{CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError};
///
/// # async fn example() {
/// let breaker = CircuitBreaker::new(CircuitBreakerConfig::default());
///
/// let result = breaker.call(|| async { Err::<String, _>("operation failed") }).await;
///
/// match result {
///     Err(CircuitBreakerError::Open) => {
///         // Circuit is open, operation was not attempted
///         println!("Service unavailable, try again later");
///     }
///     Err(CircuitBreakerError::Inner(e)) => {
///         // Operation was attempted but failed
///         println!("Operation failed: {}", e);
///     }
///     Ok(_) => unreachable!(),
/// }
/// # }
/// ```
#[derive(Debug, Error)]
pub enum CircuitBreakerError<E> {
    /// Circuit breaker is open, request rejected without attempting operation.
    ///
    /// This error occurs when the circuit is in Open state and the reset timeout
    /// has not yet expired. The operation was not executed to prevent further
    /// failures and allow the underlying service to recover.
    ///
    /// # Recovery
    ///
    /// Wait for the reset timeout to expire, then the circuit will automatically
    /// transition to `HalfOpen` and begin testing recovery.
    #[error("Circuit breaker is open")]
    Open,

    /// Inner operation error.
    ///
    /// The circuit breaker allowed the operation to execute, but it failed.
    /// This error wraps the original error from the operation.
    #[error(transparent)]
    Inner(E),
}

#[cfg(test)]
#[allow(
    clippy::str_to_string,
    clippy::panic,
    clippy::let_underscore_must_use,
    reason = "test code uses these patterns for readability and assertion"
)]
mod tests {
    use std::sync::Arc;

    use tokio::time::sleep;

    use super::*;

    #[test]
    fn test_default_config() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.success_threshold, 2);
        assert_eq!(config.reset_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_initial_state() {
        let breaker = CircuitBreaker::new(CircuitBreakerConfig::default());
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_successful_operation() {
        let breaker = CircuitBreaker::new(CircuitBreakerConfig::default());

        let result = breaker.call(|| async { Ok::<_, String>("success".to_string()) }).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_failed_operation() {
        let breaker = CircuitBreaker::new(CircuitBreakerConfig::default());

        let result = breaker.call(|| async { Err::<String, _>("failure") }).await;

        assert!(result.is_err());
        match result {
            Err(CircuitBreakerError::Inner(e)) => assert_eq!(e, "failure"),
            _ => panic!("Expected Inner error"),
        }
        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_opens_after_threshold() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            reset_timeout: Duration::from_secs(60),
        };
        let breaker = CircuitBreaker::new(config);

        // Fail 3 times to reach threshold
        for _ in 0..3 {
            let _ = breaker.call(|| async { Err::<String, _>("failure") }).await;
        }

        assert_eq!(breaker.state(), CircuitState::Open);

        // Next request should be rejected
        let result = breaker.call(|| async { Ok::<_, String>("success".to_string()) }).await;

        assert!(matches!(result, Err(CircuitBreakerError::Open)));
    }

    #[tokio::test]
    async fn test_circuit_half_open_after_timeout() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            reset_timeout: Duration::from_millis(100),
        };
        let breaker = CircuitBreaker::new(config);

        // Open the circuit
        for _ in 0..2 {
            let _ = breaker.call(|| async { Err::<String, _>("failure") }).await;
        }
        assert_eq!(breaker.state(), CircuitState::Open);

        // Wait for timeout
        sleep(Duration::from_millis(150)).await;

        // Next call should transition to HalfOpen
        let result = breaker.call(|| async { Ok::<_, String>("success".to_string()) }).await;

        assert!(result.is_ok());
        assert_eq!(breaker.state(), CircuitState::HalfOpen);
    }

    #[tokio::test]
    async fn test_circuit_closes_after_success_threshold() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            reset_timeout: Duration::from_millis(100),
        };
        let breaker = CircuitBreaker::new(config);

        // Open the circuit
        for _ in 0..2 {
            let _ = breaker.call(|| async { Err::<String, _>("failure") }).await;
        }
        assert_eq!(breaker.state(), CircuitState::Open);

        // Wait for timeout
        sleep(Duration::from_millis(150)).await;

        // Succeed twice to close circuit
        for _ in 0..2 {
            let result = breaker.call(|| async { Ok::<_, String>("success".to_string()) }).await;
            assert!(result.is_ok());
        }

        assert_eq!(breaker.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_half_open_reopens_on_failure() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            reset_timeout: Duration::from_millis(100),
        };
        let breaker = CircuitBreaker::new(config);

        // Open the circuit
        for _ in 0..2 {
            let _ = breaker.call(|| async { Err::<String, _>("failure") }).await;
        }

        // Wait for timeout to transition to HalfOpen
        sleep(Duration::from_millis(150)).await;

        // First call succeeds and transitions to HalfOpen
        let _ = breaker.call(|| async { Ok::<_, String>("success".to_string()) }).await;
        assert_eq!(breaker.state(), CircuitState::HalfOpen);

        // Second call fails, should reopen circuit
        let _ = breaker.call(|| async { Err::<String, _>("failure") }).await;
        assert_eq!(breaker.state(), CircuitState::Open);
    }

    #[tokio::test]
    async fn test_thread_safety() {
        let config = CircuitBreakerConfig {
            failure_threshold: 10,
            success_threshold: 2,
            reset_timeout: Duration::from_secs(60),
        };
        let breaker = Arc::new(CircuitBreaker::new(config));

        let mut handles = vec![];

        // Spawn multiple tasks that use the circuit breaker concurrently
        for i in 0..10 {
            let breaker_clone = Arc::clone(&breaker);
            let handle = tokio::spawn(async move {
                breaker_clone
                    .call(|| async move {
                        if i % 2 == 0 {
                            Ok::<_, String>("success".to_string())
                        } else {
                            Err("failure".to_string())
                        }
                    })
                    .await
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            let _ = handle.await;
        }

        // Circuit should still be in a valid state
        let state = breaker.state();
        assert!(matches!(
            state,
            CircuitState::Closed | CircuitState::Open | CircuitState::HalfOpen
        ));
    }

    #[test]
    fn test_circuit_breaker_error_display() {
        let open_err: CircuitBreakerError<String> = CircuitBreakerError::Open;
        assert_eq!(open_err.to_string(), "Circuit breaker is open");

        let inner_err: CircuitBreakerError<String> =
            CircuitBreakerError::Inner("test error".to_string());
        assert_eq!(inner_err.to_string(), "test error");
    }

    #[tokio::test]
    async fn test_error_propagation() {
        let breaker = CircuitBreaker::new(CircuitBreakerConfig::default());

        let result = breaker.call(|| async { Err::<String, _>("custom error") }).await;

        match result {
            Err(CircuitBreakerError::Inner(e)) => assert_eq!(e, "custom error"),
            _ => panic!("Expected Inner error with custom message"),
        }
    }

    #[tokio::test]
    async fn test_circuit_breaker_zero_reset_timeout() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2, // Need 2 successes to close
            reset_timeout: Duration::from_millis(0),
        };
        let breaker = CircuitBreaker::new(config);

        // Open the circuit
        for _ in 0..2 {
            let _ = breaker.call(|| async { Err::<String, _>("failure") }).await;
        }
        assert_eq!(breaker.state(), CircuitState::Open);

        // With zero timeout, next call should immediately transition to HalfOpen
        let result = breaker.call(|| async { Ok::<_, String>("success".to_string()) }).await;

        assert!(result.is_ok());
        // Should be in HalfOpen after one success (not enough to close yet)
        assert_eq!(breaker.state(), CircuitState::HalfOpen);
    }

    #[tokio::test]
    async fn test_circuit_breaker_very_long_timeout() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            reset_timeout: Duration::from_secs(3600), // 1 hour
        };
        let breaker = CircuitBreaker::new(config);

        // Open the circuit
        let _ = breaker.call(|| async { Err::<String, _>("failure") }).await;
        assert_eq!(breaker.state(), CircuitState::Open);

        // Should remain open since timeout hasn't expired
        let result = breaker.call(|| async { Ok::<_, String>("success".to_string()) }).await;

        assert!(matches!(result, Err(CircuitBreakerError::Open)));
        assert_eq!(breaker.state(), CircuitState::Open);
    }

    #[tokio::test]
    async fn test_circuit_breaker_high_failure_count() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1000,
            success_threshold: 2,
            reset_timeout: Duration::from_secs(60),
        };
        let breaker = CircuitBreaker::new(config);

        // Generate many failures (but not quite threshold)
        for _ in 0..999 {
            let _ = breaker.call(|| async { Err::<String, _>("failure") }).await;
        }

        // Should still be closed
        assert_eq!(breaker.state(), CircuitState::Closed);

        // One more failure should open it
        let _ = breaker.call(|| async { Err::<String, _>("failure") }).await;
        assert_eq!(breaker.state(), CircuitState::Open);
    }

    #[tokio::test]
    async fn test_circuit_breaker_multiple_half_open_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 3,
            reset_timeout: Duration::from_millis(100),
        };
        let breaker = CircuitBreaker::new(config);

        // Open the circuit
        for _ in 0..2 {
            let _ = breaker.call(|| async { Err::<String, _>("failure") }).await;
        }

        // Wait for timeout and enter HalfOpen
        sleep(Duration::from_millis(150)).await;
        let _ = breaker.call(|| async { Ok::<_, String>("success".to_string()) }).await;
        assert_eq!(breaker.state(), CircuitState::HalfOpen);

        // Fail in HalfOpen - should reopen
        let _ = breaker.call(|| async { Err::<String, _>("failure") }).await;
        assert_eq!(breaker.state(), CircuitState::Open);

        // Try again after timeout
        sleep(Duration::from_millis(150)).await;
        let _ = breaker.call(|| async { Ok::<_, String>("success".to_string()) }).await;
        assert_eq!(breaker.state(), CircuitState::HalfOpen);

        // Fail again - should reopen again
        let _ = breaker.call(|| async { Err::<String, _>("failure") }).await;
        assert_eq!(breaker.state(), CircuitState::Open);
    }
}
