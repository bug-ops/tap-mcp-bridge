//! Reliability patterns for TAP-MCP operations.
//!
//! Provides retry logic and circuit breaker patterns for handling
//! transient failures in merchant communications.

mod circuit_breaker;
mod retry;

pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerError, CircuitState,
};
pub use retry::{RetryPolicy, is_retryable, retry_with_backoff};
