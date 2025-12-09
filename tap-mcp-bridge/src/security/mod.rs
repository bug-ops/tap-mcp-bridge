//! Security features for TAP-MCP operations.
//!
//! Provides rate limiting, audit logging, and other security controls
//! to protect against abuse and ensure reliable operation.
//!
//! # Rate Limiting
//!
//! The rate limiting module implements a token bucket algorithm to control
//! the rate of TAP signature generation and request processing:
//!
//! ```rust
//! use tap_mcp_bridge::security::{RateLimitConfig, RateLimiter};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = RateLimitConfig { requests_per_second: 10, burst_size: 5 };
//!
//! let limiter = RateLimiter::new(config);
//!
//! // Acquire token before processing request
//! limiter.acquire().await?;
//! // ... process request ...
//! # Ok(())
//! # }
//! ```
//!
//! # Audit Logging
//!
//! The audit module provides structured logging for security-relevant events
//! with automatic sensitive data redaction:
//!
//! ```rust
//! use tap_mcp_bridge::security::audit::{AuditEvent, AuditEventType};
//! use uuid::Uuid;
//!
//! let event = AuditEvent::new(AuditEventType::CheckoutSucceeded, "agent-123", Uuid::new_v4())
//!     .with_merchant_url("https://merchant.example.com")
//!     .with_consumer_id("user-456");
//!
//! tap_mcp_bridge::security::audit::audit_log(&event);
//! ```
//!
//! Or use the convenience macro:
//!
//! ```rust
//! use tap_mcp_bridge::{audit, security::audit::AuditEventType};
//! use uuid::Uuid;
//!
//! audit!(
//!     AuditEventType::SignatureGenerated,
//!     "agent-789",
//!     Uuid::new_v4(),
//!     with_merchant_url("https://merchant.example.com")
//! );
//! ```
//!
//! # Security Considerations
//!
//! - Rate limiting prevents `DoS` attacks by limiting request volume
//! - Token bucket allows bursts while maintaining average rate
//! - Thread-safe implementation uses atomic operations
//! - All rate limit events are logged for security monitoring
//! - Audit logs use separate tracing target for easy filtering
//! - Sensitive data (card numbers, CVV, SSN) automatically redacted
//! - Request correlation IDs enable tracking across operations

pub mod audit;
mod rate_limit;

pub use audit::{
    AuditDetails, AuditEvent, AuditEventType, audit_log, redact_consumer_id, redact_sensitive,
};
pub use rate_limit::{RateLimitConfig, RateLimitedSigner, RateLimiter};
