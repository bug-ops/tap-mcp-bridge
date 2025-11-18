//! Error types for the TAP-MCP Bridge.
//!
//! This module defines all error types that can occur during TAP-MCP bridge operations.
//! All errors implement the standard [`std::error::Error`] trait via [`thiserror::Error`].
//!
//! # Error Categories
//!
//! - **Signature Errors** ([`BridgeError::SignatureError`], [`BridgeError::CryptoError`]):
//!   Cryptographic operation failures
//! - **Network Errors** ([`BridgeError::HttpError`]): HTTP communication failures
//! - **Validation Errors** ([`BridgeError::InvalidMerchantUrl`]): Input validation failures
//! - **Protocol Errors** ([`BridgeError::MerchantError`]): TAP protocol violations
//!
//! # Examples
//!
//! ```
//! use tap_mcp_bridge::error::{BridgeError, Result};
//!
//! fn validate_url(url: &str) -> Result<String> {
//!     if !url.starts_with("https://") {
//!         return Err(BridgeError::InvalidMerchantUrl("URL must use HTTPS".to_string()));
//!     }
//!     Ok(url.to_string())
//! }
//! ```

use thiserror::Error;

/// Result type alias for bridge operations.
///
/// This is a convenience type that uses [`BridgeError`] as the error type.
/// All fallible functions in this crate return this type.
///
/// Results should be handled by the caller - either checked for errors,
/// propagated with `?`, or explicitly acknowledged with `.unwrap()` or
/// `.expect()` in cases where failure is impossible.
pub type Result<T> = std::result::Result<T, BridgeError>;

/// Errors that can occur in the TAP-MCP bridge.
///
/// All variants include contextual information about what went wrong.
/// The error messages are designed to be user-facing and actionable.
///
/// # Error Recovery
///
/// - **Transient errors** ([`HttpError`](Self::HttpError)): Retry with exponential backoff
/// - **Validation errors** ([`InvalidMerchantUrl`](Self::InvalidMerchantUrl)): Fix input and retry
/// - **Cryptographic errors** ([`SignatureError`](Self::SignatureError),
///   [`CryptoError`](Self::CryptoError)): Check key configuration
/// - **Protocol errors** ([`MerchantError`](Self::MerchantError)): Contact merchant support
///
/// This type implements `#[must_use]` to ensure errors are not silently ignored.
/// Always handle errors by checking, propagating, or explicitly panicking.
#[must_use = "errors should be handled, propagated, or explicitly panicked"]
#[derive(Debug, Error)]
pub enum BridgeError {
    /// TAP signature generation failed.
    ///
    /// This error occurs when the bridge cannot generate a valid RFC 9421 HTTP Message Signature.
    /// Common causes include:
    /// - Invalid signing key format
    /// - System time errors (cannot determine signature timestamp)
    /// - Signature base string construction failures
    ///
    /// # Recovery
    ///
    /// Check that the Ed25519 signing key is valid and system time is correctly set.
    #[error("TAP signature generation failed: {0}")]
    SignatureError(String),

    /// HTTP request failed.
    ///
    /// This error wraps [`reqwest::Error`] and occurs when network communication with
    /// the merchant fails. Common causes include:
    /// - Network timeouts (default: 30 seconds)
    /// - Connection refused (merchant server down)
    /// - DNS resolution failures
    /// - TLS/SSL errors
    ///
    /// # Recovery
    ///
    /// Retry the request with exponential backoff. If the error persists, verify:
    /// - Merchant URL is correct and accessible
    /// - Network connectivity is available
    /// - Firewall/proxy settings allow HTTPS connections
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    /// Invalid merchant response.
    ///
    /// This error occurs when the merchant returns a response that violates the TAP protocol.
    /// Common causes include:
    /// - Unexpected HTTP status code
    /// - Malformed JSON response
    /// - Missing required fields in response
    /// - Protocol version mismatch
    ///
    /// # Recovery
    ///
    /// This usually indicates a merchant-side issue. Contact the merchant to verify:
    /// - Their TAP implementation is up to date
    /// - The endpoint accepts the request format being sent
    /// - Any API keys or authentication tokens are valid
    #[error("Invalid merchant response: {0}")]
    MerchantError(String),

    /// Cryptographic operation failed.
    ///
    /// This error occurs when a low-level cryptographic operation fails.
    /// Common causes include:
    /// - Invalid key material
    /// - Hash computation failures
    /// - Base64 encoding/decoding errors
    ///
    /// # Recovery
    ///
    /// Verify that:
    /// - Signing keys are valid Ed25519 keys
    /// - Key material has not been corrupted
    /// - System has sufficient entropy for cryptographic operations
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// Invalid merchant URL.
    ///
    /// This error occurs when input validation rejects a merchant URL.
    /// Common causes include:
    /// - Non-HTTPS URL (HTTP is not allowed)
    /// - Localhost or loopback addresses (security restriction)
    /// - Malformed URL syntax
    ///
    /// # Recovery
    ///
    /// Ensure the merchant URL:
    /// - Uses HTTPS scheme (`https://`)
    /// - Is not a localhost address (`localhost`, `127.0.0.1`)
    /// - Has valid syntax per [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::error::BridgeError;
    ///
    /// // These URLs will be rejected:
    /// let err = BridgeError::InvalidMerchantUrl("http://example.com".to_string());
    /// assert!(err.to_string().contains("Invalid merchant URL"));
    ///
    /// let err = BridgeError::InvalidMerchantUrl("https://localhost/checkout".to_string());
    /// assert!(err.to_string().contains("Invalid merchant URL"));
    /// ```
    #[error("Invalid merchant URL: {0}")]
    InvalidMerchantUrl(String),

    /// Invalid consumer ID.
    ///
    /// This error occurs when input validation rejects a consumer ID.
    /// Consumer IDs must meet these requirements:
    /// - Not empty
    /// - Maximum 64 characters
    /// - Only alphanumeric characters, hyphens, and underscores
    ///
    /// # Recovery
    ///
    /// Ensure the consumer ID:
    /// - Contains only letters (a-z, A-Z), numbers (0-9), hyphens (-), and underscores (_)
    /// - Has at least 1 character
    /// - Has no more than 64 characters
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::error::BridgeError;
    ///
    /// // These consumer IDs will be rejected:
    /// let err = BridgeError::InvalidConsumerId("consumer@example.com".to_string());
    /// assert!(err.to_string().contains("Invalid consumer ID"));
    ///
    /// let err = BridgeError::InvalidConsumerId("".to_string());
    /// assert!(err.to_string().contains("Invalid consumer ID"));
    /// ```
    #[error("Invalid consumer ID: {0}")]
    InvalidConsumerId(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = BridgeError::SignatureError("test error".into());
        assert_eq!(error.to_string(), "TAP signature generation failed: test error");
    }

    #[test]
    fn test_merchant_error() {
        let error = BridgeError::MerchantError("invalid response".into());
        assert!(error.to_string().contains("Invalid merchant response"));
    }

    #[test]
    fn test_invalid_consumer_id_error() {
        let error = BridgeError::InvalidConsumerId("invalid@id".to_owned());
        assert_eq!(error.to_string(), "Invalid consumer ID: invalid@id");
    }

    #[test]
    fn test_invalid_merchant_url_error() {
        let error = BridgeError::InvalidMerchantUrl("http://example.com".to_owned());
        assert_eq!(error.to_string(), "Invalid merchant URL: http://example.com");
    }
}
