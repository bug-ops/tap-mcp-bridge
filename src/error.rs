//! Error types for the TAP-MCP Bridge.

use thiserror::Error;

/// Result type alias for bridge operations.
pub type Result<T> = std::result::Result<T, BridgeError>;

/// Errors that can occur in the TAP-MCP bridge.
#[derive(Debug, Error)]
pub enum BridgeError {
    /// TAP signature generation failed.
    #[error("TAP signature generation failed: {0}")]
    SignatureError(String),

    /// HTTP request failed.
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    /// Invalid merchant response.
    #[error("Invalid merchant response: {0}")]
    MerchantError(String),

    /// Cryptographic operation failed.
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// Invalid merchant URL.
    #[error("Invalid merchant URL: {0}")]
    InvalidMerchantUrl(String),
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
}
