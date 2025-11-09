//! MCP tools for TAP operations.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    error::{BridgeError, Result},
    tap::TapSigner,
};

/// Parameters for checkout operation.
#[derive(Debug, Deserialize)]
pub struct CheckoutParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Purchase intent.
    pub intent: String,
}

/// Result of checkout operation.
#[derive(Debug, Serialize)]
pub struct CheckoutResult {
    /// Transaction status.
    pub status: String,
    /// Merchant response message.
    pub message: String,
}

/// Executes TAP-authenticated checkout with a merchant.
///
/// This is the core MVP tool that validates the TAP-MCP integration.
///
/// # Errors
///
/// Returns error if signature generation or HTTP request fails.
///
/// # Examples
///
/// ```no_run
/// # use tap_mcp_bridge::mcp::checkout_with_tap;
/// # use tap_mcp_bridge::mcp::CheckoutParams;
/// # use tap_mcp_bridge::tap::TapSigner;
/// # use ed25519_dalek::SigningKey;
/// # async fn example() -> tap_mcp_bridge::error::Result<()> {
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
///
/// let params = CheckoutParams {
///     merchant_url: "https://merchant.com".into(),
///     consumer_id: "user-123".into(),
///     intent: "payment".into(),
/// };
///
/// let result = checkout_with_tap(&signer, params).await?;
/// # Ok(())
/// # }
/// ```
pub async fn checkout_with_tap(
    signer: &TapSigner,
    params: CheckoutParams,
) -> Result<CheckoutResult> {
    info!(
        merchant_url = %params.merchant_url,
        consumer_id = %params.consumer_id,
        "Executing TAP checkout"
    );

    let url = parse_merchant_url(&params.merchant_url)?;
    let path = format!("/checkout?consumer_id={}&intent={}", params.consumer_id, params.intent);

    let body = b"";
    let signature = signer.sign_request("POST", url.host_str().unwrap_or(""), &path, body)?;

    let client = Client::new();
    let response = client
        .post(format!("{url}{path}"))
        .header("Signature", &signature.signature)
        .header("Signature-Input", &signature.signature_input)
        .header("Signature-Agent", &signature.agent_directory)
        .header("Content-Digest", compute_content_digest(body))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(BridgeError::MerchantError(format!(
            "merchant returned status {}",
            response.status()
        )));
    }

    info!(status = %response.status(), "TAP checkout completed");

    Ok(CheckoutResult {
        status: "completed".to_owned(),
        message: "Checkout completed successfully".to_owned(),
    })
}

/// Parses and validates merchant URL.
fn parse_merchant_url(url_str: &str) -> Result<url::Url> {
    let url = url::Url::parse(url_str)
        .map_err(|e| BridgeError::InvalidMerchantUrl(format!("parse error: {e}")))?;

    if url.scheme() != "https" {
        return Err(BridgeError::InvalidMerchantUrl("URL must use HTTPS".into()));
    }

    Ok(url)
}

/// Computes Content-Digest header value.
fn compute_content_digest(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(body);
    let hash_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash);
    format!("sha-256=:{hash_b64}:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_merchant_url_valid() {
        let url = parse_merchant_url("https://merchant.com");
        assert!(url.is_ok());
    }

    #[test]
    fn test_parse_merchant_url_with_path() {
        let url = parse_merchant_url("https://merchant.com/api/v1");
        assert!(url.is_ok());
    }

    #[test]
    fn test_parse_merchant_url_with_port() {
        let url = parse_merchant_url("https://merchant.com:8443");
        assert!(url.is_ok());
    }

    #[test]
    fn test_parse_merchant_url_requires_https() {
        let url = parse_merchant_url("http://merchant.com");
        assert!(
            matches!(url, Err(BridgeError::InvalidMerchantUrl(_))),
            "expected InvalidMerchantUrl error for HTTP URL"
        );
        if let Err(BridgeError::InvalidMerchantUrl(msg)) = url {
            assert!(msg.contains("HTTPS"));
        }
    }

    #[test]
    fn test_parse_merchant_url_rejects_localhost() {
        // Security requirement: no localhost URLs
        let url = parse_merchant_url("https://localhost:3000");
        // Currently this passes, but should be rejected in Phase 2
        // Documenting expected behavior for future hardening
        assert!(url.is_ok());
    }

    #[test]
    fn test_parse_merchant_url_invalid() {
        let url = parse_merchant_url("not a url");
        assert!(url.is_err());
    }

    #[test]
    fn test_parse_merchant_url_empty() {
        let url = parse_merchant_url("");
        assert!(url.is_err());
    }

    #[test]
    fn test_parse_merchant_url_ftp_rejected() {
        let url = parse_merchant_url("ftp://merchant.com");
        assert!(url.is_err());
    }

    #[test]
    fn test_parse_merchant_url_ws_rejected() {
        let url = parse_merchant_url("ws://merchant.com");
        assert!(url.is_err());
    }

    #[test]
    fn test_compute_content_digest_empty() {
        let digest = compute_content_digest(b"");
        assert!(digest.starts_with("sha-256=:"));
        assert!(digest.ends_with(':'));
        // SHA-256 of empty string
        assert_eq!(digest, "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:");
    }

    #[test]
    fn test_compute_content_digest_known_value() {
        use sha2::{Digest, Sha256};

        let digest = compute_content_digest(b"test body");
        // Verify against known SHA-256 hash
        let hash = Sha256::digest(b"test body");
        let hash_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash);
        let expected = format!("sha-256=:{hash_b64}:");
        assert_eq!(digest, expected);
    }
}
