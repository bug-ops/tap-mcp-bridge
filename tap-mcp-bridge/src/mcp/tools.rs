//! MCP tools for TAP operations.

use std::{sync::LazyLock, time::Duration};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, instrument};

use crate::{
    error::{BridgeError, Result},
    tap::{InteractionType, TapSigner},
};

/// Timeout for HTTP requests to merchants in seconds.
///
/// This timeout applies to the entire request-response cycle, including
/// connection establishment, TLS handshake, request transmission, and
/// response reception.
///
/// The 30-second timeout balances responsiveness with merchant processing time:
/// - Long enough for merchants to process TAP signatures and authorize payments
/// - Short enough to provide timely feedback to AI agents
///
/// This can be adjusted for testing with slower networks or merchants.
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Shared HTTP client for all TAP requests.
///
/// This static client is initialized once and reused across all requests,
/// providing connection pooling and reducing per-request overhead.
///
/// The client is configured with:
/// - 30-second timeout for all requests (see [`REQUEST_TIMEOUT_SECS`])
/// - Connection pooling (100 connections per host)
/// - HTTP/2 support with connection reuse
static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .pool_max_idle_per_host(100)
        .http2_prior_knowledge()
        .build()
        .expect("failed to create HTTP client")
});

/// Parameters for checkout operation.
#[derive(Debug, Deserialize)]
pub struct CheckoutParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Purchase intent.
    pub intent: String,

    // ACRO contextual data fields
    /// ISO 3166-1 alpha-2 country code (e.g., "US").
    pub country_code: String,
    /// Postal code or city/state (max 16 chars).
    pub zip: String,
    /// Consumer device IP address.
    pub ip_address: String,
    /// Browser/device user agent.
    pub user_agent: String,
    /// Operating system platform.
    pub platform: String,
}

/// Result of checkout operation.
#[derive(Debug, Serialize)]
pub struct CheckoutResult {
    /// Transaction status.
    pub status: String,
    /// Merchant response message.
    pub message: String,
}

/// Parameters for browse merchant operation.
#[derive(Debug, Deserialize)]
pub struct BrowseParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,

    // ACRO contextual data fields
    /// ISO 3166-1 alpha-2 country code (e.g., "US").
    pub country_code: String,
    /// Postal code or city/state (max 16 chars).
    pub zip: String,
    /// Consumer device IP address.
    pub ip_address: String,
    /// Browser/device user agent.
    pub user_agent: String,
    /// Operating system platform.
    pub platform: String,
}

/// Result of browse merchant operation.
#[derive(Debug, Serialize)]
pub struct BrowseResult {
    /// Browse status.
    pub status: String,
    /// Catalog data or message.
    pub data: String,
}

/// Executes TAP-authenticated checkout with a merchant.
///
/// This is the primary TAP-MCP integration tool for payment transactions.
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
///     country_code: "US".into(),
///     zip: "94025".into(),
///     ip_address: "192.168.1.100".into(),
///     user_agent: "Mozilla/5.0".into(),
///     platform: "macOS".into(),
/// };
///
/// let result = checkout_with_tap(&signer, params).await?;
/// # Ok(())
/// # }
/// ```
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, consumer_id = %params.consumer_id, interaction_type = "checkout"))]
pub async fn checkout_with_tap(
    signer: &TapSigner,
    params: CheckoutParams,
) -> Result<CheckoutResult> {
    info!(method = "POST", "executing TAP checkout");

    let path = super::http::build_url_with_query("/checkout", &[
        ("consumer_id", &params.consumer_id),
        ("intent", &params.intent),
    ])?;

    // Create contextual data from params
    let contextual_data = crate::tap::acro::ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    execute_tap_request_with_acro(
        signer,
        &params.merchant_url,
        &params.consumer_id,
        "POST",
        path,
        InteractionType::Checkout,
        contextual_data,
    )
    .await?;

    info!(status = "completed", "TAP checkout completed");

    Ok(CheckoutResult {
        status: "completed".to_owned(),
        message: "Checkout completed successfully".to_owned(),
    })
}

/// Browses merchant catalog with TAP authentication.
///
/// This tool enables browsing merchant catalogs with consumer identity verification.
///
/// # Errors
///
/// Returns error if signature generation or HTTP request fails.
///
/// # Examples
///
/// ```no_run
/// # use tap_mcp_bridge::mcp::browse_merchant;
/// # use tap_mcp_bridge::mcp::BrowseParams;
/// # use tap_mcp_bridge::tap::TapSigner;
/// # use ed25519_dalek::SigningKey;
/// # async fn example() -> tap_mcp_bridge::error::Result<()> {
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
///
/// let params = BrowseParams {
///     merchant_url: "https://merchant.com".into(),
///     consumer_id: "user-123".into(),
///     country_code: "US".into(),
///     zip: "94025".into(),
///     ip_address: "192.168.1.100".into(),
///     user_agent: "Mozilla/5.0".into(),
///     platform: "macOS".into(),
/// };
///
/// let result = browse_merchant(&signer, params).await?;
/// # Ok(())
/// # }
/// ```
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, consumer_id = %params.consumer_id, interaction_type = "browse"))]
pub async fn browse_merchant(signer: &TapSigner, params: BrowseParams) -> Result<BrowseResult> {
    info!(method = "GET", "browsing merchant catalog");

    let path =
        super::http::build_url_with_query("/catalog", &[("consumer_id", &params.consumer_id)])?;

    // Create contextual data from params
    let contextual_data = crate::tap::acro::ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    execute_tap_request_with_acro(
        signer,
        &params.merchant_url,
        &params.consumer_id,
        "GET",
        path,
        InteractionType::Browse,
        contextual_data,
    )
    .await?;

    info!(status = "completed", "browse catalog completed");

    Ok(BrowseResult {
        status: "completed".to_owned(),
        data: "Catalog retrieved successfully".to_owned(),
    })
}

/// Executes a TAP-authenticated HTTP request with ACRO to a merchant.
///
/// Includes Agentic Consumer Recognition Object (ACRO) in the request body for consumer identity
/// verification.
#[instrument(skip(signer, contextual_data), fields(merchant_url, consumer_id, method, path, interaction_type = ?interaction_type))]
async fn execute_tap_request_with_acro(
    signer: &TapSigner,
    merchant_url: &str,
    consumer_id: &str,
    method: &str,
    path: String,
    interaction_type: InteractionType,
    contextual_data: crate::tap::acro::ContextualData,
) -> Result<()> {
    validate_consumer_id(consumer_id)?;

    let url = parse_merchant_url(merchant_url)?;
    let authority = url.host_str().ok_or_else(|| {
        BridgeError::InvalidMerchantUrl(format!("URL missing host: {merchant_url}"))
    })?;

    // Generate nonce for signature (will be reused in ACRO and ID token)
    let nonce = uuid::Uuid::new_v4().to_string();

    // Generate ID token
    let id_token = signer.generate_id_token(consumer_id, merchant_url, &nonce)?;

    // Generate ACRO with same nonce
    let acro = signer.generate_acro(&nonce, &id_token.token, contextual_data)?;

    // Serialize ACRO to JSON body
    let body = serde_json::to_vec(&acro)
        .map_err(|e| BridgeError::CryptoError(format!("ACRO serialization failed: {e}")))?;

    // Generate signature including body digest
    let signature = signer.sign_request(method, authority, &path, &body, interaction_type)?;

    let client = &*HTTP_CLIENT;

    let request = match method {
        "POST" => client.post(format!("{url}{path}")),
        "GET" => client.get(format!("{url}{path}")),
        _ => {
            return Err(BridgeError::InvalidMerchantUrl(format!(
                "unsupported HTTP method: {method}"
            )));
        }
    };

    let content_digest = TapSigner::compute_content_digest(&body);

    let response = request
        .header("Signature", &signature.signature)
        .header("Signature-Input", &signature.signature_input)
        .header("Signature-Agent", signature.agent_directory.as_ref())
        .header("Content-Digest", &content_digest)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(BridgeError::MerchantError(format!(
            "merchant returned status {}",
            response.status()
        )));
    }

    Ok(())
}

/// Executes a TAP-authenticated HTTP request to a merchant (legacy, no ACRO).
///
/// This internal helper is kept for backward compatibility with older merchants
/// that don't support ACRO. New code should use `execute_tap_request_with_acro`.
#[allow(dead_code, reason = "kept for backward compatibility")]
async fn execute_tap_request(
    signer: &TapSigner,
    merchant_url: &str,
    consumer_id: &str,
    method: &str,
    path: String,
    interaction_type: InteractionType,
) -> Result<()> {
    validate_consumer_id(consumer_id)?;

    let url = parse_merchant_url(merchant_url)?;
    let authority = url.host_str().ok_or_else(|| {
        BridgeError::InvalidMerchantUrl(format!("URL missing host: {merchant_url}"))
    })?;

    let body = b"";
    let signature = signer.sign_request(method, authority, &path, body, interaction_type)?;

    let client = &*HTTP_CLIENT;

    let request = match method {
        "POST" => client.post(format!("{url}{path}")),
        "GET" => client.get(format!("{url}{path}")),
        _ => {
            return Err(BridgeError::InvalidMerchantUrl(format!(
                "unsupported HTTP method: {method}"
            )));
        }
    };

    let response = request
        .header("Signature", &signature.signature)
        .header("Signature-Input", &signature.signature_input)
        .header("Signature-Agent", signature.agent_directory.as_ref())
        .header("Content-Digest", TapSigner::compute_content_digest(body))
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(BridgeError::MerchantError(format!(
            "merchant returned status {}",
            response.status()
        )));
    }

    Ok(())
}

/// Validates consumer ID format.
pub(crate) fn validate_consumer_id(consumer_id: &str) -> Result<()> {
    if consumer_id.is_empty() {
        return Err(BridgeError::InvalidConsumerId("consumer_id cannot be empty".into()));
    }

    if consumer_id.len() > 64 {
        return Err(BridgeError::InvalidConsumerId(
            "consumer_id must be 64 characters or less".into(),
        ));
    }

    if !consumer_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(BridgeError::InvalidConsumerId(
            "consumer_id must contain only alphanumeric characters, hyphens, and underscores"
                .into(),
        ));
    }

    Ok(())
}

/// Parses and validates merchant URL.
pub(crate) fn parse_merchant_url(url_str: &str) -> Result<url::Url> {
    let url = url::Url::parse(url_str)
        .map_err(|e| BridgeError::InvalidMerchantUrl(format!("parse error: {e}")))?;

    if url.scheme() != "https" {
        return Err(BridgeError::InvalidMerchantUrl("URL must use HTTPS".into()));
    }

    if let Some(host) = url.host_str()
        && (host == "localhost" || host == "127.0.0.1" || host.starts_with("localhost:"))
    {
        return Err(BridgeError::InvalidMerchantUrl("localhost URLs not allowed".into()));
    }

    Ok(url)
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
        let url = parse_merchant_url("https://localhost:3000");
        assert!(
            matches!(url, Err(BridgeError::InvalidMerchantUrl(_))),
            "expected InvalidMerchantUrl error for localhost URL"
        );
        if let Err(BridgeError::InvalidMerchantUrl(msg)) = url {
            assert!(msg.contains("localhost"));
        }
    }

    #[test]
    fn test_parse_merchant_url_rejects_localhost_plain() {
        let url = parse_merchant_url("https://localhost");
        assert!(url.is_err());
    }

    #[test]
    fn test_parse_merchant_url_rejects_127_0_0_1() {
        let url = parse_merchant_url("https://127.0.0.1:8080");
        assert!(url.is_err());
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
        let digest = TapSigner::compute_content_digest(b"");
        assert!(digest.starts_with("sha-256=:"));
        assert!(digest.ends_with(':'));
        // SHA-256 of empty string
        assert_eq!(digest, "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:");
    }

    #[test]
    fn test_compute_content_digest_known_value() {
        use sha2::{Digest, Sha256};

        let digest = TapSigner::compute_content_digest(b"test body");
        // Verify against known SHA-256 hash
        let hash = Sha256::digest(b"test body");
        let hash_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash);
        let expected = format!("sha-256=:{hash_b64}:");
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_validate_consumer_id_valid() {
        assert!(validate_consumer_id("user-123").is_ok());
        assert!(validate_consumer_id("user_456").is_ok());
        assert!(validate_consumer_id("abc123-def456_ghi789").is_ok());
    }

    #[test]
    fn test_validate_consumer_id_empty() {
        let result = validate_consumer_id("");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_consumer_id_too_long() {
        let long_id = "a".repeat(65);
        let result = validate_consumer_id(&long_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_consumer_id_max_length() {
        let max_id = "a".repeat(64);
        assert!(validate_consumer_id(&max_id).is_ok());
    }

    #[test]
    fn test_validate_consumer_id_invalid_characters() {
        assert!(validate_consumer_id("user@example").is_err());
        assert!(validate_consumer_id("user#123").is_err());
        assert!(validate_consumer_id("user 123").is_err());
        assert!(validate_consumer_id("user.123").is_err());
    }

    #[test]
    fn test_validate_consumer_id_alphanumeric_only() {
        assert!(validate_consumer_id("abc123").is_ok());
        assert!(validate_consumer_id("ABC123").is_ok());
        assert!(validate_consumer_id("123456").is_ok());
    }
}
