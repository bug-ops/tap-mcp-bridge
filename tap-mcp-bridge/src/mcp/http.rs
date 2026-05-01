//! Shared HTTP client utilities for TAP-MCP bridge.
//!
//! This module provides shared HTTP client creation and request execution
//! to avoid per-request overhead and enable connection pooling.

use std::time::Duration;

use reqwest::Client;
use serde::Serialize;
use tracing::instrument;
use url::Url;

use crate::{
    error::{BridgeError, Result},
    tap::{InteractionType, TapSigner, acro::ContextualData},
};

/// HTTP methods supported by TAP requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// HTTP GET method.
    Get,
    /// HTTP POST method.
    Post,
    /// HTTP PUT method.
    Put,
    /// HTTP DELETE method.
    Delete,
}

impl HttpMethod {
    /// Returns the method as a string slice.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

/// Maximum length for search parameters (defense in depth).
const MAX_SEARCH_PARAM_LENGTH: usize = 256;

/// Composes the wire URL for a TAP request from a parsed base URL and a path.
///
/// `Url::Display` always emits a trailing slash for an origin with an empty
/// path, so naively writing `format!("{url}{path}")` produces `https://host//path`
/// when `path` itself begins with `/`. That mismatched wire path also breaks
/// RFC 9421 verification on strict merchants because the signature is built
/// against the input `path` (`/checkout`), not the doubled form.
///
/// This helper preserves the base URL's path prefix, if any, and ensures
/// exactly one slash sits between the base and the appended path.
pub(crate) fn compose_request_url(base: &Url, path: &str) -> String {
    let base_str = base.as_str().trim_end_matches('/');
    if path.starts_with('/') {
        format!("{base_str}{path}")
    } else {
        format!("{base_str}/{path}")
    }
}

/// Creates a configured HTTP client with connection pooling.
///
/// Configuration:
/// - Connection timeout: 10 seconds
/// - Total timeout: 30 seconds
/// - Connection pool: max 10 idle connections per host
/// - Redirects: disabled ([`reqwest::redirect::Policy::none`])
///
/// Redirect-following is disabled because `reqwest`'s default `Policy::limited(10)`
/// would forward TAP-specific headers (`Signature`, `Signature-Input`,
/// `Signature-Agent`, `Content-Digest`) and 307/308 request bodies to the
/// redirect target. RFC 9421 §1 binds a signature to a specific request — a
/// redirect is a different request and the agent has not authorized it. A
/// merchant returning 30x therefore surfaces as a [`BridgeError::MerchantError`]
/// rather than being followed silently.
///
/// # Errors
///
/// Returns error if client configuration fails.
pub fn create_http_client() -> Result<Client> {
    Client::builder()
        .pool_max_idle_per_host(10)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(BridgeError::HttpError)
}

/// Rejects request paths that contain `.` or `..` segments.
///
/// `reqwest` (via `url::Url`) collapses these segments before transmitting the
/// request, so a path like `/cart/items/../../admin` is signed verbatim but
/// dispatched as `/admin`. Rebuilding `@path` from the wire request — what an
/// RFC 9421 §2.2.6 conformant merchant does — yields a different value and
/// signature verification fails. A loose merchant accepts the collapsed path
/// and the bridge becomes an oracle for arbitrary endpoint targeting.
///
/// Caller validation of id fields ([`validate_path_id`]) is the primary defense.
/// This check guards against future code paths that bypass that layer.
///
/// Only the path component is inspected; query strings are passed through
/// unchanged.
///
/// [`validate_path_id`]: crate::mcp::tools::validate_path_id
fn reject_path_traversal(path: &str) -> Result<()> {
    let path_only = path.split_once('?').map_or(path, |(p, _)| p);
    if path_only.split('/').any(|segment| segment == ".." || segment == ".") {
        return Err(BridgeError::InvalidInput(format!(
            "request path contains traversal segment: {path}"
        )));
    }
    Ok(())
}

/// Validates a search or category parameter.
///
/// # Requirements
///
/// - Maximum 256 characters
/// - No null bytes
/// - Only printable ASCII or whitespace characters
///
/// # Errors
///
/// Returns error if validation fails.
pub fn validate_search_param(param: &str, param_name: &str) -> Result<()> {
    if param.len() > MAX_SEARCH_PARAM_LENGTH {
        return Err(BridgeError::InvalidInput(format!(
            "{param_name} exceeds {MAX_SEARCH_PARAM_LENGTH} characters"
        )));
    }

    if param.contains('\0') {
        return Err(BridgeError::InvalidInput(format!("null bytes not allowed in {param_name}")));
    }

    if !param.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
        return Err(BridgeError::InvalidInput(format!("{param_name} contains invalid characters")));
    }

    Ok(())
}

/// Executes a TAP-authenticated HTTP request with ACRO.
///
/// This function handles both GET requests (body is ACRO) and POST/PUT/DELETE
/// (body is provided `request_body` if Some, otherwise ACRO).
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(
    skip(client, signer, contextual_data, request_body),
    fields(merchant_url, consumer_id, method, path)
)]
#[allow(
    clippy::too_many_arguments,
    reason = "helper function needs all parameters for flexibility"
)]
pub async fn execute_tap_request_with_acro<T: Serialize>(
    client: &Client,
    signer: &TapSigner,
    merchant_url: &str,
    consumer_id: &str,
    method: HttpMethod,
    path: &str,
    interaction_type: InteractionType,
    contextual_data: ContextualData,
    request_body: Option<&T>,
) -> Result<Vec<u8>> {
    crate::mcp::tools::validate_consumer_id(consumer_id)?;
    reject_path_traversal(path)?;

    let url = crate::mcp::tools::parse_merchant_url(merchant_url)?;
    let authority = url.host_str().ok_or_else(|| {
        BridgeError::InvalidMerchantUrl(format!("URL missing host: {merchant_url}"))
    })?;

    let nonce = uuid::Uuid::new_v4().to_string();
    let id_token = signer.generate_id_token(consumer_id, merchant_url, &nonce)?;
    let acro = signer.generate_acro(&nonce, &id_token.token, contextual_data)?;

    let body = if let Some(req_body) = request_body {
        serde_json::to_vec(req_body).map_err(|e| {
            BridgeError::CryptoError(format!("request body serialization failed: {e}"))
        })?
    } else {
        serde_json::to_vec(&acro)
            .map_err(|e| BridgeError::CryptoError(format!("ACRO serialization failed: {e}")))?
    };

    let signature =
        signer.sign_request(method.as_str(), authority, path, &body, interaction_type)?;

    let full_url = compose_request_url(&url, path);
    let request = match method {
        HttpMethod::Get => client.get(&full_url),
        HttpMethod::Post => client.post(&full_url),
        HttpMethod::Put => client.put(&full_url),
        HttpMethod::Delete => client.delete(&full_url),
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

    let response_body = response.bytes().await.map_err(BridgeError::HttpError)?.to_vec();

    Ok(response_body)
}

/// Executes a TAP-authenticated HTTP request with custom nonce.
///
/// This variant allows specifying a custom nonce to match the APC nonce
/// for payment operations.
///
/// # Errors
///
/// Returns error if signature generation, HTTP request, or response parsing fails.
#[instrument(
    skip(client, signer, contextual_data, request_body, nonce),
    fields(merchant_url, consumer_id, method, path)
)]
#[allow(
    clippy::too_many_arguments,
    reason = "helper function needs all parameters"
)]
pub async fn execute_tap_request_with_custom_nonce<T: Serialize>(
    client: &Client,
    signer: &TapSigner,
    merchant_url: &str,
    consumer_id: &str,
    method: HttpMethod,
    path: &str,
    interaction_type: InteractionType,
    contextual_data: ContextualData,
    request_body: &T,
    nonce: &str,
) -> Result<Vec<u8>> {
    crate::mcp::tools::validate_consumer_id(consumer_id)?;
    reject_path_traversal(path)?;

    let url = crate::mcp::tools::parse_merchant_url(merchant_url)?;
    let authority = url.host_str().ok_or_else(|| {
        BridgeError::InvalidMerchantUrl(format!("URL missing host: {merchant_url}"))
    })?;

    let id_token = signer.generate_id_token(consumer_id, merchant_url, nonce)?;
    let acro = signer.generate_acro(nonce, &id_token.token, contextual_data)?;

    // ACRO is generated but not included in request body
    // The request body is sent directly since it already contains all necessary data
    let _ = acro;

    let body = serde_json::to_vec(request_body)
        .map_err(|e| BridgeError::CryptoError(format!("request body serialization failed: {e}")))?;

    let signature =
        signer.sign_request(method.as_str(), authority, path, &body, interaction_type)?;

    let full_url = compose_request_url(&url, path);
    let request = match method {
        HttpMethod::Get => client.get(&full_url),
        HttpMethod::Post => client.post(&full_url),
        HttpMethod::Put => client.put(&full_url),
        HttpMethod::Delete => client.delete(&full_url),
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

    let response_body = response.bytes().await.map_err(BridgeError::HttpError)?.to_vec();

    Ok(response_body)
}

/// Builds a URL path with properly encoded query parameters.
///
/// # Errors
///
/// Returns error if URL parsing fails.
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::mcp::http::build_url_with_query;
///
/// let path = build_url_with_query("/products", &[
///     ("consumer_id", "user-123"),
///     ("search", "rust programming"),
///     ("category", "books & media"),
/// ])?;
/// assert_eq!(
///     path,
///     "/products?consumer_id=user-123&search=rust+programming&category=books+%26+media"
/// );
/// # Ok::<(), tap_mcp_bridge::error::BridgeError>(())
/// ```
pub fn build_url_with_query(base_path: &str, params: &[(&str, &str)]) -> Result<String> {
    let base_url = format!("https://example.com{base_path}");
    let mut url =
        Url::parse(&base_url).map_err(|e| BridgeError::InvalidMerchantUrl(e.to_string()))?;

    {
        let mut query_pairs = url.query_pairs_mut();
        for (key, value) in params {
            query_pairs.append_pair(key, value);
        }
    }

    let full_path = url.path().to_owned();
    let query_string = url.query().unwrap_or("");

    if query_string.is_empty() {
        Ok(full_path)
    } else {
        Ok(format!("{full_path}?{query_string}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_http_client() {
        let client = create_http_client();
        assert!(client.is_ok());
    }

    /// Regression test for issue #144 — HTTP clients must not auto-follow
    /// redirects, since `reqwest` would forward TAP signature headers (and
    /// 307/308 request bodies) to the redirect target.
    #[tokio::test]
    async fn test_create_http_client_does_not_follow_redirects() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Drain the request headers before replying. Windows aborts the
            // socket with WSAECONNABORTED on shutdown if the receive buffer
            // still holds unread bytes, which fails the client-side read.
            let mut request = Vec::with_capacity(512);
            let mut chunk = [0u8; 256];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = socket.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
            }
            let response = b"HTTP/1.1 307 Temporary Redirect\r\n\
                             Location: https://attacker.example/admin/exfil\r\n\
                             Content-Length: 0\r\n\
                             Connection: close\r\n\r\n";
            socket.write_all(response).await.unwrap();
            socket.shutdown().await.unwrap();
        });

        let client = create_http_client().unwrap();
        let url = format!("http://{addr}/checkout");
        let response = client.get(&url).send().await.unwrap();

        // With `Policy::none()`, the 307 surfaces as the response status; if
        // redirects were auto-followed, reqwest would dial `attacker.example`
        // and never produce a 307 status here.
        assert_eq!(response.status().as_u16(), 307);
        server.await.unwrap();
    }

    #[test]
    fn test_compose_request_url_no_trailing_slash() {
        let base = Url::parse("https://merchant.example.com").unwrap();
        assert_eq!(
            compose_request_url(&base, "/checkout"),
            "https://merchant.example.com/checkout"
        );
    }

    #[test]
    fn test_compose_request_url_trailing_slash() {
        let base = Url::parse("https://merchant.example.com/").unwrap();
        assert_eq!(
            compose_request_url(&base, "/checkout"),
            "https://merchant.example.com/checkout"
        );
    }

    #[test]
    fn test_compose_request_url_preserves_path_prefix() {
        let base = Url::parse("https://merchant.example.com/api/v1").unwrap();
        assert_eq!(
            compose_request_url(&base, "/checkout"),
            "https://merchant.example.com/api/v1/checkout"
        );
    }

    #[test]
    fn test_compose_request_url_prefix_with_trailing_slash() {
        let base = Url::parse("https://merchant.example.com/api/v1/").unwrap();
        assert_eq!(
            compose_request_url(&base, "/checkout"),
            "https://merchant.example.com/api/v1/checkout"
        );
    }

    #[test]
    fn test_compose_request_url_path_without_leading_slash() {
        let base = Url::parse("https://merchant.example.com").unwrap();
        assert_eq!(compose_request_url(&base, "checkout"), "https://merchant.example.com/checkout");
    }

    #[test]
    fn test_compose_request_url_with_query_string_in_path() {
        let base = Url::parse("https://merchant.example.com").unwrap();
        assert_eq!(
            compose_request_url(&base, "/checkout?intent=payment"),
            "https://merchant.example.com/checkout?intent=payment"
        );
    }

    #[test]
    fn test_build_url_with_query_simple() {
        let path = build_url_with_query("/products", &[("consumer_id", "user-123")]).unwrap();
        assert_eq!(path, "/products?consumer_id=user-123");
    }

    #[test]
    fn test_build_url_with_query_multiple_params() {
        let path = build_url_with_query("/products", &[
            ("consumer_id", "user-123"),
            ("page", "1"),
            ("per_page", "20"),
        ])
        .unwrap();
        assert_eq!(path, "/products?consumer_id=user-123&page=1&per_page=20");
    }

    #[test]
    fn test_build_url_with_query_special_chars() {
        let path = build_url_with_query("/products", &[
            ("search", "rust programming"),
            ("category", "books & media"),
        ])
        .unwrap();
        assert!(path.contains("rust+programming") || path.contains("rust%20programming"));
        assert!(path.contains("books+%26+media") || path.contains("books%20%26%20media"));
    }

    #[test]
    fn test_build_url_with_query_no_params() {
        let path = build_url_with_query("/products", &[]).unwrap();
        assert_eq!(path, "/products");
    }

    #[test]
    fn test_build_url_with_query_empty_value() {
        let path = build_url_with_query("/products", &[("search", "")]).unwrap();
        assert_eq!(path, "/products?search=");
    }

    #[test]
    fn test_build_url_with_query_unicode() {
        let path = build_url_with_query("/products", &[("search", "bücher")]).unwrap();
        assert!(path.contains("b%C3%BCcher"));
    }

    #[test]
    fn test_build_url_with_query_path_with_segments() {
        let path = build_url_with_query("/products/123", &[("consumer_id", "user-456")]).unwrap();
        assert_eq!(path, "/products/123?consumer_id=user-456");
    }

    // HttpMethod tests
    #[test]
    fn test_http_method_as_str() {
        assert_eq!(HttpMethod::Get.as_str(), "GET");
        assert_eq!(HttpMethod::Post.as_str(), "POST");
        assert_eq!(HttpMethod::Put.as_str(), "PUT");
        assert_eq!(HttpMethod::Delete.as_str(), "DELETE");
    }

    #[test]
    fn test_http_method_eq() {
        assert_eq!(HttpMethod::Get, HttpMethod::Get);
        assert_ne!(HttpMethod::Get, HttpMethod::Post);
    }

    #[test]
    fn test_http_method_clone() {
        let method = HttpMethod::Post;
        let cloned = method;
        assert_eq!(method, cloned);
    }

    // validate_search_param tests
    #[test]
    fn test_validate_search_param_valid() {
        assert!(validate_search_param("books", "search").is_ok());
        assert!(validate_search_param("rust programming", "search").is_ok());
        assert!(validate_search_param("A-Z 0-9 !@#$%", "category").is_ok());
    }

    #[test]
    fn test_validate_search_param_empty() {
        assert!(validate_search_param("", "search").is_ok());
    }

    #[test]
    fn test_validate_search_param_max_length() {
        let valid = "a".repeat(256);
        assert!(validate_search_param(&valid, "search").is_ok());

        let too_long = "a".repeat(257);
        assert!(validate_search_param(&too_long, "search").is_err());
    }

    #[test]
    fn test_validate_search_param_null_bytes() {
        let with_null = "hello\0world";
        let result = validate_search_param(with_null, "search");
        assert!(result.is_err());
        if let Err(BridgeError::InvalidInput(msg)) = result {
            assert!(msg.contains("null bytes"));
        }
    }

    #[test]
    fn test_validate_search_param_non_ascii() {
        // Non-printable ASCII should fail
        let with_control = "hello\x01world";
        assert!(validate_search_param(with_control, "search").is_err());
    }

    #[test]
    fn test_reject_path_traversal_accepts_normal_paths() {
        assert!(reject_path_traversal("/cart/items/abc-123").is_ok());
        assert!(reject_path_traversal("/orders/xyz?consumer_id=user-1").is_ok());
        assert!(reject_path_traversal("/subscriptions/sub_1/cancel").is_ok());
        assert!(reject_path_traversal("/").is_ok());
    }

    #[test]
    fn test_reject_path_traversal_rejects_double_dot() {
        let err = reject_path_traversal("/cart/items/../../admin").unwrap_err();
        assert!(matches!(err, BridgeError::InvalidInput(msg) if msg.contains("traversal")));
        assert!(reject_path_traversal("/orders/..").is_err());
        assert!(reject_path_traversal("../etc/passwd").is_err());
    }

    #[test]
    fn test_reject_path_traversal_rejects_single_dot() {
        assert!(reject_path_traversal("/cart/./items").is_err());
        assert!(reject_path_traversal("/.").is_err());
    }

    #[test]
    fn test_reject_path_traversal_inspects_only_path_component() {
        // ".." inside a query value is not a path segment and must not trigger.
        assert!(reject_path_traversal("/products?search=..").is_ok());
        assert!(reject_path_traversal("/products?note=foo/../bar").is_ok());
    }
}
