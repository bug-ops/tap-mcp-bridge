//! HTTP transport implementation.
//!
//! This module provides HTTP/1.1 and HTTP/2 transport using reqwest.
//! All requests are TAP-signed per RFC 9421.

use std::{sync::LazyLock, time::Duration};

use reqwest::Client;
use tracing::instrument;
use url::Url;

use super::config::{HttpConfig, HttpVersion};
use crate::{
    error::{BridgeError, Result},
    tap::TapSigner,
    transport::{RequestContext, Transport, TransportResponse, sealed},
};

/// Default HTTP client with connection pooling enabled.
///
/// Using a singleton avoids recreating the client per transport instance,
/// preserving connection pooling benefits across all default transports.
static DEFAULT_HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .pool_max_idle_per_host(100)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .expect("Failed to create default HTTP client")
});

/// Validates URL for security constraints.
///
/// Ensures the URL uses HTTPS and does not point to localhost.
fn validate_url(url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        return Err(BridgeError::TransportError("Only HTTPS URLs are allowed".to_owned()));
    }

    if let Some(host) = url.host_str()
        && (host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]")
    {
        return Err(BridgeError::TransportError("Localhost URLs are not allowed".to_owned()));
    }

    Ok(())
}

/// Sanitizes path to prevent path traversal attacks.
///
/// Rejects paths containing directory traversal sequences.
fn sanitize_path(path: &str) -> Result<&str> {
    if path.contains("..") || path.contains("//") {
        return Err(BridgeError::TransportError(
            "Invalid path: traversal sequences not allowed".to_owned(),
        ));
    }
    if !path.is_empty() && !path.starts_with('/') {
        return Err(BridgeError::TransportError("Path must start with '/'".to_owned()));
    }
    Ok(path)
}

/// Validates header name and value for CRLF injection prevention.
fn validate_header(name: &str, value: &str) -> Result<()> {
    if name.contains('\r') || name.contains('\n') || name.contains('\0') {
        return Err(BridgeError::TransportError(
            "Invalid header name: control characters not allowed".to_owned(),
        ));
    }
    if value.contains('\r') || value.contains('\n') || value.contains('\0') {
        return Err(BridgeError::TransportError(
            "Invalid header value: control characters not allowed".to_owned(),
        ));
    }
    Ok(())
}

/// HTTP/1.1 and HTTP/2 transport using reqwest.
///
/// Supports automatic connection pooling, keep-alive, and HTTP/2 multiplexing.
/// All requests are authenticated with TAP signatures per RFC 9421.
///
/// # Examples
///
/// ```rust,no_run
/// use ed25519_dalek::SigningKey;
/// use tap_mcp_bridge::{
///     tap::{InteractionType, TapSigner},
///     transport::{HttpTransport, RequestContext, Transport},
/// };
///
/// # async fn example() -> tap_mcp_bridge::error::Result<()> {
/// // Create transport with default config
/// let transport = HttpTransport::new()?;
///
/// // Create signer
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
///
/// // Execute GET request
/// let ctx = RequestContext {
///     base_url: "https://merchant.example.com",
///     path: "/products",
///     headers: vec![],
///     content_type: None,
///     interaction_type: InteractionType::Browse,
/// };
///
/// let response = transport.get(&signer, ctx).await?;
/// println!("Status: {}", response.status);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct HttpTransport {
    client: Client,
    http_version: HttpVersion,
}

impl sealed::private::Sealed for HttpTransport {}

impl HttpTransport {
    /// Creates a new HTTP transport with default settings.
    ///
    /// Uses a shared singleton client for connection pooling efficiency.
    ///
    /// Default configuration:
    /// - Pool max idle per host: 100
    /// - Timeout: 30 seconds
    /// - Connect timeout: 10 seconds
    /// - HTTP version: Auto (prefer HTTP/2)
    ///
    /// # Errors
    ///
    /// This method is infallible but returns `Result` for API consistency.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::transport::HttpTransport;
    ///
    /// let transport = HttpTransport::new().unwrap();
    /// ```
    pub fn new() -> Result<Self> {
        Ok(Self { client: DEFAULT_HTTP_CLIENT.clone(), http_version: HttpVersion::Auto })
    }

    /// Creates HTTP transport with custom configuration.
    ///
    /// # Errors
    ///
    /// Returns error if HTTP client creation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::transport::{HttpConfig, HttpTransport, HttpVersion};
    ///
    /// let config = HttpConfig {
    ///     pool_max_idle_per_host: 20,
    ///     timeout_secs: 60,
    ///     connect_timeout_secs: 15,
    ///     http_version: HttpVersion::Http2,
    /// };
    ///
    /// let transport = HttpTransport::with_config(&config).unwrap();
    /// ```
    pub fn with_config(config: &HttpConfig) -> Result<Self> {
        let mut builder = Client::builder()
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .timeout(config.timeout())
            .connect_timeout(config.connect_timeout());

        builder = match config.http_version {
            HttpVersion::Http1 => builder.http1_only(),
            HttpVersion::Http2 => builder.http2_prior_knowledge(),
            HttpVersion::Auto => builder,
        };

        let client = builder.build().map_err(BridgeError::HttpError)?;

        Ok(Self { client, http_version: config.http_version })
    }

    /// Internal method to execute HTTP request with TAP signing.
    #[instrument(
        skip(self, signer, ctx, body),
        fields(
            method,
            base_url = ctx.base_url,
            path = ctx.path,
            interaction_type = ?ctx.interaction_type
        )
    )]
    async fn execute_request(
        &self,
        signer: &TapSigner,
        ctx: RequestContext<'_>,
        method: &str,
        body: Option<&[u8]>,
    ) -> Result<TransportResponse> {
        let url = Url::parse(ctx.base_url)
            .map_err(|e| BridgeError::InvalidMerchantUrl(format!("invalid base_url: {e}")))?;

        // Security: Validate URL scheme and host
        validate_url(&url)?;

        // Security: Sanitize path to prevent traversal attacks
        let path = sanitize_path(ctx.path)?;

        // Security: Validate custom headers for CRLF injection
        for (key, value) in &ctx.headers {
            validate_header(key, value)?;
        }

        let authority = url.host_str().ok_or_else(|| {
            BridgeError::InvalidMerchantUrl(format!("URL missing host: {}", ctx.base_url))
        })?;

        let body_bytes = body.unwrap_or(&[]);
        let signature =
            signer.sign_request(method, authority, path, body_bytes, ctx.interaction_type)?;

        let full_url = format!("{}{path}", ctx.base_url.trim_end_matches('/'));

        let mut request = match method {
            "GET" => self.client.get(&full_url),
            "POST" => self.client.post(&full_url),
            "PUT" => self.client.put(&full_url),
            "DELETE" => self.client.delete(&full_url),
            _ => {
                return Err(BridgeError::InvalidInput(format!(
                    "unsupported HTTP method: {method}"
                )));
            }
        };

        let content_digest = TapSigner::compute_content_digest(body_bytes);

        request = request
            .header("Signature", &signature.signature)
            .header("Signature-Input", &signature.signature_input)
            .header("Signature-Agent", signature.agent_directory.as_ref())
            .header("Content-Digest", &content_digest);

        if let Some(content_type) = ctx.content_type {
            request = request.header("Content-Type", content_type);
        }

        for (key, value) in ctx.headers {
            request = request.header(key, value);
        }

        if !body_bytes.is_empty() {
            request = request.body(body_bytes.to_vec());
        }

        let response = request.send().await?;

        let status = response.status().as_u16();

        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_owned()))
            .collect();

        if !response.status().is_success() {
            return Err(BridgeError::MerchantError(format!("merchant returned status {status}")));
        }

        let response_body = response.bytes().await.map_err(BridgeError::HttpError)?.to_vec();

        Ok(TransportResponse { status, body: response_body, headers })
    }
}

impl Transport for HttpTransport {
    async fn get<'a>(
        &'a self,
        signer: &'a TapSigner,
        ctx: RequestContext<'a>,
    ) -> Result<TransportResponse> {
        self.execute_request(signer, ctx, "GET", None).await
    }

    async fn post<'a>(
        &'a self,
        signer: &'a TapSigner,
        ctx: RequestContext<'a>,
        body: &'a [u8],
    ) -> Result<TransportResponse> {
        self.execute_request(signer, ctx, "POST", Some(body)).await
    }

    async fn put<'a>(
        &'a self,
        signer: &'a TapSigner,
        ctx: RequestContext<'a>,
        body: &'a [u8],
    ) -> Result<TransportResponse> {
        self.execute_request(signer, ctx, "PUT", Some(body)).await
    }

    async fn delete<'a>(
        &'a self,
        signer: &'a TapSigner,
        ctx: RequestContext<'a>,
    ) -> Result<TransportResponse> {
        self.execute_request(signer, ctx, "DELETE", None).await
    }

    fn protocol_name(&self) -> &'static str {
        match self.http_version {
            HttpVersion::Http1 => "http/1.1",
            HttpVersion::Http2 => "http/2",
            HttpVersion::Auto => "http",
        }
    }

    fn supports_streaming(&self) -> bool {
        matches!(self.http_version, HttpVersion::Http2 | HttpVersion::Auto)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::tap::InteractionType;

    #[test]
    fn test_http_transport_new() {
        let transport = HttpTransport::new();
        assert!(transport.is_ok());
    }

    #[test]
    fn test_http_transport_with_config() {
        let config = HttpConfig {
            pool_max_idle_per_host: 20,
            timeout_secs: 60,
            connect_timeout_secs: 15,
            http_version: HttpVersion::Http2,
        };

        let transport = HttpTransport::with_config(&config);
        assert!(transport.is_ok());

        let transport = transport.unwrap();
        assert_eq!(transport.protocol_name(), "http/2");
        assert!(transport.supports_streaming());
    }

    #[test]
    fn test_http_transport_protocol_name() {
        let config_http1 = HttpConfig { http_version: HttpVersion::Http1, ..Default::default() };
        let transport_http1 = HttpTransport::with_config(&config_http1).unwrap();
        assert_eq!(transport_http1.protocol_name(), "http/1.1");
        assert!(!transport_http1.supports_streaming());

        let config_http2 = HttpConfig { http_version: HttpVersion::Http2, ..Default::default() };
        let transport_http2 = HttpTransport::with_config(&config_http2).unwrap();
        assert_eq!(transport_http2.protocol_name(), "http/2");
        assert!(transport_http2.supports_streaming());

        let config_auto = HttpConfig { http_version: HttpVersion::Auto, ..Default::default() };
        let transport_auto = HttpTransport::with_config(&config_auto).unwrap();
        assert_eq!(transport_auto.protocol_name(), "http");
        assert!(transport_auto.supports_streaming());
    }

    #[tokio::test]
    async fn test_http_transport_get_invalid_url() {
        let transport = HttpTransport::new().unwrap();
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let ctx = RequestContext {
            base_url: "not-a-url",
            path: "/test",
            headers: vec![],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        let result = transport.get(&signer, ctx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::InvalidMerchantUrl(_)));
    }

    #[test]
    fn test_http_transport_default_config() {
        let transport = HttpTransport::new().unwrap();
        assert_eq!(transport.protocol_name(), "http");
    }

    #[tokio::test]
    async fn test_http_transport_url_missing_host() {
        let transport = HttpTransport::new().unwrap();
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let ctx = RequestContext {
            base_url: "file:///path/to/file",
            path: "/test",
            headers: vec![],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        let result = transport.get(&signer, ctx).await;
        assert!(result.is_err());
        // Now rejects file:// URLs due to HTTPS-only policy
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));
    }

    #[tokio::test]
    async fn test_http_transport_post_empty_body() {
        let transport = HttpTransport::new().unwrap();
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let ctx = RequestContext {
            base_url: "https://httpbin.org",
            path: "/post",
            headers: vec![],
            content_type: Some("application/json"),
            interaction_type: InteractionType::Checkout,
        };

        let _result = transport.post(&signer, ctx, b"").await;
        // Test passes if request can be sent (any result is acceptable)
    }

    #[tokio::test]
    async fn test_http_transport_with_custom_headers() {
        let transport = HttpTransport::new().unwrap();
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let ctx = RequestContext {
            base_url: "https://httpbin.org",
            path: "/get",
            headers: vec![("X-Custom-Header", "test-value"), ("X-Another", "value2")],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        let _result = transport.get(&signer, ctx).await;
        // Test passes if request can be sent (any result is acceptable)
    }

    #[test]
    fn test_http_transport_with_zero_pool_size() {
        let config = HttpConfig {
            pool_max_idle_per_host: 0,
            timeout_secs: 30,
            connect_timeout_secs: 10,
            http_version: HttpVersion::Auto,
        };

        let transport = HttpTransport::with_config(&config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_http_transport_with_large_pool_size() {
        let config = HttpConfig {
            pool_max_idle_per_host: 10000,
            timeout_secs: 30,
            connect_timeout_secs: 10,
            http_version: HttpVersion::Auto,
        };

        let transport = HttpTransport::with_config(&config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_http_transport_with_zero_timeout() {
        let config = HttpConfig {
            pool_max_idle_per_host: 10,
            timeout_secs: 0,
            connect_timeout_secs: 0,
            http_version: HttpVersion::Auto,
        };

        let transport = HttpTransport::with_config(&config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_http_transport_with_large_timeout() {
        let config = HttpConfig {
            pool_max_idle_per_host: 10,
            timeout_secs: 3600,
            connect_timeout_secs: 300,
            http_version: HttpVersion::Auto,
        };

        let transport = HttpTransport::with_config(&config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_http_transport_http1_only() {
        let config = HttpConfig {
            pool_max_idle_per_host: 10,
            timeout_secs: 30,
            connect_timeout_secs: 10,
            http_version: HttpVersion::Http1,
        };

        let transport = HttpTransport::with_config(&config).unwrap();
        assert_eq!(transport.protocol_name(), "http/1.1");
        assert!(!transport.supports_streaming());
    }

    #[tokio::test]
    async fn test_http_transport_url_with_trailing_slash() {
        let transport = HttpTransport::new().unwrap();
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let ctx = RequestContext {
            base_url: "https://httpbin.org/",
            path: "/get",
            headers: vec![],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        let _result = transport.get(&signer, ctx).await;
        // Test passes if request can be sent (any result is acceptable)
    }

    #[tokio::test]
    async fn test_http_transport_path_without_leading_slash() {
        let transport = HttpTransport::new().unwrap();
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let ctx = RequestContext {
            base_url: "https://httpbin.org",
            path: "api/test",
            headers: vec![],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        let result = transport.get(&signer, ctx).await;
        // Now rejects paths without leading slash
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));
    }

    #[tokio::test]
    async fn test_http_transport_put_request() {
        let transport = HttpTransport::new().unwrap();
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let ctx = RequestContext {
            base_url: "https://httpbin.org",
            path: "/put",
            headers: vec![],
            content_type: Some("application/json"),
            interaction_type: InteractionType::Checkout,
        };

        let _result = transport.put(&signer, ctx, b"{\"test\":\"data\"}").await;
        // Test passes if request can be sent (any result is acceptable)
    }

    #[tokio::test]
    async fn test_http_transport_delete_request() {
        let transport = HttpTransport::new().unwrap();
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let ctx = RequestContext {
            base_url: "https://httpbin.org",
            path: "/delete",
            headers: vec![],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        let _result = transport.delete(&signer, ctx).await;
        // Test passes if request can be sent (any result is acceptable)
    }

    #[tokio::test]
    async fn test_http_transport_post_with_content_type() {
        let transport = HttpTransport::new().unwrap();
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let ctx = RequestContext {
            base_url: "https://httpbin.org",
            path: "/post",
            headers: vec![],
            content_type: Some("application/x-www-form-urlencoded"),
            interaction_type: InteractionType::Checkout,
        };

        let _result = transport.post(&signer, ctx, b"key=value&key2=value2").await;
        // Test passes if request can be sent (any result is acceptable)
    }

    #[test]
    fn test_http_transport_debug_format() {
        let transport = HttpTransport::new().unwrap();
        let debug_str = format!("{transport:?}");
        assert!(debug_str.contains("HttpTransport"));
    }

    // Security validation tests

    #[test]
    fn test_validate_url_https_required() {
        let https_url = Url::parse("https://example.com").unwrap();
        assert!(validate_url(&https_url).is_ok());

        let http_url = Url::parse("http://example.com").unwrap();
        let result = validate_url(&http_url);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));
    }

    #[test]
    fn test_validate_url_localhost_blocked() {
        let localhost = Url::parse("https://localhost/api").unwrap();
        let result = validate_url(&localhost);
        assert!(result.is_err());

        let ipv4_localhost = Url::parse("https://127.0.0.1/api").unwrap();
        let result = validate_url(&ipv4_localhost);
        assert!(result.is_err());

        let ipv6_localhost = Url::parse("https://[::1]/api").unwrap();
        let result = validate_url(&ipv6_localhost);
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_path_valid() {
        assert!(sanitize_path("/api/users").is_ok());
        assert!(sanitize_path("/").is_ok());
        assert!(sanitize_path("").is_ok());
        assert!(sanitize_path("/api/v1/users/123").is_ok());
    }

    #[test]
    fn test_sanitize_path_traversal_blocked() {
        let result = sanitize_path("/../etc/passwd");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));

        let result = sanitize_path("/api/../config");
        assert!(result.is_err());

        // URL-encoded dots (%2e%2e) are allowed since they're different strings
        // Note: webserver should decode before filesystem access
        assert!(sanitize_path("/api/%2e%2e/etc").is_ok());

        let result = sanitize_path("/api//secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_path_leading_slash_required() {
        let result = sanitize_path("api/users");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));
    }

    #[test]
    fn test_validate_header_valid() {
        assert!(validate_header("Content-Type", "application/json").is_ok());
        assert!(validate_header("X-Custom", "some-value").is_ok());
    }

    #[test]
    fn test_validate_header_crlf_injection_blocked() {
        // CRLF in header name
        let result = validate_header("X-Evil\r\n", "value");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));

        // CRLF in header value
        let result = validate_header("X-Custom", "value\r\nEvil-Header: injected");
        assert!(result.is_err());

        // Null byte in header name
        let result = validate_header("X-Evil\0", "value");
        assert!(result.is_err());

        // Null byte in header value
        let result = validate_header("X-Custom", "value\0evil");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_http_transport_rejects_http_url() {
        let transport = HttpTransport::new().unwrap();
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let ctx = RequestContext {
            base_url: "http://httpbin.org",
            path: "/get",
            headers: vec![],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        let result = transport.get(&signer, ctx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));
    }

    #[tokio::test]
    async fn test_http_transport_rejects_localhost() {
        let transport = HttpTransport::new().unwrap();
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let ctx = RequestContext {
            base_url: "https://localhost",
            path: "/api",
            headers: vec![],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        let result = transport.get(&signer, ctx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));
    }

    #[tokio::test]
    async fn test_http_transport_rejects_path_traversal() {
        let transport = HttpTransport::new().unwrap();
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let ctx = RequestContext {
            base_url: "https://httpbin.org",
            path: "/../etc/passwd",
            headers: vec![],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        let result = transport.get(&signer, ctx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));
    }

    #[tokio::test]
    async fn test_http_transport_rejects_crlf_header() {
        let transport = HttpTransport::new().unwrap();
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

        let ctx = RequestContext {
            base_url: "https://httpbin.org",
            path: "/get",
            headers: vec![("X-Evil\r\n", "value")],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        let result = transport.get(&signer, ctx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));
    }

    #[test]
    fn test_default_http_client_is_singleton() {
        // Verify the singleton client is usable
        let _client = &*DEFAULT_HTTP_CLIENT;
        // Client should have connection pooling enabled
    }
}
