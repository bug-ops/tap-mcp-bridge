//! Transport protocol abstraction layer.
//!
//! This module provides a sealed `Transport` trait that abstracts over
//! different transport protocols (HTTP/1.1, HTTP/2, HTTP/3, gRPC, JSON-RPC).
//! All implementations correctly integrate TAP signing per RFC 9421.
//!
//! # Architecture
//!
//! The transport layer separates protocol mechanics from data transformation:
//! - **Transport**: Handles protocol communication (HTTP, gRPC, etc.)
//! - **`MerchantApi`**: Handles data transformation (field mapping, endpoint resolution)
//!
//! # Examples
//!
//! ```rust,no_run
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::{
//!     tap::{InteractionType, TapSigner},
//!     transport::{HttpTransport, RequestContext, Transport},
//! };
//!
//! # async fn example() -> tap_mcp_bridge::error::Result<()> {
//! // Create transport
//! let transport = HttpTransport::new()?;
//!
//! // Create signer
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
//!
//! // Execute request
//! let ctx = RequestContext {
//!     base_url: "https://merchant.example.com",
//!     path: "/checkout",
//!     headers: vec![("Content-Type", "application/json")],
//!     content_type: Some("application/json"),
//!     interaction_type: InteractionType::Checkout,
//! };
//!
//! let response = transport.post(&signer, ctx, b"{\"amount\":99.99}").await?;
//! println!("Status: {}", response.status);
//! # Ok(())
//! # }
//! ```

#[allow(
    redundant_imports,
    reason = "Future needed for RPITIT despite being in Edition 2024 prelude"
)]
use std::future::Future;

use crate::{
    error::Result,
    tap::{InteractionType, TapSigner},
};

pub mod config;
pub mod http;
mod sealed;

pub use config::{HttpConfig, HttpVersion, TransportConfig};
pub use http::HttpTransport;

/// Request context for transport operations.
///
/// Contains all parameters needed to execute a TAP-signed request.
#[derive(Debug, Clone)]
pub struct RequestContext<'a> {
    /// Merchant base URL (e.g., <https://merchant.example.com>).
    pub base_url: &'a str,
    /// Request path (e.g., "/checkout").
    pub path: &'a str,
    /// Additional HTTP headers to include.
    pub headers: Vec<(&'a str, &'a str)>,
    /// Content-Type header value (if applicable).
    pub content_type: Option<&'a str>,
    /// TAP interaction type for signature generation.
    pub interaction_type: InteractionType,
}

/// Response from transport operations.
///
/// Contains the raw response body, HTTP status code, and response headers.
#[derive(Debug)]
pub struct TransportResponse {
    /// HTTP status code (or protocol equivalent).
    pub status: u16,
    /// Raw response body bytes.
    pub body: Vec<u8>,
    /// Response headers.
    pub headers: Vec<(String, String)>,
}

/// Transport protocol abstraction.
///
/// This trait is sealed to ensure all implementations undergo security review.
/// Only implementations within this crate are allowed.
///
/// # Protocol Support
///
/// | Protocol | Signing Method | Implementation |
/// |----------|----------------|----------------|
/// | HTTP/1.1 | RFC 9421 | `HttpTransport` |
/// | HTTP/2   | RFC 9421 | `HttpTransport` |
/// | HTTP/3   | RFC 9421 | Future |
/// | gRPC     | Envelope | Future |
/// | JSON-RPC | RFC 9421/Envelope | Future |
///
/// # Security
///
/// All transport implementations:
/// - Apply TAP signatures via `TapSigner`
/// - Validate merchant URLs (HTTPS only, no localhost)
/// - Include required TAP headers (Signature, Signature-Input, Signature-Agent)
/// - Support request timeouts and connection pooling
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
/// let transport = HttpTransport::new()?;
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
///
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
pub trait Transport: sealed::private::Sealed + Send + Sync {
    /// Executes a GET request.
    ///
    /// # Errors
    ///
    /// Returns error if signature generation, HTTP request, or response parsing fails.
    fn get<'a>(
        &'a self,
        signer: &'a TapSigner,
        ctx: RequestContext<'a>,
    ) -> impl Future<Output = Result<TransportResponse>> + Send + 'a;

    /// Executes a POST request with body.
    ///
    /// # Errors
    ///
    /// Returns error if signature generation, HTTP request, or response parsing fails.
    fn post<'a>(
        &'a self,
        signer: &'a TapSigner,
        ctx: RequestContext<'a>,
        body: &'a [u8],
    ) -> impl Future<Output = Result<TransportResponse>> + Send + 'a;

    /// Executes a PUT request with body.
    ///
    /// # Errors
    ///
    /// Returns error if signature generation, HTTP request, or response parsing fails.
    fn put<'a>(
        &'a self,
        signer: &'a TapSigner,
        ctx: RequestContext<'a>,
        body: &'a [u8],
    ) -> impl Future<Output = Result<TransportResponse>> + Send + 'a;

    /// Executes a DELETE request.
    ///
    /// # Errors
    ///
    /// Returns error if signature generation, HTTP request, or response parsing fails.
    fn delete<'a>(
        &'a self,
        signer: &'a TapSigner,
        ctx: RequestContext<'a>,
    ) -> impl Future<Output = Result<TransportResponse>> + Send + 'a;

    /// Returns the protocol name for metrics and logging.
    ///
    /// Examples: "http/1.1", "http/2", "grpc", "jsonrpc-http"
    fn protocol_name(&self) -> &'static str;

    /// Checks if the transport supports streaming responses.
    ///
    /// Default: false (no streaming support)
    fn supports_streaming(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_context_creation() {
        let ctx = RequestContext {
            base_url: "https://example.com",
            path: "/api/v1/test",
            headers: vec![("X-Custom", "value")],
            content_type: Some("application/json"),
            interaction_type: InteractionType::Checkout,
        };

        assert_eq!(ctx.base_url, "https://example.com");
        assert_eq!(ctx.path, "/api/v1/test");
        assert_eq!(ctx.headers.len(), 1);
        assert_eq!(ctx.headers[0], ("X-Custom", "value"));
        assert_eq!(ctx.content_type, Some("application/json"));
    }

    #[test]
    fn test_request_context_no_headers() {
        let ctx = RequestContext {
            base_url: "https://example.com",
            path: "/test",
            headers: vec![],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        assert_eq!(ctx.headers.len(), 0);
        assert!(ctx.content_type.is_none());
    }

    #[test]
    fn test_request_context_multiple_headers() {
        let ctx = RequestContext {
            base_url: "https://example.com",
            path: "/test",
            headers: vec![
                ("X-Custom-1", "value1"),
                ("X-Custom-2", "value2"),
                ("Authorization", "Bearer token"),
            ],
            content_type: Some("text/plain"),
            interaction_type: InteractionType::Browse,
        };

        assert_eq!(ctx.headers.len(), 3);
        assert_eq!(ctx.headers[0], ("X-Custom-1", "value1"));
        assert_eq!(ctx.headers[1], ("X-Custom-2", "value2"));
        assert_eq!(ctx.headers[2], ("Authorization", "Bearer token"));
    }

    #[test]
    fn test_request_context_clone() {
        let ctx = RequestContext {
            base_url: "https://example.com",
            path: "/test",
            headers: vec![("X-Header", "value")],
            content_type: Some("application/json"),
            interaction_type: InteractionType::Checkout,
        };

        let cloned = ctx.clone();
        assert_eq!(ctx.base_url, cloned.base_url);
        assert_eq!(ctx.path, cloned.path);
        assert_eq!(ctx.headers, cloned.headers);
        assert_eq!(ctx.content_type, cloned.content_type);
    }

    #[test]
    fn test_request_context_debug() {
        let ctx = RequestContext {
            base_url: "https://example.com",
            path: "/test",
            headers: vec![],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        let debug_str = format!("{ctx:?}");
        assert!(debug_str.contains("RequestContext"));
        assert!(debug_str.contains("https://example.com"));
        assert!(debug_str.contains("/test"));
    }

    #[test]
    fn test_transport_response_creation() {
        let response = TransportResponse {
            status: 200,
            body: b"test body".to_vec(),
            headers: vec![("Content-Type".to_owned(), "text/plain".to_owned())],
        };

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"test body");
        assert_eq!(response.headers.len(), 1);
        assert_eq!(response.headers[0].0, "Content-Type");
        assert_eq!(response.headers[0].1, "text/plain");
    }

    #[test]
    fn test_transport_response_empty_body() {
        let response = TransportResponse { status: 204, body: vec![], headers: vec![] };

        assert_eq!(response.status, 204);
        assert_eq!(response.body.len(), 0);
        assert_eq!(response.headers.len(), 0);
    }

    #[test]
    fn test_transport_response_multiple_headers() {
        let response = TransportResponse {
            status: 200,
            body: b"test".to_vec(),
            headers: vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Cache-Control".to_owned(), "no-cache".to_owned()),
                ("X-Custom".to_owned(), "value".to_owned()),
            ],
        };

        assert_eq!(response.headers.len(), 3);
        assert_eq!(response.headers[0].0, "Content-Type");
        assert_eq!(response.headers[1].0, "Cache-Control");
        assert_eq!(response.headers[2].0, "X-Custom");
    }

    #[test]
    fn test_transport_response_large_body() {
        let large_body = vec![0u8; 1024 * 1024]; // 1 MB
        let response = TransportResponse { status: 200, body: large_body.clone(), headers: vec![] };

        assert_eq!(response.body.len(), 1024 * 1024);
        assert_eq!(response.body, large_body);
    }

    #[test]
    fn test_transport_response_error_status() {
        let response =
            TransportResponse { status: 404, body: b"Not Found".to_vec(), headers: vec![] };

        assert_eq!(response.status, 404);
        assert_eq!(response.body, b"Not Found");
    }

    #[test]
    fn test_transport_response_debug() {
        let response = TransportResponse { status: 200, body: b"test".to_vec(), headers: vec![] };

        let debug_str = format!("{response:?}");
        assert!(debug_str.contains("TransportResponse"));
        assert!(debug_str.contains("200"));
    }

    #[test]
    fn test_request_context_with_empty_path() {
        let ctx = RequestContext {
            base_url: "https://example.com",
            path: "",
            headers: vec![],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        assert_eq!(ctx.path, "");
    }

    #[test]
    fn test_request_context_with_query_params() {
        let ctx = RequestContext {
            base_url: "https://example.com",
            path: "/api?foo=bar&baz=qux",
            headers: vec![],
            content_type: None,
            interaction_type: InteractionType::Browse,
        };

        assert!(ctx.path.contains('?'));
        assert!(ctx.path.contains("foo=bar"));
    }

    #[test]
    fn test_transport_response_binary_body() {
        let binary_data = vec![0xff, 0xfe, 0xfd, 0xfc];
        let response =
            TransportResponse { status: 200, body: binary_data.clone(), headers: vec![] };

        assert_eq!(response.body, binary_data);
    }
}
