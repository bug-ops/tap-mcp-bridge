//! TAP-MCP Server - MCP server binary for TAP integration with AI agents
//!
//! This binary exposes TAP (Trusted Agent Protocol) functionality as MCP tools,
//! enabling AI agents to authenticate with TAP-protected merchants.
//!
//! # Configuration
//!
//! The server is configured via environment variables:
//! - `TAP_AGENT_ID`: Agent identifier (required, alphanumeric + `-_`, max 64 chars)
//! - `TAP_AGENT_DIRECTORY`: Agent directory URL (required, must be HTTPS)
//! - `TAP_SIGNING_KEY`: Ed25519 private key in hex format (required, 64 hex chars)
//! - `RUST_LOG`: Log level (optional, default: "info")
//!
//! # Example
//!
//! ```bash
//! export TAP_AGENT_ID="agent-123"
//! export TAP_AGENT_DIRECTORY="https://agent.example.com"
//! export TAP_SIGNING_KEY="0123456789abcdef..."  # 64 hex chars
//! export RUST_LOG="info"
//! tap-mcp-server
//! ```

#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "Transitive dependency version conflicts from rmcp and reqwest"
)]

use std::{env, sync::Arc};

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::{tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolRequestParam, CallToolResult, Content, ListToolsResult, PaginatedRequestParam,
    },
    schemars,
    schemars::JsonSchema,
    service::{RequestContext, ServiceExt},
    tool, tool_router, transport,
};
use serde::Deserialize;
use tap_mcp_bridge::{
    mcp::{BrowseParams, CheckoutParams, browse_merchant, checkout_with_tap},
    tap::TapSigner,
};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Configuration for TAP-MCP server loaded from environment variables.
#[derive(Debug, Clone)]
struct Config {
    /// Agent identifier (alphanumeric + `-_`, max 64 chars)
    agent_id: String,
    /// Agent directory URL (must be HTTPS)
    agent_directory: String,
    /// Ed25519 signing key in hex format (64 hex chars = 32 bytes)
    signing_key_hex: String,
}

impl Config {
    /// Loads configuration from environment variables with comprehensive validation.
    ///
    /// # Errors
    ///
    /// Returns error if any required variable is missing or invalid.
    fn from_env() -> Result<Self> {
        let agent_id = env::var("TAP_AGENT_ID").context(
            "TAP_AGENT_ID environment variable is required. Example: export \
             TAP_AGENT_ID='agent-123'",
        )?;

        // Validate agent_id format
        Self::validate_agent_id(&agent_id)?;

        let agent_directory = env::var("TAP_AGENT_DIRECTORY")
            .context("TAP_AGENT_DIRECTORY environment variable is required. Example: export TAP_AGENT_DIRECTORY='https://agent.example.com'")?;

        // Validate agent_directory is HTTPS
        Self::validate_agent_directory(&agent_directory)?;

        let signing_key_hex = env::var("TAP_SIGNING_KEY").context(
            "TAP_SIGNING_KEY environment variable is required. Example: export \
             TAP_SIGNING_KEY='0123456789abcdef...' (64 hex chars)",
        )?;

        // Validate signing key format
        Self::validate_signing_key(&signing_key_hex)?;

        Ok(Self { agent_id, agent_directory, signing_key_hex })
    }

    /// Validates agent ID format (alphanumeric + `-_`, 1-64 chars).
    fn validate_agent_id(agent_id: &str) -> Result<()> {
        if agent_id.is_empty() {
            bail!("TAP_AGENT_ID cannot be empty");
        }

        if agent_id.len() > 64 {
            bail!("TAP_AGENT_ID must be at most 64 characters, got {}", agent_id.len());
        }

        if !agent_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            bail!(
                "TAP_AGENT_ID must contain only alphanumeric characters, hyphens, and \
                 underscores. Got: '{agent_id}'"
            );
        }

        Ok(())
    }

    /// Validates agent directory is a valid HTTPS URL.
    fn validate_agent_directory(url_str: &str) -> Result<()> {
        if !url_str.starts_with("https://") {
            bail!(
                "TAP_AGENT_DIRECTORY must be an HTTPS URL. Got: '{url_str}'. Example: \
                 https://agent.example.com"
            );
        }

        // Basic URL validation
        url::Url::parse(url_str).with_context(|| {
            format!("TAP_AGENT_DIRECTORY must be a valid HTTPS URL. Got: '{url_str}'")
        })?;

        Ok(())
    }

    /// Validates signing key is exactly 64 hex characters (32 bytes).
    fn validate_signing_key(key_hex: &str) -> Result<()> {
        if key_hex.len() != 64 {
            bail!(
                "TAP_SIGNING_KEY must be exactly 64 hex characters (32 bytes). Got {} characters",
                key_hex.len()
            );
        }

        if !key_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("TAP_SIGNING_KEY must contain only hexadecimal characters (0-9, a-f, A-F)");
        }

        Ok(())
    }
}

/// Initializes logging with tracing-subscriber.
///
/// Respects `RUST_LOG` environment variable for log level filtering.
/// Default log level is "info" if `RUST_LOG` is not set.
fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false).with_thread_ids(false))
        .with(filter)
        .init();
}

/// Creates TAP signer from configuration.
///
/// Parses the hex-encoded signing key and creates a `TapSigner` instance.
///
/// # Errors
///
/// Returns error if signing key parsing fails.
fn create_signer(config: &Config) -> Result<TapSigner> {
    // Parse hex key to bytes
    let key_bytes = hex::decode(&config.signing_key_hex).context(
        "Failed to decode TAP_SIGNING_KEY as hexadecimal. Ensure it contains only 0-9, a-f \
         characters",
    )?;

    // Convert to fixed-size array
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("TAP_SIGNING_KEY must decode to exactly 32 bytes"))?;

    // Create signing key
    let signing_key = SigningKey::from_bytes(&key_array);

    // Create TAP signer
    Ok(TapSigner::new(signing_key, &config.agent_id, &config.agent_directory))
}

/// Checkout request parameters wrapper for MCP deserialization
#[derive(Debug, Deserialize, JsonSchema)]
struct CheckoutRequest {
    /// Merchant URL
    merchant_url: String,
    /// Consumer identifier
    consumer_id: String,
    /// Purchase intent
    intent: String,
    /// ISO 3166-1 alpha-2 country code
    country_code: String,
    /// Postal code
    zip: String,
    /// IP address
    ip_address: String,
    /// User agent
    user_agent: String,
    /// Platform
    platform: String,
}

/// Browse request parameters wrapper for MCP deserialization
#[derive(Debug, Deserialize, JsonSchema)]
struct BrowseRequest {
    /// Merchant URL
    merchant_url: String,
    /// Consumer identifier
    consumer_id: String,
    /// ISO 3166-1 alpha-2 country code
    country_code: String,
    /// Postal code
    zip: String,
    /// IP address
    ip_address: String,
    /// User agent
    user_agent: String,
    /// Platform
    platform: String,
}

/// TAP-MCP Server implementing MCP server handler.
///
/// This server exposes TAP functionality as MCP tools for Claude Desktop.
#[derive(Clone)]
pub struct TapMcpServer {
    /// Shared TAP signer (wrapped in Arc since `SigningKey` doesn't implement `Clone`)
    signer: Arc<TapSigner>,
    /// Tool router for MCP tool registration
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for TapMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TapMcpServer")
            .field("signer", &"[TapSigner]")
            .field("tool_router", &"[ToolRouter]")
            .finish()
    }
}

#[tool_router]
impl TapMcpServer {
    /// Creates a new TAP-MCP server with the given signer.
    fn new(signer: TapSigner) -> Self {
        Self { signer: Arc::new(signer), tool_router: Self::tool_router() }
    }

    /// Execute a payment checkout with TAP authentication
    #[tool(
        description = "Execute a payment checkout with TAP (Trusted Agent Protocol) authentication"
    )]
    async fn checkout_with_tap(
        &self,
        params: Parameters<CheckoutRequest>,
    ) -> Result<CallToolResult, McpError> {
        info!(
            tool = "checkout_with_tap",
            merchant_url = %params.0.merchant_url,
            consumer_id = %params.0.consumer_id,
            "received tool invocation"
        );

        // Convert MCP params to library params
        let checkout_params = CheckoutParams {
            merchant_url: params.0.merchant_url,
            consumer_id: params.0.consumer_id,
            intent: params.0.intent,
            country_code: params.0.country_code,
            zip: params.0.zip,
            ip_address: params.0.ip_address,
            user_agent: params.0.user_agent,
            platform: params.0.platform,
        };

        // Execute checkout
        let result = checkout_with_tap(&self.signer, checkout_params).await.map_err(|e| {
            error!(error = %e, "checkout failed");
            McpError::invalid_request(format!("Checkout failed: {e}"), None)
        })?;

        info!(
            status = %result.status,
            "checkout completed successfully"
        );

        // Return result
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Status: {}\nMessage: {}",
            result.status, result.message
        ))]))
    }

    /// Browse merchant catalog with verified agent identity
    #[tool(
        description = "Browse merchant catalog with TAP (Trusted Agent Protocol) authentication"
    )]
    async fn browse_merchant(
        &self,
        params: Parameters<BrowseRequest>,
    ) -> Result<CallToolResult, McpError> {
        info!(
            tool = "browse_merchant",
            merchant_url = %params.0.merchant_url,
            consumer_id = %params.0.consumer_id,
            "received tool invocation"
        );

        // Convert MCP params to library params
        let browse_params = BrowseParams {
            merchant_url: params.0.merchant_url,
            consumer_id: params.0.consumer_id,
            country_code: params.0.country_code,
            zip: params.0.zip,
            ip_address: params.0.ip_address,
            user_agent: params.0.user_agent,
            platform: params.0.platform,
        };

        // Execute browse
        let result = browse_merchant(&self.signer, browse_params).await.map_err(|e| {
            error!(error = %e, "browse failed");
            McpError::invalid_request(format!("Browse failed: {e}"), None)
        })?;

        info!(
            status = %result.status,
            "browse completed successfully"
        );

        // Return result
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Status: {}\nData: {}",
            result.status, result.data
        ))]))
    }
}

impl ServerHandler for TapMcpServer {
    async fn list_tools(
        &self,
        _pagination: Option<PaginatedRequestParam>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult { tools: self.tool_router.list_all(), next_cursor: None })
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParam,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        use rmcp::handler::server::tool::ToolCallContext;

        let context = ToolCallContext::new(self, params, ctx);
        self.tool_router.call(context).await
    }
}

/// Main entry point for TAP-MCP server.
///
/// Initializes logging, loads configuration, creates TAP signer,
/// sets up MCP server with tools, and runs with graceful shutdown.
///
/// # Errors
///
/// Returns error if initialization, configuration, or server execution fails.
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging first
    init_logging();

    info!("Starting TAP-MCP Server");

    // Load and validate configuration
    let config = Config::from_env().context("Failed to load configuration")?;

    info!("Configuration loaded successfully");
    info!(agent_id = %config.agent_id, "Agent ID");
    info!(agent_directory = %config.agent_directory, "Agent Directory");
    info!("Signing key: [REDACTED]");

    // Create TAP signer
    let signer = create_signer(&config).context("Failed to create TAP signer")?;

    info!("TAP signer created successfully");

    // Create server with tools
    let server = TapMcpServer::new(signer);

    info!("MCP server configured with tools: checkout_with_tap, browse_merchant");
    info!("MCP server started, listening on stdio");
    info!("Press Ctrl+C to shutdown");

    // Serve on stdio transport with graceful shutdown
    let transport = transport::stdio();

    // Run server with graceful shutdown
    tokio::select! {
        result = server.serve(transport) => {
            result.context("Server execution failed")?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal (Ctrl+C)");
        }
    }

    info!("Server shutdown complete");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_agent_id() {
        // Valid IDs
        assert!(Config::validate_agent_id("agent-123").is_ok());
        assert!(Config::validate_agent_id("my_agent").is_ok());
        assert!(Config::validate_agent_id("a").is_ok());

        // Invalid IDs
        assert!(Config::validate_agent_id("").is_err());
        assert!(Config::validate_agent_id(&"a".repeat(65)).is_err());
        assert!(Config::validate_agent_id("agent@123").is_err());
        assert!(Config::validate_agent_id("agent 123").is_err());
    }

    #[test]
    fn test_validate_agent_directory() {
        // Valid URLs
        assert!(Config::validate_agent_directory("https://agent.example.com").is_ok());
        assert!(Config::validate_agent_directory("https://localhost:8080").is_ok());

        // Invalid URLs
        assert!(Config::validate_agent_directory("http://agent.example.com").is_err());
        assert!(Config::validate_agent_directory("agent.example.com").is_err());
        assert!(Config::validate_agent_directory("").is_err());
    }

    #[test]
    fn test_validate_signing_key() {
        // Valid keys
        assert!(Config::validate_signing_key(&"0".repeat(64)).is_ok());
        assert!(Config::validate_signing_key(&"abcdef0123456789".repeat(4)).is_ok());

        // Invalid keys
        assert!(Config::validate_signing_key(&"0".repeat(63)).is_err());
        assert!(Config::validate_signing_key(&"0".repeat(65)).is_err());
        assert!(Config::validate_signing_key("not-hex-chars!!!").is_err());
    }

    #[test]
    fn test_create_signer_with_valid_key() {
        let config = Config {
            agent_id: "test-agent".to_owned(),
            agent_directory: "https://agent.example.com".to_owned(),
            signing_key_hex: "0".repeat(64),
        };

        let result = create_signer(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_signer_with_invalid_key() {
        let config = Config {
            agent_id: "test-agent".to_owned(),
            agent_directory: "https://agent.example.com".to_owned(),
            signing_key_hex: "not-hex".to_owned(),
        };

        let result = create_signer(&config);
        assert!(result.is_err());
    }
}
