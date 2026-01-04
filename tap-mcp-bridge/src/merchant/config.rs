//! Merchant configuration types.
//!
//! This module defines TOML-deserializable configuration structures for merchants.

use std::collections::HashMap;

use serde::Deserialize;
use url::Url;

use crate::error::{BridgeError, Result};

/// Root merchant configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MerchantConfig {
    /// Merchant display name.
    pub name: String,

    /// Base URL for the merchant API.
    pub base_url: String,

    /// API version prefix (e.g., "/api/v1").
    #[serde(default)]
    pub api_prefix: String,

    /// Endpoint configuration.
    #[serde(default)]
    pub endpoints: EndpointConfig,

    /// Field mapping configuration.
    #[serde(default)]
    pub field_mappings: FieldMappingConfig,

    /// Authentication configuration.
    #[serde(default)]
    pub auth: Option<AuthConfig>,

    /// Pagination style.
    #[serde(default)]
    pub pagination: PaginationStyle,
}

impl Default for MerchantConfig {
    fn default() -> Self {
        Self {
            name: "Default Merchant".to_owned(),
            base_url: String::new(),
            api_prefix: String::new(),
            endpoints: EndpointConfig::default(),
            field_mappings: FieldMappingConfig::default(),
            auth: None,
            pagination: PaginationStyle::default(),
        }
    }
}

impl MerchantConfig {
    /// Validates the merchant configuration for security issues.
    ///
    /// This method checks for:
    /// - Base URL must be HTTPS (not HTTP)
    /// - Base URL must not be localhost or loopback addresses
    /// - Endpoint templates must not contain path traversal sequences
    /// - Field mapping names must not contain injection patterns
    /// - Environment variable names in auth config must be alphanumeric
    /// - `OAuth2` token URLs must be HTTPS
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::MerchantConfigError` if any validation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::merchant::MerchantConfig;
    ///
    /// let toml = r#"
    ///     name = "Test"
    ///     base_url = "https://api.example.com"
    /// "#;
    ///
    /// let config: MerchantConfig = toml::from_str(toml).unwrap();
    /// assert!(config.validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<()> {
        // Validate base_url if not empty (empty is allowed for default config)
        if !self.base_url.is_empty() {
            self.validate_base_url()?;
        }

        // Validate endpoint templates
        self.endpoints.validate()?;

        // Validate field mappings
        self.field_mappings.validate()?;

        // Validate auth configuration
        if let Some(ref auth) = self.auth {
            auth.validate()?;
        }

        Ok(())
    }

    /// Validates the base URL.
    fn validate_base_url(&self) -> Result<()> {
        let url = Url::parse(&self.base_url).map_err(|e| {
            BridgeError::MerchantConfigError(format!("invalid base_url '{}': {e}", self.base_url))
        })?;

        // Must be HTTPS
        if url.scheme() != "https" {
            return Err(BridgeError::MerchantConfigError(format!(
                "base_url must use HTTPS, got: {}",
                url.scheme()
            )));
        }

        // Check for localhost/loopback
        if let Some(host) = url.host_str() {
            let host_lower = host.to_lowercase();
            if host_lower == "localhost"
                || host_lower == "127.0.0.1"
                || host_lower == "::1"
                || host_lower.starts_with("127.")
                || host_lower == "[::1]"
            {
                return Err(BridgeError::MerchantConfigError(format!(
                    "base_url must not be localhost or loopback: {host}"
                )));
            }
        }

        Ok(())
    }
}

/// Endpoint path overrides.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EndpointConfig {
    /// Products list endpoint (default: "/products").
    pub products: Option<String>,

    /// Single product endpoint template (default: "/products/{id}").
    /// Use `{id}` as placeholder for product ID.
    pub product: Option<String>,

    /// Cart endpoint (default: "/cart").
    pub cart: Option<String>,

    /// Add to cart endpoint (default: "/cart/add").
    pub add_to_cart: Option<String>,

    /// Cart item endpoint template (default: "/cart/items/{id}").
    pub cart_item: Option<String>,

    /// Orders endpoint (default: "/orders").
    pub orders: Option<String>,

    /// Single order endpoint template (default: "/orders/{id}").
    pub order: Option<String>,

    /// Checkout/payment endpoint (default: "/checkout").
    pub checkout: Option<String>,
}

impl EndpointConfig {
    /// Validates endpoint templates for security issues.
    ///
    /// Checks that endpoint templates:
    /// - Do not contain path traversal sequences (`..`, `//`)
    /// - Do not start with absolute paths on Windows (`C:`, `D:`, etc.)
    /// - Start with `/` (relative paths only)
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::MerchantConfigError` if any endpoint is invalid.
    pub fn validate(&self) -> Result<()> {
        let endpoints = [
            ("products", &self.products),
            ("product", &self.product),
            ("cart", &self.cart),
            ("add_to_cart", &self.add_to_cart),
            ("cart_item", &self.cart_item),
            ("orders", &self.orders),
            ("order", &self.order),
            ("checkout", &self.checkout),
        ];

        for (name, endpoint) in endpoints {
            if let Some(path) = endpoint {
                validate_endpoint_path(name, path)?;
            }
        }

        Ok(())
    }
}

/// Validates an endpoint path template for security issues.
pub(crate) fn validate_endpoint_path(name: &str, path: &str) -> Result<()> {
    // Check for path traversal
    if path.contains("..") {
        return Err(BridgeError::MerchantConfigError(format!(
            "endpoint '{name}' contains path traversal sequence '..': {path}"
        )));
    }

    // Check for double slashes (can be used for path confusion)
    if path.contains("//") {
        return Err(BridgeError::MerchantConfigError(format!(
            "endpoint '{name}' contains double slash '//': {path}"
        )));
    }

    // Check for absolute Windows paths
    if path.len() >= 2 && path.chars().nth(1) == Some(':') {
        return Err(BridgeError::MerchantConfigError(format!(
            "endpoint '{name}' appears to be an absolute Windows path: {path}"
        )));
    }

    // Must start with /
    if !path.starts_with('/') {
        return Err(BridgeError::MerchantConfigError(format!(
            "endpoint '{name}' must start with '/': {path}"
        )));
    }

    Ok(())
}

/// Field name mappings.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FieldMappingConfig {
    /// Request field mappings (standard -> merchant).
    #[serde(default)]
    pub request: HashMap<String, String>,

    /// Response field mappings (merchant -> standard).
    #[serde(default)]
    pub response: HashMap<String, String>,
}

/// Forbidden field names that could indicate injection attempts.
const FORBIDDEN_FIELD_NAMES: &[&str] = &[
    "__proto__",
    "constructor",
    "prototype",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
];

impl FieldMappingConfig {
    /// Validates field mapping names for security issues.
    ///
    /// Checks that field mapping names:
    /// - Do not contain JavaScript prototype pollution patterns
    /// - Do not contain SQL-like injection patterns
    /// - Do not contain null bytes
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::MerchantConfigError` if any field name is invalid.
    pub fn validate(&self) -> Result<()> {
        for (key, value) in &self.request {
            validate_field_name("request key", key)?;
            validate_field_name("request value", value)?;
        }

        for (key, value) in &self.response {
            validate_field_name("response key", key)?;
            validate_field_name("response value", value)?;
        }

        Ok(())
    }
}

/// Validates a field name for security issues.
pub(crate) fn validate_field_name(context: &str, name: &str) -> Result<()> {
    // Check for forbidden names (prototype pollution)
    if FORBIDDEN_FIELD_NAMES.contains(&name) {
        return Err(BridgeError::MerchantConfigError(format!(
            "{context} contains forbidden name: {name}"
        )));
    }

    // Check for null bytes
    if name.contains('\0') {
        return Err(BridgeError::MerchantConfigError(format!("{context} contains null byte")));
    }

    // Check for SQL-like patterns (basic detection)
    let name_lower = name.to_lowercase();
    if name_lower.contains("'; drop")
        || name_lower.contains("-- ")
        || name_lower.contains("/*")
        || name_lower.contains("*/")
    {
        return Err(BridgeError::MerchantConfigError(format!(
            "{context} contains suspicious SQL pattern: {name}"
        )));
    }

    Ok(())
}

/// Authentication configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    /// API key authentication.
    ApiKey {
        /// Header name for the API key.
        header: String,
        /// Environment variable containing the key.
        env_var: String,
    },
    /// Bearer token authentication.
    Bearer {
        /// Environment variable containing the token.
        env_var: String,
    },
    /// `OAuth2` client credentials.
    OAuth2 {
        /// Token endpoint URL.
        token_url: String,
        /// Client ID environment variable.
        client_id_env: String,
        /// Client secret environment variable.
        client_secret_env: String,
    },
}

impl AuthConfig {
    /// Validates authentication configuration for security issues.
    ///
    /// Checks that:
    /// - Environment variable names are alphanumeric with underscores only
    /// - `OAuth2` token URLs use HTTPS
    /// - Header names do not contain injection characters
    ///
    /// # Errors
    ///
    /// Returns `BridgeError::MerchantConfigError` if any value is invalid.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::ApiKey { header, env_var } => {
                validate_env_var_name(env_var)?;
                validate_header_name(header)?;
            }
            Self::Bearer { env_var } => {
                validate_env_var_name(env_var)?;
            }
            Self::OAuth2 { token_url, client_id_env, client_secret_env } => {
                validate_env_var_name(client_id_env)?;
                validate_env_var_name(client_secret_env)?;
                validate_oauth_token_url(token_url)?;
            }
        }
        Ok(())
    }
}

/// Validates an environment variable name.
fn validate_env_var_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::MerchantConfigError(
            "environment variable name cannot be empty".to_owned(),
        ));
    }

    // Must be alphanumeric with underscores, starting with letter or underscore
    // We already checked is_empty, so first char exists
    let first_char = name.chars().next().expect("name is not empty");
    if !first_char.is_ascii_alphabetic() && first_char != '_' {
        return Err(BridgeError::MerchantConfigError(format!(
            "environment variable name must start with letter or underscore: {name}"
        )));
    }

    for ch in name.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' {
            return Err(BridgeError::MerchantConfigError(format!(
                "environment variable name contains invalid character '{ch}': {name}"
            )));
        }
    }

    Ok(())
}

/// Validates an HTTP header name.
fn validate_header_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::MerchantConfigError("header name cannot be empty".to_owned()));
    }

    // HTTP header names: token characters per RFC 7230
    for ch in name.chars() {
        if !ch.is_ascii_alphanumeric() && !"-_".contains(ch) {
            return Err(BridgeError::MerchantConfigError(format!(
                "header name contains invalid character '{ch}': {name}"
            )));
        }
    }

    Ok(())
}

/// Validates an `OAuth2` token URL.
fn validate_oauth_token_url(url: &str) -> Result<()> {
    let parsed = Url::parse(url).map_err(|e| {
        BridgeError::MerchantConfigError(format!("invalid OAuth2 token_url '{url}': {e}"))
    })?;

    // Must be HTTPS
    if parsed.scheme() != "https" {
        return Err(BridgeError::MerchantConfigError(format!(
            "OAuth2 token_url must use HTTPS, got: {}",
            parsed.scheme()
        )));
    }

    // Check for localhost/loopback
    if let Some(host) = parsed.host_str() {
        let host_lower = host.to_lowercase();
        if host_lower == "localhost"
            || host_lower == "127.0.0.1"
            || host_lower == "::1"
            || host_lower.starts_with("127.")
        {
            return Err(BridgeError::MerchantConfigError(format!(
                "OAuth2 token_url must not be localhost or loopback: {host}"
            )));
        }
    }

    Ok(())
}

/// Pagination style used by merchant.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaginationStyle {
    /// Page-based pagination (`page`, `per_page`).
    #[default]
    PageBased,
    /// Offset-based pagination (`offset`, `limit`).
    OffsetBased,
    /// Cursor-based pagination (`cursor`, `limit`).
    CursorBased,
}

#[cfg(test)]
#[allow(
    clippy::unreachable,
    reason = "test code uses unreachable for expected-path assertions"
)]
mod tests {
    use super::*;

    #[test]
    fn test_merchant_config_default() {
        let config = MerchantConfig::default();
        assert_eq!(config.name, "Default Merchant");
        assert!(config.base_url.is_empty());
    }

    #[test]
    fn test_merchant_config_from_toml() {
        let toml = r#"
            name = "Test Merchant"
            base_url = "https://api.test.com"
            api_prefix = "/api/v2"
        "#;

        let config: MerchantConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.name, "Test Merchant");
        assert_eq!(config.base_url, "https://api.test.com");
        assert_eq!(config.api_prefix, "/api/v2");
    }

    #[test]
    fn test_endpoint_config_from_toml() {
        let toml = r#"
            name = "Test"
            base_url = "https://test.com"

            [endpoints]
            products = "/catalog"
            product = "/catalog/{id}"
        "#;

        let config: MerchantConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.endpoints.products.as_ref().unwrap(), "/catalog");
        assert_eq!(config.endpoints.product.as_ref().unwrap(), "/catalog/{id}");
    }

    #[test]
    fn test_field_mappings_from_toml() {
        let toml = r#"
            name = "Test"
            base_url = "https://test.com"

            [field_mappings.request]
            consumer_id = "customerId"
            product_id = "sku"

            [field_mappings.response]
            customerId = "consumer_id"
        "#;

        let config: MerchantConfig = toml::from_str(toml).unwrap();
        assert_eq!(&config.field_mappings.request["consumer_id"], "customerId");
        assert_eq!(&config.field_mappings.response["customerId"], "consumer_id");
    }

    #[test]
    fn test_auth_config_api_key() {
        let toml = r#"
            name = "Test"
            base_url = "https://test.com"

            [auth]
            type = "api_key"
            header = "X-API-Key"
            env_var = "MERCHANT_API_KEY"
        "#;

        let config: MerchantConfig = toml::from_str(toml).unwrap();
        let Some(AuthConfig::ApiKey { header, env_var }) = config.auth else {
            unreachable!("expected ApiKey auth config")
        };
        assert_eq!(header, "X-API-Key");
        assert_eq!(env_var, "MERCHANT_API_KEY");
    }

    #[test]
    fn test_auth_config_bearer() {
        let toml = r#"
            name = "Test"
            base_url = "https://test.com"

            [auth]
            type = "bearer"
            env_var = "BEARER_TOKEN"
        "#;

        let config: MerchantConfig = toml::from_str(toml).unwrap();
        let Some(AuthConfig::Bearer { env_var }) = config.auth else {
            unreachable!("expected Bearer auth config")
        };
        assert_eq!(env_var, "BEARER_TOKEN");
    }

    #[test]
    fn test_pagination_style() {
        let toml = r#"
            name = "Test"
            base_url = "https://test.com"
            pagination = "offset_based"
        "#;

        let config: MerchantConfig = toml::from_str(toml).unwrap();
        assert!(matches!(config.pagination, PaginationStyle::OffsetBased));
    }

    #[test]
    fn test_pagination_style_default() {
        let toml = r#"
            name = "Test"
            base_url = "https://test.com"
        "#;

        let config: MerchantConfig = toml::from_str(toml).unwrap();
        assert!(matches!(config.pagination, PaginationStyle::PageBased));
    }

    #[test]
    fn test_complete_config() {
        let toml = r#"
            name = "ACME Store"
            base_url = "https://api.acme.com"
            api_prefix = "/api/v2"
            pagination = "offset_based"

            [endpoints]
            products = "/catalog"
            product = "/catalog/{id}"
            cart = "/basket"
            add_to_cart = "/basket/add"

            [field_mappings.request]
            consumer_id = "customerId"
            product_id = "sku"

            [field_mappings.response]
            customerId = "consumer_id"
            sku = "product_id"

            [auth]
            type = "api_key"
            header = "X-ACME-Key"
            env_var = "ACME_API_KEY"
        "#;

        let config: MerchantConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.name, "ACME Store");
        assert_eq!(config.api_prefix, "/api/v2");
        assert!(config.endpoints.products.is_some());
        assert!(config.field_mappings.request.contains_key("consumer_id"));
        assert!(config.auth.is_some());
        assert!(matches!(config.pagination, PaginationStyle::OffsetBased));
    }

    #[test]
    fn test_auth_config_oauth2() {
        let toml = r#"
            name = "OAuth Merchant"
            base_url = "https://test.com"

            [auth]
            type = "o_auth2"
            token_url = "https://auth.test.com/token"
            client_id_env = "CLIENT_ID"
            client_secret_env = "CLIENT_SECRET"
        "#;

        let config: MerchantConfig = toml::from_str(toml).unwrap();
        let Some(AuthConfig::OAuth2 { token_url, client_id_env, client_secret_env }) = config.auth
        else {
            unreachable!("expected OAuth2 auth config")
        };
        assert_eq!(token_url, "https://auth.test.com/token");
        assert_eq!(client_id_env, "CLIENT_ID");
        assert_eq!(client_secret_env, "CLIENT_SECRET");
    }

    #[test]
    fn test_invalid_toml_syntax() {
        let toml = "name = unclosed string";
        let result: std::result::Result<MerchantConfig, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_name() {
        let toml = r#"
            base_url = "https://test.com"
        "#;
        let result: std::result::Result<MerchantConfig, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_base_url() {
        let toml = r#"
            name = "Test"
        "#;
        let result: std::result::Result<MerchantConfig, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_field_mappings() {
        let config = FieldMappingConfig::default();
        assert!(config.request.is_empty());
        assert!(config.response.is_empty());
    }

    #[test]
    fn test_endpoint_config_default() {
        let config = EndpointConfig::default();
        assert!(config.products.is_none());
        assert!(config.product.is_none());
        assert!(config.cart.is_none());
    }

    #[test]
    fn test_pagination_cursor_based() {
        let toml = r#"
            name = "Test"
            base_url = "https://test.com"
            pagination = "cursor_based"
        "#;

        let config: MerchantConfig = toml::from_str(toml).unwrap();
        assert!(matches!(config.pagination, PaginationStyle::CursorBased));
    }

    #[test]
    fn test_empty_api_prefix_default() {
        let config = MerchantConfig::default();
        assert_eq!(config.api_prefix, "");
    }

    #[test]
    fn test_none_auth_config() {
        let config = MerchantConfig::default();
        assert!(config.auth.is_none());
    }

    #[test]
    fn test_all_endpoints_configured() {
        let toml = r#"
            name = "Full Endpoints"
            base_url = "https://test.com"

            [endpoints]
            products = "/p"
            product = "/p/{id}"
            cart = "/c"
            add_to_cart = "/c/add"
            cart_item = "/c/i/{id}"
            orders = "/o"
            order = "/o/{id}"
            checkout = "/ch"
        "#;

        let config: MerchantConfig = toml::from_str(toml).unwrap();
        assert!(config.endpoints.products.is_some());
        assert!(config.endpoints.product.is_some());
        assert!(config.endpoints.cart.is_some());
        assert!(config.endpoints.add_to_cart.is_some());
        assert!(config.endpoints.cart_item.is_some());
        assert!(config.endpoints.orders.is_some());
        assert!(config.endpoints.order.is_some());
        assert!(config.endpoints.checkout.is_some());
    }

    // Security validation tests

    #[test]
    fn test_validate_valid_config() {
        let toml = r#"
            name = "Valid Config"
            base_url = "https://api.example.com"

            [endpoints]
            products = "/catalog"
            product = "/catalog/{id}"
        "#;

        let config: MerchantConfig = toml::from_str(toml).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_http_base_url_rejected() {
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "http://api.example.com".to_owned(),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("HTTPS"));
    }

    #[test]
    fn test_validate_localhost_base_url_rejected() {
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://localhost/api".to_owned(),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("localhost"));
    }

    #[test]
    fn test_validate_loopback_base_url_rejected() {
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://127.0.0.1/api".to_owned(),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_traversal_endpoint_rejected() {
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            endpoints: EndpointConfig {
                products: Some("/../../../etc/passwd".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("path traversal"));
    }

    #[test]
    fn test_validate_double_slash_endpoint_rejected() {
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            endpoints: EndpointConfig {
                products: Some("//evil.com/products".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("double slash"));
    }

    #[test]
    fn test_validate_endpoint_must_start_with_slash() {
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            endpoints: EndpointConfig {
                products: Some("products".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("must start with '/'"));
    }

    #[test]
    fn test_validate_prototype_pollution_field_rejected() {
        let mut request = HashMap::new();
        request.insert("__proto__".to_owned(), "malicious".to_owned());

        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            field_mappings: FieldMappingConfig { request, response: HashMap::new() },
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("forbidden name"));
    }

    #[test]
    fn test_validate_null_byte_field_rejected() {
        let mut request = HashMap::new();
        request.insert("field\0name".to_owned(), "value".to_owned());

        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            field_mappings: FieldMappingConfig { request, response: HashMap::new() },
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("null byte"));
    }

    #[test]
    fn test_validate_env_var_name_invalid_chars() {
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            auth: Some(AuthConfig::ApiKey {
                header: "X-API-Key".to_owned(),
                env_var: "MY-ENV-VAR".to_owned(), // Invalid: contains hyphen
            }),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn test_validate_oauth2_http_token_url_rejected() {
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            auth: Some(AuthConfig::OAuth2 {
                token_url: "http://auth.example.com/token".to_owned(),
                client_id_env: "CLIENT_ID".to_owned(),
                client_secret_env: "CLIENT_SECRET".to_owned(),
            }),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("HTTPS"));
    }

    #[test]
    fn test_validate_oauth2_localhost_token_url_rejected() {
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            auth: Some(AuthConfig::OAuth2 {
                token_url: "https://localhost/token".to_owned(),
                client_id_env: "CLIENT_ID".to_owned(),
                client_secret_env: "CLIENT_SECRET".to_owned(),
            }),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("localhost"));
    }

    #[test]
    fn test_validate_header_name_invalid_chars() {
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            auth: Some(AuthConfig::ApiKey {
                header: "X-API:Key".to_owned(), // Invalid: contains colon
                env_var: "API_KEY".to_owned(),
            }),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn test_validate_empty_base_url_allowed() {
        // Default config has empty base_url, which is allowed
        let config = MerchantConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_valid_auth_configs() {
        // Valid API Key
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            auth: Some(AuthConfig::ApiKey {
                header: "X-API-Key".to_owned(),
                env_var: "MY_API_KEY".to_owned(),
            }),
            ..Default::default()
        };
        assert!(config.validate().is_ok());

        // Valid Bearer
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            auth: Some(AuthConfig::Bearer { env_var: "BEARER_TOKEN".to_owned() }),
            ..Default::default()
        };
        assert!(config.validate().is_ok());

        // Valid OAuth2
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            auth: Some(AuthConfig::OAuth2 {
                token_url: "https://auth.example.com/oauth/token".to_owned(),
                client_id_env: "OAUTH_CLIENT_ID".to_owned(),
                client_secret_env: "OAUTH_CLIENT_SECRET".to_owned(),
            }),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_env_var_starts_with_number_rejected() {
        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            auth: Some(AuthConfig::Bearer { env_var: "1_INVALID_VAR".to_owned() }),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("must start with letter"));
    }

    #[test]
    fn test_validate_sql_injection_field_rejected() {
        let mut request = HashMap::new();
        request.insert("field'; DROP TABLE users-- ".to_owned(), "value".to_owned());

        let config = MerchantConfig {
            name: "Test".to_owned(),
            base_url: "https://api.example.com".to_owned(),
            field_mappings: FieldMappingConfig { request, response: HashMap::new() },
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("SQL pattern"));
    }
}
