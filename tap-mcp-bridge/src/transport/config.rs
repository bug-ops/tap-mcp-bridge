//! Transport configuration types.
//!
//! This module defines TOML-deserializable configuration structures for
//! different transport protocols.

use std::time::Duration;

use serde::Deserialize;

use crate::error::{BridgeError, Result};

/// Transport configuration from TOML.
///
/// This enum uses tagged deserialization to select the transport protocol
/// based on the `protocol` field in the configuration file.
///
/// # Examples
///
/// ```toml
/// [transport]
/// protocol = "http"
/// timeout_secs = 30
///
/// [transport.http]
/// pool_max_idle_per_host = 10
/// http_version = "http2"
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum TransportConfig {
    /// HTTP/1.1 and HTTP/2 transport.
    Http(HttpConfig),
    /// HTTP/2 transport (explicit).
    Http2(HttpConfig),
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self::Http(HttpConfig::default())
    }
}

/// HTTP transport configuration.
///
/// Supports both HTTP/1.1 and HTTP/2 via reqwest.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    /// Maximum idle connections per host.
    #[serde(default = "default_pool_max_idle")]
    pub pool_max_idle_per_host: usize,

    /// Request timeout in seconds.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Connection timeout in seconds.
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    /// HTTP version preference.
    #[serde(default)]
    pub http_version: HttpVersion,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            pool_max_idle_per_host: default_pool_max_idle(),
            timeout_secs: default_timeout_secs(),
            connect_timeout_secs: default_connect_timeout_secs(),
            http_version: HttpVersion::default(),
        }
    }
}

impl HttpConfig {
    /// Validates configuration values are within acceptable bounds.
    ///
    /// # Errors
    ///
    /// Returns error if timeout values are outside valid ranges:
    /// - `timeout_secs`: must be 1-300 seconds
    /// - `connect_timeout_secs`: must be 1-60 seconds
    pub fn validate(&self) -> Result<()> {
        if self.timeout_secs == 0 || self.timeout_secs > 300 {
            return Err(BridgeError::TransportError(
                "timeout_secs must be between 1 and 300".to_owned(),
            ));
        }
        if self.connect_timeout_secs == 0 || self.connect_timeout_secs > 60 {
            return Err(BridgeError::TransportError(
                "connect_timeout_secs must be between 1 and 60".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns timeout as Duration.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Returns connect timeout as Duration.
    #[must_use]
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }
}

/// HTTP version preference.
///
/// Controls which HTTP version to use for requests.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpVersion {
    /// HTTP/1.1 only.
    Http1,
    /// HTTP/2 only (requires prior knowledge or ALPN negotiation).
    Http2,
    /// Auto-negotiate (prefer HTTP/2, fall back to HTTP/1.1).
    #[default]
    Auto,
}

fn default_pool_max_idle() -> usize {
    100
}

fn default_timeout_secs() -> u64 {
    30
}

fn default_connect_timeout_secs() -> u64 {
    10
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_config_default() {
        let config = HttpConfig::default();
        assert_eq!(config.pool_max_idle_per_host, 100);
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.connect_timeout_secs, 10);
        assert_eq!(config.http_version, HttpVersion::Auto);
    }

    #[test]
    fn test_http_config_timeout() {
        let config = HttpConfig::default();
        assert_eq!(config.timeout(), Duration::from_secs(30));
        assert_eq!(config.connect_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_http_version_default() {
        let version = HttpVersion::default();
        assert_eq!(version, HttpVersion::Auto);
    }

    #[test]
    #[allow(clippy::unreachable, reason = "test ensures enum variant is Http")]
    fn test_transport_config_from_toml() {
        let toml = "
            protocol = \"http\"
            timeout_secs = 60
        ";

        let config: TransportConfig = toml::from_str(toml).unwrap();
        if let TransportConfig::Http(http_config) = config {
            assert_eq!(http_config.timeout_secs, 60);
        } else {
            unreachable!("expected Http transport config");
        }
    }

    #[test]
    fn test_http_config_from_toml() {
        let toml = "
            pool_max_idle_per_host = 20
            timeout_secs = 45
            connect_timeout_secs = 15
            http_version = \"http2\"
        ";

        let config: HttpConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.pool_max_idle_per_host, 20);
        assert_eq!(config.timeout_secs, 45);
        assert_eq!(config.connect_timeout_secs, 15);
        assert_eq!(config.http_version, HttpVersion::Http2);
    }

    #[test]
    fn test_http_version_from_toml() {
        // Test parsing wrapped in a struct to match TOML structure
        #[derive(Deserialize)]
        struct Wrapper {
            http_version: HttpVersion,
        }

        let toml = "http_version = \"http1\"";
        let wrapper: Wrapper = toml::from_str(toml).unwrap();
        assert_eq!(wrapper.http_version, HttpVersion::Http1);
    }

    #[test]
    fn test_http_config_with_defaults() {
        let toml = "
            timeout_secs = 60
        ";

        let config: HttpConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.pool_max_idle_per_host, 100); // default
        assert_eq!(config.timeout_secs, 60);
        assert_eq!(config.connect_timeout_secs, 10); // default
        assert_eq!(config.http_version, HttpVersion::Auto); // default
    }

    #[test]
    fn test_http_config_zero_timeout() {
        let config = HttpConfig {
            pool_max_idle_per_host: 10,
            timeout_secs: 0,
            connect_timeout_secs: 0,
            http_version: HttpVersion::Auto,
        };
        assert_eq!(config.timeout(), Duration::from_secs(0));
        assert_eq!(config.connect_timeout(), Duration::from_secs(0));
    }

    #[test]
    fn test_http_config_large_timeout() {
        let config = HttpConfig {
            pool_max_idle_per_host: 10,
            timeout_secs: u64::MAX,
            connect_timeout_secs: u64::MAX,
            http_version: HttpVersion::Auto,
        };
        assert_eq!(config.timeout(), Duration::from_secs(u64::MAX));
        assert_eq!(config.connect_timeout(), Duration::from_secs(u64::MAX));
    }

    #[test]
    fn test_http_config_zero_pool_size() {
        let toml = "
            pool_max_idle_per_host = 0
            timeout_secs = 30
            connect_timeout_secs = 10
        ";

        let config: HttpConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.pool_max_idle_per_host, 0);
    }

    #[test]
    fn test_http_config_large_pool_size() {
        let toml = "
            pool_max_idle_per_host = 1000
            timeout_secs = 30
            connect_timeout_secs = 10
        ";

        let config: HttpConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.pool_max_idle_per_host, 1000);
    }

    #[test]
    fn test_http_config_invalid_toml() {
        let toml = "
            invalid syntax here
        ";

        let result: std::result::Result<HttpConfig, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_http_config_empty_toml() {
        let toml = "";

        let config: HttpConfig = toml::from_str(toml).unwrap();
        // Should use all defaults
        assert_eq!(config.pool_max_idle_per_host, 100);
        assert_eq!(config.timeout_secs, 30);
        assert_eq!(config.connect_timeout_secs, 10);
        assert_eq!(config.http_version, HttpVersion::Auto);
    }

    #[test]
    fn test_http_version_all_variants() {
        #[derive(Deserialize)]
        struct Wrapper {
            http_version: HttpVersion,
        }

        let toml_http1 = "http_version = \"http1\"";
        let wrapper: Wrapper = toml::from_str(toml_http1).unwrap();
        assert_eq!(wrapper.http_version, HttpVersion::Http1);

        let toml_http2 = "http_version = \"http2\"";
        let wrapper: Wrapper = toml::from_str(toml_http2).unwrap();
        assert_eq!(wrapper.http_version, HttpVersion::Http2);

        let toml_auto = "http_version = \"auto\"";
        let wrapper: Wrapper = toml::from_str(toml_auto).unwrap();
        assert_eq!(wrapper.http_version, HttpVersion::Auto);
    }

    #[test]
    fn test_http_version_invalid_value() {
        #[derive(Deserialize)]
        #[allow(dead_code, reason = "field used for deserialization test")]
        struct Wrapper {
            http_version: HttpVersion,
        }

        let toml = "http_version = \"http3\"";
        let result: std::result::Result<Wrapper, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::unreachable, reason = "test ensures enum variant is Http")]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        if let TransportConfig::Http(http_config) = config {
            assert_eq!(http_config.pool_max_idle_per_host, 100);
            assert_eq!(http_config.timeout_secs, 30);
        } else {
            unreachable!("expected Http transport config");
        }
    }

    #[test]
    #[allow(clippy::unreachable, reason = "test ensures enum variant is Http2")]
    fn test_transport_config_http2() {
        let toml = "
            protocol = \"http2\"
            timeout_secs = 45
        ";

        let config: TransportConfig = toml::from_str(toml).unwrap();
        if let TransportConfig::Http2(http_config) = config {
            assert_eq!(http_config.timeout_secs, 45);
        } else {
            unreachable!("expected Http2 transport config");
        }
    }

    #[test]
    fn test_transport_config_invalid_protocol() {
        let toml = "
            protocol = \"grpc\"
        ";

        let result: std::result::Result<TransportConfig, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_transport_config_missing_protocol() {
        let toml = "
            timeout_secs = 30
        ";

        let result: std::result::Result<TransportConfig, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_http_config_partial_fields() {
        let toml = "
            pool_max_idle_per_host = 5
        ";

        let config: HttpConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.pool_max_idle_per_host, 5);
        assert_eq!(config.timeout_secs, 30); // default
        assert_eq!(config.connect_timeout_secs, 10); // default
        assert_eq!(config.http_version, HttpVersion::Auto); // default
    }

    // Validation tests

    #[test]
    fn test_http_config_validate_default() {
        let config = HttpConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_http_config_validate_valid_bounds() {
        let config = HttpConfig {
            pool_max_idle_per_host: 100,
            timeout_secs: 1,
            connect_timeout_secs: 1,
            http_version: HttpVersion::Auto,
        };
        assert!(config.validate().is_ok());

        let config = HttpConfig {
            pool_max_idle_per_host: 100,
            timeout_secs: 300,
            connect_timeout_secs: 60,
            http_version: HttpVersion::Auto,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_http_config_validate_timeout_zero() {
        let config = HttpConfig {
            pool_max_idle_per_host: 100,
            timeout_secs: 0,
            connect_timeout_secs: 10,
            http_version: HttpVersion::Auto,
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));
    }

    #[test]
    fn test_http_config_validate_timeout_too_large() {
        let config = HttpConfig {
            pool_max_idle_per_host: 100,
            timeout_secs: 301,
            connect_timeout_secs: 10,
            http_version: HttpVersion::Auto,
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));
    }

    #[test]
    fn test_http_config_validate_connect_timeout_zero() {
        let config = HttpConfig {
            pool_max_idle_per_host: 100,
            timeout_secs: 30,
            connect_timeout_secs: 0,
            http_version: HttpVersion::Auto,
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));
    }

    #[test]
    fn test_http_config_validate_connect_timeout_too_large() {
        let config = HttpConfig {
            pool_max_idle_per_host: 100,
            timeout_secs: 30,
            connect_timeout_secs: 61,
            http_version: HttpVersion::Auto,
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BridgeError::TransportError(_)));
    }
}
