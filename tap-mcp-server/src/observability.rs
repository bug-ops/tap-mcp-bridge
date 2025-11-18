//! Observability infrastructure for TAP-MCP server.
//!
//! Provides structured logging, request correlation, and health checks for
//! production deployments.

use std::io;

use tracing_subscriber::{
    EnvFilter,
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

/// Log format configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable pretty format for development.
    Pretty,
    /// JSON format for production log aggregation.
    Json,
}

impl LogFormat {
    /// Determines log format from environment.
    ///
    /// Checks `LOG_FORMAT` environment variable:
    /// - `json` => JSON format
    /// - `pretty` or unset => Pretty format
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("LOG_FORMAT")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "json" => Self::Json,
            _ => Self::Pretty,
        }
    }
}

/// Initializes observability subsystem with structured logging.
///
/// Configures tracing-subscriber with:
/// - Configurable output format (pretty for dev, JSON for production)
/// - Environment-based log level filtering (`RUST_LOG`)
/// - Span events for request/response timing
///
/// # Environment Variables
///
/// - `LOG_FORMAT`: `json` or `pretty` (default: `pretty`)
/// - `RUST_LOG`: Log level filter (default: `info`)
///
/// # Examples
///
/// ```no_run
/// use tap_mcp_server::observability::{init_observability, LogFormat};
///
/// // Development: pretty logs
/// std::env::set_var("LOG_FORMAT", "pretty");
/// init_observability(LogFormat::Pretty);
///
/// // Production: JSON logs
/// std::env::set_var("LOG_FORMAT", "json");
/// std::env::set_var("RUST_LOG", "info");
/// init_observability(LogFormat::Json);
/// ```
pub fn init_observability(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = tracing_subscriber::registry().with(filter);

    match format {
        LogFormat::Pretty => {
            subscriber
                .with(
                    fmt::layer()
                        .with_target(true)
                        .with_thread_ids(false)
                        .with_thread_names(false)
                        .with_span_events(FmtSpan::CLOSE)
                        .with_writer(io::stderr),
                )
                .init();
        }
        LogFormat::Json => {
            subscriber
                .with(
                    fmt::layer()
                        .json()
                        .with_current_span(true)
                        .with_span_list(true)
                        .with_target(true)
                        .with_thread_ids(false)
                        .with_thread_names(false)
                        .with_span_events(FmtSpan::CLOSE)
                        .with_writer(io::stderr),
                )
                .init();
        }
    }
}

/// Health check status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    /// System is healthy and operational.
    Healthy,
    /// System is degraded but operational.
    Degraded,
    /// System is unhealthy and not operational.
    Unhealthy,
}

impl HealthStatus {
    /// Returns string representation for JSON serialization.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
        }
    }
}

/// Individual health check result.
#[derive(Debug, Clone)]
pub struct HealthCheck {
    /// Check name.
    pub name: String,
    /// Check status.
    pub status: HealthCheckStatus,
    /// Optional message with details.
    pub message: Option<String>,
}

/// Health check status for individual checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthCheckStatus {
    /// Check passed.
    Pass,
    /// Check failed.
    Fail,
    /// Check warning (degraded but operational).
    Warn,
}

impl HealthCheckStatus {
    /// Returns string representation for JSON serialization.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Warn => "warn",
        }
    }
}

impl HealthCheck {
    /// Creates a passing health check with a message.
    #[must_use]
    pub fn pass_with_message<N: Into<String>, M: Into<String>>(name: N, message: M) -> Self {
        Self {
            name: name.into(),
            status: HealthCheckStatus::Pass,
            message: Some(message.into()),
        }
    }

    /// Creates a failing health check with error message.
    #[must_use]
    pub fn fail<N: Into<String>, M: Into<String>>(name: N, message: M) -> Self {
        Self { name: name.into(), status: HealthCheckStatus::Fail, message: Some(message.into()) }
    }

    #[cfg(test)]
    fn pass(name: impl Into<String>) -> Self {
        Self { name: name.into(), status: HealthCheckStatus::Pass, message: None }
    }

    #[cfg(test)]
    fn warn(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self { name: name.into(), status: HealthCheckStatus::Warn, message: Some(message.into()) }
    }
}

/// Overall health report for the system.
#[derive(Debug, Clone)]
pub struct HealthReport {
    /// Overall system status.
    pub status: HealthStatus,
    /// Server version.
    pub version: String,
    /// Agent ID.
    pub agent_id: String,
    /// Uptime in seconds.
    pub uptime_secs: u64,
    /// Individual health checks.
    pub checks: Vec<HealthCheck>,
}

impl HealthReport {
    /// Serializes health report to JSON string.
    ///
    /// # Errors
    ///
    /// Returns error if JSON serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let json = serde_json::json!({
            "status": self.status.as_str(),
            "version": self.version,
            "agent_id": self.agent_id,
            "uptime_secs": self.uptime_secs,
            "checks": self.checks.iter().map(|c| {
                let mut obj = serde_json::json!({
                    "name": c.name,
                    "status": c.status.as_str(),
                });
                if let Some(msg) = &c.message {
                    obj["message"] = serde_json::Value::String(msg.clone());
                }
                obj
            }).collect::<Vec<_>>(),
        });

        serde_json::to_string_pretty(&json)
    }

    /// Determines overall health status from individual checks.
    #[must_use]
    pub fn compute_status(checks: &[HealthCheck]) -> HealthStatus {
        if checks.iter().any(|c| c.status == HealthCheckStatus::Fail) {
            HealthStatus::Unhealthy
        } else if checks.iter().any(|c| c.status == HealthCheckStatus::Warn) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_format_from_env() {
        // SAFETY: This test runs in isolation and only modifies test-specific environment variables.
        // The LOG_FORMAT variable is only used by this test and doesn't affect other tests.
        unsafe {
            // Unset environment variable defaults to Pretty
            std::env::remove_var("LOG_FORMAT");
            assert_eq!(LogFormat::from_env(), LogFormat::Pretty);

            // JSON format
            std::env::set_var("LOG_FORMAT", "json");
            assert_eq!(LogFormat::from_env(), LogFormat::Json);

            // Pretty format (explicit)
            std::env::set_var("LOG_FORMAT", "pretty");
            assert_eq!(LogFormat::from_env(), LogFormat::Pretty);

            // Unknown format defaults to Pretty
            std::env::set_var("LOG_FORMAT", "unknown");
            assert_eq!(LogFormat::from_env(), LogFormat::Pretty);

            // Cleanup
            std::env::remove_var("LOG_FORMAT");
        }
    }

    #[test]
    fn test_health_check_pass() {
        let check = HealthCheck::pass("signing_key");
        assert_eq!(check.name, "signing_key");
        assert_eq!(check.status, HealthCheckStatus::Pass);
        assert!(check.message.is_none());
    }

    #[test]
    fn test_health_check_pass_with_message() {
        let check = HealthCheck::pass_with_message("signing_key", "Ed25519 key loaded");
        assert_eq!(check.name, "signing_key");
        assert_eq!(check.status, HealthCheckStatus::Pass);
        assert_eq!(check.message, Some("Ed25519 key loaded".to_owned()));
    }

    #[test]
    fn test_health_check_fail() {
        let check = HealthCheck::fail("signing_key", "Key not found");
        assert_eq!(check.name, "signing_key");
        assert_eq!(check.status, HealthCheckStatus::Fail);
        assert_eq!(check.message, Some("Key not found".to_owned()));
    }

    #[test]
    fn test_health_check_warn() {
        let check = HealthCheck::warn("directory", "Directory URL not reachable");
        assert_eq!(check.name, "directory");
        assert_eq!(check.status, HealthCheckStatus::Warn);
        assert_eq!(check.message, Some("Directory URL not reachable".to_owned()));
    }

    #[test]
    fn test_health_status_compute_all_pass() {
        let checks = vec![HealthCheck::pass("check1"), HealthCheck::pass("check2")];
        assert_eq!(HealthReport::compute_status(&checks), HealthStatus::Healthy);
    }

    #[test]
    fn test_health_status_compute_with_warn() {
        let checks = vec![
            HealthCheck::pass("check1"),
            HealthCheck::warn("check2", "Warning message"),
        ];
        assert_eq!(HealthReport::compute_status(&checks), HealthStatus::Degraded);
    }

    #[test]
    fn test_health_status_compute_with_fail() {
        let checks = vec![
            HealthCheck::pass("check1"),
            HealthCheck::warn("check2", "Warning"),
            HealthCheck::fail("check3", "Error"),
        ];
        assert_eq!(HealthReport::compute_status(&checks), HealthStatus::Unhealthy);
    }

    #[test]
    fn test_health_status_compute_empty() {
        let checks: Vec<HealthCheck> = vec![];
        assert_eq!(HealthReport::compute_status(&checks), HealthStatus::Healthy);
    }

    #[test]
    fn test_health_report_to_json() {
        let report = HealthReport {
            status: HealthStatus::Healthy,
            version: "0.1.0".to_owned(),
            agent_id: "agent-123".to_owned(),
            uptime_secs: 3600,
            checks: vec![
                HealthCheck::pass("signing_key"),
                HealthCheck::pass_with_message("jwks_generation", "JWKS generated successfully"),
            ],
        };

        let json = report.to_json().expect("JSON serialization should succeed");
        assert!(json.contains("\"status\": \"healthy\""));
        assert!(json.contains("\"version\": \"0.1.0\""));
        assert!(json.contains("\"agent_id\": \"agent-123\""));
        assert!(json.contains("\"uptime_secs\": 3600"));
        assert!(json.contains("\"name\": \"signing_key\""));
        assert!(json.contains("\"status\": \"pass\""));
    }

    #[test]
    fn test_health_report_to_json_with_failures() {
        let report = HealthReport {
            status: HealthStatus::Unhealthy,
            version: "0.1.0".to_owned(),
            agent_id: "agent-123".to_owned(),
            uptime_secs: 60,
            checks: vec![
                HealthCheck::fail("signing_key", "Key not loaded"),
                HealthCheck::warn("directory", "Directory not reachable"),
            ],
        };

        let json = report.to_json().expect("JSON serialization should succeed");
        assert!(json.contains("\"status\": \"unhealthy\""));
        assert!(json.contains("\"status\": \"fail\""));
        assert!(json.contains("\"status\": \"warn\""));
        assert!(json.contains("\"message\": \"Key not loaded\""));
    }

    #[test]
    fn test_health_check_status_as_str() {
        assert_eq!(HealthCheckStatus::Pass.as_str(), "pass");
        assert_eq!(HealthCheckStatus::Fail.as_str(), "fail");
        assert_eq!(HealthCheckStatus::Warn.as_str(), "warn");
    }

    #[test]
    fn test_health_status_as_str() {
        assert_eq!(HealthStatus::Healthy.as_str(), "healthy");
        assert_eq!(HealthStatus::Degraded.as_str(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.as_str(), "unhealthy");
    }
}
