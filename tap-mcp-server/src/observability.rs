//! Observability infrastructure for TAP-MCP server.
//!
//! Provides structured logging, request correlation, health checks, and metrics
//! for production deployments.

// Allow dead code for Metrics which is prepared for future integration
#![allow(dead_code, reason = "Metrics struct prepared for future integration")]

use std::{
    io,
    sync::atomic::{AtomicU64, Ordering},
};

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
        match std::env::var("LOG_FORMAT").unwrap_or_default().to_lowercase().as_str() {
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
/// use tap_mcp_server::observability::{LogFormat, init_observability};
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
        Self {
            name: name.into(),
            status: HealthCheckStatus::Fail,
            message: Some(message.into()),
        }
    }

    #[cfg(test)]
    fn pass(name: impl Into<String>) -> Self {
        Self { name: name.into(), status: HealthCheckStatus::Pass, message: None }
    }

    #[cfg(test)]
    fn warn(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthCheckStatus::Warn,
            message: Some(message.into()),
        }
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
    /// Optional metrics snapshot.
    pub metrics: Option<MetricsSnapshot>,
}

impl HealthReport {
    /// Serializes health report to JSON string.
    ///
    /// # Errors
    ///
    /// Returns error if JSON serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let mut json = serde_json::json!({
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

        if let Some(ref metrics) = self.metrics {
            json["metrics"] = serde_json::json!({
                "checkout_requests": metrics.checkout_requests,
                "checkout_successes": metrics.checkout_successes,
                "checkout_failures": metrics.checkout_failures,
                "browse_requests": metrics.browse_requests,
                "signature_generations": metrics.signature_generations,
                "http_errors": metrics.http_errors,
            });
        }

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

/// Metrics collector for TAP-MCP Bridge operations.
///
/// Thread-safe metrics collection using atomic counters. All operations use
/// `Ordering::Relaxed` as exact ordering is not required for statistical counters.
///
/// # Examples
///
/// ```
/// use tap_mcp_server::observability::Metrics;
///
/// let metrics = Metrics::default();
///
/// // Record successful checkout
/// metrics.record_checkout_success();
///
/// // Record failed checkout
/// metrics.record_checkout_failure();
///
/// // Get snapshot for reporting
/// let snapshot = metrics.snapshot();
/// assert_eq!(snapshot.checkout_requests, 2);
/// assert_eq!(snapshot.checkout_successes, 1);
/// assert_eq!(snapshot.checkout_failures, 1);
/// ```
#[derive(Debug, Default)]
pub struct Metrics {
    /// Total checkout requests initiated.
    pub checkout_requests: AtomicU64,
    /// Successful checkout completions.
    pub checkout_successes: AtomicU64,
    /// Failed checkout attempts.
    pub checkout_failures: AtomicU64,
    /// Total browse requests.
    pub browse_requests: AtomicU64,
    /// Total signature generations.
    pub signature_generations: AtomicU64,
    /// HTTP errors encountered.
    pub http_errors: AtomicU64,
}

impl Metrics {
    /// Records a successful checkout operation.
    ///
    /// Increments both total checkout requests and success counter.
    pub fn record_checkout_success(&self) {
        self.checkout_requests.fetch_add(1, Ordering::Relaxed);
        self.checkout_successes.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a failed checkout operation.
    ///
    /// Increments both total checkout requests and failure counter.
    pub fn record_checkout_failure(&self) {
        self.checkout_requests.fetch_add(1, Ordering::Relaxed);
        self.checkout_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a browse operation.
    pub fn record_browse(&self) {
        self.browse_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a signature generation operation.
    pub fn record_signature_generation(&self) {
        self.signature_generations.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an HTTP error.
    pub fn record_http_error(&self) {
        self.http_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Creates a point-in-time snapshot of all metrics.
    ///
    /// Returns owned copy of current metric values for serialization or reporting.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_server::observability::Metrics;
    ///
    /// let metrics = Metrics::default();
    /// metrics.record_checkout_success();
    ///
    /// let snapshot = metrics.snapshot();
    /// println!("Total checkouts: {}", snapshot.checkout_requests);
    /// ```
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            checkout_requests: self.checkout_requests.load(Ordering::Relaxed),
            checkout_successes: self.checkout_successes.load(Ordering::Relaxed),
            checkout_failures: self.checkout_failures.load(Ordering::Relaxed),
            browse_requests: self.browse_requests.load(Ordering::Relaxed),
            signature_generations: self.signature_generations.load(Ordering::Relaxed),
            http_errors: self.http_errors.load(Ordering::Relaxed),
        }
    }

    /// Exports metrics in Prometheus text format.
    ///
    /// Returns metrics formatted according to Prometheus exposition format
    /// specification for scraping by monitoring systems.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_server::observability::Metrics;
    ///
    /// let metrics = Metrics::default();
    /// metrics.record_checkout_success();
    ///
    /// let prometheus = metrics.to_prometheus();
    /// assert!(prometheus.contains("tap_checkout_requests_total 1"));
    /// ```
    #[must_use]
    pub fn to_prometheus(&self) -> String {
        let snapshot = self.snapshot();

        format!(
            "# HELP tap_checkout_requests_total Total checkout requests\n# TYPE \
             tap_checkout_requests_total counter\ntap_checkout_requests_total {}\n# HELP \
             tap_checkout_successes_total Successful checkouts\n# TYPE \
             tap_checkout_successes_total counter\ntap_checkout_successes_total {}\n# HELP \
             tap_checkout_failures_total Failed checkouts\n# TYPE tap_checkout_failures_total \
             counter\ntap_checkout_failures_total {}\n# HELP tap_browse_requests_total Total \
             browse requests\n# TYPE tap_browse_requests_total counter\ntap_browse_requests_total \
             {}\n# HELP tap_signature_generations_total Total signature generations\n# TYPE \
             tap_signature_generations_total counter\ntap_signature_generations_total {}\n# HELP \
             tap_http_errors_total HTTP errors encountered\n# TYPE tap_http_errors_total \
             counter\ntap_http_errors_total {}\n",
            snapshot.checkout_requests,
            snapshot.checkout_successes,
            snapshot.checkout_failures,
            snapshot.browse_requests,
            snapshot.signature_generations,
            snapshot.http_errors,
        )
    }
}

/// Point-in-time snapshot of metrics values.
///
/// Contains owned copies of metric values at snapshot time. Safe to serialize
/// and send across threads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Total checkout requests.
    pub checkout_requests: u64,
    /// Successful checkouts.
    pub checkout_successes: u64,
    /// Failed checkouts.
    pub checkout_failures: u64,
    /// Total browse requests.
    pub browse_requests: u64,
    /// Total signature generations.
    pub signature_generations: u64,
    /// HTTP errors.
    pub http_errors: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_format_from_env() {
        // SAFETY: This test runs in isolation and only modifies test-specific environment
        // variables. The LOG_FORMAT variable is only used by this test and doesn't affect
        // other tests.
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
        let checks =
            vec![HealthCheck::pass("check1"), HealthCheck::warn("check2", "Warning message")];
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
            metrics: None,
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
            metrics: None,
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

    #[test]
    fn test_metrics_default() {
        let metrics = Metrics::default();
        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.checkout_requests, 0);
        assert_eq!(snapshot.checkout_successes, 0);
        assert_eq!(snapshot.checkout_failures, 0);
        assert_eq!(snapshot.browse_requests, 0);
        assert_eq!(snapshot.signature_generations, 0);
        assert_eq!(snapshot.http_errors, 0);
    }

    #[test]
    fn test_metrics_record_checkout_success() {
        let metrics = Metrics::default();

        metrics.record_checkout_success();
        metrics.record_checkout_success();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.checkout_requests, 2);
        assert_eq!(snapshot.checkout_successes, 2);
        assert_eq!(snapshot.checkout_failures, 0);
    }

    #[test]
    fn test_metrics_record_checkout_failure() {
        let metrics = Metrics::default();

        metrics.record_checkout_failure();
        metrics.record_checkout_failure();
        metrics.record_checkout_failure();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.checkout_requests, 3);
        assert_eq!(snapshot.checkout_successes, 0);
        assert_eq!(snapshot.checkout_failures, 3);
    }

    #[test]
    fn test_metrics_record_checkout_mixed() {
        let metrics = Metrics::default();

        metrics.record_checkout_success();
        metrics.record_checkout_failure();
        metrics.record_checkout_success();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.checkout_requests, 3);
        assert_eq!(snapshot.checkout_successes, 2);
        assert_eq!(snapshot.checkout_failures, 1);
    }

    #[test]
    fn test_metrics_record_browse() {
        let metrics = Metrics::default();

        metrics.record_browse();
        metrics.record_browse();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.browse_requests, 2);
    }

    #[test]
    fn test_metrics_record_signature_generation() {
        let metrics = Metrics::default();

        metrics.record_signature_generation();
        metrics.record_signature_generation();
        metrics.record_signature_generation();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.signature_generations, 3);
    }

    #[test]
    fn test_metrics_record_http_error() {
        let metrics = Metrics::default();

        metrics.record_http_error();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.http_errors, 1);
    }

    #[test]
    fn test_metrics_snapshot_multiple_times() {
        let metrics = Metrics::default();

        metrics.record_checkout_success();
        let snapshot1 = metrics.snapshot();

        metrics.record_checkout_success();
        let snapshot2 = metrics.snapshot();

        assert_eq!(snapshot1.checkout_requests, 1);
        assert_eq!(snapshot2.checkout_requests, 2);
    }

    #[test]
    fn test_metrics_to_prometheus() {
        let metrics = Metrics::default();

        metrics.record_checkout_success();
        metrics.record_checkout_failure();
        metrics.record_browse();
        metrics.record_signature_generation();
        metrics.record_http_error();

        let output = metrics.to_prometheus();

        // Check format compliance
        assert!(output.contains("# HELP tap_checkout_requests_total Total checkout requests"));
        assert!(output.contains("# TYPE tap_checkout_requests_total counter"));
        assert!(output.contains("tap_checkout_requests_total 2"));

        assert!(output.contains("# HELP tap_checkout_successes_total Successful checkouts"));
        assert!(output.contains("# TYPE tap_checkout_successes_total counter"));
        assert!(output.contains("tap_checkout_successes_total 1"));

        assert!(output.contains("# HELP tap_checkout_failures_total Failed checkouts"));
        assert!(output.contains("# TYPE tap_checkout_failures_total counter"));
        assert!(output.contains("tap_checkout_failures_total 1"));

        assert!(output.contains("# HELP tap_browse_requests_total Total browse requests"));
        assert!(output.contains("tap_browse_requests_total 1"));

        assert!(
            output.contains("# HELP tap_signature_generations_total Total signature generations")
        );
        assert!(output.contains("tap_signature_generations_total 1"));

        assert!(output.contains("# HELP tap_http_errors_total HTTP errors encountered"));
        assert!(output.contains("tap_http_errors_total 1"));
    }

    #[test]
    fn test_metrics_to_prometheus_zero_values() {
        let metrics = Metrics::default();
        let output = metrics.to_prometheus();

        assert!(output.contains("tap_checkout_requests_total 0"));
        assert!(output.contains("tap_checkout_successes_total 0"));
        assert!(output.contains("tap_checkout_failures_total 0"));
        assert!(output.contains("tap_browse_requests_total 0"));
        assert!(output.contains("tap_signature_generations_total 0"));
        assert!(output.contains("tap_http_errors_total 0"));
    }

    #[test]
    fn test_metrics_snapshot_equality() {
        let snapshot1 = MetricsSnapshot {
            checkout_requests: 10,
            checkout_successes: 8,
            checkout_failures: 2,
            browse_requests: 5,
            signature_generations: 15,
            http_errors: 1,
        };

        let snapshot2 = MetricsSnapshot {
            checkout_requests: 10,
            checkout_successes: 8,
            checkout_failures: 2,
            browse_requests: 5,
            signature_generations: 15,
            http_errors: 1,
        };

        assert_eq!(snapshot1, snapshot2);
    }

    #[test]
    fn test_metrics_snapshot_clone() {
        let snapshot = MetricsSnapshot {
            checkout_requests: 5,
            checkout_successes: 3,
            checkout_failures: 2,
            browse_requests: 1,
            signature_generations: 10,
            http_errors: 0,
        };

        let cloned = snapshot.clone();
        assert_eq!(snapshot, cloned);
    }

    #[test]
    fn test_health_report_with_metrics() {
        let metrics = Metrics::default();
        metrics.record_checkout_success();
        metrics.record_browse();

        let report = HealthReport {
            status: HealthStatus::Healthy,
            version: "0.1.0".to_owned(),
            agent_id: "agent-123".to_owned(),
            uptime_secs: 3600,
            checks: vec![HealthCheck::pass("test")],
            metrics: Some(metrics.snapshot()),
        };

        let json = report.to_json().expect("JSON serialization should succeed");
        assert!(json.contains("\"metrics\""));
        assert!(json.contains("\"checkout_requests\": 1"));
        assert!(json.contains("\"browse_requests\": 1"));
    }

    #[test]
    fn test_health_report_without_metrics() {
        let report = HealthReport {
            status: HealthStatus::Healthy,
            version: "0.1.0".to_owned(),
            agent_id: "agent-123".to_owned(),
            uptime_secs: 3600,
            checks: vec![],
            metrics: None,
        };

        let json = report.to_json().expect("JSON serialization should succeed");
        assert!(!json.contains("\"metrics\""));
    }
}
