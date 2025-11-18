# Observability Guide

This document describes the observability features of the TAP-MCP Bridge project, including logging, monitoring, and health checks.

## Table of Contents

- [Overview](#overview)
- [Structured Logging](#structured-logging)
- [Health Checks](#health-checks)
- [Request Correlation](#request-correlation)
- [Configuration](#configuration)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)

## Overview

The TAP-MCP Bridge implements production-grade observability features to support debugging, monitoring, and operations:

- **Structured Logging**: JSON or pretty-printed logs with contextual fields
- **Request Correlation**: Automatic span tracking for all operations
- **Health Checks**: Built-in health verification via MCP tool
- **Instrumentation**: Distributed tracing-compatible spans

## Structured Logging

### Log Formats

The server supports two log formats:

#### Pretty Format (Development)

Human-readable output for local development and debugging:

```
2025-01-18T10:15:30.123Z  INFO tap_mcp_server: Starting TAP-MCP Server log_format=Pretty version="0.1.0"
2025-01-18T10:15:30.145Z  INFO tap_mcp_server: Configuration loaded successfully
2025-01-18T10:15:30.156Z  INFO tap_mcp_server: TAP signer created successfully
```

#### JSON Format (Production)

Machine-parsable JSON for log aggregation and analysis:

```json
{
  "timestamp": "2025-01-18T10:15:30.123456Z",
  "level": "INFO",
  "target": "tap_mcp_server",
  "fields": {
    "message": "Starting TAP-MCP Server",
    "log_format": "Json",
    "version": "0.1.0"
  },
  "span": {
    "name": "main"
  }
}
```

### Log Levels

The server respects the `RUST_LOG` environment variable for filtering:

```bash
# All logs (default: info)
export RUST_LOG=debug

# Per-module filtering
export RUST_LOG=tap_mcp_server=debug,tap_mcp_bridge=info

# Only errors
export RUST_LOG=error
```

### Contextual Fields

All log entries include contextual fields for better debugging:

| Field | Description | Example |
|-------|-------------|---------|
| `tool` | MCP tool name | `checkout_with_tap` |
| `merchant_url` | Merchant endpoint | `https://merchant.example.com` |
| `consumer_id` | Consumer identifier | `user-123` |
| `interaction_type` | TAP interaction type | `checkout`, `browse` |
| `method` | HTTP method | `POST`, `GET` |
| `status` | Operation status | `completed`, `failed` |
| `error` | Error message (if applicable) | `Signature generation failed` |
| `nonce` | Request nonce | `550e8400-e29b-41d4-a716-446655440000` |

### Instrumentation

The codebase uses `#[instrument]` macros for automatic span tracking:

```rust
#[instrument(skip(signer, params), fields(
    merchant_url = %params.merchant_url,
    consumer_id = %params.consumer_id,
    interaction_type = "checkout"
))]
pub async fn checkout_with_tap(
    signer: &TapSigner,
    params: CheckoutParams,
) -> Result<CheckoutResult> {
    // Function body
}
```

This automatically creates spans with timing information and contextual fields.

## Health Checks

### Verify Agent Identity Tool

The server exposes a `verify_agent_identity` MCP tool that serves as a health check endpoint:

```json
{
  "status": "healthy",
  "version": "0.1.0",
  "agent_id": "agent-123",
  "uptime_secs": 3600,
  "checks": [
    {
      "name": "signing_key",
      "status": "pass",
      "message": "Ed25519 signing key loaded successfully"
    },
    {
      "name": "jwks_generation",
      "status": "pass",
      "message": "JWKS generated successfully"
    }
  ]
}
```

### Health Status Values

| Status | Meaning | HTTP Equivalent |
|--------|---------|----------------|
| `healthy` | All checks passed | 200 OK |
| `degraded` | Some checks have warnings | 200 OK |
| `unhealthy` | One or more checks failed | 503 Service Unavailable |

### Individual Check Status

Each health check returns one of:

- `pass`: Check succeeded
- `warn`: Check passed with warnings (degraded)
- `fail`: Check failed (critical)

### Available Checks

1. **signing_key**: Verifies Ed25519 signing key is loaded and accessible
2. **jwks_generation**: Verifies JWKS generation works correctly

## Request Correlation

### Automatic Span Tracking

All operations are automatically wrapped in spans with timing information:

```json
{
  "timestamp": "2025-01-18T10:15:30.500Z",
  "level": "INFO",
  "target": "tap_mcp_bridge::mcp::tools",
  "fields": {
    "message": "executing TAP checkout",
    "method": "POST"
  },
  "span": {
    "name": "checkout_with_tap",
    "merchant_url": "https://merchant.example.com",
    "consumer_id": "user-123",
    "interaction_type": "checkout"
  }
}
```

### Nonce Correlation

All TAP requests use a unique nonce (UUID v4) that appears across:
- HTTP signature nonce
- ID token nonce
- ACRO nonce
- Log entries

This enables end-to-end request tracing.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_FORMAT` | `pretty` | Log format: `json` or `pretty` |
| `RUST_LOG` | `info` | Log level filter (see [tracing-subscriber](https://docs.rs/tracing-subscriber)) |
| `TAP_AGENT_ID` | (required) | Agent identifier |
| `TAP_AGENT_DIRECTORY` | (required) | Agent directory URL |
| `TAP_SIGNING_KEY` | (required) | Ed25519 private key (hex) |

### Development Configuration

```bash
# Pretty logs for local debugging
export LOG_FORMAT=pretty
export RUST_LOG=debug
export TAP_AGENT_ID=dev-agent-123
export TAP_AGENT_DIRECTORY=https://dev.agent.example.com
export TAP_SIGNING_KEY=0000000000000000000000000000000000000000000000000000000000000000

tap-mcp-server
```

### Production Configuration

```bash
# JSON logs for log aggregation
export LOG_FORMAT=json
export RUST_LOG=info
export TAP_AGENT_ID=prod-agent-456
export TAP_AGENT_DIRECTORY=https://agent.example.com
export TAP_SIGNING_KEY=$(cat /secure/signing-key.hex)

tap-mcp-server
```

## Production Deployment

### Log Aggregation

JSON logs are designed for ingestion into log aggregation systems:

#### Elasticsearch / OpenSearch

```json
{
  "@timestamp": "2025-01-18T10:15:30.500Z",
  "level": "INFO",
  "message": "executing TAP checkout",
  "merchant_url": "https://merchant.example.com",
  "consumer_id": "user-123",
  "interaction_type": "checkout",
  "service": "tap-mcp-server",
  "version": "0.1.0"
}
```

#### Datadog

Use the Datadog log forwarder with JSON parsing:

```yaml
logs:
  - type: file
    path: /var/log/tap-mcp-server.log
    service: tap-mcp-server
    source: rust
    sourcecategory: mcp
```

#### Splunk

Forward JSON logs to Splunk HTTP Event Collector:

```bash
tail -f /var/log/tap-mcp-server.log | \
  jq -c '. + {sourcetype: "tap-mcp-server"}' | \
  curl -X POST https://splunk.example.com:8088/services/collector \
    -H "Authorization: Splunk ${SPLUNK_TOKEN}" \
    -d @-
```

### Monitoring

#### Key Metrics to Monitor

1. **Request Rate**: Number of tool invocations per minute
2. **Error Rate**: Failed requests / total requests
3. **Response Time**: p50, p95, p99 latency
4. **Health Status**: Current health check status
5. **Uptime**: Server uptime in seconds

#### Sample Prometheus Queries

```promql
# Request rate (requests/sec)
rate(tap_mcp_requests_total[5m])

# Error rate (percentage)
rate(tap_mcp_requests_total{status="error"}[5m]) / rate(tap_mcp_requests_total[5m]) * 100

# 95th percentile latency
histogram_quantile(0.95, rate(tap_mcp_request_duration_seconds_bucket[5m]))
```

### Alerting

#### Critical Alerts

1. **Service Down**: Health check fails for >1 minute
2. **High Error Rate**: >5% errors over 5 minutes
3. **Signing Key Failure**: `signing_key` check fails

#### Warning Alerts

1. **Degraded Health**: Health status = `degraded` for >5 minutes
2. **High Latency**: p95 latency > 1 second
3. **JWKS Generation Warning**: `jwks_generation` check warning

### Example Alert Configuration (Prometheus)

```yaml
groups:
  - name: tap-mcp-server
    rules:
      - alert: TapMcpServerDown
        expr: up{job="tap-mcp-server"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "TAP-MCP server is down"
          description: "The TAP-MCP server has been down for more than 1 minute"

      - alert: TapMcpHighErrorRate
        expr: |
          rate(tap_mcp_requests_total{status="error"}[5m])
          / rate(tap_mcp_requests_total[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | humanizePercentage }} over the last 5 minutes"

      - alert: TapMcpDegradedHealth
        expr: tap_mcp_health_status{status="degraded"} == 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "TAP-MCP server health degraded"
          description: "Server health has been degraded for more than 5 minutes"
```

## Troubleshooting

### Common Issues

#### 1. No Logs Appearing

**Symptoms**: Server starts but no logs are visible

**Solution**:
```bash
# Check RUST_LOG is set
echo $RUST_LOG

# Try explicit log level
export RUST_LOG=debug
tap-mcp-server
```

#### 2. JSON Logs Not Parsing

**Symptoms**: Log aggregation system rejects logs

**Solution**:
```bash
# Verify JSON format
export LOG_FORMAT=json
tap-mcp-server 2>&1 | jq .

# Check for stderr output mixed with logs
tap-mcp-server 2>/dev/null | jq .
```

#### 3. Health Check Failing

**Symptoms**: `verify_agent_identity` returns `unhealthy`

**Debug Steps**:
```bash
# Check which check is failing
tap-mcp-server 2>&1 | grep -i "health\|check"

# Verify signing key is loaded
echo $TAP_SIGNING_KEY | wc -c  # Should be 64 hex chars + newline = 65

# Test JWKS generation manually
# (Run in separate terminal with server running)
# Call verify_agent_identity tool via MCP client
```

#### 4. Missing Contextual Fields

**Symptoms**: Logs don't include expected fields (merchant_url, consumer_id, etc.)

**Solution**:
```bash
# Enable span events
export RUST_LOG=tap_mcp_server=debug,tap_mcp_bridge=debug

# Verify instrumentation is enabled (JSON logs show spans)
export LOG_FORMAT=json
tap-mcp-server 2>&1 | jq '.span'
```

### Debug Logging

For maximum verbosity during troubleshooting:

```bash
export LOG_FORMAT=pretty
export RUST_LOG=trace
tap-mcp-server
```

This enables all log levels including `trace`, which shows:
- Function entry/exit
- Internal state changes
- Detailed cryptographic operations
- HTTP request/response details

**Warning**: Trace logs may include sensitive data. Never use in production.

### Performance Impact

Observability features have minimal performance overhead:

- **Structured logging**: <1% CPU overhead
- **Instrumentation**: <0.5% latency overhead
- **Health checks**: Only run on-demand (via tool invocation)

For extremely high-throughput scenarios, consider:

```bash
# Reduce log verbosity
export RUST_LOG=warn

# Use JSON format (faster serialization)
export LOG_FORMAT=json
```

## Future Enhancements

Planned observability improvements:

1. **Metrics Export**: Native Prometheus/OpenTelemetry metrics
2. **Distributed Tracing**: OpenTelemetry trace propagation
3. **Request ID Injection**: Custom request ID headers
4. **Audit Logging**: Security-focused audit trail
5. **Performance Profiling**: CPU/memory profiling endpoints

## Resources

- [tracing documentation](https://docs.rs/tracing)
- [tracing-subscriber documentation](https://docs.rs/tracing-subscriber)
- [OpenTelemetry](https://opentelemetry.io/)
- [Prometheus](https://prometheus.io/)
- [Rust logging best practices](https://github.com/rust-lang/log)
