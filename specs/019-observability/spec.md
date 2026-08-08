# Spec 019 — `observability` Subsystem: Logging, Health Checks, Metrics

**Status**: Documented (as-built)
**Priority**: N/A (subsystem documentation, not a fix)
**Type**: Subsystem specification — documents existing behavior
**Owner**: N/A
**Discovered**: Authored during specs migration cycle, 2026-08-08, closing the
subsystem-coverage gap against `.claude/rules/continuous-improvement.md` §
Project Subsystems
**Source**: `tap-mcp-server/src/observability.rs`

> [!warning]
> Unlike the other subsystem specs in this batch, this one documents a
> **partially-dead-code state**, not a fully wired subsystem. `Metrics` is
> defined, tested, and can render Prometheus text output, but is never
> constructed or incremented anywhere in `tap-mcp-server/src/main.rs` — the
> whole module carries `#![allow(dead_code, reason = "Metrics struct prepared
> for future integration")]`. This spec records that fact rather than
> describing aspirational "wired" behavior.

## 1. Overview

### Problem Statement

The `tap-mcp-server` binary needs structured logging (for operational
debugging), a health-check payload (`verify_agent_identity` MCP tool), and —
eventually — Prometheus-exportable metrics. This module (binary-local, not
part of the `tap-mcp-bridge` library) implements all three, but only the
first two are actually exercised by `main.rs` today.

### Goal

`init_observability` wires `tracing_subscriber` with an `EnvFilter` and a
JSON-or-pretty formatter; `HealthReport`/`HealthCheck` back the
`verify_agent_identity` tool's response; `Metrics` exists as a ready-to-adopt
counter set with Prometheus exposition formatting, awaiting integration into
the actual request path.

### Out of Scope

- Metrics integration itself (i.e. actually calling `record_checkout_success`
  etc. from `mcp` tool call sites) — not yet done; this spec documents the
  current state, it does not perform the integration
- Structured audit logging (`AuditEvent`) — that is a library concern, see
  [[018-security-hardening]]

## 2. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| `LogFormat` | Output format selector | `Pretty \| Json`; `from_env()` reads `LOG_FORMAT` |
| `HealthStatus` | Overall health | `Healthy \| Degraded \| Unhealthy` |
| `HealthCheckStatus` | Per-check result | `Pass \| Fail \| Warn` |
| `HealthCheck` | One named check result | `name, status, message: Option<String>` |
| `HealthReport` | Full health payload | `status, version, agent_id, uptime_secs, checks: Vec<HealthCheck>, metrics: Option<MetricsSnapshot>` |
| `Metrics` | Atomic counters (currently unwired) | `checkout_requests, checkout_successes, checkout_failures, browse_requests, signature_generations, http_errors` — all `AtomicU64` |

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-1 | WHEN `init_observability(format)` runs THE SYSTEM SHALL configure a `tracing_subscriber` registry with an `EnvFilter` sourced from `RUST_LOG` (default `"info"`) and a formatting layer (JSON or pretty per `format`) writing to `stderr` with `FmtSpan::CLOSE` span events | must |
| FR-2 | WHEN `HealthReport::compute_status` evaluates a set of `HealthCheck`s THE SYSTEM SHALL return `Unhealthy` if any check is `Fail`, else `Degraded` if any check is `Warn`, else `Healthy` | must |
| FR-3 | WHEN `HealthReport::to_json` serializes a report THE SYSTEM SHALL build it via `serde_json::json!` in a way that preserves key order (a fix for a prior key-ordering regression, #138/#139) | must |
| FR-4 | WHEN `Metrics::to_prometheus` is called THE SYSTEM SHALL render counters in Prometheus text exposition format with names prefixed `tap_` (e.g. `tap_checkout_requests_total`) | must |
| FR-5 | THE SYSTEM SHALL NOT currently construct or increment any `Metrics` counter from `tap-mcp-server/src/main.rs` — the `verify_agent_identity` tool's response sets `metrics: None` with an explicit `// TODO` marker | must (documents current state) |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-1 | Configuration | `LOG_FORMAT` (`json`\|`pretty`, default `pretty`) and `RUST_LOG` (default `info`) are the only two env vars this module reads |
| NFR-2 | Testability | Inline `#[cfg(test)]` module covers `LogFormat` env parsing, `HealthCheck` constructors, `HealthReport` JSON shape (including the key-order regression test), `Metrics` counter behavior, and Prometheus text-format assertions |
| NFR-3 | Scope | Prometheus metrics are not currently scraped by anything — no HTTP endpoint exists in `tap-mcp-server` to expose `to_prometheus()`'s output. The function is tested but has no caller in `main.rs` |

## 5. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|--------------------|
| `LOG_FORMAT` is unset or has an unrecognized value | Falls back to `Pretty` (`from_env`'s else-branch) |
| A `HealthCheck` has `status: Fail` alongside other `Pass` checks | `compute_status` returns `Unhealthy` — `Fail` dominates `Warn` and `Pass` |
| `verify_agent_identity` is called | Returns a `HealthReport` with `metrics: None` (FR-5) — callers cannot currently observe request counters through this tool |

## 6. Agent Boundaries

### Always (without asking)
- Preserve the `serde_json::json!`-based key-order-preserving construction in `HealthReport::to_json` (FR-3) — do not refactor to a struct-derived `Serialize` without re-verifying key order, per the #138/#139 regression history

### Ask First
- Wiring `Metrics` into actual MCP tool call sites (`checkout_with_tap`, `browse_merchant`, etc.) and exposing a Prometheus scrape endpoint — this is real, scoped feature work, not documentation; it should go through its own `/sdd specify` → `/sdd plan` cycle rather than being bundled into an unrelated change
- Removing the `#![allow(dead_code, ...)]` on this module — only do so once `Metrics` actually has a caller

### Never
- Silently start incrementing `Metrics` counters from only some call sites while leaving others unwired — partial instrumentation is worse than none because it implies false completeness

## 7. Open Questions

- `[NEEDS CLARIFICATION: is Prometheus metrics integration still planned (README/CHANGELOG reference it as a "production feature"), and if so, is a pull-based scrape endpoint or push-based exporter the intended design? This determines whether main.rs needs a second listener alongside the MCP stdio transport.]`
- `[NEEDS CLARIFICATION: should this module move into the tap-mcp-bridge library (so any binary embedding the bridge gets the same health/metrics shape), or does it stay tap-mcp-server-specific by design?]`

## 8. See Also

- [[MOC-specs]] — all specifications
- [[002-json-key-ordering-regression]] — the #138/#139 incident behind FR-3's key-order preservation requirement
- [[018-security-hardening]] — the library-side audit-logging counterpart to this binary-side observability module
- [[020-tap-mcp-server-binary]] — where `init_observability` and `HealthReport` are actually invoked
- `.claude/rules/continuous-improvement.md` § Performance & Benchmark Coverage — `observability_overhead` is the workspace's only existing benchmark, and it targets this module
