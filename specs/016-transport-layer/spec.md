# Spec 016 — `transport` Subsystem: Sealed HTTP Transport Abstraction

**Status**: Documented (as-built)
**Priority**: N/A (subsystem documentation, not a fix)
**Type**: Subsystem specification — documents existing behavior
**Owner**: N/A
**Discovered**: Authored during specs migration cycle, 2026-08-08, closing the
subsystem-coverage gap against `.claude/rules/continuous-improvement.md` §
Project Subsystems
**Source**: `tap-mcp-bridge/src/transport/{mod,config,sealed}.rs`, `transport/http/mod.rs`

> [!note]
> Describes existing, tested code.

## 1. Overview

### Problem Statement

Every outbound request the bridge makes must go through TAP-signed HTTP —
there must be no way for a caller (in this crate or a future external crate)
to construct a transport that bypasses the security checks (HTTPS
enforcement, loopback rejection, path sanitization, header injection
prevention) that TAP requires. The `transport` module defines a `Transport`
trait that is **sealed**, so only this crate can implement it, with
`HttpTransport` as the sole current implementation over `reqwest`.

### Goal

A `Transport` implementor exposes `get`/`post`/`put`/`delete` returning a
uniform `TransportResponse`, while internally enforcing HTTPS-only,
loopback-rejecting, traversal-safe, CRLF-safe requests, leaving room for
future protocols (HTTP/3, gRPC) without changing the trait's public shape.

### Out of Scope

- The TAP-signing-specific request executors in `mcp/http.rs` (which build on
  top of a plain `reqwest::Client`, not this module's `Transport` trait) —
  see [[014-mcp-tool-surface]]. The two HTTP client configurations
  (`mcp/http.rs`'s `create_http_client` and this module's
  `DEFAULT_HTTP_CLIENT`) are separate, parallel client instances with
  equivalent but independently maintained security settings

## 2. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| `Transport` (trait, sealed) | Uniform async HTTP interface | `get/post/put/delete` (RPITIT futures), `protocol_name() -> &'static str`, `supports_streaming() -> bool` (default `false`) |
| `RequestContext<'a>` | Per-request parameters | `base_url, path, headers: Vec<(&str,&str)>, content_type: Option<&str>, interaction_type: InteractionType` |
| `TransportResponse` | Uniform response shape | `status: u16, body: Vec<u8>, headers: Vec<(String,String)>` |
| `HttpTransport` | The sole current `Transport` implementor | `client: Client, http_version: HttpVersion` |
| `TransportConfig` | Tagged config enum | `Http(HttpConfig) \| Http2(HttpConfig)` |
| `HttpConfig` | Tunable client parameters | `pool_max_idle_per_host, timeout_secs, connect_timeout_secs, http_version` |
| `HttpVersion` | Protocol selection | `Http1 \| Http2 \| Auto (default)` |

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-1 | THE SYSTEM SHALL prevent any type outside this crate from implementing `Transport`, via a `pub(crate)` sealing trait in `sealed.rs` | must |
| FR-2 | WHEN `HttpConfig` is validated THE SYSTEM SHALL require `timeout_secs` in `1..=300` and `connect_timeout_secs` in `1..=60`, rejecting values outside those ranges | must |
| FR-3 | WHEN a URL is validated (`validate_url`) THE SYSTEM SHALL require HTTPS and SHALL reject `localhost`/`127.0.0.1`/`::1`/`[::1]` hosts | must |
| FR-4 | WHEN a path is sanitized (`sanitize_path`) THE SYSTEM SHALL reject `..` and `//` segments and SHALL require the path to start with `/` | must |
| FR-5 | WHEN a header name or value is validated (`validate_header`) THE SYSTEM SHALL reject any CR, LF, or NUL byte (CRLF/header injection prevention) | must |
| FR-6 | WHEN the module-local `DEFAULT_HTTP_CLIENT` singleton is used THE SYSTEM SHALL disable automatic redirect following | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-1 | Defaults | `pool_max_idle_per_host = 100`, `timeout_secs = 30`, `connect_timeout_secs = 10`, `http_version = Auto` |
| NFR-2 | Extensibility | The `Transport` trait's shape (async methods returning `TransportResponse`, `protocol_name`, `supports_streaming`) is designed to accommodate future HTTP/3 or gRPC implementors without a breaking change, per the module doc comment |
| NFR-3 | Testability | Inline `#[cfg(test)]` coverage exists for `RequestContext`/`TransportResponse` construction and equivalent validation logic in `http/mod.rs` |

## 5. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|--------------------|
| `timeout_secs = 0` or `> 300` | `HttpConfig::validate()` rejects it (`TransportError`) |
| URL scheme is `http://` | Rejected by `validate_url` |
| Path is `/cart/../admin` | Rejected by `sanitize_path` |
| Header value contains `\r\n` | Rejected by `validate_header` |
| A future protocol needs `supports_streaming() == true` | Override the default method on the new implementor; no trait-level change required |

## 6. Agent Boundaries

### Always (without asking)
- Run new outbound requests through `HttpTransport` (or a future sealed implementor), never a bare unvalidated `reqwest::Client`
- Keep the sealed-trait pattern (`sealed.rs`) intact when adding new `Transport` methods

### Ask First
- Adding a new `Transport` implementor (HTTP/3, gRPC, JSON-RPC) — significant new surface
- Consolidating this module's HTTP client configuration with `mcp/http.rs`'s separate `create_http_client` (currently two parallel, independently-configured clients with equivalent security posture — a DRY opportunity, not yet acted on)

### Never
- Remove or weaken the `sealed` trait bound on `Transport`
- Re-enable redirect following on `DEFAULT_HTTP_CLIENT`

## 7. Open Questions

- `[NEEDS CLARIFICATION: should transport::http and mcp::http's parallel HTTP client configurations be unified into a single shared client factory, given they enforce equivalent but independently-maintained security settings? This is a DRY candidate per the arch-audit requirements in .claude/rules/continuous-improvement.md.]`

## 8. See Also

- [[MOC-specs]] — all specifications
- [[005-redirects-leak-tap-headers]], [[006-incomplete-redirect-fix]] — history behind FR-6's no-redirect policy (originally found in `mcp/http.rs`'s client, not this module's, but the same posture applies here)
- [[014-mcp-tool-surface]] — the parallel, TAP-signing-specific HTTP client this module does not itself drive
- `tap-mcp-bridge/src/transport/mod.rs` — module entry point
