# Spec 020 — `tap-mcp-server` Binary: MCP Stdio Server Exposing TAP Tools

**Status**: Documented (as-built)
**Priority**: N/A (subsystem documentation, not a fix)
**Type**: Subsystem specification — documents existing behavior
**Owner**: N/A
**Discovered**: Authored during specs migration cycle, 2026-08-08, closing the
subsystem-coverage gap against `.claude/rules/continuous-improvement.md` §
Project Subsystems
**Source**: `tap-mcp-server/src/main.rs`

> [!note]
> Describes existing, tested code. This is the binary crate that consumes
> [[014-mcp-tool-surface]]'s library functions and exposes them over the
> Model Context Protocol.

## 1. Overview

### Problem Statement

An MCP-compatible AI agent client (e.g. Claude Desktop) needs to discover and
invoke TAP operations as MCP tools over a standard transport. `tap-mcp-server`
is the binary that loads agent credentials from the environment, builds a
`TapSigner`, registers every `mcp` library function as an MCP tool, and serves
them over stdio using JSON-RPC 2.0 framing.

### Goal

Running `tap-mcp-server` with three required environment variables
(`TAP_AGENT_ID`, `TAP_AGENT_DIRECTORY`, `TAP_SIGNING_KEY`) produces a working
MCP server an agent client can `initialize` and `tools/list`/`tools/call`
against, with graceful shutdown on Ctrl-C.

### Out of Scope

- The tool implementations themselves — see [[014-mcp-tool-surface]]
- Logging/health-check internals — see [[019-observability]]

## 2. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| `Config` | Validated startup configuration | loaded via `Config::from_env()` |
| `TapMcpServer` | The MCP service implementor | `Arc<TapSigner>`, `ToolRouter`, start time, `agent_id`; manual `Debug` redacts the signer field as `"[TapSigner]"` |
| Per-tool request wrapper structs | e.g. `CheckoutRequest`, `BrowseRequest` | derive `Deserialize + JsonSchema`; map 1:1 into the corresponding `mcp::*Params` type |
| `EmptyRequest` | Zero-field request marker for parameterless tools | Declared as `struct EmptyRequest {}` (brace form), not a unit struct |

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-1 | WHEN the binary starts THE SYSTEM SHALL read and validate `TAP_AGENT_ID` (alphanumeric + `-`/`_`, 1–64 chars), `TAP_AGENT_DIRECTORY` (must be `https://`, must reject loopback hosts, userinfo, port 0, and `.`/`..` path segments), and `TAP_SIGNING_KEY` (exactly 64 hex characters / 32 bytes, must reject any all-bytes-equal seed) before constructing a signer | must |
| FR-2 | WHEN `TAP_SIGNING_KEY` decodes to a seed where every byte is equal (all-zero, all-`0xff`, or any other repeated byte) THE SYSTEM SHALL reject startup, since such a key is publicly derivable | must |
| FR-3 | WHEN the server starts THE SYSTEM SHALL call `init_observability` before config validation output is needed, so startup errors are captured by the configured log format | must |
| FR-4 | THE SYSTEM SHALL register exactly these MCP tools via `#[tool_router]`/`#[tool]`: `checkout_with_tap`, `browse_merchant`, `get_products`, `get_product`, `add_to_cart`, `get_cart`, `update_cart_item`, `remove_from_cart`, `create_order`, `get_order`, `process_payment`, `verify_agent_identity` | must |
| FR-5 | WHEN a tool takes no parameters THE SYSTEM SHALL use `Parameters<EmptyRequest>` (brace-form empty struct) rather than `Parameters<()>`, so the emitted JSON Schema is `type: "object"` rather than `type: "null"` (regression fix for #120) | must |
| FR-6 | WHEN the server reports its identity (MCP `initialize` response) THE SYSTEM SHALL override `ServerInfo` via `Implementation::new(CARGO_PKG_NAME, CARGO_PKG_VERSION)` so clients see `tap-mcp-server`'s own name/version, not the underlying `rmcp` framework's build identity | must |
| FR-7 | WHEN the process receives `Ctrl-C` (or the MCP service's `waiting()` future completes) THE SYSTEM SHALL shut down gracefully via `tokio::select!` between the two futures | must |
| FR-8 | WHEN `verify_agent_identity` is invoked THE SYSTEM SHALL report signing-key-loaded status, a JWKS-generation check, process uptime, and version — as a `HealthReport` (see [[019-observability]]) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-1 | Transport | MCP is served exclusively over stdio (`rmcp::transport::stdio()`) with JSON-RPC 2.0 framing; no network listener exists in this binary |
| NFR-2 | Configuration | All configuration is environment-variable-based: `TAP_AGENT_ID`, `TAP_AGENT_DIRECTORY`, `TAP_SIGNING_KEY` (required), `RUST_LOG` (optional, default `info`), `LOG_FORMAT` (optional, default `pretty`) |
| NFR-3 | Testability | Inline `#[cfg(test)]` module in `main.rs` covers config validation (including the loopback/userinfo/port-0/traversal/all-equal-byte-key regressions), signer creation, `get_info` identity, tool-list completeness (regression #121), and empty-request schema shape (regression #120) |
| NFR-4 | Secrets | `TAP_SIGNING_KEY` is read directly from the process environment by this binary at runtime — this is the one place in the project where a `TAP_*` secret is expected to come from an env var rather than the Zeph vault, since the binary itself has no vault integration; the vault is a development-workflow concern for this repo's own contributors, not a deployment requirement for consumers of the binary |

## 5. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|--------------------|
| `TAP_AGENT_DIRECTORY` is `https://user:pass@directory.example/` (userinfo present) | Startup rejected |
| `TAP_AGENT_DIRECTORY` path contains `..` | Startup rejected (regression #149 class) |
| `TAP_SIGNING_KEY` is 64 hex chars of all `0`s or all `f`s | Startup rejected (regression #148 class) |
| A tool call arrives before `initialize` completes | Handled by the underlying `rmcp` service lifecycle, not this binary's own logic |
| Ctrl-C arrives while a tool call is in flight | `tokio::select!` races shutdown against the service's `waiting()` future; in-flight call completion behavior is governed by `rmcp`'s own service shutdown semantics, not re-implemented here |

## 6. Agent Boundaries

### Always (without asking)
- Keep `Config::from_env()` as the single validation choke point for all three required env vars
- Keep the tool list in FR-4 in sync with `tap-mcp-bridge`'s `mcp` module — if a new library tool function is added, register it here or explicitly note it is intentionally not yet exposed

### Ask First
- Adding a network-based transport (HTTP/SSE) alongside stdio — currently stdio-only by design
- Adding new required environment variables — expands the deployment contract for every consumer

### Never
- Read `TAP_SIGNING_KEY` (or any secret) from a file path or hardcoded default — env-var-only per FR-1
- Expose `ServerInfo` reflecting the underlying `rmcp` framework's identity instead of `tap-mcp-server`'s own (FR-6)

## 7. Open Questions

- `[NEEDS CLARIFICATION: is a network transport (HTTP/SSE per newer MCP spec revisions) planned, given rmcp 3.x's feature set now supports it, or is stdio-only a deliberate, permanent scope boundary for this binary?]`

## 8. See Also

- [[MOC-specs]] — all specifications
- [[007-weak-signing-keys-accepted]] — origin of FR-2's all-equal-byte-key rejection
- [[014-mcp-tool-surface]] — the library functions registered as tools here
- [[019-observability]] — `init_observability`/`HealthReport`, invoked from this binary's startup and `verify_agent_identity` respectively
- `tap-mcp-server/src/main.rs` — full implementation and inline tests
