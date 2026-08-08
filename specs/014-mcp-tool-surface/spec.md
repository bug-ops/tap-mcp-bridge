# Spec 014 — `mcp` Subsystem: TAP Operations Exposed as Callable Tools

**Status**: Documented (as-built)
**Priority**: N/A (subsystem documentation, not a fix)
**Type**: Subsystem specification — documents existing behavior
**Owner**: N/A
**Discovered**: Authored during specs migration cycle, 2026-08-08, closing the
subsystem-coverage gap against `.claude/rules/continuous-improvement.md` §
Project Subsystems
**Source**: `tap-mcp-bridge/src/mcp/{mod,tools,models,http,cart,orders,payment,products}.rs`,
`tap-mcp-bridge/src/mcp/subscriptions/{mod,tools,models,lifecycle,pricing,proration}.rs`

> [!note]
> Describes existing, tested code. This is the largest subsystem by surface
> area — it is the library-side implementation consumed by the
> `tap-mcp-server` binary (see [[020-tap-mcp-server-binary]]) to expose MCP
> tools over stdio.

## 1. Overview

### Problem Statement

An AI agent needs a catalog of async, strongly-typed operations — browse,
cart, checkout, orders, payment, subscriptions — that internally handle TAP
signing, HTTP transport, and merchant-specific request/response shaping. The
`mcp` module is this catalog: every public `async fn` here takes a `&TapSigner`
plus a `Params` struct and returns a typed `Result`.

### Goal

Every commerce operation the bridge supports (legacy checkout/browse, catalog,
cart, orders, payment, subscription lifecycle) is reachable through one
consistent function-per-operation shape, sharing two executor primitives
(`execute_tap_request_with_acro`, `execute_tap_request_with_custom_nonce`) so
that TAP signing and HTTP request construction are implemented exactly once.

### Out of Scope

- The MCP wire protocol / tool registration itself (JSON-RPC framing, stdio
  transport) — that's [[020-tap-mcp-server-binary]]
- Merchant-specific endpoint/field mapping — that's [[015-merchant-abstraction]]
- Whether ACRO actually reaches the wire for body-bearing requests — already
  fully analyzed in [[011-process-payment-acro-wire-contract]]; this spec
  states the current behavior as fact without re-litigating it

## 2. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| `Product` / `ProductVariant` / `ProductCatalog` | Standard catalog wire format | merchant-agnostic; `MerchantApi` implementors convert to/from this shape |
| `CartItem` / `CartState` | Standard cart wire format | same conversion pattern |
| `Order` / `OrderLineItem` / `OrderStatus` / `Address` | Standard order wire format | `OrderStatus` is an enum |
| `PaymentResult` / `PaymentStatus` | Standard payment result | `PaymentStatus` is an enum |
| `PlanId` / `SubscriptionId` | Validated newtype IDs (non-empty, ≤64 chars) | constructed only via `::new()` |
| `Subscription<State>` | Typestate-pattern subscription; `State ∈ {Trial, Active, Paused, PastDue, Canceled, Expired}` | consuming transition methods return the next state type, making illegal transitions a compile error |
| `PricingModel` | Flat / Tiered / PerSeat / Usage / Hybrid pricing | `minimum_price() -> Decimal` |

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-1 | WHEN any tool function in this module sends an HTTP request THE SYSTEM SHALL route it through exactly one of the two executors in `http.rs` (`execute_tap_request_with_acro` or `execute_tap_request_with_custom_nonce`) rather than constructing requests ad hoc | must |
| FR-2 | WHEN `execute_tap_request_with_acro` is called with `request_body = Some(_)` THE SYSTEM SHALL send `request_body` as the wire body and SHALL NOT transmit the generated ACRO object; WHEN called with `request_body = None` THE SYSTEM SHALL serialize the ACRO object itself as the entire wire body | must |
| FR-3 | WHEN `payment::process_payment` executes THE SYSTEM SHALL use `execute_tap_request_with_custom_nonce` so that the APC nonce and the HTTP signature nonce are identical | must |
| FR-4 | WHEN any path segment supplied to an executor contains a `.` or `..` component THE SYSTEM SHALL reject the call via `reject_path_traversal` before constructing the request | must |
| FR-5 | WHEN an HTTP response with a 3xx status is received by the shared `reqwest::Client` (built via `create_http_client`) THE SYSTEM SHALL NOT follow it (`Policy::none()`) — the response is surfaced as-is to the caller | must |
| FR-6 | WHEN `validate_consumer_id` receives a consumer ID THE SYSTEM SHALL reject it unless non-empty, ≤64 characters, and composed only of alphanumerics, `-`, and `_` | must |
| FR-7 | WHEN `parse_merchant_url` receives a merchant URL THE SYSTEM SHALL require HTTPS, EXCEPT WHEN the `TAP_ALLOW_LOOPBACK` environment variable is set to `1`, in which case `http://localhost` and `http://127.0.0.1` are also accepted | must |
| FR-8 | WHEN a `Subscription<State>` transition method is called on a state that does not define that transition THE SYSTEM SHALL fail to compile (no runtime state-transition validation is needed for statically-known transitions) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-1 | Security | `TAP_ALLOW_LOOPBACK=1` is a documented escape hatch for local testing; it must never be set in production merchant integrations. This is flagged in `.claude/rules/continuous-improvement.md` § Security Audit Depth as an item requiring continued scrutiny |
| NFR-2 | Consistency | All 12+ tool functions (`checkout_with_tap`, `browse_merchant`, `get_products`, `get_product`, `add_to_cart`, `get_cart`, `update_cart_item`, `remove_from_cart`, `create_order`, `get_order`, `process_payment`, `process_payment_rate_limited`, plus 11 subscription tools) follow the identical `async fn(&TapSigner, Params) -> Result<T>` shape |
| NFR-3 | Testability | Inline `#[cfg(test)]` modules exist per file across `mcp/` and `mcp/subscriptions/` |
| NFR-4 | Duplication | `execute_tap_request_with_acro` and `execute_tap_request_with_custom_nonce` share substantial logic (nonce handling, ACRO generation, header construction); issue #240 tracks deduplicating them into a shared executor — this spec documents the current pre-deduplication state |

## 5. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|--------------------|
| Search/query parameter exceeds `MAX_SEARCH_PARAM_LENGTH` (256 chars) | Rejected by `validate_search_param` before the request is sent |
| Search parameter contains a NUL byte or non-graphic character | Rejected by `validate_search_param` |
| Base URL has a trailing slash and path starts with `/` | `compose_request_url` avoids the resulting double-slash |
| Merchant responds with a non-2xx status | Surfaced as `BridgeError::MerchantError`, never silently retried inside this module (retry is a caller/`reliability` concern) |
| `process_payment` receives ACRO-context fields (`country_code`, `zip`, etc.) | Per [[011-process-payment-acro-wire-contract]], these are currently signed into an ACRO that is generated but never transmitted for this call path — tracked as a known defect in that spec, not restated as correct behavior here |

## 6. Agent Boundaries

### Always (without asking)
- Add new tool functions following the existing `async fn(&TapSigner, Params) -> Result<T>` shape
- Route new HTTP calls through the existing executors in `http.rs`, not a new ad hoc client

### Ask First
- Deduplicating `execute_tap_request_with_acro` / `execute_tap_request_with_custom_nonce` (issue #240) — significant refactor touching every call site
- Changing `TAP_ALLOW_LOOPBACK` semantics or default

### Never
- Bypass `reject_path_traversal` or `validate_consumer_id` for a new call site
- Re-enable HTTP redirect following on the shared client (`create_http_client`) — see [[005-redirects-leak-tap-headers]] and [[006-incomplete-redirect-fix]] for why this was disabled

## 7. Open Questions

- `[NEEDS CLARIFICATION: is issue #240's executor deduplication scheduled, and should it be coordinated with the FR-5 follow-up from spec 011 (extending the ACRO-discard fix to add_to_cart/update_cart_item/remove_from_cart/subscription mutations)?]`

## 8. See Also

- [[MOC-specs]] — all specifications
- [[001-cart-id-silently-dropped]] — precedent bug in this subsystem (cart tools)
- [[003-rate-limit-not-per-consumer]] — `process_payment_rate_limited` behavior history
- [[004-id-fields-path-traversal]] — origin of `reject_path_traversal` (FR-4)
- [[005-redirects-leak-tap-headers]], [[006-incomplete-redirect-fix]] — origin of the no-redirect policy (FR-5)
- [[011-process-payment-acro-wire-contract]] — deep analysis of FR-2's ACRO transmission rule and its `process_payment` defect
- [[015-merchant-abstraction]] — the trait layer this module's tools convert to/from
- [[020-tap-mcp-server-binary]] — where these functions are registered as MCP tools
