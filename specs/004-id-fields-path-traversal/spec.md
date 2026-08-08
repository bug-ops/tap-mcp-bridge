# Spec 004 — id-fields embedded in URL paths via `format!()` enable path-traversal

**Status**: Draft
**Priority**: P1 (Bug — broken functionality on strict TAP merchants / security on loose merchants; systemic across 12+ tool functions)
**Type**: Bug fix + input validation
**Owner**: TBD
**Discovered**: 2026-05-01, Cycle 13 live testing, master @ 10b919e
**Source**: `.local/testing/scratch/src/adversarial_ids.rs`

## Problem Statement

Multiple MCP tool functions in `tap-mcp-bridge` accept caller-supplied `id`
fields (`item_id`, `order_id`, `product_id`, `subscription_id`, `plan_id`,
etc.) and embed them verbatim into URL paths via `format!()`, with **no
input validation and no percent-encoding of path-segment-special characters**.

When a caller supplies an id containing `..` segments (e.g.
`item_id="../../admin"`), the resulting path:

1. The bridge constructs `path = "/cart/items/../../admin"` and passes it to
   `signer.sign_request(method, authority, path, ...)`. The Ed25519 signature
   covers `/cart/items/../../admin` as the `@path` derived component.
2. `compose_request_url` (`tap-mcp-bridge/src/mcp/http.rs:57–64`) does
   **no path normalization** — it simply concatenates the base URL string
   with `path`.
3. When `reqwest` actually issues the request, its internal `url::Url`
   parser **does** normalize `..` segments. The wire path therefore
   becomes `/admin`.

Two failure modes follow:

- **TAP-strict merchant** (RFC 9421 §2.2.6 conformant): reconstructs
  `@path` from the wire request → `/admin`. Compares to signed `@path`
  → `/cart/items/../../admin`. Mismatch ⇒ **signature verification fails
  ⇒ legitimate cart-item-update requests are rejected** whenever the
  `item_id` happens to contain `..` segments (even by accident, e.g.
  merchant-issued ids that happen to contain `..`).
- **TAP-loose merchant** (does not strictly verify `@path`, or accepts
  the signed form): receives a request bound for `/admin` (or any
  arbitrary endpoint the attacker constructs). **Privilege escalation**:
  a malicious MCP client controlling `item_id` can target any merchant
  endpoint reachable from the same host, with a valid Ed25519 signature
  from the bridge's registered agent identity.

Affected functions (all use `format!("/.../{id}", ...)` for path
construction):

| Function | id field | Path template |
|---|---|---|
| `update_cart_item` | `item_id` | `/cart/items/{item_id}` |
| `remove_from_cart` | `item_id` | `/cart/items/{item_id}` |
| `get_product` | `product_id` | `/products/{product_id}` |
| `get_order` | `order_id` | `/orders/{order_id}` |
| `get_subscription_plan` | `plan_id` | `/subscriptions/plans/{plan_id}` |
| `get_subscription` | `subscription_id` | `/subscriptions/{subscription_id}` |
| `update_subscription` | `subscription_id` | `/subscriptions/{subscription_id}` |
| `cancel_subscription` | `subscription_id` | `/subscriptions/{subscription_id}/cancel` |
| `pause_subscription` | `subscription_id` | `/subscriptions/{subscription_id}/pause` |
| `resume_subscription` | `subscription_id` | `/subscriptions/{subscription_id}/resume` |
| `report_usage` | `subscription_id` | `/subscriptions/{subscription_id}/usage` |
| `get_usage` | `subscription_id` | `/subscriptions/{subscription_id}/usage/summary` |
| `update_payment_method` | `subscription_id` | `/subscriptions/{subscription_id}/payment-method` |
| `preview_proration` | `subscription_id` | `/subscriptions/{subscription_id}/proration-preview` |

Confirmed live for `update_cart_item`, `get_order`, `get_product` in cycle
13's `adversarial-ids` harness:

```
update_cart_item item_id='../../admin' → wire path "/admin"
get_order order_id='../../admin'        → wire path "/admin"
get_product product_id='../../secret'   → wire path "/secret"
```

The remaining 11 functions follow the same code pattern and are presumed
to behave identically.

## User Stories

- **As a TAP-strict merchant** I expect that any signed request with a
  valid Ed25519 signature and matching `@path` derived component
  represents the agent's intent. The bridge breaking this invariant
  silently means I reject otherwise-valid requests and the agent looks
  buggy from my side.
- **As a TAP-loose merchant** (or one that has admin endpoints reachable
  from the same host as the cart endpoint) I am exposed to privilege
  escalation if a malicious caller controls any of the id fields the
  bridge passes through.
- **As a bridge maintainer** I expect that the signed `@path` and the
  wire `@path` are always identical — that is the RFC 9421 invariant
  that makes signature verification meaningful. Currently it is broken
  for any id containing `..`, `\\`, or other URL-path-special characters.
- **As a security reviewer** I need user-controlled values that flow into
  URL paths to either be rejected or percent-encoded — never embedded
  verbatim. This is OWASP A1 / A4 territory.

## Functional Requirements

**FR-1**: All caller-supplied id fields routed through `format!("/.../{id}")`
MUST either be:
  - **(A)** validated at the tool entry point against a strict allowlist
    (e.g. ASCII alphanumeric + hyphen + underscore, max 64 chars — same
    constraint as `validate_consumer_id` and the existing typed
    `SubscriptionId::new` / `PlanId::new`), with a clear `BridgeError`
    on rejection; OR
  - **(B)** percent-encoded as a single path segment via
    `url::form_urlencoded` or equivalent, so `..`, `/`, `?`, `#`, `%`,
    NUL, CRLF are encoded.

Position A is preferred — the bridge already enforces a strict allowlist
on `consumer_id` and on the typed wrapper constructors. The
"plain `String`" id fields are an inconsistency.

**FR-2**: `compose_request_url` MUST guarantee that signed `@path` ==
wire `@path`. If validation/encoding does not happen at the tool entry
point, `compose_request_url` should canonicalize the path (or refuse to
proceed if `..` segments are present) so signature and wire stay in sync.

**FR-3**: A regression test MUST exist for at least one id-field per
distinct path pattern (`/cart/items/{}`, `/orders/{}`, `/products/{}`,
`/subscriptions/{}`, `/subscriptions/{}/cancel`, etc.) asserting that:
  - id values containing `..` are rejected at the tool entry point, OR
  - if accepted, the wire path's segment count and structure match the
    template (so `..` cannot collapse into `/admin`).

**FR-4**: Documentation on each tool function's `# Errors` section MUST
list the id-field constraints (ascii alphanumeric + hyphen + underscore,
max length, etc.).

## Non-Functional Requirements

- **Performance**: validation is O(n) over each id; negligible.
- **Backward compatibility**: pre-1.0 — breaking changes allowed.
  Existing callers using strict ids (alphanumeric + hyphen + underscore)
  are unaffected. Callers passing arbitrary strings will start receiving
  validation errors — capture in CHANGELOG.
- **Documentation**: CHANGELOG entry under [Unreleased] / Fixed
  describing the path-traversal surface, the allowlist applied, and any
  breaking-change implications for callers passing non-strict ids.
- **Security**: this is a defense-in-depth issue. Even on TAP-strict
  merchants, the bridge produces signature-invalid requests for some
  inputs; on loose merchants it is a privilege-escalation surface.

## Design Choices (Open Questions for /sdd plan)

1. **Position A vs B**: validate at entry point (reject), or
   percent-encode the segment (accept-and-encode)? The TAP spec does not
   restrict id syntax; merchants are free to issue ids with arbitrary
   characters. Position B preserves more flexibility but lets `..` /
   `/` reach the merchant in encoded form, which a buggy merchant may
   still misinterpret. Position A is conservative and matches the
   existing `consumer_id` validator. Recommendation: **Position A** for
   `update_cart_item`, `remove_from_cart`, `get_subscription_plan`,
   `get_subscription`, all subscription mutators (`update`, `cancel`,
   `pause`, `resume`, `report_usage`, `get_usage`,
   `update_payment_method`, `preview_proration`), `get_order`, and
   `get_product`. The typed `PlanId::new` and `SubscriptionId::new`
   already enforce this — wrap the caller-supplied strings in those
   types at the MCP entry point.
2. **What about `consumer_id` in path segments?** None of the affected
   functions put `consumer_id` in the path — it's always in the query
   string. So `consumer_id`'s existing allowlist is sufficient.
3. **`cart_id` in `get_cart`** routes through query string and is
   correctly percent-encoded by `build_url_with_query`. Not affected.
4. **Should `compose_request_url` reject `..` defensively?** Even with
   FR-1 in place, a future code path that bypasses the tool layer (e.g.
   tests, library users calling `execute_tap_request_with_acro`
   directly) would still slip through. Adding `..` rejection to
   `compose_request_url` is one-line defense-in-depth.

[NEEDS CLARIFICATION: confirm with TAP spec authors whether merchant ids
are required to be ASCII-safe, or whether the bridge should percent-encode
to support arbitrary id syntax.]

## Reproduction / Evidence

`adversarial-ids` harness (`.local/testing/scratch/src/adversarial_ids.rs`)
output, cycle 13:

```
=== adversarial-ids: probe id-field handling in URL paths ===

--- 1. update_cart_item item_id="../../admin" ---
  wire path: "/admin"
  signed @path snippet: "/admin"
[FAIL] path-traversal succeeded: original /cart/items/X became "/admin"

--- 7. systemic path-traversal across id-fields ---
[FAIL] get_order order_id='../../admin'      → wire path "/admin"  (path-traversal succeeded)
[FAIL] get_product product_id='../../secret' → wire path "/secret" (path-traversal succeeded)
```

Source evidence:

- `tap-mcp-bridge/src/mcp/cart.rs:259` — `format!("/cart/items/{}", params.item_id)`
- `tap-mcp-bridge/src/mcp/cart.rs:307` — same for `remove_from_cart`
- `tap-mcp-bridge/src/mcp/products.rs` — `format!("/products/{}", product_id)`
- `tap-mcp-bridge/src/mcp/orders.rs` — `format!("/orders/{}", order_id)`
- `tap-mcp-bridge/src/mcp/subscriptions/tools.rs:491,624,689,755,815,872,934,979,1044,1106` — 10 sites for subscriptions
- `tap-mcp-bridge/src/mcp/http.rs:57–64` — `compose_request_url` does no normalization
- `reqwest` internally uses `url::Url::parse`, which collapses `..` segments

## See Also

- Issue (filed by Cycle 13)
- Spec 001 (`update_cart_item` and `remove_from_cart` silently dropped `cart_id`) — closed by #132. Different defect, same general theme: id-fields are insufficiently validated at the MCP entry point.
- `validate_consumer_id` (`tap-mcp-bridge/src/mcp/tools.rs:380`) and `SubscriptionId::new` / `PlanId::new` (`tap-mcp-bridge/src/mcp/subscriptions/models.rs:29, 63`) — the existing constraint shape, unused at the relevant call sites.
- RFC 9421 §2.2.6 — `@path` derived component definition.
