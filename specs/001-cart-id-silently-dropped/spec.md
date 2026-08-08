# Spec 001 — `update_cart_item` and `remove_from_cart` silently drop required `cart_id`

**Status**: Draft
**Priority**: P1 (High)
**Type**: Bug fix
**Owner**: TBD
**Discovered**: 2026-05-01, Cycle 7 live testing, master @ 9aa61b3
**Source**: live-test harness `.local/testing/scratch/src/wire_drive.rs`

## Problem Statement

Two MCP tools — `update_cart_item` and `remove_from_cart` — accept `cart_id` as a
**required** parameter in both their library `Params` struct and the MCP
`tools/list` schema, but the library implementations **never read the field
when constructing the outbound HTTP request**. As a result:

- A merchant receiving the request has no way to know which cart context
  applies, breaking the multi-cart-per-consumer semantics.
- The MCP API contract is violated: clients are required to supply a value
  that is silently discarded — they have no way to detect that this happened.
- Symmetric tools (`add_to_cart`, `get_cart`) correctly transmit `cart_id`.
  The asymmetry is a latent contract bug, not a deliberate design choice.

## User Stories

- **As a TAP-MCP client developer** building an agent that maintains multiple
  shopping carts per consumer, I need `update_cart_item` and `remove_from_cart`
  to operate on the cart I specify so that operations on cart A do not
  accidentally affect cart B.
- **As a merchant API operator**, I need the request to disambiguate between
  carts so that my server can route the operation correctly without inventing
  state inference (e.g. "most recent cart").
- **As a security reviewer**, I need declared required parameters to actually
  reach the wire, otherwise the schema is misleading and review is unsound.

## Functional Requirements

**FR-1**: When a caller invokes `update_cart_item` with a `cart_id` value,
that value MUST be present in the outbound HTTP request in at least one of:
URL path, query string, or request body.

**FR-2**: When a caller invokes `remove_from_cart` with a `cart_id` value,
that value MUST be present in the outbound HTTP request in at least one of:
URL path, query string, or request body.

**FR-3**: The `cart_id` placement chosen for FR-1 and FR-2 SHOULD be
consistent with the project's existing convention: `add_to_cart` uses the
request body; `get_cart` uses the query string. The chosen placement should
match one of these or be documented as a deliberate departure.

**FR-4**: The RFC 9421 `@path` signature component MUST cover the chosen
placement so that a man-in-the-middle cannot rewrite `cart_id` in transit
without invalidating the signature. (Path/query are already covered by
`@path`; a body placement is covered by `Content-Digest`.)

**FR-5**: If, after design review, `cart_id` is determined to be unnecessary
for these endpoints (i.e. the merchant API is item-id-keyed and cart context
is implicit), the `cart_id` field MUST be removed from `UpdateCartItemParams`,
`RemoveFromCartParams`, and the MCP tool schemas, with a CHANGELOG entry
documenting the breaking change.

## Non-Functional Requirements

- **Backwards compatibility**: pre-1.0 — breaking changes are allowed, must
  be recorded in `CHANGELOG.md` `[Unreleased]`.
- **Test coverage**: a regression test in `tap-mcp-bridge/src/mcp/cart.rs`
  must assert that `cart_id` reaches the wire (or is absent if FR-5 is taken).
  The wiremock harness at `.local/testing/scratch/src/wire_drive.rs` already
  covers this and should keep producing zero anomalies after the fix.
- **Documentation**: the doc comment for both functions must describe where
  on the wire `cart_id` lands.

## Design Choices (Open Questions for /sdd plan)

The HOW belongs in a follow-up `/sdd plan` session; the spec captures the
candidate placements:

1. **Path-segment style**: `PUT /cart/{cart_id}/items/{item_id}` and
   `DELETE /cart/{cart_id}/items/{item_id}`. RESTful, consistent with how a
   merchant might expose nested resources. Covered by `@path` automatically.
2. **Query-parameter style**: `PUT /cart/items/{item_id}?cart_id=…&consumer_id=…`
   (analogous to `get_cart`). Minimal change to existing path. Covered by
   `@path` (query is part of the request target per RFC 9421 §2.2.6).
3. **Body style** (PUT only): extend `UpdateCartItemRequest` to include
   `cart_id`. Asymmetric for DELETE since DELETE has no body convention.
4. **Drop the field** (FR-5): if the merchant API treats `item_id` as
   globally unique, `cart_id` is genuinely redundant. Risk: ambiguity if a
   future merchant has overlapping item IDs across carts.

[NEEDS CLARIFICATION: which placement matches the merchant API convention
this bridge is designed against (TAP spec or VISA reference implementations)?]

## Reproduction / Evidence

Cycle 7 wiremock harness output (full log: `.local/testing/debug/cycle7/wire_drive.log`):

```
[ANOMALY] update_cart_item: required cart_id NOT present anywhere on the wire
  (path="/cart/items/I1", query="consumer_id=user-1", body=14 bytes)
[ANOMALY] remove_from_cart: required cart_id NOT present anywhere on the wire
  (path="/cart/items/I1", query="consumer_id=user-1", body=750 bytes)
```

The 14-byte PUT body is `UpdateCartItemRequest { quantity: 3 }` (JSON: about
`{"quantity":3}`), no cart_id field exists. The 750-byte DELETE body is the
ACRO envelope, which carries no cart_id either.

Static reference points:
- `tap-mcp-bridge/src/mcp/cart.rs:80` — `UpdateCartItemParams.cart_id: String`
- `tap-mcp-bridge/src/mcp/cart.rs:107` — `RemoveFromCartParams.cart_id: String`
- `tap-mcp-bridge/src/mcp/cart.rs:241-283` — `update_cart_item` impl, no `cart_id` reference
- `tap-mcp-bridge/src/mcp/cart.rs:291-331` — `remove_from_cart` impl, no `cart_id` reference
- `tap-mcp-bridge/src/mcp/cart.rs:135-139` — `UpdateCartItemRequest` body struct, no `cart_id` field

## See Also

- Issue (filed by Cycle 7 with link back to this spec)
- `add_to_cart` / `get_cart` for the existing patterns
- TAP spec sections covering merchant cart semantics (if applicable)
