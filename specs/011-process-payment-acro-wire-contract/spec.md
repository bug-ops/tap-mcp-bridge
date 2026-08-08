# Spec 011 — `process_payment` discards ACRO/ID-token signature; ACRO has no wire slot for any body-bearing TAP request

**Status**: Draft
**Priority**: P1 (High — matches issue #239 severity; scope is broader than originally filed)
**Type**: Bug fix / design decision (resolves the "NEEDS SPEC" flag on #239)
**Owner**: TBD
**Discovered**: Cycle 27, 2026-08-08 (CI-027 architecture audit, filed as #239; this spec broadens the finding after reading the sibling function)
**Source**: [Issue #239](https://github.com/bug-ops/tap-mcp-bridge/issues/239), [Issue #240](https://github.com/bug-ops/tap-mcp-bridge/issues/240) (shared-executor duplication), `tap-mcp-bridge/src/mcp/http.rs`, `tap-mcp-bridge/src/mcp/cart.rs`, `tap-mcp-bridge/src/mcp/tools.rs`, `tap-mcp-bridge/src/mcp/subscriptions/tools.rs`, `tap-mcp-bridge/src/tap/acro.rs`

## Problem Statement

Issue #239 reports that `execute_tap_request_with_custom_nonce`
(`tap-mcp-bridge/src/mcp/http.rs:249-312`), the sole request path used
by `process_payment`, generates a full ID token and ACRO (two Ed25519
signing operations) from caller-supplied `country_code`/`zip`/
`ip_address`/`user_agent`/`platform` fields, then discards the ACRO
with `let _ = acro;` and sends only `ProcessPaymentRequest { order_id,
apc }` — no ACRO, no fraud-context data reaches the merchant. The
issue frames this as a divergence from the "sibling" function
`execute_tap_request_with_acro`, which supposedly *does* transmit
ACRO, and asks this spec to determine whether `process_payment` should
adopt that sibling's behavior or drop the dead ACRO generation
entirely.

**Reading `execute_tap_request_with_acro` closely changes the answer.**
It does not always transmit ACRO either:

```rust
// tap-mcp-bridge/src/mcp/http.rs:189-196
let body = if let Some(req_body) = request_body {
    serde_json::to_vec(req_body)?     // ACRO computed above, never touched again
} else {
    serde_json::to_vec(&acro)?        // ACRO becomes the ENTIRE body
};
```

ACRO is only ever placed on the wire when `request_body` is `None` —
i.e. when the endpoint has no JSON payload of its own and ACRO
substitutes for it wholesale. Cross-referencing every call site:

| Caller | Method | `request_body` | ACRO transmitted? |
|---|---|---|---|
| `cart::get_cart` (`cart.rs:215`) | GET | `None::<&()>` | Yes — ACRO *is* the body |
| `subscriptions::tools` (5 GET calls, e.g. `:454`, `:504`, `:1005`) | GET | `None` | Yes — ACRO *is* the body |
| `tools::checkout_with_tap` (private variant, `tools.rs:185`) | POST | n/a — always ACRO body | Yes — no other payload exists |
| `tools::browse_merchant` (private variant, `tools.rs:255`) | GET | n/a — always ACRO body | Yes — no other payload exists |
| `cart::add_to_cart` (`cart.rs:170`) | POST | `Some(&request_body)` | **No** — ACRO generated, discarded |
| `cart::update_cart_item` (`cart.rs:267`) | PUT | `Some(&request_body)` | **No** |
| `cart::remove_from_cart` (`cart.rs:317`) | DELETE | `Some(&request_body)` | **No** |
| `subscriptions::tools` (6 POST/PUT calls, e.g. `:589`, `:639`, `:711`, `:773`, `:840`, `:899`, `:963`, `:1077`, `:1141`) | POST/PUT | `Some(&request_body)` | **No** |
| `payment::process_payment` (`http.rs:249-312`, custom-nonce variant) | POST | always `Some` (no `Option` at all) | **No** (issue #239) |

So `execute_tap_request_with_custom_nonce`'s `let _ = acro;` is not an
isolated regression from a working pattern — it is **the same code
shape and the same defect** as every `Some(request_body)` call through
`execute_tap_request_with_acro`. The only functions that actually put
ACRO on the wire are the four GET-style / no-payload calls, where ACRO
happens to be the only content available to serialize. There is no
implemented mechanism anywhere in this codebase — no header, no
wrapper body field, no `Signature-Input` component — for ACRO to
accompany a request that already carries its own JSON payload:

- `tap-mcp-bridge/src/tap/mod.rs` documents the RFC 9421 signature
  base as covering exactly `@method`, `@authority`, `@path`, and
  `content-digest` — no ACRO-related signed component exists.
- No header named `Acro`, `X-Tap-Acro`, or similar appears anywhere
  under `tap-mcp-bridge/src/` (verified by grep).
- No test in `acro.rs`, `http.rs`, `cart.rs`, or the
  `subscriptions` module exercises "ACRO alongside a body" — every
  ACRO test constructs and signs the object in isolation, never
  checks it against a transmitted request.
- No merchant TOML fixture, doc comment, or module doc in this
  project describes a wire slot for "ACRO + JSON payload" together.

This reframes the design question #239 asked. It is not "should
`process_payment` copy what its sibling does" — the sibling doesn't do
it either for any body-bearing call. The real question is: **does the
TAP wire protocol require consumer-recognition context (ACRO) to
accompany body-bearing requests at all, and if so, where does it go?**
This bridge's own implementation has never answered that question for
*any* endpoint; `process_payment` merely makes the gap most visible
because payment is the highest-stakes, most fraud-sensitive path and
its doc comment (`payment.rs:148`, "Generates TAP signature with
ACRO") explicitly promises behavior the code does not deliver.

## User Stories

### US-1: Merchant fraud/risk system relying on consumer context

AS A merchant operator running fraud/risk scoring on incoming TAP
checkout and cart-mutation requests
I WANT the consumer's declared location, IP, and device context (ACRO)
to actually reach my server on every request that carries it
SO THAT my risk engine can evaluate agent-initiated purchases with the
same contextual signal a human checkout flow would provide

**Acceptance criteria:**
```
GIVEN a caller supplies country_code/zip/ip_address/user_agent/platform
      to process_payment (or add_to_cart, update_cart_item, any other
      body-bearing TAP call)
WHEN the bridge sends the request to the merchant
THEN the merchant either receives the ACRO object on the wire (if
     Position A is adopted) or the caller is not asked to supply
     contextual data that is silently thrown away (if Position B is
     adopted) — never the current state where the data is requested,
     signed, and discarded without any signal to the caller
```

### US-2: Maintainer implementing the fix

AS A developer implementing the resolution to #239
I WANT a single, explicit wire-contract decision that covers
`process_payment` AND the systemic gap in `execute_tap_request_with_acro`
SO THAT I don't ship a `process_payment`-only patch that leaves the
identical defect live in `add_to_cart`, `update_cart_item`,
`remove_from_cart`, and every subscription mutation call

**Acceptance criteria:**
```
GIVEN this spec's recommended position (see Recommendation)
WHEN the fix lands
THEN process_payment's doc comment accurately describes what is sent,
     no Ed25519 signing operation's output is silently discarded on
     that path, and a new issue exists tracking the identical pattern
     in the other Some(request_body) call sites so the fix is not
     re-litigated per-endpoint
```

## Recommendation

**Position B — remove the dead ACRO/ID-token generation from
`process_payment`'s request path; do not attempt to invent a wire slot
for ACRO-alongside-body as part of resolving #239.**

Justification:

1. **No wire contract exists to extend.** Position A ("make
   `process_payment` transmit ACRO like its sibling does") is not
   actually available — the sibling doesn't transmit ACRO for any
   body-bearing call either. Adopting Position A for `process_payment`
   alone would require inventing a new wire mechanism (header or body
   envelope) from scratch, unvalidated against any TAP reference
   material available to this project, and would leave `add_to_cart`,
   `update_cart_item`, `remove_from_cart`, and every subscription
   mutation with the identical unaddressed gap. That is a materially
   larger design effort than #239's stated scope ("resolve the ACRO
   wire contract for `process_payment`") and belongs in its own
   `/sdd plan` cycle once a concrete TAP wire format is confirmed
   — see Open Questions.
2. **Same defect class as Spec 001.** Spec 001
   (`specs/001-cart-id-silently-dropped/spec.md`) resolved an
   analogous "field accepted, signed/validated, never reaches the
   wire" defect for `cart_id` by choosing, per-case, either to route
   the field onto the wire or to remove it and document the breaking
   change (FR-5 in that spec). The same two-option structure applies
   here, and for the reasons in point 1, the "remove it" branch is the
   correct choice for `process_payment` specifically: nothing in this
   codebase currently defines where ACRO would go on a body-bearing
   request, so there is nothing concrete to route it onto.
3. **Wasted cryptographic work compounds the case for removal, not
   extension.** Every `process_payment` call currently performs two
   Ed25519 signing operations (`generate_id_token`, `generate_acro`)
   whose output is discarded. Removing them is a pure win with zero
   behavior change to what the merchant already receives (nothing).
   Extending the wire format instead would add complexity and CPU
   cost on the payment critical path for a benefit (fraud-context
   delivery) that cannot yet be verified against merchant expectations.
4. **`ProcessPaymentParams` currently over-collects.** Requiring every
   caller to supply `country_code`, `zip`, `ip_address`, `user_agent`,
   `platform` — and signing them into an ACRO that is then thrown away
   — is worse than not collecting them: it creates a false impression
   (reinforced by the doc comment) that this data reaches the
   merchant and influences fraud scoring, when it does not. Removing
   the dead generation should also remove or clearly re-scope these
   fields (see FR-3) so the API contract matches actual behavior.
5. **This is reversible and additive-safe.** Per this project's
   pre-1.0 conventions, removing unused fields now is a documented
   breaking change (`CHANGELOG.md`), not a permanent foreclosure. If a
   future spec establishes a concrete TAP wire slot for
   ACRO-alongside-body (Position A, properly scoped across *all*
   affected call sites), `ProcessPaymentParams` can re-add the fields
   at that point with full test coverage, rather than carrying
   dead-but-signed fields indefinitely in the meantime.

This is **not** a claim that ACRO/consumer-context delivery on
body-bearing requests is unimportant — it is a claim that this
specific issue (#239) cannot responsibly resolve that question by
patching one endpoint, because the answer doesn't exist anywhere in
this codebase yet for any endpoint. See FR-5 and Open Questions for
the follow-up this spec requires.

## Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-1 | `execute_tap_request_with_custom_nonce` (`http.rs:249-312`) SHALL NOT call `signer.generate_id_token` or `signer.generate_acro` when their output is not placed on the wire. The function SHALL either transmit what it signs or not sign it. | must |
| FR-2 | `process_payment` (`payment.rs:218-274`) SHALL stop passing `contextual_data` through to the (now-corrected) executor for a purpose that discards it. If FR-5's shared executor still accepts a `contextual_data` parameter for API consistency with the ACRO-transmitting call sites, `process_payment`'s call SHALL NOT trigger ACRO generation. | must |
| FR-3 | `ProcessPaymentParams`'s `country_code`, `zip`, `ip_address`, `user_agent`, `platform` fields SHALL be removed, since nothing in the corrected code path consumes them. This is a breaking change; document it in `CHANGELOG.md` `[Unreleased]` per project convention. | must |
| FR-4 | The doc comment on `process_payment` (currently: "2. Generates TAP signature with ACRO") SHALL be corrected to describe actual behavior: TAP signature generation without ACRO for this endpoint. | must |
| FR-5 | A new issue SHALL be filed (referencing this spec, #239, and #240) covering the identical `let _ = acro`-equivalent pattern present in every `Some(request_body)` call to `execute_tap_request_with_acro` (`add_to_cart`, `update_cart_item`, `remove_from_cart`, and the 8+ subscription mutation calls enumerated in the Problem Statement table). That issue SHOULD propose either (a) stop generating ACRO for those calls too (mirroring this spec's Position B), or (b) a proper `/sdd specify` + `/sdd plan` cycle to design a real ACRO-alongside-body wire mechanism, validated against TAP reference material, applied uniformly across all affected endpoints — not decided ad hoc per call site. | must |
| FR-6 | Existing regression test coverage for `process_payment` (`payment.rs` `#[cfg(test)]` module) MUST be extended to assert that no ACRO-shaped signing side effect occurs (e.g. via a spy/mock signer or an integration test asserting the transmitted body is exactly `ProcessPaymentRequest`, no more) — mirroring how Spec 001 required a wire-level regression test for its equivalent fix. | must |
| FR-7 | The shared-executor refactor tracked by issue #240 SHOULD incorporate this spec's fix directly (i.e. do not implement FR-1/FR-2 in the current duplicated `execute_tap_request_with_custom_nonce`, then redo the same edit when #240's deduplication lands) if #240 is scheduled for the same development cycle. If #240 is not imminent, implement FR-1/FR-2 in the existing function as-is; #240 remains a separate, independently valuable cleanup. | should |

## Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-1 | Performance | Removing the two discarded Ed25519 signing operations per `process_payment` call reduces CPU cost on the payment critical path. No new NFR beyond "do not regress this" — the fix is a straightforward removal. |
| NFR-2 | Compatibility | Pre-1.0 breaking change (FR-3's field removal) — no deprecation shim; record in `CHANGELOG.md` `[Unreleased]` per project convention (`CLAUDE.md`, `.claude/rules/branching.md`). |
| NFR-3 | Documentation | If `tap-mcp-server`'s MCP tool schema for `checkout_with_tap`/payment tooling documents these fields externally (README, tool `inputSchema`), it MUST be updated to match `ProcessPaymentParams`'s corrected shape (`.claude/rules/branching.md`: "If touching MCP tool surface, update `tap-mcp-server` README/docs"). |
| NFR-4 | Cross-interface consistency | Per `.claude/rules/continuous-improvement.md`, any change to ACRO/APC/ID-token generation logic must be exercised through both a library example and the `tap-mcp-server` MCP tool path — verify `process_payment`'s example (`payment.rs` doc-test, `basic_checkout`/`full_checkout_flow` examples if they exercise payment) still compiles and runs after FR-3's field removal. |
| NFR-5 | Security | This fix has no negative security impact: it removes signing operations whose output was never transmitted, so no signature or replay-protection guarantee weakens. It does, however, mean `process_payment` sends strictly less consumer-context data to the merchant than the (never-functional) doc comment implied — flag this in the CHANGELOG as a behavioral clarification, not a regression, since the data never reached the merchant either way. |

## Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| Existing caller code still populates the now-removed `country_code`/`zip`/`ip_address`/`user_agent`/`platform` fields on `ProcessPaymentParams` | Compile error (struct field removed) — correct pre-1.0 behavior per project convention; document migration in `CHANGELOG.md` |
| `execute_tap_request_with_custom_nonce` is reused by a future caller that *does* want ACRO transmitted | Not supported by this spec's fix (FR-1 removes ACRO generation unconditionally from this function). If a future endpoint needs ACRO-alongside-body, it must go through the FR-5 follow-up issue's proper design, not silently reintroduce the discard-prone pattern here |
| `execute_tap_request_with_acro`'s existing `Some(request_body)` call sites (`add_to_cart`, etc.) | Explicitly out of scope for this spec's implementation (tracked separately per FR-5); do not touch as part of resolving #239 to keep the PR reviewable and scoped |
| A future TAP spec revision defines exactly where ACRO belongs on a body-bearing request | Re-open via the FR-5 follow-up issue; this spec's Position B is not permanent, it is the correct choice given the *current* absence of any implemented or documented wire slot |

## Agent Boundaries

### Always (without asking)
- Read `tap-mcp-bridge/src/mcp/http.rs`, `payment.rs` fully before editing, to avoid re-breaking the `Some`/`None` branch structure shared with `execute_tap_request_with_acro`
- Update `CHANGELOG.md` `[Unreleased]` for the `ProcessPaymentParams` breaking change (FR-3)
- Run the full local check suite (`cargo make pre-commit` or the direct cargo equivalents) before considering the fix complete

### Ask First
- Extending this fix to also remove ACRO generation from `execute_tap_request_with_acro`'s `Some(request_body)` call sites — that is FR-5's separate issue, not this spec's implementation scope, even though the code shape is identical
- Any decision to instead pursue Position A (invent an ACRO-alongside-body wire mechanism) — that requires new TAP reference material this spec did not have access to, and a dedicated `/sdd specify` cycle

### Never
- Ship a `process_payment`-only fix while leaving its doc comment inaccurate, or vice versa (doc comment and code must be corrected together, per FR-4)
- Silently drop the `ProcessPaymentParams` fields without a `CHANGELOG.md` entry — this is a breaking API change

## Open Questions

- `[NEEDS CLARIFICATION: is there authoritative TAP specification text (beyond what's referenced in this codebase's module docs) that defines a header or body-envelope mechanism for ACRO to accompany a request that already carries its own JSON payload? This spec's recommendation (Position B) is contingent on no such mechanism being currently implementable in this codebase; if TAP reference material surfaces one, Position A should be revisited via a new spec scoped across all affected endpoints, not just process_payment.]`
- `[NEEDS CLARIFICATION: does removing consumer-context collection from process_payment reduce this bridge's fraud-prevention posture in a way that matters to a specific merchant integration, or is APC (Agentic Payment Container) alone considered sufficient for payment-stage authentication, with ACRO reserved for browse/cart-context establishment only? If the latter, this strengthens Position B further — ACRO may be architecturally scoped to browse/read interactions by design, not merely by implementation gap.]`
- `[NEEDS CLARIFICATION: should the FR-5 follow-up issue be filed as part of this spec's closure, or deferred until #240's shared-executor refactor is scheduled, since fixing the Some(request_body) call sites likely touches the same executor code #240 targets?]`

## See Also

- [Issue #239](https://github.com/bug-ops/tap-mcp-bridge/issues/239) — original finding this spec resolves
- [Issue #240](https://github.com/bug-ops/tap-mcp-bridge/issues/240) — near-duplicate executor logic; FR-7 recommends coordinating implementation order
- Spec 001 (`specs/001-cart-id-silently-dropped/spec.md`) — precedent for the "route it onto the wire, or remove it and document the breaking change" decision structure applied here
- `tap-mcp-bridge/src/mcp/http.rs:150-312` — `execute_tap_request_with_acro` and `execute_tap_request_with_custom_nonce`, both examined for this spec
- `tap-mcp-bridge/src/mcp/payment.rs:218-274` — `process_payment`, the fix target
- `tap-mcp-bridge/src/mcp/cart.rs:150-330` — `add_to_cart`/`update_cart_item`/`remove_from_cart`, cited as evidence of the systemic `Some(request_body)` discard pattern (FR-5 scope, not this spec's implementation scope)
- `tap-mcp-bridge/src/mcp/subscriptions/tools.rs` — additional `Some(request_body)` call sites with the same pattern (FR-5 scope)
- `tap-mcp-bridge/src/tap/acro.rs` — `Acro`/`ContextualData`/`DeviceData` definitions and module docs (no header/body-envelope mechanism documented)
- `.claude/rules/continuous-improvement.md` — cross-interface consistency requirement (NFR-4)
