# Spec 010 — Track Google Agent Payments Protocol (AP2) and its x402 crypto-payment extension as an emerging parallel standard to Visa TAP

**Status**: Draft
**Priority**: P4 (Nice-to-have — awareness/tracking item, no urgency, not an active gap)
**Type**: Research finding — competitive landscape / ecosystem evolution
**Owner**: TBD
**Discovered**: Cycle 26, 2026-08-08
**Source**: [AP2 protocol site](https://ap2-protocol.org/), [Google Cloud announcement](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol), [x402 security analysis (arXiv)](https://arxiv.org/pdf/2605.30998)

## Problem Statement

`tap-mcp-bridge` bridges Visa's Trusted Agent Protocol (TAP) with MCP,
and its entire signing/verification stack (RFC 9421 HTTP message
signatures, ACRO/APC payloads, JWK thumbprints) is built exclusively
around TAP's agent-identity/bot-detection model.

As of 2026, a second major agent-payments standard has emerged with
significant multi-vendor backing: Google's **Agent Payments Protocol
(AP2)**, currently at v0.2 (April 2026). AP2 differs from TAP in scope
and mechanism:

- **Payment-rail-agnostic**: AP2 covers cards, bank transfers, and
  stablecoins, whereas TAP is scoped to agent-identity assertions at
  the HTTP transaction layer for existing card-network checkout flows.
- **Mandate-based authorization**: AP2 uses cryptographically signed
  "mandates" (intent/cart/payment mandate objects) as its core
  authorization primitive, rather than TAP's RFC 9421 HTTP message
  signatures over individual requests.
- **x402 extension**: built with Coinbase, the Ethereum Foundation, and
  MetaMask, targeting crypto-native/stablecoin agent payments. x402 has
  already been natively integrated by Google AP2, Cloudflare Agents,
  Stripe, and AWS Bedrock — indicating broader ecosystem pull than a
  single-vendor experiment.

TAP and AP2 are not inherently incompatible — TAP answers "is this
request really coming from a trusted, verifiable agent?" at the HTTP
layer, while AP2 answers "is this payment authorized, and by whom?" at
the transaction-mandate layer. In principle a merchant could require
both for the same checkout flow. However, `tap-mcp-bridge` today has
**no protocol abstraction boundary** between "TAP-the-transport-and-
identity-layer" and "TAP-the-only-supported-payment-authorization-
model" — the bridge's `MerchantApi` trait, tool surface, and signing
stack all assume TAP end-to-end.

If AP2/x402 adoption continues to grow among merchants and MCP-based
commerce tooling — particularly given the multi-vendor backing (Google,
Coinbase, Ethereum Foundation, MetaMask, Cloudflare, Stripe, AWS) — this
project's exclusive TAP focus becomes a merchant-coverage limitation:
agents built on `tap-mcp-bridge` cannot reach merchants that require or
prefer AP2 mandates or x402 stablecoin settlement, regardless of
whether those merchants also support TAP.

This spec captures the landscape signal and the shape of a possible
future gap. It is explicitly **not** a commitment to implement AP2/x402
support, and does not prescribe a design — that decision belongs to a
later `/sdd plan` cycle, contingent on continued adoption evidence.

## User Stories

### US-1: Agent operator wanting to reach AP2/x402-only merchants

AS A TAP agent operator deploying `tap-mcp-server`
I WANT to know whether the bridge can (now or via a future extension)
transact with merchants that only accept AP2 mandates or x402
stablecoin payments
SO THAT I can decide whether `tap-mcp-bridge` alone covers my target
merchant set, or whether I need a separate integration path for
AP2/x402-only storefronts

**Acceptance criteria:**
```
GIVEN an agent operator evaluating tap-mcp-bridge against a merchant
      that advertises AP2 mandate support (with or without x402)
      but does not implement TAP
WHEN the operator checks this project's documented protocol coverage
THEN the operator finds an explicit statement that AP2/x402 is not
     currently supported, tracked as a known landscape gap, distinct
     from a silent capability hole
```

### US-2: Maintainer deciding whether to prioritize AP2/x402 work

AS A maintainer planning future `tap-mcp-bridge` work
I WANT a standing, low-noise record of AP2/x402 adoption signals
SO THAT a future decision to add parallel protocol support is made
from accumulated evidence (merchant demand, ecosystem integrations)
rather than from a cold start

**Acceptance criteria:**
```
GIVEN this spec exists as a tracking record
WHEN a future research cycle re-evaluates AP2/x402 adoption
THEN the cycle can update this spec (or supersede it with a new one)
     with fresh evidence instead of re-deriving the landscape from
     scratch
```

## Functional Requirements

These are intentionally high-level and conditional — they describe
what a *future* integration would need to consider IF the project ever
takes on AP2/x402 support. None of them are committed scope for this
spec.

| ID | Requirement | Priority |
|----|------------|----------|
| FR-1 | IF AP2/x402 support is ever undertaken, THE SYSTEM MAY expose a pluggable payment-protocol abstraction (distinct from the current TAP-specific `MerchantApi`/signing stack) so that TAP and AP2 code paths do not entangle | could |
| FR-2 | IF AP2/x402 support is ever undertaken, THE SYSTEM SHALL treat AP2 mandate signing/verification as an additive capability that does not alter existing TAP request/response formats or the default TAP-only code path | must (conditional) |
| FR-3 | THE SYSTEM SHALL NOT require any AP2/x402-related change as part of this spec; this spec's only mandatory deliverable is the tracking record itself | must |
| FR-4 | WHEN a future research cycle finds material new AP2/x402 adoption evidence (e.g. named merchant integrations, MCP-ecosystem tooling adopting AP2/x402, TAP-AP2 interop guidance from Visa or Google), THE SYSTEM's spec set SHOULD be updated (this spec revised, or a new spec filed referencing it) rather than the signal being dropped | should |

## Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-1 | Security | IF AP2/x402 support is ever undertaken, it MUST NOT compromise the existing TAP security posture (RFC 9421 signature integrity, replay-protection nonce cache per Spec 008, HTTPS enforcement, loopback/path-traversal/CRLF blocking). Any shared transport code between TAP and AP2 paths must preserve today's security invariants for TAP traffic unchanged. |
| NFR-2 | Security | The x402 extension has a documented security analysis — ["Free-Riding the Agentic Web: A Systematic Security Analysis of x402 Payments"](https://arxiv.org/pdf/2605.30998) — that catalogs known pitfalls in x402-style payment flows. This MUST be reviewed before any x402 implementation work begins, not treated as optional background reading. |
| NFR-3 | Compatibility | Any future AP2/x402 work MUST be additive: existing TAP-only deployments, merchant TOML configs, and the current MCP tool surface (`checkout_with_tap`, `browse_merchant`, `get_products`, etc.) must continue to function unchanged. |
| NFR-4 | Maintainability | This tracking spec SHOULD be revisited on a defined cadence (e.g. each landscape-scanning research cycle, per `.claude/rules/continuous-improvement.md`) rather than left stale indefinitely, given standards in this space are evolving quickly (AP2 was at v0.2 as of April 2026). |

## Edge Cases and Error Handling

Not applicable in the traditional sense — this is a landscape-tracking
spec with no implementation. The table below instead captures decision
triggers for escalating this from "tracked" to "actionable":

| Scenario | Expected Handling |
|----------|--------------------|
| A specific merchant integration `tap-mcp-bridge` is targeting requires AP2/x402 and has no TAP fallback | Escalate this spec's priority (P4 → higher) and file a follow-up `/sdd specify` scoped to that concrete merchant requirement, rather than expanding this landscape spec |
| AP2 or x402 specification changes materially (e.g. AP2 reaches v1.0, or TAP publishes explicit AP2 interop guidance) | Update this spec's Problem Statement and re-check the "not an active incompatibility" framing |
| No further adoption signal appears over multiple research cycles | Leave as-is; do not escalate priority without new evidence |

## Agent Boundaries

### Always (without asking)
- Treat this spec as informational/tracking only — no code changes are implied or required by its existence

### Ask First
- Starting any implementation work toward AP2/x402 support (this would require a dedicated `/sdd specify` + `/sdd plan` cycle with explicit scope, not an extension of this tracking spec)

### Never
- Infer authorization to add AP2/x402 dependencies, new signing algorithms, or protocol abstractions from this spec alone
- Treat FR-1/FR-2 (MAY/conditional requirements) as committed deliverables

## Open Questions

- `[NEEDS CLARIFICATION: does the project want a recurring "protocol landscape watch" item in the continuous-improvement cycle (per .claude/rules/continuous-improvement.md's "Reference Projects" section), or is a one-off spec update sufficient when new evidence appears?]`
- `[NEEDS CLARIFICATION: is there a specific merchant or MCP-ecosystem partner currently requesting AP2/x402 support, or is this purely proactive landscape awareness?]`
- `[NEEDS CLARIFICATION: should Visa's TAP roadmap (if any public signal exists) addressing AP2 interoperability be tracked separately, since that would reduce the urgency of a bridge-side dual-protocol implementation?]`

## See Also

- [AP2 protocol documentation](https://ap2-protocol.org/) — protocol overview, mandate model, v0.2 spec
- [Google Cloud: Announcing Agents to Payments (AP2) Protocol](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol) — vendor announcement and ecosystem backing
- [Free-Riding the Agentic Web: A Systematic Security Analysis of x402 Payments (arXiv)](https://arxiv.org/pdf/2605.30998) — required reading before any x402 implementation work (NFR-2)
- Spec 009 (`specs/009-rsa-pss-signing-support/spec.md`) — prior algorithm-parity research finding against the TAP reference implementation; same "capture what/why, defer how to `/sdd plan`" pattern
- `tap-mcp-bridge/src/lib.rs` — current TAP-only architecture entry point; would be the anchor point for any future protocol abstraction (FR-1)
