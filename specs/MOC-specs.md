# Map of Content — Specifications

Living index of specs under `specs/`. Two categories of spec live here:

- **Finding specs (001–011)**: each corresponds to a non-trivial finding
  (P0–P2 bug, enhancement, research gap) and is the source of truth for the
  WHAT and WHY; `/sdd plan` artefacts capture the HOW.
- **Subsystem specs (012–020)**: document the current, as-built behavior of
  each logical subsystem tracked in
  `.claude/rules/continuous-improvement.md` § Project Subsystems. They were
  authored to close a coverage gap — the finding specs are point fixes, not
  a comprehensive record of what the system does — and describe existing,
  tested code rather than proposing new work. See each subsystem spec's own
  `[!note]` callout for this framing.

## Finding Specs

| Spec | Title | Priority | Status | Discovered |
|------|-------|---------|--------|-----------|
| [001](001-cart-id-silently-dropped/spec.md) | `update_cart_item` and `remove_from_cart` silently drop required `cart_id` | P1 | Resolved (#132) | Cycle 7, 2026-05-01 |
| [002](002-json-key-ordering-regression/spec.md) | JSON object key ordering changed silently after #130 (loss of `serde_json/preserve_order`) | P2 | Resolved (#139) | Cycle 9, 2026-05-01 |
| [003](003-rate-limit-not-per-consumer/spec.md) | `process_payment_rate_limited` is process-global despite "per consumer" claim | P1 | Resolved (#141, Position A) | Cycle 11, 2026-05-01 |
| [004](004-id-fields-path-traversal/spec.md) | id-fields embedded in URL paths via `format!()` enable path-traversal across 14 tool functions | P1 | Resolved (#143, Position A + defense-in-depth) | Cycle 13, 2026-05-01 |
| [005](005-redirects-leak-tap-headers/spec.md) | HTTP redirects leak signed TAP headers and ACRO body to redirect target | P1 | Resolved (#145 + #147) | Cycle 15, 2026-05-01 |
| [006](006-incomplete-redirect-fix/spec.md) | #145 missed `mcp::tools::HTTP_CLIENT`; redirect leak persists for `browse_merchant` + `checkout_with_tap` | P1 | Resolved (#147, includes shared `tap_http_client_builder()` factory) | Cycle 16, 2026-05-01 |
| [007](007-weak-signing-keys-accepted/spec.md) | `TAP_SIGNING_KEY` validator accepts all-zero / all-ones / low-entropy seeds | P2 | Resolved (#151, all-byte-equal rejection per Position A) | Cycle 18, 2026-05-01 |
| [008](008-replay-cache-lru-eviction/spec.md) | `TapVerifier`'s LRU eviction creates a replay-protection bypass | P2 | Resolved (#155, Position B from spec) | Cycle 20, 2026-05-01 |
| [009](009-rsa-pss-signing-support/spec.md) | `tap-mcp-bridge` signs exclusively with Ed25519; official TAP reference agent also supports RSA-PSS-SHA256 | P2 | Draft | Cycle 26, 2026-08-08 |
| [010](010-ap2-x402-landscape-tracking/spec.md) | Track Google Agent Payments Protocol (AP2) and its x402 crypto-payment extension as an emerging parallel standard to Visa TAP | P4 | Open — tracking | Cycle 26, 2026-08-08 |
| [011](011-process-payment-acro-wire-contract/spec.md) | `process_payment` discards ACRO/ID-token signature; ACRO has no wire slot for any body-bearing TAP request (resolves #239) | P1 | Draft | Cycle 27, 2026-08-08 |

Note: #149 (TAP_AGENT_DIRECTORY validator gaps) had no separate spec — the issue body covered it. Closed by #152 in cycle 21.

Note: #150 (TOML validator bundle) had no separate spec — issue body covered the four validator sections. Closed by #154 in cycle 23 via shared `validate_https_url` helper + extended endpoint-path checks.

## Subsystem Specs

| Spec | Subsystem | Status | Discovered |
|------|-----------|--------|-----------|
| [012](012-tap-protocol-implementation/spec.md) | `tap` — RFC 9421 signatures, JWK/JWT, ACRO/APC | Documented (as-built) | Specs migration, 2026-08-08 |
| [013](013-jwe-encryption/spec.md) | `jwe` — RFC 7516 compact serialization for APC | Documented (as-built) | Specs migration, 2026-08-08 |
| [014](014-mcp-tool-surface/spec.md) | `mcp` — TAP operations exposed as callable tools | Documented (as-built) | Specs migration, 2026-08-08 |
| [015](015-merchant-abstraction/spec.md) | `merchant` — `MerchantApi` abstraction + TOML config | Documented (as-built) | Specs migration, 2026-08-08 |
| [016](016-transport-layer/spec.md) | `transport` — sealed HTTP transport abstraction | Documented (as-built) | Specs migration, 2026-08-08 |
| [017](017-reliability-patterns/spec.md) | `reliability` — retry with backoff, circuit breaker | Documented (as-built) | Specs migration, 2026-08-08 |
| [018](018-security-hardening/spec.md) | `security` — rate limiting, audit logging | Documented (as-built) | Specs migration, 2026-08-08 |
| [019](019-observability/spec.md) | `observability` — logging, health checks, metrics (`tap-mcp-server`) | Documented (as-built; metrics unwired) | Specs migration, 2026-08-08 |
| [020](020-tap-mcp-server-binary/spec.md) | `tap-mcp-server` — MCP stdio server binary | Documented (as-built) | Specs migration, 2026-08-08 |

No root-level BRD/SRS/NFR was added: `README.md` and `tap-mcp-bridge/src/lib.rs`'s
module-level rustdoc already cover product-level WHAT/WHY at a level judged
sufficient; a redundant BRD was not deemed to add value. Likewise, no
`constitution.md`/`TEMPLATE.md`/`ARCHITECTURE.md` was copied from sibling
projects — none of that content currently exists in this repo to migrate.
