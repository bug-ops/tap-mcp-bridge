# Map of Content — Specifications

Living index of specs under `specs/`. Each spec corresponds to a
non-trivial finding (P0–P2 bug, enhancement, research gap) and is the source
of truth for the WHAT and WHY; `/sdd plan` artefacts capture the HOW.

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
