# Spec 005 — HTTP redirects leak signed TAP headers and ACRO body to redirect target

**Status**: Draft
**Priority**: P1 (Bug — security exposure: signed credentials + PII forwarded to non-merchant hosts)
**Type**: Bug fix (HTTP client configuration)
**Owner**: TBD
**Discovered**: 2026-05-01, Cycle 15 live testing, master @ 19bb549
**Source**: `.local/testing/scratch/src/redirect_probe.rs`

## Problem Statement

None of the bridge's three `reqwest::Client::builder()` call sites set a
`redirect()` policy. `reqwest`'s default is `Policy::limited(10)` — follow
up to 10 redirects automatically. For 307/308 the original method and
body are preserved; for 301/302/303 the method is downgraded to GET and
the body is dropped. In **all** cases, only the four "sensitive" headers
(`Authorization`, `Cookie`, `Proxy-Authorization`, `Cookie2`) are
stripped on cross-host redirects. TAP-specific headers
(`Signature`, `Signature-Input`, `Signature-Agent`, `Content-Digest`)
are NOT in reqwest's strip list — they are forwarded verbatim.

A malicious or compromised merchant (or DNS-spoofed merchant, or
merchant under MITM) can therefore use a 30x response to redirect the
agent to an attacker-controlled host and capture:

- The Ed25519 `Signature` (proof of agent identity, bound to the
  signed `@path`).
- The signed components in `Signature-Input` (revealing the agent's
  intent).
- The agent's `Signature-Agent` directory URL.
- The `Content-Digest` (binds the body to the signature).
- For 307/308: the **full request body**.
  - For ACRO requests: contains `country_code`, `zip`, `ip_address`,
    `user_agent`, `platform` — PII tied to the consumer_id.
  - For APC requests: contains the RSA-OAEP / AES-GCM encrypted
    ciphertext (cannot be decrypted by the attacker without the
    merchant's private RSA key, but timing/size/replay correlation
    possible).

The defect is **systemic** across all three HTTP clients in the
workspace:

| Client | File | Used by |
|---|---|---|
| `create_http_client()` | `tap-mcp-bridge/src/mcp/http.rs:76-83` | every e-commerce tool (browse, checkout, products, cart, orders, payment) |
| `SUBSCRIPTION_HTTP_CLIENT` | `tap-mcp-bridge/src/mcp/subscriptions/tools.rs:33-40` | every subscription tool |
| `DEFAULT_HTTP_CLIENT` | `tap-mcp-bridge/src/transport/http/mod.rs:23-30` | the public `transport::http::HttpTransport` |

## User Stories

- **As a TAP agent operator** I expect that signed credentials are sent
  ONLY to the registered merchant. If the merchant returns a 30x, that
  is either a misconfiguration (which I want to surface as an error) or
  a compromise attempt (which I want to refuse outright). Silently
  forwarding the signature to a redirect target is neither.
- **As a security reviewer** I expect signed credentials to be
  point-to-point, not transitive across HTTP redirects. The TAP
  protocol does not contemplate redirect-following at the agent layer;
  any redirect handling should be a deliberate caller decision, not
  silent reqwest default behavior.
- **As a downstream library consumer** I expect that the bridge's
  HTTP client is hardened against the cross-host header-leak class of
  attacks. Authorization-style headers (which TAP signatures
  effectively are) must not flow across host boundaries.

## Functional Requirements

**FR-1**: The three HTTP clients
(`create_http_client`, `SUBSCRIPTION_HTTP_CLIENT`, `DEFAULT_HTTP_CLIENT`)
MUST disable redirect following by default. The recommended
configuration is `.redirect(reqwest::redirect::Policy::none())`. Any
30x response from the merchant MUST surface as a `BridgeError` rather
than be silently followed.

**FR-2**: If a future feature requires redirect-aware behavior, it MUST
use a custom `Policy::custom(...)` that:
  - Requires the redirect target's host to match the signed `@authority`
    (i.e. follow only same-host redirects).
  - Strips all four TAP headers AND `Content-Digest` before re-issuing
    the request.
  - Re-signs the request with the new `@path` / `@authority` (since
    the agent's intent has effectively changed — different URL is a
    different request under RFC 9421).
  - Bounds total hops more conservatively than the default 10.

**FR-3**: A regression test MUST exist asserting that a merchant
returning 307 to a different host produces a `BridgeError` and that
no follow-up request is issued. The `redirect-probe` harness in
`.local/testing/scratch/` already encodes this check.

**FR-4**: The error message returned for a refused redirect MUST be
distinguishable from generic transport errors so callers can implement
their own redirect policy at a higher layer if their use case requires
it.

## Non-Functional Requirements

- **Performance**: redirect-disabling is a one-line configuration with
  no performance impact.
- **Backward compatibility**: pre-1.0 — any caller currently relying
  on the bridge auto-following 30x will start receiving errors. This
  is a security-positive breaking change. CHANGELOG entry under
  `[Unreleased] / Fixed` with an explicit "BREAKING" callout for
  callers that depend on the old behavior.
- **Documentation**: every `Client::builder()` call site needs an
  inline comment documenting why redirect-following is disabled
  (cross-reference RFC 9421 §1: signatures are bound to the request,
  redirect = different request).
- **Security**: this is a defense-in-depth addition. The bridge already
  enforces HTTPS-only (modulo `TAP_ALLOW_LOOPBACK` for tests) and
  rejects loopback hosts. Disabling redirect-following closes the gap
  where a TAP-signed request can leave the merchant's authority.

## Design Choices (Open Questions for /sdd plan)

1. **Position A — `Policy::none()`**: refuse all redirects. Simplest,
   most conservative. Recommended.
2. **Position B — `Policy::custom()` with same-host check**: allow
   redirects only if the new host equals the original. Useful if
   merchants legitimately use redirects (e.g. `/checkout` → `/checkout/`
   trailing-slash normalization, or HTTP-to-HTTPS upgrade — though
   HTTP is already rejected by `parse_merchant_url`). Risk: fragile to
   `vhost` setups, CDN tricks, or load balancer hostnames.
3. **Position C — `Policy::custom()` that re-signs**: auto-detect a
   safe redirect target, strip TAP headers, re-sign. Most flexible but
   complex; agent identity flows through redirect chain which is hard
   to reason about.

[NEEDS CLARIFICATION: TAP spec position on agent following redirects.
RFC 9421 §1 says signatures are bound to the request; redirect = new
request → re-sign or refuse. The TAP draft probably defers to the
RFC.]

Recommendation: **Position A** (`Policy::none()`). If a real merchant
emits 30x in normal operation, the operator can patch their merchant
config or escalate via a feature request — that's a clearer signal than
silent header leakage.

## Reproduction / Evidence

`redirect-probe` harness output, cycle 15:

```
[test-307]
  merchant received: 1 request(s)
  attacker received: 1 request(s)
[!] redirect WAS followed — checking what leaked to attacker
    Path on attacker side:        /admin/exfil
    Signature header forwarded:   true
    Signature-Input forwarded:    true
    Signature-Agent forwarded:    true
    Content-Digest forwarded:     true
    Body size at attacker:        766 bytes
    Body carries ACRO PII fields: true

[test-302]
    Signature header forwarded: true

[test-chain]
  merchant served 11 requests in the chain
[ok] redirect chain bounded (11≤11)
  result: Err — TooManyRedirects
```

Source evidence:

- `tap-mcp-bridge/src/mcp/http.rs:76-83` — `create_http_client()`,
  no `.redirect(...)` configured
- `tap-mcp-bridge/src/mcp/subscriptions/tools.rs:33-40` —
  `SUBSCRIPTION_HTTP_CLIENT`, no `.redirect(...)` configured
- `tap-mcp-bridge/src/transport/http/mod.rs:23-30` —
  `DEFAULT_HTTP_CLIENT`, no `.redirect(...)` configured

`reqwest` default `Policy::limited(10)` follows up to 10 redirects;
TAP-specific headers (`Signature`, `Signature-Input`, `Signature-Agent`,
`Content-Digest`) are not in reqwest's auto-strip list (only
`Authorization`, `Cookie`, `Proxy-Authorization`, `Cookie2`).

## See Also

- Issue (filed by Cycle 15)
- Spec 004 (path-traversal in id-fields) — different defect, same
  general theme: the bridge's HTTP layer needs hardening against
  attacker-controlled inputs.
- RFC 9421 §1 — HTTP Message Signatures bind a signature to a specific
  request; redirected requests are different requests.
- reqwest docs on `redirect::Policy` — sensitive-header strip list.
