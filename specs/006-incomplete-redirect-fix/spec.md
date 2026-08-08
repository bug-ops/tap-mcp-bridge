# Spec 006 — #145 missed `mcp::tools::HTTP_CLIENT`; redirect leak persists for `browse_merchant` and `checkout_with_tap`

**Status**: Draft
**Priority**: P1 (Bug — same security exposure as #144 still active for two MCP tools)
**Type**: Bug fix (one-line addition)
**Owner**: TBD
**Discovered**: 2026-05-01, Cycle 16 live testing, master @ 035e635
**Source**: `.local/testing/scratch/src/redirect_probe.rs` (cycle 15 harness, re-run cycle 16)

## Problem Statement

PR #145 (closes #144) added
`.redirect(reqwest::redirect::Policy::none())` to four
`reqwest::Client::builder()` call sites:

- `tap-mcp-bridge/src/mcp/http.rs:86` (`create_http_client`)
- `tap-mcp-bridge/src/mcp/subscriptions/tools.rs:38` (`SUBSCRIPTION_HTTP_CLIENT`)
- `tap-mcp-bridge/src/transport/http/mod.rs:28` (`DEFAULT_HTTP_CLIENT`)
- `tap-mcp-bridge/src/transport/http/mod.rs:175` (`HttpTransport::with_config`)

A **fifth** call site was missed: `tap-mcp-bridge/src/mcp/tools.rs:37`,
the `HTTP_CLIENT: LazyLock<Client>` static that backs the private
`execute_tap_request_with_acro` helper inside `mcp::tools`. This helper
is called from `checkout_with_tap` (line 164) and `browse_merchant`
(line 234) — the **two original e-commerce MCP tools** registered in
`tap-mcp-server`.

As a result, `tools/call browse_merchant` and `tools/call checkout_with_tap`
through the MCP server still:

- Follow merchant 30x responses (up to reqwest's default `Policy::limited(10)`).
- Forward all four TAP signature headers (`Signature`, `Signature-Input`,
  `Signature-Agent`, `Content-Digest`) to the redirect target.
- For 307/308: forward the unencrypted ACRO body (consumer PII:
  `country_code`, `zip`, `ip_address`, `user_agent`, `platform`)
  to the redirect target.

The attack surface from #144 is unchanged for these two tools. The
other 12 MCP tools (the e-commerce expansion in #125 and the 12
subscription functions) ARE fixed because they go through `mcp::http`
or `mcp::subscriptions::tools` clients — both correctly patched.

## User Stories

- **As a TAP agent operator** I expect that when an upstream PR closes
  a security issue, the fix covers all relevant code paths, not a
  subset. The CHANGELOG entry for #145 says "all reqwest clients" but
  one was missed.
- **As a security reviewer** I expect a `grep -rn 'Client::builder()'`
  to be part of the verification of any redirect-policy fix. Cycle 16's
  re-run of `redirect-probe` immediately surfaced the gap.

## Functional Requirements

**FR-1**: Add `.redirect(reqwest::redirect::Policy::none())` to the
`Client::builder()` chain at `tap-mcp-bridge/src/mcp/tools.rs:37`.
The chain currently reads:

```rust
Client::builder()
    .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
    .pool_max_idle_per_host(100)
    .http2_prior_knowledge()
    .build()
    .expect("failed to create HTTP client")
```

Insert `.redirect(reqwest::redirect::Policy::none())` before `.build()`.

**FR-2**: A regression test MUST exist in `mcp/tools.rs` (or its `mod
tests`) asserting that `HTTP_CLIENT` does not follow redirects, mirroring
the existing `test_create_http_client_does_not_follow_redirects` in
`mcp/http.rs:372`. Without this test, the next refactor that adds yet
another client constructor risks the same omission.

**FR-3**: Update `regressions.md` permanent gates to require all 5+
`Client::builder()` call sites to call `.redirect(...)` — the live
tester should `grep -rn 'Client::builder()' tap-mcp-bridge/src/ |
xargs grep -L 'redirect'` after any HTTP-client touching PR. Currently
this is encoded in `redirect-probe`, which exercises the
`browse_merchant` path; if the harness ever stops covering this exact
path, the gap returns.

## Non-Functional Requirements

- **Performance**: zero impact (same as #145).
- **Backward compatibility**: matches the security-positive breaking
  change introduced in #145 — `tools/call browse_merchant` and
  `tools/call checkout_with_tap` will start refusing 30x responses.
  CHANGELOG entry under `[Unreleased] / Fixed` referencing both #144
  and the follow-up.
- **Documentation**: copy the doc-comment from
  `mcp::http::create_http_client` (lines 65-91) onto the
  `HTTP_CLIENT` static so the rationale is visible at the
  declaration site.

## Reproduction / Evidence

`cargo run --bin redirect-probe` after pulling master @ `035e635`:

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
```

Source evidence:

```
$ grep -rn 'Client::builder()' tap-mcp-bridge/src/
tap-mcp-bridge/src/transport/http/mod.rs:28:    Client::builder()       # has redirect(none) ✓
tap-mcp-bridge/src/transport/http/mod.rs:175:        let mut builder = Client::builder()  # has redirect(none) ✓
tap-mcp-bridge/src/mcp/tools.rs:37:    Client::builder()                # MISSED ✗
tap-mcp-bridge/src/mcp/http.rs:86:    Client::builder()                 # has redirect(none) ✓
tap-mcp-bridge/src/mcp/subscriptions/tools.rs:38:    Client::builder()  # has redirect(none) ✓
```

`mcp/tools.rs` HTTP_CLIENT chain (lines 36-43) does not call `.redirect(...)`:

```rust
static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .pool_max_idle_per_host(100)
        .http2_prior_knowledge()
        .build()
        .expect("failed to create HTTP client")
});
```

`browse_merchant` (line 217) → `execute_tap_request_with_acro` (line 234) →
private function at line 258 → `HTTP_CLIENT` (line 290).

`checkout_with_tap` (line 142) → same path through line 164 → 290.

## See Also

- Issue (filed by Cycle 16)
- #144 (parent issue) and #145 (incomplete fix) — context for why this is a follow-up.
- Spec 005 — the original spec, all FRs still apply with this fifth call site added.
