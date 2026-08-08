# Spec 002 — JSON object key ordering changed silently after #130

**Status**: Draft
**Priority**: P2 (Bug — suboptimal/minor inconsistency / Enhancement — make the contract explicit)
**Type**: Bug fix or design clarification (depends on chosen direction)
**Owner**: TBD
**Discovered**: 2026-05-01, Cycle 9 live testing, master @ d96d657
**Source**: live-test diff between cycle 7 (`9aa61b3`) and cycle 9 (`d96d657`) MCP smoke transcripts

## Problem Statement

PR #130 (`feat(security)!: replace josekit JWE with aws-lc-rs (drop OpenSSL)`)
removed `josekit` from the dependency graph. As a transitive side-effect,
`serde_json` is no longer compiled with the `preserve_order` feature
(`josekit`'s dep tree had been pulling it in via `indexmap`), and its
`Value::Object`/`json!{}` macro now uses `BTreeMap` instead of `IndexMap`.
The result: every JSON object built through `serde_json::json!({…})` is now
serialized with **alphabetically sorted keys**, while previously the keys
matched the insertion order in the source.

This change is **not documented** in the #130 PR description, the
`BREAKING CHANGE` footer (which only mentioned PEM acceptance), or the
`CHANGELOG.md` `[Unreleased]` entry for #130. It crossed multiple
serialization boundaries silently:

1. **`tap-mcp-server::observability::HealthReport::to_json`**
   (`tap-mcp-server/src/observability.rs:223–252`) — produces the body of
   the MCP `verify_agent_identity` tool response. Cycle 7 emitted the
   declared order `status, version, agent_id, uptime_secs, checks`; cycle
   8/9 emit the alphabetical order `agent_id, checks, status, uptime_secs,
   version` (and inside each `HealthCheck`: previously `name, status,
   message`, now `message, name, status`).
2. **`tap_mcp_bridge::tap::apc::PaymentMethod::to_json`**
   (`tap-mcp-bridge/src/tap/apc.rs:362–396`) — produces the **plaintext
   that gets RSA-OAEP / AES-256-GCM-encrypted into the APC**. The byte
   sequence sent over the wire (the JWE ciphertext) is now derived from a
   different plaintext byte sequence. The decrypted content is functionally
   identical (same fields, same values), but the byte layout is changed.
3. **`tap_mcp_bridge::tap::jwt::IdToken::create`**
   (`tap-mcp-bridge/src/tap/jwt.rs:301–304`) — JWT header `{"alg","typ"}`.
   The keys `alg < typ` are already alphabetical in the source, so this
   call site is unaffected in practice.

`#[derive(Serialize)]` structs (e.g. `Apc`, `Acro`, `IdTokenClaims`) are
**not** affected because serde-derive emits fields in declaration order
regardless of the `preserve_order` feature.

## User Stories

- **As a downstream consumer** that may snapshot or hash the JSON output of
  `verify_agent_identity` for monitoring/alerting/audit purposes, I should
  not see a hash mismatch caused by an unrelated security PR.
- **As a TAP-MCP bridge maintainer** I should be able to read the
  `[Unreleased]` section of `CHANGELOG.md` and know about every behavioral
  change introduced in a PR. A silent change to the JSON serialization of
  the encrypted APC plaintext bytes is the kind of thing that belongs there.
- **As a future test author** verifying APC encryption against a TAP
  reference vector or a known-merchant fixture, I need a stable plaintext
  byte layout, otherwise reference comparisons drift.

## Functional Requirements

**FR-1**: The project MUST adopt one of the following positions and document
it explicitly:

  - **Position A — Restore stability**: enable `serde_json/preserve_order`
    in `tap-mcp-bridge/Cargo.toml` and `tap-mcp-server/Cargo.toml` so JSON
    object key order matches the source declaration order at all `json!{}`
    call sites. This restores cycle 7 byte layout.
  - **Position B — Embrace alphabetical**: keep current alphabetical
    behavior, document it in `CHANGELOG.md` under the #130 entry, and add
    a regression test asserting the exact byte layout of `HealthReport`
    JSON and `PaymentMethod::to_json` for each variant.

**FR-2**: Whichever position is chosen, the regression test MUST cover at
least:
  - `HealthReport` round-trip (build → `to_json()` → exact-byte assertion).
  - `PaymentMethod::Card`, `BankAccount`, `DigitalWallet` round-trips
    (build → `to_json()` → exact-byte assertion of the inner JSON).
  - Documentation that explicitly states "key ordering of `json!{}`
    output is/is-not stable across releases".

**FR-3**: `CHANGELOG.md` MUST be amended (under #130 or a new
`[Unreleased]` entry, depending on whether 0.3.0 is already published) to
note the JSON-ordering side-effect.

## Non-Functional Requirements

- **Performance**: enabling `preserve_order` swaps `BTreeMap` for
  `IndexMap`; the binary cost is one extra hashmap-style data structure
  pulled into the dep graph (`indexmap`, ~few hundred KB). Negligible.
- **Backward compatibility**: pre-1.0 — explicit position-A "restore" is
  itself a breaking change vs the just-released cycle-8 byte layout, but
  restores parity with the cycle-7 layout that v0.3.0 was tagged on.
  Position-B accepts the cycle-8 layout as the new normal.
- **Documentation**: Position A or B must be cross-referenced from the
  `serde_json` features list to make the choice intentional and stable.

## Design Choices (Open Questions for /sdd plan)

- Is there a TAP/RFC requirement on APC plaintext byte order? RFC 7516
  (JWE) says nothing about JSON inside the plaintext. RFC 8259 (JSON) says
  member order is not significant. So no protocol-level requirement.
- Is there a merchant-side replay or audit hash that depends on exact
  plaintext bytes? If yes → Position A is mandatory.
- Position A locks the project into `IndexMap` for the entire dep graph;
  Position B keeps the dep graph minimal at the cost of unstable byte
  layout. Position B + an explicit derive struct (instead of `json!{}`) for
  every order-sensitive JSON object is a third path: zero extra deps, byte-
  stable, but more code per call site.

[NEEDS CLARIFICATION: confirm with TAP spec authors whether APC plaintext
byte stability is a protocol invariant.]

## Reproduction / Evidence

Same `verify_agent_identity` MCP smoke run, two master commits.

Cycle 7 (`9aa61b3`) — declared order:
```
{
  "status": "healthy",
  "version": "0.3.0",
  "agent_id": "test-agent-1",
  "uptime_secs": 0,
  "checks": [
    {
      "name": "signing_key",
      "status": "pass",
      "message": "Ed25519 signing key loaded successfully"
    },
```

Cycle 8 (`d61c2dc`) and Cycle 9 (`d96d657`) — alphabetical:
```
{
  "agent_id": "test-agent-9",
  "checks": [
    {
      "message": "Ed25519 signing key loaded successfully",
      "name": "signing_key",
      "status": "pass"
    },
```

The dependency graph delta (`Cargo.lock`):

```
  [[package]]
  name = "serde_json"
  version = "1.0.149"
  ...
  dependencies = [
- "indexmap",
   "itoa",
   "memchr",
   "serde",
   "serde_core",
   "zmij",
  ]
```

`indexmap` is the marker for `serde_json`'s `preserve_order` feature.

## See Also

- Issue (filed by Cycle 9 with link back to this spec)
- PR #130 (replaces josekit with aws-lc-rs — root cause)
- `tap-mcp-server/src/observability.rs:223–252` — affected `to_json`
- `tap-mcp-bridge/src/tap/apc.rs:362–396` — affected APC plaintext builder
- `tap-mcp-bridge/src/tap/jwt.rs:301–304` — JWT header (incidentally already alphabetical)
