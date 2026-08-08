# Spec 009 — `tap-mcp-bridge` signs exclusively with Ed25519; official TAP reference agent also supports RSA-PSS-SHA256

**Status**: Draft
**Priority**: P2 (Research / parity gap — interoperability risk with RSA-only merchants, not a defect in current behavior)
**Type**: Research finding — algorithm parity gap
**Owner**: TBD
**Discovered**: Cycle 26, 2026-08-08
**Source**: Research comparison against https://github.com/visa/trusted-agent-protocol (`tap-agent/` reference implementation README)

## Problem Statement

`tap-mcp-bridge`'s TAP signing implementation hardcodes the RFC 9421
signature algorithm to Ed25519. The `alg` field is a string literal,
not a configurable or pluggable value:

- `tap-mcp-bridge/src/tap/acro.rs:185` — `alg: "ed25519".to_owned()`
  inside `Acro` construction (also documented as "always ed25519" at
  `acro.rs:122`).
- `tap-mcp-bridge/src/tap/apc.rs:195` — same pattern for `Apc`
  (documented as "always ed25519" at `apc.rs:146`).
- `tap-mcp-bridge/src/tap/signer.rs:150-151` and `:430-431` — the
  `Signature-Input` header is built with a literal
  `alg="ed25519"` component.
- `tap-mcp-bridge/src/tap/jwk.rs` — the JWK representation is
  hardcoded to `kty: "OKP"`, `crv: "Ed25519"` (an Octet Key Pair JWK);
  there is no `kty: "RSA"` path.
- `tap-mcp-bridge/Cargo.toml:26` — only `ed25519-dalek` is a signing
  dependency; no RSA crate (`rsa`, `ring`, or similar) is present.
- No `SigningAlgorithm` enum, trait abstraction, or algorithm
  selection point exists anywhere under `tap-mcp-bridge/src/tap/`.

Visa's official reference implementation at
[visa/trusted-agent-protocol](https://github.com/visa/trusted-agent-protocol)
(the `tap-agent/` Streamlit reference agent) documents support for two
RFC 9421-compatible signing algorithms:

- **Ed25519** — recommended, modern, fast (this bridge's only path today).
- **RSA-PSS-SHA256** — traditional RSA with PSS padding and SHA-256,
  used by merchants whose key-management infrastructure is RSA-based
  (e.g. existing HSM/PKI deployments that predate widespread Ed25519
  adoption).

`tap-mcp-bridge` exists specifically to let AI agents interoperate
with TAP-conformant merchants. Because the reference implementation —
the interoperability baseline for the whole protocol ecosystem —
treats RSA-PSS-SHA256 as a first-class algorithm choice, any merchant
that only accepts RSA-PSS-SHA256 signatures (by policy, compliance
requirement, or existing key infrastructure) **cannot transact through
this bridge at all**. This is a genuine interoperability gap, not a
cosmetic omission: the bridge's entire purpose is broad merchant
compatibility, and the current implementation silently narrows that to
"merchants that accept Ed25519."

This spec captures **what** the gap is and **why** it matters. It
deliberately does not prescribe an implementation (crate choice, key
storage format, negotiation protocol) — that belongs to `/sdd plan`.

## User Stories

### US-1: Merchant that only accepts RSA-PSS-SHA256

AS A merchant operator running a TAP-conformant backend that only
verifies RSA-PSS-SHA256 signatures (e.g. because their HSM/PKI
infrastructure issues RSA keys and cannot mint Ed25519 keys)
I WANT an agent using `tap-mcp-bridge` to be able to sign TAP requests
with RSA-PSS-SHA256
SO THAT agents built on this bridge can complete checkout flows against
my storefront without me having to add Ed25519 key support first.

**Acceptance criteria:**
```
GIVEN a merchant backend configured to verify RFC 9421 signatures
      using RSA-PSS-SHA256 only
WHEN an agent operator configures tap-mcp-bridge with an RSA signing
     key and the matching algorithm selection
THEN the bridge produces an ACRO/APC payload and Signature-Input
     header with alg="rsa-pss-sha256", and the merchant's verifier
     accepts the request
```

### US-2: Agent operator wanting broader merchant compatibility

AS A TAP agent operator deploying `tap-mcp-server` across multiple
merchants
I WANT to choose the signing algorithm per deployment (Ed25519 or
RSA-PSS-SHA256) via configuration, without forking the bridge
SO THAT I can target the widest possible set of TAP-conformant
merchants with a single codebase, matching what the official
reference agent already offers.

**Acceptance criteria:**
```
GIVEN an operator configuring TAP_SIGNING_KEY (or equivalent) for
      tap-mcp-server
WHEN the operator supplies an RSA private key and selects
     RSA-PSS-SHA256 as the algorithm
THEN the server starts successfully, signs all outbound TAP requests
     with RSA-PSS-SHA256, and Ed25519-only deployments remain
     unaffected (no behavior change for existing Ed25519 users)
```

## Functional Requirements

**FR-1**: The signing algorithm MUST become a selectable/pluggable
property rather than a hardcoded literal. `Acro::alg`, `Apc::alg`, and
the `Signature-Input` header's `alg` parameter MUST reflect the
algorithm actually used to produce the signature, not a fixed string.

**FR-2**: The bridge MUST support signing RFC 9421 message signatures
with RSA-PSS-SHA256 (RSASSA-PSS using SHA-256, per RFC 9421 §3.3.6 /
the `rsa-pss-sha256` registered algorithm identifier), in addition to
the existing Ed25519 (`ed25519`) path.

**FR-3**: RSA key material MUST be loadable through a mechanism
consistent with the project's existing key-handling conventions (e.g.
`TAP_SIGNING_KEY`-style configuration in `tap-mcp-server`, or an
equivalent explicit key-loading API in the library). Exact format
(PEM, PKCS#8, raw modulus/exponent) is left to `/sdd plan`.

**FR-4**: The JWK representation (`tap-mcp-bridge/src/tap/jwk.rs`)
MUST be extended to represent RSA public keys (`kty: "RSA"` with `n`
and `e` members per RFC 7518 §6.3.1) alongside the existing OKP/Ed25519
representation, so that agent-directory publication and JWK
thumbprinting (RFC 7638) work for both algorithms.

**FR-5**: WHEN no algorithm is explicitly configured, THE SYSTEM SHALL
default to Ed25519, preserving current behavior for all existing
deployments (no breaking change for the default path).

**FR-6**: WHEN an RSA key is configured, THE SYSTEM SHALL validate key
strength (e.g. minimum modulus size — align with common TAP/PKI
guidance, likely 2048-bit minimum, `[NEEDS CLARIFICATION: minimum RSA
key size mandated or recommended by the TAP spec, if any]`) before
accepting it, mirroring the existing weak-key rejection posture
established for Ed25519 seeds (see Spec 007).

**FR-7**: A regression test suite MUST cover RSA-PSS-SHA256 signing
end-to-end: `Acro`/`Apc` construction with `alg: "rsa-pss-sha256"`,
`Signature-Input` header construction, and signature verification
against a known-good fixture (mirroring the existing Ed25519 test
coverage in `acro.rs`, `apc.rs`, and `signer.rs`).

**FR-8**: Both a library example (per this repo's convention of
exercising critical paths through `tap-mcp-bridge/examples/`) and the
`tap-mcp-server` MCP tool path MUST be able to exercise RSA-PSS-SHA256
signing, consistent with the project's cross-interface-consistency
requirement (`.claude/rules/continuous-improvement.md`).

## Non-Functional Requirements

- **Compatibility**: Adding RSA-PSS-SHA256 support MUST NOT change the
  wire format, default algorithm, or public API behavior for existing
  Ed25519-only callers. This is an additive capability.
- **Crypto library choice**: `[NEEDS CLARIFICATION: which RSA crate —
  `rsa` (pure Rust, RustCrypto), `ring`, or an OpenSSL binding — best
  fits this project's existing dependency posture (`ed25519-dalek`,
  workspace `deny.toml` license/advisory constraints)? This is a
  `/sdd plan` decision but flagged here since it affects feasibility.]`
- **Performance**: RSA-PSS-SHA256 signing/verification is
  computationally heavier than Ed25519 (larger keys, modular
  exponentiation vs. elliptic-curve operations). The chosen
  implementation should not introduce unbounded latency in the
  checkout hot path; benchmark against existing Ed25519 signing
  latency once implemented.
- **Key management**: RSA private keys are larger and have more
  encoding variants (PKCS#1 vs PKCS#8, DER vs PEM) than the raw 32-byte
  Ed25519 seed currently accepted via `TAP_SIGNING_KEY`. The configured
  loading mechanism must not weaken the "secrets never in this repo's
  dev workflow, resolved via the Zeph age vault" convention.
- **Security**: RSA-PSS-SHA256 must use a cryptographically secure
  salt length and SHA-256 as both hash and MGF1 hash, per RFC 9421
  §3.3.6, to avoid downgrade or malleability issues. No custom padding
  scheme.
- **No regression to Ed25519 default path**: existing test suites,
  examples, and merchant TOML fixtures under
  `tap-mcp-bridge/examples/merchants/` must continue to pass unchanged.

## Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|-------------------|
| No algorithm configured | Default to Ed25519 (current behavior, unchanged) |
| RSA key configured but below minimum strength | Bridge refuses to start / sign, with an explicit error message (mirrors Spec 007's weak-key rejection posture) |
| RSA key configured but malformed (bad PEM/DER) | Fail fast at load time with a clear parse error, not a silent fallback to Ed25519 |
| Merchant rejects the chosen algorithm | Out of scope for this spec — algorithm negotiation/fallback (trying both algorithms against a merchant) is a design question for `/sdd plan`, not assumed here |
| Both an Ed25519 and RSA key configured simultaneously | `[NEEDS CLARIFICATION: is dual-key configuration in scope, or is algorithm selection strictly one-key-one-algorithm per deployment?]` |

## Design Choices (Open Questions for `/sdd plan`)

This research finding intentionally stops short of prescribing HOW.
Key questions for the planning phase:

1. **Algorithm selection mechanism** — new env var
   (`TAP_SIGNING_ALGORITHM`), key-format sniffing (detect RSA vs
   Ed25519 from the key material itself), or explicit
   `SigningAlgorithm` enum on the library's public API?
2. **RSA crate choice** — pure-Rust `rsa` crate vs. `ring` vs. an
   OpenSSL binding; must satisfy `cargo make deny` (license/advisory
   bans) and the workspace's `unsafe`-avoidance posture.
3. **Signer abstraction** — does `tap-mcp-bridge/src/tap/signer.rs`
   need a `Signer` trait with `Ed25519Signer` / `RsaPssSigner`
   implementations, or a simpler enum-dispatch approach appropriate
   for an MVP (per this project's "no premature abstraction"
   convention)?
4. **JWK/thumbprint impact** — RFC 7638 thumbprint computation differs
   between OKP (`crv`, `kty`, `x`) and RSA (`e`, `kty`, `n`) member
   sets; verify the thumbprint module generalizes correctly for both.

## See Also

- [Visa Trusted Agent Protocol reference implementation](https://github.com/visa/trusted-agent-protocol) — `tap-agent/` README documents both Ed25519 and RSA-PSS-SHA256 as supported signing algorithms
- [RFC 9421 — HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html) — §3.3.6 defines `rsa-pss-sha256`; §3.3.7 defines `ed25519` (this bridge's current sole path)
- [RFC 7518 — JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518.html) — §6.3.1 defines the RSA JWK member set (`n`, `e`) needed to extend `tap-mcp-bridge/src/tap/jwk.rs`
- [RFC 7638 — JSON Web Key (JWK) Thumbprint](https://www.rfc-editor.org/rfc/rfc7638.html) — thumbprint canonicalization differs by `kty`
- Spec 007 (`specs/007-weak-signing-keys-accepted/spec.md`) — precedent for weak-key rejection posture, to be mirrored for RSA key strength validation (FR-6)
- `tap-mcp-bridge/src/tap/acro.rs`, `apc.rs`, `signer.rs`, `jwk.rs` — current Ed25519-only implementation
