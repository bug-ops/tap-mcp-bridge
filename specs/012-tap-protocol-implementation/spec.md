# Spec 012 — `tap` Subsystem: RFC 9421 Signatures, JWK/JWT, ACRO/APC

**Status**: Documented (as-built)
**Priority**: N/A (subsystem documentation, not a fix)
**Type**: Subsystem specification — documents existing behavior
**Owner**: N/A
**Discovered**: Authored during specs migration cycle, 2026-08-08, to close the
subsystem-coverage gap identified against `.claude/rules/continuous-improvement.md`
§ Project Subsystems (the 11 pre-existing specs are individual bug-fix/finding
specs, not subsystem-level documentation)
**Source**: `tap-mcp-bridge/src/tap/{mod,signer,verifier,jwk,jwt,acro,apc}.rs`

> [!note]
> This spec describes the `tap` module **as currently implemented**. It is not a
> proposal for new functionality — every requirement below is a description of
> code that already exists and is tested. Its purpose is to give a coding agent
> (or reviewer) a single reference for this subsystem's contract without reading
> every source file, and to serve as the baseline against which future changes
> (e.g. spec [[009-rsa-pss-signing-support]], spec [[008-replay-cache-lru-eviction]])
> are diffed.

## 1. Overview

### Problem Statement

The bridge must let an AI agent prove its identity to a merchant on every HTTP
request, per Visa's Trusted Agent Protocol (TAP). TAP defines this proof as an
RFC 9421 HTTP Message Signature over Ed25519, plus a set of TAP-specific
payloads (JWKS for public key distribution, JWT ID tokens, ACRO for consumer
context, APC for encrypted payment data). The `tap` module is the sole place in
the codebase where these cryptographic primitives are constructed; every other
module (`mcp`, `merchant`) calls into it rather than re-implementing signing.

### Goal

A single `TapSigner` instance, constructed once from an `Ed25519` signing key
and an agent identity, can produce every TAP-required artifact (request
signature, JWKS, ID token, ACRO, APC) needed for a full checkout/browse
interaction, and a paired `TapVerifier` can validate an inbound signed request
including replay protection.

### Out of Scope

- Transport/HTTP client concerns (see [[016-transport-layer]] and `mcp/http.rs`,
  covered in [[014-mcp-tool-surface]])
- JWE compact serialization internals (see [[013-jwe-encryption]] — `tap`
  depends on it for `Apc::create` but does not implement it)
- RSA-PSS-SHA256 as an alternative signing algorithm — not yet implemented;
  tracked separately in [[009-rsa-pss-signing-support]]

## 2. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| `TapSigner` | Holds the agent's Ed25519 signing key and identity; the sole signing entry point | `signing_key: SigningKey`, `agent_id: String`, `agent_directory: Arc<str>` |
| `TapSignature` | Output of `sign_request` — the four TAP HTTP headers | `signature`, `signature_input`, `agent_directory`, `nonce` |
| `InteractionType` | Distinguishes browse vs. checkout interactions for the `tag` signature parameter | `Browse` → `"agent-browser-auth"`, `Checkout` → `"agent-payer-auth"` |
| `TapVerifier` | Validates inbound signed requests and tracks replay state | `nonce_cache: Arc<Mutex<NonceCache>>` |
| `Jwk` / `Jwks` | Public key material for the agent directory endpoint | `kty, crv, x, kid, alg, key_use`; `Jwks.keys: Vec<Jwk>` |
| `IdTokenClaims` / `IdToken` | JWT proving consumer identity to the merchant | `sub, iss, aud, exp, iat, nonce, agent_directory` |
| `Acro` | Agentic Consumer Recognition Object — consumer/device context, signed | `nonce, id_token, contextual_data, kid, alg, signature` |
| `ContextualData` / `DeviceData` | Fields carried inside ACRO | `country_code, zip, ip_address` / `user_agent, platform` |
| `Apc` | Agentic Payment Container — encrypted payment method, signed | `nonce, encrypted_payment_data, kid, alg, signature` |
| `PaymentMethod` | Card / BankAccount / DigitalWallet payload encrypted into APC | `Card(CardData) \| BankAccount(BankAccountData) \| DigitalWallet(DigitalWalletData)` |

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-1 | WHEN `TapSigner::sign_request` is called with method, authority, path, body, and an `InteractionType` THE SYSTEM SHALL produce a `TapSignature` whose `signature_input` covers `@method`, `@authority`, `@path`, `content-digest`, `created`, `expires`, `nonce`, `keyid`, `alg`, and `tag`, per RFC 9421 | must |
| FR-2 | WHEN a signature is generated THE SYSTEM SHALL set `expires - created` to at most `TAP_MAX_VALIDITY_WINDOW_SECS` (480s / 8 minutes), per TAP's maximum validity window requirement | must |
| FR-3 | WHEN `TapSigner::generate_jwks` is called THE SYSTEM SHALL derive `kid` as the RFC 7638 JWK thumbprint of the agent's Ed25519 public key | must |
| FR-4 | WHEN `TapVerifier::verify_request` is called with a signature that reuses a nonce already present and unexpired in the nonce cache THE SYSTEM SHALL reject the request with `BridgeError::ReplayAttack` | must |
| FR-5 | WHEN the nonce cache is at capacity and a new nonce must be recorded THE SYSTEM SHALL reject the request with `BridgeError::ReplayCacheSaturated` rather than evict an unexpired entry to make room (fail-closed; see [[008-replay-cache-lru-eviction]] for the incident this behavior resolves) | must |
| FR-6 | WHEN `TapSigner::generate_acro` or `generate_apc` is called THE SYSTEM SHALL compute the signature over the canonical JSON of all fields except `signature` itself, and set `kid` to the same RFC 7638 thumbprint used in FR-3 | must |
| FR-7 | WHEN a `CardData`/`BankAccountData` value is formatted via `{:?}` (`Debug`) THE SYSTEM SHALL redact the PAN/CVV/account/routing numbers, showing at most the last 4 digits | must |
| FR-8 | WHEN a `CardData`/`BankAccountData`/`DigitalWalletData` value is dropped THE SYSTEM SHALL zero its memory (`zeroize()`) | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-1 | Security | Clock skew tolerance is fixed at 60 seconds (`CLOCK_SKEW_TOLERANCE_SECS`); a `RequestTooOld` error is returned outside the combined validity + skew window |
| NFR-2 | Security | The only supported signing algorithm today is Ed25519. No algorithm negotiation or downgrade path exists in `sign_request` (relevant to spec [[009-rsa-pss-signing-support]]) |
| NFR-3 | Testability | Every file in the module has an inline `#[cfg(test)]` module; `tap/tests/proptest_signatures.rs` adds property-based round-trip coverage for signature generation/verification |
| NFR-4 | Performance | No `criterion` benchmark currently exists for RFC 9421 signing, ACRO/APC serialization, or JWT issuance — this is a known coverage gap per `.claude/rules/continuous-improvement.md` § Performance & Benchmark Coverage, not something this spec resolves |

## 5. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|--------------------|
| Nonce cache constructed with `capacity = 0` | Falls back to a default capacity of 1000 (`TapVerifier::new(0)`) |
| Signature `created`/`expires` outside the 480s window | `verify_request` returns `RequestTooOld` |
| `kid` in an ACRO/APC does not match the signer's own JWK thumbprint | Verification fails with `CryptoError` (mismatched key identification) |
| Nonce cache full of entries that have not yet expired | New signatures are rejected (`ReplayCacheSaturated`), never silently evicted (FR-5) |

## 6. Agent Boundaries

### Always (without asking)
- Route all new signing/verification logic through `TapSigner`/`TapVerifier` — never construct a raw RFC 9421 signature base outside this module
- Keep the 480-second validity cap and 60-second skew tolerance unless a spec explicitly changes them

### Ask First
- Adding a second signing algorithm (RSA-PSS) — see [[009-rsa-pss-signing-support]] for the open research spec that must resolve first
- Changing the nonce-cache fail-closed policy (FR-5) — this is a deliberate security posture, not an oversight

### Never
- Log or `Debug`-print raw `CardData`/`BankAccountData`/`DigitalWalletData` contents outside the redacted `Debug` impl
- Widen the signature validity window beyond what TAP's spec permits without a dedicated spec change

## 7. Open Questions

- `[NEEDS CLARIFICATION: is RSA-PSS-SHA256 support (spec 009) still planned, and if so, does it require a breaking change to TapSigner's single-algorithm design, or an additive enum-based signer?]`

## 8. See Also

- [[MOC-specs]] — all specifications
- [[008-replay-cache-lru-eviction]] — the incident that produced FR-5's fail-closed policy
- [[009-rsa-pss-signing-support]] — open research on adding a second signing algorithm
- [[013-jwe-encryption]] — `Apc::create` depends on this subsystem for compact serialization
- [[011-process-payment-acro-wire-contract]] — analysis of when ACRO output actually reaches the wire (a `mcp`-layer concern, not a `tap`-layer one)
- `tap-mcp-bridge/src/tap/mod.rs` — module entry point and signature base documentation
