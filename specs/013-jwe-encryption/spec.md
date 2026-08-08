# Spec 013 — `jwe` Subsystem: RFC 7516 Compact Serialization for APC Payment Data

**Status**: Documented (as-built)
**Priority**: N/A (subsystem documentation, not a fix)
**Type**: Subsystem specification — documents existing behavior
**Owner**: N/A
**Discovered**: Authored during specs migration cycle, 2026-08-08, closing the
subsystem-coverage gap against `.claude/rules/continuous-improvement.md` §
Project Subsystems
**Source**: `tap-mcp-bridge/src/tap/jwe.rs`

> [!note]
> Describes existing, tested code. `jwe` lives physically under `tap/` but is
> tracked as its own logical subsystem in this project's continuous-improvement
> rules because it has an independent RFC (7516) and its own security
> properties distinct from the RFC 9421 signing in [[012-tap-protocol-implementation]].

## 1. Overview

### Problem Statement

`Apc::create` (in the `tap` subsystem) needs to encrypt a consumer's payment
method (card, bank account, digital wallet) so that only the merchant's RSA
key holder can read it, while everything else in the ACRO/APC envelope stays
signed but unencrypted. The `jwe` module implements RFC 7516 JWE compact
serialization for exactly this purpose, built directly on `aws-lc-rs`
primitives rather than a general-purpose JOSE crate, to avoid pulling in
OpenSSL.

### Goal

Given an RSA public key (merchant-supplied, SPKI-encoded PEM or DER) and a
plaintext payload, produce a valid 5-part RFC 7516 compact-serialized JWE
string using a fixed algorithm pair, with no key or IV reuse across calls.

### Out of Scope

- JWE decryption (this module only encrypts — the bridge is the sender, not
  the receiver, of APC payloads)
- Algorithm negotiation — `RSA-OAEP-256` + `A256GCM` are hardcoded, not
  configurable
- ACRO/APC signing (see [[012-tap-protocol-implementation]])

## 2. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| `RsaPublicKey` | Parsed merchant RSA public key | `spki_der: Vec<u8>`, `key_size_bits: usize` |
| JWE compact string | The output artifact | 5 base64url segments: protected header, encrypted key, IV, ciphertext, auth tag |

Constants: `PROTECTED_HEADER_JSON = {"alg":"RSA-OAEP-256","enc":"A256GCM"}`
(fixed, also serves as AEAD associated data), `A256GCM_KEY_LEN = 32`,
`A256GCM_IV_LEN = 12`, `MIN_RSA_KEY_BITS = 2048`.

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-1 | WHEN `RsaPublicKey::from_pem` receives a PEM block THE SYSTEM SHALL accept only X.509 SubjectPublicKeyInfo (`-----BEGIN PUBLIC KEY-----`) form and SHALL reject PKCS#1 (`-----BEGIN RSA PUBLIC KEY-----`) form with a distinct error | must |
| FR-2 | WHEN a parsed RSA key has fewer than `MIN_RSA_KEY_BITS` (2048) bits THE SYSTEM SHALL reject it at parse time | must |
| FR-3 | WHEN `encrypt_compact` is called THE SYSTEM SHALL generate a fresh Content Encryption Key (CEK) and IV via `aws_lc_rs::rand::SystemRandom` for every call — no key or IV is ever reused across invocations | must |
| FR-4 | WHEN AES-256-GCM sealing is performed THE SYSTEM SHALL use the base64url-encoded protected header bytes as the AEAD associated data, per RFC 7516 §5.1 step 14 | must |
| FR-5 | WHEN encryption completes (success or error) THE SYSTEM SHALL zero the CEK in memory (`zeroize::Zeroize`), including on error paths | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-1 | Security | Ciphertext tampering (bit-flip in any of the 5 segments) MUST cause AEAD authentication failure — verified by an inline test |
| NFR-2 | Compatibility | Whitespace variation in input PEM is tolerated (verified by an inline test) |
| NFR-3 | Portability | `aws-lc-rs`'s FFI is incompatible with Miri; the affected tests are `#[cfg_attr(miri, ignore)]` |
| NFR-4 | Performance | No `criterion` benchmark exists yet for JWE encryption — known gap, not resolved by this spec |

## 5. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|--------------------|
| PKCS#1 PEM supplied instead of SPKI | Rejected with a distinct, identifiable error message (not silently mis-parsed) |
| RSA key < 2048 bits | Rejected at parse time, before any encryption is attempted |
| Empty plaintext payload | Encrypts successfully (covered by an inline round-trip test) |
| Large plaintext payload | Encrypts successfully (covered by an inline round-trip test) |
| Ciphertext or auth tag modified after encryption | Decryption (by the merchant, out of scope here) fails; this module's own tests verify the ciphertext is not trivially forgeable |

## 6. Agent Boundaries

### Always (without asking)
- Generate a fresh CEK/IV per `encrypt_compact` call — never cache or reuse
- Zeroize CEK material on every code path, including early returns on error

### Ask First
- Adding a second key-wrap or content-encryption algorithm (currently hardcoded to `RSA-OAEP-256` / `A256GCM`)
- Adding JWE decryption support (would change this module's role from sender-only to bidirectional)

### Never
- Accept PKCS#1-format RSA public keys as equivalent to SPKI
- Reduce `MIN_RSA_KEY_BITS` below 2048 without a dedicated security review

## 7. Open Questions

- `[NEEDS CLARIFICATION: does any current or planned merchant integration require JWE decryption (bridge as receiver), or is sender-only always sufficient given TAP's payment-container direction?]`

## 8. See Also

- [[MOC-specs]] — all specifications
- [[012-tap-protocol-implementation]] — `Apc::create` is the sole caller of this module's `encrypt_compact`
- `tap-mcp-bridge/src/tap/jwe.rs` — full implementation and inline tests
- `tap-mcp-bridge/examples/apc_generation.rs` — example usage
