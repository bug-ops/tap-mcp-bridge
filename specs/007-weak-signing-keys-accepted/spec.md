# Spec 007 — `TAP_SIGNING_KEY` validator accepts all-zero / all-ones / low-entropy seeds

**Status**: Draft
**Priority**: P2 (Bug — operational hazard: operator misconfiguration leads to silent impersonation surface)
**Type**: Bug fix (input validation hardening)
**Owner**: TBD
**Discovered**: 2026-05-01, Cycle 18 live testing, master @ f61b61e
**Source**: `.local/testing/debug/cycle18/probe_env.sh`

## Problem Statement

`tap-mcp-server`'s `validate_signing_key` (`tap-mcp-server/src/main.rs:149`)
checks two things and only two: that the input is exactly 64 hex
characters, and that every character is in `[0-9a-fA-F]`. Any 32-byte
seed that satisfies these constraints is accepted, including:

- All zeros (`0000...0000`, 64 × `0`).
- All ones (`ffff...ffff`, 64 × `f`).
- Any other low-entropy seed an operator might type as a placeholder
  (`0123...` repeating, `cafebabe...`, etc.).

Ed25519 derives the keypair from the seed by hashing it with SHA-512
and clamping the result, so even pathological seeds produce a valid
signing key. The all-zero seed produces a publicly-known, reproducible
keypair — anyone who happens to use the same all-zero seed signs
identically.

A common operator mistake: copy-pasting a placeholder value from docs
or examples (`TAP_SIGNING_KEY="0000...0000"`), or running
`TAP_SIGNING_KEY=$(printf '0%.0s' {1..64})` instead of
`TAP_SIGNING_KEY=$(openssl rand -hex 32)`. The bridge accepts the value,
runs the server, and silently signs every TAP request with a key that
has no entropy.

This is a **defense-in-depth gap**: the validator catches obvious
malformed input (wrong length, non-hex chars) but not the catastrophic
operator-mistake case where a placeholder seed makes it into
production.

## User Stories

- **As a TAP agent operator** I expect the bridge to refuse to start
  with a key that has no entropy, so a copy-paste placeholder doesn't
  silently end up in production. SSH and TLS tooling have refused
  trivially-weak keys for years; the bridge should follow suit.
- **As a security reviewer** I expect Ed25519 key validation to include
  at least a "not all zeros / not all ones" check. Anything more
  sophisticated (NIST SP 800-22, randomness tests) is overkill for a
  validator running once at startup, but the trivial cases must be
  rejected.

## Functional Requirements

**FR-1**: `validate_signing_key` MUST reject inputs whose decoded 32
bytes are entirely composed of `0x00` or entirely composed of `0xff`.
Error message MUST mention that the seed appears to have no entropy
and reference `openssl rand -hex 32` as the suggested generator.

**FR-2**: `validate_signing_key` SHOULD warn (or reject, depending on
appetite) when the decoded seed has obvious low-entropy patterns:
  - All bytes equal (e.g. all `0x55`, all `0xaa`).
  - Sequential bytes (e.g. `00 01 02 03 ... 1f`).
  - Repeating short pattern (e.g. `de ad be ef de ad be ef ...`).

The simplest practical implementation is to compute the Shannon
entropy of the 32-byte seed and reject anything below a threshold
(e.g. 4.5 bits/byte). The Shannon-entropy check rejects the all-zero
and all-ones cases naturally without enumerating them.

**FR-3**: A regression test in `tap-mcp-server::tests` MUST cover at
least:
  - All-zero seed → rejected.
  - All-ones seed → rejected.
  - All-bytes-equal seed (e.g. all `0xab`) → rejected.
  - Properly random seed (32 random bytes from a known fixture) → accepted.

**FR-4**: CHANGELOG entry under `[Unreleased] / Fixed` describing the
hardening, with explicit "BREAKING" callout for any operator currently
running with a weak placeholder seed (which would now refuse to start
— security-positive).

## Non-Functional Requirements

- **Performance**: validation is O(1) over the 32-byte seed; one-time
  startup cost. Negligible.
- **Backward compatibility**: pre-1.0 — operators currently running
  with a weak placeholder will see a startup failure. Security-positive
  breaking change.
- **Documentation**: the doc-comment on the `signing_key_hex` field
  and the env-var doc at the top of `main.rs` should mention the
  entropy requirement and reference `openssl rand -hex 32`.

## Design Choices (Open Questions for /sdd plan)

1. **Position A — "trivial weak" only**: reject all-zero and all-ones,
   nothing else. Cheapest fix, covers 90% of the operator-mistake
   surface. Recommended starting point.
2. **Position B — Shannon entropy threshold**: compute Shannon entropy
   of the 32-byte seed and reject below threshold. Catches more
   patterns including all-bytes-equal-to-X for any X. Slightly more
   complex; threshold tuning could be over-aggressive (a poorly-RNG-d
   seed might trip it).
3. **Position C — NIST SP 800-22 lite**: a few of the simpler NIST
   randomness tests (frequency, runs, cumulative sums). Overkill for
   a one-shot validator and risks false positives on legitimate keys.

Recommendation: **Position A** for v0.x. Position B as a follow-up if
the project ships a security-conscious release later.

[NEEDS CLARIFICATION: TAP spec position on agent key entropy. RFC
specifies "use of cryptographically secure random number generators";
whether the bridge should enforce post-hoc on operator-provided values
is a deployment-time concern.]

## Reproduction / Evidence

`probe_env.sh` (cycle 18) output, relevant lines:

```
=== TAP_SIGNING_KEY validator probes ===
KEY_valid                                          | STARTED  ✓
KEY_all_zeros                                      | STARTED  ✓
KEY_all_ones                                       | STARTED  ✓
KEY_63chars                                        | rejected
KEY_65chars                                        | rejected
KEY_with_spaces                                    | rejected
KEY_uppercase_OK                                   | STARTED  ✓
KEY_unicode                                        | rejected
KEY_mixed_nonhex                                   | rejected
```

Note: `KEY_uppercase_OK` accepting hex case-insensitive is correct
(the existing length + alphabet checks). The defect is specifically
the `KEY_all_zeros` / `KEY_all_ones` rows.

Source evidence — `tap-mcp-server/src/main.rs:149-162`:

```rust
fn validate_signing_key(key_hex: &str) -> Result<()> {
    if key_hex.len() != 64 { ... }                    // length only
    if !key_hex.chars().all(|c| c.is_ascii_hexdigit()) { ... }   // alphabet only
    Ok(())                                            // no entropy check
}
```

Public Ed25519 key derived from the all-zero seed:
`3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29`. This
is a publicly-known constant; anyone who happens to also use the
all-zero seed gets the same keypair.

## See Also

- Issue (filed by Cycle 18)
- Spec 003 (`process_payment_rate_limited` per-consumer scope) — same
  general theme: validators that enforce some constraints but miss
  obvious operator-mistake cases.
- Cycle 18 also surfaced TAP_AGENT_DIRECTORY validator gaps (loopback
  hosts, userinfo URLs, port 0, path-traversal segments). Those are
  filed separately as P3 enhancement since they're operator-config
  quality issues, not security operational hazards.
