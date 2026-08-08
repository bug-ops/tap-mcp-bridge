# Spec 008 — `TapVerifier`'s LRU eviction creates a replay-protection bypass

**Status**: Draft
**Priority**: P2 (Bug — replay protection has a knowable bypass; security-relevant, downstream-consumer impact)
**Type**: Bug fix (architecture: eviction policy)
**Owner**: TBD
**Discovered**: 2026-05-01, Cycle 20 live testing, master @ f61b61e
**Source**: `.local/testing/scratch/src/replay_cache_eviction.rs`

## Problem Statement

`TapVerifier` (`tap-mcp-bridge/src/tap/verifier.rs`) uses
`Arc<Mutex<LruCache<nonce_string, expires_secs>>>` for replay protection.
The `verify_request` flow:

1. Lock the cache.
2. If `nonce` is in the cache with non-expired `cached_expires`, return
   `BridgeError::ReplayAttack`.
3. Otherwise, insert `(nonce, expires)`.

The cache is bounded — `LruCache::new(capacity)` — and uses **LRU
eviction**: when capacity is reached, the least-recently-used entry is
evicted regardless of whether its `expires` has passed.

This creates a **knowable bypass**: an attacker who can cause the
verifier to process `capacity + 1` distinct nonces within the original
signature's `expires` window (max 8 minutes per TAP §2.3) evicts the
legitimate nonce, then replays the captured request:

- Cache lookup misses (entry was evicted).
- Timestamp check passes (`now <= expires`).
- The cached-expires-vs-now check at line 148-156 never fires because
  the entry is gone.
- Replay accepted as fresh.

For default capacity `10_000`, an attacker needs to flood >10k distinct
nonces in 8 min ≈ 21 RPS sustained. Feasible for any well-resourced
attacker. Capacity is not part of the public API documentation, so
downstream consumers may use smaller values without realising the
window-of-vulnerability is correspondingly smaller.

`TapVerifier` is a `pub` re-export from `tap_mcp_bridge::tap`. Merchants
or middleware using this crate as their TAP verifier are exposed.
`tap-mcp-server` itself doesn't verify signatures (it's the agent
side), so the bridge's own runtime is not directly affected.

## User Stories

- **As a merchant operator** using `tap-mcp-bridge::TapVerifier` for
  replay protection, I expect signatures within their `expires` window
  to be detected as replays even when the verifier is under load. The
  current LRU policy means a noisy peer (or a flood attacker) silently
  shortens my replay-protection window from the documented "until
  expires" down to "until cache rotates".
- **As a security reviewer** I expect replay-protection eviction to be
  TTL-driven (entries leave the cache when they're no longer needed),
  not LRU-driven (entries leave when something else is more recently
  used). LRU is the wrong policy class for security-state.

## Functional Requirements

**FR-1**: Replace LRU eviction with TTL-driven eviction. Entries leave
the cache when their `expires` (plus `CLOCK_SKEW_TOLERANCE_SECS`)
passes. The cache is bounded by `max_validity_window × max_concurrent_RPS`
worth of entries — finite and predictable.

**FR-2**: If a hard memory cap is required, fail-closed when the cache
is full: return a non-replay error (e.g. `BridgeError::CryptoError(
"verifier overloaded; refusing fresh signatures")` ) rather than evict
a still-valid entry. Operationally this surfaces as a backpressure
signal.

**FR-3**: A regression test in `tap-mcp-bridge::tap::verifier::tests`
must assert that a fresh-but-evicted nonce is detected as replay. The
test is exactly the cycle-20 probe shape: tiny capacity, sign,
flood-with-distinct-nonces, replay original.

**FR-4**: `TapVerifier::new` documentation must explicitly describe
the eviction policy and what guarantees the chosen `capacity` provides
under flood conditions.

## Non-Functional Requirements

- **Performance**: TTL-driven eviction can be O(log N) using a
  BTreeMap ordered by expires, plus a HashMap nonce → key. LRU's
  amortised O(1) is replaced by O(log N), but TTL cleanup runs only
  when entries actually need to leave.
- **Memory**: bounded by `max_validity_window × peak_RPS`. For TAP's
  8-min window and 100 RPS that's 48k entries — comparable to the
  current 10k LRU capacity.
- **Backward compatibility**: pre-1.0 — `TapVerifier::new(capacity)`
  signature can stay the same, but the parameter's semantics shift
  from "max entries before LRU evicts" to "max entries before
  fail-closed kicks in" (FR-2 path) or "advisory hint, ignored if
  TTL-driven" (FR-1 pure form).
- **Documentation**: CHANGELOG entry under `[Unreleased] / Security`
  describing the bypass and the mitigation.

## Design Choices (Open Questions for /sdd plan)

1. **Position A — TTL-only with no hard cap**: simplest, memory is
   bounded by validity-window × peak-RPS. Risk: under unbounded
   adversarial flood, memory grows linearly until expires fires.
   Acceptable if the application has its own rate-limiting layer
   upstream of the verifier.
2. **Position B — TTL-primary, hard cap fail-closed**: TTL-driven
   eviction in normal operation; if a hard cap is hit, refuse new
   signatures (return error). Operator-visible backpressure signal.
3. **Position C — LRU + TTL hybrid (deletion priority)**: maintain
   LRU for performance, but BEFORE evicting check if the LRU-victim's
   `expires` is still in the future — if so, fail-closed instead of
   evicting. More code, but preserves O(1) hot path.

Recommendation: **Position B** — TTL-primary with a configurable
hard cap. The hard cap protects against pathological memory growth,
the TTL protects against the LRU-bypass.

[NEEDS CLARIFICATION: TAP/RFC 9421 position on verifier-side replay
protection guarantees. RFC 9421 §2.5 says verifiers SHOULD maintain a
cache of recent nonces — doesn't specify eviction policy. The TAP
draft probably defers to RFC. So the choice is implementation-side.]

## Reproduction / Evidence

Cycle 20 `replay-cache-eviction` harness output:

```
=== replay-cache-eviction: LRU eviction creates a replay window? ===

[step 1] sign legitimate request → verify (should be Ok)
  legitimate verify: Ok ✓

[step 2] immediate replay (cache hit) → must be ReplayAttack
  ReplayAttack ✓

[step 3] flood verifier with 8 distinct fresh nonces → evict N1 by LRU
  8 distinct fresh nonces all verified ✓

[step 4] replay original N1 signature post-eviction → ?
[FAIL] POST-EVICTION REPLAY ACCEPTED AS Ok — bridge has a knowable
       replay-protection bypass via LRU flooding
```

Source evidence — `tap-mcp-bridge/src/tap/verifier.rs`:

- Line 30: `nonce_cache: Arc<Mutex<LruCache<String, u64>>>`
- Line 48: `Self { nonce_cache: Arc::new(Mutex::new(LruCache::new(cap))) }`
- Lines 142-160: replay check; if cache lookup misses (because LRU
  evicted), `pop` doesn't run and the nonce is unconditionally
  re-inserted.

The probe uses capacity = 8 for observability; the same dynamic plays
out at any capacity once the attacker can flood `capacity + 1` distinct
nonces within the validity window.

## See Also

- Issue (filed by Cycle 20)
- RFC 9421 §2.5 — verifier MAY maintain a cache of nonces (silent on
  eviction policy)
- TAP spec §3.x (validity window, max 8 minutes)
- `lru` crate (used as backing store; the issue is policy choice, not
  crate behaviour)
- Cycle 3 (`reliability-drive` harness): tested LRU + replay with
  *sequential* access only; missed the eviction-under-flood window.
