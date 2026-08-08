# Spec 003 — `process_payment_rate_limited` is process-global despite "per consumer" claim

**Status**: Draft
**Priority**: P1 (Bug — degraded UX / contract violation / multi-tenant DoS surface)
**Type**: Bug fix or doc correction (depends on chosen direction)
**Owner**: TBD
**Discovered**: 2026-05-01, Cycle 11 live testing, master @ 4adf44f
**Source**: `.local/testing/scratch/src/rate_limit_multi_consumer.rs`

## Problem Statement

The public function `tap_mcp_bridge::mcp::payment::process_payment_rate_limited`
documents a **per-consumer** rate limit, but the implementation enforces a
**process-global** rate limit. Any single consumer that exhausts the bucket
denies service to every other consumer in the same process.

**Doc claims** (`tap-mcp-bridge/src/mcp/payment.rs`):
- Line 281: `/// Default configuration: 5 payments per minute per consumer`
- Line 309: `/// Default rate limit: 5 attempts per minute per consumer (burst of 3).`

**Implementation** (lines 282–302): a single
`static PAYMENT_RATE_LIMITER: Mutex<Option<Arc<RateLimiter>>>` is initialized
lazily on first call with `requests_per_second=1, burst_size=3`.
`get_payment_rate_limiter()` returns the same `Arc<RateLimiter>` for every
caller, regardless of `params.consumer_id`. The `consumer_id` is never read
when acquiring a token.

In a multi-tenant deployment (e.g. a single bridge process serving many
end-users), one noisy or malicious consumer exhausts the shared bucket and
silently rate-limits all other consumers — directly opposite of the
documented contract.

## User Stories

- **As a multi-tenant bridge operator** I expect that one noisy consumer
  cannot deny service to other consumers via the rate limiter, because the
  documented contract says rate limits are per-consumer.
- **As a security reviewer** I need documented behavior to match
  implementation: an undocumented global bucket is a covert DoS surface.
- **As a downstream library consumer** I read the doc-comment, configure
  my code accordingly, and expect the function to behave as documented. A
  silent contract mismatch leads to subtle production bugs (e.g. retry
  loops that exhaust the global bucket and surprise everyone else).

## Functional Requirements

**FR-1**: The project MUST resolve the contract mismatch by adopting one of
the following positions and document it explicitly:

  - **Position A — Implement per-consumer limiting**: replace the
    process-global static with a per-consumer keyed structure (e.g.
    `DashMap<String, Arc<RateLimiter>>` or a sharded LRU of limiters).
    Each consumer_id gets its own bucket. Matches the current doc-comment.
  - **Position B — Correct the documentation**: change both doc-comments
    on `payment.rs:281` and `:309` to say "per process" / "shared across
    consumers" and update the `CHANGELOG.md` to note the behavior. The
    current behavior remains; only the docs are fixed.

**FR-2**: Whichever position is chosen, a regression test MUST exist that
asserts the chosen scope. For Position A, two distinct consumer_ids must
each be able to drain their own burst without blocking each other. For
Position B, the test asserts that two consumer_ids share the bucket.

**FR-3**: If Position A is chosen, the per-consumer storage MUST have a
bounded size with eviction (LRU or TTL) so that an attacker submitting
millions of distinct consumer_ids cannot exhaust process memory. The
default size and eviction policy MUST be documented.

**FR-4**: The MCP tool surface (`process_payment` registered in
`tap-mcp-server`) does NOT currently call `process_payment_rate_limited`.
The MCP path uses the unrate-limited `process_payment` function directly.
This is orthogonal to FR-1/FR-2 but should be reviewed: if the MCP path
needs rate limiting, it should be wired explicitly. If it doesn't need it,
say so in the doc.

## Non-Functional Requirements

- **Performance**: per-consumer keyed lookups should remain O(log n) or
  O(1) on the hot path. Avoid taking a global mutex for every call.
- **Memory**: bounded — see FR-3.
- **Observability**: rate-limit rejections should log the consumer_id so
  operators can identify the noisy tenant.
- **Documentation**: the chosen position must be reflected in
  `CHANGELOG.md` and in the function's `# Errors` section.

## Design Choices (Open Questions for /sdd plan)

- **Position A — DashMap of limiters**: simple, common pattern. Memory
  overhead = ~tracker_size * unique_consumers; needs eviction.
- **Position A — Sharded LRU**: bounds memory by construction; one mutex
  per shard avoids contention.
- **Position A — token-bucket per consumer with global ceiling**: hybrid
  that protects the process from cross-consumer flooding while still
  giving each consumer their own limit. More complex to reason about.
- **Position B — accept process-global**: simplest; matches current code;
  fixes only the docs. Multi-tenant operators must layer their own
  per-consumer rate limiting upstream of the bridge.

[NEEDS CLARIFICATION: is this bridge intended for single-tenant or
multi-tenant deployment? The CHANGELOG / README don't say explicitly. The
choice between Position A and B hinges on this.]

## Reproduction / Evidence

Cycle 11 live test (`rate-limit-multi-consumer` harness):

```
=== rate-limit-multi-consumer: per-consumer scope probe ===
[A] 3 calls as 'alice' (drains alice's documented per-consumer burst)
  alice call 1: Ok
  alice call 2: Ok
  alice call 3: Ok
[B] bob's first call: RateLimitExceeded     ← expected Ok per docs
[B] bob's second call: RateLimitExceeded
[C] charlie's first call: RateLimitExceeded

GLOBAL scope detected: bob/charlie blocked because alice drained the shared bucket
```

Static evidence — `tap-mcp-bridge/src/mcp/payment.rs:282–302`:

```rust
static PAYMENT_RATE_LIMITER: Mutex<Option<Arc<RateLimiter>>> = Mutex::new(None);

fn get_payment_rate_limiter() -> Arc<RateLimiter> {
    let mut limiter_opt = PAYMENT_RATE_LIMITER.lock()...;
    if let Some(limiter) = limiter_opt.as_ref() {
        Arc::clone(limiter)
    } else {
        let config = RateLimitConfig {
            requests_per_second: 1,
            burst_size: 3,
        };
        let limiter = Arc::new(RateLimiter::new(config));
        *limiter_opt = Some(Arc::clone(&limiter));
        limiter
    }
}
```

`consumer_id` is never threaded through.

## See Also

- Issue (filed by Cycle 11 with link back to this spec)
- `tap-mcp-bridge/src/security/rate_limit.rs` — the underlying `RateLimiter` primitive (per-bucket, not per-key by design)
- Cycle 9 single-consumer harness `.local/testing/scratch/src/rate_limit_drive.rs` — never noticed the multi-consumer issue because it only tested with one consumer_id
