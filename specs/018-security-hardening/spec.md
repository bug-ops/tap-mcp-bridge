# Spec 018 — `security` Subsystem: Rate Limiting and Audit Logging

**Status**: Documented (as-built)
**Priority**: N/A (subsystem documentation, not a fix)
**Type**: Subsystem specification — documents existing behavior
**Owner**: N/A
**Discovered**: Authored during specs migration cycle, 2026-08-08, closing the
subsystem-coverage gap against `.claude/rules/continuous-improvement.md` §
Project Subsystems
**Source**: `tap-mcp-bridge/src/security/{mod,rate_limit,audit}.rs`

> [!note]
> Describes existing, tested code. The replay-protection nonce cache — often
> assumed to live here — is actually implemented in `tap::verifier::NonceCache`
> and is documented in [[012-tap-protocol-implementation]], not this spec;
> this was confirmed by reading the source directly.

## 1. Overview

### Problem Statement

Two distinct concerns live in this module: (1) preventing a single caller or
key from overwhelming a merchant or the bridge itself (token-bucket rate
limiting), and (2) producing a structured, redacted audit trail of
security-relevant events (signature generation, checkout attempts,
authentication failures, rate-limit hits) for later forensic review.

### Goal

`RateLimiter`/`KeyedRateLimiter` give per-process or per-key request-rate
control; `RateLimitedSigner` wraps `TapSigner` so signing itself can be
rate-limited; `AuditEvent`/`audit_log` give a consistent, redaction-aware
logging path for security events.

### Out of Scope

- Replay-protection nonce cache — see [[012-tap-protocol-implementation]]
- Circuit breaker / retry — see [[017-reliability-patterns]]

## 2. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| `RateLimitConfig` | Token-bucket parameters | `requests_per_second, burst_size`; `Default`: `10, 5` |
| `RateLimiter` | Single-bucket limiter | `tokens: AtomicU64` (fixed-point ×1000), `last_update: Mutex<Instant>` |
| `KeyedRateLimiter` | Per-key limiter via bounded `LruCache` | `::new(config, capacity: NonZeroUsize)` |
| `RateLimitedSigner` | Wraps `TapSigner` with rate limiting applied to signing itself | `::new(signer, config)` |
| `AuditEventType` | Enumerated security event kinds | `SignatureGenerated, CheckoutAttempted, CheckoutSucceeded, CheckoutFailed, BrowseAttempted, BrowseSucceeded, AuthenticationFailed, RateLimitExceeded, CircuitBreakerStateChanged` |
| `AuditDetails` | Optional contextual fields on an event | `merchant_url, consumer_id, nonce, error, duration_ms` (all `Option`) |
| `AuditEvent` | The logged unit | `timestamp, event_type, agent_id, request_id: Uuid, details` |

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-1 | WHEN `RateLimiter::acquire` is called and no tokens are available THE SYSTEM SHALL return `Err(RateLimitExceeded)` without blocking; WHEN `acquire_blocking` is called under the same condition THE SYSTEM SHALL wait until a token becomes available | must |
| FR-2 | WHEN `KeyedRateLimiter::acquire(key)` is called for a key not yet tracked THE SYSTEM SHALL create a fresh bucket for that key, evicting the least-recently-used tracked key if the configured capacity is exceeded | must |
| FR-3 | WHEN an `AuditEvent` is constructed with a consumer ID THE SYSTEM SHALL recommend (via `redact_consumer_id`) pre-redaction before attaching it to `AuditDetails` | should |
| FR-4 | WHEN `redact_sensitive` processes a string containing card numbers, CVV, or SSN-shaped data THE SYSTEM SHALL redact it before it reaches an audit log entry | must |
| FR-5 | WHEN a rate limit is exceeded THE SYSTEM SHALL itself emit an audit event (`RateLimitExceeded` `AuditEventType`), so rate-limit hits are forensically visible | should |
| FR-6 | THE SYSTEM SHALL write audit logs to a separate `tracing` target from general application logs, allowing independent filtering | must |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-1 | Concurrency | `RateLimiter`'s token count is atomic (`AtomicU64`, fixed-point) with a mutex-guarded `last_update` timestamp — safe under concurrent `acquire` calls |
| NFR-2 | Defaults | `RateLimitConfig::default()` is `requests_per_second=10, burst_size=5`; `KeyedRateLimiter` capacity has no default constant — callers must supply a `NonZeroUsize` |
| NFR-3 | Testability | Inline `#[cfg(test)]` coverage exists in both `rate_limit.rs` and `audit.rs` |

## 5. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|--------------------|
| `KeyedRateLimiter` capacity reached and a new key requests a bucket | The least-recently-used existing key's bucket is evicted (standard LRU semantics) |
| `RateLimitedSigner::sign_request` is called when the wrapped rate limit is exhausted | Returns an error (via the underlying `RateLimitExceeded`) rather than signing |
| An `AuditDetails.consumer_id` is attached without prior redaction | Not automatically redacted by `AuditEvent` construction itself — redaction is caller-applied via `redact_consumer_id`, per FR-3's "should" (not "must") — a caller that forgets this step will leak a raw consumer ID into logs |

## 6. Agent Boundaries

### Always (without asking)
- Call `redact_consumer_id`/`redact_sensitive` before attaching caller-supplied strings to `AuditDetails`
- Route new rate-limiting needs through `RateLimiter`/`KeyedRateLimiter` rather than a new ad hoc mechanism

### Ask First
- Changing default `RateLimitConfig` values (affects every current caller)
- Making FR-3 (consumer-ID redaction) mandatory/automatic at the `AuditEvent` construction level rather than caller-applied — would be a safety improvement but changes the API contract

### Never
- Log unredacted card numbers, CVV, SSNs, or full consumer IDs through the audit path
- Bypass rate limiting for a production call path without an explicit, reviewed justification

## 7. Open Questions

- `[NEEDS CLARIFICATION: should AuditEvent's consumer_id field require pre-redacted input at the type level (e.g. a RedactedConsumerId newtype) rather than relying on callers to remember to call redact_consumer_id? Current FR-3 is a "should", not enforced by the type system.]`

## 8. See Also

- [[MOC-specs]] — all specifications
- [[003-rate-limit-not-per-consumer]] — prior finding about `process_payment_rate_limited` not being per-consumer; relevant history for FR-1/FR-2's per-key vs. global distinction
- [[012-tap-protocol-implementation]] — the separate replay-protection nonce cache, not part of this subsystem
- [[017-reliability-patterns]] — the sibling subsystem for retry/circuit-breaker
- `tap-mcp-bridge/src/security/mod.rs` — module entry point
