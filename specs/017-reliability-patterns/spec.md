# Spec 017 — `reliability` Subsystem: Retry with Backoff and Circuit Breaker

**Status**: Documented (as-built)
**Priority**: N/A (subsystem documentation, not a fix)
**Type**: Subsystem specification — documents existing behavior
**Owner**: N/A
**Discovered**: Authored during specs migration cycle, 2026-08-08, closing the
subsystem-coverage gap against `.claude/rules/continuous-improvement.md` §
Project Subsystems
**Source**: `tap-mcp-bridge/src/reliability/{mod,retry,circuit_breaker}.rs`

> [!note]
> Describes existing, tested code. Rate limiting is a related but separate
> reliability concern implemented in the `security` module — see
> [[018-security-hardening]] — not in this one, despite the name suggesting
> otherwise; this is confirmed directly from the module's own doc comment.

## 1. Overview

### Problem Statement

Merchant endpoints are external services and will occasionally fail
transiently (network blips, momentary overload). Callers need a standard way
to retry with exponential backoff, and a way to stop hammering a merchant that
is persistently failing (circuit breaker), without every call site
reimplementing this logic.

### Goal

`RetryPolicy` + `retry_with_backoff` gives any async operation configurable
exponential-backoff retry; `CircuitBreaker` gives any operation a
three-state (Closed/Open/HalfOpen) failure-isolation wrapper. Both are
general-purpose and not TAP-specific — they take arbitrary async closures.

### Out of Scope

- Rate limiting (token bucket) — implemented in `security::rate_limit`, see
  [[018-security-hardening]]
- Any specific merchant-call integration of these primitives — this spec
  documents the primitives themselves, not where they are or aren't yet wired
  into `mcp` tool functions

## 2. Data Model

| Entity | Description | Key Attributes |
|--------|-------------|-----------------|
| `RetryPolicy` | Exponential backoff configuration | `max_attempts, initial_delay, max_delay, backoff_multiplier`; `Default`: `3, 100ms, 5s, 2.0` |
| `CircuitState` | Three-state enum, `#[repr(u8)]` for atomic storage | `Closed = 0, Open = 1, HalfOpen = 2` |
| `CircuitBreakerConfig` | Thresholds and timeout | `failure_threshold, success_threshold, reset_timeout`; defaults `failure_threshold=5, success_threshold=2` |
| `CircuitBreaker` | Atomic state machine wrapping an operation | internally `AtomicU8`/`AtomicU64` counters + `tokio::sync::RwLock` |
| `CircuitBreakerError` | `thiserror` error type for breaker rejections | — |

## 3. Functional Requirements

| ID | Requirement | Priority |
|----|------------|----------|
| FR-1 | WHEN `retry_with_backoff` retries a failed operation THE SYSTEM SHALL compute the delay for attempt N as `initial_delay * backoff_multiplier^(N-1)`, capped at `max_delay` | must |
| FR-2 | WHEN `retry_with_backoff` reaches `max_attempts` without success THE SYSTEM SHALL return the last error, not retry further | must |
| FR-3 | WHEN a `CircuitBreaker` in `Closed` state observes `failure_threshold` consecutive failures THE SYSTEM SHALL transition to `Open` | must |
| FR-4 | WHEN a `CircuitBreaker` in `Open` state has been open for at least `reset_timeout` THE SYSTEM SHALL transition to `HalfOpen` on the next call attempt | must |
| FR-5 | WHEN a `CircuitBreaker` in `HalfOpen` state observes `success_threshold` consecutive successes THE SYSTEM SHALL transition to `Closed`; WHEN it observes any failure in `HalfOpen` THE SYSTEM SHALL transition back to `Open` | must |
| FR-6 | WHEN `is_retryable` classifies an error THE SYSTEM SHALL determine whether `retry_with_backoff` should attempt another call for that error kind | should |

## 4. Non-Functional Requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-1 | Concurrency | `CircuitBreaker` state is stored in atomics (`AtomicU8` state, `AtomicU64` counters) so concurrent callers observe consistent state without a full mutex on the hot path |
| NFR-2 | Testability | `retry.rs` and `circuit_breaker.rs` each carry inline `#[cfg(test)]` coverage plus doc-tests demonstrating state transitions |
| NFR-3 | Performance | No `criterion` benchmark exists for either primitive — not flagged as a Critical Path in `.claude/rules/continuous-improvement.md`, so this is a lower-priority gap than the `tap`/`jwe` benchmark gaps |

## 5. Edge Cases and Error Handling

| Scenario | Expected Behavior |
|----------|--------------------|
| `max_attempts = 1` | No retries occur; the first failure is returned immediately |
| Computed delay would exceed `max_delay` | Delay is capped at `max_delay`, not left unbounded |
| A call is attempted while the breaker is `Open` and `reset_timeout` has not yet elapsed | The call is rejected immediately via `CircuitBreakerError`, without invoking the wrapped operation |
| A single failure occurs while `HalfOpen` | Breaker reopens immediately (does not require reaching `failure_threshold` again while half-open) |

## 6. Agent Boundaries

### Always (without asking)
- Use `retry_with_backoff`/`CircuitBreaker` for new merchant-call resilience needs rather than hand-rolled retry loops

### Ask First
- Changing default `RetryPolicy`/`CircuitBreakerConfig` values — affects every current caller's behavior
- Wiring `CircuitBreaker` into a new call site that doesn't currently have one — worth confirming the failure mode is actually transient/circuit-appropriate

### Never
- Retry non-idempotent operations (e.g. payment submission) without confirming idempotency at the merchant/API level first

## 7. Open Questions

- `[NEEDS CLARIFICATION: which of the mcp tool functions in specs 014 currently have retry_with_backoff and/or CircuitBreaker wired in, versus relying on caller-side retry? This spec documents the primitives; a follow-up audit could map actual call-site adoption.]`

## 8. See Also

- [[MOC-specs]] — all specifications
- [[018-security-hardening]] — the sibling subsystem holding the token-bucket rate limiter (not this one)
- `tap-mcp-bridge/src/reliability/mod.rs` — module entry point and doc comment clarifying scope
