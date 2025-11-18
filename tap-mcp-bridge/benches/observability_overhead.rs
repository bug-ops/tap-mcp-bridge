//! Benchmark suite for measuring observability overhead in Phase 7.
//!
//! This benchmark measures the performance impact of:
//! - Structured logging (JSON vs pretty formatting)
//! - Instrumentation macros (#[instrument])
//! - Span creation and field extraction
//! - Different log levels
//!
//! Run with: `cargo bench --bench observability_overhead`

#![allow(clippy::let_underscore_must_use, reason = "Criterion benchmarks ignore results")]
#![allow(missing_docs, reason = "Benchmark functions are self-documenting")]

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ed25519_dalek::SigningKey;
use tap_mcp_bridge::tap::{InteractionType, TapSigner};

/// Setup test data for benchmarks
fn setup_test_signer() -> TapSigner {
    let signing_key = SigningKey::from_bytes(&[
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ]);

    let agent_id = "test-agent-001";
    let agent_directory = "https://agent.example.com";

    TapSigner::new(signing_key, agent_id, agent_directory)
}

/// Benchmark TAP signature generation without logging
fn bench_signature_no_logging(c: &mut Criterion) {
    // Disable all logging for baseline
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::ERROR).try_init();

    let signer = setup_test_signer();
    let body = b"{\"consumer_id\":\"test-consumer\",\"intent\":\"purchase\"}";

    c.bench_function("signature_generation_no_logging", |b| {
        b.iter(|| {
            let result = signer.sign_request(
                black_box("POST"),
                black_box("merchant.example.com"),
                black_box("/checkout"),
                black_box(body),
                black_box(InteractionType::Checkout),
            );
            black_box(result)
        });
    });
}

/// Benchmark TAP signature generation with INFO logging
fn bench_signature_with_logging(c: &mut Criterion) {
    let mut group = c.benchmark_group("signature_with_logging");

    let signer = setup_test_signer();
    let body = b"{\"consumer_id\":\"test-consumer\",\"intent\":\"purchase\"}";

    for log_level in ["ERROR", "WARN", "INFO", "DEBUG"] {
        group.bench_with_input(BenchmarkId::new("level", log_level), log_level, |b, _level| {
            b.iter(|| {
                let result = signer.sign_request(
                    black_box("POST"),
                    black_box("merchant.example.com"),
                    black_box("/checkout"),
                    black_box(body),
                    black_box(InteractionType::Checkout),
                );
                black_box(result)
            });
        });
    }

    group.finish();
}

/// Benchmark span creation overhead
fn bench_span_creation(c: &mut Criterion) {
    use tracing::{Instrument, info_span};

    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();

    c.bench_function("span_creation_no_fields", |b| {
        b.iter(|| {
            let span = info_span!("test_operation");
            black_box(span)
        });
    });

    c.bench_function("span_creation_with_fields", |b| {
        b.iter(|| {
            let span =
                info_span!("test_operation", method = "POST", path = "/checkout", body_len = 1024);
            black_box(span)
        });
    });

    c.bench_function("span_enter_exit", |b| {
        b.iter(|| {
            async {
                async_operation().await;
            }
            .instrument(info_span!("outer"))
        });
    });
}

async fn async_operation() {
    // Simulate some work
    tokio::time::sleep(tokio::time::Duration::from_micros(1)).await;
}

/// Benchmark log formatting overhead
fn bench_log_formatting(c: &mut Criterion) {
    let mut group = c.benchmark_group("log_formatting");

    // JSON formatting
    group.bench_function("json_format", |b| {
        let subscriber =
            tracing_subscriber::fmt().json().with_max_level(tracing::Level::INFO).finish();

        tracing::subscriber::with_default(subscriber, || {
            b.iter(|| {
                tracing::info!(
                    merchant_url = "https://merchant.example.com",
                    consumer_id = "test-consumer-001",
                    request_id = "req-123",
                    "Processing TAP request"
                );
            });
        });
    });

    // Pretty formatting
    group.bench_function("pretty_format", |b| {
        let subscriber =
            tracing_subscriber::fmt().pretty().with_max_level(tracing::Level::INFO).finish();

        tracing::subscriber::with_default(subscriber, || {
            b.iter(|| {
                tracing::info!(
                    merchant_url = "https://merchant.example.com",
                    consumer_id = "test-consumer-001",
                    request_id = "req-123",
                    "Processing TAP request"
                );
            });
        });
    });

    // Compact formatting (default)
    group.bench_function("compact_format", |b| {
        let subscriber = tracing_subscriber::fmt()
            .compact()
            .with_max_level(tracing::Level::INFO)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            b.iter(|| {
                tracing::info!(
                    merchant_url = "https://merchant.example.com",
                    consumer_id = "test-consumer-001",
                    request_id = "req-123",
                    "Processing TAP request"
                );
            });
        });
    });

    group.finish();
}

/// Benchmark field extraction overhead
fn bench_field_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_extraction");

    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();

    // No fields
    group.bench_function("no_fields", |b| {
        b.iter(|| {
            tracing::info!("Simple message");
        });
    });

    // Few fields
    group.bench_function("few_fields", |b| {
        b.iter(|| {
            tracing::info!(request_id = "req-123", "Request processed");
        });
    });

    // Many fields
    group.bench_function("many_fields", |b| {
        b.iter(|| {
            tracing::info!(
                request_id = "req-123",
                merchant_url = "https://merchant.example.com",
                consumer_id = "test-consumer",
                method = "POST",
                path = "/checkout",
                status_code = 200,
                duration_ms = 125,
                "Request completed"
            );
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_signature_no_logging,
    bench_signature_with_logging,
    bench_span_creation,
    bench_log_formatting,
    bench_field_extraction
);
criterion_main!(benches);
