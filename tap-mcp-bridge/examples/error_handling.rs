//! Error handling example showing how to handle different error types.
//!
//! This example demonstrates proper error handling patterns for TAP-MCP bridge operations,
//! including validation errors, network errors, and recovery strategies.
//!
//! # Running this example
//!
//! First, generate and set a signing key:
//! ```bash
//! export AGENT_SIGNING_KEY=$(openssl rand -hex 32)
//! cargo run --example error_handling
//! ```

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::str_to_string,
    clippy::uninlined_format_args,
    clippy::use_debug,
    reason = "examples are allowed to use println and simple formatting"
)]

use std::env;

use ed25519_dalek::SigningKey;
use tap_mcp_bridge::{
    error::BridgeError,
    mcp::{CheckoutParams, checkout_with_tap},
    tap::TapSigner,
};

/// Loads signing key from environment variable.
///
/// # Security Warning
///
/// Never hardcode signing keys. Always load from secure storage.
fn load_signing_key() -> Result<SigningKey, Box<dyn std::error::Error>> {
    let key_hex = env::var("AGENT_SIGNING_KEY").map_err(|_| {
        "AGENT_SIGNING_KEY environment variable not set.\nGenerate a key with: openssl rand -hex \
         32\nSet it with: export AGENT_SIGNING_KEY=<hex>"
    })?;

    let key_bytes = hex::decode(&key_hex)?;

    if key_bytes.len() != 32 {
        return Err("AGENT_SIGNING_KEY must be exactly 32 bytes (64 hex characters)".into());
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    Ok(SigningKey::from_bytes(&key_array))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TAP-MCP Bridge: Error Handling Example\n");

    println!("SECURITY NOTICE:");
    println!("  Never hardcode signing keys in production code");
    println!("  Always load from secure storage (HSM, secrets manager, environment)");
    println!("  Never commit signing keys to version control\n");

    let signing_key = load_signing_key()?;
    let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

    // Example 1: Invalid URL (HTTP instead of HTTPS)
    println!("Example 1: Testing HTTP URL (should fail)");
    let params = CheckoutParams {
        merchant_url: "http://merchant.example.com".to_owned(),
        consumer_id: "user-123".to_owned(),
        intent: "payment".to_owned(),
        country_code: "US".to_owned(),
        zip: "94103".to_owned(),
        ip_address: "192.168.1.100".to_owned(),
        user_agent: "Mozilla/5.0 (X11; Linux x86_64)".to_owned(),
        platform: "Linux".to_owned(),
    };

    match checkout_with_tap(&signer, params).await {
        Ok(_) => println!("   Unexpected success"),
        Err(BridgeError::InvalidMerchantUrl(msg)) => {
            println!("   ✓ Caught validation error: {}", msg);
            println!("   Recovery: Use HTTPS URL instead");
        }
        Err(e) => println!("   Unexpected error: {}", e),
    }

    // Example 2: Localhost URL (security restriction)
    println!("\nExample 2: Testing localhost URL (should fail)");
    let params = CheckoutParams {
        merchant_url: "https://localhost:8080/checkout".to_owned(),
        consumer_id: "user-123".to_owned(),
        intent: "payment".to_owned(),
        country_code: "US".to_owned(),
        zip: "94103".to_owned(),
        ip_address: "192.168.1.100".to_owned(),
        user_agent: "Mozilla/5.0 (X11; Linux x86_64)".to_owned(),
        platform: "Linux".to_owned(),
    };

    match checkout_with_tap(&signer, params).await {
        Ok(_) => println!("   Unexpected success"),
        Err(BridgeError::InvalidMerchantUrl(msg)) => {
            println!("   ✓ Caught security validation: {}", msg);
            println!("   Recovery: Use public HTTPS URL");
        }
        Err(e) => println!("   Unexpected error: {}", e),
    }

    // Example 3: Network timeout (unreachable host)
    println!("\nExample 3: Testing unreachable host (network timeout)");
    let params = CheckoutParams {
        merchant_url: "https://merchant.example.com/checkout".to_owned(),
        consumer_id: "user-123".to_owned(),
        intent: "payment".to_owned(),
        country_code: "US".to_owned(),
        zip: "94103".to_owned(),
        ip_address: "192.168.1.100".to_owned(),
        user_agent: "Mozilla/5.0 (X11; Linux x86_64)".to_owned(),
        platform: "Linux".to_owned(),
    };

    match checkout_with_tap(&signer, params).await {
        Ok(result) => {
            println!("   ✓ Success: {}", result.status);
        }
        Err(BridgeError::HttpError(e)) => {
            println!("   ✓ Caught network error: {}", e);
            println!("   Recovery strategies:");
            println!("   - Retry with exponential backoff");
            println!("   - Check network connectivity");
            println!("   - Verify merchant URL is accessible");
            println!("   - Check firewall/proxy settings");
        }
        Err(BridgeError::MerchantError(msg)) => {
            println!("   ✓ Merchant protocol error: {}", msg);
            println!("   Recovery: Contact merchant support");
        }
        Err(e) => {
            println!("   Other error: {}", e);
        }
    }

    // Example 4: Comprehensive error matching
    println!("\nExample 4: Comprehensive error pattern matching");
    let result = checkout_with_tap(&signer, CheckoutParams {
        merchant_url: "https://merchant.example.com/api/checkout".to_owned(),
        consumer_id: "user-789".to_owned(),
        intent: "browsing".to_owned(),
        country_code: "US".to_owned(),
        zip: "94103".to_owned(),
        ip_address: "192.168.1.100".to_owned(),
        user_agent: "Mozilla/5.0 (X11; Linux x86_64)".to_owned(),
        platform: "Linux".to_owned(),
    })
    .await;

    handle_checkout_result(result);

    println!("\n✓ Error handling examples complete");
    Ok(())
}

/// Demonstrates comprehensive error handling with recovery guidance.
fn handle_checkout_result(result: Result<tap_mcp_bridge::mcp::CheckoutResult, BridgeError>) {
    match result {
        Ok(checkout) => {
            println!("   ✓ Checkout successful!");
            println!("   Status: {}", checkout.status);
            println!("   Message: {}", checkout.message);
        }

        // Validation errors - fix input and retry
        Err(BridgeError::InvalidMerchantUrl(msg)) => {
            eprintln!("   ✗ Invalid merchant URL: {}", msg);
            eprintln!("   → Fix: Ensure URL is HTTPS and not localhost");
            eprintln!("   → Retry: After correcting the URL");
        }

        Err(BridgeError::InvalidConsumerId(msg)) => {
            eprintln!("   ✗ Invalid consumer ID: {}", msg);
            eprintln!("   → Fix: Use only alphanumeric, hyphen, and underscore characters");
            eprintln!("   → Fix: Ensure ID is 1-64 characters");
            eprintln!("   → Retry: After correcting the consumer ID");
        }

        // Network errors - retry with backoff
        Err(BridgeError::HttpError(e)) => {
            eprintln!("   ✗ Network error: {}", e);
            eprintln!("   → Fix: Check network connectivity");
            eprintln!("   → Retry: Use exponential backoff strategy");
            eprintln!("   → Timeout: Default is 30 seconds");
        }

        // Signature errors - check key configuration
        Err(BridgeError::SignatureError(msg)) => {
            eprintln!("   ✗ Signature generation failed: {}", msg);
            eprintln!("   → Fix: Verify Ed25519 signing key is valid");
            eprintln!("   → Fix: Check system time is correct");
            eprintln!("   → Retry: After fixing key/time issues");
        }

        // Cryptographic errors - check key material
        Err(BridgeError::CryptoError(msg)) => {
            eprintln!("   ✗ Cryptographic error: {}", msg);
            eprintln!("   → Fix: Verify key material is not corrupted");
            eprintln!("   → Fix: Ensure system has sufficient entropy");
        }

        // Merchant errors - contact merchant support
        Err(BridgeError::MerchantError(msg)) => {
            eprintln!("   ✗ Merchant protocol error: {}", msg);
            eprintln!("   → Fix: Contact merchant support");
            eprintln!("   → Fix: Verify TAP implementation compatibility");
            eprintln!("   → Note: This is usually a merchant-side issue");
        }

        // Security errors
        Err(BridgeError::ReplayAttack) => {
            eprintln!("   ✗ Replay attack detected");
            eprintln!("   → Fix: Ensure nonces are unique");
            eprintln!("   → Fix: Check for duplicate requests");
        }

        Err(BridgeError::RequestTooOld(time)) => {
            eprintln!("   ✗ Request too old: {time:?}");
            eprintln!("   → Fix: Check system clock synchronization");
            eprintln!("   → Fix: Ensure request is sent immediately after signing");
        }

        Err(BridgeError::RateLimitExceeded) => {
            eprintln!("   ✗ Rate limit exceeded");
            eprintln!("   → Fix: Reduce request frequency");
            eprintln!("   → Fix: Wait before retrying");
        }

        Err(BridgeError::CircuitOpen) => {
            eprintln!("   ✗ Circuit breaker is open");
            eprintln!("   → Fix: Wait for circuit breaker to recover");
            eprintln!("   → Fix: Check merchant availability");
        }

        Err(BridgeError::InvalidInput(msg)) => {
            eprintln!("   ✗ Invalid input: {msg}");
            eprintln!("   → Fix: Check input parameter constraints");
            eprintln!("   → Fix: Ensure no null bytes or invalid characters");
        }

        Err(BridgeError::MerchantConfigError(msg)) => {
            eprintln!("   ✗ Merchant configuration error: {msg}");
            eprintln!("   → Fix: Check merchant configuration TOML file");
            eprintln!("   → Fix: Verify all required fields are present");
        }

        Err(BridgeError::FieldMappingError(msg)) => {
            eprintln!("   ✗ Field mapping error: {msg}");
            eprintln!("   → Fix: Check field mapping configuration");
            eprintln!("   → Fix: Ensure mappings match actual API fields");
        }

        Err(BridgeError::TransformationError(msg)) => {
            eprintln!("   ✗ Response transformation error: {msg}");
            eprintln!("   → Fix: Check merchant response format");
            eprintln!("   → Fix: Verify custom transformers are correct");
        }

        Err(BridgeError::TransportError(msg)) => {
            eprintln!("   ✗ Transport error: {msg}");
            eprintln!("   → Fix: Check transport configuration");
            eprintln!("   → Fix: Verify merchant supports selected protocol");
        }

        Err(BridgeError::UnsupportedProtocol(msg)) => {
            eprintln!("   ✗ Unsupported protocol: {msg}");
            eprintln!("   → Fix: Enable required feature flags");
            eprintln!("   → Fix: Use a supported transport protocol");
        }
    }
}
