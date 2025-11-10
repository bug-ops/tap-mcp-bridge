//! Error handling example showing how to handle different error types.
//!
//! This example demonstrates proper error handling patterns for TAP-MCP bridge operations,
//! including validation errors, network errors, and recovery strategies.
//!
//! # Running this example
//!
//! ```bash
//! cargo run --example error_handling
//! ```

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::str_to_string,
    clippy::uninlined_format_args,
    reason = "examples are allowed to use println and simple formatting"
)]

use ed25519_dalek::SigningKey;
use tap_mcp_bridge::{
    error::BridgeError,
    mcp::{CheckoutParams, checkout_with_tap},
    tap::TapSigner,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TAP-MCP Bridge: Error Handling Example\n");

    let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

    // Example 1: Invalid URL (HTTP instead of HTTPS)
    println!("Example 1: Testing HTTP URL (should fail)");
    let params = CheckoutParams {
        merchant_url: "http://merchant.example.com".to_string(),
        consumer_id: "user-123".to_string(),
        intent: "payment".to_string(),
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
        merchant_url: "https://localhost:8080/checkout".to_string(),
        consumer_id: "user-123".to_string(),
        intent: "payment".to_string(),
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
        merchant_url: "https://merchant.example.com/checkout".to_string(),
        consumer_id: "user-123".to_string(),
        intent: "payment".to_string(),
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
        merchant_url: "https://merchant.example.com/api/checkout".to_string(),
        consumer_id: "user-789".to_string(),
        intent: "browsing".to_string(),
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
    }
}
