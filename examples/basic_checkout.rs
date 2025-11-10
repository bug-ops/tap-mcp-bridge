//! Basic checkout example demonstrating TAP-MCP bridge usage.
//!
//! This example shows the simplest way to execute a TAP-authenticated checkout
//! with a merchant using the bridge library.
//!
//! # Running this example
//!
//! ```bash
//! cargo run --example basic_checkout
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
    mcp::{CheckoutParams, checkout_with_tap},
    tap::TapSigner,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TAP-MCP Bridge: Basic Checkout Example\n");

    // Step 1: Create agent signing key
    // In production, load this from secure storage (HSM, environment variable, etc.)
    println!("1. Creating Ed25519 signing key...");
    let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    println!("   ✓ Signing key created");

    // Step 2: Create TAP signer
    println!("\n2. Creating TAP signer...");
    let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
    println!("   ✓ TAP signer initialized");

    // Step 3: Define checkout parameters
    println!("\n3. Preparing checkout parameters...");
    let params = CheckoutParams {
        merchant_url: "https://merchant.example.com".to_string(),
        consumer_id: "user-456".to_string(),
        intent: "payment".to_string(),
    };
    println!("   Merchant: {}", params.merchant_url);
    println!("   Consumer: {}", params.consumer_id);
    println!("   Intent: {}", params.intent);

    // Step 4: Execute TAP-authenticated checkout
    println!("\n4. Executing checkout with TAP signature...");
    match checkout_with_tap(&signer, params).await {
        Ok(result) => {
            println!("   ✓ Checkout successful!");
            println!("\n   Response Details:");
            println!("   - Status: {}", result.status);
            println!("   - Message: {}", result.message);
        }
        Err(e) => {
            eprintln!("   ✗ Checkout failed: {}", e);
            eprintln!("\n   This is expected when running against example.com");
            eprintln!("   In production, use a real TAP-enabled merchant URL.");
        }
    }

    println!("\n✓ Example complete");
    Ok(())
}
