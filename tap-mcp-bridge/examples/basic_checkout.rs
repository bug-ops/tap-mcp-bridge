//! Basic checkout example demonstrating TAP-MCP bridge usage.
//!
//! This example shows the simplest way to execute a TAP-authenticated checkout
//! with a merchant using the bridge library.
//!
//! # Running this example
//!
//! First, generate a signing key:
//! ```bash
//! openssl rand -hex 32
//! ```
//!
//! Then set the environment variable and run:
//! ```bash
//! export AGENT_SIGNING_KEY=<hex_from_above>
//! cargo run --example basic_checkout
//! ```

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::str_to_string,
    clippy::uninlined_format_args,
    reason = "examples are allowed to use println and simple formatting"
)]

use std::env;

use ed25519_dalek::SigningKey;
use tap_mcp_bridge::{
    mcp::{CheckoutParams, checkout_with_tap},
    tap::TapSigner,
};

/// Loads signing key from environment variable.
///
/// # Security Warning
///
/// This function demonstrates secure key loading for production use.
/// Never hardcode signing keys in source code or commit them to version control.
/// Always load keys from secure storage (HSM, secrets manager, environment).
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
    println!("TAP-MCP Bridge: Basic Checkout Example\n");

    println!("SECURITY NOTICE:");
    println!("  Never hardcode signing keys in production code");
    println!("  Always load from secure storage (HSM, secrets manager, environment)");
    println!("  Never commit signing keys to version control\n");

    // Step 1: Load agent signing key from environment
    println!("1. Loading Ed25519 signing key from environment...");
    let signing_key = load_signing_key()?;
    println!("   ✓ Signing key loaded securely");

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
        // ACRO contextual data
        country_code: "US".to_string(),
        zip: "94103".to_string(),
        ip_address: "192.168.1.100".to_string(),
        user_agent: "Mozilla/5.0 (X11; Linux x86_64)".to_string(),
        platform: "Linux".to_string(),
    };
    println!("   Merchant: {}", params.merchant_url);
    println!("   Consumer: {}", params.consumer_id);
    println!("   Intent: {}", params.intent);
    println!("   Location: {} {}", params.country_code, params.zip);

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
