//! Merchant catalog browsing example.
//!
//! This example demonstrates how to browse a merchant's catalog
//! using TAP-authenticated requests.
//!
//! # Running this example
//!
//! First, generate and set a signing key:
//! ```bash
//! export AGENT_SIGNING_KEY=$(openssl rand -hex 32)
//! cargo run --example browse_catalog
//! ```

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::str_to_string,
    clippy::uninlined_format_args,
    clippy::string_slice,
    reason = "examples are allowed to use println and simple formatting"
)]

use std::env;

use ed25519_dalek::SigningKey;
use tap_mcp_bridge::{
    mcp::{BrowseParams, browse_merchant},
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
    println!("TAP-MCP Bridge: Browse Merchant Catalog Example\n");

    println!("SECURITY NOTICE:");
    println!("  Never hardcode signing keys in production code");
    println!("  Always load from secure storage (HSM, secrets manager, environment)");
    println!("  Never commit signing keys to version control\n");

    // Step 1: Load signing key
    println!("1. Loading signing key from environment...");
    let signing_key = load_signing_key()?;
    println!("   ✓ Key loaded securely");

    // Step 2: Create TAP signer
    println!("\n2. Creating TAP signer...");
    let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
    println!("   ✓ TAP signer initialized");

    // Step 3: Browse catalog for a consumer
    println!("\n3. Browsing merchant catalog...");
    let params = BrowseParams {
        merchant_url: "https://merchant.example.com".to_string(),
        consumer_id: "user-456".to_string(),
    };

    println!("   Merchant: {}", params.merchant_url);
    println!("   Consumer: {}", params.consumer_id);

    // Step 4: Execute browse request with TAP authentication
    println!("\n4. Sending TAP-signed browse request...");
    match browse_merchant(&signer, params).await {
        Ok(result) => {
            println!("   ✓ Browse successful!");
            println!("\n   Response:");
            println!("   Status: {}", result.status);
            println!("   Data: {}", result.data);
        }
        Err(e) => {
            eprintln!("   ✗ Browse failed: {}", e);
            eprintln!("\n   This is expected when running against example.com");
            eprintln!("   In production, the merchant would return catalog data.");
        }
    }

    // Example: Browse multiple merchants
    println!("\n5. Browsing multiple merchants sequentially...");
    let merchants = vec![
        "https://merchant-a.example.com",
        "https://merchant-b.example.com",
        "https://merchant-c.example.com",
    ];

    for merchant_url in merchants {
        println!("\n   Browsing: {}", merchant_url);
        let params = BrowseParams {
            merchant_url: merchant_url.to_string(),
            consumer_id: "user-456".to_string(),
        };

        match browse_merchant(&signer, params).await {
            Ok(result) => {
                println!("   ✓ Success - Status: {}", result.status);
                println!("   Data preview: {}", &result.data[..result.data.len().min(50)]);
            }
            Err(e) => {
                eprintln!("   ✗ Failed: {}", e);
            }
        }
    }

    println!("\n✓ Browse catalog example complete");
    Ok(())
}
