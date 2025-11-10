//! Direct TAP signature generation example.
//!
//! This example demonstrates low-level TAP signature generation
//! without using MCP tools. Useful for custom integrations.
//!
//! # Running this example
//!
//! ```bash
//! cargo run --example signature_generation
//! ```

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::str_to_string,
    clippy::uninlined_format_args,
    clippy::string_slice,
    reason = "examples are allowed to use println and simple formatting"
)]

use ed25519_dalek::SigningKey;
use tap_mcp_bridge::tap::{InteractionType, TapSigner};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TAP-MCP Bridge: Signature Generation Example\n");

    // Step 1: Create Ed25519 signing key
    println!("1. Creating Ed25519 signing key...");
    let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    println!("   ✓ Key created");

    // Step 2: Initialize TAP signer
    println!("\n2. Initializing TAP signer...");
    let signer = TapSigner::new(signing_key, "agent-123", "https://agent-directory.example.com");
    println!("   Agent ID: agent-123");
    println!("   Agent Directory: https://agent-directory.example.com");

    // Step 3: Generate signature for a POST request
    println!("\n3. Generating RFC 9421 signature for POST request...");
    let request_body = br#"{"amount":99.99,"currency":"USD"}"#;

    let signature = signer.sign_request(
        "POST",
        "merchant.example.com",
        "/api/checkout",
        request_body,
        InteractionType::Checkout,
    )?;

    println!("   ✓ Signature generated successfully\n");

    // Display signature components
    println!("   HTTP Headers to include:");
    println!("   ┌─────────────────────────────────────────────────────────");
    println!("   │ Signature: {}", signature.signature);
    println!("   │");
    println!("   │ Signature-Input: {}", signature.signature_input);
    println!("   │");
    println!("   │ Signature-Agent: {}", signature.agent_directory);
    println!("   └─────────────────────────────────────────────────────────");

    // Step 4: Generate signature for a GET request
    println!("\n4. Generating signature for GET request (browsing)...");
    let signature = signer.sign_request(
        "GET",
        "merchant.example.com",
        "/catalog",
        b"",
        InteractionType::Browse,
    )?;

    println!("   ✓ Signature generated\n");
    println!("   Signature format: sig1=:<base64-encoded-signature>:");
    println!("   Signature length: {} bytes", signature.signature.len());

    // Step 5: Demonstrate signature components
    println!("\n5. Understanding signature components...");
    println!("   Covered components (per RFC 9421):");
    println!("   - @method:        HTTP method (POST, GET, etc.)");
    println!("   - @authority:     Target merchant domain");
    println!("   - @path:          Request path");
    println!("   - content-digest: SHA-256 hash of request body");
    println!();
    println!("   Signature parameters:");
    println!("   - created:        Unix timestamp");
    println!("   - keyid:          JWK thumbprint (RFC 7638)");
    println!("   - alg:            ed25519");

    // Step 6: Multiple signatures for different merchants
    println!("\n6. Generating signatures for multiple merchants...");
    let merchants = vec![
        ("merchant-a.example.com", "/checkout"),
        ("merchant-b.example.com", "/api/payment"),
        ("merchant-c.example.com", "/transaction"),
    ];

    for (authority, path) in merchants {
        let sig = signer.sign_request("POST", authority, path, b"{}", InteractionType::Checkout)?;
        println!("   ✓ Signed request to {}{}", authority, path);
        println!("     Signature preview: {}...", &sig.signature[..30]);
    }

    println!("\n✓ Signature generation example complete");
    println!("\nNext steps:");
    println!("  - Add these headers to your HTTP requests");
    println!("  - Merchant verifies signature using agent's public key");
    println!("  - Agent directory serves public keys via JWKS endpoint");

    Ok(())
}
