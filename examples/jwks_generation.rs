//! JWKS generation example for TAP agent directory.
//!
//! Demonstrates how to generate and serve agent public keys
//! in JWKS format for merchant verification.

#![allow(clippy::print_stdout, reason = "examples need output")]
#![allow(clippy::use_debug, reason = "examples need output")]

use ed25519_dalek::SigningKey;
use tap_mcp_bridge::tap::TapSigner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TAP-MCP Bridge: JWKS Generation Example\n");

    // Create agent signing key (in production: load from secure storage)
    let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

    // Generate JWKS for public key distribution
    println!("Generating JWKS for agent directory...");
    let jwks = signer.generate_jwks();

    // Serialize to JSON
    let json = jwks.to_json()?;

    println!("\nJWKS for /.well-known/http-message-signatures-directory:");
    println!("{json}");

    println!("\n✓ JWKS generated successfully");
    println!("\nNext steps:");
    println!("  - Serve this JWKS at /.well-known/http-message-signatures-directory");
    println!("  - Merchants will use this to verify agent signatures");
    println!("  - kid in JWKS must match keyid in HTTP signatures");

    Ok(())
}
