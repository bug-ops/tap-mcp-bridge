//! ID token (JWT) generation example for TAP authentication.
//!
//! This example demonstrates how to generate JWT ID tokens for TAP agent
//! authentication. ID tokens authenticate the agent and delegate consumer
//! authority to the agent for TAP-protected operations.
//!
//! Run with: `cargo run --example id_token_generation`

#![allow(
    clippy::print_stdout,
    clippy::uninlined_format_args,
    reason = "examples demonstrate output to console"
)]

use ed25519_dalek::SigningKey;
use tap_mcp_bridge::tap::TapSigner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TAP-MCP Bridge: ID Token Generation Example\n");

    // Create agent signing key (in production, load from secure storage)
    let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");

    // Generate ID token for consumer authentication
    let token =
        signer.generate_id_token("user-456", "https://merchant.example.com", "nonce-unique-123")?;

    println!("ID Token (JWT):");
    println!("{}\n", token.token);

    println!("Token Claims:");
    println!("  sub (consumer):  {}", token.claims.sub);
    println!("  iss (agent):     {}", token.claims.iss);
    println!("  aud (merchant):  {}", token.claims.aud);
    println!("  nonce:           {}", token.claims.nonce);
    println!("  iat:             {}", token.claims.iat);
    println!(
        "  exp:             {} ({}s from now)",
        token.claims.exp,
        token.claims.exp - token.claims.iat
    );

    if let Some(dir) = &token.claims.agent_directory {
        println!("  agent_directory: {}", dir);
    }

    // Verify JWT structure
    let parts: Vec<&str> = token.token.split('.').collect();
    println!("\nJWT Structure:");
    println!("  Parts:           {}", parts.len());
    println!("  Header length:   {} bytes", parts[0].len());
    println!("  Payload length:  {} bytes", parts[1].len());
    println!("  Signature length: {} bytes", parts[2].len());

    println!("\n✓ ID token generated successfully");

    println!("\nUsage:");
    println!("  - Include in Authorization header: Bearer {}", token.token);
    println!("  - Or include in request body for TAP operations");
    println!("  - Merchant verifies using agent's public key (JWKS)");
    println!("  - Nonce should match HTTP signature nonce for correlation");

    println!("\nIntegration with HTTP Signatures:");
    println!("  1. Generate nonce: uuid::Uuid::new_v4()");
    println!("  2. Create HTTP Message Signature with nonce");
    println!("  3. Create ID Token with same nonce");
    println!("  4. Merchant verifies both signatures correlate via nonce");

    Ok(())
}
