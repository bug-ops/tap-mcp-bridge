//! ACRO generation example for TAP consumer recognition.
//!
//! This example demonstrates how to generate an Agentic Consumer Recognition
//! Object (ACRO) for TAP authentication. The ACRO identifies the consumer on
//! whose behalf the agent is acting and provides verification of consumer identity.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example acro_generation
//! ```
#![allow(clippy::print_stdout, reason = "example demonstrates output")]
#![allow(clippy::uninlined_format_args, reason = "explicit format for clarity")]
#![allow(clippy::string_slice, reason = "example uses safe slicing")]

use ed25519_dalek::SigningKey;
use tap_mcp_bridge::tap::{
    TapSigner,
    acro::{ContextualData, DeviceData},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TAP-MCP Bridge: ACRO Generation Example\n");
    println!("========================================\n");

    // Create agent signing key (in production, load from secure storage)
    let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    let signer = TapSigner::new(
        signing_key,
        "agent-123",
        "https://agent.example.com/.well-known/http-message-signatures-directory",
    );

    println!("1. Agent Configuration");
    println!("   Agent ID: agent-123");
    println!(
        "   Directory: https://agent.example.com/.well-known/http-message-signatures-directory\n"
    );

    // Generate nonce (shared between HTTP signature, ID token, and ACRO)
    let nonce = uuid::Uuid::new_v4().to_string();
    println!("2. Generated Nonce (for replay protection)");
    println!("   Nonce: {}\n", nonce);

    // Generate ID token first (required by ACRO)
    let id_token = signer.generate_id_token("user-456", "https://merchant.example.com", &nonce)?;

    println!("3. Generated ID Token (JWT)");
    println!("   Token: {}...", &id_token.token[..50]);
    println!("   Consumer: {}", id_token.claims.sub);
    println!("   Issuer: {}", id_token.claims.iss);
    println!("   Audience: {}", id_token.claims.aud);
    println!("   Expires: {} (Unix timestamp)\n", id_token.claims.exp);

    // Create contextual data (consumer location and device info)
    let contextual_data = ContextualData {
        country_code: "US".to_owned(),
        zip: "94103".to_owned(),
        ip_address: "192.168.1.100".to_owned(),
        device_data: DeviceData {
            user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
                         Chrome/120.0.0.0 Safari/537.36"
                .to_owned(),
            platform: "Linux x86_64".to_owned(),
        },
    };

    println!("4. Contextual Data (Consumer Location & Device)");
    println!("   Country: {}", contextual_data.country_code);
    println!("   ZIP: {}", contextual_data.zip);
    println!("   IP Address: {}", contextual_data.ip_address);
    println!("   User Agent: {}", contextual_data.device_data.user_agent);
    println!("   Platform: {}\n", contextual_data.device_data.platform);

    // Generate ACRO (signs all fields with Ed25519)
    let acro = signer.generate_acro(&nonce, &id_token.token, contextual_data)?;

    println!("5. Generated ACRO (Agentic Consumer Recognition Object)");
    println!("   Nonce: {}", acro.nonce);
    println!("   ID Token: {}...", &acro.id_token[..50]);
    println!("   Kid (Key ID): {}", acro.kid);
    println!("   Algorithm: {}", acro.alg);
    println!("   Country: {}", acro.contextual_data.country_code);
    println!("   ZIP: {}", acro.contextual_data.zip);
    println!("   Signature: {}...\n", &acro.signature[..40]);

    // Serialize ACRO to JSON for transmission to merchant
    let acro_json = serde_json::to_string_pretty(&acro)?;
    println!("6. ACRO JSON (ready for merchant transmission)");
    println!("{}\n", acro_json);

    println!("========================================");
    println!("✓ ACRO generated successfully!");
    println!("✓ Ready for inclusion in TAP POST/GET request body");
    println!("✓ Nonce matches across HTTP signature, ID token, and ACRO");
    println!("✓ Signature is verifiable with agent's public key");

    Ok(())
}
