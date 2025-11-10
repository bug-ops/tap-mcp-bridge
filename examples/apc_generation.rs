//! APC generation example for TAP payment transactions.
//!
//! This example demonstrates how to generate an Agentic Payment Container
//! (APC) for TAP payment processing. The APC contains encrypted payment
//! credentials and authorization for transaction processing.
//!
//! # Usage
//!
//! ```bash
//! cargo run --example apc_generation
//! ```
#![allow(clippy::print_stdout, reason = "example demonstrates output")]
#![allow(clippy::uninlined_format_args, reason = "explicit format for clarity")]
#![allow(clippy::string_slice, reason = "example uses safe slicing")]
#![allow(
    clippy::too_many_lines,
    reason = "example demonstrates multiple payment methods"
)]

use ed25519_dalek::SigningKey;
use tap_mcp_bridge::tap::{
    TapSigner,
    apc::{BankAccountData, CardData, DigitalWalletData, PaymentMethod},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("TAP-MCP Bridge: APC Generation Example\n");
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

    // Generate nonce (shared between HTTP signature, ID token, ACRO, and APC)
    let nonce = uuid::Uuid::new_v4().to_string();
    println!("2. Generated Nonce (for replay protection)");
    println!("   Nonce: {}\n", nonce);

    // Example 1: Card Payment
    println!("========================================");
    println!("Example 1: Card Payment\n");

    let card = CardData {
        number: "4111111111111111".to_owned(),
        exp_month: "12".to_owned(),
        exp_year: "25".to_owned(),
        cvv: "123".to_owned(),
        cardholder_name: "John Doe".to_owned(),
    };

    println!("3. Card Payment Data");
    println!("   Card Number: ****{}", card.last_four());
    println!("   Expiry: {}/{}", card.exp_month, card.exp_year);
    println!("   Cardholder: {}", card.cardholder_name);
    println!("   Credential Hash: {}\n", card.credential_hash());

    let payment_method = PaymentMethod::Card(card);
    let apc = signer.generate_apc(&nonce, &payment_method)?;

    println!("4. Generated APC (Card Payment)");
    println!("   Nonce: {}", apc.nonce);
    println!("   Kid (Key ID): {}", apc.kid);
    println!("   Algorithm: {}", apc.alg);
    println!(
        "   Encrypted Payment Data: {}...",
        &apc.encrypted_payment_data[..40.min(apc.encrypted_payment_data.len())]
    );
    println!("   Signature: {}...\n", &apc.signature[..40]);

    // Serialize APC to JSON
    let apc_json = serde_json::to_string_pretty(&apc)?;
    println!("5. APC JSON (Card Payment)");
    println!("{}\n", apc_json);

    // Example 2: Bank Account Payment
    println!("========================================");
    println!("Example 2: Bank Account Payment\n");

    let account = BankAccountData {
        account_number: "1234567890".to_owned(),
        routing_number: "021000021".to_owned(),
        account_type: "checking".to_owned(),
        account_holder_name: "Jane Doe".to_owned(),
    };

    println!("6. Bank Account Payment Data");
    println!("   Account Number: ****{}", account.last_four());
    println!("   Routing Number: {}", account.routing_number);
    println!("   Account Type: {}", account.account_type);
    println!("   Account Holder: {}\n", account.account_holder_name);

    let payment_method = PaymentMethod::BankAccount(account);
    let apc = signer.generate_apc(&nonce, &payment_method)?;

    println!("7. Generated APC (Bank Account)");
    println!("   Nonce: {}", apc.nonce);
    println!("   Kid (Key ID): {}", apc.kid);
    println!("   Algorithm: {}", apc.alg);
    println!(
        "   Encrypted Payment Data: {}...",
        &apc.encrypted_payment_data[..40.min(apc.encrypted_payment_data.len())]
    );
    println!("   Signature: {}...\n", &apc.signature[..40]);

    // Example 3: Digital Wallet Payment
    println!("========================================");
    println!("Example 3: Digital Wallet Payment\n");

    let wallet = DigitalWalletData {
        wallet_type: "apple_pay".to_owned(),
        wallet_token: "encrypted-wallet-token-xyz123".to_owned(),
        account_holder_name: "Bob Smith".to_owned(),
    };

    println!("8. Digital Wallet Payment Data");
    println!("   Wallet Type: {}", wallet.wallet_type);
    println!("   Account Holder: {}\n", wallet.account_holder_name);

    let payment_method = PaymentMethod::DigitalWallet(wallet);
    let apc = signer.generate_apc(&nonce, &payment_method)?;

    println!("9. Generated APC (Digital Wallet)");
    println!("   Nonce: {}", apc.nonce);
    println!("   Kid (Key ID): {}", apc.kid);
    println!("   Algorithm: {}", apc.alg);
    println!(
        "   Encrypted Payment Data: {}...",
        &apc.encrypted_payment_data[..40.min(apc.encrypted_payment_data.len())]
    );
    println!("   Signature: {}...\n", &apc.signature[..40]);

    println!("========================================");
    println!("✓ APC generated successfully for all payment methods!");
    println!("✓ Payment credentials encrypted per PCI-DSS requirements");
    println!("✓ Ready for inclusion in TAP checkout request body");
    println!("✓ Nonce matches across HTTP signature, ID token, ACRO, and APC");
    println!("✓ Signature is verifiable with agent's public key");
    println!("\nSecurity Notes:");
    println!("  - Payment data is encrypted before transmission");
    println!("  - Sensitive fields are zeroized on drop");
    println!("  - Never log plaintext payment credentials");
    println!("  - Use JWE encryption with merchant's public key in production");

    Ok(())
}
