//! Integration tests for TAP-MCP bridge.
//!
//! Tests end-to-end flow from signature generation to HTTP request.

use ed25519_dalek::SigningKey;
use tap_mcp_bridge::{
    mcp::{CheckoutParams, checkout_with_tap},
    tap::{InteractionType, TapSigner},
};

#[test]
fn test_signature_generation_end_to_end() {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let signer = TapSigner::new(signing_key, "test-agent", "https://agent.example.com");

    let signature = signer
        .sign_request("POST", "merchant.com", "/checkout", b"test body", InteractionType::Checkout)
        .expect("signature generation should succeed");

    assert!(
        signature.signature.starts_with("sig1=:"),
        "signature should have correct format"
    );
    assert!(
        signature.signature_input.contains("created="),
        "signature input should contain timestamp"
    );
    assert!(
        signature.signature_input.contains("ed25519"),
        "signature should use ed25519 algorithm"
    );
    assert_eq!(
        signature.agent_directory, "https://agent.example.com",
        "agent directory should be preserved"
    );
}

#[tokio::test]
async fn test_checkout_with_invalid_url() {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let signer = TapSigner::new(signing_key, "test-agent", "https://agent.example.com");

    let params = CheckoutParams {
        merchant_url: "http://insecure.com".into(),
        consumer_id: "user-123".into(),
        intent: "payment".into(),
    };

    let result = checkout_with_tap(&signer, params).await;

    assert!(result.is_err(), "checkout with HTTP URL should fail");
}

#[tokio::test]
async fn test_checkout_params_validation() {
    let signing_key = SigningKey::from_bytes(&[1u8; 32]);
    let signer = TapSigner::new(signing_key, "test-agent", "https://agent.example.com");

    let params = CheckoutParams {
        merchant_url: "not a url".into(),
        consumer_id: "user-123".into(),
        intent: "payment".into(),
    };

    let result = checkout_with_tap(&signer, params).await;

    assert!(result.is_err(), "checkout with invalid URL should fail");
}
