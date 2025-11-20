use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use crate::tap::{InteractionType, TapSigner, TapVerifier};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn test_signature_verification_roundtrip(
        seed in any::<[u8; 32]>(),
        agent_id in "[a-zA-Z0-9-_]{1,64}",
        agent_directory in "https://[a-z0-9]+\\.com",
        method in "GET|POST|PUT|DELETE",
        authority in "[a-z0-9]+\\.com",
        path in "/[a-z0-9/]+",
        body in any::<Vec<u8>>(),
    ) {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let signer = TapSigner::new(signing_key, &agent_id, &agent_directory);
        let verifier = TapVerifier::new(1000);

        // Generate signature
        let signature = signer.sign_request(
            &method,
            &authority,
            &path,
            &body,
            InteractionType::Checkout,
        ).expect("Signature generation failed");

        // Verify signature
        let result = verifier.verify_request(
            &method,
            &authority,
            &path,
            &body,
            &signature.signature,
            &signature.signature_input,
            &verifying_key,
        );

        prop_assert!(result.is_ok(), "Verification failed: {:?}", result.err());
    }

    #[test]
    fn test_replay_protection_property(
        seed in any::<[u8; 32]>(),
        agent_id in "[a-zA-Z0-9-_]{1,64}",
        agent_directory in "https://[a-z0-9]+\\.com",
        method in "GET|POST",
        authority in "[a-z0-9]+\\.com",
        path in "/[a-z0-9/]+",
        body in any::<Vec<u8>>(),
    ) {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let signer = TapSigner::new(signing_key, &agent_id, &agent_directory);
        let verifier = TapVerifier::new(1000);

        let signature = signer.sign_request(
            &method,
            &authority,
            &path,
            &body,
            InteractionType::Checkout,
        ).unwrap();

        // First verification succeeds
        prop_assert!(verifier.verify_request(
            &method,
            &authority,
            &path,
            &body,
            &signature.signature,
            &signature.signature_input,
            &verifying_key,
        ).is_ok());

        // Second verification fails (replay)
        prop_assert!(verifier.verify_request(
            &method,
            &authority,
            &path,
            &body,
            &signature.signature,
            &signature.signature_input,
            &verifying_key,
        ).is_err());
    }
}
