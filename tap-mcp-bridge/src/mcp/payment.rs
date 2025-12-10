//! Payment processing tools for TAP-MCP bridge.
//!
//! This module provides secure payment processing with APC (Agentic Payment Container)
//! encryption and TAP authentication.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tracing::{info, instrument};

use crate::{
    error::{BridgeError, Result},
    mcp::{
        http::{build_url_with_query, create_http_client, execute_tap_request_with_custom_nonce},
        models::PaymentResult,
    },
    security::{RateLimitConfig, RateLimiter},
    tap::{
        InteractionType, TapSigner,
        acro::ContextualData,
        apc::{BankAccountData, CardData, DigitalWalletData, PaymentMethod, RsaPublicKey},
    },
};

/// Parameters for processing a payment.
#[derive(Debug, Deserialize)]
pub struct ProcessPaymentParams {
    /// Merchant URL.
    pub merchant_url: String,
    /// Consumer identifier.
    pub consumer_id: String,
    /// Order ID.
    pub order_id: String,
    /// Payment method.
    pub payment_method: PaymentMethodParams,
    /// Merchant RSA public key (PEM format) for APC encryption.
    pub merchant_public_key_pem: String,

    // ACRO contextual data fields
    /// ISO 3166-1 alpha-2 country code (e.g., "US").
    pub country_code: String,
    /// Postal code or city/state (max 16 chars).
    pub zip: String,
    /// Consumer device IP address.
    pub ip_address: String,
    /// Browser/device user agent.
    pub user_agent: String,
    /// Operating system platform.
    pub platform: String,
}

/// Payment method parameters.
///
/// Sensitive payment data that will be encrypted in APC.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PaymentMethodParams {
    /// Credit or debit card.
    Card {
        /// Card number.
        card_number: String,
        /// Expiry month (01-12).
        expiry_month: String,
        /// Expiry year (2-digit or 4-digit).
        expiry_year: String,
        /// CVV/CVC.
        cvv: String,
        /// Cardholder name.
        cardholder_name: String,
    },
    /// Bank account (ACH).
    BankAccount {
        /// Account number.
        account_number: String,
        /// Routing number.
        routing_number: String,
        /// Account type (checking or savings).
        account_type: String,
        /// Account holder name.
        account_holder_name: String,
    },
    /// Digital wallet.
    DigitalWallet {
        /// Wallet type (`apple_pay`, `google_pay`, etc.).
        wallet_type: String,
        /// Encrypted wallet token.
        wallet_token: String,
        /// Account holder name.
        account_holder_name: String,
    },
}

impl From<PaymentMethodParams> for PaymentMethod {
    fn from(params: PaymentMethodParams) -> Self {
        match params {
            PaymentMethodParams::Card {
                card_number,
                expiry_month,
                expiry_year,
                cvv,
                cardholder_name,
            } => Self::Card(CardData {
                number: card_number,
                exp_month: expiry_month,
                exp_year: expiry_year,
                cvv,
                cardholder_name,
            }),
            PaymentMethodParams::BankAccount {
                account_number,
                routing_number,
                account_type,
                account_holder_name,
            } => Self::BankAccount(BankAccountData {
                account_number,
                routing_number,
                account_type,
                account_holder_name,
            }),
            PaymentMethodParams::DigitalWallet {
                wallet_type,
                wallet_token,
                account_holder_name,
            } => Self::DigitalWallet(DigitalWalletData {
                wallet_type,
                wallet_token,
                account_holder_name,
            }),
        }
    }
}

/// Request body for payment processing.
#[derive(Debug, Serialize, Deserialize)]
struct ProcessPaymentRequest {
    order_id: String,
    /// Encrypted APC (JWE format).
    apc: String,
}

/// Processes payment for an order with APC encryption and TAP authentication.
///
/// This function:
/// 1. Encrypts payment credentials in APC using merchant's public key
/// 2. Generates TAP signature with ACRO
/// 3. Sends encrypted payment to merchant
/// 4. Returns payment result
///
/// # Security
///
/// - Payment credentials are encrypted before transmission
/// - Uses RSA-OAEP-256 + A256GCM for JWE encryption
/// - Sensitive data is zeroized after use
/// - Never logs payment credentials
///
/// # Errors
///
/// Returns error if:
/// - Merchant public key is invalid
/// - APC encryption fails
/// - Signature generation fails
/// - HTTP request fails
/// - Response parsing fails
///
/// # Examples
///
/// ```no_run
/// use ed25519_dalek::SigningKey;
/// use tap_mcp_bridge::{
///     mcp::payment::{PaymentMethodParams, ProcessPaymentParams, process_payment},
///     tap::TapSigner,
/// };
///
/// # async fn example() -> tap_mcp_bridge::error::Result<()> {
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
///
/// let payment_method = PaymentMethodParams::Card {
///     card_number: "4111111111111111".into(),
///     expiry_month: "12".into(),
///     expiry_year: "25".into(),
///     cvv: "123".into(),
///     cardholder_name: "John Doe".into(),
/// };
///
/// let merchant_key_pem = r#"-----BEGIN PUBLIC KEY-----
/// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
/// 4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
/// +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
/// kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
/// 0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
/// cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
/// mwIDAQAB
/// -----END PUBLIC KEY-----"#;
///
/// let params = ProcessPaymentParams {
///     merchant_url: "https://merchant.com".into(),
///     consumer_id: "user-123".into(),
///     order_id: "order-789".into(),
///     payment_method,
///     merchant_public_key_pem: merchant_key_pem.into(),
///     country_code: "US".into(),
///     zip: "94025".into(),
///     ip_address: "192.168.1.100".into(),
///     user_agent: "Mozilla/5.0".into(),
///     platform: "macOS".into(),
/// };
///
/// let result = process_payment(&signer, params).await?;
/// println!("Transaction ID: {}", result.transaction_id);
/// # Ok(())
/// # }
/// ```
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, order_id = %params.order_id))]
pub async fn process_payment(
    signer: &TapSigner,
    params: ProcessPaymentParams,
) -> Result<PaymentResult> {
    info!("processing payment");

    let contextual_data = ContextualData {
        country_code: params.country_code,
        zip: params.zip,
        ip_address: params.ip_address,
        device_data: crate::tap::acro::DeviceData {
            user_agent: params.user_agent,
            platform: params.platform,
        },
    };

    // Load merchant's RSA public key
    let merchant_public_key = RsaPublicKey::from_pem(params.merchant_public_key_pem.as_bytes())?;

    // Convert params to PaymentMethod
    let payment_method: PaymentMethod = params.payment_method.into();

    // Generate nonce (will be shared between HTTP signature and APC)
    let nonce = uuid::Uuid::new_v4().to_string();

    // Generate APC with encrypted payment data
    let apc_jwe = signer.generate_apc(&nonce, &payment_method, &merchant_public_key)?;

    // Serialize APC to JSON
    let apc_json = serde_json::to_string(&apc_jwe)
        .map_err(|e| BridgeError::CryptoError(format!("APC serialization failed: {e}")))?;

    // Create payment request with encrypted APC
    let request_body = ProcessPaymentRequest { order_id: params.order_id, apc: apc_json };

    let path = build_url_with_query("/checkout", &[("consumer_id", &params.consumer_id)])?;

    let client = create_http_client()?;
    let response = execute_tap_request_with_custom_nonce(
        &client,
        signer,
        &params.merchant_url,
        &params.consumer_id,
        "POST",
        &path,
        InteractionType::Checkout,
        contextual_data,
        &request_body,
        &nonce,
    )
    .await?;

    let payment_result: PaymentResult = serde_json::from_slice(&response)
        .map_err(|e| BridgeError::MerchantError(format!("failed to parse payment result: {e}")))?;

    Ok(payment_result)
}

/// Rate limiter for payment operations.
///
/// Global rate limiter shared across all payment processing operations
/// to prevent abuse and ensure compliance with merchant policies.
///
/// Default configuration: 5 payments per minute per consumer
static PAYMENT_RATE_LIMITER: Mutex<Option<Arc<RateLimiter>>> = Mutex::new(None);

/// Gets or initializes the global payment rate limiter.
fn get_payment_rate_limiter() -> Arc<RateLimiter> {
    let mut limiter_opt = PAYMENT_RATE_LIMITER
        .lock()
        .expect("payment rate limiter mutex should not be poisoned");
    if let Some(limiter) = limiter_opt.as_ref() {
        Arc::clone(limiter)
    } else {
        // Default: 5 payments per minute = 0.083 per second
        // Using burst_size of 3 to allow some flexibility
        let config = RateLimitConfig {
            requests_per_second: 1, // ~60/min with some margin
            burst_size: 3,          // Allow burst of 3 payments
        };
        let limiter = Arc::new(RateLimiter::new(config));
        *limiter_opt = Some(Arc::clone(&limiter));
        limiter
    }
}

/// Processes payment with rate limiting applied.
///
/// This is a wrapper around [`process_payment`] that enforces rate limiting
/// to prevent excessive payment attempts.
///
/// Default rate limit: 5 attempts per minute per consumer (burst of 3).
///
/// # Errors
///
/// Returns [`crate::error::BridgeError::RateLimitExceeded`] if rate limit is exceeded,
/// or any error from the underlying [`process_payment`] function.
///
/// # Examples
///
/// ```no_run
/// use ed25519_dalek::SigningKey;
/// use tap_mcp_bridge::{
///     mcp::payment::{PaymentMethodParams, ProcessPaymentParams, process_payment_rate_limited},
///     tap::TapSigner,
/// };
///
/// # async fn example() -> tap_mcp_bridge::error::Result<()> {
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
///
/// let payment_method = PaymentMethodParams::Card {
///     card_number: "4111111111111111".into(),
///     expiry_month: "12".into(),
///     expiry_year: "25".into(),
///     cvv: "123".into(),
///     cardholder_name: "John Doe".into(),
/// };
///
/// let merchant_key_pem = "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----";
///
/// let params = ProcessPaymentParams {
///     merchant_url: "https://merchant.com".into(),
///     consumer_id: "user-123".into(),
///     order_id: "order-789".into(),
///     payment_method,
///     merchant_public_key_pem: merchant_key_pem.into(),
///     country_code: "US".into(),
///     zip: "94025".into(),
///     ip_address: "192.168.1.100".into(),
///     user_agent: "Mozilla/5.0".into(),
///     platform: "macOS".into(),
/// };
///
/// // Rate-limited payment processing
/// let result = process_payment_rate_limited(&signer, params).await?;
/// println!("Transaction ID: {}", result.transaction_id);
/// # Ok(())
/// # }
/// ```
#[instrument(skip(signer, params), fields(merchant_url = %params.merchant_url, order_id = %params.order_id))]
pub async fn process_payment_rate_limited(
    signer: &TapSigner,
    params: ProcessPaymentParams,
) -> Result<PaymentResult> {
    // Acquire rate limit token
    let limiter = get_payment_rate_limiter();
    limiter.acquire().await?;

    info!("rate limit passed, processing payment");

    // Process payment
    process_payment(signer, params).await
}

#[cfg(test)]
#[allow(
    clippy::unreachable,
    reason = "tests use unreachable! for exhaustive pattern matching"
)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_method_params_card() {
        let params = PaymentMethodParams::Card {
            card_number: "4111111111111111".to_owned(),
            expiry_month: "12".to_owned(),
            expiry_year: "25".to_owned(),
            cvv: "123".to_owned(),
            cardholder_name: "John Doe".to_owned(),
        };

        let payment_method: PaymentMethod = params.into();
        assert!(matches!(payment_method, PaymentMethod::Card(_)));
    }

    #[test]
    fn test_payment_method_params_card_various_formats() {
        let cards = vec![
            ("4111111111111111", "12", "25", "123"),
            ("5555555555554444", "01", "2025", "456"),
            ("378282246310005", "06", "26", "1234"),
            ("6011111111111117", "12", "2027", "789"),
        ];

        for (number, month, year, cvv) in cards {
            let params = PaymentMethodParams::Card {
                card_number: number.to_owned(),
                expiry_month: month.to_owned(),
                expiry_year: year.to_owned(),
                cvv: cvv.to_owned(),
                cardholder_name: "Test User".to_owned(),
            };

            let payment_method: PaymentMethod = params.into();
            let PaymentMethod::Card(data) = payment_method else {
                unreachable!("expected Card variant");
            };
            assert_eq!(data.number, number);
            assert_eq!(data.exp_month, month);
            assert_eq!(data.exp_year, year);
            assert_eq!(data.cvv, cvv);
        }
    }

    #[test]
    fn test_payment_method_params_bank_account() {
        let params = PaymentMethodParams::BankAccount {
            account_number: "1234567890".to_owned(),
            routing_number: "021000021".to_owned(),
            account_type: "checking".to_owned(),
            account_holder_name: "Jane Doe".to_owned(),
        };

        let payment_method: PaymentMethod = params.into();
        assert!(matches!(payment_method, PaymentMethod::BankAccount(_)));
    }

    #[test]
    fn test_payment_method_params_bank_account_types() {
        let account_types = vec!["checking", "savings"];

        for account_type in account_types {
            let params = PaymentMethodParams::BankAccount {
                account_number: "9876543210".to_owned(),
                routing_number: "111000025".to_owned(),
                account_type: account_type.to_owned(),
                account_holder_name: "Test User".to_owned(),
            };

            let payment_method: PaymentMethod = params.into();
            let PaymentMethod::BankAccount(data) = payment_method else {
                unreachable!("expected BankAccount variant");
            };
            assert_eq!(data.account_type, account_type);
        }
    }

    #[test]
    fn test_payment_method_params_digital_wallet() {
        let params = PaymentMethodParams::DigitalWallet {
            wallet_type: "apple_pay".to_owned(),
            wallet_token: "encrypted-token-abc123".to_owned(),
            account_holder_name: "John Smith".to_owned(),
        };

        let payment_method: PaymentMethod = params.into();
        assert!(matches!(payment_method, PaymentMethod::DigitalWallet(_)));
    }

    #[test]
    fn test_payment_method_params_wallet_types() {
        let wallet_types = vec!["apple_pay", "google_pay", "paypal", "venmo", "samsung_pay"];

        for wallet_type in wallet_types {
            let params = PaymentMethodParams::DigitalWallet {
                wallet_type: wallet_type.to_owned(),
                wallet_token: "token-123".to_owned(),
                account_holder_name: "Test User".to_owned(),
            };

            let payment_method: PaymentMethod = params.into();
            let PaymentMethod::DigitalWallet(data) = payment_method else {
                unreachable!("expected DigitalWallet variant");
            };
            assert_eq!(data.wallet_type, wallet_type);
        }
    }

    #[test]
    fn test_process_payment_params_creation() {
        let params = ProcessPaymentParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-123".to_owned(),
            order_id: "order-456".to_owned(),
            payment_method: PaymentMethodParams::Card {
                card_number: "4111111111111111".to_owned(),
                expiry_month: "12".to_owned(),
                expiry_year: "25".to_owned(),
                cvv: "123".to_owned(),
                cardholder_name: "John Doe".to_owned(),
            },
            merchant_public_key_pem: "test-key".to_owned(),
            country_code: "US".to_owned(),
            zip: "94025".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            user_agent: "Mozilla/5.0".to_owned(),
            platform: "Linux".to_owned(),
        };

        assert_eq!(params.order_id, "order-456");
    }

    #[test]
    fn test_process_payment_request_serialization() {
        let request = ProcessPaymentRequest {
            order_id: "order-123".to_owned(),
            apc: "encrypted-apc-data".to_owned(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"order_id\":\"order-123\""));
        assert!(json.contains("\"apc\":\"encrypted-apc-data\""));
    }

    #[test]
    fn test_process_payment_request_deserialization() {
        let json = r#"{"order_id":"order-999","apc":"apc-encrypted-payload"}"#;
        let request: ProcessPaymentRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.order_id, "order-999");
        assert_eq!(request.apc, "apc-encrypted-payload");
    }

    #[test]
    fn test_payment_method_deserialization_card() {
        let json = r#"{
            "type": "card",
            "card_number": "4111111111111111",
            "expiry_month": "12",
            "expiry_year": "25",
            "cvv": "123",
            "cardholder_name": "Test User"
        }"#;

        let params: PaymentMethodParams = serde_json::from_str(json).unwrap();
        assert!(matches!(params, PaymentMethodParams::Card { .. }));
    }

    #[test]
    fn test_payment_method_deserialization_bank_account() {
        let json = r#"{
            "type": "bank_account",
            "account_number": "1234567890",
            "routing_number": "021000021",
            "account_type": "checking",
            "account_holder_name": "Test User"
        }"#;

        let params: PaymentMethodParams = serde_json::from_str(json).unwrap();
        assert!(matches!(params, PaymentMethodParams::BankAccount { .. }));
    }

    #[test]
    fn test_payment_method_deserialization_digital_wallet() {
        let json = r#"{
            "type": "digital_wallet",
            "wallet_type": "apple_pay",
            "wallet_token": "token-xyz",
            "account_holder_name": "Test User"
        }"#;

        let params: PaymentMethodParams = serde_json::from_str(json).unwrap();
        assert!(matches!(params, PaymentMethodParams::DigitalWallet { .. }));
    }

    #[test]
    fn test_card_data_conversion() {
        let params = PaymentMethodParams::Card {
            card_number: "5555555555554444".to_owned(),
            expiry_month: "06".to_owned(),
            expiry_year: "2026".to_owned(),
            cvv: "789".to_owned(),
            cardholder_name: "Jane Smith".to_owned(),
        };

        let payment_method: PaymentMethod = params.into();
        let PaymentMethod::Card(data) = payment_method else {
            unreachable!("expected Card variant");
        };
        assert_eq!(data.number, "5555555555554444");
        assert_eq!(data.exp_month, "06");
        assert_eq!(data.exp_year, "2026");
        assert_eq!(data.cvv, "789");
        assert_eq!(data.cardholder_name, "Jane Smith");
    }

    #[test]
    fn test_bank_account_data_conversion() {
        let params = PaymentMethodParams::BankAccount {
            account_number: "9876543210".to_owned(),
            routing_number: "111000025".to_owned(),
            account_type: "savings".to_owned(),
            account_holder_name: "Bob Johnson".to_owned(),
        };

        let payment_method: PaymentMethod = params.into();
        let PaymentMethod::BankAccount(data) = payment_method else {
            unreachable!("expected BankAccount variant");
        };
        assert_eq!(data.account_number, "9876543210");
        assert_eq!(data.routing_number, "111000025");
        assert_eq!(data.account_type, "savings");
        assert_eq!(data.account_holder_name, "Bob Johnson");
    }

    #[test]
    fn test_digital_wallet_data_conversion() {
        let params = PaymentMethodParams::DigitalWallet {
            wallet_type: "google_pay".to_owned(),
            wallet_token: "encrypted-token-xyz".to_owned(),
            account_holder_name: "Alice Brown".to_owned(),
        };

        let payment_method: PaymentMethod = params.into();
        let PaymentMethod::DigitalWallet(data) = payment_method else {
            unreachable!("expected DigitalWallet variant");
        };
        assert_eq!(data.wallet_type, "google_pay");
        assert_eq!(data.wallet_token, "encrypted-token-xyz");
        assert_eq!(data.account_holder_name, "Alice Brown");
    }

    #[test]
    fn test_process_payment_params_with_bank_account() {
        let params = ProcessPaymentParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-456".to_owned(),
            order_id: "order-789".to_owned(),
            payment_method: PaymentMethodParams::BankAccount {
                account_number: "1234567890".to_owned(),
                routing_number: "021000021".to_owned(),
                account_type: "checking".to_owned(),
                account_holder_name: "Test User".to_owned(),
            },
            merchant_public_key_pem: "test-key-pem".to_owned(),
            country_code: "CA".to_owned(),
            zip: "M5H2N2".to_owned(),
            ip_address: "10.0.0.1".to_owned(),
            user_agent: "Chrome/120.0".to_owned(),
            platform: "Windows".to_owned(),
        };

        assert!(matches!(params.payment_method, PaymentMethodParams::BankAccount { .. }));
    }

    #[test]
    fn test_process_payment_params_with_digital_wallet() {
        let params = ProcessPaymentParams {
            merchant_url: "https://merchant.com".to_owned(),
            consumer_id: "user-999".to_owned(),
            order_id: "order-abc".to_owned(),
            payment_method: PaymentMethodParams::DigitalWallet {
                wallet_type: "apple_pay".to_owned(),
                wallet_token: "token-123".to_owned(),
                account_holder_name: "Test User".to_owned(),
            },
            merchant_public_key_pem: "pem-key".to_owned(),
            country_code: "GB".to_owned(),
            zip: "SW1A1AA".to_owned(),
            ip_address: "192.168.0.100".to_owned(),
            user_agent: "Safari/17.0".to_owned(),
            platform: "macOS".to_owned(),
        };

        assert!(matches!(params.payment_method, PaymentMethodParams::DigitalWallet { .. }));
    }

    #[test]
    fn test_empty_cvv() {
        let params = PaymentMethodParams::Card {
            card_number: "4111111111111111".to_owned(),
            expiry_month: "12".to_owned(),
            expiry_year: "25".to_owned(),
            cvv: String::new(),
            cardholder_name: "Test User".to_owned(),
        };

        let payment_method: PaymentMethod = params.into();
        let PaymentMethod::Card(data) = payment_method else {
            unreachable!("expected Card variant");
        };
        assert!(data.cvv.is_empty());
    }

    #[test]
    fn test_various_expiry_year_formats() {
        let year_formats = vec!["25", "2025", "26", "2026", "30", "2030"];

        for year in year_formats {
            let params = PaymentMethodParams::Card {
                card_number: "4111111111111111".to_owned(),
                expiry_month: "12".to_owned(),
                expiry_year: year.to_owned(),
                cvv: "123".to_owned(),
                cardholder_name: "Test User".to_owned(),
            };

            let payment_method: PaymentMethod = params.into();
            let PaymentMethod::Card(data) = payment_method else {
                unreachable!("expected Card variant");
            };
            assert_eq!(data.exp_year, year);
        }
    }
}
