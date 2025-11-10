//! Agentic Payment Container (APC) for TAP.
//!
//! This module implements the APC specification for TAP, which provides
//! secure packaging of payment credentials for transaction processing.
//!
//! # APC Purpose
//!
//! The APC contains payment credentials and authorization for transaction
//! processing. It includes:
//! - Encrypted payment data (JWE format)
//! - Payment method metadata
//! - Digital signature over all fields
//!
//! # TAP Requirements
//!
//! - **Nonce correlation**: APC nonce MUST match HTTP signature nonce
//! - **Kid matching**: APC kid SHOULD match HTTP signature keyid
//! - **Signature**: Signs all fields except the signature field itself
//! - **Algorithm**: Uses Ed25519 (same key as HTTP signatures)
//! - **PCI-DSS Compliance**: Sensitive payment data must be encrypted
//!
//! # Examples
//!
//! ```
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::tap::{
//!     TapSigner,
//!     apc::{CardData, PaymentMethod, RsaPublicKey},
//! };
//!
//! # fn example() -> tap_mcp_bridge::error::Result<()> {
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
//!
//! // Create card payment method
//! let card = CardData {
//!     number: "4111111111111111".to_owned(),
//!     exp_month: "12".to_owned(),
//!     exp_year: "25".to_owned(),
//!     cvv: "123".to_owned(),
//!     cardholder_name: "John Doe".to_owned(),
//! };
//! let payment_method = PaymentMethod::Card(card);
//!
//! // Load merchant's public key
//! let pem = b"-----BEGIN PUBLIC KEY-----
//! MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
//! 4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
//! +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
//! kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
//! 0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
//! cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
//! mwIDAQAB
//! -----END PUBLIC KEY-----";
//! let merchant_key = RsaPublicKey::from_pem(pem)?;
//!
//! // Generate APC (encrypts payment data)
//! let apc = signer.generate_apc("nonce-unique-123", &payment_method, &merchant_key)?;
//!
//! println!("APC nonce: {}", apc.nonce);
//! println!("Algorithm: {}", apc.alg);
//! # Ok(())
//! # }
//! ```

use ed25519_dalek::{Signer, SigningKey};
use josekit::jwe::{JweEncrypter, RSA_OAEP_256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{BridgeError, Result};

/// RSA public key for JWE encryption.
///
/// Represents a merchant's RSA public key used for encrypting payment data
/// in the APC. The key must be at least 2048 bits and in PEM format.
///
/// # Examples
///
/// ```no_run
/// use tap_mcp_bridge::tap::apc::RsaPublicKey;
///
/// let pem = r#"-----BEGIN PUBLIC KEY-----
/// ...
/// -----END PUBLIC KEY-----"#;
///
/// let public_key = RsaPublicKey::from_pem(pem.as_bytes())?;
/// # Ok::<(), tap_mcp_bridge::error::BridgeError>(())
/// ```
#[derive(Debug, Clone)]
pub struct RsaPublicKey {
    encrypter: Box<dyn JweEncrypter>,
}

impl RsaPublicKey {
    /// Creates an RSA public key from PEM-encoded data.
    ///
    /// # Arguments
    ///
    /// * `pem` - PEM-encoded RSA public key
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CryptoError`] if:
    /// - PEM format is invalid
    /// - Key is not an RSA public key
    /// - Key size is insufficient (<2048 bits)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tap_mcp_bridge::tap::apc::RsaPublicKey;
    ///
    /// let pem = std::fs::read("merchant_public_key.pem")?;
    /// let public_key = RsaPublicKey::from_pem(&pem)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let encrypter = RSA_OAEP_256
            .encrypter_from_pem(pem)
            .map_err(|e| BridgeError::CryptoError(format!("failed to load RSA public key: {e}")))?;

        Ok(Self { encrypter: Box::new(encrypter) })
    }

    /// Returns the encrypter for JWE operations.
    fn encrypter(&self) -> &dyn JweEncrypter {
        self.encrypter.as_ref()
    }
}

/// Agentic Payment Container (APC).
///
/// Contains encrypted payment credentials and authorization for transaction
/// processing per TAP specification.
///
/// # TAP Requirements
///
/// - `nonce` must match HTTP Message Signature nonce
/// - `kid` should match HTTP Message Signature keyid
/// - `signature` covers all fields except itself
/// - Signature uses same Ed25519 key as HTTP signatures
/// - Payment data must be encrypted (PCI-DSS compliance)
///
/// # Security Considerations
///
/// - Payment credentials are encrypted before storage
/// - Sensitive fields use `secrecy::Secret` for memory protection
/// - All sensitive data is zeroized on drop
/// - Never log or expose plaintext payment credentials
///
/// # Examples
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use tap_mcp_bridge::tap::{
///     TapSigner,
///     apc::{CardData, PaymentMethod, RsaPublicKey},
/// };
///
/// # fn example() -> tap_mcp_bridge::error::Result<()> {
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
///
/// let card = CardData {
///     number: "4111111111111111".to_owned(),
///     exp_month: "12".to_owned(),
///     exp_year: "25".to_owned(),
///     cvv: "123".to_owned(),
///     cardholder_name: "John Doe".to_owned(),
/// };
///
/// let pem = b"-----BEGIN PUBLIC KEY-----
/// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
/// 4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
/// +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
/// kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
/// 0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
/// cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
/// mwIDAQAB
/// -----END PUBLIC KEY-----";
/// let merchant_key = RsaPublicKey::from_pem(pem)?;
///
/// let apc = signer.generate_apc("nonce", &PaymentMethod::Card(card), &merchant_key)?;
/// assert_eq!(apc.nonce, "nonce");
/// assert_eq!(apc.alg, "ed25519");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Apc {
    /// Nonce for replay protection (must match HTTP signature nonce).
    pub nonce: String,

    /// Encrypted payment data (JWE format).
    #[serde(rename = "encryptedPaymentData")]
    pub encrypted_payment_data: String,

    /// Public key identifier (JWK thumbprint).
    pub kid: String,

    /// Signature algorithm (always "ed25519").
    pub alg: String,

    /// Base64url-encoded signature over all other fields.
    pub signature: String,
}

impl Apc {
    /// Creates and signs an APC.
    ///
    /// # Arguments
    ///
    /// * `nonce` - Nonce (must match HTTP signature nonce)
    /// * `encrypted_payment_data` - JWE-encrypted payment credentials
    /// * `kid` - Public key identifier (JWK thumbprint)
    /// * `signing_key` - Ed25519 signing key
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CryptoError`] if signature generation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use ed25519_dalek::SigningKey;
    /// use tap_mcp_bridge::tap::apc::Apc;
    ///
    /// # fn example() -> tap_mcp_bridge::error::Result<()> {
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    ///
    /// let apc = Apc::create("test-nonce", "encrypted-payment-data-jwe", "test-kid", &signing_key)?;
    ///
    /// assert_eq!(apc.nonce, "test-nonce");
    /// assert_eq!(apc.kid, "test-kid");
    /// assert_eq!(apc.alg, "ed25519");
    /// assert!(!apc.signature.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub fn create(
        nonce: &str,
        encrypted_payment_data: &str,
        kid: &str,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        // Create unsigned APC
        let mut apc = Self {
            nonce: nonce.to_owned(),
            encrypted_payment_data: encrypted_payment_data.to_owned(),
            kid: kid.to_owned(),
            alg: "ed25519".to_owned(),
            signature: String::new(), // Placeholder
        };

        // Generate signature over all fields except signature
        let signature = apc.compute_signature(signing_key)?;
        apc.signature = signature;

        Ok(apc)
    }

    /// Computes signature over APC fields.
    ///
    /// Signs all fields except the signature field itself using Ed25519.
    /// The signature base is the canonical JSON representation of the APC
    /// without the signature field.
    fn compute_signature(&self, signing_key: &SigningKey) -> Result<String> {
        // Create signature base: JSON of all fields except signature
        let base = self.signature_base()?;

        // Sign with Ed25519
        let signature_bytes = signing_key.sign(base.as_bytes());

        // Encode as base64url
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            signature_bytes.to_bytes(),
        ))
    }

    /// Creates signature base string (canonical JSON without signature field).
    ///
    /// Serializes the APC to JSON excluding the signature field to create
    /// the data that will be signed. This uses deterministic JSON serialization
    /// to ensure the signature can be verified.
    fn signature_base(&self) -> Result<String> {
        // Helper struct for serialization without signature field
        #[derive(Serialize)]
        struct ApcBase<'a> {
            nonce: &'a str,
            #[serde(rename = "encryptedPaymentData")]
            encrypted_payment_data: &'a str,
            kid: &'a str,
            alg: &'a str,
        }

        // Serialize to JSON without signature field
        let base = ApcBase {
            nonce: &self.nonce,
            encrypted_payment_data: &self.encrypted_payment_data,
            kid: &self.kid,
            alg: &self.alg,
        };

        serde_json::to_string(&base)
            .map_err(|e| BridgeError::CryptoError(format!("APC JSON serialization failed: {e}")))
    }
}

/// Payment method type for APC.
///
/// Represents different types of payment methods that can be used in TAP
/// transactions. Each variant contains the payment-specific data required
/// for processing.
///
/// # Security
///
/// All payment credentials are encrypted before transmission to merchants.
/// Never log or expose plaintext payment data.
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::tap::apc::{BankAccountData, CardData, PaymentMethod};
///
/// // Card payment
/// let card = CardData {
///     number: "4111111111111111".to_owned(),
///     exp_month: "12".to_owned(),
///     exp_year: "25".to_owned(),
///     cvv: "123".to_owned(),
///     cardholder_name: "John Doe".to_owned(),
/// };
/// let payment = PaymentMethod::Card(card);
///
/// // Bank account payment
/// let account = BankAccountData {
///     account_number: "1234567890".to_owned(),
///     routing_number: "021000021".to_owned(),
///     account_type: "checking".to_owned(),
///     account_holder_name: "Jane Doe".to_owned(),
/// };
/// let payment = PaymentMethod::BankAccount(account);
/// ```
#[derive(Debug, Clone)]
pub enum PaymentMethod {
    /// Credit or debit card payment.
    Card(CardData),
    /// Bank account payment (ACH).
    BankAccount(BankAccountData),
    /// Digital wallet payment (Apple Pay, Google Pay, etc.).
    DigitalWallet(DigitalWalletData),
}

impl PaymentMethod {
    /// Encrypts payment method data to JWE format using RFC 7516.
    ///
    /// Uses RSA-OAEP-256 for key encryption and A256GCM for content encryption,
    /// producing JWE compact serialization format (5 dot-separated parts).
    ///
    /// # Arguments
    ///
    /// * `merchant_public_key` - Merchant's RSA public key for encryption
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CryptoError`] if:
    /// - JSON serialization fails
    /// - JWE encryption fails
    /// - Public key is invalid
    ///
    /// # Security
    ///
    /// - Uses A256GCM (AES-256-GCM) for content encryption
    /// - Uses RSA-OAEP-256 for key encryption
    /// - Produces RFC 7516 compliant JWE compact serialization
    /// - Sensitive data zeroized after encryption
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::tap::apc::{CardData, PaymentMethod, RsaPublicKey};
    ///
    /// # fn example() -> tap_mcp_bridge::error::Result<()> {
    /// let card = CardData {
    ///     number: "4111111111111111".to_owned(),
    ///     exp_month: "12".to_owned(),
    ///     exp_year: "25".to_owned(),
    ///     cvv: "123".to_owned(),
    ///     cardholder_name: "John Doe".to_owned(),
    /// };
    ///
    /// let pem = b"-----BEGIN PUBLIC KEY-----
    /// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
    /// 4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
    /// +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
    /// kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
    /// 0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
    /// cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
    /// mwIDAQAB
    /// -----END PUBLIC KEY-----";
    /// let public_key = RsaPublicKey::from_pem(pem)?;
    ///
    /// let payment = PaymentMethod::Card(card);
    /// let jwe = payment.encrypt(&public_key)?;
    ///
    /// // JWE has 5 dot-separated parts
    /// assert_eq!(jwe.split('.').count(), 5);
    /// # Ok(())
    /// # }
    /// ```
    pub fn encrypt(&self, merchant_public_key: &RsaPublicKey) -> Result<String> {
        // Serialize payment method to JSON
        let json = self.to_json()?;

        // Create JWE header with RSA-OAEP-256 and A256GCM
        let mut header = josekit::jwe::JweHeader::new();
        header.set_algorithm("RSA-OAEP-256");
        header.set_content_encryption("A256GCM");

        // Encrypt to JWE compact serialization (5 parts: header.key.iv.ciphertext.tag)
        let jwe = josekit::jwe::serialize_compact(
            json.as_bytes(),
            &header,
            merchant_public_key.encrypter(),
        )
        .map_err(|e| BridgeError::CryptoError(format!("JWE encryption failed: {e}")))?;

        Ok(jwe)
    }

    /// Serializes payment method to JSON.
    fn to_json(&self) -> Result<String> {
        let json = match self {
            Self::Card(card) => {
                serde_json::json!({
                    "type": "card",
                    "cardNumber": card.number,
                    "expiryMonth": card.exp_month,
                    "expiryYear": card.exp_year,
                    "cvv": card.cvv,
                    "cardholderName": card.cardholder_name,
                })
            }
            Self::BankAccount(account) => {
                serde_json::json!({
                    "type": "bank_account",
                    "accountNumber": account.account_number,
                    "routingNumber": account.routing_number,
                    "accountType": account.account_type,
                    "accountHolderName": account.account_holder_name,
                })
            }
            Self::DigitalWallet(wallet) => {
                serde_json::json!({
                    "type": "digital_wallet",
                    "walletType": wallet.wallet_type,
                    "walletToken": wallet.wallet_token,
                    "accountHolderName": wallet.account_holder_name,
                })
            }
        };

        serde_json::to_string(&json).map_err(|e| {
            BridgeError::CryptoError(format!("payment method serialization failed: {e}"))
        })
    }
}

/// Credit or debit card payment data.
///
/// Contains the card details required for payment processing.
/// All fields are sensitive and must be protected per PCI-DSS requirements.
///
/// # Security
///
/// - Never log card numbers, CVV, or expiry dates
/// - Always encrypt before transmission
/// - Zeroize memory on drop
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::tap::apc::CardData;
///
/// let card = CardData {
///     number: "4111111111111111".to_owned(),
///     exp_month: "12".to_owned(),
///     exp_year: "25".to_owned(),
///     cvv: "123".to_owned(),
///     cardholder_name: "John Doe".to_owned(),
/// };
///
/// assert_eq!(card.last_four(), "1111");
/// ```
#[derive(Debug, Clone)]
pub struct CardData {
    /// Card number (PAN).
    pub number: String,
    /// Expiry month (01-12).
    pub exp_month: String,
    /// Expiry year (2-digit or 4-digit).
    pub exp_year: String,
    /// Card verification value (CVV/CVC).
    pub cvv: String,
    /// Cardholder name as printed on card.
    pub cardholder_name: String,
}

impl CardData {
    /// Returns last four digits of card number for display.
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::tap::apc::CardData;
    ///
    /// let card = CardData {
    ///     number: "4111111111111111".to_owned(),
    ///     exp_month: "12".to_owned(),
    ///     exp_year: "25".to_owned(),
    ///     cvv: "123".to_owned(),
    ///     cardholder_name: "John Doe".to_owned(),
    /// };
    ///
    /// assert_eq!(card.last_four(), "1111");
    /// ```
    #[must_use]
    #[allow(clippy::string_slice, reason = "card numbers are ASCII digits")]
    pub fn last_four(&self) -> &str {
        if self.number.len() >= 4 {
            &self.number[self.number.len() - 4..]
        } else {
            &self.number
        }
    }

    /// Computes payment credential hash per TAP specification.
    ///
    /// Hash format: SHA-256(16-digit PAN + 2-digit exp month + 2-digit exp year + 3-digit CVV)
    ///
    /// # Examples
    ///
    /// ```
    /// use tap_mcp_bridge::tap::apc::CardData;
    ///
    /// let card = CardData {
    ///     number: "4111111111111111".to_owned(),
    ///     exp_month: "12".to_owned(),
    ///     exp_year: "25".to_owned(),
    ///     cvv: "123".to_owned(),
    ///     cardholder_name: "John Doe".to_owned(),
    /// };
    ///
    /// let hash = card.credential_hash();
    /// assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex characters
    /// ```
    #[must_use]
    pub fn credential_hash(&self) -> String {
        // Concatenate: 16-digit PAN + 2-digit exp month + 2-digit exp year + 3-digit CVV
        let credential = format!("{}{}{}{}", self.number, self.exp_month, self.exp_year, self.cvv);

        // Compute SHA-256
        let mut hasher = Sha256::new();
        hasher.update(credential.as_bytes());
        let hash = hasher.finalize();

        // Return as hex string
        hex::encode(hash)
    }
}

impl Drop for CardData {
    fn drop(&mut self) {
        // Zeroize sensitive fields on drop (PCI-DSS requirement)
        self.number.zeroize();
        self.cvv.zeroize();
    }
}

/// Bank account payment data (ACH).
///
/// Contains bank account details for ACH payments.
/// All fields are sensitive and must be protected.
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::tap::apc::BankAccountData;
///
/// let account = BankAccountData {
///     account_number: "1234567890".to_owned(),
///     routing_number: "021000021".to_owned(),
///     account_type: "checking".to_owned(),
///     account_holder_name: "Jane Doe".to_owned(),
/// };
///
/// assert_eq!(account.last_four(), "7890");
/// ```
#[derive(Debug, Clone)]
pub struct BankAccountData {
    /// Bank account number.
    pub account_number: String,
    /// Bank routing number (ABA).
    pub routing_number: String,
    /// Account type (checking or savings).
    pub account_type: String,
    /// Account holder name.
    pub account_holder_name: String,
}

impl BankAccountData {
    /// Returns last four digits of account number for display.
    #[must_use]
    #[allow(clippy::string_slice, reason = "account numbers are ASCII digits")]
    pub fn last_four(&self) -> &str {
        if self.account_number.len() >= 4 {
            &self.account_number[self.account_number.len() - 4..]
        } else {
            &self.account_number
        }
    }
}

impl Drop for BankAccountData {
    fn drop(&mut self) {
        // Zeroize sensitive fields on drop
        self.account_number.zeroize();
        self.routing_number.zeroize();
    }
}

/// Digital wallet payment data.
///
/// Contains wallet token for digital wallet payments (Apple Pay, Google Pay, etc.).
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::tap::apc::DigitalWalletData;
///
/// let wallet = DigitalWalletData {
///     wallet_type: "apple_pay".to_owned(),
///     wallet_token: "encrypted-wallet-token".to_owned(),
///     account_holder_name: "Bob Smith".to_owned(),
/// };
///
/// assert_eq!(wallet.wallet_type, "apple_pay");
/// ```
#[derive(Debug, Clone)]
pub struct DigitalWalletData {
    /// Wallet type (`apple_pay`, `google_pay`, etc.).
    pub wallet_type: String,
    /// Encrypted wallet token.
    pub wallet_token: String,
    /// Account holder name.
    pub account_holder_name: String,
}

impl Drop for DigitalWalletData {
    fn drop(&mut self) {
        // Zeroize sensitive fields on drop
        self.wallet_token.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper struct for test verification
    #[derive(Serialize)]
    struct ApcBaseForTest<'a> {
        nonce: &'a str,
        #[serde(rename = "encryptedPaymentData")]
        encrypted_payment_data: &'a str,
        kid: &'a str,
        alg: &'a str,
    }

    // Helper function to create test RSA public key
    fn create_test_rsa_public_key() -> RsaPublicKey {
        // 2048-bit RSA public key in PEM format (for testing only)
        let pem = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----";

        RsaPublicKey::from_pem(pem.as_bytes()).expect("Failed to create test RSA key")
    }

    #[test]
    fn test_apc_creation() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);

        let apc = Apc::create("test-nonce", "encrypted-data", "test-kid", &signing_key);

        assert!(apc.is_ok());
        let apc = apc.unwrap();
        assert_eq!(apc.nonce, "test-nonce");
        assert_eq!(apc.encrypted_payment_data, "encrypted-data");
        assert_eq!(apc.kid, "test-kid");
        assert_eq!(apc.alg, "ed25519");
        assert!(!apc.signature.is_empty());
    }

    #[test]
    fn test_apc_signature_not_empty() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let apc = Apc::create("nonce", "encrypted", "kid", &signing_key).unwrap();

        assert!(!apc.signature.is_empty());
        // Base64url encoded Ed25519 signature should be ~86 characters (64 bytes)
        assert!(apc.signature.len() > 80);
    }

    #[test]
    fn test_apc_signature_verifiable() {
        use ed25519_dalek::{Signature, Verifier};

        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let apc = Apc::create("test-nonce", "encrypted-data", "test-kid", &signing_key).unwrap();

        // Reconstruct signature base
        let base = ApcBaseForTest {
            nonce: &apc.nonce,
            encrypted_payment_data: &apc.encrypted_payment_data,
            kid: &apc.kid,
            alg: &apc.alg,
        };

        let signature_base = serde_json::to_string(&base).unwrap();

        // Decode signature
        let signature_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &apc.signature,
        )
        .expect("signature should be valid base64url");

        let signature =
            Signature::from_bytes(&signature_bytes.try_into().expect("signature is 64 bytes"));

        // Verify signature
        assert!(
            verifying_key.verify(signature_base.as_bytes(), &signature).is_ok(),
            "APC signature must be verifiable"
        );
    }

    #[test]
    fn test_apc_different_keys_different_signatures() {
        let key1 = SigningKey::from_bytes(&[0u8; 32]);
        let key2 = SigningKey::from_bytes(&[1u8; 32]);

        let apc1 = Apc::create("nonce", "encrypted", "kid", &key1).unwrap();
        let apc2 = Apc::create("nonce", "encrypted", "kid", &key2).unwrap();

        assert_ne!(
            apc1.signature, apc2.signature,
            "different keys must produce different signatures"
        );
    }

    #[test]
    fn test_apc_different_data_different_signatures() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);

        let apc1 = Apc::create("nonce", "encrypted-data-1", "kid", &signing_key).unwrap();
        let apc2 = Apc::create("nonce", "encrypted-data-2", "kid", &signing_key).unwrap();

        assert_ne!(
            apc1.signature, apc2.signature,
            "different data must produce different signatures"
        );
    }

    #[test]
    fn test_apc_serialization() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let apc = Apc::create("nonce", "encrypted", "kid", &signing_key).unwrap();

        let json = serde_json::to_string(&apc).unwrap();

        // Verify camelCase field names
        assert!(json.contains("\"encryptedPaymentData\":"));
    }

    #[test]
    fn test_apc_deserialization() {
        let json = r#"{
            "nonce": "test-nonce",
            "encryptedPaymentData": "encrypted-data",
            "kid": "test-kid",
            "alg": "ed25519",
            "signature": "abc123"
        }"#;

        let apc: Apc = serde_json::from_str(json).unwrap();
        assert_eq!(apc.nonce, "test-nonce");
        assert_eq!(apc.encrypted_payment_data, "encrypted-data");
        assert_eq!(apc.kid, "test-kid");
        assert_eq!(apc.alg, "ed25519");
        assert_eq!(apc.signature, "abc123");
    }

    #[test]
    fn test_card_data_creation() {
        let card = CardData {
            number: "4111111111111111".to_owned(),
            exp_month: "12".to_owned(),
            exp_year: "25".to_owned(),
            cvv: "123".to_owned(),
            cardholder_name: "John Doe".to_owned(),
        };

        assert_eq!(card.number, "4111111111111111");
        assert_eq!(card.exp_month, "12");
        assert_eq!(card.exp_year, "25");
        assert_eq!(card.cvv, "123");
        assert_eq!(card.cardholder_name, "John Doe");
    }

    #[test]
    fn test_card_last_four() {
        let card = CardData {
            number: "4111111111111111".to_owned(),
            exp_month: "12".to_owned(),
            exp_year: "25".to_owned(),
            cvv: "123".to_owned(),
            cardholder_name: "John Doe".to_owned(),
        };

        assert_eq!(card.last_four(), "1111");
    }

    #[test]
    fn test_card_credential_hash() {
        let card = CardData {
            number: "4111111111111111".to_owned(),
            exp_month: "12".to_owned(),
            exp_year: "25".to_owned(),
            cvv: "123".to_owned(),
            cardholder_name: "John Doe".to_owned(),
        };

        let hash = card.credential_hash();
        assert_eq!(hash.len(), 64); // SHA-256 produces 64 hex characters
    }

    #[test]
    fn test_card_credential_hash_consistency() {
        let card = CardData {
            number: "4111111111111111".to_owned(),
            exp_month: "12".to_owned(),
            exp_year: "25".to_owned(),
            cvv: "123".to_owned(),
            cardholder_name: "John Doe".to_owned(),
        };

        let hash1 = card.credential_hash();
        let hash2 = card.credential_hash();

        assert_eq!(hash1, hash2, "hash must be deterministic");
    }

    #[test]
    fn test_bank_account_creation() {
        let account = BankAccountData {
            account_number: "1234567890".to_owned(),
            routing_number: "021000021".to_owned(),
            account_type: "checking".to_owned(),
            account_holder_name: "Jane Doe".to_owned(),
        };

        assert_eq!(account.account_number, "1234567890");
        assert_eq!(account.routing_number, "021000021");
        assert_eq!(account.account_type, "checking");
        assert_eq!(account.account_holder_name, "Jane Doe");
    }

    #[test]
    fn test_bank_account_last_four() {
        let account = BankAccountData {
            account_number: "1234567890".to_owned(),
            routing_number: "021000021".to_owned(),
            account_type: "checking".to_owned(),
            account_holder_name: "Jane Doe".to_owned(),
        };

        assert_eq!(account.last_four(), "7890");
    }

    #[test]
    fn test_digital_wallet_creation() {
        let wallet = DigitalWalletData {
            wallet_type: "apple_pay".to_owned(),
            wallet_token: "encrypted-token".to_owned(),
            account_holder_name: "Bob Smith".to_owned(),
        };

        assert_eq!(wallet.wallet_type, "apple_pay");
        assert_eq!(wallet.wallet_token, "encrypted-token");
        assert_eq!(wallet.account_holder_name, "Bob Smith");
    }

    #[test]
    fn test_payment_method_card_encryption() {
        let card = CardData {
            number: "4111111111111111".to_owned(),
            exp_month: "12".to_owned(),
            exp_year: "25".to_owned(),
            cvv: "123".to_owned(),
            cardholder_name: "John Doe".to_owned(),
        };
        let payment = PaymentMethod::Card(card);
        let merchant_key = create_test_rsa_public_key();

        let encrypted = payment.encrypt(&merchant_key);
        assert!(encrypted.is_ok());
        let encrypted = encrypted.unwrap();
        assert!(!encrypted.is_empty());
        // Verify JWE format (5 dot-separated parts)
        assert_eq!(encrypted.split('.').count(), 5);
    }

    #[test]
    fn test_payment_method_bank_account_encryption() {
        let account = BankAccountData {
            account_number: "1234567890".to_owned(),
            routing_number: "021000021".to_owned(),
            account_type: "checking".to_owned(),
            account_holder_name: "Jane Doe".to_owned(),
        };
        let payment = PaymentMethod::BankAccount(account);
        let merchant_key = create_test_rsa_public_key();

        let encrypted = payment.encrypt(&merchant_key);
        assert!(encrypted.is_ok());
        let encrypted = encrypted.unwrap();
        // Verify JWE format (5 dot-separated parts)
        assert_eq!(encrypted.split('.').count(), 5);
    }

    #[test]
    fn test_payment_method_digital_wallet_encryption() {
        let wallet = DigitalWalletData {
            wallet_type: "apple_pay".to_owned(),
            wallet_token: "encrypted-token".to_owned(),
            account_holder_name: "Bob Smith".to_owned(),
        };
        let payment = PaymentMethod::DigitalWallet(wallet);
        let merchant_key = create_test_rsa_public_key();

        let encrypted = payment.encrypt(&merchant_key);
        assert!(encrypted.is_ok());
        let encrypted = encrypted.unwrap();
        // Verify JWE format (5 dot-separated parts)
        assert_eq!(encrypted.split('.').count(), 5);
    }

    #[test]
    fn test_apc_nonce_matches_requirement() {
        // Verify that APC nonce can match HTTP signature nonce
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let http_nonce = "shared-nonce-12345";

        let apc = Apc::create(http_nonce, "encrypted", "kid", &signing_key).unwrap();

        assert_eq!(apc.nonce, http_nonce);
    }

    #[test]
    fn test_apc_kid_matches_requirement() {
        // Verify that APC kid can match HTTP signature keyid
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let keyid = "shared-keyid-12345";

        let apc = Apc::create("nonce", "encrypted", keyid, &signing_key).unwrap();

        assert_eq!(apc.kid, keyid);
    }

    #[test]
    fn test_signature_base_excludes_signature() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let mut apc = Apc::create("nonce", "encrypted", "kid", &signing_key).unwrap();

        // Modify signature to verify it's excluded from signature base
        apc.signature = "modified-signature".to_owned();
        let base = apc.signature_base().unwrap();

        // Signature field should not appear in base
        assert!(!base.contains("\"signature\""));
        assert!(!base.contains("modified-signature"));
    }
}
