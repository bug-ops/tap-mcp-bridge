//! Agentic Consumer Recognition Object (ACRO) for TAP.
//!
//! This module implements the ACRO specification for TAP, which provides
//! consumer identity verification and contextual data about the consumer's
//! location and device.
//!
//! # ACRO Purpose
//!
//! The ACRO identifies the consumer on whose behalf the agent is acting and
//! provides verification of consumer identity. It includes:
//! - Consumer ID token (JWT)
//! - Location context (country code, postal code, IP address)
//! - Device fingerprinting data
//! - Digital signature over all fields
//!
//! # TAP Requirements
//!
//! - **Nonce correlation**: ACRO nonce MUST match HTTP signature nonce
//! - **Kid matching**: ACRO kid SHOULD match HTTP signature keyid
//! - **Signature**: Signs all fields except the signature field itself
//! - **Algorithm**: Uses Ed25519 (same key as HTTP signatures)
//!
//! # Examples
//!
//! ```
//! use ed25519_dalek::SigningKey;
//! use tap_mcp_bridge::tap::{
//!     TapSigner,
//!     acro::{ContextualData, DeviceData},
//! };
//!
//! # fn example() -> tap_mcp_bridge::error::Result<()> {
//! let signing_key = SigningKey::from_bytes(&[0u8; 32]);
//! let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
//!
//! // Generate ID token first
//! let id_token =
//!     signer.generate_id_token("user-456", "https://merchant.example.com", "nonce-unique-123")?;
//!
//! // Create contextual data
//! let contextual_data = ContextualData {
//!     country_code: "US".to_owned(),
//!     zip: "94103".to_owned(),
//!     ip_address: "192.168.1.100".to_owned(),
//!     device_data: DeviceData {
//!         user_agent: "Mozilla/5.0 (X11; Linux x86_64)".to_owned(),
//!         platform: "Linux".to_owned(),
//!     },
//! };
//!
//! // Generate ACRO
//! let acro = signer.generate_acro("nonce-unique-123", &id_token.token, contextual_data)?;
//!
//! println!("ACRO nonce: {}", acro.nonce);
//! # Ok(())
//! # }
//! ```

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use signature::Signer;

use crate::error::{BridgeError, Result};

/// Agentic Consumer Recognition Object (ACRO).
///
/// Identifies the consumer on whose behalf the agent is acting and provides
/// verification of consumer identity per TAP specification.
///
/// # TAP Requirements
///
/// - `nonce` must match HTTP Message Signature nonce
/// - `kid` should match HTTP Message Signature keyid
/// - `signature` covers all fields except itself
/// - Signature uses same Ed25519 key as HTTP signatures
///
/// # Examples
///
/// ```
/// # use ed25519_dalek::SigningKey;
/// use tap_mcp_bridge::tap::{
///     TapSigner,
///     acro::{ContextualData, DeviceData},
/// };
///
/// # fn example() -> tap_mcp_bridge::error::Result<()> {
/// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
/// let signer = TapSigner::new(signing_key, "agent-123", "https://agent.example.com");
///
/// let id_token = signer.generate_id_token("user", "https://m.com", "nonce")?;
/// let contextual_data = ContextualData {
///     country_code: "US".to_owned(),
///     zip: "94103".to_owned(),
///     ip_address: "192.168.1.1".to_owned(),
///     device_data: DeviceData {
///         user_agent: "Mozilla/5.0".to_owned(),
///         platform: "Linux".to_owned(),
///     },
/// };
///
/// let acro = signer.generate_acro("nonce", &id_token.token, contextual_data)?;
/// assert_eq!(acro.nonce, "nonce");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acro {
    /// Nonce for replay protection (must match HTTP signature nonce).
    pub nonce: String,

    /// ID token (JWT) containing consumer claims.
    #[serde(rename = "idToken")]
    pub id_token: String,

    /// Contextual data about consumer location and device.
    #[serde(rename = "contextualData")]
    pub contextual_data: ContextualData,

    /// Public key identifier (JWK thumbprint).
    pub kid: String,

    /// Signature algorithm (always "ed25519").
    pub alg: String,

    /// Base64url-encoded signature over all other fields.
    pub signature: String,
}

impl Acro {
    /// Creates and signs an ACRO.
    ///
    /// # Arguments
    ///
    /// * `nonce` - Nonce (must match HTTP signature nonce)
    /// * `id_token` - JWT ID token string
    /// * `contextual_data` - Consumer location and device data
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
    /// use tap_mcp_bridge::tap::acro::{Acro, ContextualData, DeviceData};
    ///
    /// # fn example() -> tap_mcp_bridge::error::Result<()> {
    /// let signing_key = SigningKey::from_bytes(&[0u8; 32]);
    /// let contextual_data = ContextualData {
    ///     country_code: "US".to_owned(),
    ///     zip: "94103".to_owned(),
    ///     ip_address: "192.168.1.1".to_owned(),
    ///     device_data: DeviceData {
    ///         user_agent: "Mozilla/5.0".to_owned(),
    ///         platform: "Linux".to_owned(),
    ///     },
    /// };
    ///
    /// let acro =
    ///     Acro::create("test-nonce", "test.id.token", contextual_data, "test-kid", &signing_key)?;
    ///
    /// assert_eq!(acro.nonce, "test-nonce");
    /// assert_eq!(acro.kid, "test-kid");
    /// assert_eq!(acro.alg, "ed25519");
    /// assert!(!acro.signature.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub fn create(
        nonce: &str,
        id_token: &str,
        contextual_data: ContextualData,
        kid: &str,
        signing_key: &SigningKey,
    ) -> Result<Self> {
        // Create unsigned ACRO
        let mut acro = Self {
            nonce: nonce.to_owned(),
            id_token: id_token.to_owned(),
            contextual_data,
            kid: kid.to_owned(),
            alg: "ed25519".to_owned(),
            signature: String::new(), // Placeholder
        };

        // Generate signature over all fields except signature
        let signature = acro.compute_signature(signing_key)?;
        acro.signature = signature;

        Ok(acro)
    }

    /// Computes signature over ACRO fields.
    ///
    /// Signs all fields except the signature field itself using Ed25519.
    /// The signature base is the canonical JSON representation of the ACRO
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
    /// Serializes the ACRO to JSON excluding the signature field to create
    /// the data that will be signed. This uses deterministic JSON serialization
    /// to ensure the signature can be verified.
    fn signature_base(&self) -> Result<String> {
        // Helper struct for serialization without signature field
        #[derive(Serialize)]
        struct AcroBase<'a> {
            nonce: &'a str,
            #[serde(rename = "idToken")]
            id_token: &'a str,
            #[serde(rename = "contextualData")]
            contextual_data: &'a ContextualData,
            kid: &'a str,
            alg: &'a str,
        }

        // Serialize to JSON without signature field
        let base = AcroBase {
            nonce: &self.nonce,
            id_token: &self.id_token,
            contextual_data: &self.contextual_data,
            kid: &self.kid,
            alg: &self.alg,
        };

        serde_json::to_string(&base)
            .map_err(|e| BridgeError::CryptoError(format!("ACRO JSON serialization failed: {e}")))
    }
}

/// Contextual information about consumer location and device.
///
/// Provides additional context about the consumer's location and device
/// for fraud prevention and regulatory compliance.
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::tap::acro::{ContextualData, DeviceData};
///
/// let data = ContextualData {
///     country_code: "US".to_owned(),
///     zip: "94103".to_owned(),
///     ip_address: "192.168.1.100".to_owned(),
///     device_data: DeviceData {
///         user_agent: "Mozilla/5.0 (X11; Linux x86_64)".to_owned(),
///         platform: "Linux".to_owned(),
///     },
/// };
///
/// assert_eq!(data.country_code, "US");
/// assert_eq!(data.zip, "94103");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextualData {
    /// ISO 3166-1 alpha-2 country code (e.g., "US", "CA").
    ///
    /// Identifies the country where the consumer is located.
    /// Must be a valid two-letter country code per ISO 3166-1 alpha-2.
    #[serde(rename = "countryCode")]
    pub country_code: String,

    /// Postal code or city/state identifier (max 16 characters).
    ///
    /// Provides more specific location information within the country.
    /// May be a postal code, ZIP code, or city/state combination.
    pub zip: String,

    /// Consumer device IP address.
    ///
    /// The IP address of the device the consumer is using.
    /// May be IPv4 or IPv6 format.
    #[serde(rename = "ipAddress")]
    pub ip_address: String,

    /// Device fingerprinting information.
    ///
    /// Additional data about the consumer's device for fraud prevention.
    #[serde(rename = "deviceData")]
    pub device_data: DeviceData,
}

/// Device fingerprinting information.
///
/// Captures device characteristics for fraud prevention and analytics.
///
/// # Examples
///
/// ```
/// use tap_mcp_bridge::tap::acro::DeviceData;
///
/// let device = DeviceData {
///     user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36".to_owned(),
///     platform: "Linux x86_64".to_owned(),
/// };
///
/// assert_eq!(device.platform, "Linux x86_64");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceData {
    /// User agent string from browser/device.
    ///
    /// The User-Agent HTTP header value from the consumer's browser or device.
    /// Used to identify the browser type, version, and operating system.
    #[serde(rename = "userAgent")]
    pub user_agent: String,

    /// Operating system platform.
    ///
    /// Identifies the operating system and platform the consumer is using.
    /// Examples: "Linux", "Windows", "macOS", "iOS", "Android".
    pub platform: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper struct for test verification
    #[derive(Serialize)]
    struct AcroBaseForTest<'a> {
        nonce: &'a str,
        #[serde(rename = "idToken")]
        id_token: &'a str,
        #[serde(rename = "contextualData")]
        contextual_data: &'a ContextualData,
        kid: &'a str,
        alg: &'a str,
    }

    fn create_test_contextual_data() -> ContextualData {
        ContextualData {
            country_code: "US".to_owned(),
            zip: "94103".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            device_data: DeviceData {
                user_agent: "Mozilla/5.0".to_owned(),
                platform: "Linux".to_owned(),
            },
        }
    }

    #[test]
    fn test_acro_creation() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let contextual_data = create_test_contextual_data();

        let acro =
            Acro::create("test-nonce", "test.id.token", contextual_data, "test-kid", &signing_key);

        assert!(acro.is_ok());
        let acro = acro.unwrap();
        assert_eq!(acro.nonce, "test-nonce");
        assert_eq!(acro.id_token, "test.id.token");
        assert_eq!(acro.kid, "test-kid");
        assert_eq!(acro.alg, "ed25519");
        assert!(!acro.signature.is_empty());
    }

    #[test]
    fn test_acro_signature_not_empty() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let acro =
            Acro::create("nonce", "token", create_test_contextual_data(), "kid", &signing_key)
                .unwrap();

        assert!(!acro.signature.is_empty());
        // Base64url encoded Ed25519 signature should be ~86 characters (64 bytes)
        assert!(acro.signature.len() > 80);
    }

    #[test]
    fn test_acro_signature_verifiable() {
        use ed25519_dalek::Signature;
        use signature::Verifier;

        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let contextual_data = create_test_contextual_data();

        let acro =
            Acro::create("test-nonce", "test.token", contextual_data, "test-kid", &signing_key)
                .unwrap();

        // Reconstruct signature base
        let base = AcroBaseForTest {
            nonce: &acro.nonce,
            id_token: &acro.id_token,
            contextual_data: &acro.contextual_data,
            kid: &acro.kid,
            alg: &acro.alg,
        };

        let signature_base = serde_json::to_string(&base).unwrap();

        // Decode signature
        let signature_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &acro.signature,
        )
        .expect("signature should be valid base64url");

        let signature =
            Signature::from_bytes(&signature_bytes.try_into().expect("signature is 64 bytes"));

        // Verify signature
        assert!(
            verifying_key.verify(signature_base.as_bytes(), &signature).is_ok(),
            "ACRO signature must be verifiable"
        );
    }

    #[test]
    fn test_acro_different_keys_different_signatures() {
        let key1 = SigningKey::from_bytes(&[0u8; 32]);
        let key2 = SigningKey::from_bytes(&[1u8; 32]);

        let acro1 =
            Acro::create("nonce", "token", create_test_contextual_data(), "kid", &key1).unwrap();
        let acro2 =
            Acro::create("nonce", "token", create_test_contextual_data(), "kid", &key2).unwrap();

        assert_ne!(
            acro1.signature, acro2.signature,
            "different keys must produce different signatures"
        );
    }

    #[test]
    fn test_acro_different_data_different_signatures() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);

        let data1 = ContextualData {
            country_code: "US".to_owned(),
            zip: "94103".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            device_data: DeviceData {
                user_agent: "Mozilla/5.0".to_owned(),
                platform: "Linux".to_owned(),
            },
        };

        let data2 = ContextualData {
            country_code: "CA".to_owned(), // Different country
            zip: "M5H 2N2".to_owned(),
            ip_address: "192.168.1.1".to_owned(),
            device_data: DeviceData {
                user_agent: "Mozilla/5.0".to_owned(),
                platform: "Linux".to_owned(),
            },
        };

        let acro1 = Acro::create("nonce", "token", data1, "kid", &signing_key).unwrap();
        let acro2 = Acro::create("nonce", "token", data2, "kid", &signing_key).unwrap();

        assert_ne!(
            acro1.signature, acro2.signature,
            "different data must produce different signatures"
        );
    }

    #[test]
    fn test_acro_serialization() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let acro =
            Acro::create("nonce", "token", create_test_contextual_data(), "kid", &signing_key)
                .unwrap();

        let json = serde_json::to_string(&acro).unwrap();

        // Verify camelCase field names
        assert!(json.contains("\"idToken\":"));
        assert!(json.contains("\"contextualData\":"));
        assert!(json.contains("\"countryCode\":"));
        assert!(json.contains("\"ipAddress\":"));
        assert!(json.contains("\"deviceData\":"));
        assert!(json.contains("\"userAgent\":"));
    }

    #[test]
    fn test_acro_deserialization() {
        let json = r#"{
            "nonce": "test-nonce",
            "idToken": "test.token",
            "contextualData": {
                "countryCode": "US",
                "zip": "94103",
                "ipAddress": "192.168.1.1",
                "deviceData": {
                    "userAgent": "Mozilla/5.0",
                    "platform": "Linux"
                }
            },
            "kid": "test-kid",
            "alg": "ed25519",
            "signature": "abc123"
        }"#;

        let acro: Acro = serde_json::from_str(json).unwrap();
        assert_eq!(acro.nonce, "test-nonce");
        assert_eq!(acro.id_token, "test.token");
        assert_eq!(acro.contextual_data.country_code, "US");
        assert_eq!(acro.contextual_data.zip, "94103");
        assert_eq!(acro.kid, "test-kid");
        assert_eq!(acro.alg, "ed25519");
        assert_eq!(acro.signature, "abc123");
    }

    #[test]
    fn test_contextual_data_creation() {
        let data = ContextualData {
            country_code: "CA".to_owned(),
            zip: "M5H 2N2".to_owned(),
            ip_address: "10.0.0.1".to_owned(),
            device_data: DeviceData {
                user_agent: "Chrome/120.0".to_owned(),
                platform: "macOS".to_owned(),
            },
        };

        assert_eq!(data.country_code, "CA");
        assert_eq!(data.zip, "M5H 2N2");
        assert_eq!(data.ip_address, "10.0.0.1");
        assert_eq!(data.device_data.user_agent, "Chrome/120.0");
        assert_eq!(data.device_data.platform, "macOS");
    }

    #[test]
    fn test_device_data_creation() {
        let device =
            DeviceData { user_agent: "Safari/17.0".to_owned(), platform: "iOS".to_owned() };

        assert_eq!(device.user_agent, "Safari/17.0");
        assert_eq!(device.platform, "iOS");
    }

    #[test]
    fn test_signature_base_excludes_signature() {
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let mut acro =
            Acro::create("nonce", "token", create_test_contextual_data(), "kid", &signing_key)
                .unwrap();

        // Modify signature to verify it's excluded from signature base
        acro.signature = "modified-signature".to_owned();
        let base = acro.signature_base().unwrap();

        // Signature field should not appear in base
        assert!(!base.contains("\"signature\""));
        assert!(!base.contains("modified-signature"));
    }

    #[test]
    fn test_acro_nonce_matches_requirement() {
        // Verify that ACRO nonce can match HTTP signature nonce
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let http_nonce = "shared-nonce-12345";

        let acro =
            Acro::create(http_nonce, "token", create_test_contextual_data(), "kid", &signing_key)
                .unwrap();

        assert_eq!(acro.nonce, http_nonce);
    }

    #[test]
    fn test_acro_kid_matches_requirement() {
        // Verify that ACRO kid can match HTTP signature keyid
        let signing_key = SigningKey::from_bytes(&[0u8; 32]);
        let keyid = "shared-keyid-12345";

        let acro =
            Acro::create("nonce", "token", create_test_contextual_data(), keyid, &signing_key)
                .unwrap();

        assert_eq!(acro.kid, keyid);
    }
}
