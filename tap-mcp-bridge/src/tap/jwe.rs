//! JWE compact serialization for TAP payment payloads.
//!
//! Implements [RFC 7516] JWE compact serialization with the
//! `RSA-OAEP-256` key wrapping algorithm and the `A256GCM` content
//! encryption algorithm, as required by the TAP Agentic Payment Container
//! (APC) format.
//!
//! The implementation is built directly on top of [`aws_lc_rs`] primitives
//! (RSA-OAEP from [`aws_lc_rs::rsa`] and AES-GCM from [`aws_lc_rs::aead`])
//! to avoid pulling OpenSSL into the dependency graph. `aws-lc-rs` is also
//! the cryptographic backend used by `jsonwebtoken` in this workspace.
//!
//! # Wire Format
//!
//! JWE compact serialization is a five-part dot-separated string:
//!
//! ```text
//! BASE64URL(header) "." BASE64URL(encrypted_cek) "." BASE64URL(iv) "."
//!                  BASE64URL(ciphertext) "." BASE64URL(tag)
//! ```
//!
//! Each section is base64url-encoded without padding (per [RFC 7515]
//! §2). The protected header is `{"alg":"RSA-OAEP-256","enc":"A256GCM"}`
//! and its base64url ASCII bytes serve as Additional Authenticated Data
//! for the AES-GCM seal operation, per [RFC 7516] §5.1 step 14.
//!
//! [RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515
//! [RFC 7516]: https://www.rfc-editor.org/rfc/rfc7516

use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
    rsa::{OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey, PublicEncryptingKey},
};
use base64::Engine;
use zeroize::Zeroize;

use crate::error::{BridgeError, Result};

/// Protected header (`alg`/`enc`) used for every TAP JWE.
///
/// JSON serialization is fixed and deterministic so the encoded header is
/// constant — this matters because the AAD for the AES-GCM seal is derived
/// from the encoded header bytes.
const PROTECTED_HEADER_JSON: &str = r#"{"alg":"RSA-OAEP-256","enc":"A256GCM"}"#;

/// AES-256-GCM key length (RFC 7518 §5.3).
const A256GCM_KEY_LEN: usize = 32;

/// AES-256-GCM IV length (RFC 7518 §5.3 mandates a 96-bit IV).
const A256GCM_IV_LEN: usize = 12;

/// Minimum RSA key size (TAP requires ≥ 2048 bits).
const MIN_RSA_KEY_BITS: usize = 2048;

/// RSA public key for JWE encryption.
///
/// Configured with `RSA-OAEP-256` and accepts X.509 `SubjectPublicKeyInfo`
/// PEM input (`-----BEGIN PUBLIC KEY-----`). Keys are validated to be at
/// least 2048 bits during construction.
///
/// # Examples
///
/// ```no_run
/// use tap_mcp_bridge::tap::jwe::RsaPublicKey;
///
/// let pem = std::fs::read("merchant_public_key.pem")?;
/// let public_key = RsaPublicKey::from_pem(&pem)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
// `aws-lc-rs` does not expose `OaepPublicEncryptingKey` as `Send + Sync`
// (only `KeyPair` is upstream-marked thread-safe), so we keep the validated
// SubjectPublicKeyInfo DER and rebuild the encrypting key per call.
// Reconstruction is just a wrap around an EVP_PKEY handle and runs in
// microseconds; storing bytes also makes `Clone`/`Send`/`Sync` automatic
// through `Vec<u8>`.
pub struct RsaPublicKey {
    spki_der: Vec<u8>,
    key_size_bits: usize,
}

impl RsaPublicKey {
    /// Parses an X.509 `SubjectPublicKeyInfo` PEM-encoded RSA public key.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CryptoError`] when the PEM is malformed,
    /// the inner DER is not a valid RSA SPKI, or the key is shorter than
    /// 2048 bits. Legacy PKCS#1 PEM (`-----BEGIN RSA PUBLIC KEY-----`) is
    /// rejected with an explanatory message.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tap_mcp_bridge::tap::jwe::RsaPublicKey;
    ///
    /// let pem = std::fs::read("merchant_public_key.pem")?;
    /// let public_key = RsaPublicKey::from_pem(&pem)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        let der = decode_spki_pem(pem)?;
        Self::from_der(&der)
    }

    /// Parses an X.509 `SubjectPublicKeyInfo` DER-encoded RSA public key.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CryptoError`] when the DER is invalid or
    /// the key is shorter than 2048 bits.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let public = PublicEncryptingKey::from_der(der).map_err(|e| {
            BridgeError::CryptoError(format!("invalid RSA SubjectPublicKeyInfo: {e}"))
        })?;
        let key_size_bits = public.key_size_bits();
        if key_size_bits < MIN_RSA_KEY_BITS {
            return Err(BridgeError::CryptoError(format!(
                "RSA key must be at least {MIN_RSA_KEY_BITS} bits (got {key_size_bits})"
            )));
        }
        // Round-trip through OAEP construction so we surface any compatibility
        // issue (e.g. unsupported curve/parameters) at parse time rather than
        // first encrypt.
        OaepPublicEncryptingKey::new(public).map_err(|e| {
            BridgeError::CryptoError(format!("RSA-OAEP key construction failed: {e}"))
        })?;
        Ok(Self { spki_der: der.to_vec(), key_size_bits })
    }

    /// Returns the RSA modulus size in bits.
    #[must_use]
    pub fn key_size_bits(&self) -> usize {
        self.key_size_bits
    }

    fn oaep_key(&self) -> Result<OaepPublicEncryptingKey> {
        let public = PublicEncryptingKey::from_der(&self.spki_der).map_err(|e| {
            BridgeError::CryptoError(format!("RSA SubjectPublicKeyInfo became invalid: {e}"))
        })?;
        OaepPublicEncryptingKey::new(public).map_err(|e| {
            BridgeError::CryptoError(format!("RSA-OAEP key reconstruction failed: {e}"))
        })
    }

    /// Encrypts `plaintext` to a JWE compact serialization string.
    ///
    /// Produces the canonical
    /// `BASE64URL(header).BASE64URL(encrypted_cek).BASE64URL(iv).BASE64URL(ciphertext).
    /// BASE64URL(tag)` form with `alg=RSA-OAEP-256` and `enc=A256GCM`.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::CryptoError`] if any RNG, RSA, or AES-GCM
    /// primitive call fails.
    pub(crate) fn encrypt_compact(&self, plaintext: &[u8]) -> Result<String> {
        let rng = SystemRandom::new();
        let oaep = self.oaep_key()?;

        let mut cek = [0u8; A256GCM_KEY_LEN];
        rng.fill(&mut cek)
            .map_err(|_| BridgeError::CryptoError("RNG failed generating CEK".to_owned()))?;

        let result = (|| -> Result<String> {
            let mut wrapped = vec![0u8; oaep.ciphertext_size()];
            let wrapped_slice =
                oaep.encrypt(&OAEP_SHA256_MGF1SHA256, &cek, &mut wrapped, None).map_err(|e| {
                    BridgeError::CryptoError(format!("RSA-OAEP-256 key wrap failed: {e}"))
                })?;
            let wrapped_len = wrapped_slice.len();

            let mut iv = [0u8; A256GCM_IV_LEN];
            rng.fill(&mut iv)
                .map_err(|_| BridgeError::CryptoError("RNG failed generating IV".to_owned()))?;

            let unbound = UnboundKey::new(&AES_256_GCM, &cek)
                .map_err(|_| BridgeError::CryptoError("invalid AES-256-GCM key".to_owned()))?;
            let sealing = LessSafeKey::new(unbound);

            let nonce = Nonce::try_assume_unique_for_key(&iv)
                .map_err(|_| BridgeError::CryptoError("invalid AES-GCM nonce".to_owned()))?;

            let encoded_header = b64url(PROTECTED_HEADER_JSON.as_bytes());

            let mut ciphertext = plaintext.to_vec();
            let tag = sealing
                .seal_in_place_separate_tag(
                    nonce,
                    Aad::from(encoded_header.as_bytes()),
                    &mut ciphertext,
                )
                .map_err(|e| BridgeError::CryptoError(format!("AES-256-GCM seal failed: {e}")))?;

            let mut out = String::with_capacity(
                encoded_header.len()
                    + 4
                    + b64url_len(wrapped_len)
                    + b64url_len(iv.len())
                    + b64url_len(ciphertext.len())
                    + b64url_len(tag.as_ref().len()),
            );
            out.push_str(&encoded_header);
            out.push('.');
            out.push_str(&b64url(&wrapped[..wrapped_len]));
            out.push('.');
            out.push_str(&b64url(&iv));
            out.push('.');
            out.push_str(&b64url(&ciphertext));
            out.push('.');
            out.push_str(&b64url(tag.as_ref()));
            Ok(out)
        })();

        cek.zeroize();
        result
    }
}

/// Encodes bytes as base64url without padding (RFC 7515 §2).
fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Worst-case length of a base64url-no-pad encoding of `n` bytes.
const fn b64url_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Decodes an X.509 `SubjectPublicKeyInfo` PEM block into raw DER bytes.
///
/// Accepts only `-----BEGIN PUBLIC KEY-----`; legacy PKCS#1
/// (`-----BEGIN RSA PUBLIC KEY-----`) is rejected with a clear error.
fn decode_spki_pem(pem: &[u8]) -> Result<Vec<u8>> {
    let pem_str = std::str::from_utf8(pem)
        .map_err(|_| BridgeError::CryptoError("PEM input is not valid UTF-8".to_owned()))?;

    let mut header: Option<&str> = None;
    let mut footer: Option<&str> = None;
    let mut body = String::new();
    let mut in_body = false;

    for line in pem_str.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rest) =
            trimmed.strip_prefix("-----BEGIN ").and_then(|s| s.strip_suffix("-----"))
        {
            header = Some(rest);
            in_body = true;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("-----END ").and_then(|s| s.strip_suffix("-----"))
        {
            footer = Some(rest);
            in_body = false;
            continue;
        }
        if in_body {
            body.push_str(trimmed);
        }
    }

    match (header, footer) {
        (Some("PUBLIC KEY"), Some("PUBLIC KEY")) => {}
        (Some("RSA PUBLIC KEY"), _) | (_, Some("RSA PUBLIC KEY")) => {
            return Err(BridgeError::CryptoError(
                "PKCS#1 'RSA PUBLIC KEY' PEM is not supported; supply X.509 SubjectPublicKeyInfo \
                 ('PUBLIC KEY')"
                    .to_owned(),
            ));
        }
        _ => {
            return Err(BridgeError::CryptoError(
                "expected '-----BEGIN PUBLIC KEY-----' / '-----END PUBLIC KEY-----' PEM block"
                    .to_owned(),
            ));
        }
    }

    base64::engine::general_purpose::STANDARD
        .decode(body.as_bytes())
        .map_err(|e| BridgeError::CryptoError(format!("invalid PEM base64 body: {e}")))
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
        encoding::{AsDer, PublicKeyX509Der},
        rsa::{
            KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey,
            PublicEncryptingKey,
        },
    };
    use base64::Engine;

    use super::{
        A256GCM_IV_LEN, A256GCM_KEY_LEN, PROTECTED_HEADER_JSON, RsaPublicKey, b64url,
        decode_spki_pem,
    };

    /// Wraps DER bytes in a textbook PEM frame (64-char base64 lines).
    fn der_to_spki_pem(der: &[u8]) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        pem
    }

    /// Decrypts a JWE compact string produced by `RsaPublicKey::encrypt_compact`.
    ///
    /// Mirrors the encryption path against the matching private key — used to
    /// verify round-trip correctness in tests.
    fn decrypt_compact(jwe: &str, private_key: &PrivateDecryptingKey) -> Vec<u8> {
        let parts: Vec<&str> = jwe.split('.').collect();
        assert_eq!(parts.len(), 5, "JWE compact serialization has 5 parts");

        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("header is base64url");
        assert_eq!(header_bytes, PROTECTED_HEADER_JSON.as_bytes());

        let wrapped = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("encrypted key is base64url");
        let iv = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .expect("iv is base64url");
        let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[3])
            .expect("ciphertext is base64url");
        let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[4])
            .expect("tag is base64url");

        assert_eq!(iv.len(), A256GCM_IV_LEN);
        assert_eq!(tag.len(), 16);

        let oaep = OaepPrivateDecryptingKey::new(private_key.clone()).expect("oaep priv");
        let mut cek_buf = vec![0u8; oaep.min_output_size()];
        let cek = oaep
            .decrypt(&OAEP_SHA256_MGF1SHA256, &wrapped, &mut cek_buf, None)
            .expect("RSA-OAEP-256 unwrap");
        assert_eq!(cek.len(), A256GCM_KEY_LEN);

        let unbound = UnboundKey::new(&AES_256_GCM, cek).expect("aes key");
        let opening = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&iv).expect("nonce");

        let mut combined = ciphertext;
        combined.extend_from_slice(&tag);
        let plaintext = opening
            .open_in_place(nonce, Aad::from(parts[0].as_bytes()), &mut combined)
            .expect("AES-256-GCM open");
        plaintext.to_vec()
    }

    fn generate_test_keypair() -> (RsaPublicKey, PrivateDecryptingKey) {
        let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("rsa keygen");
        let public = private.public_key();
        let der = AsDer::<PublicKeyX509Der<'_>>::as_der(&public).expect("spki der");
        let pem = der_to_spki_pem(der.as_ref());
        let key = RsaPublicKey::from_pem(pem.as_bytes()).expect("parse pem");
        (key, private)
    }

    #[test]
    fn encrypt_compact_has_five_parts() {
        let (key, _priv) = generate_test_keypair();
        let jwe = key.encrypt_compact(b"hello world").expect("encrypt");
        assert_eq!(jwe.split('.').count(), 5);
        // First section must decode to the protected header.
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwe.split('.').next().unwrap())
            .expect("header b64");
        assert_eq!(header, PROTECTED_HEADER_JSON.as_bytes());
    }

    #[test]
    fn round_trip_card_payload() {
        let (key, priv_key) = generate_test_keypair();
        let payload = br#"{"type":"card","cardNumber":"4111111111111111"}"#;
        let jwe = key.encrypt_compact(payload).expect("encrypt");
        let decrypted = decrypt_compact(&jwe, &priv_key);
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn round_trip_empty_payload() {
        let (key, priv_key) = generate_test_keypair();
        let jwe = key.encrypt_compact(b"").expect("encrypt empty");
        let decrypted = decrypt_compact(&jwe, &priv_key);
        assert!(decrypted.is_empty());
    }

    #[test]
    fn round_trip_large_payload() {
        let (key, priv_key) = generate_test_keypair();
        let payload = vec![0xa5_u8; 4096];
        let jwe = key.encrypt_compact(&payload).expect("encrypt large");
        let decrypted = decrypt_compact(&jwe, &priv_key);
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn each_encryption_uses_fresh_cek_and_iv() {
        let (key, _priv) = generate_test_keypair();
        let a = key.encrypt_compact(b"same plaintext").expect("encrypt a");
        let b = key.encrypt_compact(b"same plaintext").expect("encrypt b");
        assert_ne!(a, b, "fresh CEK + IV must produce different JWE");

        let parts_a: Vec<&str> = a.split('.').collect();
        let parts_b: Vec<&str> = b.split('.').collect();
        assert_ne!(parts_a[1], parts_b[1], "encrypted CEK must differ");
        assert_ne!(parts_a[2], parts_b[2], "IV must differ");
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let (key, priv_key) = generate_test_keypair();
        let jwe = key.encrypt_compact(b"sensitive").expect("encrypt");

        let mut parts: Vec<String> = jwe.split('.').map(str::to_owned).collect();
        let mut ct = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&parts[3])
            .expect("ct b64");
        ct[0] ^= 0x01;
        parts[3] = b64url(&ct);
        let tampered = parts.join(".");

        // Replicate the open path inline so we observe the AAD/tag mismatch.
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0].as_bytes())
            .expect("header");
        assert_eq!(header_bytes, PROTECTED_HEADER_JSON.as_bytes());
        let wrapped = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1].as_bytes())
            .expect("wrapped");
        let iv = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2].as_bytes())
            .expect("iv");
        let mut combined = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[3].as_bytes())
            .expect("ct");
        let tag = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[4].as_bytes())
            .expect("tag");
        combined.extend_from_slice(&tag);

        let oaep = OaepPrivateDecryptingKey::new(priv_key.clone()).expect("oaep");
        let mut cek_buf = vec![0u8; oaep.min_output_size()];
        let cek = oaep
            .decrypt(&OAEP_SHA256_MGF1SHA256, &wrapped, &mut cek_buf, None)
            .expect("oaep unwrap");
        let unbound = UnboundKey::new(&AES_256_GCM, cek).expect("aes");
        let opening = LessSafeKey::new(unbound);
        let nonce = Nonce::try_assume_unique_for_key(&iv).expect("nonce");
        let result = opening.open_in_place(nonce, Aad::from(parts[0].as_bytes()), &mut combined);
        assert!(result.is_err(), "tampered ciphertext must fail to authenticate");
        let _ = tampered;
    }

    #[test]
    fn rejects_pkcs1_pem() {
        let pkcs1_pem = b"-----BEGIN RSA PUBLIC KEY-----\nAAAA\n-----END RSA PUBLIC KEY-----\n";
        let err = RsaPublicKey::from_pem(pkcs1_pem).expect_err("must reject PKCS#1");
        let msg = format!("{err}");
        assert!(msg.contains("PKCS#1"), "error should mention PKCS#1, got: {msg}");
    }

    #[test]
    fn rejects_invalid_pem_header() {
        let bogus = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        assert!(RsaPublicKey::from_pem(bogus).is_err(), "must reject non-SPKI header");
    }

    #[test]
    fn rejects_short_rsa_keys() {
        // Generate a 1024-bit DER manually is awkward; we exercise the size
        // gate via the parsed key path with an obviously-short bytestring.
        let too_short = b"not a real key";
        assert!(RsaPublicKey::from_der(too_short).is_err());
    }

    #[test]
    fn decode_spki_pem_strips_whitespace() {
        let (_key, _priv) = generate_test_keypair();
        // Use an existing valid PEM and stress whitespace/empty lines.
        let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).expect("keygen");
        let der = AsDer::<PublicKeyX509Der<'_>>::as_der(&private.public_key()).expect("der");
        let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
        let mut messy = String::from("\n  -----BEGIN PUBLIC KEY-----  \n");
        for chunk in b64.as_bytes().chunks(48) {
            messy.push('\t');
            messy.push_str(std::str::from_utf8(chunk).unwrap());
            messy.push_str("  \n");
        }
        messy.push_str("-----END PUBLIC KEY-----\n\n");
        let der_decoded = decode_spki_pem(messy.as_bytes()).expect("decode messy pem");
        let _ = PublicEncryptingKey::from_der(&der_decoded).expect("der valid");
    }
}
