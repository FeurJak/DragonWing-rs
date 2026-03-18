// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Binary Peripheral Protocol (BPP) Codec
//
// Implements a secure container format for Arduino IoT Companion App communication.
// Compatible with the Python implementation in arduino_app_bricks.
//
// Protocol supports three security modes:
// - Mode 0: No Security
// - Mode 1: HMAC-SHA256 Signing (authentication + integrity)
// - Mode 2: ChaCha20-Poly1305 Encryption (confidentiality + authentication + integrity)
//
// Binary format:
// [Version:1][Mode:1][Timestamp:8][Random:4][Payload:Var][AuthTag/Sig:16/32]

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

fn new_hmac(key: &[u8]) -> HmacSha256 {
    <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC can take any size key")
}

/// BPP protocol version
const BPP_VERSION: u8 = 0x00;

/// Security modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecurityMode {
    /// No security (plaintext)
    None = 0x00,
    /// HMAC-SHA256 signing
    Sign = 0x01,
    /// ChaCha20-Poly1305 encryption
    Encrypt = 0x02,
}

impl TryFrom<u8> for SecurityMode {
    type Error = BppError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(SecurityMode::None),
            0x01 => Ok(SecurityMode::Sign),
            0x02 => Ok(SecurityMode::Encrypt),
            _ => Err(BppError::InvalidMode(value)),
        }
    }
}

/// Header size: Version(1) + Mode(1) + Timestamp(8) + Random(4) = 14 bytes
const HEADER_SIZE: usize = 14;

/// HMAC-SHA256 signature size
const HMAC_SIZE: usize = 32;

/// ChaCha20-Poly1305 auth tag size
const AUTH_TAG_SIZE: usize = 16;

/// Replay protection window (10 seconds in microseconds)
const WINDOW_US: i64 = 10_000_000;

/// BPP codec errors
#[derive(Debug, thiserror::Error)]
pub enum BppError {
    #[error("Message too short")]
    MessageTooShort,

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("Invalid security mode: {0}")]
    InvalidMode(u8),

    #[error("Security mode mismatch: expected {expected:?}, got {received:?}")]
    ModeMismatch {
        expected: SecurityMode,
        received: SecurityMode,
    },

    #[error("Message outside validity window (drift: {drift_ms}ms)")]
    ReplayWindowExceeded { drift_ms: i64 },

    #[error("IV/nonce reuse detected")]
    IvReuse,

    #[error("HMAC verification failed")]
    HmacFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Encryption failed")]
    EncryptionFailed,
}

/// Replay protection using a sliding window
struct ReplayProtection {
    window_us: i64,
    cache: HashMap<[u8; 12], i64>, // IV -> expiration timestamp
}

impl ReplayProtection {
    fn new() -> Self {
        Self {
            window_us: WINDOW_US,
            cache: HashMap::new(),
        }
    }

    fn check_and_update(&mut self, iv: &[u8; 12], timestamp_us: i64) -> Result<(), BppError> {
        let now = Self::now_us();

        // Check time window
        let drift = (now - timestamp_us).abs();
        if drift > self.window_us {
            return Err(BppError::ReplayWindowExceeded {
                drift_ms: drift / 1000,
            });
        }

        // Check IV reuse
        if self.cache.contains_key(iv) {
            return Err(BppError::IvReuse);
        }

        // Prune old entries if cache grows too large
        if self.cache.len() > 1000 {
            self.prune(now);
        }

        // Add to cache
        self.cache.insert(*iv, now + self.window_us);
        Ok(())
    }

    fn prune(&mut self, now: i64) {
        self.cache.retain(|_, &mut expiry| now <= expiry);
    }

    fn now_us() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_micros() as i64
    }
}

/// BPP Codec for encoding and decoding messages
pub struct BppCodec {
    secret: Vec<u8>,
    mode: SecurityMode,
    cipher: Option<ChaCha20Poly1305>,
    replay_protection: ReplayProtection,
}

impl BppCodec {
    /// Create a new BPP codec with no security
    pub fn new_plaintext() -> Self {
        Self {
            secret: Vec::new(),
            mode: SecurityMode::None,
            cipher: None,
            replay_protection: ReplayProtection::new(),
        }
    }

    /// Create a new BPP codec with HMAC-SHA256 signing
    pub fn new_signed(secret: &str) -> Self {
        Self {
            secret: secret.as_bytes().to_vec(),
            mode: SecurityMode::Sign,
            cipher: None,
            replay_protection: ReplayProtection::new(),
        }
    }

    /// Create a new BPP codec with ChaCha20-Poly1305 encryption
    pub fn new_encrypted(secret: &str) -> Self {
        // Derive 32-byte key using SHA-256
        let key = Sha256::digest(secret.as_bytes());
        let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("Invalid key length");

        Self {
            secret: secret.as_bytes().to_vec(),
            mode: SecurityMode::Encrypt,
            cipher: Some(cipher),
            replay_protection: ReplayProtection::new(),
        }
    }

    /// Get the current security mode
    pub fn security_mode(&self) -> SecurityMode {
        self.mode
    }

    /// Encode data into a BPP message
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, BppError> {
        let timestamp_us = ReplayProtection::now_us() as u64;
        let random_val: u32 = rand::random();

        // Build header (big-endian)
        let mut header = Vec::with_capacity(HEADER_SIZE);
        header.push(BPP_VERSION);
        header.push(self.mode as u8);
        header.extend_from_slice(&timestamp_us.to_be_bytes());
        header.extend_from_slice(&random_val.to_be_bytes());

        match self.mode {
            SecurityMode::None => {
                let mut message = header;
                message.extend_from_slice(data);
                Ok(message)
            }
            SecurityMode::Sign => {
                // HMAC-SHA256 signature over header + payload
                let mut mac = new_hmac(&self.secret);
                mac.update(&header);
                mac.update(data);
                let signature = mac.finalize().into_bytes();

                let mut message = header;
                message.extend_from_slice(data);
                message.extend_from_slice(&signature);
                Ok(message)
            }
            SecurityMode::Encrypt => {
                let cipher = self.cipher.as_ref().ok_or(BppError::EncryptionFailed)?;

                // IV is last 12 bytes of header (timestamp + random)
                let iv: [u8; 12] = header[2..14].try_into().unwrap();
                let nonce = Nonce::from_slice(&iv);

                // Encrypt with AAD (header) - matches Python implementation
                let payload = Payload {
                    msg: data,
                    aad: &header,
                };
                let ciphertext = cipher
                    .encrypt(nonce, payload)
                    .map_err(|_| BppError::EncryptionFailed)?;

                // Note: ChaCha20Poly1305 appends the 16-byte auth tag automatically
                let mut message = header;
                message.extend_from_slice(&ciphertext);
                Ok(message)
            }
        }
    }

    /// Decode a BPP message and return the payload
    pub fn decode(&mut self, message: &[u8]) -> Result<Vec<u8>, BppError> {
        if message.len() < HEADER_SIZE {
            return Err(BppError::MessageTooShort);
        }

        // Parse header
        let version = message[0];
        let mode = SecurityMode::try_from(message[1])?;
        let timestamp_us = i64::from_be_bytes(message[2..10].try_into().unwrap());
        let _random_val = u32::from_be_bytes(message[10..14].try_into().unwrap());

        if version != BPP_VERSION {
            return Err(BppError::UnsupportedVersion(version));
        }

        // Check security mode matches expected
        if mode != self.mode {
            return Err(BppError::ModeMismatch {
                expected: self.mode,
                received: mode,
            });
        }

        // Calculate footer size
        let footer_size = match mode {
            SecurityMode::None => 0,
            SecurityMode::Sign => HMAC_SIZE,
            SecurityMode::Encrypt => AUTH_TAG_SIZE,
        };

        if message.len() < HEADER_SIZE + footer_size {
            return Err(BppError::MessageTooShort);
        }

        // Check replay protection
        let iv: [u8; 12] = message[2..14].try_into().unwrap();
        self.replay_protection.check_and_update(&iv, timestamp_us)?;

        let header = &message[..HEADER_SIZE];

        match mode {
            SecurityMode::None => Ok(message[HEADER_SIZE..].to_vec()),

            SecurityMode::Sign => {
                let payload = &message[HEADER_SIZE..message.len() - HMAC_SIZE];
                let received_sig = &message[message.len() - HMAC_SIZE..];

                // Verify HMAC
                let mut mac = new_hmac(&self.secret);
                mac.update(header);
                mac.update(payload);

                mac.verify_slice(received_sig)
                    .map_err(|_| BppError::HmacFailed)?;

                Ok(payload.to_vec())
            }

            SecurityMode::Encrypt => {
                let cipher = self.cipher.as_ref().ok_or(BppError::DecryptionFailed)?;

                let nonce = Nonce::from_slice(&iv);
                let ciphertext_with_tag = &message[HEADER_SIZE..];

                // Decrypt with AAD (header) - matches Python implementation
                let payload = Payload {
                    msg: ciphertext_with_tag,
                    aad: header,
                };
                cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| BppError::DecryptionFailed)
            }
        }
    }

    /// Encode data and return as base64 string (text-safe)
    pub fn encode_text(&self, data: &[u8]) -> Result<String, BppError> {
        let binary = self.encode(data)?;
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            binary,
        ))
    }

    /// Decode a base64-encoded BPP message
    pub fn decode_text(&mut self, b64: &str) -> Result<Vec<u8>, BppError> {
        use base64::Engine;
        let binary = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| BppError::MessageTooShort)?;
        self.decode(&binary)
    }
}

impl std::fmt::Display for SecurityMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityMode::None => write!(f, "none"),
            SecurityMode::Sign => write!(f, "authenticated (HMAC-SHA256)"),
            SecurityMode::Encrypt => write!(f, "encrypted (ChaCha20-Poly1305)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plaintext_roundtrip() {
        let codec = BppCodec::new_plaintext();
        let data = b"Hello, world!";

        let encoded = codec.encode(data).unwrap();
        assert!(encoded.len() >= HEADER_SIZE + data.len());

        let mut decoder = BppCodec::new_plaintext();
        let decoded = decoder.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_signed_roundtrip() {
        let secret = "123456";
        let codec = BppCodec::new_signed(secret);
        let data = b"Secret message";

        let encoded = codec.encode(data).unwrap();
        assert!(encoded.len() >= HEADER_SIZE + data.len() + HMAC_SIZE);

        let mut decoder = BppCodec::new_signed(secret);
        let decoded = decoder.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encrypted_roundtrip() {
        let secret = "123456";
        let codec = BppCodec::new_encrypted(secret);
        let data = b"Top secret message";

        let encoded = codec.encode(data).unwrap();
        // Ciphertext + auth tag
        assert!(encoded.len() >= HEADER_SIZE + data.len() + AUTH_TAG_SIZE);

        let mut decoder = BppCodec::new_encrypted(secret);
        let decoded = decoder.decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_wrong_secret_fails() {
        let codec = BppCodec::new_signed("correct");
        let data = b"Message";

        let encoded = codec.encode(data).unwrap();

        let mut decoder = BppCodec::new_signed("wrong");
        assert!(decoder.decode(&encoded).is_err());
    }

    #[test]
    fn test_mode_mismatch_fails() {
        let codec = BppCodec::new_encrypted("secret");
        let data = b"Message";

        let encoded = codec.encode(data).unwrap();

        let mut decoder = BppCodec::new_signed("secret");
        let result = decoder.decode(&encoded);
        assert!(matches!(result, Err(BppError::ModeMismatch { .. })));
    }
}
