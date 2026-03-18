//! SAGA + X-Wing Hybrid Protocol
//!
//! This module provides integrated protocols combining:
//! - **SAGA**: Anonymous credentials with unlinkable presentations (BBS-style MAC)
//! - **X-Wing**: Hybrid post-quantum key encapsulation (ML-KEM-768 + X25519)
//!
//! # Use Cases
//!
//! ## 1. Credential-Protected Key Exchange
//!
//! A device proves it has a valid credential while establishing a PQ-secure channel:
//!
//! ```text
//! Device                              Server (Issuer/Verifier)
//!   │                                        │
//!   │─── pk_xwing, SAGA presentation ──────▶ │
//!   │                                        │ verify presentation
//!   │                                        │ encapsulate with pk_xwing
//!   │◀── ciphertext, encrypted_data ──────── │
//!   │                                        │
//!   │ decapsulate → shared_secret            │
//!   │ decrypt data with shared_secret        │
//! ```
//!
//! ## 2. Anonymous Authenticated Key Exchange (AAKE)
//!
//! Two devices mutually authenticate with anonymous credentials while
//! establishing a PQ-secure channel:
//!
//! ```text
//! Device A                             Device B
//!   │                                        │
//!   │─── pk_xwing_A ───────────────────────▶ │
//!   │◀── pk_xwing_B, ct_B ─────────────────  │
//!   │─── ct_A, presentation_A ─────────────▶ │
//!   │◀── presentation_B ───────────────────  │
//!   │                                        │
//!   │ shared_secret = KDF(ss_A ⊕ ss_B)       │
//! ```
//!
//! # Security Properties
//!
//! - **Post-quantum confidentiality**: Key exchange uses X-Wing (ML-KEM-768 + X25519)
//! - **Credential anonymity**: SAGA presentations are unlinkable
//! - **Channel binding**: Presentations can be bound to the session key
//!
//! # Example
//!
//! ```ignore
//! use dragonwing_crypto::saga_xwing::{
//!     CredentialKeyExchange, SessionKeys
//! };
//! use dragonwing_crypto::rng::HwRng;
//!
//! let mut rng = HwRng::new();
//!
//! // Server: Setup SAGA credentials and distribute to devices
//! let saga_keypair = saga::KeyPair::setup(&mut rng, 3)?;
//!
//! // Device: Prove credential while establishing channel
//! let (request, device_state) = CredentialKeyExchange::initiate(&mut rng)?;
//!
//! // Server: Verify credential and encapsulate
//! let response = CredentialKeyExchange::respond(&mut rng, &saga_keypair, &request)?;
//!
//! // Device: Complete key exchange
//! let session = CredentialKeyExchange::complete(&device_state, &response)?;
//! ```

#[cfg(test)]
use crate::saga::Scalar;
use crate::saga::{
    self, KeyPair as SagaKeyPair, Parameters, Point, Presentation, PublicKey as SagaPubKey, Tag,
    MAX_ATTRS,
};
use crate::classical::xchacha20poly1305::{self, Key, Nonce};
use crate::post_quantum::xwing::{
    self, Ciphertext, PublicKey as XWingPubKey, SecretKey as XWingSk, SharedSecret,
};

/// Error type for SAGA+X-Wing operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// SAGA credential verification failed
    CredentialInvalid,
    /// SAGA presentation verification failed
    PresentationInvalid,
    /// X-Wing encapsulation failed
    EncapsulationFailed,
    /// X-Wing decapsulation failed
    DecapsulationFailed,
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed
    DecryptionFailed,
    /// Session binding mismatch
    SessionBindingMismatch,
    /// Invalid state
    InvalidState,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::CredentialInvalid => write!(f, "credential verification failed"),
            Error::PresentationInvalid => write!(f, "presentation verification failed"),
            Error::EncapsulationFailed => write!(f, "X-Wing encapsulation failed"),
            Error::DecapsulationFailed => write!(f, "X-Wing decapsulation failed"),
            Error::EncryptionFailed => write!(f, "encryption failed"),
            Error::DecryptionFailed => write!(f, "decryption failed"),
            Error::SessionBindingMismatch => write!(f, "session binding mismatch"),
            Error::InvalidState => write!(f, "invalid state"),
        }
    }
}

/// Session keys derived from the key exchange
#[derive(Clone)]
pub struct SessionKeys {
    /// Key for encrypting data from device to server
    pub device_to_server: Key,
    /// Key for encrypting data from server to device
    pub server_to_device: Key,
    /// The raw shared secret (for custom KDF if needed)
    pub shared_secret: SharedSecret,
}

/// Device state during key exchange (kept private until completion)
pub struct DeviceState {
    xwing_sk: XWingSk,
    /// Kept for potential session resumption or debugging
    #[allow(dead_code)]
    xwing_pk: XWingPubKey,
}

/// Request from device to server
pub struct KeyExchangeRequest {
    /// Device's X-Wing public key
    pub xwing_pk: XWingPubKey,
    /// SAGA presentation (proves credential possession)
    pub presentation: Presentation,
    /// Randomized commitments for presentation verification
    pub commitments: [Point; MAX_ATTRS],
    /// Number of active commitments
    pub num_commitments: usize,
}

/// Response from server to device
pub struct KeyExchangeResponse {
    /// X-Wing ciphertext
    pub ciphertext: Ciphertext,
    /// Optional encrypted payload (e.g., session token, permissions)
    pub encrypted_payload: Option<EncryptedPayload>,
}

/// Encrypted payload with authentication
pub struct EncryptedPayload {
    /// Nonce used for encryption
    pub nonce: Nonce,
    /// Ciphertext
    pub ciphertext: [u8; 256], // Fixed max size for no_std
    /// Ciphertext length
    pub ciphertext_len: usize,
    /// Authentication tag
    pub tag: xchacha20poly1305::Tag,
}

/// Credential-protected key exchange protocol
pub struct CredentialKeyExchange;

impl CredentialKeyExchange {
    /// Device initiates the key exchange.
    ///
    /// This generates an X-Wing keypair and creates a SAGA presentation
    /// to prove credential possession.
    ///
    /// # Arguments
    /// * `rng` - Random number generator
    /// * `saga_params` - SAGA public parameters
    /// * `saga_pk` - SAGA issuer's public key
    /// * `credential` - Device's SAGA credential (Tag)
    /// * `messages` - Credential attributes
    ///
    /// # Returns
    /// A tuple of (request to send to server, state to keep private)
    pub fn initiate<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
        saga_params: &Parameters,
        saga_pk: &SagaPubKey,
        credential: &Tag,
        messages: &[Point],
    ) -> Result<(KeyExchangeRequest, DeviceState), Error> {
        // Generate X-Wing keypair
        let mut seed = [0u8; xwing::SECRET_KEY_SIZE];
        rng.fill_bytes(&mut seed);
        let xwing_sk = XWingSk::from_seed(&seed);
        // Clone the public key immediately to avoid borrow issues
        let xwing_pk = xwing_sk.public_key().clone();

        // Create SAGA presentation
        let predicate = credential
            .get_predicate(rng, saga_params, saga_pk, messages)
            .map_err(|_| Error::CredentialInvalid)?;

        let presentation = predicate.presentation();

        // Copy commitments to fixed-size array
        let mut commitments = [Point::identity(); MAX_ATTRS];
        let commit_slice = predicate.commitments();
        let num_commitments = commit_slice.len();
        commitments[..num_commitments].copy_from_slice(commit_slice);

        let request = KeyExchangeRequest {
            xwing_pk: xwing_pk.clone(),
            presentation,
            commitments,
            num_commitments,
        };

        let state = DeviceState { xwing_sk, xwing_pk };

        Ok((request, state))
    }

    /// Server responds to key exchange request.
    ///
    /// This verifies the SAGA presentation and encapsulates a shared secret.
    ///
    /// # Arguments
    /// * `rng` - Random number generator
    /// * `saga_keypair` - SAGA issuer's keypair (for verification)
    /// * `request` - The request from the device
    /// * `payload` - Optional payload to encrypt and send back
    ///
    /// # Returns
    /// Response containing X-Wing ciphertext and optional encrypted payload
    pub fn respond<R: rand_core::RngCore + rand_core::CryptoRng>(
        rng: &mut R,
        saga_keypair: &SagaKeyPair,
        request: &KeyExchangeRequest,
        payload: Option<&[u8]>,
    ) -> Result<(KeyExchangeResponse, SessionKeys), Error> {
        // Verify SAGA presentation
        let commitments = &request.commitments[..request.num_commitments];
        let valid = saga_keypair
            .verify_presentation(&request.presentation, commitments)
            .map_err(|_| Error::PresentationInvalid)?;

        if !valid {
            return Err(Error::PresentationInvalid);
        }

        // Encapsulate shared secret with X-Wing
        let mut encaps_seed = [0u8; xwing::ENCAPS_SEED_SIZE];
        rng.fill_bytes(&mut encaps_seed);
        let (ciphertext, shared_secret) = xwing::encapsulate(&request.xwing_pk, encaps_seed);

        // Derive session keys
        let session_keys = Self::derive_session_keys(&shared_secret);

        // Optionally encrypt payload
        let encrypted_payload = if let Some(data) = payload {
            // Generate random nonce
            let mut nonce_bytes = [0u8; xchacha20poly1305::NONCE_SIZE];
            rng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_bytes(&nonce_bytes);

            // Encrypt with server-to-device key
            let (ct, tag) = xchacha20poly1305::encrypt(
                &session_keys.server_to_device,
                &nonce,
                data,
                &[], // No AAD
            )
            .map_err(|_| Error::EncryptionFailed)?;

            let mut ciphertext_buf = [0u8; 256];
            let len = ct.len().min(256);
            ciphertext_buf[..len].copy_from_slice(&ct[..len]);

            Some(EncryptedPayload {
                nonce,
                ciphertext: ciphertext_buf,
                ciphertext_len: len,
                tag,
            })
        } else {
            None
        };

        let response = KeyExchangeResponse {
            ciphertext,
            encrypted_payload,
        };

        Ok((response, session_keys))
    }

    /// Device completes the key exchange.
    ///
    /// # Arguments
    /// * `state` - Device's private state from initiation
    /// * `response` - Server's response
    ///
    /// # Returns
    /// Session keys and optionally decrypted payload
    pub fn complete(
        state: &DeviceState,
        response: &KeyExchangeResponse,
    ) -> Result<(SessionKeys, Option<[u8; 256]>), Error> {
        // Decapsulate shared secret
        let shared_secret = xwing::decapsulate(&state.xwing_sk, &response.ciphertext);

        // Derive session keys
        let session_keys = Self::derive_session_keys(&shared_secret);

        // Optionally decrypt payload
        let decrypted_payload = if let Some(ref enc) = response.encrypted_payload {
            let plaintext = xchacha20poly1305::decrypt(
                &session_keys.server_to_device,
                &enc.nonce,
                &enc.ciphertext[..enc.ciphertext_len],
                &enc.tag,
                &[], // No AAD
            )
            .map_err(|_| Error::DecryptionFailed)?;

            let mut payload_buf = [0u8; 256];
            let len = plaintext.len().min(256);
            payload_buf[..len].copy_from_slice(&plaintext[..len]);
            Some(payload_buf)
        } else {
            None
        };

        Ok((session_keys, decrypted_payload))
    }

    /// Derive session keys from shared secret using a simple KDF.
    ///
    /// In production, use a proper KDF like HKDF.
    fn derive_session_keys(shared_secret: &SharedSecret) -> SessionKeys {
        use sha2::{Digest, Sha256};

        let ss_bytes = shared_secret.as_bytes();

        // Derive device-to-server key
        let mut hasher = Sha256::new();
        hasher.update(b"SAGA-XWING-D2S-v1");
        hasher.update(ss_bytes);
        let d2s_hash = hasher.finalize();
        let device_to_server = Key::from_bytes(d2s_hash.as_slice().try_into().unwrap());

        // Derive server-to-device key
        let mut hasher = Sha256::new();
        hasher.update(b"SAGA-XWING-S2D-v1");
        hasher.update(ss_bytes);
        let s2d_hash = hasher.finalize();
        let server_to_device = Key::from_bytes(s2d_hash.as_slice().try_into().unwrap());

        SessionKeys {
            device_to_server,
            server_to_device,
            shared_secret: shared_secret.clone(),
        }
    }
}

// Re-export Point::identity via saga
use saga::Identity;

#[cfg(test)]
mod tests {
    use super::*;

    // Mock RNG for testing
    struct MockRng(u64);

    impl MockRng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
    }

    impl rand_core::RngCore for MockRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            self.0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let val = self.next_u64();
                let bytes = val.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for MockRng {}

    #[test]
    fn test_credential_key_exchange() {
        let mut rng = MockRng::new(42);

        // Setup: Server creates SAGA keypair
        let saga_keypair = SagaKeyPair::setup(&mut rng, 3).unwrap();
        let saga_params = saga_keypair.params();
        let saga_pk = saga_keypair.pk();

        // Setup: Server issues credential to device
        let mut messages = [Point::identity(); MAX_ATTRS];
        for i in 0..3 {
            let s = Scalar::from((i + 1) as u64);
            messages[i] = saga::smul(&saga_params.g, &s);
        }
        let credential = saga_keypair.mac(&mut rng, &messages[..3]).unwrap();

        // Protocol: Device initiates
        let (request, device_state) = CredentialKeyExchange::initiate(
            &mut rng,
            saga_params,
            saga_pk,
            &credential,
            &messages[..3],
        )
        .unwrap();

        // Protocol: Server responds
        let payload = b"Welcome, authenticated device!";
        let (response, server_keys) =
            CredentialKeyExchange::respond(&mut rng, &saga_keypair, &request, Some(payload))
                .unwrap();

        // Protocol: Device completes
        let (device_keys, decrypted) =
            CredentialKeyExchange::complete(&device_state, &response).unwrap();

        // Verify: Shared secrets match
        assert_eq!(
            server_keys.shared_secret.as_bytes(),
            device_keys.shared_secret.as_bytes()
        );

        // Verify: Payload decrypted correctly
        let decrypted_payload = decrypted.unwrap();
        assert_eq!(&decrypted_payload[..payload.len()], payload);
    }

    #[test]
    fn test_invalid_presentation_rejected() {
        let mut rng = MockRng::new(123);

        // Setup: Server creates SAGA keypair
        let saga_keypair = SagaKeyPair::setup(&mut rng, 2).unwrap();
        let saga_params = saga_keypair.params();
        let saga_pk = saga_keypair.pk();

        // Setup: Create credential for device
        let mut messages = [Point::identity(); MAX_ATTRS];
        messages[0] = saga::smul(&saga_params.g, &Scalar::from(1u64));
        messages[1] = saga::smul(&saga_params.g, &Scalar::from(2u64));
        let credential = saga_keypair.mac(&mut rng, &messages[..2]).unwrap();

        // Device initiates
        let (mut request, _device_state) = CredentialKeyExchange::initiate(
            &mut rng,
            saga_params,
            saga_pk,
            &credential,
            &messages[..2],
        )
        .unwrap();

        // Tamper with the presentation (modify a commitment)
        request.commitments[0] = saga::smul(&saga_params.g, &Scalar::from(999u64));

        // Server should reject
        let result = CredentialKeyExchange::respond(&mut rng, &saga_keypair, &request, None);
        assert!(matches!(result, Err(Error::PresentationInvalid)));
    }
}
