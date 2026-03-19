// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Ratchet Session Management for Secure Relayer
//!
//! This module manages the PQ-Ratchet session lifecycle:
//! - X-Wing keypair generation
//! - Handshake initiation and completion
//! - Message encryption with ratchet
//! - Chunking of encrypted messages
//!
//! # Architecture
//!
//! The Secure-Relayer acts as the **Initiator** in the X-Wing handshake:
//! 1. Relayer generates X-Wing keypair and sends public key to MCU
//! 2. MCU encapsulates to our public key and responds with ciphertext + its PK
//! 3. Relayer decapsulates to get shared secret, establishes ratchet
//!
//! After handshake, the relayer encrypts messages using the ratchet and chunks
//! them for transmission to the MCU via the MPU proxy.

use dragonwing_crypto::experimental::pq_ratchet::{
    chunking::{Chunker, MAX_CHUNK_SIZE},
    encrypt::encrypt_message,
    kdf::KEY_SIZE,
    state::{Established, PqRatchet, XWING_SEED_SIZE},
    xwing_ratchet::{ResponseMessage, XWingRatchet, XWingRatchetAwaiting},
    XWING_CIPHERTEXT_SIZE, XWING_PUBLIC_KEY_SIZE,
};

use crate::error::{RelayerError, Result};
use crate::protocol::HandshakeResponse;

// ============================================================================
// Session States
// ============================================================================

/// Ratchet session state machine
enum SessionState {
    /// No session - initial state
    Uninitialized,
    /// Awaiting handshake response from MCU
    AwaitingResponse { awaiting: XWingRatchetAwaiting },
    /// Session established, ready for encryption
    Established {
        ratchet: PqRatchet<Established>,
        /// MCU's public key (for future KEM ratchets)
        mcu_public_key: [u8; XWING_PUBLIC_KEY_SIZE],
    },
}

// ============================================================================
// Ratchet Session
// ============================================================================

/// PQ-Ratchet session for secure communication with MCU
///
/// Manages X-Wing keypair, handshake, and message encryption.
pub struct RatchetSession {
    state: SessionState,
    chunker: Chunker,
    /// Our seed for X-Wing (kept for potential re-keying)
    our_seed: [u8; XWING_SEED_SIZE],
    /// Current epoch (increments on KEM ratchet)
    epoch: u64,
}

impl RatchetSession {
    /// Create a new ratchet session
    ///
    /// Generates a random X-Wing seed for the session.
    pub fn new() -> Result<Self> {
        // Generate random seed for X-Wing keypair
        let our_seed: [u8; XWING_SEED_SIZE] = rand::random();

        Ok(Self {
            state: SessionState::Uninitialized,
            chunker: Chunker::new(),
            our_seed,
            epoch: 0,
        })
    }

    /// Create a session with a specific seed (for testing/deterministic behavior)
    pub fn with_seed(seed: [u8; XWING_SEED_SIZE]) -> Self {
        Self {
            state: SessionState::Uninitialized,
            chunker: Chunker::new(),
            our_seed: seed,
            epoch: 0,
        }
    }

    /// Build the handshake init payload
    ///
    /// Returns the X-Wing public key to send to the MCU.
    pub fn build_handshake_init(&mut self) -> Result<Vec<u8>> {
        // Generate X-Wing keypair and get init message
        let (awaiting, init_msg) = XWingRatchet::initiate(self.our_seed)
            .map_err(|e| RelayerError::XWing(format!("{:?}", e)))?;

        // Transition to awaiting response state
        self.state = SessionState::AwaitingResponse { awaiting };

        log::debug!(
            "Generated X-Wing public key ({} bytes)",
            XWING_PUBLIC_KEY_SIZE
        );

        Ok(init_msg.to_bytes().to_vec())
    }

    /// Process the handshake response from MCU
    ///
    /// Extracts the ciphertext and MCU's public key, decapsulates to get
    /// shared secret, and establishes the ratchet.
    pub fn process_handshake_response(&mut self, response_payload: &[u8]) -> Result<()> {
        // Take the awaiting state
        let awaiting = match std::mem::replace(&mut self.state, SessionState::Uninitialized) {
            SessionState::AwaitingResponse { awaiting } => awaiting,
            _ => return Err(RelayerError::Handshake("not awaiting response".to_string())),
        };

        // Parse response payload
        let handshake_response = HandshakeResponse::from_payload(response_payload)
            .map_err(|e| RelayerError::Handshake(format!("invalid response: {:?}", e)))?;

        log::debug!(
            "Received MCU ciphertext ({} bytes) and public key ({} bytes)",
            XWING_CIPHERTEXT_SIZE,
            XWING_PUBLIC_KEY_SIZE
        );

        // Build ResponseMessage for X-Wing completion
        // Note: MCU response format is [ciphertext | public_key]
        // but ResponseMessage expects [public_key | ciphertext]
        let response_msg = ResponseMessage::new(
            handshake_response.mcu_public_key,
            handshake_response.ciphertext,
        );

        // For now, use zero auth root (can be enhanced with SAGA later)
        // In production, this should be derived from a pre-shared key or
        // authenticated key exchange
        let auth_root = [0u8; KEY_SIZE];

        // Complete the handshake
        let ratchet = awaiting
            .complete(response_msg, auth_root)
            .map_err(|e| RelayerError::Handshake(format!("completion failed: {:?}", e)))?;

        log::info!("X-Wing decapsulation successful");

        // Store the established ratchet
        self.state = SessionState::Established {
            ratchet,
            mcu_public_key: handshake_response.mcu_public_key,
        };
        self.epoch = 1;

        Ok(())
    }

    /// Encrypt data using the ratchet
    ///
    /// Returns the encrypted RatchetMessage bytes.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ratchet = match &mut self.state {
            SessionState::Established { ratchet, .. } => ratchet,
            _ => return Err(RelayerError::NoSession),
        };

        // Encrypt the message using the ratchet state
        // This advances the send chain internally
        let state = ratchet.state_mut();
        let epoch = state.epoch();

        // encrypt_message takes the state and handles key derivation internally
        // No new public key for now (symmetric ratchet only)
        let message = encrypt_message(state, plaintext, None)
            .map_err(|e| RelayerError::Encryption(format!("{:?}", e)))?;

        // Encode to bytes for transmission
        let encrypted = message.encode_to_vec();

        log::debug!(
            "Encrypted {} bytes -> {} bytes (epoch={})",
            plaintext.len(),
            encrypted.len(),
            epoch
        );

        Ok(encrypted)
    }

    /// Chunk encrypted data for transmission
    ///
    /// Returns a vector of encoded chunks ready to send.
    pub fn chunk(&mut self, encrypted_data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let chunks = self
            .chunker
            .chunk(encrypted_data)
            .map_err(|e| RelayerError::Chunking(format!("{:?}", e)))?;

        log::debug!(
            "Chunked {} bytes into {} chunks",
            encrypted_data.len(),
            chunks.len()
        );

        // Encode each chunk into a Vec<u8>
        let encoded: Vec<Vec<u8>> = chunks
            .iter()
            .map(|c| {
                let mut buf = vec![0u8; MAX_CHUNK_SIZE];
                let len = c.encode(&mut buf).expect("buffer is large enough");
                buf.truncate(len);
                buf
            })
            .collect();

        Ok(encoded)
    }

    /// Encrypt and chunk data in one operation
    pub fn encrypt_and_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<Vec<u8>>> {
        let encrypted = self.encrypt(plaintext)?;
        self.chunk(&encrypted)
    }

    /// Get current ratchet epoch
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Check if session is established
    pub fn is_established(&self) -> bool {
        matches!(self.state, SessionState::Established { .. })
    }

    /// Get the MCU's public key (if session is established)
    pub fn mcu_public_key(&self) -> Option<&[u8; XWING_PUBLIC_KEY_SIZE]> {
        match &self.state {
            SessionState::Established { mcu_public_key, .. } => Some(mcu_public_key),
            _ => None,
        }
    }
}

impl Default for RatchetSession {
    fn default() -> Self {
        Self::new().expect("Failed to create RatchetSession")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = RatchetSession::new().unwrap();
        assert!(!session.is_established());
        assert_eq!(session.epoch(), 0);
    }

    #[test]
    fn test_deterministic_seed() {
        let seed = [0x42u8; 32];
        let session = RatchetSession::with_seed(seed);
        assert_eq!(session.our_seed, seed);
    }

    #[test]
    fn test_build_handshake_init() {
        let mut session = RatchetSession::new().unwrap();
        let init_payload = session.build_handshake_init().unwrap();

        // Should be X-Wing public key size
        assert_eq!(init_payload.len(), XWING_PUBLIC_KEY_SIZE);

        // Session should now be awaiting response
        assert!(matches!(
            session.state,
            SessionState::AwaitingResponse { .. }
        ));
    }

    #[test]
    fn test_encrypt_requires_session() {
        let mut session = RatchetSession::new().unwrap();
        let result = session.encrypt(b"test data");
        assert!(result.is_err());
    }
}
