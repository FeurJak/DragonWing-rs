// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! PQ-Ratchet Handler for MCU Secure World
//!
//! This module manages:
//! - PQ-Ratchet state with TrustZone ITS persistence
//! - Chunk reassembly for large encrypted messages
//! - Session handshake and key exchange
//! - Message decryption using the ratchet protocol

use log::warn;

use dragonwing_crypto::post_quantum::xwing;
use dragonwing_crypto::rng::HwRng;

// PQ-Ratchet imports
use dragonwing_crypto::experimental::pq_ratchet::{
    chunking::{Chunk, Reassembler, ReassemblyStatus, MAX_CHUNK_PAYLOAD},
    kdf::KEY_SIZE,
    state::{Direction, RatchetState},
};

use crate::protocol::{
    ChunkStatus, ProtocolError, HANDSHAKE_INIT_MIN_SIZE, HANDSHAKE_RESPONSE_SIZE,
};

// ============================================================================
// Constants
// ============================================================================

/// Maximum chunks for reassembly (64 * 2000 = 128KB max message)
const MAX_REASSEMBLY_CHUNKS: usize = 64;

/// Plaintext buffer size (matches max reassembled message size)
const PLAINTEXT_BUFFER_SIZE: usize = MAX_REASSEMBLY_CHUNKS * MAX_CHUNK_PAYLOAD;

/// PSA ITS UIDs for ratchet state
const UID_RATCHET_STATE: u64 = 0x3000;
const UID_XWING_SEED: u64 = 0x3001;

// ============================================================================
// Ratchet Handler
// ============================================================================

/// Handler for PQ-Ratchet protocol operations
pub struct RatchetHandler {
    /// Current ratchet state (None if no session)
    state: Option<RatchetState>,
    /// Our X-Wing secret key
    xwing_sk: Option<xwing::SecretKey>,
    /// Our X-Wing public key (cached for responses)
    xwing_pk: Option<xwing::PublicKey>,
    /// Chunk reassembler
    reassembler: Reassembler<MAX_REASSEMBLY_CHUNKS>,
    /// Buffer for decrypted plaintext
    plaintext_buffer: [u8; PLAINTEXT_BUFFER_SIZE],
    /// Length of current plaintext
    plaintext_len: usize,
    /// Session established flag
    session_active: bool,
}

impl RatchetHandler {
    /// Create a new ratchet handler
    pub fn new() -> Self {
        Self {
            state: None,
            xwing_sk: None,
            xwing_pk: None,
            reassembler: Reassembler::new(),
            plaintext_buffer: [0u8; PLAINTEXT_BUFFER_SIZE],
            plaintext_len: 0,
            session_active: false,
        }
    }

    /// Initialize the handler (generate or load X-Wing keypair)
    pub fn init(&mut self, rng: &mut HwRng) -> bool {
        // Generate X-Wing keypair
        let seed: [u8; 32] = rng.random_array();
        let sk = xwing::SecretKey::from_seed(&seed);
        // Get public key bytes before moving sk (public_key returns a reference)
        let pk_bytes = sk.public_key().to_bytes();
        let pk = xwing::PublicKey::from_bytes(&pk_bytes);

        warn!("X-Wing keypair generated");
        warn!("  Public key size: {} bytes", xwing::PUBLIC_KEY_SIZE);
        warn!("  Ciphertext size: {} bytes", xwing::CIPHERTEXT_SIZE);

        self.xwing_sk = Some(sk);
        self.xwing_pk = Some(pk);

        // TODO: Try to load existing ratchet state from ITS
        // For now, start fresh each boot

        true
    }

    /// Handle handshake init from relayer
    ///
    /// Payload format:
    /// - [0..1216] X-Wing public key from relayer
    /// - [1216..] Optional SAGA presentation
    ///
    /// Returns response payload:
    /// - [0..1120] X-Wing ciphertext
    /// - [1120..2336] Our X-Wing public key (for future ratchet steps)
    pub fn handle_handshake_init(
        &mut self,
        rng: &mut HwRng,
        payload: &[u8],
    ) -> Result<[u8; HANDSHAKE_RESPONSE_SIZE], ProtocolError> {
        if payload.len() < HANDSHAKE_INIT_MIN_SIZE {
            warn!(
                "Handshake payload too short: {} < {}",
                payload.len(),
                HANDSHAKE_INIT_MIN_SIZE
            );
            return Err(ProtocolError::InvalidHandshake);
        }

        // Extract relayer's X-Wing public key
        let relayer_pk_bytes: &[u8; xwing::PUBLIC_KEY_SIZE] = payload[..xwing::PUBLIC_KEY_SIZE]
            .try_into()
            .map_err(|_| ProtocolError::InvalidHandshake)?;
        let relayer_pk = xwing::PublicKey::from_bytes(relayer_pk_bytes);

        warn!("Received relayer X-Wing public key");

        // TODO: If SAGA presentation is included, verify it
        // let saga_payload = &payload[xwing::PUBLIC_KEY_SIZE..];
        // if !saga_payload.is_empty() {
        //     self.verify_saga_presentation(saga_payload)?;
        // }

        // Perform X-Wing encapsulation to relayer's public key
        let encaps_seed: [u8; xwing::ENCAPS_SEED_SIZE] = rng.random_array();
        let (ciphertext, shared_secret) = xwing::encapsulate(&relayer_pk, encaps_seed);

        warn!("X-Wing encapsulation complete");
        warn!(
            "  Shared secret: {:02X}{:02X}{:02X}{:02X}...",
            shared_secret.as_bytes()[0],
            shared_secret.as_bytes()[1],
            shared_secret.as_bytes()[2],
            shared_secret.as_bytes()[3]
        );

        // Initialize ratchet state as responder
        // The relayer is the initiator, we are the responder
        let mut root_key = [0u8; KEY_SIZE];
        root_key.copy_from_slice(shared_secret.as_bytes());

        // Get our public key for the response
        let our_pk = self.xwing_pk.as_ref().ok_or(ProtocolError::XWingError)?;

        // Create initial ratchet state
        // Direction::Responder because we're responding (receiving from relayer)
        let auth_root: [u8; KEY_SIZE] = rng.random_array();
        let state = RatchetState::new(
            Direction::Responder,
            root_key,
            *relayer_pk_bytes,  // Peer's public key
            rng.random_array(), // Random seed for our X-Wing key
            auth_root,          // Authenticator root key
        );

        self.state = Some(state);
        self.session_active = true;
        self.reassembler.reset();

        warn!("PQ-Ratchet session initialized (responder mode)");

        // Build response: ciphertext + our public key
        let mut response = [0u8; HANDSHAKE_RESPONSE_SIZE];
        let ct_bytes = ciphertext.to_bytes();
        response[..xwing::CIPHERTEXT_SIZE].copy_from_slice(&ct_bytes);
        response[xwing::CIPHERTEXT_SIZE..].copy_from_slice(&our_pk.to_bytes());

        Ok(response)
    }

    /// Handle incoming chunk
    pub fn handle_chunk(&mut self, chunk_data: &[u8]) -> Result<ChunkStatus, ProtocolError> {
        if !self.session_active {
            return Err(ProtocolError::NoSession);
        }

        // Decode chunk
        let chunk = Chunk::decode(chunk_data).map_err(|_| ProtocolError::ChunkError)?;
        let chunk_index = chunk.header.chunk_index;

        // Add to reassembler
        match self.reassembler.add_chunk(&chunk) {
            ReassemblyStatus::NeedMore => Ok(ChunkStatus::NeedMore { chunk_index }),

            ReassemblyStatus::Complete => {
                // All chunks received, decrypt the message
                let plaintext_len = self.decrypt_reassembled_message()?;
                Ok(ChunkStatus::Complete { plaintext_len })
            }

            ReassemblyStatus::Error(e) => {
                warn!("Reassembly error: {:?}", e);
                // Check if it's a duplicate
                if matches!(
                    e,
                    dragonwing_crypto::experimental::pq_ratchet::chunking::ChunkError::DuplicateChunk
                ) {
                    Ok(ChunkStatus::Duplicate { chunk_index })
                } else {
                    Err(ProtocolError::ChunkError)
                }
            }
        }
    }

    /// Decrypt the reassembled message using ratchet state
    fn decrypt_reassembled_message(&mut self) -> Result<usize, ProtocolError> {
        let state = self.state.as_mut().ok_or(ProtocolError::NoSession)?;

        // Get the reassembled ciphertext
        let ciphertext_len = self.reassembler.data_length();
        if ciphertext_len == 0 {
            return Err(ProtocolError::RatchetError);
        }

        // Copy reassembled data to a temporary buffer
        // (We reuse plaintext_buffer temporarily for the ciphertext)
        let mut ciphertext = [0u8; PLAINTEXT_BUFFER_SIZE];
        self.reassembler
            .copy_to(&mut ciphertext)
            .map_err(|_| ProtocolError::ChunkError)?;

        // Reset reassembler for next message
        self.reassembler.reset();

        // Parse the ratchet message from ciphertext
        // The reassembled data is a complete RatchetMessage
        let message = dragonwing_crypto::experimental::pq_ratchet::message::RatchetMessage::decode(
            &ciphertext[..ciphertext_len],
        )
        .map_err(|_| ProtocolError::RatchetError)?;

        // Decrypt using ratchet state
        // For now, use simplified decryption (symmetric ratchet only)
        // Full KEM ratchet would require handling new public keys in the message

        // Get the message key for this message using ratchet state
        // This handles the expected case as well as out-of-order messages
        let (message_key, nonce) = state
            .get_recv_key(message.header.epoch, message.header.message_num)
            .map_err(|_| ProtocolError::RatchetError)?;

        // Decrypt the payload using the derived key and nonce
        let header_bytes = message.header_bytes();
        let decrypted = dragonwing_crypto::experimental::pq_ratchet::encrypt::aead_decrypt(
            &message_key,
            &nonce,
            &message.ciphertext,
            &header_bytes, // Use header as AAD
        )
        .map_err(|_| ProtocolError::RatchetError)?;

        // Copy to plaintext buffer
        let plaintext_len = decrypted.len().min(PLAINTEXT_BUFFER_SIZE);
        self.plaintext_buffer[..plaintext_len].copy_from_slice(&decrypted[..plaintext_len]);
        self.plaintext_len = plaintext_len;

        // TODO: Persist updated ratchet state to ITS
        // self.persist_state()?;

        Ok(plaintext_len)
    }

    /// Get reference to decrypted plaintext
    pub fn get_plaintext(&self, len: usize) -> &[u8] {
        let actual_len = len.min(self.plaintext_len);
        &self.plaintext_buffer[..actual_len]
    }

    /// Check if session is active
    pub fn is_session_active(&self) -> bool {
        self.session_active
    }

    /// Get current ratchet epoch
    pub fn current_epoch(&self) -> u64 {
        self.state.as_ref().map(|s| s.epoch()).unwrap_or(0)
    }
}

impl Default for RatchetHandler {
    fn default() -> Self {
        Self::new()
    }
}
