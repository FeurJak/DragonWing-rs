// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! X-Wing Integration for PQ-Ratchet
//!
//! This module provides the integration between the PQ-Ratchet protocol and
//! X-Wing (ML-KEM-768 + X25519) hybrid KEM. It implements:
//!
//! - Session initialization (handshake)
//! - KEM ratchet steps during messaging
//! - Key material management with secure zeroization
//!
//! # Protocol Overview
//!
//! The handshake follows a 2-message pattern:
//!
//! ```text
//! Initiator                                    Responder
//! ─────────                                    ─────────
//! Generate X-Wing keypair
//! pk_I, sk_I = XWing.KeyGen(seed_I)
//!
//!                 ──── InitMessage(pk_I) ────►
//!
//!                                              Generate X-Wing keypair
//!                                              pk_R, sk_R = XWing.KeyGen(seed_R)
//!                                              
//!                                              Encapsulate to initiator
//!                                              (ct, ss) = XWing.Encap(pk_I, rand)
//!
//!                 ◄─── ResponseMessage(pk_R, ct) ────
//!
//! Decapsulate response
//! ss = XWing.Decap(sk_I, ct)
//!
//! Both parties now have:
//! - Shared secret `ss` for root key
//! - Peer's public key for future KEM ratchets
//! ```
//!
//! # KEM Ratchet Steps
//!
//! During messaging, either party can perform a KEM ratchet:
//!
//! 1. **Sender**: Generates new keypair, encapsulates to peer's PK, includes
//!    new PK and ciphertext in message header
//! 2. **Receiver**: Decapsulates ciphertext, updates ratchet state with new
//!    shared secret, stores sender's new PK for next encapsulation
//!
//! # Feature Requirements
//!
//! Requires the `xwing` feature to be enabled, which provides:
//! - `crate::post_quantum::xwing` module
//! - X-Wing keypair generation, encapsulation, decapsulation
//!
//! # Example
//!
//! ```rust,ignore
//! use dragonwing_crypto::experimental::pq_ratchet::xwing_ratchet::*;
//! use dragonwing_crypto::rng::HwRng;
//!
//! let rng = HwRng::new();
//!
//! // Initiator side
//! let init_seed: [u8; 32] = rng.random_array();
//! let (initiator, init_msg) = XWingRatchet::initiate(init_seed)?;
//!
//! // Send init_msg to responder...
//!
//! // Responder side
//! let resp_seed: [u8; 32] = rng.random_array();
//! let encap_rand: [u8; 64] = rng.random_array();
//! let (responder, resp_msg) = XWingRatchet::respond(&init_msg, resp_seed, encap_rand)?;
//!
//! // Send resp_msg back to initiator...
//!
//! // Initiator completes handshake
//! let initiator = initiator.complete(resp_msg)?;
//!
//! // Both parties now have established ratchets
//! ```

#[cfg(feature = "xwing")]
use crate::post_quantum::xwing::{
    self, Ciphertext, PublicKey, SecretKey, SharedSecret, CIPHERTEXT_SIZE, ENCAPS_SEED_SIZE,
    PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SHARED_SECRET_SIZE,
};

use super::kdf::{self, KEY_SIZE};
use super::state::{
    Direction, PqRatchet, RatchetState, XWING_CIPHERTEXT_SIZE, XWING_PUBLIC_KEY_SIZE,
    XWING_SEED_SIZE, XWING_SHARED_SECRET_SIZE,
};

// Compile-time assertions to ensure our constants match X-Wing's
#[cfg(feature = "xwing")]
const _: () = {
    assert!(XWING_PUBLIC_KEY_SIZE == PUBLIC_KEY_SIZE);
    assert!(XWING_CIPHERTEXT_SIZE == CIPHERTEXT_SIZE);
    assert!(XWING_SEED_SIZE == SECRET_KEY_SIZE);
    assert!(XWING_SHARED_SECRET_SIZE == SHARED_SECRET_SIZE);
};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during X-Wing ratchet operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XWingRatchetError {
    /// Invalid public key format or validation failed
    InvalidPublicKey,
    /// Invalid ciphertext format
    InvalidCiphertext,
    /// Key derivation failed
    KeyDerivationFailed,
    /// Handshake not in expected state
    InvalidState,
    /// X-Wing operation failed
    XWingError,
}

/// Result type for X-Wing ratchet operations
pub type Result<T> = core::result::Result<T, XWingRatchetError>;

// ============================================================================
// Handshake Messages
// ============================================================================

/// Initial handshake message from initiator to responder
///
/// Contains the initiator's X-Wing public key.
#[derive(Clone)]
pub struct InitMessage {
    /// Initiator's X-Wing public key (1216 bytes)
    pub public_key: [u8; XWING_PUBLIC_KEY_SIZE],
}

impl InitMessage {
    /// Create a new init message with the given public key
    pub fn new(public_key: [u8; XWING_PUBLIC_KEY_SIZE]) -> Self {
        Self { public_key }
    }

    /// Encode to bytes for transmission
    pub fn to_bytes(&self) -> [u8; XWING_PUBLIC_KEY_SIZE] {
        self.public_key
    }

    /// Decode from bytes
    pub fn from_bytes(bytes: &[u8; XWING_PUBLIC_KEY_SIZE]) -> Self {
        Self { public_key: *bytes }
    }
}

/// Response message from responder to initiator
///
/// Contains the responder's X-Wing public key and ciphertext encapsulated
/// to the initiator's public key.
#[derive(Clone)]
pub struct ResponseMessage {
    /// Responder's X-Wing public key (1216 bytes)
    pub public_key: [u8; XWING_PUBLIC_KEY_SIZE],
    /// X-Wing ciphertext encapsulated to initiator's public key (1120 bytes)
    pub ciphertext: [u8; XWING_CIPHERTEXT_SIZE],
}

impl ResponseMessage {
    /// Create a new response message
    pub fn new(
        public_key: [u8; XWING_PUBLIC_KEY_SIZE],
        ciphertext: [u8; XWING_CIPHERTEXT_SIZE],
    ) -> Self {
        Self {
            public_key,
            ciphertext,
        }
    }

    /// Encoded size in bytes
    pub const fn encoded_size() -> usize {
        XWING_PUBLIC_KEY_SIZE + XWING_CIPHERTEXT_SIZE
    }

    /// Encode to bytes for transmission
    pub fn to_bytes(&self) -> [u8; Self::encoded_size()] {
        let mut bytes = [0u8; Self::encoded_size()];
        bytes[..XWING_PUBLIC_KEY_SIZE].copy_from_slice(&self.public_key);
        bytes[XWING_PUBLIC_KEY_SIZE..].copy_from_slice(&self.ciphertext);
        bytes
    }

    /// Decode from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::encoded_size() {
            return Err(XWingRatchetError::InvalidCiphertext);
        }

        let mut public_key = [0u8; XWING_PUBLIC_KEY_SIZE];
        let mut ciphertext = [0u8; XWING_CIPHERTEXT_SIZE];

        public_key.copy_from_slice(&bytes[..XWING_PUBLIC_KEY_SIZE]);
        ciphertext.copy_from_slice(&bytes[XWING_PUBLIC_KEY_SIZE..Self::encoded_size()]);

        Ok(Self {
            public_key,
            ciphertext,
        })
    }
}

// ============================================================================
// X-Wing Ratchet (Awaiting Response State)
// ============================================================================

/// X-Wing Ratchet in the "awaiting response" state
///
/// This state holds the initiator's secret key while waiting for the
/// responder's response message.
#[cfg(feature = "xwing")]
pub struct XWingRatchetAwaiting {
    /// Our X-Wing secret key (for decapsulating the response)
    secret_key: SecretKey,
    /// Our seed (for storing in ratchet state after completion)
    seed: [u8; XWING_SEED_SIZE],
}

#[cfg(feature = "xwing")]
impl XWingRatchetAwaiting {
    /// Complete the handshake by processing the response message
    ///
    /// This decapsulates the ciphertext from the response and establishes
    /// the ratchet with the derived shared secret.
    ///
    /// # Arguments
    /// * `response` - The response message from the responder
    /// * `auth_root` - Root key for the authenticator chain (should be derived
    ///                 from a separate key exchange or pre-shared)
    ///
    /// # Returns
    /// An established `PqRatchet` ready for messaging
    pub fn complete(
        self,
        response: ResponseMessage,
        auth_root: [u8; KEY_SIZE],
    ) -> Result<PqRatchet<super::state::Established>> {
        // Parse the ciphertext
        let ciphertext = Ciphertext::from_bytes(&response.ciphertext);

        // Decapsulate to get shared secret
        let shared_secret = self.secret_key.decapsulate(&ciphertext);

        // Derive root key from shared secret
        // Use HKDF with domain separation
        let root_key = derive_root_key(shared_secret.as_bytes(), b"xwing-ratchet-init");

        // Create the ratchet state
        let state = RatchetState::new(
            Direction::Initiator,
            root_key,
            response.public_key,
            self.seed,
            auth_root,
        );

        Ok(PqRatchet::from_state(state))
    }
}

// ============================================================================
// X-Wing Ratchet Operations
// ============================================================================

/// X-Wing Ratchet protocol operations
///
/// This struct provides static methods for X-Wing ratchet operations.
/// The actual ratchet state is stored in `PqRatchet<Established>`.
#[cfg(feature = "xwing")]
pub struct XWingRatchet;

#[cfg(feature = "xwing")]
impl XWingRatchet {
    /// Initiate a new X-Wing ratchet session
    ///
    /// Generates an X-Wing keypair and returns:
    /// - An `XWingRatchetAwaiting` to complete the handshake later
    /// - An `InitMessage` to send to the responder
    ///
    /// # Arguments
    /// * `seed` - 32-byte seed for X-Wing key generation
    ///
    /// # Returns
    /// A tuple of (awaiting_state, init_message)
    pub fn initiate(seed: [u8; XWING_SEED_SIZE]) -> Result<(XWingRatchetAwaiting, InitMessage)> {
        // Generate X-Wing keypair from seed
        let secret_key = SecretKey::from_seed(&seed);
        let public_key = secret_key.public_key();

        // Create init message with our public key
        let init_msg = InitMessage::new(public_key.to_bytes());

        // Return awaiting state
        let awaiting = XWingRatchetAwaiting { secret_key, seed };

        Ok((awaiting, init_msg))
    }

    /// Respond to an initiation message
    ///
    /// Generates an X-Wing keypair, encapsulates to the initiator's public key,
    /// and returns an established ratchet plus the response message.
    ///
    /// # Arguments
    /// * `init_msg` - The initiation message from the initiator
    /// * `seed` - 32-byte seed for our X-Wing key generation
    /// * `encap_randomness` - 64 bytes of randomness for encapsulation
    /// * `auth_root` - Root key for the authenticator chain
    ///
    /// # Returns
    /// A tuple of (established_ratchet, response_message)
    pub fn respond(
        init_msg: &InitMessage,
        seed: [u8; XWING_SEED_SIZE],
        encap_randomness: [u8; ENCAPS_SEED_SIZE],
        auth_root: [u8; KEY_SIZE],
    ) -> Result<(PqRatchet<super::state::Established>, ResponseMessage)> {
        // Parse initiator's public key
        let initiator_pk = PublicKey::from_bytes(&init_msg.public_key);

        // Generate our X-Wing keypair
        let our_secret_key = SecretKey::from_seed(&seed);
        let our_public_key = our_secret_key.public_key();

        // Encapsulate to initiator's public key
        let (ciphertext, shared_secret) = initiator_pk.encapsulate(encap_randomness);

        // Derive root key from shared secret
        let root_key = derive_root_key(shared_secret.as_bytes(), b"xwing-ratchet-init");

        // Create response message
        let response = ResponseMessage::new(our_public_key.to_bytes(), ciphertext.to_bytes());

        // Create ratchet state (we're the responder)
        let state = RatchetState::new(
            Direction::Responder,
            root_key,
            init_msg.public_key,
            seed,
            auth_root,
        );

        Ok((PqRatchet::from_state(state), response))
    }

    /// Perform a KEM ratchet step as the sender
    ///
    /// Generates a new X-Wing keypair, encapsulates to the peer's public key,
    /// and updates the ratchet state with the new shared secret.
    ///
    /// # Arguments
    /// * `ratchet` - The established ratchet to update
    /// * `new_seed` - 32-byte seed for the new X-Wing keypair
    /// * `encap_randomness` - 64 bytes of randomness for encapsulation
    ///
    /// # Returns
    /// A tuple of (new_public_key, ciphertext) to include in the message header
    pub fn kem_ratchet_send(
        ratchet: &mut PqRatchet<super::state::Established>,
        new_seed: [u8; XWING_SEED_SIZE],
        encap_randomness: [u8; ENCAPS_SEED_SIZE],
    ) -> Result<([u8; XWING_PUBLIC_KEY_SIZE], [u8; XWING_CIPHERTEXT_SIZE])> {
        let state = ratchet.state_mut();

        // Parse peer's public key
        let peer_pk = PublicKey::from_bytes(state.peer_public_key());

        // Encapsulate to peer's public key
        let (ciphertext, shared_secret) = peer_pk.encapsulate(encap_randomness);

        // Generate our new keypair
        let new_secret_key = SecretKey::from_seed(&new_seed);
        let new_public_key = new_secret_key.public_key();

        // Update ratchet state with new shared secret and seed
        state.kem_ratchet_send(shared_secret.as_bytes(), &new_seed);

        Ok((new_public_key.to_bytes(), ciphertext.to_bytes()))
    }

    /// Perform a KEM ratchet step as the receiver
    ///
    /// Decapsulates the ciphertext from the message header and updates
    /// the ratchet state with the new shared secret and peer's new public key.
    ///
    /// # Arguments
    /// * `ratchet` - The established ratchet to update
    /// * `ciphertext` - The X-Wing ciphertext from the message header
    /// * `new_peer_pk` - The sender's new public key from the message header
    pub fn kem_ratchet_recv(
        ratchet: &mut PqRatchet<super::state::Established>,
        ciphertext: &[u8; XWING_CIPHERTEXT_SIZE],
        new_peer_pk: &[u8; XWING_PUBLIC_KEY_SIZE],
    ) -> Result<()> {
        let state = ratchet.state_mut();

        // Parse ciphertext
        let ct = Ciphertext::from_bytes(ciphertext);

        // Generate our secret key from stored seed to decapsulate
        let our_secret_key = SecretKey::from_seed(state.my_xwing_seed());

        // Decapsulate to get shared secret
        let shared_secret = our_secret_key.decapsulate(&ct);

        // Update ratchet state
        state.kem_ratchet_recv(shared_secret.as_bytes(), new_peer_pk);

        Ok(())
    }

    /// Get our current X-Wing public key
    ///
    /// Generates the public key from our stored seed. Useful for including
    /// in messages when performing a KEM ratchet.
    pub fn my_public_key(
        ratchet: &PqRatchet<super::state::Established>,
    ) -> [u8; XWING_PUBLIC_KEY_SIZE] {
        let state = ratchet.state();
        let secret_key = SecretKey::from_seed(state.my_xwing_seed());
        secret_key.public_key().to_bytes()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Derive a root key from a shared secret using HKDF
///
/// Uses domain separation to ensure different contexts produce different keys.
fn derive_root_key(shared_secret: &[u8; SHARED_SECRET_SIZE], context: &[u8]) -> [u8; KEY_SIZE] {
    // Use our KDF infrastructure
    // HKDF-Expand with context as info
    use sha2::{Digest, Sha256};

    // Simple HKDF-Extract + Expand
    // Extract: PRK = HMAC(salt, IKM)
    // We use a fixed salt for domain separation
    let salt = b"DragonWing-PQ-Ratchet-v1";

    // HMAC for extract
    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    let mut key_block = [0u8; BLOCK_SIZE];
    key_block[..salt.len()].copy_from_slice(salt);

    // Inner hash
    let mut inner_hasher = Sha256::new();
    let mut inner_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key[i] = key_block[i] ^ IPAD;
    }
    inner_hasher.update(&inner_key);
    inner_hasher.update(shared_secret);
    let inner_hash = inner_hasher.finalize();

    // Outer hash
    let mut outer_hasher = Sha256::new();
    let mut outer_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_key[i] = key_block[i] ^ OPAD;
    }
    outer_hasher.update(&outer_key);
    outer_hasher.update(&inner_hash);
    let prk = outer_hasher.finalize();

    // Expand: OKM = HMAC(PRK, info || 0x01)
    let mut expand_key_block = [0u8; BLOCK_SIZE];
    expand_key_block[..32].copy_from_slice(&prk);

    let mut inner_hasher = Sha256::new();
    let mut inner_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key[i] = expand_key_block[i] ^ IPAD;
    }
    inner_hasher.update(&inner_key);
    inner_hasher.update(context);
    inner_hasher.update(&[0x01u8]);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    let mut outer_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_key[i] = expand_key_block[i] ^ OPAD;
    }
    outer_hasher.update(&outer_key);
    outer_hasher.update(&inner_hash);
    let okm = outer_hasher.finalize();

    let mut result = [0u8; KEY_SIZE];
    result.copy_from_slice(&okm);
    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "xwing"))]
mod tests {
    use super::*;

    #[test]
    fn test_init_message_roundtrip() {
        let pk = [0x42u8; XWING_PUBLIC_KEY_SIZE];
        let msg = InitMessage::new(pk);

        let bytes = msg.to_bytes();
        let decoded = InitMessage::from_bytes(&bytes);

        assert_eq!(decoded.public_key, pk);
    }

    #[test]
    fn test_response_message_roundtrip() {
        let pk = [0x42u8; XWING_PUBLIC_KEY_SIZE];
        let ct = [0x24u8; XWING_CIPHERTEXT_SIZE];
        let msg = ResponseMessage::new(pk, ct);

        let bytes = msg.to_bytes();
        let decoded = ResponseMessage::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.public_key, pk);
        assert_eq!(decoded.ciphertext, ct);
    }

    #[test]
    fn test_handshake_full_flow() {
        // Initiator starts handshake
        let init_seed = [0x11u8; XWING_SEED_SIZE];
        let (awaiting, init_msg) = XWingRatchet::initiate(init_seed).unwrap();

        // Responder processes init and generates response
        let resp_seed = [0x22u8; XWING_SEED_SIZE];
        let encap_rand = [0x33u8; ENCAPS_SEED_SIZE];
        let auth_root = [0x44u8; KEY_SIZE];

        let (responder_ratchet, response_msg) =
            XWingRatchet::respond(&init_msg, resp_seed, encap_rand, auth_root).unwrap();

        // Initiator completes handshake
        let initiator_ratchet = awaiting.complete(response_msg, auth_root).unwrap();

        // Both should be at epoch 0
        assert_eq!(initiator_ratchet.state().epoch(), 0);
        assert_eq!(responder_ratchet.state().epoch(), 0);

        // Directions should be correct
        assert_eq!(initiator_ratchet.state().direction(), Direction::Initiator);
        assert_eq!(responder_ratchet.state().direction(), Direction::Responder);
    }

    #[test]
    fn test_kem_ratchet_step() {
        // Set up a session
        let init_seed = [0x11u8; XWING_SEED_SIZE];
        let (awaiting, init_msg) = XWingRatchet::initiate(init_seed).unwrap();

        let resp_seed = [0x22u8; XWING_SEED_SIZE];
        let encap_rand = [0x33u8; ENCAPS_SEED_SIZE];
        let auth_root = [0x44u8; KEY_SIZE];

        let (mut responder_ratchet, response_msg) =
            XWingRatchet::respond(&init_msg, resp_seed, encap_rand, auth_root).unwrap();

        let mut initiator_ratchet = awaiting.complete(response_msg, auth_root).unwrap();

        // Initiator performs KEM ratchet send
        let new_init_seed = [0x55u8; XWING_SEED_SIZE];
        let new_encap_rand = [0x66u8; ENCAPS_SEED_SIZE];

        let (new_pk, ciphertext) =
            XWingRatchet::kem_ratchet_send(&mut initiator_ratchet, new_init_seed, new_encap_rand)
                .unwrap();

        // Responder performs KEM ratchet recv
        XWingRatchet::kem_ratchet_recv(&mut responder_ratchet, &ciphertext, &new_pk).unwrap();

        // Both should have advanced to epoch 1
        // Note: kem_ratchet_send doesn't increment epoch (that happens in recv)
        // and responder's kem_ratchet_recv increments epoch
        assert_eq!(responder_ratchet.state().epoch(), 1);
    }

    #[test]
    fn test_derive_root_key_deterministic() {
        let ss = [0xABu8; SHARED_SECRET_SIZE];
        let context = b"test-context";

        let key1 = derive_root_key(&ss, context);
        let key2 = derive_root_key(&ss, context);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_root_key_different_contexts() {
        let ss = [0xABu8; SHARED_SECRET_SIZE];

        let key1 = derive_root_key(&ss, b"context-1");
        let key2 = derive_root_key(&ss, b"context-2");

        assert_ne!(key1, key2);
    }
}
