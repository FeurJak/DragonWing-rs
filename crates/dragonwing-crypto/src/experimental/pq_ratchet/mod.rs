// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Post-Quantum Double Ratchet Protocol
//!
//! This module implements the cryptographic primitives for a Signal-style
//! double ratchet protocol using X-Wing (ML-KEM-768 + X25519) for the
//! KEM ratchet step.
//!
//! # Overview
//!
//! The PQ-Ratchet provides:
//! - **Forward secrecy**: Compromise of current keys doesn't reveal past messages
//! - **Post-compromise security**: Security is restored after key rotation
//! - **Post-quantum security**: X-Wing provides hybrid PQ/classical protection
//!
//! # Modules
//!
//! - [`kdf`] - Key derivation functions (HKDF-SHA256 with domain separation)
//! - [`state`] - Ratchet state types (chains, authenticator, skipped keys)
//!
//! # Example
//!
//! ```rust,ignore
//! use dragonwing_crypto::experimental::pq_ratchet::{kdf, state::*};
//!
//! // Create a new ratchet state after initial X-Wing key exchange
//! let state = RatchetState::new(
//!     Direction::Initiator,
//!     root_key,           // From X-Wing shared secret
//!     peer_public_key,    // Peer's X-Wing public key
//!     my_xwing_seed,      // Our X-Wing seed
//!     auth_root,          // Initial authenticator key
//! );
//!
//! // Wrap in typestate for compile-time safety
//! let mut ratchet = PqRatchet::from_state(state);
//!
//! // Get keys for sending a message
//! let (msg_key, nonce) = ratchet.state_mut().next_send_key();
//!
//! // Get keys for receiving a message
//! let (msg_key, nonce) = ratchet.state_mut().get_recv_key(epoch, msg_num)?;
//! ```

pub mod chunking;
pub mod encrypt;
pub mod kdf;
pub mod message;
pub mod psa_storage;
pub mod serialize;
pub mod state;

/// SAGA authorization layer for PQ-Ratchet sessions.
///
/// Provides anonymous credential-based authorization using SAGA (BBS-style MAC).
/// The MCU acts as both issuer and verifier of credentials.
///
/// Requires the `saga` feature to be enabled.
#[cfg(feature = "saga")]
pub mod saga_auth;

/// X-Wing integration for the PQ-Ratchet protocol.
///
/// Provides session initialization (handshake) and KEM ratchet operations
/// using X-Wing (ML-KEM-768 + X25519) hybrid KEM.
///
/// Requires the `xwing` feature to be enabled.
#[cfg(feature = "xwing")]
pub mod xwing_ratchet;

// Re-export commonly used types
pub use kdf::{
    derive_nonce, kdf_auth, kdf_chain, kdf_root, KEY_SIZE, LABEL_AUTH, LABEL_CHAIN, LABEL_MESSAGE,
    LABEL_NONCE, LABEL_ROOT, NONCE_SIZE,
};

pub use state::{
    Authenticator, AwaitingResponse, ChainState, Direction, Established, Key32, PqRatchet,
    RatchetPhase, RatchetState, SkippedKeys, Uninitialized, MAX_SKIP, MAX_SKIPPED_KEYS,
    XWING_CIPHERTEXT_SIZE, XWING_PUBLIC_KEY_SIZE, XWING_SEED_SIZE, XWING_SHARED_SECRET_SIZE,
};

pub use message::{
    MessageError, MessageHeader, RatchetMessage, RatchetMessageFixed, FLAG_HAS_CIPHERTEXT,
    FLAG_HAS_NEW_PK, FLAG_IS_RESPONSE, MAC_SIZE, MAX_PAYLOAD_SIZE, MIN_HEADER_SIZE, TAG_SIZE,
    VERSION,
};

pub use encrypt::{
    aead_decrypt, aead_encrypt, decrypt_message, decrypt_message_fixed, encrypt_message,
    encrypt_message_fixed,
};

pub use serialize::{SerializeError, MAGIC, RATCHET_STATE_SIZE, VERSION as SERIALIZE_VERSION};

pub use chunking::{
    crc16_ccitt, Chunk, ChunkError, ChunkHeader, Chunker, Reassembler, ReassemblyStatus,
    CHUNK_HEADER_SIZE, CHUNK_MAGIC, CHUNK_VERSION, DEFAULT_MAX_REASSEMBLY_CHUNKS, FLAG_FIRST_CHUNK,
    FLAG_LAST_CHUNK, FLAG_RETRANSMIT, MAX_CHUNKS_PER_STREAM, MAX_CHUNK_PAYLOAD, MAX_CHUNK_SIZE,
};

pub use psa_storage::{
    LazyPersistence, PersistenceConfig, RatchetMetadata, UID_RATCHET_BASE, UID_RATCHET_METADATA,
    UID_RATCHET_STATE_BACKUP, UID_RATCHET_STATE_PRIMARY,
};

// SAGA authorization exports (requires saga feature)
#[cfg(feature = "saga")]
pub use saga_auth::{
    derive_credential_binding, hash_presentation, AuthContext, AuthRequest, SagaAuthError,
    SagaHolder, SagaIssuer, AUTH_CONTEXT_SIZE, LABEL_CREDENTIAL_BIND, NUM_AUTH_ATTRS,
    UID_SAGA_BASE, UID_SAGA_CREDENTIAL, UID_SAGA_KEYPAIR, UID_SAGA_PARAMS, UID_SAGA_PUBLIC_KEY,
};

// X-Wing integration exports
#[cfg(feature = "xwing")]
pub use xwing_ratchet::{
    InitMessage, ResponseMessage, XWingRatchet, XWingRatchetAwaiting, XWingRatchetError,
};
