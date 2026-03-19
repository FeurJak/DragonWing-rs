// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Serialization for PQ-Ratchet State
//!
//! This module provides serialization and deserialization for `RatchetState`,
//! enabling persistent storage in TrustZone Internal Trusted Storage (ITS).
//!
//! # Design Goals
//!
//! - **Fixed-size format**: No dynamic allocation, suitable for no_std
//! - **Deterministic**: Same state always produces same bytes
//! - **Versioned**: Magic + version header for future compatibility
//! - **Secure**: Sensitive keys are included (encrypt before storing!)
//!
//! # Wire Format
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │  Header (8 bytes)                                                    │
//! │    [0..4]   Magic: "PQRS" (0x50 0x51 0x52 0x53)                      │
//! │    [4..6]   Version: u16 BE (currently 1)                            │
//! │    [6..8]   Reserved: u16 (0x0000)                                   │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  Core State                                                          │
//! │    [8]       direction (0=Initiator, 1=Responder)                   │
//! │    [9..17]   epoch (u64 BE)                                         │
//! │    [17..49]  root_key (32 bytes)                                    │
//! │    [49..1265] peer_public_key (1216 bytes)                          │
//! │    [1265]    kem_ratchet_pending (0/1)                              │
//! │    [1266..1298] my_xwing_seed (32 bytes)                            │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  Chain States                                                        │
//! │    [1298..1330] send_chain.chain_key (32 bytes)                     │
//! │    [1330..1334] send_chain.message_num (u32 BE)                     │
//! │    [1334..1366] recv_chain.chain_key (32 bytes)                     │
//! │    [1366..1370] recv_chain.message_num (u32 BE)                     │
//! │    [1370..1374] prev_send_chain_len (u32 BE)                        │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  Authenticator                                                       │
//! │    [1374..1406] auth_root (32 bytes)                                │
//! │    [1406..1438] mac_key (32 bytes)                                  │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  Skipped Keys (variable content, fixed size)                        │
//! │    [1438..1440] count (u16 BE)                                      │
//! │    [1440..1442] oldest_idx (u16 BE)                                 │
//! │    [1442..]    entries (MAX_SKIPPED_KEYS * ENTRY_SIZE)              │
//! │                Each entry: epoch(8) + msg_num(4) + key(32) + occ(1) │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Warning
//!
//! The serialized state contains sensitive key material. It MUST be:
//! - Stored only in encrypted storage (TrustZone ITS)
//! - Never transmitted over insecure channels
//! - Zeroized after use
//!
//! # Example
//!
//! ```rust,ignore
//! use dragonwing_crypto::experimental::pq_ratchet::serialize::*;
//! use dragonwing_crypto::experimental::pq_ratchet::state::RatchetState;
//!
//! // Serialize state for storage
//! let bytes = state.to_bytes();
//!
//! // Store in TrustZone ITS...
//!
//! // Later, restore state
//! let restored = RatchetState::from_bytes(&bytes)?;
//! ```

use super::kdf::KEY_SIZE;
use super::state::{
    Authenticator, ChainState, Direction, Key32, RatchetState, SkippedKeys, MAX_SKIPPED_KEYS,
    XWING_PUBLIC_KEY_SIZE, XWING_SEED_SIZE,
};

// ============================================================================
// Constants
// ============================================================================

/// Magic bytes identifying a PQ-Ratchet state blob
pub const MAGIC: [u8; 4] = [0x50, 0x51, 0x52, 0x53]; // "PQRS"

/// Current serialization format version
pub const VERSION: u16 = 1;

/// Size of each skipped key entry in bytes
/// epoch(8) + message_num(4) + message_key(32) + occupied(1) = 45
const SKIPPED_ENTRY_SIZE: usize = 8 + 4 + KEY_SIZE + 1;

/// Total size of skipped keys section
const SKIPPED_KEYS_SIZE: usize = 2 + 2 + (MAX_SKIPPED_KEYS * SKIPPED_ENTRY_SIZE);

/// Header size (magic + version + reserved)
const HEADER_SIZE: usize = 4 + 2 + 2;

/// Core state size (direction through my_xwing_seed)
const CORE_STATE_SIZE: usize = 1 + 8 + KEY_SIZE + XWING_PUBLIC_KEY_SIZE + 1 + XWING_SEED_SIZE;

/// Chain states size (send + recv chains + prev_send_chain_len)
const CHAINS_SIZE: usize = (KEY_SIZE + 4) * 2 + 4;

/// Authenticator size (auth_root + mac_key)
const AUTHENTICATOR_SIZE: usize = KEY_SIZE * 2;

/// Total serialized size of RatchetState
pub const RATCHET_STATE_SIZE: usize =
    HEADER_SIZE + CORE_STATE_SIZE + CHAINS_SIZE + AUTHENTICATOR_SIZE + SKIPPED_KEYS_SIZE;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during serialization/deserialization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializeError {
    /// Invalid magic bytes (not a PQ-Ratchet state)
    InvalidMagic,
    /// Unsupported version
    UnsupportedVersion,
    /// Buffer too small for serialization
    BufferTooSmall,
    /// Invalid data during deserialization
    InvalidData,
}

/// Result type for serialization operations
pub type Result<T> = core::result::Result<T, SerializeError>;

// ============================================================================
// Serialization Implementation
// ============================================================================

impl RatchetState {
    /// Serialize the ratchet state to a fixed-size byte array
    ///
    /// # Returns
    /// A byte array containing the serialized state
    pub fn to_bytes(&self) -> [u8; RATCHET_STATE_SIZE] {
        let mut buf = [0u8; RATCHET_STATE_SIZE];
        self.encode(&mut buf);
        buf
    }

    /// Encode the ratchet state into a buffer
    ///
    /// # Arguments
    /// * `buf` - Buffer to write into (must be at least RATCHET_STATE_SIZE bytes)
    ///
    /// # Returns
    /// Number of bytes written
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        let mut offset = 0;

        // Header
        buf[offset..offset + 4].copy_from_slice(&MAGIC);
        offset += 4;
        buf[offset..offset + 2].copy_from_slice(&VERSION.to_be_bytes());
        offset += 2;
        buf[offset..offset + 2].copy_from_slice(&0u16.to_be_bytes()); // reserved
        offset += 2;

        // Direction
        buf[offset] = match self.direction() {
            Direction::Initiator => 0,
            Direction::Responder => 1,
        };
        offset += 1;

        // Epoch
        buf[offset..offset + 8].copy_from_slice(&self.epoch().to_be_bytes());
        offset += 8;

        // Root key (access via internal method)
        buf[offset..offset + KEY_SIZE].copy_from_slice(self.root_key_bytes());
        offset += KEY_SIZE;

        // Peer public key
        buf[offset..offset + XWING_PUBLIC_KEY_SIZE].copy_from_slice(self.peer_public_key());
        offset += XWING_PUBLIC_KEY_SIZE;

        // KEM ratchet pending
        buf[offset] = if self.kem_ratchet_pending() { 1 } else { 0 };
        offset += 1;

        // My X-Wing seed
        buf[offset..offset + XWING_SEED_SIZE].copy_from_slice(self.my_xwing_seed());
        offset += XWING_SEED_SIZE;

        // Send chain
        buf[offset..offset + KEY_SIZE].copy_from_slice(self.send_chain_key());
        offset += KEY_SIZE;
        buf[offset..offset + 4].copy_from_slice(&self.send_message_num().to_be_bytes());
        offset += 4;

        // Recv chain
        buf[offset..offset + KEY_SIZE].copy_from_slice(self.recv_chain_key());
        offset += KEY_SIZE;
        buf[offset..offset + 4].copy_from_slice(&self.recv_message_num().to_be_bytes());
        offset += 4;

        // Previous send chain length
        buf[offset..offset + 4].copy_from_slice(&self.prev_send_chain_len().to_be_bytes());
        offset += 4;

        // Authenticator
        let (auth_root, mac_key) = self.authenticator_keys();
        buf[offset..offset + KEY_SIZE].copy_from_slice(auth_root);
        offset += KEY_SIZE;
        buf[offset..offset + KEY_SIZE].copy_from_slice(mac_key);
        offset += KEY_SIZE;

        // Skipped keys
        offset += self.encode_skipped_keys(&mut buf[offset..]);

        offset
    }

    /// Encode skipped keys into buffer
    fn encode_skipped_keys(&self, buf: &mut [u8]) -> usize {
        let mut offset = 0;

        let (count, oldest_idx, entries) = self.skipped_keys_data();

        buf[offset..offset + 2].copy_from_slice(&(count as u16).to_be_bytes());
        offset += 2;
        buf[offset..offset + 2].copy_from_slice(&(oldest_idx as u16).to_be_bytes());
        offset += 2;

        for entry in entries {
            buf[offset..offset + 8].copy_from_slice(&entry.0.to_be_bytes()); // epoch
            offset += 8;
            buf[offset..offset + 4].copy_from_slice(&entry.1.to_be_bytes()); // msg_num
            offset += 4;
            buf[offset..offset + KEY_SIZE].copy_from_slice(&entry.2); // key
            offset += KEY_SIZE;
            buf[offset] = if entry.3 { 1 } else { 0 }; // occupied
            offset += 1;
        }

        offset
    }

    /// Deserialize a ratchet state from bytes
    ///
    /// # Arguments
    /// * `bytes` - Serialized state bytes
    ///
    /// # Returns
    /// The deserialized state, or an error if parsing fails
    pub fn from_bytes(bytes: &[u8; RATCHET_STATE_SIZE]) -> Result<Self> {
        Self::decode(bytes)
    }

    /// Decode a ratchet state from a buffer
    ///
    /// # Arguments
    /// * `buf` - Buffer containing serialized state
    ///
    /// # Returns
    /// The deserialized state, or an error if parsing fails
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < RATCHET_STATE_SIZE {
            return Err(SerializeError::BufferTooSmall);
        }

        let mut offset = 0;

        // Verify magic
        if buf[offset..offset + 4] != MAGIC {
            return Err(SerializeError::InvalidMagic);
        }
        offset += 4;

        // Check version
        let version = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        if version != VERSION {
            return Err(SerializeError::UnsupportedVersion);
        }
        offset += 2;

        // Skip reserved
        offset += 2;

        // Direction
        let direction = match buf[offset] {
            0 => Direction::Initiator,
            1 => Direction::Responder,
            _ => return Err(SerializeError::InvalidData),
        };
        offset += 1;

        // Epoch
        let epoch = u64::from_be_bytes(buf[offset..offset + 8].try_into().unwrap());
        offset += 8;

        // Root key
        let mut root_key = [0u8; KEY_SIZE];
        root_key.copy_from_slice(&buf[offset..offset + KEY_SIZE]);
        offset += KEY_SIZE;

        // Peer public key
        let mut peer_public_key = [0u8; XWING_PUBLIC_KEY_SIZE];
        peer_public_key.copy_from_slice(&buf[offset..offset + XWING_PUBLIC_KEY_SIZE]);
        offset += XWING_PUBLIC_KEY_SIZE;

        // KEM ratchet pending
        let kem_ratchet_pending = buf[offset] != 0;
        offset += 1;

        // My X-Wing seed
        let mut my_xwing_seed = [0u8; XWING_SEED_SIZE];
        my_xwing_seed.copy_from_slice(&buf[offset..offset + XWING_SEED_SIZE]);
        offset += XWING_SEED_SIZE;

        // Send chain
        let mut send_chain_key = [0u8; KEY_SIZE];
        send_chain_key.copy_from_slice(&buf[offset..offset + KEY_SIZE]);
        offset += KEY_SIZE;
        let send_message_num = u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // Recv chain
        let mut recv_chain_key = [0u8; KEY_SIZE];
        recv_chain_key.copy_from_slice(&buf[offset..offset + KEY_SIZE]);
        offset += KEY_SIZE;
        let recv_message_num = u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // Previous send chain length
        let prev_send_chain_len = u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // Authenticator
        let mut auth_root = [0u8; KEY_SIZE];
        auth_root.copy_from_slice(&buf[offset..offset + KEY_SIZE]);
        offset += KEY_SIZE;
        let mut mac_key = [0u8; KEY_SIZE];
        mac_key.copy_from_slice(&buf[offset..offset + KEY_SIZE]);
        offset += KEY_SIZE;

        // Skipped keys
        let skipped_keys = Self::decode_skipped_keys(&buf[offset..])?;

        // Reconstruct state
        Ok(Self::from_parts(
            direction,
            epoch,
            root_key,
            peer_public_key,
            kem_ratchet_pending,
            my_xwing_seed,
            send_chain_key,
            send_message_num,
            recv_chain_key,
            recv_message_num,
            prev_send_chain_len,
            auth_root,
            mac_key,
            skipped_keys,
        ))
    }

    /// Decode skipped keys from buffer
    fn decode_skipped_keys(buf: &[u8]) -> Result<SkippedKeys> {
        let mut offset = 0;

        let count = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
        offset += 2;
        let oldest_idx = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
        offset += 2;

        if count > MAX_SKIPPED_KEYS || oldest_idx >= MAX_SKIPPED_KEYS {
            return Err(SerializeError::InvalidData);
        }

        let mut entries = [(0u64, 0u32, [0u8; KEY_SIZE], false); MAX_SKIPPED_KEYS];

        for entry in entries.iter_mut() {
            let epoch = u64::from_be_bytes(buf[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let msg_num = u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap());
            offset += 4;
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&buf[offset..offset + KEY_SIZE]);
            offset += KEY_SIZE;
            let occupied = buf[offset] != 0;
            offset += 1;

            *entry = (epoch, msg_num, key, occupied);
        }

        Ok(SkippedKeys::from_parts(count, oldest_idx, entries))
    }
}

// ============================================================================
// PSA Storable Implementation
// ============================================================================

#[cfg(feature = "psa")]
impl crate::psa::PsaStorable for RatchetState {
    const SERIALIZED_SIZE: usize = RATCHET_STATE_SIZE;
    type Bytes = [u8; RATCHET_STATE_SIZE];

    fn to_psa_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self> {
        Self::from_bytes(bytes).ok()
    }

    fn zero_bytes() -> Self::Bytes {
        [0u8; RATCHET_STATE_SIZE]
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Verify size calculations
        assert_eq!(HEADER_SIZE, 8);
        assert_eq!(SKIPPED_ENTRY_SIZE, 45);
        assert_eq!(SKIPPED_KEYS_SIZE, 4 + 50 * 45); // 2254

        // Total should be under 4KB for ITS compatibility
        assert!(RATCHET_STATE_SIZE < 4096);
        // RATCHET_STATE_SIZE = 3692 bytes (fits in 4KB ITS limit)
    }

    #[test]
    fn test_serialize_roundtrip() {
        let state = RatchetState::new(
            Direction::Initiator,
            [0x11u8; KEY_SIZE],
            [0x22u8; XWING_PUBLIC_KEY_SIZE],
            [0x33u8; XWING_SEED_SIZE],
            [0x44u8; KEY_SIZE],
        );

        let bytes = state.to_bytes();

        // Check magic
        assert_eq!(&bytes[0..4], &MAGIC);

        // Check version
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        assert_eq!(version, VERSION);

        // Deserialize
        let restored = RatchetState::from_bytes(&bytes).unwrap();

        // Verify fields
        assert_eq!(restored.direction(), Direction::Initiator);
        assert_eq!(restored.epoch(), 0);
        assert_eq!(restored.peer_public_key(), &[0x22u8; XWING_PUBLIC_KEY_SIZE]);
    }

    #[test]
    fn test_serialize_with_advanced_state() {
        let mut state = RatchetState::new(
            Direction::Responder,
            [0x11u8; KEY_SIZE],
            [0x22u8; XWING_PUBLIC_KEY_SIZE],
            [0x33u8; XWING_SEED_SIZE],
            [0x44u8; KEY_SIZE],
        );

        // Advance the state
        let _ = state.next_send_key();
        let _ = state.next_send_key();
        let _ = state.next_recv_key();

        let bytes = state.to_bytes();
        let restored = RatchetState::from_bytes(&bytes).unwrap();

        assert_eq!(restored.direction(), Direction::Responder);
        assert_eq!(restored.send_message_num(), 2);
        assert_eq!(restored.recv_message_num(), 1);
    }

    #[test]
    fn test_invalid_magic() {
        let mut bytes = [0u8; RATCHET_STATE_SIZE];
        bytes[0..4].copy_from_slice(b"XXXX"); // Wrong magic

        let result = RatchetState::from_bytes(&bytes);
        assert_eq!(result.unwrap_err(), SerializeError::InvalidMagic);
    }

    #[test]
    fn test_unsupported_version() {
        let state = RatchetState::new(
            Direction::Initiator,
            [0x11u8; KEY_SIZE],
            [0x22u8; XWING_PUBLIC_KEY_SIZE],
            [0x33u8; XWING_SEED_SIZE],
            [0x44u8; KEY_SIZE],
        );

        let mut bytes = state.to_bytes();
        // Set version to 99
        bytes[4..6].copy_from_slice(&99u16.to_be_bytes());

        let result = RatchetState::from_bytes(&bytes);
        assert_eq!(result.unwrap_err(), SerializeError::UnsupportedVersion);
    }

    #[test]
    fn test_invalid_direction() {
        let state = RatchetState::new(
            Direction::Initiator,
            [0x11u8; KEY_SIZE],
            [0x22u8; XWING_PUBLIC_KEY_SIZE],
            [0x33u8; XWING_SEED_SIZE],
            [0x44u8; KEY_SIZE],
        );

        let mut bytes = state.to_bytes();
        // Set direction to invalid value
        bytes[8] = 99;

        let result = RatchetState::from_bytes(&bytes);
        assert_eq!(result.unwrap_err(), SerializeError::InvalidData);
    }
}
