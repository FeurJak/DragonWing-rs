// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Ratchet State Types for PQ-Ratchet
//!
//! This module defines the state structures for the post-quantum double ratchet
//! protocol. The design follows Signal's Double Ratchet specification adapted
//! for X-Wing (ML-KEM-768 + X25519) KEM operations.
//!
//! # Architecture
//!
//! The ratchet maintains several components:
//! - **Root chain**: Updated on each KEM ratchet (new epoch)
//! - **Send/Recv chains**: Updated per-message (symmetric ratchet)
//! - **Authenticator**: Epoch-evolving MAC keys for header authentication
//! - **Skipped keys**: Bounded storage for out-of-order message handling
//!
//! # Memory Constraints
//!
//! All structures are designed for `no_std` environments with bounded memory:
//! - No heap allocations in core types
//! - Fixed-size arrays for keys
//! - Bounded collections for skipped keys (max 50 entries)
//!
//! # Security
//!
//! - All key material implements `Zeroize` for secure erasure
//! - Keys are zeroized on drop
//! - Constant-time comparisons where applicable

use core::marker::PhantomData;

use super::kdf::{self, KEY_SIZE, NONCE_SIZE};

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of skipped message keys to store
/// This bounds memory usage and limits how far out-of-order messages can be
pub const MAX_SKIPPED_KEYS: usize = 50;

/// Maximum number of messages to skip when advancing the chain
/// Prevents DoS via messages with very high sequence numbers
pub const MAX_SKIP: u32 = 100;

/// Size of X-Wing public key in bytes
pub const XWING_PUBLIC_KEY_SIZE: usize = 1216;

/// Size of X-Wing secret key seed in bytes
pub const XWING_SEED_SIZE: usize = 32;

/// Size of X-Wing ciphertext in bytes
pub const XWING_CIPHERTEXT_SIZE: usize = 1120;

/// Size of X-Wing shared secret in bytes
pub const XWING_SHARED_SECRET_SIZE: usize = 32;

// ============================================================================
// Direction
// ============================================================================

/// Direction of the ratchet (who initiated the session)
///
/// This determines the initial send/receive chain assignment and affects
/// how KEM ratchet steps are performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// We initiated the session (sent first message)
    Initiator,
    /// We responded to the session (received first message)
    Responder,
}

impl Direction {
    /// Get the opposite direction
    pub fn opposite(self) -> Self {
        match self {
            Direction::Initiator => Direction::Responder,
            Direction::Responder => Direction::Initiator,
        }
    }
}

// ============================================================================
// Key Types (with secure zeroization)
// ============================================================================

/// A 32-byte cryptographic key with secure zeroization
#[derive(Clone)]
pub struct Key32([u8; KEY_SIZE]);

impl Key32 {
    /// Create a new key from bytes
    pub fn new(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Create a zero key (for initialization)
    pub fn zero() -> Self {
        Self([0u8; KEY_SIZE])
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }

    /// Get mutable access to key bytes
    pub fn as_bytes_mut(&mut self) -> &mut [u8; KEY_SIZE] {
        &mut self.0
    }
}

impl Drop for Key32 {
    fn drop(&mut self) {
        // Secure zeroization
        for byte in &mut self.0 {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl core::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Don't leak key material in debug output
        f.write_str("Key32([REDACTED])")
    }
}

// ============================================================================
// Chain State
// ============================================================================

/// State of a single ratchet chain (send or receive)
///
/// Each chain produces a sequence of message keys. The chain key is updated
/// after each message key derivation (symmetric ratchet step).
#[derive(Clone)]
pub struct ChainState {
    /// Current chain key (updated per-message)
    chain_key: Key32,
    /// Message counter (number of messages sent/received on this chain)
    message_num: u32,
}

impl ChainState {
    /// Create a new chain state with the given initial chain key
    pub fn new(chain_key: [u8; KEY_SIZE]) -> Self {
        Self {
            chain_key: Key32::new(chain_key),
            message_num: 0,
        }
    }

    /// Reconstruct chain state from parts (for deserialization)
    pub(crate) fn from_parts(chain_key: [u8; KEY_SIZE], message_num: u32) -> Self {
        Self {
            chain_key: Key32::new(chain_key),
            message_num,
        }
    }

    /// Get the current chain key
    pub fn chain_key(&self) -> &[u8; KEY_SIZE] {
        self.chain_key.as_bytes()
    }

    /// Get the current message number
    pub fn message_num(&self) -> u32 {
        self.message_num
    }

    /// Advance the chain and return the message key
    ///
    /// This performs one symmetric ratchet step:
    /// 1. Derives (next_chain_key, message_key) from current chain_key
    /// 2. Updates chain_key to next_chain_key
    /// 3. Increments message_num
    /// 4. Returns message_key
    pub fn advance(&mut self) -> [u8; KEY_SIZE] {
        let (next_chain_key, message_key) = kdf::kdf_chain(self.chain_key.as_bytes());
        *self.chain_key.as_bytes_mut() = next_chain_key;
        self.message_num += 1;
        message_key
    }

    /// Advance the chain multiple steps, storing skipped keys
    ///
    /// Used when receiving a message with a higher sequence number than expected.
    /// Returns the skipped keys as (message_num, message_key) pairs.
    ///
    /// # Arguments
    /// * `target_num` - The target message number to advance to
    /// * `max_skip` - Maximum number of steps to skip
    ///
    /// # Returns
    /// * `Ok(skipped_keys)` - Vector of skipped (message_num, message_key) pairs
    /// * `Err(())` - If target_num would require skipping more than max_skip messages
    pub fn advance_to(
        &mut self,
        target_num: u32,
        max_skip: u32,
    ) -> Result<[(u32, [u8; KEY_SIZE]); MAX_SKIPPED_KEYS], ()> {
        if target_num < self.message_num {
            return Err(()); // Can't go backwards
        }

        let skip_count = target_num - self.message_num;
        if skip_count > max_skip {
            return Err(()); // Too many to skip
        }

        let mut skipped = [Default::default(); MAX_SKIPPED_KEYS];
        let mut skipped_count = 0;

        while self.message_num < target_num && skipped_count < MAX_SKIPPED_KEYS {
            let msg_num = self.message_num;
            let msg_key = self.advance();
            skipped[skipped_count] = (msg_num, msg_key);
            skipped_count += 1;
        }

        Ok(skipped)
    }
}

impl core::fmt::Debug for ChainState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChainState")
            .field("chain_key", &"[REDACTED]")
            .field("message_num", &self.message_num)
            .finish()
    }
}

// ============================================================================
// Authenticator
// ============================================================================

/// Epoch-evolving authenticator for header MAC
///
/// The authenticator provides MAC keys that evolve with each epoch,
/// following Signal's SPQR pattern. This ensures header authentication
/// is bound to the current epoch.
#[derive(Clone)]
pub struct Authenticator {
    /// Root key for authenticator chain
    auth_root: Key32,
    /// Current MAC key (derived from auth_root + epoch_secret)
    mac_key: Key32,
}

impl Authenticator {
    /// Create a new authenticator with the given root key
    pub fn new(auth_root: [u8; KEY_SIZE]) -> Self {
        Self {
            auth_root: Key32::new(auth_root),
            mac_key: Key32::zero(),
        }
    }

    /// Update the authenticator for a new epoch
    ///
    /// # Arguments
    /// * `epoch_secret` - The shared secret from the KEM ratchet step
    pub fn update(&mut self, epoch_secret: &[u8; KEY_SIZE]) {
        let (new_auth_root, new_mac_key) = kdf::kdf_auth(self.auth_root.as_bytes(), epoch_secret);
        *self.auth_root.as_bytes_mut() = new_auth_root;
        *self.mac_key.as_bytes_mut() = new_mac_key;
    }

    /// Get the current MAC key for header authentication
    pub fn mac_key(&self) -> &[u8; KEY_SIZE] {
        self.mac_key.as_bytes()
    }

    /// Get the authenticator root key (for serialization)
    pub(crate) fn auth_root(&self) -> &[u8; KEY_SIZE] {
        self.auth_root.as_bytes()
    }

    /// Reconstruct authenticator from parts (for deserialization)
    pub(crate) fn from_parts(auth_root: [u8; KEY_SIZE], mac_key: [u8; KEY_SIZE]) -> Self {
        Self {
            auth_root: Key32::new(auth_root),
            mac_key: Key32::new(mac_key),
        }
    }

    /// Compute MAC over header data
    ///
    /// Uses HMAC-SHA256 truncated to 32 bytes
    pub fn mac_header(&self, header: &[u8]) -> [u8; KEY_SIZE] {
        // Simple HMAC using our existing infrastructure
        use sha2::{Digest, Sha256};

        const BLOCK_SIZE: usize = 64;
        const IPAD: u8 = 0x36;
        const OPAD: u8 = 0x5c;

        let key = self.mac_key.as_bytes();

        // Pad key to block size
        let mut key_block = [0u8; BLOCK_SIZE];
        key_block[..KEY_SIZE].copy_from_slice(key);

        // Inner hash
        let mut inner_hasher = Sha256::new();
        let mut inner_key = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            inner_key[i] = key_block[i] ^ IPAD;
        }
        inner_hasher.update(&inner_key);
        inner_hasher.update(header);
        let inner_hash = inner_hasher.finalize();

        // Outer hash
        let mut outer_hasher = Sha256::new();
        let mut outer_key = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            outer_key[i] = key_block[i] ^ OPAD;
        }
        outer_hasher.update(&outer_key);
        outer_hasher.update(&inner_hash);
        let outer_hash = outer_hasher.finalize();

        let mut result = [0u8; KEY_SIZE];
        result.copy_from_slice(&outer_hash);
        result
    }

    /// Verify MAC over header data (constant-time comparison)
    pub fn verify_header(&self, header: &[u8], mac: &[u8; KEY_SIZE]) -> bool {
        let computed = self.mac_header(header);
        constant_time_eq(&computed, mac)
    }
}

impl core::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Authenticator")
            .field("auth_root", &"[REDACTED]")
            .field("mac_key", &"[REDACTED]")
            .finish()
    }
}

// ============================================================================
// Skipped Keys Storage
// ============================================================================

/// Entry in the skipped keys storage
#[derive(Clone)]
struct SkippedKeyEntry {
    /// Epoch when this key was skipped
    epoch: u64,
    /// Message number within the epoch
    message_num: u32,
    /// The skipped message key
    message_key: [u8; KEY_SIZE],
    /// Whether this entry is occupied
    occupied: bool,
}

impl SkippedKeyEntry {
    const fn empty() -> Self {
        Self {
            epoch: 0,
            message_num: 0,
            message_key: [0u8; KEY_SIZE],
            occupied: false,
        }
    }
}

/// Bounded storage for skipped message keys
///
/// When messages arrive out of order, we need to store the skipped keys
/// to decrypt them later. This structure provides bounded storage (no heap)
/// with FIFO eviction when full.
pub struct SkippedKeys {
    /// Fixed-size array of entries
    entries: [SkippedKeyEntry; MAX_SKIPPED_KEYS],
    /// Number of occupied entries
    count: usize,
    /// Index of oldest entry (for FIFO eviction)
    oldest_idx: usize,
}

impl SkippedKeys {
    /// Create a new empty skipped keys storage
    pub fn new() -> Self {
        Self {
            entries: [const { SkippedKeyEntry::empty() }; MAX_SKIPPED_KEYS],
            count: 0,
            oldest_idx: 0,
        }
    }

    /// Store a skipped key
    ///
    /// If storage is full, the oldest entry is evicted.
    pub fn store(&mut self, epoch: u64, message_num: u32, message_key: [u8; KEY_SIZE]) {
        // Find a free slot or use FIFO eviction
        let idx = if self.count < MAX_SKIPPED_KEYS {
            // Find first unoccupied slot
            let mut idx = 0;
            for i in 0..MAX_SKIPPED_KEYS {
                if !self.entries[i].occupied {
                    idx = i;
                    break;
                }
            }
            self.count += 1;
            idx
        } else {
            // Evict oldest entry
            let idx = self.oldest_idx;
            self.oldest_idx = (self.oldest_idx + 1) % MAX_SKIPPED_KEYS;
            idx
        };

        self.entries[idx] = SkippedKeyEntry {
            epoch,
            message_num,
            message_key,
            occupied: true,
        };
    }

    /// Lookup and remove a skipped key
    ///
    /// Returns the message key if found, removing it from storage.
    pub fn take(&mut self, epoch: u64, message_num: u32) -> Option<[u8; KEY_SIZE]> {
        for entry in &mut self.entries {
            if entry.occupied && entry.epoch == epoch && entry.message_num == message_num {
                entry.occupied = false;
                self.count = self.count.saturating_sub(1);
                return Some(entry.message_key);
            }
        }
        None
    }

    /// Check if a key exists without removing it
    pub fn contains(&self, epoch: u64, message_num: u32) -> bool {
        self.entries
            .iter()
            .any(|e| e.occupied && e.epoch == epoch && e.message_num == message_num)
    }

    /// Get the number of stored keys
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if storage is empty
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Clear all stored keys
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            entry.occupied = false;
            // Keys are zeroized when entry is dropped/overwritten
        }
        self.count = 0;
        self.oldest_idx = 0;
    }

    /// Export skipped keys data for serialization
    ///
    /// Returns (count, oldest_idx, entries) where entries is an array of
    /// (epoch, message_num, message_key, occupied) tuples.
    pub(crate) fn to_parts(
        &self,
    ) -> (
        usize,
        usize,
        [(u64, u32, [u8; KEY_SIZE], bool); MAX_SKIPPED_KEYS],
    ) {
        let mut entries = [(0u64, 0u32, [0u8; KEY_SIZE], false); MAX_SKIPPED_KEYS];
        for (i, entry) in self.entries.iter().enumerate() {
            entries[i] = (
                entry.epoch,
                entry.message_num,
                entry.message_key,
                entry.occupied,
            );
        }
        (self.count, self.oldest_idx, entries)
    }

    /// Reconstruct skipped keys from parts (for deserialization)
    pub(crate) fn from_parts(
        count: usize,
        oldest_idx: usize,
        entries: [(u64, u32, [u8; KEY_SIZE], bool); MAX_SKIPPED_KEYS],
    ) -> Self {
        let mut result = Self::new();
        result.count = count;
        result.oldest_idx = oldest_idx;

        for (i, (epoch, message_num, message_key, occupied)) in entries.iter().enumerate() {
            result.entries[i] = SkippedKeyEntry {
                epoch: *epoch,
                message_num: *message_num,
                message_key: *message_key,
                occupied: *occupied,
            };
        }

        result
    }
}

impl Default for SkippedKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for SkippedKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SkippedKeys")
            .field("count", &self.count)
            .field("capacity", &MAX_SKIPPED_KEYS)
            .finish()
    }
}

// ============================================================================
// Main Ratchet State
// ============================================================================

/// Complete state for the PQ-Ratchet protocol
///
/// This structure contains all state needed for the double ratchet:
/// - KEM ratchet state (root key, epoch, peer public key)
/// - Symmetric ratchet state (send and receive chains)
/// - Authenticator for header MAC
/// - Skipped keys for out-of-order handling
pub struct RatchetState {
    /// Our direction in the session
    direction: Direction,

    /// Current epoch number (increments on each KEM ratchet)
    epoch: u64,

    /// Root key (updated on each KEM ratchet)
    root_key: Key32,

    /// Peer's current X-Wing public key (for encapsulation)
    peer_public_key: [u8; XWING_PUBLIC_KEY_SIZE],

    /// Whether we have performed a KEM ratchet this epoch
    /// (determines if we should send our new public key)
    kem_ratchet_pending: bool,

    /// Our current X-Wing key seed (for generating keypair)
    /// Stored as seed to minimize state size
    my_xwing_seed: Key32,

    /// Send chain state
    send_chain: ChainState,

    /// Receive chain state  
    recv_chain: ChainState,

    /// Previous send chain message count (for header)
    prev_send_chain_len: u32,

    /// Header authenticator
    authenticator: Authenticator,

    /// Skipped message keys for out-of-order handling
    skipped_keys: SkippedKeys,
}

impl RatchetState {
    /// Create a new ratchet state after initial key exchange
    ///
    /// # Arguments
    /// * `direction` - Whether we initiated or responded
    /// * `root_key` - Initial root key from X-Wing key exchange
    /// * `peer_public_key` - Peer's X-Wing public key
    /// * `my_xwing_seed` - Our X-Wing key seed
    /// * `auth_root` - Initial authenticator root key
    pub fn new(
        direction: Direction,
        root_key: [u8; KEY_SIZE],
        peer_public_key: [u8; XWING_PUBLIC_KEY_SIZE],
        my_xwing_seed: [u8; XWING_SEED_SIZE],
        auth_root: [u8; KEY_SIZE],
    ) -> Self {
        // Derive initial chain keys from root
        // Initiator gets send chain first, responder gets receive chain first
        let (send_chain_key, recv_chain_key) = match direction {
            Direction::Initiator => {
                let (_, chain) = kdf::kdf_root(&root_key, &[0u8; 32]);
                (chain, [0u8; KEY_SIZE]) // Initiator sends first
            }
            Direction::Responder => {
                let (_, chain) = kdf::kdf_root(&root_key, &[0u8; 32]);
                ([0u8; KEY_SIZE], chain) // Responder receives first
            }
        };

        Self {
            direction,
            epoch: 0,
            root_key: Key32::new(root_key),
            peer_public_key,
            kem_ratchet_pending: direction == Direction::Initiator,
            my_xwing_seed: Key32::new(my_xwing_seed),
            send_chain: ChainState::new(send_chain_key),
            recv_chain: ChainState::new(recv_chain_key),
            prev_send_chain_len: 0,
            authenticator: Authenticator::new(auth_root),
            skipped_keys: SkippedKeys::new(),
        }
    }

    /// Get the current epoch
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Get our direction
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Get the peer's public key
    pub fn peer_public_key(&self) -> &[u8; XWING_PUBLIC_KEY_SIZE] {
        &self.peer_public_key
    }

    /// Get our X-Wing seed
    pub fn my_xwing_seed(&self) -> &[u8; XWING_SEED_SIZE] {
        self.my_xwing_seed.as_bytes()
    }

    /// Check if we need to send our new public key
    pub fn kem_ratchet_pending(&self) -> bool {
        self.kem_ratchet_pending
    }

    /// Get the current send message number
    pub fn send_message_num(&self) -> u32 {
        self.send_chain.message_num()
    }

    /// Get the current receive message number
    pub fn recv_message_num(&self) -> u32 {
        self.recv_chain.message_num()
    }

    /// Get the previous send chain length
    pub fn prev_send_chain_len(&self) -> u32 {
        self.prev_send_chain_len
    }

    /// Get the root key (for testing/debugging only)
    #[cfg(test)]
    pub fn root_key(&self) -> &[u8; KEY_SIZE] {
        self.root_key.as_bytes()
    }

    /// Advance the send chain and return message key + nonce
    pub fn next_send_key(&mut self) -> ([u8; KEY_SIZE], [u8; NONCE_SIZE]) {
        let msg_key = self.send_chain.advance();
        let nonce = kdf::derive_nonce(&msg_key);
        (msg_key, nonce)
    }

    /// Get the next receive key for the expected message
    ///
    /// Returns the message key and nonce for decryption.
    pub fn next_recv_key(&mut self) -> ([u8; KEY_SIZE], [u8; NONCE_SIZE]) {
        let msg_key = self.recv_chain.advance();
        let nonce = kdf::derive_nonce(&msg_key);
        (msg_key, nonce)
    }

    /// Try to get a receive key for a specific message number
    ///
    /// Handles out-of-order messages by:
    /// 1. Checking skipped keys storage
    /// 2. Advancing the chain if needed (storing skipped keys)
    ///
    /// # Arguments
    /// * `epoch` - The epoch of the message
    /// * `message_num` - The message number within the epoch
    ///
    /// # Returns
    /// * `Ok((msg_key, nonce))` - Keys for decryption
    /// * `Err(())` - Message number invalid or too far ahead
    pub fn get_recv_key(
        &mut self,
        epoch: u64,
        message_num: u32,
    ) -> Result<([u8; KEY_SIZE], [u8; NONCE_SIZE]), ()> {
        // Check if this is from a different epoch
        if epoch != self.epoch {
            // Try skipped keys from previous epochs
            if let Some(msg_key) = self.skipped_keys.take(epoch, message_num) {
                let nonce = kdf::derive_nonce(&msg_key);
                return Ok((msg_key, nonce));
            }
            return Err(());
        }

        // Check if we already have this key stored
        if let Some(msg_key) = self.skipped_keys.take(epoch, message_num) {
            let nonce = kdf::derive_nonce(&msg_key);
            return Ok((msg_key, nonce));
        }

        // Check if this is the next expected message
        let expected = self.recv_chain.message_num();
        if message_num == expected {
            return Ok(self.next_recv_key());
        }

        // Need to skip ahead
        if message_num < expected {
            return Err(()); // Already processed or invalid
        }

        // Advance chain, storing skipped keys
        let skipped = self.recv_chain.advance_to(message_num, MAX_SKIP)?;

        // Store skipped keys
        for (num, key) in skipped.iter() {
            if *num < message_num {
                self.skipped_keys.store(epoch, *num, *key);
            }
        }

        // Now get the key for our target message
        Ok(self.next_recv_key())
    }

    /// Perform a KEM ratchet step with a new shared secret
    ///
    /// Called when we receive a new public key from the peer.
    ///
    /// # Arguments
    /// * `shared_secret` - The shared secret from X-Wing decapsulation
    /// * `new_peer_pk` - The peer's new public key
    pub fn kem_ratchet_recv(
        &mut self,
        shared_secret: &[u8; XWING_SHARED_SECRET_SIZE],
        new_peer_pk: &[u8; XWING_PUBLIC_KEY_SIZE],
    ) {
        // Save previous send chain length
        self.prev_send_chain_len = self.send_chain.message_num();

        // Update root key and derive new receive chain
        let (new_root, new_recv_chain) = kdf::kdf_root(self.root_key.as_bytes(), shared_secret);
        *self.root_key.as_bytes_mut() = new_root;
        self.recv_chain = ChainState::new(new_recv_chain);

        // Update peer public key
        self.peer_public_key = *new_peer_pk;

        // Update authenticator
        self.authenticator.update(shared_secret);

        // Increment epoch
        self.epoch += 1;

        // Mark that we need to send our new public key
        self.kem_ratchet_pending = true;
    }

    /// Perform a KEM ratchet step when we're sending
    ///
    /// Called when we encapsulate to the peer's public key.
    ///
    /// # Arguments
    /// * `shared_secret` - The shared secret from X-Wing encapsulation
    /// * `new_seed` - Our new X-Wing seed for the next keypair
    pub fn kem_ratchet_send(
        &mut self,
        shared_secret: &[u8; XWING_SHARED_SECRET_SIZE],
        new_seed: &[u8; XWING_SEED_SIZE],
    ) {
        // Update root key and derive new send chain
        let (new_root, new_send_chain) = kdf::kdf_root(self.root_key.as_bytes(), shared_secret);
        *self.root_key.as_bytes_mut() = new_root;
        self.send_chain = ChainState::new(new_send_chain);

        // Update our seed
        *self.my_xwing_seed.as_bytes_mut() = *new_seed;

        // Update authenticator
        self.authenticator.update(shared_secret);

        // Clear pending flag
        self.kem_ratchet_pending = false;
    }

    /// Compute MAC for a message header
    pub fn mac_header(&self, header: &[u8]) -> [u8; KEY_SIZE] {
        self.authenticator.mac_header(header)
    }

    /// Verify MAC for a message header
    pub fn verify_header(&self, header: &[u8], mac: &[u8; KEY_SIZE]) -> bool {
        self.authenticator.verify_header(header, mac)
    }

    // ========================================================================
    // Serialization Support Methods
    // ========================================================================

    /// Get root key bytes (for serialization)
    pub(crate) fn root_key_bytes(&self) -> &[u8; KEY_SIZE] {
        self.root_key.as_bytes()
    }

    /// Get send chain key (for serialization)
    pub(crate) fn send_chain_key(&self) -> &[u8; KEY_SIZE] {
        self.send_chain.chain_key()
    }

    /// Get recv chain key (for serialization)
    pub(crate) fn recv_chain_key(&self) -> &[u8; KEY_SIZE] {
        self.recv_chain.chain_key()
    }

    /// Get authenticator keys (for serialization)
    pub(crate) fn authenticator_keys(&self) -> (&[u8; KEY_SIZE], &[u8; KEY_SIZE]) {
        (self.authenticator.auth_root(), self.authenticator.mac_key())
    }

    /// Get skipped keys data (for serialization)
    pub(crate) fn skipped_keys_data(
        &self,
    ) -> (
        usize,
        usize,
        [(u64, u32, [u8; KEY_SIZE], bool); MAX_SKIPPED_KEYS],
    ) {
        self.skipped_keys.to_parts()
    }

    /// Reconstruct state from parts (for deserialization)
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        direction: Direction,
        epoch: u64,
        root_key: [u8; KEY_SIZE],
        peer_public_key: [u8; XWING_PUBLIC_KEY_SIZE],
        kem_ratchet_pending: bool,
        my_xwing_seed: [u8; XWING_SEED_SIZE],
        send_chain_key: [u8; KEY_SIZE],
        send_message_num: u32,
        recv_chain_key: [u8; KEY_SIZE],
        recv_message_num: u32,
        prev_send_chain_len: u32,
        auth_root: [u8; KEY_SIZE],
        mac_key: [u8; KEY_SIZE],
        skipped_keys: SkippedKeys,
    ) -> Self {
        Self {
            direction,
            epoch,
            root_key: Key32::new(root_key),
            peer_public_key,
            kem_ratchet_pending,
            my_xwing_seed: Key32::new(my_xwing_seed),
            send_chain: ChainState::from_parts(send_chain_key, send_message_num),
            recv_chain: ChainState::from_parts(recv_chain_key, recv_message_num),
            prev_send_chain_len,
            authenticator: Authenticator::from_parts(auth_root, mac_key),
            skipped_keys,
        }
    }
}

impl core::fmt::Debug for RatchetState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RatchetState")
            .field("direction", &self.direction)
            .field("epoch", &self.epoch)
            .field("send_msg_num", &self.send_chain.message_num())
            .field("recv_msg_num", &self.recv_chain.message_num())
            .field("kem_ratchet_pending", &self.kem_ratchet_pending)
            .field("skipped_keys", &self.skipped_keys.len())
            .finish()
    }
}

// ============================================================================
// Typestate Pattern for Protocol Phases
// ============================================================================

/// Marker trait for ratchet protocol phases
pub trait RatchetPhase {}

/// Uninitialized state - no keys established yet
pub struct Uninitialized;
impl RatchetPhase for Uninitialized {}

/// Awaiting response after sending initial message
pub struct AwaitingResponse {
    /// The epoch we're expecting
    pub epoch: u64,
    /// Our ephemeral X-Wing seed (for decapsulating response)
    pub ephemeral_seed: [u8; XWING_SEED_SIZE],
}
impl RatchetPhase for AwaitingResponse {}

/// Session established, ready for messaging
pub struct Established;
impl RatchetPhase for Established {}

/// Typestate wrapper for the ratchet protocol
///
/// This enforces valid state transitions at compile time:
/// - `Uninitialized` → `AwaitingResponse` (via `initiate`)
/// - `AwaitingResponse` → `Established` (via `complete`)
/// - `Uninitialized` → `Established` (via `respond`)
pub struct PqRatchet<S: RatchetPhase> {
    _phase: PhantomData<S>,
    state: Option<RatchetState>,
}

impl PqRatchet<Uninitialized> {
    /// Create a new uninitialized ratchet
    pub fn new() -> Self {
        Self {
            _phase: PhantomData,
            state: None,
        }
    }
}

impl Default for PqRatchet<Uninitialized> {
    fn default() -> Self {
        Self::new()
    }
}

impl PqRatchet<Established> {
    /// Create an established ratchet from state
    pub fn from_state(state: RatchetState) -> Self {
        Self {
            _phase: PhantomData,
            state: Some(state),
        }
    }

    /// Get a reference to the ratchet state
    pub fn state(&self) -> &RatchetState {
        self.state
            .as_ref()
            .expect("Established ratchet must have state")
    }

    /// Get a mutable reference to the ratchet state
    pub fn state_mut(&mut self) -> &mut RatchetState {
        self.state
            .as_mut()
            .expect("Established ratchet must have state")
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Constant-time byte array comparison
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }

    diff == 0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direction_opposite() {
        assert_eq!(Direction::Initiator.opposite(), Direction::Responder);
        assert_eq!(Direction::Responder.opposite(), Direction::Initiator);
    }

    #[test]
    fn test_key32_zeroize_on_drop() {
        let key = Key32::new([0xAB; KEY_SIZE]);
        assert_eq!(key.as_bytes(), &[0xAB; KEY_SIZE]);
        // Key will be zeroized when dropped
    }

    #[test]
    fn test_chain_state_advance() {
        let mut chain = ChainState::new([1u8; KEY_SIZE]);

        let key1 = chain.advance();
        assert_eq!(chain.message_num(), 1);

        let key2 = chain.advance();
        assert_eq!(chain.message_num(), 2);

        // Keys should be different
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_chain_state_advance_to() {
        let mut chain = ChainState::new([1u8; KEY_SIZE]);

        // Advance to message 3
        let result = chain.advance_to(3, MAX_SKIP);
        assert!(result.is_ok());
        assert_eq!(chain.message_num(), 3);
    }

    #[test]
    fn test_chain_state_advance_to_too_far() {
        let mut chain = ChainState::new([1u8; KEY_SIZE]);

        // Try to advance too far
        let result = chain.advance_to(MAX_SKIP + 10, MAX_SKIP);
        assert!(result.is_err());
    }

    #[test]
    fn test_skipped_keys_store_and_take() {
        let mut skipped = SkippedKeys::new();

        skipped.store(1, 5, [0xAA; KEY_SIZE]);
        skipped.store(1, 7, [0xBB; KEY_SIZE]);

        assert_eq!(skipped.len(), 2);

        // Take existing key
        let key = skipped.take(1, 5);
        assert!(key.is_some());
        assert_eq!(key.unwrap(), [0xAA; KEY_SIZE]);
        assert_eq!(skipped.len(), 1);

        // Take non-existing key
        let key = skipped.take(1, 6);
        assert!(key.is_none());

        // Take the other key
        let key = skipped.take(1, 7);
        assert!(key.is_some());
        assert_eq!(key.unwrap(), [0xBB; KEY_SIZE]);
        assert!(skipped.is_empty());
    }

    #[test]
    fn test_skipped_keys_fifo_eviction() {
        let mut skipped = SkippedKeys::new();

        // Fill up the storage
        for i in 0..MAX_SKIPPED_KEYS {
            skipped.store(1, i as u32, [i as u8; KEY_SIZE]);
        }
        assert_eq!(skipped.len(), MAX_SKIPPED_KEYS);

        // Add one more - should evict the oldest
        skipped.store(1, 100, [0xFF; KEY_SIZE]);
        assert_eq!(skipped.len(), MAX_SKIPPED_KEYS);

        // The new key should be there
        assert!(skipped.contains(1, 100));
    }

    #[test]
    fn test_authenticator_mac() {
        let mut auth = Authenticator::new([1u8; KEY_SIZE]);
        auth.update(&[2u8; KEY_SIZE]);

        let header = b"test header data";
        let mac = auth.mac_header(header);

        // Verify should pass
        assert!(auth.verify_header(header, &mac));

        // Modified header should fail
        assert!(!auth.verify_header(b"wrong header data", &mac));
    }

    #[test]
    fn test_ratchet_state_creation() {
        let state = RatchetState::new(
            Direction::Initiator,
            [1u8; KEY_SIZE],
            [2u8; XWING_PUBLIC_KEY_SIZE],
            [3u8; XWING_SEED_SIZE],
            [4u8; KEY_SIZE],
        );

        assert_eq!(state.direction(), Direction::Initiator);
        assert_eq!(state.epoch(), 0);
        assert!(state.kem_ratchet_pending());
    }

    #[test]
    fn test_ratchet_state_send_recv() {
        let mut state = RatchetState::new(
            Direction::Initiator,
            [1u8; KEY_SIZE],
            [2u8; XWING_PUBLIC_KEY_SIZE],
            [3u8; XWING_SEED_SIZE],
            [4u8; KEY_SIZE],
        );

        // Get send keys
        let (key1, nonce1) = state.next_send_key();
        let (key2, nonce2) = state.next_send_key();

        // Keys should be different
        assert_ne!(key1, key2);
        assert_ne!(nonce1, nonce2);

        // Message numbers should advance
        assert_eq!(state.send_message_num(), 2);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &[1u8, 2, 3])); // Different length
    }

    #[test]
    fn test_pq_ratchet_typestate() {
        // Can create uninitialized
        let _ratchet: PqRatchet<Uninitialized> = PqRatchet::new();

        // Can create established from state
        let state = RatchetState::new(
            Direction::Initiator,
            [1u8; KEY_SIZE],
            [2u8; XWING_PUBLIC_KEY_SIZE],
            [3u8; XWING_SEED_SIZE],
            [4u8; KEY_SIZE],
        );
        let ratchet = PqRatchet::from_state(state);

        // Can access state
        assert_eq!(ratchet.state().epoch(), 0);
    }
}
