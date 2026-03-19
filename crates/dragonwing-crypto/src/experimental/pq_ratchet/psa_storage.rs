// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! PSA Storage Integration for PQ-Ratchet State
//!
//! This module provides persistent storage for PQ-Ratchet state using
//! PSA Internal Trusted Storage (ITS). This enables the MCU to persist
//! ratchet state across power cycles in TrustZone-protected storage.
//!
//! # Overview
//!
//! The ratchet state (3692 bytes) is stored as a single ITS entry containing:
//! - Root key and chain keys
//! - Epoch and message counters
//! - Peer's X-Wing public key
//! - Authenticator state
//! - Skipped message keys for out-of-order handling
//!
//! # Storage Strategy
//!
//! To minimize flash wear (following PQC-IIoT lazy persistence pattern):
//! - State is NOT written on every message
//! - Flush triggers: every N messages, time interval, or explicit request
//! - Use double-buffering for atomic updates
//!
//! # UID Allocation
//!
//! Recommended UID ranges (application should define):
//! ```text
//! 0x0003_0000 - 0x0003_00FF: PQ-Ratchet States (up to 256 sessions)
//! 0x0003_0100 - 0x0003_01FF: PQ-Ratchet Metadata
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use dragonwing_crypto::experimental::pq_ratchet::psa_storage::*;
//! use dragonwing_crypto::psa::StorageFlags;
//!
//! // After establishing a ratchet session
//! store_ratchet_state(UID_RATCHET_STATE_PRIMARY, &state, StorageFlags::NONE)?;
//!
//! // After reboot, restore state
//! let state = load_ratchet_state(UID_RATCHET_STATE_PRIMARY)?;
//! let ratchet = PqRatchet::from_state(state);
//! ```

use super::serialize::RATCHET_STATE_SIZE;
use super::state::RatchetState;

// Re-export for convenience (use public re-exports from psa module)
#[cfg(feature = "psa")]
pub use crate::psa::{PsaError, PsaResult, PsaStorable, StorageFlags, StorageUid};

// ============================================================================
// Suggested UID Constants
// ============================================================================

/// Base UID for PQ-Ratchet state storage
pub const UID_RATCHET_BASE: u32 = 0x0003_0000;

/// Primary ratchet state (main session)
pub const UID_RATCHET_STATE_PRIMARY: u32 = UID_RATCHET_BASE;

/// Backup ratchet state (for atomic updates via double-buffering)
pub const UID_RATCHET_STATE_BACKUP: u32 = UID_RATCHET_BASE + 1;

/// Ratchet metadata (flush counter, last flush time, etc.)
pub const UID_RATCHET_METADATA: u32 = UID_RATCHET_BASE + 0x100;

// ============================================================================
// Lazy Persistence Configuration
// ============================================================================

/// Configuration for lazy persistence (to minimize flash wear)
#[derive(Debug, Clone, Copy)]
pub struct PersistenceConfig {
    /// Flush state after this many messages
    pub flush_interval_messages: u32,
    /// Flush state after this many seconds (0 = disabled)
    pub flush_interval_seconds: u32,
    /// Always flush on epoch change (KEM ratchet)
    pub flush_on_epoch_change: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            flush_interval_messages: 50,
            flush_interval_seconds: 60,
            flush_on_epoch_change: true,
        }
    }
}

/// Metadata stored alongside ratchet state for persistence tracking
#[derive(Debug, Clone, Copy)]
pub struct RatchetMetadata {
    /// Number of messages since last flush
    pub messages_since_flush: u32,
    /// Last flush timestamp (seconds since boot or epoch)
    pub last_flush_time: u32,
    /// Last persisted epoch
    pub last_epoch: u64,
    /// Which buffer is currently active (0 = primary, 1 = backup)
    pub active_buffer: u8,
    /// Reserved for future use
    pub _reserved: [u8; 7],
}

impl RatchetMetadata {
    /// Size of serialized metadata
    pub const SIZE: usize = 4 + 4 + 8 + 1 + 7; // 24 bytes

    /// Create new metadata
    pub fn new() -> Self {
        Self {
            messages_since_flush: 0,
            last_flush_time: 0,
            last_epoch: 0,
            active_buffer: 0,
            _reserved: [0; 7],
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.messages_since_flush.to_be_bytes());
        buf[4..8].copy_from_slice(&self.last_flush_time.to_be_bytes());
        buf[8..16].copy_from_slice(&self.last_epoch.to_be_bytes());
        buf[16] = self.active_buffer;
        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        Self {
            messages_since_flush: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            last_flush_time: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            last_epoch: u64::from_be_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]),
            active_buffer: bytes[16],
            _reserved: [0; 7],
        }
    }

    /// Check if flush is needed based on configuration
    pub fn needs_flush(&self, config: &PersistenceConfig, current_epoch: u64) -> bool {
        // Check message count
        if self.messages_since_flush >= config.flush_interval_messages {
            return true;
        }

        // Check epoch change
        if config.flush_on_epoch_change && current_epoch != self.last_epoch {
            return true;
        }

        // Note: Time-based flushing requires external timestamp comparison
        false
    }
}

impl Default for RatchetMetadata {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PSA Storage Functions (require "psa" feature)
// ============================================================================

/// Store a PQ-Ratchet state in PSA ITS.
///
/// # Arguments
///
/// * `uid` - Unique identifier for the storage entry
/// * `state` - The ratchet state to store
/// * `flags` - Storage flags
///
/// # Example
///
/// ```rust,ignore
/// use dragonwing_crypto::experimental::pq_ratchet::psa_storage::*;
///
/// store_ratchet_state(UID_RATCHET_STATE_PRIMARY, &state, StorageFlags::NONE)?;
/// ```
#[cfg(feature = "psa")]
pub fn store_ratchet_state(
    uid: StorageUid,
    state: &RatchetState,
    flags: StorageFlags,
) -> PsaResult<()> {
    state.psa_store(uid, flags)
}

/// Load a PQ-Ratchet state from PSA ITS.
///
/// # Arguments
///
/// * `uid` - Unique identifier for the storage entry
///
/// # Example
///
/// ```rust,ignore
/// use dragonwing_crypto::experimental::pq_ratchet::psa_storage::*;
///
/// let state = load_ratchet_state(UID_RATCHET_STATE_PRIMARY)?;
/// ```
#[cfg(feature = "psa")]
pub fn load_ratchet_state(uid: StorageUid) -> PsaResult<RatchetState> {
    RatchetState::psa_load(uid)
}

/// Check if a ratchet state exists at the given UID.
#[cfg(feature = "psa")]
#[inline]
pub fn ratchet_state_exists(uid: StorageUid) -> bool {
    RatchetState::psa_exists(uid)
}

/// Remove a ratchet state from PSA ITS.
#[cfg(feature = "psa")]
#[inline]
pub fn remove_ratchet_state(uid: StorageUid) -> PsaResult<()> {
    RatchetState::psa_remove(uid)
}

/// Store ratchet metadata in PSA ITS.
#[cfg(feature = "psa")]
pub fn store_metadata(
    uid: StorageUid,
    metadata: &RatchetMetadata,
    flags: StorageFlags,
) -> PsaResult<()> {
    crate::psa::its::set(uid, &metadata.to_bytes(), flags)
}

/// Load ratchet metadata from PSA ITS.
#[cfg(feature = "psa")]
pub fn load_metadata(uid: StorageUid) -> PsaResult<RatchetMetadata> {
    let bytes: [u8; RatchetMetadata::SIZE] = crate::psa::its::load(uid)?;
    Ok(RatchetMetadata::from_bytes(&bytes))
}

// ============================================================================
// Double-Buffered Atomic Storage
// ============================================================================

/// Atomically store ratchet state using double-buffering.
///
/// This ensures that a valid state is always available even if power
/// is lost during a write operation.
///
/// # Algorithm
///
/// 1. Read current metadata to find active buffer
/// 2. Write new state to inactive buffer
/// 3. Update metadata to point to new buffer
///
/// If power is lost between steps 2 and 3, the old state remains valid.
///
/// # Example
///
/// ```rust,ignore
/// atomic_store_ratchet_state(&state)?;
/// ```
#[cfg(feature = "psa")]
pub fn atomic_store_ratchet_state(state: &RatchetState) -> PsaResult<()> {
    // Load or create metadata
    let mut metadata = load_metadata(UID_RATCHET_METADATA).unwrap_or_default();

    // Determine which buffer to write to (opposite of current active)
    let write_uid = if metadata.active_buffer == 0 {
        UID_RATCHET_STATE_BACKUP
    } else {
        UID_RATCHET_STATE_PRIMARY
    };

    // Write state to inactive buffer
    store_ratchet_state(write_uid, state, StorageFlags::NONE)?;

    // Update metadata to point to new buffer
    metadata.active_buffer = if metadata.active_buffer == 0 { 1 } else { 0 };
    metadata.messages_since_flush = 0;
    metadata.last_epoch = state.epoch();

    store_metadata(UID_RATCHET_METADATA, &metadata, StorageFlags::NONE)?;

    Ok(())
}

/// Load ratchet state from the currently active buffer.
///
/// This handles the double-buffering scheme by checking metadata
/// to determine which buffer contains the valid state.
#[cfg(feature = "psa")]
pub fn atomic_load_ratchet_state() -> PsaResult<RatchetState> {
    // Try to load metadata
    let metadata = load_metadata(UID_RATCHET_METADATA);

    let uid = match metadata {
        Ok(m) => {
            if m.active_buffer == 0 {
                UID_RATCHET_STATE_PRIMARY
            } else {
                UID_RATCHET_STATE_BACKUP
            }
        }
        Err(_) => {
            // No metadata, try primary first
            UID_RATCHET_STATE_PRIMARY
        }
    };

    // Try to load from determined buffer
    match load_ratchet_state(uid) {
        Ok(state) => Ok(state),
        Err(_) => {
            // Fall back to other buffer
            let fallback_uid = if uid == UID_RATCHET_STATE_PRIMARY {
                UID_RATCHET_STATE_BACKUP
            } else {
                UID_RATCHET_STATE_PRIMARY
            };
            load_ratchet_state(fallback_uid)
        }
    }
}

// ============================================================================
// Lazy Persistence Manager
// ============================================================================

/// Manager for lazy persistence of ratchet state.
///
/// Tracks message counts and decides when to flush state to storage,
/// minimizing flash wear while ensuring state is not lost.
pub struct LazyPersistence {
    /// Configuration for flush triggers
    pub config: PersistenceConfig,
    /// Current metadata
    metadata: RatchetMetadata,
    /// Whether state has been modified since last flush
    dirty: bool,
}

impl LazyPersistence {
    /// Create a new lazy persistence manager
    pub fn new(config: PersistenceConfig) -> Self {
        Self {
            config,
            metadata: RatchetMetadata::new(),
            dirty: false,
        }
    }

    /// Load existing metadata from storage (if available)
    #[cfg(feature = "psa")]
    pub fn load_metadata(&mut self) -> PsaResult<()> {
        self.metadata = load_metadata(UID_RATCHET_METADATA)?;
        self.dirty = false;
        Ok(())
    }

    /// Record that a message was processed
    ///
    /// Returns true if state should be flushed
    pub fn record_message(&mut self, current_epoch: u64) -> bool {
        self.metadata.messages_since_flush += 1;
        self.dirty = true;

        self.metadata.needs_flush(&self.config, current_epoch)
    }

    /// Record that time has passed
    ///
    /// Returns true if state should be flushed
    pub fn check_time_flush(&self, current_time: u32) -> bool {
        if self.config.flush_interval_seconds == 0 {
            return false;
        }

        current_time.saturating_sub(self.metadata.last_flush_time)
            >= self.config.flush_interval_seconds
    }

    /// Flush state to storage
    #[cfg(feature = "psa")]
    pub fn flush(&mut self, state: &RatchetState, current_time: u32) -> PsaResult<()> {
        atomic_store_ratchet_state(state)?;

        self.metadata.messages_since_flush = 0;
        self.metadata.last_flush_time = current_time;
        self.metadata.last_epoch = state.epoch();
        self.dirty = false;

        Ok(())
    }

    /// Check if there are unflushed changes
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Get current metadata
    pub fn metadata(&self) -> &RatchetMetadata {
        &self.metadata
    }
}

impl Default for LazyPersistence {
    fn default() -> Self {
        Self::new(PersistenceConfig::default())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_serialization() {
        let metadata = RatchetMetadata {
            messages_since_flush: 42,
            last_flush_time: 1234567,
            last_epoch: 99,
            active_buffer: 1,
            _reserved: [0; 7],
        };

        let bytes = metadata.to_bytes();
        let restored = RatchetMetadata::from_bytes(&bytes);

        assert_eq!(restored.messages_since_flush, 42);
        assert_eq!(restored.last_flush_time, 1234567);
        assert_eq!(restored.last_epoch, 99);
        assert_eq!(restored.active_buffer, 1);
    }

    #[test]
    fn test_metadata_needs_flush() {
        let config = PersistenceConfig {
            flush_interval_messages: 50,
            flush_interval_seconds: 60,
            flush_on_epoch_change: true,
        };

        // Not yet needing flush
        let metadata = RatchetMetadata {
            messages_since_flush: 10,
            last_epoch: 5,
            ..Default::default()
        };
        assert!(!metadata.needs_flush(&config, 5));

        // Message count exceeded
        let metadata2 = RatchetMetadata {
            messages_since_flush: 50,
            last_epoch: 5,
            ..Default::default()
        };
        assert!(metadata2.needs_flush(&config, 5));

        // Epoch changed
        let metadata3 = RatchetMetadata {
            messages_since_flush: 10,
            last_epoch: 5,
            ..Default::default()
        };
        assert!(metadata3.needs_flush(&config, 6));
    }

    #[test]
    fn test_lazy_persistence_record() {
        let config = PersistenceConfig {
            flush_interval_messages: 5,
            flush_interval_seconds: 0,
            flush_on_epoch_change: false,
        };
        let mut persistence = LazyPersistence::new(config);

        // Record messages, should not need flush until 5th
        assert!(!persistence.record_message(0));
        assert!(!persistence.record_message(0));
        assert!(!persistence.record_message(0));
        assert!(!persistence.record_message(0));
        assert!(persistence.record_message(0)); // 5th message triggers flush
        assert!(persistence.is_dirty());
    }

    #[test]
    fn test_persistence_config_default() {
        let config = PersistenceConfig::default();
        assert_eq!(config.flush_interval_messages, 50);
        assert_eq!(config.flush_interval_seconds, 60);
        assert!(config.flush_on_epoch_change);
    }

    #[test]
    fn test_ratchet_state_size_fits_its() {
        // ITS typically has 4KB limit, our state is 3692 bytes
        assert!(RATCHET_STATE_SIZE < 4096);
        assert_eq!(RATCHET_STATE_SIZE, 3692);
    }
}
