// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// PSA Storage Integration for X-Wing Post-Quantum Keys
//
// This module provides persistent storage for X-Wing hybrid PQ-KEM keys
// using PSA Internal Trusted Storage (ITS).
//
// # Overview
//
// X-Wing keys can be stored persistently in encrypted flash storage,
// allowing them to survive device reboots. This is useful for:
//
// - Long-term key exchange scenarios
// - Pre-provisioned device identity keys
// - Quantum-resistant communication channels
//
// # Storage Strategy
//
// - **Seed (32 bytes)**: Store only the seed, regenerate keys on load
//   - Minimal storage footprint
//   - Keys are deterministically derived from seed
//   - Seed should be stored with full confidentiality
//
// - **PublicKey (1216 bytes)**: Store separately if needed for verification
//   - Large but fits within increased ITS limit (1280 bytes)
//   - Can be stored with `NO_CONFIDENTIALITY` flag
//
// - **Ciphertext (1120 bytes)**: Temporary, typically not stored persistently
//   - Can be stored if needed for deferred decapsulation
//
// # UID Allocation
//
// UID allocation is left to application implementations. Example:
//
// ```text
// 0x0003_0000 - 0x0003_00FF: X-Wing seeds
// 0x0003_0100 - 0x0003_01FF: X-Wing public keys (if caching)
// ```
//
// # Example
//
// ```rust,ignore
// use dragonwing_crypto::psa::xwing::{store_seed, load_keypair};
// use dragonwing_crypto::psa::StorageFlags;
// use dragonwing_crypto::xwing::SecretKey;
//
// // Generate a new keypair
// let seed: [u8; 32] = rng.random_array();
// let secret_key = SecretKey::from_seed(&seed);
//
// // Store the seed persistently
// store_seed(0x0003_0000, &seed, StorageFlags::NONE)?;
//
// // Later (possibly after reboot), regenerate keypair from seed
// let (secret_key, public_key) = load_keypair(0x0003_0000)?;
//
// // Use for key exchange
// let shared_secret = secret_key.decapsulate(&ciphertext);
// ```

use super::errors::{PsaError, PsaResult};
use super::its;
use super::storable::PsaStorable;
use super::types::{StorageFlags, StorageUid};

// Import X-Wing types - only available when xwing feature is enabled
#[cfg(feature = "xwing")]
use crate::post_quantum::xwing:::{
    Ciphertext, PublicKey, SecretKey, SharedSecret, CIPHERTEXT_SIZE, PUBLIC_KEY_SIZE,
    SECRET_KEY_SIZE, SHARED_SECRET_SIZE,
};

// ============================================================================
// PsaStorable Implementations for X-Wing Types
// ============================================================================

/// Wrapper for X-Wing seed to enable PsaStorable implementation.
///
/// Since SecretKey cannot be directly serialized (it contains expanded keys),
/// we store the 32-byte seed instead and regenerate the full key on load.
#[cfg(feature = "xwing")]
#[derive(Clone, Copy)]
pub struct StorableSeed {
    /// The 32-byte seed
    pub seed: [u8; SECRET_KEY_SIZE],
}

#[cfg(feature = "xwing")]
impl StorableSeed {
    /// Create a new storable seed.
    pub fn new(seed: [u8; SECRET_KEY_SIZE]) -> Self {
        Self { seed }
    }

    /// Get the seed bytes.
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.seed
    }

    /// Generate a SecretKey from this seed.
    pub fn to_secret_key(&self) -> SecretKey {
        SecretKey::from_seed(&self.seed)
    }
}

#[cfg(feature = "xwing")]
impl PsaStorable for StorableSeed {
    const SERIALIZED_SIZE: usize = SECRET_KEY_SIZE;
    type Bytes = [u8; SECRET_KEY_SIZE];

    fn to_psa_bytes(&self) -> Self::Bytes {
        self.seed
    }

    fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self> {
        Some(Self { seed: *bytes })
    }

    fn zero_bytes() -> Self::Bytes {
        [0u8; SECRET_KEY_SIZE]
    }
}

#[cfg(feature = "xwing")]
impl PsaStorable for PublicKey {
    const SERIALIZED_SIZE: usize = PUBLIC_KEY_SIZE;
    type Bytes = [u8; PUBLIC_KEY_SIZE];

    fn to_psa_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self> {
        Some(Self::from_bytes(bytes))
    }

    fn zero_bytes() -> Self::Bytes {
        [0u8; PUBLIC_KEY_SIZE]
    }
}

#[cfg(feature = "xwing")]
impl PsaStorable for Ciphertext {
    const SERIALIZED_SIZE: usize = CIPHERTEXT_SIZE;
    type Bytes = [u8; CIPHERTEXT_SIZE];

    fn to_psa_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self> {
        Some(Self::from_bytes(bytes))
    }

    fn zero_bytes() -> Self::Bytes {
        [0u8; CIPHERTEXT_SIZE]
    }
}

#[cfg(feature = "xwing")]
impl PsaStorable for SharedSecret {
    const SERIALIZED_SIZE: usize = SHARED_SECRET_SIZE;
    type Bytes = [u8; SHARED_SECRET_SIZE];

    fn to_psa_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self> {
        Some(Self::from_bytes(bytes))
    }

    fn zero_bytes() -> Self::Bytes {
        [0u8; SHARED_SECRET_SIZE]
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Store an X-Wing seed in PSA ITS.
///
/// The seed is the canonical way to persist X-Wing keys - the full
/// SecretKey can be deterministically regenerated from the seed.
///
/// # Arguments
///
/// * `uid` - Unique identifier for the storage entry
/// * `seed` - The 32-byte seed to store
/// * `flags` - Storage flags (consider `WRITE_ONCE` for root identity keys)
///
/// # Security
///
/// Seeds should be stored with full confidentiality (default flags).
/// Never use `NO_CONFIDENTIALITY` for seed storage.
///
/// # Example
///
/// ```rust,ignore
/// use dragonwing_crypto::psa::xwing::store_seed;
/// use dragonwing_crypto::psa::StorageFlags;
///
/// let seed: [u8; 32] = rng.random_array();
/// store_seed(0x0003_0000, &seed, StorageFlags::NONE)?;
/// ```
#[cfg(feature = "xwing")]
pub fn store_seed(
    uid: StorageUid,
    seed: &[u8; SECRET_KEY_SIZE],
    flags: StorageFlags,
) -> PsaResult<()> {
    let storable = StorableSeed::new(*seed);
    storable.psa_store(uid, flags)
}

/// Load an X-Wing seed from PSA ITS.
///
/// # Arguments
///
/// * `uid` - Unique identifier for the storage entry
///
/// # Returns
///
/// The 32-byte seed.
#[cfg(feature = "xwing")]
pub fn load_seed(uid: StorageUid) -> PsaResult<[u8; SECRET_KEY_SIZE]> {
    let storable = StorableSeed::psa_load(uid)?;
    Ok(storable.seed)
}

/// Load an X-Wing keypair from a stored seed.
///
/// This loads the seed from storage and regenerates the full keypair.
///
/// # Arguments
///
/// * `uid` - Unique identifier for the stored seed
///
/// # Returns
///
/// A tuple of (SecretKey, PublicKey) regenerated from the seed.
///
/// # Example
///
/// ```rust,ignore
/// use dragonwing_crypto::psa::xwing::load_keypair;
///
/// let (secret_key, public_key) = load_keypair(0x0003_0000)?;
/// let shared_secret = secret_key.decapsulate(&ciphertext);
/// ```
#[cfg(feature = "xwing")]
pub fn load_keypair(uid: StorageUid) -> PsaResult<(SecretKey, PublicKey)> {
    let seed = load_seed(uid)?;
    let secret_key = SecretKey::from_seed(&seed);
    let public_key = secret_key.public_key().clone();
    Ok((secret_key, public_key))
}

/// Check if an X-Wing seed exists at the given UID.
#[cfg(feature = "xwing")]
#[inline]
pub fn seed_exists(uid: StorageUid) -> bool {
    StorableSeed::psa_exists(uid)
}

/// Remove an X-Wing seed from PSA ITS.
#[cfg(feature = "xwing")]
#[inline]
pub fn remove_seed(uid: StorageUid) -> PsaResult<()> {
    StorableSeed::psa_remove(uid)
}

/// Store an X-Wing public key in PSA ITS.
///
/// Public keys are large (1216 bytes) but may be cached if frequently needed.
/// They can be stored with `NO_CONFIDENTIALITY` since they are public.
///
/// # Arguments
///
/// * `uid` - Unique identifier for the storage entry
/// * `pk` - The public key to store
/// * `flags` - Storage flags (can use `NO_CONFIDENTIALITY`)
#[cfg(feature = "xwing")]
pub fn store_public_key(uid: StorageUid, pk: &PublicKey, flags: StorageFlags) -> PsaResult<()> {
    pk.psa_store(uid, flags)
}

/// Load an X-Wing public key from PSA ITS.
#[cfg(feature = "xwing")]
pub fn load_public_key(uid: StorageUid) -> PsaResult<PublicKey> {
    PublicKey::psa_load(uid)
}

/// Check if an X-Wing public key exists at the given UID.
#[cfg(feature = "xwing")]
#[inline]
pub fn public_key_exists(uid: StorageUid) -> bool {
    PublicKey::psa_exists(uid)
}

/// Remove an X-Wing public key from PSA ITS.
#[cfg(feature = "xwing")]
#[inline]
pub fn remove_public_key(uid: StorageUid) -> PsaResult<()> {
    PublicKey::psa_remove(uid)
}

/// Store an X-Wing ciphertext in PSA ITS.
///
/// Ciphertexts are typically ephemeral, but can be stored if needed
/// for deferred decapsulation scenarios.
#[cfg(feature = "xwing")]
pub fn store_ciphertext(uid: StorageUid, ct: &Ciphertext, flags: StorageFlags) -> PsaResult<()> {
    ct.psa_store(uid, flags)
}

/// Load an X-Wing ciphertext from PSA ITS.
#[cfg(feature = "xwing")]
pub fn load_ciphertext(uid: StorageUid) -> PsaResult<Ciphertext> {
    Ciphertext::psa_load(uid)
}

/// Store an X-Wing shared secret in PSA ITS.
///
/// Shared secrets should be stored with full confidentiality.
/// Consider if persistent storage is appropriate for your security model.
#[cfg(feature = "xwing")]
pub fn store_shared_secret(
    uid: StorageUid,
    ss: &SharedSecret,
    flags: StorageFlags,
) -> PsaResult<()> {
    ss.psa_store(uid, flags)
}

/// Load an X-Wing shared secret from PSA ITS.
#[cfg(feature = "xwing")]
pub fn load_shared_secret(uid: StorageUid) -> PsaResult<SharedSecret> {
    SharedSecret::psa_load(uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "xwing")]
    #[test]
    fn test_seed_size() {
        // Verify seed fits within ITS limits
        assert!(
            SECRET_KEY_SIZE <= its::MAX_DATA_SIZE,
            "Seed too large for ITS"
        );
    }

    #[cfg(feature = "xwing")]
    #[test]
    fn test_public_key_size() {
        // Verify public key fits with increased MAX_DATA_SIZE
        assert!(
            PUBLIC_KEY_SIZE <= 1280,
            "PublicKey exceeds MAX_DATA_SIZE of 1280"
        );
    }

    #[cfg(feature = "xwing")]
    #[test]
    fn test_ciphertext_size() {
        // Verify ciphertext fits with increased MAX_DATA_SIZE
        assert!(
            CIPHERTEXT_SIZE <= 1280,
            "Ciphertext exceeds MAX_DATA_SIZE of 1280"
        );
    }
}
