// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// PSA Storage Integration for SAGA Credentials
//
// This module provides persistent storage for SAGA anonymous credentials
// using PSA Internal Trusted Storage (ITS).
//
// # Overview
//
// SAGA credentials (Tags) can be stored persistently in encrypted flash storage,
// allowing them to survive device reboots. This is useful for:
//
// - Storing issued credentials for later use
// - Caching credentials to avoid re-issuance
// - Maintaining credential state across power cycles
//
// # Storage Strategy
//
// - **Tag (credential)**: Stored directly in ITS (392 bytes with MAX_ATTRS=8)
// - **KeyPair**: Can be stored but exceeds single ITS entry limit, requires
//   splitting or increased MAX_DATA_SIZE (1176 bytes with MAX_ATTRS=8)
//
// # UID Allocation
//
// UID allocation is left to application implementations. Applications should
// define their own UID ranges to avoid conflicts. Example:
//
// ```text
// 0x0002_0000 - 0x0002_00FF: SAGA Tags
// 0x0002_0100 - 0x0002_01FF: SAGA KeyPairs (if stored)
// ```
//
// # Example
//
// ```rust,ignore
// use dragonwing_crypto::psa::saga::{store_tag, load_tag};
// use dragonwing_crypto::psa::StorageFlags;
// use dragonwing_crypto::saga::{KeyPair, Tag};
//
// // After receiving a credential from the issuer
// let tag: Tag = keypair.mac(&mut rng, &messages)?;
//
// // Store it persistently
// store_tag(0x0002_0000, &tag, StorageFlags::NONE)?;
//
// // Later (possibly after reboot), load it back
// let loaded_tag: Tag = load_tag(0x0002_0000)?;
//
// // Use the tag for presentations
// let predicate = loaded_tag.get_predicate(&mut rng, params, pk, &messages)?;
// ```

use super::errors::{PsaError, PsaResult};
use super::its;
use super::storable::PsaStorable;
use super::types::{StorageFlags, StorageUid};

// Import SAGA types - only available when saga feature is enabled
#[cfg(feature = "saga")]
use crate::saga::{
    KeyPair, Parameters, Presentation, PublicKey, SecretKey, Tag, KEY_PAIR_SIZE, PARAMETERS_SIZE,
    PRESENTATION_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, TAG_SIZE,
};

// ============================================================================
// PsaStorable Implementations for SAGA Types
// ============================================================================

#[cfg(feature = "saga")]
impl PsaStorable for Tag {
    const SERIALIZED_SIZE: usize = TAG_SIZE;
    type Bytes = [u8; TAG_SIZE];

    fn to_psa_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self> {
        Self::from_bytes(bytes)
    }

    fn zero_bytes() -> Self::Bytes {
        [0u8; TAG_SIZE]
    }
}

#[cfg(feature = "saga")]
impl PsaStorable for Parameters {
    const SERIALIZED_SIZE: usize = PARAMETERS_SIZE;
    type Bytes = [u8; PARAMETERS_SIZE];

    fn to_psa_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self> {
        Self::from_bytes(bytes)
    }

    fn zero_bytes() -> Self::Bytes {
        [0u8; PARAMETERS_SIZE]
    }
}

#[cfg(feature = "saga")]
impl PsaStorable for SecretKey {
    const SERIALIZED_SIZE: usize = SECRET_KEY_SIZE;
    type Bytes = [u8; SECRET_KEY_SIZE];

    fn to_psa_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self> {
        Self::from_bytes(bytes)
    }

    fn zero_bytes() -> Self::Bytes {
        [0u8; SECRET_KEY_SIZE]
    }
}

#[cfg(feature = "saga")]
impl PsaStorable for PublicKey {
    const SERIALIZED_SIZE: usize = PUBLIC_KEY_SIZE;
    type Bytes = [u8; PUBLIC_KEY_SIZE];

    fn to_psa_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self> {
        Self::from_bytes(bytes)
    }

    fn zero_bytes() -> Self::Bytes {
        [0u8; PUBLIC_KEY_SIZE]
    }
}

#[cfg(feature = "saga")]
impl PsaStorable for KeyPair {
    const SERIALIZED_SIZE: usize = KEY_PAIR_SIZE;
    type Bytes = [u8; KEY_PAIR_SIZE];

    fn to_psa_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self> {
        Self::from_bytes(bytes)
    }

    fn zero_bytes() -> Self::Bytes {
        [0u8; KEY_PAIR_SIZE]
    }
}

#[cfg(feature = "saga")]
impl PsaStorable for Presentation {
    const SERIALIZED_SIZE: usize = PRESENTATION_SIZE;
    type Bytes = [u8; PRESENTATION_SIZE];

    fn to_psa_bytes(&self) -> Self::Bytes {
        self.to_bytes()
    }

    fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self> {
        Self::from_bytes(bytes)
    }

    fn zero_bytes() -> Self::Bytes {
        [0u8; PRESENTATION_SIZE]
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Store a SAGA Tag (credential) in PSA ITS.
///
/// # Arguments
///
/// * `uid` - Unique identifier for the storage entry
/// * `tag` - The credential to store
/// * `flags` - Storage flags
///
/// # Example
///
/// ```rust,ignore
/// use dragonwing_crypto::psa::saga::store_tag;
/// use dragonwing_crypto::psa::StorageFlags;
///
/// store_tag(0x0002_0000, &tag, StorageFlags::NONE)?;
/// ```
#[cfg(feature = "saga")]
pub fn store_tag(uid: StorageUid, tag: &Tag, flags: StorageFlags) -> PsaResult<()> {
    tag.psa_store(uid, flags)
}

/// Load a SAGA Tag (credential) from PSA ITS.
///
/// # Arguments
///
/// * `uid` - Unique identifier for the storage entry
///
/// # Example
///
/// ```rust,ignore
/// use dragonwing_crypto::psa::saga::load_tag;
///
/// let tag = load_tag(0x0002_0000)?;
/// ```
#[cfg(feature = "saga")]
pub fn load_tag(uid: StorageUid) -> PsaResult<Tag> {
    Tag::psa_load(uid)
}

/// Check if a SAGA Tag exists at the given UID.
#[cfg(feature = "saga")]
#[inline]
pub fn tag_exists(uid: StorageUid) -> bool {
    Tag::psa_exists(uid)
}

/// Remove a SAGA Tag from PSA ITS.
#[cfg(feature = "saga")]
#[inline]
pub fn remove_tag(uid: StorageUid) -> PsaResult<()> {
    Tag::psa_remove(uid)
}

/// Store a SAGA KeyPair in PSA ITS.
///
/// Note: KeyPair is large (1176 bytes with MAX_ATTRS=8). Ensure your
/// CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE is set appropriately.
///
/// # Arguments
///
/// * `uid` - Unique identifier for the storage entry
/// * `keypair` - The keypair to store
/// * `flags` - Storage flags (consider `WRITE_ONCE` for root keys)
#[cfg(feature = "saga")]
pub fn store_keypair(uid: StorageUid, keypair: &KeyPair, flags: StorageFlags) -> PsaResult<()> {
    keypair.psa_store(uid, flags)
}

/// Load a SAGA KeyPair from PSA ITS.
#[cfg(feature = "saga")]
pub fn load_keypair(uid: StorageUid) -> PsaResult<KeyPair> {
    KeyPair::psa_load(uid)
}

/// Check if a SAGA KeyPair exists at the given UID.
#[cfg(feature = "saga")]
#[inline]
pub fn keypair_exists(uid: StorageUid) -> bool {
    KeyPair::psa_exists(uid)
}

/// Remove a SAGA KeyPair from PSA ITS.
#[cfg(feature = "saga")]
#[inline]
pub fn remove_keypair(uid: StorageUid) -> PsaResult<()> {
    KeyPair::psa_remove(uid)
}

/// Store SAGA Parameters in PSA ITS.
///
/// Parameters are typically shared between issuer and holder, and may be
/// stored with `NO_CONFIDENTIALITY` flag since they are public.
#[cfg(feature = "saga")]
pub fn store_parameters(
    uid: StorageUid,
    params: &Parameters,
    flags: StorageFlags,
) -> PsaResult<()> {
    params.psa_store(uid, flags)
}

/// Load SAGA Parameters from PSA ITS.
#[cfg(feature = "saga")]
pub fn load_parameters(uid: StorageUid) -> PsaResult<Parameters> {
    Parameters::psa_load(uid)
}

/// Store a SAGA PublicKey in PSA ITS.
///
/// Public keys can be stored with `NO_CONFIDENTIALITY` flag.
#[cfg(feature = "saga")]
pub fn store_public_key(uid: StorageUid, pk: &PublicKey, flags: StorageFlags) -> PsaResult<()> {
    pk.psa_store(uid, flags)
}

/// Load a SAGA PublicKey from PSA ITS.
#[cfg(feature = "saga")]
pub fn load_public_key(uid: StorageUid) -> PsaResult<PublicKey> {
    PublicKey::psa_load(uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "saga")]
    #[test]
    fn test_tag_size() {
        // Verify Tag fits within ITS limits
        assert!(TAG_SIZE <= its::MAX_DATA_SIZE, "Tag too large for ITS");
    }

    #[cfg(feature = "saga")]
    #[test]
    fn test_keypair_size() {
        // KeyPair is large but should fit with increased MAX_DATA_SIZE
        assert!(
            KEY_PAIR_SIZE <= 1280,
            "KeyPair exceeds recommended MAX_DATA_SIZE"
        );
    }
}
