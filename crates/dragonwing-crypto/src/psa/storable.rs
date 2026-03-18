// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// PSA Storable Trait
//
// This module defines a trait for types that can be stored in PSA ITS.
// It provides a uniform interface for serialization and storage operations.

use super::errors::{PsaError, PsaResult};
use super::its;
use super::types::{StorageFlags, StorageUid};

/// Trait for types that can be stored in PSA Internal Trusted Storage.
///
/// Implementors must provide serialization/deserialization and define their
/// serialized size. The trait provides default implementations for storage
/// operations using the [`its`] module.
///
/// # Example Implementation
///
/// ```rust,ignore
/// use dragonwing_crypto::psa::{PsaStorable, PsaError};
///
/// struct MyCredential {
///     data: [u8; 64],
/// }
///
/// impl PsaStorable for MyCredential {
///     const SERIALIZED_SIZE: usize = 64;
///     type Bytes = [u8; 64];
///
///     fn to_psa_bytes(&self) -> Self::Bytes {
///         self.data
///     }
///
///     fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self> {
///         Some(Self { data: *bytes })
///     }
///
///     fn zero_bytes() -> Self::Bytes {
///         [0u8; 64]
///     }
/// }
/// ```
pub trait PsaStorable: Sized {
    /// The size of the serialized representation in bytes.
    const SERIALIZED_SIZE: usize;

    /// The byte array type for serialization.
    /// Must be `[u8; Self::SERIALIZED_SIZE]`.
    type Bytes: AsRef<[u8]> + AsMut<[u8]> + Copy;

    /// Serialize the value to bytes.
    fn to_psa_bytes(&self) -> Self::Bytes;

    /// Deserialize the value from bytes.
    /// Returns `None` if deserialization fails (e.g., invalid encoding).
    fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self>;

    /// Create a zero-initialized byte array.
    /// This is needed because `Default` is not implemented for large arrays.
    fn zero_bytes() -> Self::Bytes;

    /// Store this value in PSA ITS at the given UID.
    ///
    /// # Arguments
    ///
    /// * `uid` - Unique identifier for the storage entry
    /// * `flags` - Storage flags (e.g., `WRITE_ONCE` for immutable data)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dragonwing_crypto::psa::{PsaStorable, StorageFlags};
    ///
    /// let credential = MyCredential::new();
    /// credential.psa_store(0x2000, StorageFlags::NONE)?;
    /// ```
    fn psa_store(&self, uid: StorageUid, flags: StorageFlags) -> PsaResult<()> {
        let bytes = self.to_psa_bytes();
        its::set(uid, bytes.as_ref(), flags)
    }

    /// Load a value from PSA ITS at the given UID.
    ///
    /// # Arguments
    ///
    /// * `uid` - Unique identifier for the storage entry
    ///
    /// # Errors
    ///
    /// * `DoesNotExist` - No entry with this UID
    /// * `DataCorrupt` - Stored data has wrong size or invalid encoding
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use dragonwing_crypto::psa::PsaStorable;
    ///
    /// let credential: MyCredential = MyCredential::psa_load(0x2000)?;
    /// ```
    fn psa_load(uid: StorageUid) -> PsaResult<Self> {
        // Check size first
        let info = its::get_info(uid)?;
        if info.size != Self::SERIALIZED_SIZE {
            return Err(PsaError::DataCorrupt);
        }

        // Load into appropriately sized buffer
        let mut bytes = Self::zero_bytes();
        let len = its::get(uid, 0, bytes.as_mut())?;

        if len != Self::SERIALIZED_SIZE {
            return Err(PsaError::DataCorrupt);
        }

        Self::from_psa_bytes(&bytes).ok_or(PsaError::DataCorrupt)
    }

    /// Check if a value exists at the given UID.
    #[inline]
    fn psa_exists(uid: StorageUid) -> bool {
        its::exists(uid)
    }

    /// Remove a value from PSA ITS at the given UID.
    #[inline]
    fn psa_remove(uid: StorageUid) -> PsaResult<()> {
        its::remove(uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test implementation
    struct TestData {
        value: [u8; 32],
    }

    impl PsaStorable for TestData {
        const SERIALIZED_SIZE: usize = 32;
        type Bytes = [u8; 32];

        fn to_psa_bytes(&self) -> Self::Bytes {
            self.value
        }

        fn from_psa_bytes(bytes: &Self::Bytes) -> Option<Self> {
            Some(Self { value: *bytes })
        }

        fn zero_bytes() -> Self::Bytes {
            [0u8; 32]
        }
    }

    #[test]
    fn test_serialized_size() {
        assert_eq!(TestData::SERIALIZED_SIZE, 32);
    }
}
