// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// PSA Internal Trusted Storage (ITS) API
//
// This module provides Rust bindings to the PSA Internal Trusted Storage API,
// which allows storing and retrieving small pieces of data securely.
//
// The ITS is designed for storing:
// - Cryptographic keys
// - Credentials and certificates
// - Configuration data that requires integrity/confidentiality
//
// # Features
//
// - Data is encrypted at rest (when transform module is configured)
// - Integrity protection via AEAD authentication tag
// - Persistent storage across reboots
// - Write-once support for immutable data
//
// # Setup Requirements
//
// Add to your `prj.conf`:
// ```
// CONFIG_SECURE_STORAGE=y
// CONFIG_SECURE_STORAGE_ITS_IMPLEMENTATION_ZEPHYR=y
// CONFIG_SECURE_STORAGE_ITS_TRANSFORM_IMPLEMENTATION_AEAD=y
// CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_SETTINGS=y
// CONFIG_SETTINGS=y
// CONFIG_NVS=y
// CONFIG_FLASH=y
// CONFIG_FLASH_MAP=y
// CONFIG_MBEDTLS=y
// CONFIG_MBEDTLS_PSA_CRYPTO_C=y
// ```
//
// # Example
//
// ```rust,no_run
// use dragonwing_crypto::psa::its;
// use dragonwing_crypto::psa::{StorageUid, StorageFlags};
//
// // Store some data
// let uid: StorageUid = 0x1000;
// let secret = b"my-secret-key-material";
// its::set(uid, secret, StorageFlags::NONE).unwrap();
//
// // Retrieve it later
// let mut buffer = [0u8; 32];
// let len = its::get(uid, 0, &mut buffer).unwrap();
// assert_eq!(&buffer[..len], secret);
//
// // Clean up
// its::remove(uid).unwrap();
// ```

use super::errors::{PsaError, PsaResult};
use super::types::{StorageFlags, StorageInfo, StorageUid};

/// Maximum data size for ITS entries (configurable via CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE)
/// X-Wing public key (1216 bytes) is the largest item we need to store.
/// Set to 1280 to provide headroom. Must match CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE.
pub const MAX_DATA_SIZE: usize = 1280;

/// FFI bindings to the C PSA ITS wrapper
mod ffi {
    use core::ffi::c_int;

    #[repr(C)]
    pub struct PsaStorageInfo {
        pub capacity: usize,
        pub size: usize,
        pub flags: u32,
    }

    extern "C" {
        /// Store data in ITS
        pub fn psa_its_set_wrapper(
            uid: u32,
            data_length: usize,
            p_data: *const u8,
            create_flags: u32,
        ) -> c_int;

        /// Retrieve data from ITS
        pub fn psa_its_get_wrapper(
            uid: u32,
            data_offset: usize,
            data_size: usize,
            p_data: *mut u8,
            p_data_length: *mut usize,
        ) -> c_int;

        /// Get info about an ITS entry
        pub fn psa_its_get_info_wrapper(uid: u32, p_info: *mut PsaStorageInfo) -> c_int;

        /// Remove an entry from ITS
        pub fn psa_its_remove_wrapper(uid: u32) -> c_int;
    }
}

/// Store data in the Internal Trusted Storage.
///
/// Creates a new entry or replaces an existing entry with the specified UID.
/// The data is encrypted and authenticated before being written to flash.
///
/// # Arguments
///
/// * `uid` - Unique identifier for the entry (must be nonzero)
/// * `data` - The data to store
/// * `flags` - Storage flags (e.g., `WRITE_ONCE` for immutable data)
///
/// # Errors
///
/// * `NotPermitted` - Entry exists and was created with `WRITE_ONCE`
/// * `NotSupported` - Invalid flags
/// * `InvalidArgument` - Invalid UID or data
/// * `InsufficientStorage` - Not enough space in storage
/// * `StorageFailure` - Flash write failed
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::its;
/// use dragonwing_crypto::psa::{StorageFlags};
///
/// // Store a mutable entry
/// its::set(0x1000, b"my-data", StorageFlags::NONE)?;
///
/// // Store an immutable entry
/// its::set(0x1001, b"root-key", StorageFlags::WRITE_ONCE)?;
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
pub fn set(uid: StorageUid, data: &[u8], flags: StorageFlags) -> PsaResult<()> {
    if uid == 0 {
        return Err(PsaError::InvalidArgument);
    }
    if data.len() > MAX_DATA_SIZE {
        return Err(PsaError::InvalidArgument);
    }

    let status = unsafe { ffi::psa_its_set_wrapper(uid, data.len(), data.as_ptr(), flags.0) };

    PsaError::from_status(status)
}

/// Retrieve data from the Internal Trusted Storage.
///
/// Reads data from the entry with the specified UID into the provided buffer.
/// The data is authenticated and decrypted before being returned.
///
/// # Arguments
///
/// * `uid` - Unique identifier for the entry
/// * `offset` - Byte offset to start reading from
/// * `buffer` - Buffer to read data into
///
/// # Returns
///
/// The number of bytes read on success.
///
/// # Errors
///
/// * `InvalidArgument` - Invalid UID or offset > entry size
/// * `DoesNotExist` - No entry with this UID
/// * `StorageFailure` - Flash read failed
/// * `InvalidSignature` - Data authentication failed (corrupt or tampered)
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::its;
///
/// let mut buffer = [0u8; 128];
/// let len = its::get(0x1000, 0, &mut buffer)?;
/// println!("Read {} bytes", len);
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
pub fn get(uid: StorageUid, offset: usize, buffer: &mut [u8]) -> PsaResult<usize> {
    if uid == 0 {
        return Err(PsaError::InvalidArgument);
    }

    let mut data_length: usize = 0;

    let status = unsafe {
        ffi::psa_its_get_wrapper(
            uid,
            offset,
            buffer.len(),
            buffer.as_mut_ptr(),
            &mut data_length,
        )
    };

    PsaError::from_status(status)?;
    Ok(data_length)
}

/// Get metadata about an ITS entry.
///
/// Returns information about the entry without reading its data.
///
/// # Arguments
///
/// * `uid` - Unique identifier for the entry
///
/// # Returns
///
/// Metadata including capacity, size, and flags.
///
/// # Errors
///
/// * `InvalidArgument` - Invalid UID
/// * `DoesNotExist` - No entry with this UID
/// * `StorageFailure` - Storage access failed
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::its;
///
/// let info = its::get_info(0x1000)?;
/// println!("Entry size: {} bytes, flags: 0x{:x}", info.size, info.flags.0);
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
pub fn get_info(uid: StorageUid) -> PsaResult<StorageInfo> {
    if uid == 0 {
        return Err(PsaError::InvalidArgument);
    }

    let mut info = ffi::PsaStorageInfo {
        capacity: 0,
        size: 0,
        flags: 0,
    };

    let status = unsafe { ffi::psa_its_get_info_wrapper(uid, &mut info) };

    PsaError::from_status(status)?;

    Ok(StorageInfo {
        capacity: info.capacity,
        size: info.size,
        flags: StorageFlags(info.flags),
    })
}

/// Remove an entry from the Internal Trusted Storage.
///
/// Deletes the entry and its associated data from storage.
///
/// # Arguments
///
/// * `uid` - Unique identifier for the entry to remove
///
/// # Errors
///
/// * `NotPermitted` - Entry was created with `WRITE_ONCE`
/// * `InvalidArgument` - Invalid UID
/// * `DoesNotExist` - No entry with this UID
/// * `StorageFailure` - Storage operation failed
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::its;
///
/// its::remove(0x1000)?;
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
pub fn remove(uid: StorageUid) -> PsaResult<()> {
    if uid == 0 {
        return Err(PsaError::InvalidArgument);
    }

    let status = unsafe { ffi::psa_its_remove_wrapper(uid) };
    PsaError::from_status(status)
}

// ============================================================================
// High-Level Convenience Functions
// ============================================================================

/// Check if an entry exists in storage.
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::its;
///
/// if its::exists(0x1000) {
///     println!("Entry exists!");
/// }
/// ```
#[inline]
pub fn exists(uid: StorageUid) -> bool {
    get_info(uid).is_ok()
}

/// Store a fixed-size array in ITS.
///
/// This is a convenience function for storing data of known size at compile time.
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::its;
/// use dragonwing_crypto::psa::StorageFlags;
///
/// let key: [u8; 32] = [0u8; 32]; // Your key here
/// its::store(0x1000, &key, StorageFlags::NONE)?;
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
#[inline]
pub fn store<const N: usize>(
    uid: StorageUid,
    data: &[u8; N],
    flags: StorageFlags,
) -> PsaResult<()> {
    set(uid, data, flags)
}

/// Load a fixed-size array from ITS.
///
/// This is a convenience function for loading data of known size at compile time.
/// Returns an error if the stored data size doesn't match the expected size.
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::its;
///
/// let key: [u8; 32] = its::load(0x1000)?;
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
pub fn load<const N: usize>(uid: StorageUid) -> PsaResult<[u8; N]> {
    // First check the size
    let info = get_info(uid)?;
    if info.size != N {
        return Err(PsaError::InvalidArgument);
    }

    let mut buffer = [0u8; N];
    let len = get(uid, 0, &mut buffer)?;

    if len != N {
        return Err(PsaError::DataCorrupt);
    }

    Ok(buffer)
}

/// Store data and return the UID for convenience.
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::its;
/// use dragonwing_crypto::psa::StorageFlags;
///
/// let uid = its::store_and_return_uid(0x1000, b"my-secret", StorageFlags::NONE)?;
/// assert_eq!(uid, 0x1000);
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
#[inline]
pub fn store_and_return_uid(
    uid: StorageUid,
    data: &[u8],
    flags: StorageFlags,
) -> PsaResult<StorageUid> {
    set(uid, data, flags)?;
    Ok(uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_flags() {
        let flags = StorageFlags::WRITE_ONCE | StorageFlags::NO_CONFIDENTIALITY;
        assert!(flags.contains(StorageFlags::WRITE_ONCE));
        assert!(flags.contains(StorageFlags::NO_CONFIDENTIALITY));
        assert!(!flags.contains(StorageFlags::NO_REPLAY_PROTECTION));
    }
}
