// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// PSA Crypto API - Key Management
//
// This module provides Rust bindings to the PSA Crypto API for key management,
// enabling generation, import, export, and destruction of cryptographic keys.
//
// Keys can be either volatile (lost on reset) or persistent (stored in secure
// storage and surviving reboots).
//
// # Features
//
// - Generate random keys with specified attributes
// - Import existing key material
// - Export keys (if permitted by usage flags)
// - Persistent key storage via PSA ITS
// - Key usage restrictions via usage flags
//
// # Setup Requirements
//
// Add to your `prj.conf`:
// ```
// CONFIG_MBEDTLS=y
// CONFIG_MBEDTLS_PSA_CRYPTO_C=y
// CONFIG_MBEDTLS_ENABLE_HEAP=y
// CONFIG_MBEDTLS_HEAP_SIZE=8192
// CONFIG_SECURE_STORAGE=y  # For persistent keys
// ```
//
// # Example
//
// ```rust,no_run
// use dragonwing_crypto::psa::crypto;
// use dragonwing_crypto::psa::{KeyAttributes, KeyType, Algorithm, KeyUsageFlags, KeyLifetime};
//
// // Initialize PSA Crypto
// crypto::init()?;
//
// // Generate a persistent AES-256 key
// let attrs = KeyAttributes::new()
//     .with_type(KeyType::Aes)
//     .with_bits(256)
//     .with_algorithm(Algorithm::AesGcm)
//     .with_usage(KeyUsageFlags::ENCRYPT | KeyUsageFlags::DECRYPT)
//     .persistent(0x0001_0001);
//
// let key_id = crypto::generate_key(&attrs)?;
//
// // Key survives reboot - later retrieve it
// // (key is automatically loaded when used)
//
// // When done, destroy the key
// crypto::destroy_key(key_id)?;
// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
// ```

use super::errors::{PsaError, PsaResult};
use super::types::{Algorithm, KeyAttributes, KeyId, KeyLifetime, KeyType, KeyUsageFlags};

/// FFI bindings to the C PSA Crypto wrapper
mod ffi {
    use core::ffi::c_int;

    /// Opaque key attributes structure for FFI
    /// This matches the size of psa_key_attributes_t in mbedTLS
    #[repr(C)]
    pub struct PsaKeyAttributes {
        // Opaque - actual size depends on mbedTLS configuration
        // We'll let C code handle the details
        _opaque: [u8; 64], // Conservative size
    }

    impl Default for PsaKeyAttributes {
        fn default() -> Self {
            Self { _opaque: [0u8; 64] }
        }
    }

    extern "C" {
        /// Initialize PSA Crypto subsystem
        pub fn psa_crypto_init_wrapper() -> c_int;

        /// Generate a key
        pub fn psa_generate_key_wrapper(
            key_type: u32,
            bits: usize,
            algorithm: u32,
            usage: u32,
            lifetime: u32,
            key_id: u32,
            out_key_id: *mut u32,
        ) -> c_int;

        /// Import a key
        pub fn psa_import_key_wrapper(
            key_type: u32,
            bits: usize,
            algorithm: u32,
            usage: u32,
            lifetime: u32,
            key_id: u32,
            data: *const u8,
            data_length: usize,
            out_key_id: *mut u32,
        ) -> c_int;

        /// Export a key
        pub fn psa_export_key_wrapper(
            key_id: u32,
            data: *mut u8,
            data_size: usize,
            data_length: *mut usize,
        ) -> c_int;

        /// Export public key from a key pair
        pub fn psa_export_public_key_wrapper(
            key_id: u32,
            data: *mut u8,
            data_size: usize,
            data_length: *mut usize,
        ) -> c_int;

        /// Destroy a key
        pub fn psa_destroy_key_wrapper(key_id: u32) -> c_int;

        /// Purge a key from volatile memory (persistent keys only)
        pub fn psa_purge_key_wrapper(key_id: u32) -> c_int;

        /// Get key attributes
        pub fn psa_get_key_attributes_wrapper(
            key_id: u32,
            out_type: *mut u32,
            out_bits: *mut usize,
            out_algorithm: *mut u32,
            out_usage: *mut u32,
            out_lifetime: *mut u32,
        ) -> c_int;
    }
}

/// Initialize the PSA Crypto subsystem.
///
/// This must be called before any other PSA Crypto functions.
/// It is safe to call multiple times - subsequent calls are no-ops.
///
/// # Errors
///
/// * `InsufficientMemory` - Not enough memory for crypto operations
/// * `StorageFailure` - Failed to initialize key storage
/// * `InsufficientEntropy` - RNG initialization failed
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::crypto;
///
/// crypto::init()?;
/// // Now ready for crypto operations
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
pub fn init() -> PsaResult<()> {
    let status = unsafe { ffi::psa_crypto_init_wrapper() };
    PsaError::from_status(status)
}

/// Generate a random key with the specified attributes.
///
/// Creates a new key using the hardware random number generator.
/// For persistent keys, the key is stored in secure storage and
/// survives device resets.
///
/// # Arguments
///
/// * `attributes` - Key attributes specifying type, size, algorithm, usage, and lifetime
///
/// # Returns
///
/// The key ID that can be used to reference the key in future operations.
///
/// # Errors
///
/// * `InvalidArgument` - Invalid key attributes
/// * `NotSupported` - Key type or algorithm not supported
/// * `AlreadyExists` - Persistent key with this ID already exists
/// * `InsufficientStorage` - Not enough space for persistent key
/// * `InsufficientEntropy` - RNG failed
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::crypto;
/// use dragonwing_crypto::psa::{KeyAttributes, KeyType, Algorithm, KeyUsageFlags};
///
/// crypto::init()?;
///
/// // Generate a volatile AES-256 key
/// let attrs = KeyAttributes::new()
///     .with_type(KeyType::Aes)
///     .with_bits(256)
///     .with_algorithm(Algorithm::AesGcm)
///     .with_usage(KeyUsageFlags::ENCRYPT | KeyUsageFlags::DECRYPT);
///
/// let key_id = crypto::generate_key(&attrs)?;
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
pub fn generate_key(attributes: &KeyAttributes) -> PsaResult<KeyId> {
    let key_type = attributes
        .key_type
        .ok_or(PsaError::InvalidArgument)?
        .as_raw();
    let algorithm = attributes.algorithm.map(|a| a.as_raw()).unwrap_or(0);
    let requested_id = attributes.id.unwrap_or(0);

    let mut out_key_id: u32 = 0;

    let status = unsafe {
        ffi::psa_generate_key_wrapper(
            key_type,
            attributes.bits,
            algorithm,
            attributes.usage.0,
            attributes.lifetime as u32,
            requested_id,
            &mut out_key_id,
        )
    };

    PsaError::from_status(status)?;
    Ok(out_key_id)
}

/// Import key material with the specified attributes.
///
/// Imports existing key material (e.g., from a backup or external source).
/// The key format depends on the key type.
///
/// # Arguments
///
/// * `attributes` - Key attributes specifying type, size, algorithm, usage, and lifetime
/// * `data` - The key material to import
///
/// # Returns
///
/// The key ID that can be used to reference the key.
///
/// # Key Format
///
/// - Symmetric keys (AES, ChaCha20): Raw key bytes
/// - ECC private keys: Raw scalar value
/// - ECC public keys: Uncompressed point (0x04 || x || y)
/// - RSA keys: DER-encoded PKCS#1
///
/// # Errors
///
/// * `InvalidArgument` - Invalid key attributes or data
/// * `NotSupported` - Key type not supported
/// * `AlreadyExists` - Persistent key with this ID already exists
/// * `InsufficientStorage` - Not enough space for persistent key
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::crypto;
/// use dragonwing_crypto::psa::{KeyAttributes, KeyType, Algorithm, KeyUsageFlags};
///
/// crypto::init()?;
///
/// // Import a 256-bit AES key
/// let key_material = [0u8; 32]; // Your key here
/// let attrs = KeyAttributes::new()
///     .with_type(KeyType::Aes)
///     .with_bits(256)
///     .with_algorithm(Algorithm::AesGcm)
///     .with_usage(KeyUsageFlags::ENCRYPT | KeyUsageFlags::DECRYPT);
///
/// let key_id = crypto::import_key(&attrs, &key_material)?;
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
pub fn import_key(attributes: &KeyAttributes, data: &[u8]) -> PsaResult<KeyId> {
    let key_type = attributes
        .key_type
        .ok_or(PsaError::InvalidArgument)?
        .as_raw();
    let algorithm = attributes.algorithm.map(|a| a.as_raw()).unwrap_or(0);
    let requested_id = attributes.id.unwrap_or(0);

    let mut out_key_id: u32 = 0;

    let status = unsafe {
        ffi::psa_import_key_wrapper(
            key_type,
            attributes.bits,
            algorithm,
            attributes.usage.0,
            attributes.lifetime as u32,
            requested_id,
            data.as_ptr(),
            data.len(),
            &mut out_key_id,
        )
    };

    PsaError::from_status(status)?;
    Ok(out_key_id)
}

/// Export a key's material.
///
/// Copies the key material to the provided buffer. The key must have
/// the `EXPORT` usage flag set.
///
/// # Arguments
///
/// * `key_id` - The key to export
/// * `buffer` - Buffer to receive the key material
///
/// # Returns
///
/// The number of bytes written to the buffer.
///
/// # Errors
///
/// * `InvalidArgument` - Invalid key ID
/// * `DoesNotExist` - Key not found
/// * `NotPermitted` - Key doesn't have EXPORT usage flag
/// * `BufferTooSmall` - Buffer is too small for the key
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::crypto;
///
/// let mut buffer = [0u8; 32];
/// let len = crypto::export_key(key_id, &mut buffer)?;
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
pub fn export_key(key_id: KeyId, buffer: &mut [u8]) -> PsaResult<usize> {
    let mut data_length: usize = 0;

    let status = unsafe {
        ffi::psa_export_key_wrapper(key_id, buffer.as_mut_ptr(), buffer.len(), &mut data_length)
    };

    PsaError::from_status(status)?;
    Ok(data_length)
}

/// Export the public key from a key pair.
///
/// For asymmetric keys, exports just the public component.
/// This can be called even if the key doesn't have the EXPORT flag.
///
/// # Arguments
///
/// * `key_id` - The key pair to export from
/// * `buffer` - Buffer to receive the public key
///
/// # Returns
///
/// The number of bytes written to the buffer.
///
/// # Errors
///
/// * `InvalidArgument` - Key is not an asymmetric key pair
/// * `DoesNotExist` - Key not found
/// * `BufferTooSmall` - Buffer is too small
pub fn export_public_key(key_id: KeyId, buffer: &mut [u8]) -> PsaResult<usize> {
    let mut data_length: usize = 0;

    let status = unsafe {
        ffi::psa_export_public_key_wrapper(
            key_id,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut data_length,
        )
    };

    PsaError::from_status(status)?;
    Ok(data_length)
}

/// Destroy a key.
///
/// Removes the key from memory (and storage for persistent keys).
/// After this call, the key ID is invalid.
///
/// # Arguments
///
/// * `key_id` - The key to destroy
///
/// # Errors
///
/// * `InvalidArgument` - Invalid key ID
/// * `DoesNotExist` - Key not found (or already destroyed)
/// * `NotPermitted` - Cannot destroy this key (e.g., in use)
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::crypto;
///
/// crypto::destroy_key(key_id)?;
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
pub fn destroy_key(key_id: KeyId) -> PsaResult<()> {
    let status = unsafe { ffi::psa_destroy_key_wrapper(key_id) };
    PsaError::from_status(status)
}

/// Purge a key from volatile memory.
///
/// For persistent keys, this removes the key from RAM but keeps it in
/// secure storage. The key will be automatically reloaded from storage
/// when next used. This can free up RAM while keeping the key available.
///
/// For volatile keys, this is equivalent to `destroy_key`.
///
/// # Arguments
///
/// * `key_id` - The key to purge
///
/// # Errors
///
/// * `InvalidArgument` - Invalid key ID
/// * `DoesNotExist` - Key not found
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::crypto;
///
/// // Free RAM while keeping the key in storage
/// crypto::purge_key(key_id)?;
///
/// // Key is still usable - will be reloaded automatically
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
pub fn purge_key(key_id: KeyId) -> PsaResult<()> {
    let status = unsafe { ffi::psa_purge_key_wrapper(key_id) };
    PsaError::from_status(status)
}

/// Retrieve key attributes.
///
/// Gets information about a key including its type, size, and usage flags.
///
/// # Arguments
///
/// * `key_id` - The key to query
///
/// # Returns
///
/// Key attributes structure containing the key's properties.
///
/// # Errors
///
/// * `InvalidArgument` - Invalid key ID
/// * `DoesNotExist` - Key not found
pub fn get_key_attributes(key_id: KeyId) -> PsaResult<KeyAttributes> {
    let mut key_type: u32 = 0;
    let mut bits: usize = 0;
    let mut algorithm: u32 = 0;
    let mut usage: u32 = 0;
    let mut lifetime: u32 = 0;

    let status = unsafe {
        ffi::psa_get_key_attributes_wrapper(
            key_id,
            &mut key_type,
            &mut bits,
            &mut algorithm,
            &mut usage,
            &mut lifetime,
        )
    };

    PsaError::from_status(status)?;

    // Convert raw values back to typed values
    let key_type_enum = match key_type {
        0x1001 => Some(KeyType::RawData),
        0x1100 => Some(KeyType::Hmac),
        0x2400 => Some(KeyType::Aes),
        0x2004 => Some(KeyType::ChaCha20),
        _ => None, // Unknown type
    };

    let algorithm_enum = match algorithm {
        0 => None,
        0x04c01000 => Some(Algorithm::AesCtr),
        0x05500100 => Some(Algorithm::AesGcm),
        0x05100500 => Some(Algorithm::ChaCha20Poly1305),
        _ => None, // Unknown algorithm
    };

    let lifetime_enum = match lifetime {
        0 => KeyLifetime::Volatile,
        _ => KeyLifetime::Persistent,
    };

    Ok(KeyAttributes {
        key_type: key_type_enum,
        bits,
        algorithm: algorithm_enum,
        usage: KeyUsageFlags(usage),
        lifetime: lifetime_enum,
        id: if lifetime != 0 { Some(key_id) } else { None },
    })
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Generate a persistent AES-256 key for encryption/decryption.
///
/// This is a convenience function for the common case of creating
/// an AES key for authenticated encryption.
///
/// # Arguments
///
/// * `key_id` - The persistent key ID to assign
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::crypto;
///
/// crypto::init()?;
/// let key_id = crypto::generate_aes256_key(0x0001_0001)?;
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
pub fn generate_aes256_key(key_id: KeyId) -> PsaResult<KeyId> {
    let attrs = KeyAttributes::new()
        .with_type(KeyType::Aes)
        .with_bits(256)
        .with_algorithm(Algorithm::AesGcm)
        .with_usage(KeyUsageFlags::ENCRYPT | KeyUsageFlags::DECRYPT)
        .persistent(key_id);

    generate_key(&attrs)
}

/// Import an AES-256 key for encryption/decryption.
///
/// # Arguments
///
/// * `key_id` - The persistent key ID to assign
/// * `key_material` - The 32-byte key material
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::crypto;
///
/// crypto::init()?;
/// let key_material = [0u8; 32]; // Your key
/// let key_id = crypto::import_aes256_key(0x0001_0001, &key_material)?;
/// # Ok::<(), dragonwing_crypto::psa::PsaError>(())
/// ```
pub fn import_aes256_key(key_id: KeyId, key_material: &[u8; 32]) -> PsaResult<KeyId> {
    let attrs = KeyAttributes::new()
        .with_type(KeyType::Aes)
        .with_bits(256)
        .with_algorithm(Algorithm::AesGcm)
        .with_usage(KeyUsageFlags::ENCRYPT | KeyUsageFlags::DECRYPT)
        .persistent(key_id);

    import_key(&attrs, key_material)
}

/// Check if a persistent key exists.
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::crypto;
///
/// if crypto::key_exists(0x0001_0001) {
///     println!("Key exists!");
/// }
/// ```
#[inline]
pub fn key_exists(key_id: KeyId) -> bool {
    get_key_attributes(key_id).is_ok()
}
