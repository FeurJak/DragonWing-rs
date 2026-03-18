// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// PSA Secure Storage and Crypto API
//
// This module provides Rust bindings to the PSA Certified APIs for secure
// storage and cryptographic key management on the Arduino Uno Q.
//
// # Architecture
//
// ```text
// ┌─────────────────────────────────────────────────────────┐
// │                    Application                          │
// ├─────────────────────────────────────────────────────────┤
// │    psa::its (ITS)         │     psa::crypto (Keys)     │
// ├─────────────────────────────────────────────────────────┤
// │                  Zephyr Secure Storage                  │
// │    ┌───────────────────────────────────────────┐        │
// │    │  AEAD Transform (encryption + auth tag)   │        │
// │    └───────────────────────────────────────────┘        │
// │    ┌───────────────────────────────────────────┐        │
// │    │   NVS/Settings Store (flash backend)      │        │
// │    └───────────────────────────────────────────┘        │
// ├─────────────────────────────────────────────────────────┤
// │                    STM32U585 Flash                      │
// └─────────────────────────────────────────────────────────┘
// ```
//
// # Submodules
//
// - [`its`] - Internal Trusted Storage for arbitrary encrypted data
// - [`crypto`] - PSA Crypto key management (generate, import, export)
//
// # Setup Requirements
//
// Add to your `prj.conf`:
// ```text
// # Secure Storage
// CONFIG_SECURE_STORAGE=y
// CONFIG_SECURE_STORAGE_ITS_IMPLEMENTATION_ZEPHYR=y
// CONFIG_SECURE_STORAGE_ITS_TRANSFORM_IMPLEMENTATION_AEAD=y
// CONFIG_SECURE_STORAGE_ITS_STORE_IMPLEMENTATION_SETTINGS=y
// CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE=512
//
// # Storage backends
// CONFIG_SETTINGS=y
// CONFIG_NVS=y
// CONFIG_FLASH=y
// CONFIG_FLASH_MAP=y
//
// # PSA Crypto
// CONFIG_MBEDTLS=y
// CONFIG_MBEDTLS_PSA_CRYPTO_C=y
// CONFIG_MBEDTLS_ENABLE_HEAP=y
// CONFIG_MBEDTLS_HEAP_SIZE=8192
// ```
//
// # Example
//
// ```rust,no_run
// use dragonwing_crypto::psa::{self, its, crypto};
// use dragonwing_crypto::psa::{StorageUid, StorageFlags, KeyAttributes, KeyType, Algorithm, KeyUsageFlags};
//
// // Initialize PSA Crypto (required for key operations)
// crypto::init()?;
//
// // Store arbitrary data in ITS
// let uid: StorageUid = 0x1000;
// its::set(uid, b"my-secret-data", StorageFlags::NONE)?;
//
// // Generate a persistent AES key
// let key_id = crypto::generate_aes256_key(0x0001_0001)?;
//
// // Both survive device resets!
// # Ok::<(), psa::PsaError>(())
// ```

// Submodules - public for namespaced access (psa::its, psa::crypto)
pub mod crypto;
pub mod its;

// Storage integration modules (feature-gated)
#[cfg(feature = "saga")]
pub mod saga;
#[cfg(feature = "xwing")]
pub mod xwing;

// Storable trait module
mod storable;

// Private submodules
mod errors;
mod types;

// Re-export error types
pub use errors::{PsaError, PsaResult};

// Re-export common types
pub use types::{
    Algorithm, KeyAttributes, KeyId, KeyLifetime, KeyType, KeyUsageFlags, StorageFlags,
    StorageInfo, StorageUid,
};

// Re-export key ID utilities
pub use types::key_id;

// Also export ITS constants
pub use its::MAX_DATA_SIZE;

// Re-export the PsaStorable trait for custom types
pub use storable::PsaStorable;
