// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Hash Functions Module
//
// Provides cryptographic hash functions for key derivation and integrity.

/// Compute SHA-256 hash of the input data
///
/// # Arguments
/// * `data` - Input bytes to hash
///
/// # Returns
/// 32-byte SHA-256 digest
///
/// # Example
/// ```ignore
/// use dragonwing_crypto::hash::sha256;
///
/// let digest = sha256(b"Hello, World!");
/// assert_eq!(digest.len(), 32);
/// ```
#[cfg(feature = "xwing")]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    libcrux_iot_sha3::sha256(data)
}
