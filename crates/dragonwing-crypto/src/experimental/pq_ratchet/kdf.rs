// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Key Derivation Functions for PQ-Ratchet
//!
//! This module provides HKDF-SHA256 based key derivation functions with
//! domain separation, following Signal's Double Ratchet specification
//! adapted for post-quantum security with X-Wing.
//!
//! # Functions
//!
//! - [`kdf_root`] - Derive new root key and chain key after KEM ratchet
//! - [`kdf_chain`] - Derive next chain key and message key (symmetric ratchet)
//! - [`derive_nonce`] - Derive AEAD nonce from message key
//!
//! # Security
//!
//! All functions use domain separation labels to ensure keys derived for
//! different purposes are cryptographically independent, even if the same
//! input material is accidentally reused.
//!
//! # References
//!
//! - [RFC 5869](https://tools.ietf.org/html/rfc5869) - HKDF specification
//! - [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)

use sha2::{Digest, Sha256};

// ============================================================================
// Constants
// ============================================================================

/// Domain separation label for root key derivation (after X-Wing KEM ratchet)
pub const LABEL_ROOT: &[u8] = b"DragonWing PQ-Ratchet V1 Root";

/// Domain separation label for chain key derivation (symmetric ratchet)
pub const LABEL_CHAIN: &[u8] = b"DragonWing PQ-Ratchet V1 Chain";

/// Domain separation label for message key derivation
pub const LABEL_MESSAGE: &[u8] = b"DragonWing PQ-Ratchet V1 Message";

/// Domain separation label for nonce derivation
pub const LABEL_NONCE: &[u8] = b"DragonWing PQ-Ratchet V1 Nonce";

/// Domain separation label for authenticator key update
pub const LABEL_AUTH: &[u8] = b"DragonWing PQ-Ratchet V1 Auth";

/// Size of derived keys in bytes
pub const KEY_SIZE: usize = 32;

/// Size of XChaCha20-Poly1305 nonce in bytes
pub const NONCE_SIZE: usize = 24;

// ============================================================================
// HKDF-SHA256 Implementation (RFC 5869)
// ============================================================================

/// HKDF-Extract: Extract a pseudorandom key from input keying material.
///
/// PRK = HMAC-SHA256(salt, IKM)
///
/// # Arguments
/// * `salt` - Optional salt value (if None, uses zeros)
/// * `ikm` - Input keying material
///
/// # Returns
/// A 32-byte pseudorandom key (PRK)
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand: Expand a pseudorandom key to desired length.
///
/// Uses HMAC-SHA256 in counter mode with info as context.
/// This implementation is no_std compatible (no heap allocation).
///
/// # Arguments
/// * `prk` - Pseudorandom key from extract phase
/// * `info` - Context and application specific information  
/// * `length` - Desired output length (max 64 bytes for this implementation)
///
/// # Returns
/// Output keying material of specified length (64-byte array, use first `length` bytes)
///
/// # Panics
/// Panics if length > 64 bytes or info > 64 bytes
fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> [u8; 64] {
    assert!(
        length <= 64,
        "HKDF expand length must be <= 64 for this implementation"
    );
    assert!(
        info.len() <= 64,
        "HKDF info must be <= 64 bytes for this implementation"
    );

    let mut okm = [0u8; 64];
    let mut t = [0u8; 32];
    let mut offset = 0;
    let mut counter = 1u8;

    // Fixed-size buffer for HMAC input: T(i-1)[32] + info[64] + counter[1] = 97 bytes max
    let mut input_buf = [0u8; 97];

    while offset < length {
        // T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
        let mut input_len = 0;

        if counter > 1 {
            input_buf[..32].copy_from_slice(&t);
            input_len = 32;
        }

        input_buf[input_len..input_len + info.len()].copy_from_slice(info);
        input_len += info.len();

        input_buf[input_len] = counter;
        input_len += 1;

        t = hmac_sha256(prk, &input_buf[..input_len]);

        let copy_len = core::cmp::min(32, length - offset);
        okm[offset..offset + copy_len].copy_from_slice(&t[..copy_len]);

        offset += 32;
        counter += 1;
    }

    okm
}

/// HMAC-SHA256 implementation.
///
/// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
///
/// # Arguments
/// * `key` - The secret key
/// * `message` - The message to authenticate
///
/// # Returns
/// 32-byte HMAC tag
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    // If key is longer than block size, hash it
    let key_block: [u8; BLOCK_SIZE] = if key.len() > BLOCK_SIZE {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hash = hasher.finalize();
        let mut block = [0u8; BLOCK_SIZE];
        block[..32].copy_from_slice(&hash);
        block
    } else {
        let mut block = [0u8; BLOCK_SIZE];
        block[..key.len()].copy_from_slice(key);
        block
    };

    // Inner hash: H((K ⊕ ipad) || message)
    let mut inner_hasher = Sha256::new();
    let mut inner_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key[i] = key_block[i] ^ IPAD;
    }
    inner_hasher.update(&inner_key);
    inner_hasher.update(message);
    let inner_hash = inner_hasher.finalize();

    // Outer hash: H((K ⊕ opad) || inner_hash)
    let mut outer_hasher = Sha256::new();
    let mut outer_key = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_key[i] = key_block[i] ^ OPAD;
    }
    outer_hasher.update(&outer_key);
    outer_hasher.update(&inner_hash);
    let outer_hash = outer_hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&outer_hash);
    result
}

/// Full HKDF: Extract-then-Expand
///
/// # Arguments
/// * `salt` - Salt value
/// * `ikm` - Input keying material  
/// * `info` - Context information
/// * `length` - Desired output length
///
/// # Returns
/// Output keying material
fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> [u8; 64] {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

// ============================================================================
// PQ-Ratchet KDF Functions
// ============================================================================

/// Derive new root key and chain key after X-Wing KEM ratchet.
///
/// This function is called when performing a KEM ratchet step (new epoch).
/// The X-Wing shared secret is mixed with the current root key to derive
/// both a new root key and the initial chain key for the new epoch.
///
/// # Arguments
/// * `root_key` - Current root key (32 bytes)
/// * `shared_secret` - X-Wing shared secret from encapsulation (32 bytes)
///
/// # Returns
/// Tuple of (new_root_key, chain_key), each 32 bytes
///
/// # Security
///
/// The root key provides forward secrecy: even if a chain key is compromised,
/// previous root keys (and thus previous chain keys) remain secure because
/// deriving root_key from new_root_key requires inverting HKDF.
///
/// # Example
///
/// ```rust,ignore
/// use dragonwing_crypto::experimental::pq_ratchet::kdf::kdf_root;
///
/// let root_key = [0u8; 32];
/// let xwing_shared_secret = [1u8; 32]; // From X-Wing encapsulation
///
/// let (new_root, chain_key) = kdf_root(&root_key, &xwing_shared_secret);
/// ```
pub fn kdf_root(root_key: &[u8; 32], shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // HKDF with root_key as salt, shared_secret as IKM, domain label as info
    // Output: 64 bytes = new_root_key (32) || chain_key (32)
    let output = hkdf(root_key, shared_secret, LABEL_ROOT, 64);

    let mut new_root_key = [0u8; 32];
    let mut chain_key = [0u8; 32];

    new_root_key.copy_from_slice(&output[0..32]);
    chain_key.copy_from_slice(&output[32..64]);

    (new_root_key, chain_key)
}

/// Derive next chain key and message key from current chain key.
///
/// This function implements the symmetric ratchet step. Each message
/// advances the chain, deriving a unique message key while updating
/// the chain key for the next message.
///
/// # Arguments
/// * `chain_key` - Current chain key (32 bytes)
///
/// # Returns
/// Tuple of (next_chain_key, message_key), each 32 bytes
///
/// # Security
///
/// The chain provides forward secrecy within an epoch: message keys are
/// derived in order, and each chain_key is immediately replaced, so
/// compromising a message key doesn't reveal past message keys.
///
/// # Example
///
/// ```rust,ignore
/// use dragonwing_crypto::experimental::pq_ratchet::kdf::kdf_chain;
///
/// let chain_key = [0u8; 32];
///
/// // Derive key for first message
/// let (chain_key_1, msg_key_0) = kdf_chain(&chain_key);
///
/// // Derive key for second message
/// let (chain_key_2, msg_key_1) = kdf_chain(&chain_key_1);
/// ```
pub fn kdf_chain(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // HKDF with empty salt, chain_key as IKM, domain label as info
    // Output: 64 bytes = next_chain_key (32) || message_key (32)
    let output = hkdf(&[0u8; 32], chain_key, LABEL_CHAIN, 64);

    let mut next_chain_key = [0u8; 32];
    let mut message_key = [0u8; 32];

    next_chain_key.copy_from_slice(&output[0..32]);
    message_key.copy_from_slice(&output[32..64]);

    (next_chain_key, message_key)
}

/// Derive AEAD nonce from message key.
///
/// Since each message key is unique and used only once, we can derive
/// a deterministic nonce from it. This avoids the need for nonce counters
/// or random nonce generation.
///
/// # Arguments
/// * `message_key` - The message key (32 bytes)
///
/// # Returns
/// 24-byte nonce suitable for XChaCha20-Poly1305
///
/// # Security
///
/// The nonce is deterministically derived from the message key using HKDF.
/// Since each message key is unique (from the chain ratchet), each nonce
/// is also unique, satisfying AEAD security requirements.
///
/// # Example
///
/// ```rust,ignore
/// use dragonwing_crypto::experimental::pq_ratchet::kdf::{kdf_chain, derive_nonce};
///
/// let chain_key = [0u8; 32];
/// let (_, message_key) = kdf_chain(&chain_key);
///
/// let nonce = derive_nonce(&message_key);
/// // Use nonce with XChaCha20-Poly1305
/// ```
pub fn derive_nonce(message_key: &[u8; 32]) -> [u8; NONCE_SIZE] {
    // HKDF with empty salt, message_key as IKM, nonce label as info
    // Output: 24 bytes for XChaCha20-Poly1305 nonce
    let output = hkdf(&[0u8; 32], message_key, LABEL_NONCE, NONCE_SIZE);

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&output[0..NONCE_SIZE]);
    nonce
}

/// Derive authenticator keys for header MAC.
///
/// The authenticator provides epoch-evolving MAC keys for authenticating
/// message headers before decryption. This follows Signal's SPQR pattern.
///
/// # Arguments
/// * `auth_root` - Current authenticator root key (32 bytes)
/// * `epoch_secret` - Secret material for this epoch (32 bytes)
///
/// # Returns
/// Tuple of (new_auth_root, mac_key), each 32 bytes
///
/// # Example
///
/// ```rust,ignore
/// use dragonwing_crypto::experimental::pq_ratchet::kdf::kdf_auth;
///
/// let auth_root = [0u8; 32];
/// let epoch_secret = [1u8; 32];
///
/// let (new_auth_root, mac_key) = kdf_auth(&auth_root, &epoch_secret);
/// ```
pub fn kdf_auth(auth_root: &[u8; 32], epoch_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // HKDF with auth_root as salt, epoch_secret as IKM, auth label as info
    // Output: 64 bytes = new_auth_root (32) || mac_key (32)
    let output = hkdf(auth_root, epoch_secret, LABEL_AUTH, 64);

    let mut new_auth_root = [0u8; 32];
    let mut mac_key = [0u8; 32];

    new_auth_root.copy_from_slice(&output[0..32]);
    mac_key.copy_from_slice(&output[32..64]);

    (new_auth_root, mac_key)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test HMAC-SHA256 against RFC 4231 test vectors
    #[test]
    fn test_hmac_sha256_rfc4231() {
        // Test Case 1 from RFC 4231
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];

        let result = hmac_sha256(&key, data);
        assert_eq!(result, expected);
    }

    /// Test HMAC-SHA256 with key longer than block size
    #[test]
    fn test_hmac_sha256_long_key() {
        // Test Case 6 from RFC 4231 (key longer than block size)
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let expected = [
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5,
            0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f,
            0x0e, 0xe3, 0x7f, 0x54,
        ];

        let result = hmac_sha256(&key, data);
        assert_eq!(result, expected);
    }

    /// Test HKDF against RFC 5869 test vector
    #[test]
    fn test_hkdf_rfc5869() {
        // Test Case 1 from RFC 5869 (SHA-256)
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let expected_prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let expected_okm_42 = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];

        // Test extract
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(prk, expected_prk);

        // Test expand (first 42 bytes)
        let okm = hkdf_expand(&prk, &info, 42);
        assert_eq!(&okm[..42], &expected_okm_42[..]);
    }

    /// Test that kdf_root produces different outputs for different inputs
    #[test]
    fn test_kdf_root_uniqueness() {
        let root_key = [0u8; 32];
        let ss1 = [1u8; 32];
        let ss2 = [2u8; 32];

        let (new_root1, chain1) = kdf_root(&root_key, &ss1);
        let (new_root2, chain2) = kdf_root(&root_key, &ss2);

        // Different shared secrets should produce different outputs
        assert_ne!(new_root1, new_root2);
        assert_ne!(chain1, chain2);

        // Root key and chain key should be different from each other
        assert_ne!(new_root1, chain1);
    }

    /// Test that kdf_chain produces unique keys per step
    #[test]
    fn test_kdf_chain_uniqueness() {
        let chain_key = [0u8; 32];

        let (chain1, msg1) = kdf_chain(&chain_key);
        let (chain2, msg2) = kdf_chain(&chain1);
        let (chain3, msg3) = kdf_chain(&chain2);

        // Each step should produce unique keys
        assert_ne!(msg1, msg2);
        assert_ne!(msg2, msg3);
        assert_ne!(msg1, msg3);

        // Chain keys should also be unique
        assert_ne!(chain1, chain2);
        assert_ne!(chain2, chain3);
    }

    /// Test that derive_nonce produces correct length
    #[test]
    fn test_derive_nonce_length() {
        let message_key = [0u8; 32];
        let nonce = derive_nonce(&message_key);

        assert_eq!(nonce.len(), NONCE_SIZE);
        assert_eq!(nonce.len(), 24); // XChaCha20-Poly1305 nonce size
    }

    /// Test that derive_nonce is deterministic
    #[test]
    fn test_derive_nonce_deterministic() {
        let message_key = [42u8; 32];

        let nonce1 = derive_nonce(&message_key);
        let nonce2 = derive_nonce(&message_key);

        assert_eq!(nonce1, nonce2);
    }

    /// Test that derive_nonce produces different nonces for different keys
    #[test]
    fn test_derive_nonce_uniqueness() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let nonce1 = derive_nonce(&key1);
        let nonce2 = derive_nonce(&key2);

        assert_ne!(nonce1, nonce2);
    }

    /// Test kdf_auth produces valid outputs
    #[test]
    fn test_kdf_auth() {
        let auth_root = [0u8; 32];
        let epoch_secret = [1u8; 32];

        let (new_auth_root, mac_key) = kdf_auth(&auth_root, &epoch_secret);

        // Should produce different values
        assert_ne!(new_auth_root, mac_key);
        assert_ne!(new_auth_root, auth_root);
        assert_ne!(mac_key, epoch_secret);
    }

    /// Test full ratchet chain derivation
    #[test]
    fn test_full_ratchet_derivation() {
        // Simulate initial key exchange
        let initial_root = [0u8; 32];
        let xwing_shared_secret = [0xABu8; 32];

        // KEM ratchet step
        let (root_key, chain_key) = kdf_root(&initial_root, &xwing_shared_secret);

        // Derive keys for 3 messages
        let (ck1, mk0) = kdf_chain(&chain_key);
        let (ck2, mk1) = kdf_chain(&ck1);
        let (_ck3, mk2) = kdf_chain(&ck2);

        // Derive nonces
        let n0 = derive_nonce(&mk0);
        let n1 = derive_nonce(&mk1);
        let n2 = derive_nonce(&mk2);

        // All message keys and nonces should be unique
        assert_ne!(mk0, mk1);
        assert_ne!(mk1, mk2);
        assert_ne!(n0, n1);
        assert_ne!(n1, n2);

        // Root key should be independent
        assert_ne!(root_key, chain_key);
        assert_ne!(root_key, mk0);
    }
}
