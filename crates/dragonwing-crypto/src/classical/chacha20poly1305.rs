// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// ChaCha20-Poly1305 AEAD (RFC 8439)
//
// This module provides standard ChaCha20-Poly1305 authenticated encryption
// with a 96-bit (12-byte) nonce as specified in RFC 8439.
//
// This is the cipher used by:
// - TLS 1.3
// - QUIC
// - WireGuard
// - BPP (Binary Packet Protocol) for phone-to-MCU encrypted streaming
//
// # Key Sizes
//
// - Key: 32 bytes (256 bits)
// - Nonce: 12 bytes (96 bits)
// - Tag: 16 bytes (128 bits)
//
// # Nonce Considerations
//
// Unlike XChaCha20-Poly1305, the 12-byte nonce is NOT safe for random
// generation due to the birthday bound (~2^48 messages before collision).
// Use a counter, timestamp, or hybrid scheme (e.g., timestamp + random).
//
// BPP uses: timestamp(8 bytes) + random(4 bytes) = 12 bytes
//
// # Requirements
//
// Enable mbedTLS in your Zephyr application (prj.conf):
// ```
// CONFIG_MBEDTLS=y
// CONFIG_MBEDTLS_BUILTIN=y
// CONFIG_MBEDTLS_CIPHER_CHACHA20_ENABLED=y
// CONFIG_MBEDTLS_POLY1305=y
// CONFIG_MBEDTLS_CHACHAPOLY_AEAD_ENABLED=y
// ```
//
// Include the C source file in your CMakeLists.txt:
// ```cmake
// target_sources(app PRIVATE ${CMAKE_SOURCE_DIR}/dragonwing-crypto/c/chacha20poly1305.c)
// ```
//
// # Example
//
// ```rust,no_run
// use dragonwing_crypto::classical::chacha20poly1305::{Key, Nonce, encrypt, decrypt};
//
// let key = Key::from_bytes(&[0u8; 32]);
// let nonce = Nonce::from_bytes(&[0u8; 12]); // Use timestamp+random in production
//
// // Encrypt a message
// let plaintext = b"Hello, ChaCha20-Poly1305!";
// let aad = b"additional authenticated data";
// let (ciphertext, tag) = encrypt(&key, &nonce, plaintext, aad).unwrap();
//
// // Decrypt the message
// let decrypted = decrypt(&key, &nonce, &ciphertext, &tag, aad).unwrap();
// assert_eq!(plaintext.as_slice(), decrypted.as_slice());
// ```

/// Size of the encryption key in bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// Size of the nonce in bytes (96 bits)
pub const NONCE_SIZE: usize = 12;

/// Size of the authentication tag in bytes (128 bits)
pub const TAG_SIZE: usize = 16;

/// FFI bindings to the C ChaCha20-Poly1305 implementation
mod ffi {
    use core::ffi::c_int;

    extern "C" {
        /// Initialize the library
        pub fn chacha20poly1305_init() -> c_int;

        /// Encrypt and authenticate
        pub fn chacha20poly1305_encrypt(
            ciphertext: *mut u8,
            tag: *mut u8,
            plaintext: *const u8,
            plaintext_len: usize,
            aad: *const u8,
            aad_len: usize,
            nonce: *const u8,
            key: *const u8,
        ) -> c_int;

        /// Authenticate and decrypt
        pub fn chacha20poly1305_decrypt(
            plaintext: *mut u8,
            ciphertext: *const u8,
            ciphertext_len: usize,
            tag: *const u8,
            aad: *const u8,
            aad_len: usize,
            nonce: *const u8,
            key: *const u8,
        ) -> c_int;
    }

    /* Error codes from C */
    pub const SUCCESS: c_int = 0;
    pub const ERROR_AUTH: c_int = -4;
}

/// Error type for ChaCha20-Poly1305 operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Initialization failed
    InitFailed,
    /// Encryption failed
    EncryptFailed,
    /// Decryption failed
    DecryptFailed,
    /// Authentication failed (ciphertext was tampered or wrong key)
    AuthenticationFailed,
    /// Invalid parameters
    InvalidParams,
}

/// Result type for ChaCha20-Poly1305 operations
pub type Result<T> = core::result::Result<T, Error>;

/// ChaCha20-Poly1305 encryption key (256 bits)
///
/// Keys should be generated from a cryptographically secure random source.
/// The same key can be used for multiple messages as long as nonces are unique.
#[derive(Clone)]
pub struct Key {
    bytes: [u8; KEY_SIZE],
}

impl Key {
    /// Create a key from raw bytes.
    ///
    /// The bytes should be generated from a cryptographically secure
    /// random number generator (e.g., `HwRng`).
    pub fn from_bytes(bytes: &[u8; KEY_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Get the raw bytes of this key.
    pub fn to_bytes(&self) -> [u8; KEY_SIZE] {
        self.bytes
    }

    /// Get a reference to the raw bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.bytes
    }

    /// Generate a random key using the provided RNG.
    #[cfg(feature = "rng")]
    pub fn random(rng: &crate::rng::HwRng) -> Self {
        Self {
            bytes: rng.random_array(),
        }
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // Zero out the key bytes on drop for security
        for byte in &mut self.bytes {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// ChaCha20-Poly1305 nonce (96 bits)
///
/// IMPORTANT: Unlike XChaCha20-Poly1305, this 12-byte nonce is NOT safe
/// for random generation. Use a counter or hybrid scheme.
///
/// BPP format: timestamp(8 bytes) + random(4 bytes) = 12 bytes
///
/// A new nonce MUST be used for each encryption with the same key.
/// Reusing a nonce with the same key completely breaks security.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce {
    bytes: [u8; NONCE_SIZE],
}

impl Nonce {
    /// Create a nonce from raw bytes.
    pub fn from_bytes(bytes: &[u8; NONCE_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Get the raw bytes of this nonce.
    pub fn to_bytes(&self) -> [u8; NONCE_SIZE] {
        self.bytes
    }

    /// Get a reference to the raw bytes.
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.bytes
    }

    /// Create a nonce from timestamp and random components (BPP format).
    ///
    /// This is the recommended way to construct nonces for BPP:
    /// - timestamp: 8-byte big-endian microseconds since UNIX epoch
    /// - random: 4-byte random value
    pub fn from_timestamp_random(timestamp: u64, random: u32) -> Self {
        let mut bytes = [0u8; NONCE_SIZE];
        bytes[0..8].copy_from_slice(&timestamp.to_be_bytes());
        bytes[8..12].copy_from_slice(&random.to_be_bytes());
        Self { bytes }
    }
}

/// Authentication tag (128 bits)
///
/// The tag is produced during encryption and must be provided during
/// decryption to verify the ciphertext hasn't been tampered with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    bytes: [u8; TAG_SIZE],
}

impl Tag {
    /// Create a tag from raw bytes.
    pub fn from_bytes(bytes: &[u8; TAG_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Get the raw bytes of this tag.
    pub fn to_bytes(&self) -> [u8; TAG_SIZE] {
        self.bytes
    }

    /// Get a reference to the raw bytes.
    pub fn as_bytes(&self) -> &[u8; TAG_SIZE] {
        &self.bytes
    }
}

/// Initialize the ChaCha20-Poly1305 library.
///
/// This is called automatically by encrypt/decrypt, but can be called
/// explicitly for early initialization.
pub fn init() -> Result<()> {
    let ret = unsafe { ffi::chacha20poly1305_init() };
    if ret == ffi::SUCCESS {
        Ok(())
    } else {
        Err(Error::InitFailed)
    }
}

/// Encrypt and authenticate a message.
///
/// # Arguments
///
/// * `key` - The 256-bit encryption key
/// * `nonce` - A unique 96-bit nonce (use timestamp+random, NOT random-only)
/// * `plaintext` - The message to encrypt
/// * `aad` - Additional authenticated data (not encrypted, but authenticated)
///
/// # Returns
///
/// A tuple of (ciphertext, tag) where:
/// * `ciphertext` is the same length as plaintext
/// * `tag` is 16 bytes and must be stored with the ciphertext
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::classical::chacha20poly1305::{Key, Nonce, encrypt};
///
/// let key = Key::from_bytes(&[0u8; 32]);
/// let nonce = Nonce::from_bytes(&[0u8; 12]);
/// let plaintext = b"secret message";
/// let aad = b"header";
///
/// let (ciphertext, tag) = encrypt(&key, &nonce, plaintext, aad).unwrap();
/// ```
pub fn encrypt(
    key: &Key,
    nonce: &Nonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(alloc::vec::Vec<u8>, Tag)> {
    let mut ciphertext = alloc::vec![0u8; plaintext.len()];
    let mut tag_bytes = [0u8; TAG_SIZE];

    let ret = unsafe {
        ffi::chacha20poly1305_encrypt(
            ciphertext.as_mut_ptr(),
            tag_bytes.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len(),
            aad.as_ptr(),
            aad.len(),
            nonce.bytes.as_ptr(),
            key.bytes.as_ptr(),
        )
    };

    if ret == ffi::SUCCESS {
        Ok((ciphertext, Tag { bytes: tag_bytes }))
    } else {
        Err(Error::EncryptFailed)
    }
}

/// Authenticate and decrypt a message.
///
/// # Arguments
///
/// * `key` - The 256-bit encryption key (same as used for encryption)
/// * `nonce` - The 96-bit nonce (same as used for encryption)
/// * `ciphertext` - The encrypted message
/// * `tag` - The 16-byte authentication tag from encryption
/// * `aad` - Additional authenticated data (same as used for encryption)
///
/// # Returns
///
/// The decrypted plaintext if authentication succeeds.
///
/// # Errors
///
/// Returns `Error::AuthenticationFailed` if:
/// * The ciphertext was tampered with
/// * The wrong key was used
/// * The wrong nonce was used
/// * The AAD doesn't match what was used for encryption
///
/// # Security
///
/// If authentication fails, NO data is returned. This prevents any
/// information leakage from partial decryption of tampered data.
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::classical::chacha20poly1305::{Key, Nonce, Tag, decrypt};
///
/// let key = Key::from_bytes(&[0u8; 32]);
/// let nonce = Nonce::from_bytes(&[0u8; 12]);
/// let ciphertext = &[/* encrypted data */];
/// let tag = Tag::from_bytes(&[/* tag bytes */]);
/// let aad = b"header";
///
/// match decrypt(&key, &nonce, ciphertext, &tag, aad) {
///     Ok(plaintext) => { /* use plaintext */ }
///     Err(_) => { /* authentication failed - data was tampered */ }
/// }
/// ```
pub fn decrypt(
    key: &Key,
    nonce: &Nonce,
    ciphertext: &[u8],
    tag: &Tag,
    aad: &[u8],
) -> Result<alloc::vec::Vec<u8>> {
    let mut plaintext = alloc::vec![0u8; ciphertext.len()];

    let ret = unsafe {
        ffi::chacha20poly1305_decrypt(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            tag.bytes.as_ptr(),
            aad.as_ptr(),
            aad.len(),
            nonce.bytes.as_ptr(),
            key.bytes.as_ptr(),
        )
    };

    match ret {
        ffi::SUCCESS => Ok(plaintext),
        ffi::ERROR_AUTH => Err(Error::AuthenticationFailed),
        _ => Err(Error::DecryptFailed),
    }
}

/// Encrypt a message in place, returning the tag.
///
/// This is more memory-efficient for large messages as it doesn't
/// allocate a separate buffer for the ciphertext.
///
/// # Arguments
///
/// * `key` - The 256-bit encryption key
/// * `nonce` - A unique 96-bit nonce
/// * `buffer` - The plaintext to encrypt (will be overwritten with ciphertext)
/// * `aad` - Additional authenticated data
///
/// # Returns
///
/// The 16-byte authentication tag.
pub fn encrypt_in_place(key: &Key, nonce: &Nonce, buffer: &mut [u8], aad: &[u8]) -> Result<Tag> {
    let mut tag_bytes = [0u8; TAG_SIZE];

    // Note: ChaCha20-Poly1305 can encrypt in place since ChaCha20 is a stream cipher
    let ret = unsafe {
        ffi::chacha20poly1305_encrypt(
            buffer.as_mut_ptr(),
            tag_bytes.as_mut_ptr(),
            buffer.as_ptr(),
            buffer.len(),
            aad.as_ptr(),
            aad.len(),
            nonce.bytes.as_ptr(),
            key.bytes.as_ptr(),
        )
    };

    if ret == ffi::SUCCESS {
        Ok(Tag { bytes: tag_bytes })
    } else {
        Err(Error::EncryptFailed)
    }
}

/// Decrypt a message in place.
///
/// This is more memory-efficient for large messages as it doesn't
/// allocate a separate buffer for the plaintext.
///
/// # Arguments
///
/// * `key` - The 256-bit encryption key
/// * `nonce` - The 96-bit nonce (same as used for encryption)
/// * `buffer` - The ciphertext to decrypt (will be overwritten with plaintext)
/// * `tag` - The 16-byte authentication tag
/// * `aad` - Additional authenticated data
///
/// # Security
///
/// If authentication fails, the buffer contents are undefined. The caller
/// should not use the buffer contents if this function returns an error.
pub fn decrypt_in_place(
    key: &Key,
    nonce: &Nonce,
    buffer: &mut [u8],
    tag: &Tag,
    aad: &[u8],
) -> Result<()> {
    let ret = unsafe {
        ffi::chacha20poly1305_decrypt(
            buffer.as_mut_ptr(),
            buffer.as_ptr(),
            buffer.len(),
            tag.bytes.as_ptr(),
            aad.as_ptr(),
            aad.len(),
            nonce.bytes.as_ptr(),
            key.bytes.as_ptr(),
        )
    };

    match ret {
        ffi::SUCCESS => Ok(()),
        ffi::ERROR_AUTH => Err(Error::AuthenticationFailed),
        _ => Err(Error::DecryptFailed),
    }
}

extern crate alloc;

#[cfg(test)]
mod tests {
    // Tests would run on target hardware with mbedTLS available
}
