// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// X25519 Key Agreement (RFC 7748)
//
// This module provides X25519 Diffie-Hellman key agreement using a standalone
// C implementation optimized for embedded systems.
//
// X25519 is a widely-used key agreement scheme with:
// - 32-byte private keys
// - 32-byte public keys
// - 32-byte shared secrets
// - Fast key exchange
// - Constant-time implementation (resistant to timing attacks)
//
// # Requirements
//
// Include the C source file in your Zephyr application:
// ```cmake
// target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/dragonwing-crypto/c/x25519.c)
// ```
//
// # Example
//
// ```rust,no_run
// use dragonwing_crypto::classical::x25519::SecretKey;
// use dragonwing_crypto::rng::HwRng;
//
// // Alice generates a key pair
// let rng = HwRng::new();
// let alice_seed: [u8; 32] = rng.random_array();
// let alice_secret = SecretKey::from_bytes(&alice_seed);
// let alice_public = alice_secret.public_key();
//
// // Bob generates a key pair
// let bob_seed: [u8; 32] = rng.random_array();
// let bob_secret = SecretKey::from_bytes(&bob_seed);
// let bob_public = bob_secret.public_key();
//
// // Both compute the same shared secret
// let alice_shared = alice_secret.diffie_hellman(&bob_public).unwrap();
// let bob_shared = bob_secret.diffie_hellman(&alice_public).unwrap();
// assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
// ```

/// Size of the secret key in bytes
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of the public key in bytes
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of the shared secret in bytes
pub const SHARED_SECRET_SIZE: usize = 32;

/// FFI bindings to the C X25519 implementation
mod ffi {
    extern "C" {
        /// Initialize the X25519 library
        pub fn x25519_init() -> i32;

        /// Derive public key from secret key
        pub fn x25519_public_key(public_key: *mut u8, secret_key: *const u8);

        /// Compute shared secret
        pub fn x25519_shared_secret(
            shared_secret: *mut u8,
            secret_key: *const u8,
            peer_public_key: *const u8,
        ) -> i32;

        /// Generate a keypair
        pub fn x25519_keypair(public_key: *mut u8, secret_key: *const u8);

        /// Raw scalar multiplication
        pub fn x25519_scalarmult(result: *mut u8, scalar: *const u8, point: *const u8);
    }
}

/// Error type for X25519 operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Initialization failed
    InitFailed,
    /// Invalid public key (low-order point)
    InvalidPublicKey,
    /// Key derivation failed
    KeyDerivationFailed,
}

/// Result type for X25519 operations
pub type Result<T> = core::result::Result<T, Error>;

/// Initialize the X25519 library.
///
/// This is called automatically by other functions, but can be
/// called explicitly for early initialization.
pub fn init() -> Result<()> {
    let ret = unsafe { ffi::x25519_init() };
    if ret == 0 {
        Ok(())
    } else {
        Err(Error::InitFailed)
    }
}

/// X25519 secret key (private key)
///
/// Contains a 32-byte scalar. The actual DH operation uses a clamped
/// version of this scalar.
#[derive(Clone)]
pub struct SecretKey {
    bytes: [u8; SECRET_KEY_SIZE],
}

impl SecretKey {
    /// Create a secret key from raw bytes.
    ///
    /// The bytes should be generated from a cryptographically secure
    /// random number generator (e.g., `HwRng`).
    ///
    /// Note: The actual scalar used in DH operations is clamped per RFC 7748:
    /// - Bits 0, 1, 2 are cleared
    /// - Bit 255 is cleared
    /// - Bit 254 is set
    pub fn from_bytes(bytes: &[u8; SECRET_KEY_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Get the raw bytes of this secret key.
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_SIZE] {
        self.bytes
    }

    /// Get a reference to the raw bytes.
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_SIZE] {
        &self.bytes
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        let mut pk_bytes = [0u8; PUBLIC_KEY_SIZE];

        unsafe {
            ffi::x25519_init();
            ffi::x25519_public_key(pk_bytes.as_mut_ptr(), self.bytes.as_ptr());
        }

        PublicKey { bytes: pk_bytes }
    }

    /// Perform Diffie-Hellman key agreement with a peer's public key.
    ///
    /// Returns the shared secret, or an error if the peer's public key
    /// is invalid (e.g., a low-order point).
    ///
    /// IMPORTANT: The returned shared secret should be passed through a KDF
    /// (like HKDF) before using as a symmetric key.
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> Result<SharedSecret> {
        let mut shared = [0u8; SHARED_SECRET_SIZE];

        let ret = unsafe {
            ffi::x25519_shared_secret(
                shared.as_mut_ptr(),
                self.bytes.as_ptr(),
                peer_public.bytes.as_ptr(),
            )
        };

        if ret == 0 {
            Ok(SharedSecret { bytes: shared })
        } else {
            Err(Error::InvalidPublicKey)
        }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Zero out the key bytes on drop for security
        for byte in &mut self.bytes {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        // Compiler barrier to prevent optimization
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// X25519 public key
///
/// Contains a 32-byte point on Curve25519 (x-coordinate only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; PUBLIC_KEY_SIZE],
}

impl PublicKey {
    /// Create a public key from raw bytes.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Get the raw bytes of this public key.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.bytes
    }

    /// Get a reference to the raw bytes.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.bytes
    }
}

/// X25519 shared secret
///
/// Contains a 32-byte shared secret derived from DH key agreement.
///
/// IMPORTANT: This should be passed through a KDF before use as a
/// symmetric encryption key. Never use the raw shared secret directly.
#[derive(Clone)]
pub struct SharedSecret {
    bytes: [u8; SHARED_SECRET_SIZE],
}

impl SharedSecret {
    /// Create a shared secret from raw bytes.
    ///
    /// Note: This should typically only be used for testing or when you have
    /// a pre-computed shared secret from another source.
    pub fn from_bytes(bytes: &[u8; SHARED_SECRET_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Get the raw bytes of this shared secret.
    pub fn to_bytes(&self) -> [u8; SHARED_SECRET_SIZE] {
        self.bytes
    }

    /// Get a reference to the raw bytes.
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_SIZE] {
        &self.bytes
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        // Zero out the shared secret on drop for security
        for byte in &mut self.bytes {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        // Compiler barrier to prevent optimization
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Generate a keypair from random bytes.
///
/// This is a convenience function that creates a secret key and
/// derives the corresponding public key.
pub fn generate_keypair(random_bytes: &[u8; SECRET_KEY_SIZE]) -> (SecretKey, PublicKey) {
    let secret_key = SecretKey::from_bytes(random_bytes);
    let public_key = secret_key.public_key();
    (secret_key, public_key)
}

/// Perform raw X25519 scalar multiplication.
///
/// Computes: result = scalar * point
///
/// This is the low-level operation underlying both public key derivation
/// (point = basepoint) and shared secret computation (point = peer's public key).
///
/// Most users should use `SecretKey::public_key()` and `SecretKey::diffie_hellman()`
/// instead of this function.
pub fn scalarmult(
    scalar: &[u8; SECRET_KEY_SIZE],
    point: &[u8; PUBLIC_KEY_SIZE],
) -> [u8; SHARED_SECRET_SIZE] {
    let mut result = [0u8; SHARED_SECRET_SIZE];

    unsafe {
        ffi::x25519_scalarmult(result.as_mut_ptr(), scalar.as_ptr(), point.as_ptr());
    }

    result
}

#[cfg(test)]
mod tests {
    // Tests would run on target hardware
}
