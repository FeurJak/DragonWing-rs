// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// X25519 Key Agreement (RFC 7748)
//
// This module provides X25519 Diffie-Hellman key agreement.
//
// Platform-specific implementations:
// - MCU (no_std): Uses standalone C implementation optimized for embedded systems
// - Host (std): Uses pure-Rust curve25519-dalek crate
//
// X25519 is a widely-used key agreement scheme with:
// - 32-byte private keys
// - 32-byte public keys
// - 32-byte shared secrets
// - Fast key exchange
// - Constant-time implementation (resistant to timing attacks)
//
// # MCU Requirements (no_std)
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

// ============================================================================
// MCU Implementation (no_std) - Uses C FFI
// ============================================================================

#[cfg(not(feature = "std"))]
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

/// Initialize the X25519 library.
///
/// This is called automatically by other functions, but can be
/// called explicitly for early initialization.
#[cfg(not(feature = "std"))]
pub fn init() -> Result<()> {
    let ret = unsafe { ffi::x25519_init() };
    if ret == 0 {
        Ok(())
    } else {
        Err(Error::InitFailed)
    }
}

#[cfg(feature = "std")]
pub fn init() -> Result<()> {
    // No initialization needed for curve25519-dalek
    Ok(())
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
    #[cfg(not(feature = "std"))]
    pub fn public_key(&self) -> PublicKey {
        let mut pk_bytes = [0u8; PUBLIC_KEY_SIZE];

        unsafe {
            ffi::x25519_init();
            ffi::x25519_public_key(pk_bytes.as_mut_ptr(), self.bytes.as_ptr());
        }

        PublicKey { bytes: pk_bytes }
    }

    /// Derive the corresponding public key (host implementation using curve25519-dalek).
    #[cfg(feature = "std")]
    pub fn public_key(&self) -> PublicKey {
        use curve25519_dalek::montgomery::MontgomeryPoint;

        // X25519 uses the Montgomery u-coordinate of the base point (9)
        let basepoint = MontgomeryPoint([
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);

        // mul_clamped applies RFC 7748 clamping internally
        let public_point = basepoint.mul_clamped(self.bytes);
        PublicKey {
            bytes: public_point.0,
        }
    }

    /// Perform Diffie-Hellman key agreement with a peer's public key.
    ///
    /// Returns the shared secret, or an error if the peer's public key
    /// is invalid (e.g., a low-order point).
    ///
    /// IMPORTANT: The returned shared secret should be passed through a KDF
    /// (like HKDF) before using as a symmetric key.
    #[cfg(not(feature = "std"))]
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

    /// Perform Diffie-Hellman key agreement (host implementation using curve25519-dalek).
    #[cfg(feature = "std")]
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> Result<SharedSecret> {
        use curve25519_dalek::montgomery::MontgomeryPoint;

        let peer_point = MontgomeryPoint(peer_public.bytes);

        // mul_clamped applies RFC 7748 clamping internally
        let shared_point = peer_point.mul_clamped(self.bytes);

        // Check for low-order point (all zeros result)
        let all_zeros = shared_point.0.iter().all(|&b| b == 0);
        if all_zeros {
            return Err(Error::InvalidPublicKey);
        }

        Ok(SharedSecret {
            bytes: shared_point.0,
        })
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
#[cfg(not(feature = "std"))]
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

#[cfg(feature = "std")]
pub fn scalarmult(
    scalar: &[u8; SECRET_KEY_SIZE],
    point: &[u8; PUBLIC_KEY_SIZE],
) -> [u8; SHARED_SECRET_SIZE] {
    use curve25519_dalek::montgomery::MontgomeryPoint;

    let p = MontgomeryPoint(*point);

    // mul_clamped applies RFC 7748 clamping internally
    p.mul_clamped(*scalar).0
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let seed = [42u8; 32];
        let (sk, pk) = generate_keypair(&seed);
        let pk2 = sk.public_key();
        assert_eq!(pk.as_bytes(), pk2.as_bytes());
    }

    #[test]
    fn test_diffie_hellman() {
        let alice_seed = [1u8; 32];
        let bob_seed = [2u8; 32];

        let (alice_sk, alice_pk) = generate_keypair(&alice_seed);
        let (bob_sk, bob_pk) = generate_keypair(&bob_seed);

        let alice_shared = alice_sk.diffie_hellman(&bob_pk).unwrap();
        let bob_shared = bob_sk.diffie_hellman(&alice_pk).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_rfc7748_vector() {
        // Test vector from RFC 7748 Section 6.1 (Alice's keypair)
        let scalar = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];

        let sk = SecretKey::from_bytes(&scalar);
        let pk = sk.public_key();

        let expected = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];

        assert_eq!(pk.as_bytes(), &expected);
    }
}
