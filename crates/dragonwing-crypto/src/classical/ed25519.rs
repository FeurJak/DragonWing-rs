// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Ed25519 Digital Signatures (RFC 8032)
//
// This module provides Ed25519 signature operations using a standalone
// C implementation optimized for embedded systems.
//
// Ed25519 is a widely-used digital signature scheme with:
// - 32-byte private keys (seeds)
// - 32-byte public keys
// - 64-byte signatures
// - Fast signing and verification
// - Resistance to timing attacks
//
// # Requirements
//
// Include the C source file in your Zephyr application:
// ```cmake
// target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/dragonwing-crypto/c/ed25519.c)
// ```
//
// For SHA-512, the implementation will use mbedTLS if available (CONFIG_MBEDTLS=y),
// otherwise it falls back to a built-in implementation.
//
// # Example
//
// ```rust,no_run
// use dragonwing_crypto::classical::ed25519::{SecretKey, Signature};
// use dragonwing_crypto::rng::HwRng;
//
// // Generate a key pair
// let rng = HwRng::new();
// let seed: [u8; 32] = rng.random_array();
// let secret_key = SecretKey::from_seed(&seed);
// let public_key = secret_key.public_key();
//
// // Sign a message
// let message = b"Hello, Ed25519!";
// let signature = secret_key.sign(message);
//
// // Verify the signature
// assert!(public_key.verify(message, &signature));
// ```

/// Size of the secret key (seed) in bytes
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of the public key in bytes
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of a signature in bytes
pub const SIGNATURE_SIZE: usize = 64;

/// FFI bindings to the C Ed25519 implementation
mod ffi {
    extern "C" {
        /// Initialize the Ed25519 library
        pub fn ed25519_init() -> i32;

        /// Derive public key from secret key
        pub fn ed25519_get_pubkey(public_key: *mut u8, secret_key: *const u8);

        /// Create a key pair from a seed
        pub fn ed25519_create_keypair(public_key: *mut u8, secret_key: *const u8);

        /// Sign a message
        pub fn ed25519_sign(
            signature: *mut u8,
            message: *const u8,
            message_len: usize,
            secret_key: *const u8,
            public_key: *const u8,
        );

        /// Verify a signature
        pub fn ed25519_verify(
            signature: *const u8,
            message: *const u8,
            message_len: usize,
            public_key: *const u8,
        ) -> i32;
    }
}

/// Error type for Ed25519 operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Initialization failed
    InitFailed,
    /// Invalid signature
    InvalidSignature,
    /// Invalid public key
    InvalidPublicKey,
}

/// Result type for Ed25519 operations
pub type Result<T> = core::result::Result<T, Error>;

/// Initialize the Ed25519 library.
///
/// This is called automatically by other functions, but can be
/// called explicitly for early initialization.
pub fn init() -> Result<()> {
    let ret = unsafe { ffi::ed25519_init() };
    if ret == 0 {
        Ok(())
    } else {
        Err(Error::InitFailed)
    }
}

/// Ed25519 secret key (private key / signing key)
///
/// Contains a 32-byte seed. The actual signing key is derived
/// from this seed using SHA-512.
#[derive(Clone)]
pub struct SecretKey {
    seed: [u8; SECRET_KEY_SIZE],
    public_key: [u8; PUBLIC_KEY_SIZE],
}

impl SecretKey {
    /// Create a secret key from a 32-byte seed.
    ///
    /// The seed should be generated from a cryptographically secure
    /// random number generator (e.g., `HwRng`).
    pub fn from_seed(seed: &[u8; SECRET_KEY_SIZE]) -> Self {
        let mut public_key = [0u8; PUBLIC_KEY_SIZE];

        unsafe {
            ffi::ed25519_init();
            ffi::ed25519_get_pubkey(public_key.as_mut_ptr(), seed.as_ptr());
        }

        Self {
            seed: *seed,
            public_key,
        }
    }

    /// Get the seed bytes.
    pub fn to_seed(&self) -> [u8; SECRET_KEY_SIZE] {
        self.seed
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            bytes: self.public_key,
        }
    }

    /// Sign a message.
    ///
    /// Returns a 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];

        unsafe {
            ffi::ed25519_sign(
                sig_bytes.as_mut_ptr(),
                message.as_ptr(),
                message.len(),
                self.seed.as_ptr(),
                self.public_key.as_ptr(),
            );
        }

        Signature(sig_bytes)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Zero out the seed on drop for security
        for byte in &mut self.seed {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        // Compiler barrier to prevent optimization
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Ed25519 public key (verification key)
///
/// Contains a 32-byte compressed point on the Ed25519 curve.
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

    /// Verify a signature on a message.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let ret = unsafe {
            ffi::ed25519_verify(
                signature.0.as_ptr(),
                message.as_ptr(),
                message.len(),
                self.bytes.as_ptr(),
            )
        };
        ret == 1
    }

    /// Verify a signature, returning a Result.
    pub fn verify_strict(&self, message: &[u8], signature: &Signature) -> Result<()> {
        if self.verify(message, signature) {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

/// Ed25519 signature
///
/// Contains a 64-byte signature (R, S components).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; SIGNATURE_SIZE]);

impl Signature {
    /// Create a signature from raw bytes.
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Get the raw bytes of this signature.
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.0
    }

    /// Get a reference to the raw bytes.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    // Tests would run on target hardware
}
