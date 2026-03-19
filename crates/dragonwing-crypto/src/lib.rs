// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// DragonWing Cryptography Library
//
// Provides cryptographic primitives for the Arduino Uno Q:
//
// Post-Quantum Cryptography (via libcrux-iot):
// - ML-KEM (FIPS 203) for key encapsulation
// - ML-DSA (FIPS 204) for digital signatures
//
// Classical Cryptography (via mbedTLS PSA Crypto):
// - Ed25519 (RFC 8032) for digital signatures
//
// Common:
// - Hardware RNG integration via Zephyr's entropy API
//
// This library provides a unified interface for cryptographic operations
// on the STM32U585 MCU.

#![no_std]

// Re-export libcrux_secrets for classified byte handling
pub use libcrux_secrets;

/// Hardware Random Number Generator using Zephyr's entropy subsystem.
///
/// Provides cryptographically secure randomness from the STM32U585's TRNG.
/// See the module documentation for setup requirements.
pub mod rng;

/// Hash functions for key derivation and integrity.
///
/// Provides:
/// - [`hash::sha256`] - SHA-256 hash (requires `xwing` feature)
#[cfg(feature = "xwing")]
pub mod hash;

/// Post-quantum cryptography modules.
///
/// Provides:
/// - [`post_quantum::mlkem`] - ML-KEM key encapsulation (FIPS 203)
/// - [`post_quantum::mldsa`] - ML-DSA digital signatures (FIPS 204)
/// - [`post_quantum::xwing`] - X-Wing hybrid KEM (ML-KEM-768 + X25519)
pub mod post_quantum;

/// Classical cryptography modules.
///
/// Provides:
/// - [`classical::ed25519`] - Ed25519 digital signatures (RFC 8032)
/// - [`classical::x25519`] - X25519 key agreement (RFC 7748)
/// - [`classical::xchacha20poly1305`] - XChaCha20-Poly1305 AEAD
pub mod classical;

/// SAGA anonymous credential scheme (BBS-style MAC).
///
/// Provides:
/// - MAC-based credentials with zero-knowledge proofs
/// - Unlinkable presentations (same credential cannot be correlated across uses)
/// - Selective disclosure of attributes
///
/// Note: SAGA is MAC-based, requiring the issuer's secret key for verification.
/// This differs from BBS+ signatures which support public verification.
///
/// See the module documentation for usage examples.
#[cfg(feature = "saga")]
pub mod saga;

/// PSA Secure Storage and Crypto Key Management.
///
/// Provides:
/// - [`psa::its`] - Internal Trusted Storage for encrypted data
/// - [`psa::crypto`] - Key generation, import, export, destruction
///
/// Data is encrypted at rest using AEAD with a device-unique key.
/// Supports persistent storage that survives device reboots.
///
/// See the module documentation for setup requirements.
#[cfg(feature = "psa")]
pub mod psa;

/// Experimental protocols combining multiple cryptographic primitives.
///
/// Provides:
/// - [`experimental::saga_xwing`] - SAGA + X-Wing hybrid protocol
pub mod experimental;

// ============================================================================
// Convenience Re-exports
// ============================================================================

/// Re-export ML-KEM types and functions
pub mod mlkem {
    #[cfg(feature = "mlkem512")]
    pub use libcrux_iot_ml_kem::mlkem512;

    #[cfg(feature = "mlkem768")]
    pub use libcrux_iot_ml_kem::mlkem768;

    #[cfg(feature = "mlkem1024")]
    pub use libcrux_iot_ml_kem::mlkem1024;

    // Re-export common types
    #[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
    pub use libcrux_iot_ml_kem::{
        MlKemCiphertext, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, MlKemSharedSecret,
        ENCAPS_SEED_SIZE, KEY_GENERATION_SEED_SIZE, SHARED_SECRET_SIZE,
    };
}

/// Re-export ML-DSA types and functions
pub mod mldsa {
    #[cfg(feature = "mldsa44")]
    pub use libcrux_iot_ml_dsa::ml_dsa_44;

    #[cfg(feature = "mldsa65")]
    pub use libcrux_iot_ml_dsa::ml_dsa_65;

    #[cfg(feature = "mldsa87")]
    pub use libcrux_iot_ml_dsa::ml_dsa_87;

    // Re-export common types and error types
    #[cfg(any(feature = "mldsa44", feature = "mldsa65", feature = "mldsa87"))]
    pub use libcrux_iot_ml_dsa::{
        MLDSAKeyPair, MLDSASignature, MLDSASigningKey, MLDSAVerificationKey, SigningError,
        VerificationError, KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE,
    };
}

/// ML-KEM 768 convenience module (recommended security level)
#[cfg(feature = "mlkem768")]
pub mod kem {
    use libcrux_iot_ml_kem::mlkem768;

    /// Size of the public key in bytes
    pub const PUBLIC_KEY_SIZE: usize = mlkem768::MlKem768PublicKey::len();

    /// Size of the private key in bytes  
    pub const PRIVATE_KEY_SIZE: usize = mlkem768::MlKem768PrivateKey::len();

    /// Size of the ciphertext in bytes
    pub const CIPHERTEXT_SIZE: usize = mlkem768::MlKem768Ciphertext::len();

    /// Size of the shared secret in bytes
    pub const SHARED_SECRET_SIZE: usize = 32;

    /// Size of randomness needed for key generation
    pub const KEYGEN_SEED_SIZE: usize = 64;

    /// Size of randomness needed for encapsulation
    pub const ENCAPS_SEED_SIZE: usize = 32;

    /// Public key type
    pub type PublicKey = mlkem768::MlKem768PublicKey;

    /// Private key type
    pub type PrivateKey = mlkem768::MlKem768PrivateKey;

    /// Key pair type
    pub type KeyPair = mlkem768::MlKem768KeyPair;

    /// Ciphertext type
    pub type Ciphertext = mlkem768::MlKem768Ciphertext;

    /// Shared secret type (32 bytes)
    pub type SharedSecret = libcrux_iot_ml_kem::MlKemSharedSecret;

    /// Generate a new ML-KEM 768 key pair
    ///
    /// # Arguments
    /// * `randomness` - 64 bytes of random data for key generation
    ///
    /// # Returns
    /// A key pair containing public and private keys
    pub fn generate_key_pair(randomness: [u8; KEYGEN_SEED_SIZE]) -> KeyPair {
        mlkem768::generate_key_pair(randomness)
    }

    /// Encapsulate a shared secret to a public key
    ///
    /// # Arguments
    /// * `public_key` - The recipient's public key
    /// * `randomness` - 32 bytes of random data
    ///
    /// # Returns
    /// A tuple of (ciphertext, shared_secret)
    pub fn encapsulate(
        public_key: &PublicKey,
        randomness: [u8; ENCAPS_SEED_SIZE],
    ) -> (Ciphertext, SharedSecret) {
        mlkem768::encapsulate(public_key, randomness)
    }

    /// Decapsulate a shared secret from a ciphertext
    ///
    /// # Arguments
    /// * `private_key` - The recipient's private key
    /// * `ciphertext` - The ciphertext from encapsulation
    ///
    /// # Returns
    /// The shared secret (32 bytes)
    pub fn decapsulate(private_key: &PrivateKey, ciphertext: &Ciphertext) -> SharedSecret {
        mlkem768::decapsulate(private_key, ciphertext)
    }

    /// Validate a public key
    ///
    /// # Arguments
    /// * `public_key` - The public key to validate
    ///
    /// # Returns
    /// True if the public key is valid
    pub fn validate_public_key(public_key: &PublicKey) -> bool {
        mlkem768::validate_public_key(public_key)
    }

    /// Create a public key from bytes
    ///
    /// # Arguments
    /// * `bytes` - Serialized public key bytes
    ///
    /// # Returns
    /// The public key
    pub fn public_key_from_bytes(bytes: &[u8; PUBLIC_KEY_SIZE]) -> PublicKey {
        PublicKey::from(bytes)
    }

    /// Create a ciphertext from bytes
    ///
    /// # Arguments
    /// * `bytes` - Serialized ciphertext bytes
    ///
    /// # Returns
    /// The ciphertext
    pub fn ciphertext_from_bytes(bytes: &[u8; CIPHERTEXT_SIZE]) -> Ciphertext {
        Ciphertext::from(bytes)
    }
}

/// ML-DSA 65 convenience module (recommended security level - NIST Level 3)
#[cfg(feature = "mldsa65")]
pub mod dsa {
    use libcrux_iot_ml_dsa::ml_dsa_65;
    use libcrux_secrets::{Classify, U8};

    // Re-export error types
    pub use libcrux_iot_ml_dsa::{SigningError, VerificationError};

    /// Size of the verification key in bytes
    pub const VERIFICATION_KEY_SIZE: usize = 1952;

    /// Size of the signing key in bytes
    pub const SIGNING_KEY_SIZE: usize = 4032;

    /// Size of the signature in bytes
    pub const SIGNATURE_SIZE: usize = 3309;

    /// Size of randomness needed for key generation (32 bytes)
    pub const KEYGEN_RANDOMNESS_SIZE: usize = 32;

    /// Size of randomness needed for signing (32 bytes)
    pub const SIGNING_RANDOMNESS_SIZE: usize = 32;

    /// Verification key type
    pub type VerificationKey = ml_dsa_65::MLDSA65VerificationKey;

    /// Signing key type
    pub type SigningKey = ml_dsa_65::MLDSA65SigningKey;

    /// Key pair type
    pub type KeyPair = ml_dsa_65::MLDSA65KeyPair;

    /// Signature type
    pub type Signature = ml_dsa_65::MLDSA65Signature;

    /// Generate a new ML-DSA 65 key pair
    ///
    /// # Arguments
    /// * `randomness` - 32 bytes of random data for key generation
    ///
    /// # Returns
    /// A key pair containing signing and verification keys
    pub fn generate_key_pair(randomness: [u8; KEYGEN_RANDOMNESS_SIZE]) -> KeyPair {
        // Convert to classified bytes
        let classified: [U8; KEYGEN_RANDOMNESS_SIZE] = randomness.map(|b| b.classify());
        ml_dsa_65::generate_key_pair(classified)
    }

    /// Sign a message with ML-DSA 65
    ///
    /// # Arguments
    /// * `signing_key` - The signer's signing key
    /// * `message` - The message to sign
    /// * `context` - Domain separation context (up to 255 bytes, can be empty)
    /// * `randomness` - 32 bytes of random data for signing
    ///
    /// # Returns
    /// The signature, or an error if signing fails
    pub fn sign(
        signing_key: &SigningKey,
        message: &[u8],
        context: &[u8],
        randomness: [u8; SIGNING_RANDOMNESS_SIZE],
    ) -> Result<Signature, SigningError> {
        // Convert to classified bytes
        let classified: [U8; SIGNING_RANDOMNESS_SIZE] = randomness.map(|b| b.classify());
        ml_dsa_65::sign(signing_key, message, context, classified)
    }

    /// Verify an ML-DSA 65 signature
    ///
    /// # Arguments
    /// * `verification_key` - The signer's verification key
    /// * `message` - The message that was signed
    /// * `context` - Domain separation context (must match what was used during signing)
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    /// Ok(()) if the signature is valid, or a VerificationError otherwise
    pub fn verify(
        verification_key: &VerificationKey,
        message: &[u8],
        context: &[u8],
        signature: &Signature,
    ) -> Result<(), VerificationError> {
        ml_dsa_65::verify(verification_key, message, context, signature)
    }

    /// Create a signature from raw bytes
    ///
    /// # Arguments
    /// * `bytes` - The signature bytes (must be SIGNATURE_SIZE bytes)
    ///
    /// # Returns
    /// The signature
    pub fn signature_from_bytes(bytes: [u8; SIGNATURE_SIZE]) -> Signature {
        Signature::new(bytes)
    }
}
