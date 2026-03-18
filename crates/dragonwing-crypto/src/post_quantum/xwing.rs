// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// X-Wing Hybrid KEM (draft-connolly-cfrg-xwing-kem)
//
// This module provides the X-Wing hybrid post-quantum KEM, which combines:
// - ML-KEM-768 (FIPS 203) for post-quantum security
// - X25519 (RFC 7748) for classical security
// - SHA3-256 for combining shared secrets
//
// X-Wing provides "hybrid" security: it remains secure as long as EITHER
// the classical (X25519) OR the post-quantum (ML-KEM) component is secure.
//
// Key sizes:
//   - Secret key (seed): 32 bytes
//   - Public key: 1216 bytes (1184 ML-KEM + 32 X25519)
//   - Ciphertext: 1120 bytes (1088 ML-KEM + 32 X25519)
//   - Shared secret: 32 bytes
//
// # Requirements
//
// Requires both ML-KEM-768 and X25519 features enabled:
// ```toml
// [features]
// xwing = ["x25519", "mlkem768"]
// ```
//
// # Example
//
// ```rust,no_run
// use dragonwing_crypto::post_quantum::xwing::{SecretKey, encapsulate, decapsulate};
// use dragonwing_crypto::rng::HwRng;
//
// // Generate a key pair
// let rng = HwRng::new();
// let seed: [u8; 32] = rng.random_array();
// let secret_key = SecretKey::from_seed(&seed);
// let public_key = secret_key.public_key();
//
// // Encapsulate (sender side)
// let encap_seed: [u8; 64] = rng.random_array();
// let (ciphertext, shared_secret_sender) = encapsulate(&public_key, encap_seed);
//
// // Decapsulate (receiver side)
// let shared_secret_receiver = decapsulate(&secret_key, &ciphertext);
//
// // Both sides now have the same shared secret
// assert_eq!(shared_secret_sender.as_bytes(), shared_secret_receiver.as_bytes());
// ```

use crate::classical::x25519;
use libcrux_iot_ml_kem::mlkem768;
use libcrux_iot_sha3::{sha256, shake256};
use libcrux_secrets::{Classify, Declassify};

/// KEM ID for X-Wing as per draft-connolly-cfrg-xwing-kem
pub const KEM_ID: u16 = 0x647A;

/// Size of the secret key (seed) in bytes
pub const SECRET_KEY_SIZE: usize = 32;

/// Size of the ML-KEM-768 public key
pub const MLKEM_PUBLIC_KEY_SIZE: usize = 1184;

/// Size of the X25519 public key
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// Size of the combined public key in bytes (ML-KEM + X25519)
pub const PUBLIC_KEY_SIZE: usize = MLKEM_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE; // 1216

/// Size of the ML-KEM-768 ciphertext
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1088;

/// Size of the X25519 ephemeral public key in ciphertext
pub const X25519_CIPHERTEXT_SIZE: usize = 32;

/// Size of the ciphertext in bytes (ML-KEM + X25519 ephemeral)
pub const CIPHERTEXT_SIZE: usize = MLKEM_CIPHERTEXT_SIZE + X25519_CIPHERTEXT_SIZE; // 1120

/// Size of the shared secret in bytes
pub const SHARED_SECRET_SIZE: usize = 32;

/// Size of randomness needed for key generation (for ML-KEM)
pub const KEYGEN_SEED_SIZE: usize = 64;

/// Size of randomness needed for encapsulation
pub const ENCAPS_SEED_SIZE: usize = 64; // 32 for ML-KEM + 32 for X25519

/// X-Wing domain separator label (6 bytes: 0x5c 0x2e 0x2f 0x2f 0x5e 0x5c)
/// ASCII: "\./", "/^\" concatenated = "\.//^\"
const XWING_LABEL: &[u8] = b"\\.//^\\";

/// Error type for X-Wing operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Invalid public key format
    InvalidPublicKey,
    /// Invalid ciphertext format
    InvalidCiphertext,
    /// Key derivation failed
    KeyDerivationFailed,
    /// X25519 operation failed (low-order point)
    X25519Failed,
}

/// Result type for X-Wing operations
pub type Result<T> = core::result::Result<T, Error>;

/// X-Wing secret key (decapsulation key)
///
/// Contains a 32-byte seed from which both ML-KEM and X25519 keys are derived.
/// Note: This type does not implement Clone because the ML-KEM private key
/// contains sensitive material that should not be easily copied.
pub struct SecretKey {
    /// ML-KEM-768 private key
    mlkem_sk: mlkem768::MlKem768PrivateKey,
    /// X25519 private key
    x25519_sk: x25519::SecretKey,
    /// Cached public key
    public_key: PublicKey,
}

impl SecretKey {
    /// Create a secret key from a 32-byte seed.
    ///
    /// The seed is expanded using SHAKE256 to derive both ML-KEM and X25519 keypairs.
    /// Per draft-connolly-cfrg-xwing-kem Section 5.2:
    ///   expanded = SHAKE256(sk, 96)
    ///   (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
    ///   sk_X = expanded[64:96]
    ///   pk_X = X25519(sk_X, X25519_BASE)
    pub fn from_seed(seed: &[u8; SECRET_KEY_SIZE]) -> Self {
        // Expand seed to 96 bytes using SHAKE256
        let seed_classified = seed.map(|b| b.classify());
        let expanded: [libcrux_secrets::U8; 96] = shake256(&seed_classified);

        // Convert from classified bytes back to regular bytes
        let mut expanded_bytes = [0u8; 96];
        for i in 0..96 {
            expanded_bytes[i] = expanded[i].declassify();
        }

        // ML-KEM key generation uses expanded[0:64] as the randomness
        let mut mlkem_seed = [0u8; 64];
        mlkem_seed.copy_from_slice(&expanded_bytes[0..64]);

        // Generate ML-KEM keypair
        let mlkem_kp = mlkem768::generate_key_pair(mlkem_seed);

        // X25519 secret key is expanded[64:96]
        let x25519_seed: [u8; 32] = expanded_bytes[64..96].try_into().unwrap();
        let x25519_sk = x25519::SecretKey::from_bytes(&x25519_seed);
        let x25519_pk = x25519_sk.public_key();

        // Combine public keys: pk = pk_M || pk_X
        let mut pk_bytes = [0u8; PUBLIC_KEY_SIZE];
        pk_bytes[..MLKEM_PUBLIC_KEY_SIZE].copy_from_slice(mlkem_kp.pk().as_ref());
        pk_bytes[MLKEM_PUBLIC_KEY_SIZE..].copy_from_slice(x25519_pk.as_bytes());

        // into_parts() returns (private_key, public_key)
        let (mlkem_sk, _mlkem_pk) = mlkem_kp.into_parts();

        Self {
            mlkem_sk,
            x25519_sk,
            public_key: PublicKey { bytes: pk_bytes },
        }
    }

    /// Get the corresponding public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Decapsulate a ciphertext to recover the shared secret.
    pub fn decapsulate(&self, ciphertext: &Ciphertext) -> SharedSecret {
        // Split ciphertext into ML-KEM and X25519 parts
        let (mlkem_ct_bytes, x25519_ek) = ciphertext.bytes.split_at(MLKEM_CIPHERTEXT_SIZE);

        // Decapsulate ML-KEM
        let mlkem_ct = mlkem768::MlKem768Ciphertext::from(
            <&[u8; MLKEM_CIPHERTEXT_SIZE]>::try_from(mlkem_ct_bytes).unwrap(),
        );
        let mlkem_ss = mlkem768::decapsulate(&self.mlkem_sk, &mlkem_ct);

        // Compute X25519 shared secret
        let x25519_ek_pk = x25519::PublicKey::from_bytes(
            <&[u8; X25519_PUBLIC_KEY_SIZE]>::try_from(x25519_ek).unwrap(),
        );
        let x25519_ss = self
            .x25519_sk
            .diffie_hellman(&x25519_ek_pk)
            .unwrap_or_else(|_| {
                // In case of low-order point, use zeros (this maintains constant-time behavior)
                // The combined hash will still be unpredictable to attackers
                x25519::SharedSecret::from_bytes(&[0u8; 32])
            });

        // Combine shared secrets using X-Wing combiner
        // ss = SHA3-256(XWING_LABEL || mlkem_ss || x25519_ss || x25519_ek || x25519_pk)
        Self::combine_secrets(
            mlkem_ss.as_ref(),
            x25519_ss.as_bytes(),
            x25519_ek,
            &self.public_key.bytes[MLKEM_PUBLIC_KEY_SIZE..],
        )
    }

    /// Combine the component shared secrets into the final X-Wing shared secret.
    ///
    /// Per draft-connolly-cfrg-xwing-kem Section 5.3:
    /// ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
    fn combine_secrets(
        mlkem_ss: &[u8],
        x25519_ss: &[u8],
        x25519_ct: &[u8], // ct_X = ephemeral public key
        x25519_pk: &[u8],
    ) -> SharedSecret {
        // Concatenate: mlkem_ss || x25519_ss || x25519_ct || x25519_pk || XWING_LABEL
        // Total: 32 + 32 + 32 + 32 + 6 = 134 bytes
        let mut input = [0u8; 134];
        input[0..32].copy_from_slice(mlkem_ss);
        input[32..64].copy_from_slice(x25519_ss);
        input[64..96].copy_from_slice(x25519_ct);
        input[96..128].copy_from_slice(x25519_pk);
        input[128..134].copy_from_slice(XWING_LABEL);

        // Convert to classified bytes for SHA3-256
        let input_classified = input.map(|b| b.classify());
        let hash_classified = sha256(&input_classified);

        // Convert back to regular bytes
        let mut hash = [0u8; 32];
        for i in 0..32 {
            hash[i] = hash_classified[i].declassify();
        }

        SharedSecret { bytes: hash }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Note: mlkem_sk and x25519_sk implement their own secure drop
        // Zero out the public key cache as well
        for byte in &mut self.public_key.bytes {
            unsafe {
                core::ptr::write_volatile(byte, 0);
            }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// X-Wing public key (encapsulation key)
///
/// Contains the concatenation of ML-KEM-768 public key and X25519 public key.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Get the ML-KEM-768 public key portion.
    pub fn mlkem_public_key(&self) -> &[u8; MLKEM_PUBLIC_KEY_SIZE] {
        self.bytes[..MLKEM_PUBLIC_KEY_SIZE].try_into().unwrap()
    }

    /// Get the X25519 public key portion.
    pub fn x25519_public_key(&self) -> &[u8; X25519_PUBLIC_KEY_SIZE] {
        self.bytes[MLKEM_PUBLIC_KEY_SIZE..].try_into().unwrap()
    }

    /// Encapsulate a shared secret to this public key.
    ///
    /// Requires 64 bytes of randomness (32 for ML-KEM, 32 for X25519).
    pub fn encapsulate(&self, randomness: [u8; ENCAPS_SEED_SIZE]) -> (Ciphertext, SharedSecret) {
        let (mlkem_rand, x25519_rand) = randomness.split_at(32);
        let mlkem_rand: [u8; 32] = mlkem_rand.try_into().unwrap();
        let x25519_rand: [u8; 32] = x25519_rand.try_into().unwrap();

        // Encapsulate to ML-KEM public key
        let mlkem_pk = mlkem768::MlKem768PublicKey::from(self.mlkem_public_key());
        let (mlkem_ct, mlkem_ss) = mlkem768::encapsulate(&mlkem_pk, mlkem_rand);

        // Generate ephemeral X25519 keypair and compute shared secret
        let x25519_ek_sk = x25519::SecretKey::from_bytes(&x25519_rand);
        let x25519_ek_pk = x25519_ek_sk.public_key();
        let x25519_pk = x25519::PublicKey::from_bytes(self.x25519_public_key());
        let x25519_ss = x25519_ek_sk.diffie_hellman(&x25519_pk).unwrap_or_else(|_| {
            // Handle low-order point (shouldn't happen with valid keys)
            x25519::SharedSecret::from_bytes(&[0u8; 32])
        });

        // Combine ciphertexts
        let mut ct_bytes = [0u8; CIPHERTEXT_SIZE];
        ct_bytes[..MLKEM_CIPHERTEXT_SIZE].copy_from_slice(mlkem_ct.as_ref());
        ct_bytes[MLKEM_CIPHERTEXT_SIZE..].copy_from_slice(x25519_ek_pk.as_bytes());

        // Combine shared secrets
        let shared_secret = SecretKey::combine_secrets(
            mlkem_ss.as_ref(),
            x25519_ss.as_bytes(),
            x25519_ek_pk.as_bytes(),
            self.x25519_public_key(),
        );

        (Ciphertext { bytes: ct_bytes }, shared_secret)
    }
}

/// X-Wing ciphertext
///
/// Contains the concatenation of ML-KEM-768 ciphertext and X25519 ephemeral public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    bytes: [u8; CIPHERTEXT_SIZE],
}

impl Ciphertext {
    /// Create a ciphertext from raw bytes.
    pub fn from_bytes(bytes: &[u8; CIPHERTEXT_SIZE]) -> Self {
        Self { bytes: *bytes }
    }

    /// Get the raw bytes of this ciphertext.
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_SIZE] {
        self.bytes
    }

    /// Get a reference to the raw bytes.
    pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_SIZE] {
        &self.bytes
    }

    /// Get the ML-KEM-768 ciphertext portion.
    pub fn mlkem_ciphertext(&self) -> &[u8; MLKEM_CIPHERTEXT_SIZE] {
        self.bytes[..MLKEM_CIPHERTEXT_SIZE].try_into().unwrap()
    }

    /// Get the X25519 ephemeral public key portion.
    pub fn x25519_ephemeral(&self) -> &[u8; X25519_CIPHERTEXT_SIZE] {
        self.bytes[MLKEM_CIPHERTEXT_SIZE..].try_into().unwrap()
    }
}

/// X-Wing shared secret
///
/// Contains a 32-byte shared secret derived from both ML-KEM and X25519.
#[derive(Clone)]
pub struct SharedSecret {
    bytes: [u8; SHARED_SECRET_SIZE],
}

impl SharedSecret {
    /// Create a shared secret from raw bytes.
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
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Generate a keypair from a 32-byte seed.
///
/// This is a convenience function that creates a SecretKey and extracts its PublicKey.
pub fn generate_keypair(seed: &[u8; SECRET_KEY_SIZE]) -> (SecretKey, PublicKey) {
    let sk = SecretKey::from_seed(seed);
    let pk = sk.public_key().clone();
    (sk, pk)
}

/// Encapsulate a shared secret to a public key.
///
/// Requires 64 bytes of randomness (32 for ML-KEM, 32 for X25519 ephemeral key).
pub fn encapsulate(
    pk: &PublicKey,
    randomness: [u8; ENCAPS_SEED_SIZE],
) -> (Ciphertext, SharedSecret) {
    pk.encapsulate(randomness)
}

/// Decapsulate a ciphertext using a secret key.
pub fn decapsulate(sk: &SecretKey, ct: &Ciphertext) -> SharedSecret {
    sk.decapsulate(ct)
}

#[cfg(test)]
mod tests {
    // Tests would run on target hardware
}
