// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Hardware Random Number Generator (HWRNG) for Zephyr
//
// This module provides cryptographically secure randomness using the
// STM32U585's True Random Number Generator (TRNG) peripheral via Zephyr's
// entropy subsystem.
//
// # Setup Requirements
//
// 1. Add to your `prj.conf`:
//    ```
//    CONFIG_ENTROPY_GENERATOR=y
//    CONFIG_ENTROPY_DEVICE_RANDOM_GENERATOR=y
//    ```
//
// 2. Enable RNG in device tree overlay (if not already enabled):
//    ```dts
//    &rng {
//        status = "okay";
//    };
//    ```
//
// 3. Add the C wrapper to your CMakeLists.txt. Copy the file from
//    `dragonwing-crypto/c/hwrng.c` to your project's C source directory
//    and add it to your build:
//    ```cmake
//    target_sources(app PRIVATE src/c/hwrng.c)
//    ```
//
// # Example
//
// ```rust,no_run
// use dragonwing_crypto::rng::HwRng;
// use dragonwing_crypto::kem;
//
// let rng = HwRng::new();
//
// // Generate randomness for ML-KEM key generation (64 bytes)
// let keygen_seed: [u8; kem::KEYGEN_SEED_SIZE] = rng.random_array();
// let keypair = kem::generate_key_pair(keygen_seed);
//
// // Generate randomness for encapsulation (32 bytes)
// let encaps_seed: [u8; kem::ENCAPS_SEED_SIZE] = rng.random_array();
// let (ciphertext, shared_secret) = kem::encapsulate(keypair.public_key(), encaps_seed);
// ```

extern "C" {
    /// C wrapper around Zephyr's sys_rand_get()
    ///
    /// This function is defined in `c/hwrng.c` and must be compiled into your
    /// Zephyr application. It fills the buffer with random bytes from the
    /// hardware entropy source.
    fn hwrng_fill_bytes(dst: *mut u8, len: usize);
}

/// Hardware Random Number Generator using Zephyr's entropy subsystem.
///
/// On STM32U585, this uses the True Random Number Generator (TRNG) peripheral
/// which provides cryptographically secure randomness from physical entropy
/// sources (thermal noise).
///
/// # Thread Safety
///
/// This struct is zero-sized and stateless - multiple instances can be created
/// and used concurrently. The underlying Zephyr entropy API handles thread safety.
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::rng::HwRng;
///
/// let rng = HwRng::new();
///
/// // Fill a buffer with random bytes
/// let mut buffer = [0u8; 32];
/// rng.fill_bytes(&mut buffer);
///
/// // Or generate a fixed-size array directly
/// let random_bytes: [u8; 64] = rng.random_array();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct HwRng;

impl HwRng {
    /// Create a new hardware RNG instance.
    ///
    /// This is a zero-cost operation as `HwRng` is stateless.
    #[inline]
    pub const fn new() -> Self {
        Self
    }

    /// Fill a buffer with random bytes from the hardware TRNG.
    ///
    /// # Arguments
    ///
    /// * `dest` - The buffer to fill with random bytes
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// let rng = HwRng::new();
    /// let mut seed = [0u8; 32];
    /// rng.fill_bytes(&mut seed);
    /// ```
    #[inline]
    pub fn fill_bytes(&self, dest: &mut [u8]) {
        if !dest.is_empty() {
            unsafe {
                hwrng_fill_bytes(dest.as_mut_ptr(), dest.len());
            }
        }
    }

    /// Generate a fixed-size array of random bytes.
    ///z
    /// This is a convenience method for generating randomness of a known size
    /// at compile time, which is common for cryptographic operations.
    ///
    /// # Type Parameters
    ///
    /// * `N` - The number of random bytes to generate
    ///
    /// # Returns
    ///
    /// An array of `N` random bytes
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// let rng = HwRng::new();
    ///
    /// // Generate 64 bytes for ML-KEM key generation
    /// let keygen_randomness: [u8; 64] = rng.random_array();
    ///
    /// // Generate 32 bytes for ML-DSA signing
    /// let signing_randomness: [u8; 32] = rng.random_array();
    /// ```
    #[inline]
    pub fn random_array<const N: usize>(&self) -> [u8; N] {
        let mut buf = [0u8; N];
        self.fill_bytes(&mut buf);
        buf
    }

    /// Generate randomness for ML-KEM key generation.
    ///
    /// Returns 64 bytes of random data suitable for `kem::generate_key_pair()`.
    #[cfg(feature = "mlkem768")]
    #[inline]
    pub fn mlkem_keygen_randomness(&self) -> [u8; crate::kem::KEYGEN_SEED_SIZE] {
        self.random_array()
    }

    /// Generate randomness for ML-KEM encapsulation.
    ///
    /// Returns 32 bytes of random data suitable for `kem::encapsulate()`.
    #[cfg(feature = "mlkem768")]
    #[inline]
    pub fn mlkem_encaps_randomness(&self) -> [u8; crate::kem::ENCAPS_SEED_SIZE] {
        self.random_array()
    }

    /// Generate randomness for ML-DSA key generation.
    ///
    /// Returns 32 bytes of random data suitable for `dsa::generate_key_pair()`.
    #[cfg(feature = "mldsa65")]
    #[inline]
    pub fn mldsa_keygen_randomness(&self) -> [u8; crate::dsa::KEYGEN_RANDOMNESS_SIZE] {
        self.random_array()
    }

    /// Generate randomness for ML-DSA signing.
    ///
    /// Returns 32 bytes of random data suitable for `dsa::sign()`.
    #[cfg(feature = "mldsa65")]
    #[inline]
    pub fn mldsa_signing_randomness(&self) -> [u8; crate::dsa::SIGNING_RANDOMNESS_SIZE] {
        self.random_array()
    }
}

// Implement rand_core 0.6 traits for compatibility with curve25519-dalek
// (used by SAGA module)
#[cfg(feature = "saga")]
impl rand_core::RngCore for HwRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Delegate to our existing fill_bytes implementation
        HwRng::fill_bytes(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// HwRng is a cryptographically secure RNG (backed by hardware TRNG)
#[cfg(feature = "saga")]
impl rand_core::CryptoRng for HwRng {}
