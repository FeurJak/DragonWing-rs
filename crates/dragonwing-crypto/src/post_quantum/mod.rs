// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Post-Quantum Cryptography Modules
//
// This module provides access to post-quantum cryptographic primitives:
// - ML-KEM (FIPS 203) for key encapsulation
// - ML-DSA (FIPS 204) for digital signatures
// - X-Wing hybrid KEM (ML-KEM-768 + X25519)

/// ML-KEM (Module-Lattice-based Key Encapsulation Mechanism) - FIPS 203
///
/// Re-exports from libcrux-iot-ml-kem.
pub mod mlkem;

/// ML-DSA (Module-Lattice-based Digital Signature Algorithm) - FIPS 204
///
/// Re-exports from libcrux-iot-ml-dsa.
pub mod mldsa;

/// X-Wing hybrid post-quantum KEM (ML-KEM-768 + X25519).
///
/// Provides hybrid security: remains secure as long as EITHER
/// the classical (X25519) OR the post-quantum (ML-KEM) component is secure.
#[cfg(feature = "xwing")]
pub mod xwing;
