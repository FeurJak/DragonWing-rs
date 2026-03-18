// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// ML-DSA (Module-Lattice-based Digital Signature Algorithm) - FIPS 204
//
// Re-exports from libcrux-iot-ml-dsa for convenient access.
//
// ML-DSA provides post-quantum digital signatures based on the Module-LWE problem.
// Available security levels:
// - ML-DSA-44: NIST Level 2 (~SHA-256/AES-128 equivalent)
// - ML-DSA-65: NIST Level 3 (~AES-192 equivalent) - RECOMMENDED
// - ML-DSA-87: NIST Level 5 (~AES-256 equivalent)

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
