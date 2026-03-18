// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// ML-KEM (Module-Lattice-based Key Encapsulation Mechanism) - FIPS 203
//
// Re-exports from libcrux-iot-ml-kem for convenient access.
//
// ML-KEM provides post-quantum key encapsulation based on the Module-LWE problem.
// Available security levels:
// - ML-KEM-512: NIST Level 1 (~AES-128 equivalent)
// - ML-KEM-768: NIST Level 3 (~AES-192 equivalent) - RECOMMENDED
// - ML-KEM-1024: NIST Level 5 (~AES-256 equivalent)

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
