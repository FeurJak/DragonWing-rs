//! SAGA - BBS-style MAC scheme for anonymous credentials.
//!
//! This module implements the SAGA anonymous credential scheme based on
//! BBS+ style MACs, providing:
//! - MAC-based credentials with zero-knowledge proofs
//! - Unlinkable presentations
//! - Selective disclosure proofs
//!
//! # no_std Compatibility
//!
//! This implementation is fully `no_std` compatible using fixed-size arrays
//! instead of heap-allocated vectors. The maximum number of attributes is
//! defined at compile time via the `MAX_ATTRS` constant.
//!
//! # Usage
//!
//! ```ignore
//! use dragonwing_crypto::saga::{KeyPair, Parameters, MAX_ATTRS};
//! use dragonwing_crypto::rng::HardwareRng;
//!
//! let mut rng = HardwareRng::new();
//!
//! // Setup with 3 attributes
//! let keypair = KeyPair::setup(&mut rng, 3).unwrap();
//!
//! // Create messages (as curve points)
//! let messages = [...]; // Your attribute points
//!
//! // Issue a credential (MAC)
//! let tag = keypair.mac(&mut rng, &messages).unwrap();
//!
//! // Verify the MAC (holder side, with public key)
//! assert!(tag.verify(keypair.params(), keypair.pk(), &messages));
//!
//! // Create unlinkable presentation
//! let predicate = tag.get_predicate(&mut rng, keypair.params(), keypair.pk(), &messages).unwrap();
//! let presentation = predicate.presentation();
//!
//! // Verify presentation (issuer side, with secret key)
//! assert!(keypair.verify_presentation(&presentation, predicate.commitments()).unwrap());
//! ```
//!
//! # Security
//!
//! SAGA provides:
//! - **Unforgeability**: Only the issuer (with secret key) can create valid tags
//! - **Unlinkability**: Same credential shown twice cannot be correlated  
//! - **Zero-knowledge**: Proofs reveal nothing beyond validity
//!
//! Note: SAGA is MAC-based, so verification requires the secret key (or
//! delegation to a designated verifier). This differs from BBS+ signatures
//! which support public verification.

mod errors;
mod mac;
mod nizk;
mod types;

pub use errors::SagaError;
pub use mac::{Proof, Tag, PROOF_SIZE, TAG_SIZE};
pub use nizk::{Predicate, Presentation, PRESENTATION_SIZE};
pub use types::{
    KeyPair, Parameters, Point, PointExt, PublicKey, Scalar, ScalarExt, SecretKey, KEY_PAIR_SIZE,
    MAX_ATTRS, NUM_ATTRS_SIZE, PARAMETERS_SIZE, POINT_SIZE, PUBLIC_KEY_SIZE, SCALAR_SIZE,
    SECRET_KEY_SIZE,
};

// Re-export Identity trait so users can call Point::identity()
pub use curve25519_dalek::traits::Identity;

/// Protocol name for domain separation in hash-to-scalar
pub(crate) const PROT_NAME_MAC: &[u8] = b"AKVAC-BBSsaga-MAC";

/// Scalar multiplication: s * P
#[inline]
pub fn smul(p: &Point, s: &Scalar) -> Point {
    s * p
}

/// Hash arbitrary bytes to a scalar using SHA-256
#[inline]
pub fn hash_to_scalar(bytes: &[u8]) -> Scalar {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&d);
    Scalar::from_bytes_mod_order(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;

    // Mock RNG for testing (deterministic)
    struct MockRng(u64);

    impl MockRng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }
    }

    impl rand_core::RngCore for MockRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            // Simple LCG
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            self.0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let val = self.next_u64();
                let bytes = val.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for MockRng {}

    #[test]
    fn test_full_saga_flow() {
        let mut rng = MockRng::new(42);
        let l = 3;

        // 1) Setup
        let keypair = KeyPair::setup(&mut rng, l).unwrap();
        let params = keypair.params();
        let pk = keypair.pk();

        // 2) Create messages as points (hash-free demo using multiples of G)
        let mut messages = [Point::identity(); MAX_ATTRS];
        for i in 0..l {
            let s = Scalar::from(i as u64);
            messages[i] = smul(&params.g, &s);
        }

        // 3) Compute MAC
        let tag = keypair.mac(&mut rng, &messages[..l]).unwrap();

        // 4) MAC Verification (Holder side with public key)
        let ok = tag.verify(params, pk, &messages[..l]);
        assert!(ok, "MAC verification failed");

        // 5) Create predicate/presentation
        let predicate = tag
            .get_predicate(&mut rng, params, pk, &messages[..l])
            .unwrap();
        let presentation = predicate.presentation();

        // 6) Holder predicate check
        let ok = predicate.check(params, pk).unwrap();
        assert!(ok, "predicate check failed");

        // 7) Issuer verification (MAC verify on randomized commitments)
        let ok = keypair
            .verify_presentation(&presentation, predicate.commitments())
            .unwrap();
        assert!(ok, "presentation verification failed");

        // 8) Issuer MAC verify on original (A,e,M)
        let ok = keypair.verify_mac(&tag, &messages[..l]).unwrap();
        assert!(ok, "MAC check failed");
    }

    #[test]
    fn test_unlinkability() {
        let mut rng = MockRng::new(123);
        let l = 2;

        let keypair = KeyPair::setup(&mut rng, l).unwrap();
        let params = keypair.params();
        let pk = keypair.pk();

        // Create messages
        let mut messages = [Point::identity(); MAX_ATTRS];
        messages[0] = smul(&params.g, &Scalar::from(1u64));
        messages[1] = smul(&params.g, &Scalar::from(2u64));

        // Issue credential
        let tag = keypair.mac(&mut rng, &messages[..l]).unwrap();

        // Create two presentations from the same tag
        let pred1 = tag
            .get_predicate(&mut rng, params, pk, &messages[..l])
            .unwrap();
        let pred2 = tag
            .get_predicate(&mut rng, params, pk, &messages[..l])
            .unwrap();

        let pres1 = pred1.presentation();
        let pres2 = pred2.presentation();

        // Both should verify
        assert!(keypair
            .verify_presentation(&pres1, pred1.commitments())
            .unwrap());
        assert!(keypair
            .verify_presentation(&pres2, pred2.commitments())
            .unwrap());

        // But they should be different (unlinkable)
        assert_ne!(
            pres1.c_a.compress().as_bytes(),
            pres2.c_a.compress().as_bytes()
        );
        assert_ne!(pres1.t.compress().as_bytes(), pres2.t.compress().as_bytes());
    }
}
