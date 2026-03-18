//! MAC computation and verification for SAGA.
//!
//! Implements the core MAC operations:
//! - `compute_tag`: Issue a credential (requires secret key)
//! - `verify_tag`: Verify a credential (requires secret key)

use rand_core::{CryptoRng, RngCore};

use super::errors::SagaError;
use super::nizk::{compute_predicate, compute_tag_proof, verify_tag_proof, Predicate};
use super::smul;
use super::types::{
    Parameters, Point, PointExt, PublicKey, Scalar, ScalarExt, SecretKey, MAX_ATTRS,
    NUM_ATTRS_SIZE, POINT_SIZE, SCALAR_SIZE,
};

// ============================================================================
// Serialization Size Constants
// ============================================================================

/// Size of serialized Proof:
/// c (32) + s_x (32) + s_y_vec (MAX_ATTRS * 32) + num_attrs (1)
pub const PROOF_SIZE: usize =
    SCALAR_SIZE + SCALAR_SIZE + (MAX_ATTRS * SCALAR_SIZE) + NUM_ATTRS_SIZE;

/// Size of serialized Tag:
/// g_a (32) + e (32) + proof (PROOF_SIZE)
pub const TAG_SIZE: usize = POINT_SIZE + SCALAR_SIZE + PROOF_SIZE;

/// Schnorr-style NIZK proof for BBS-SAGA MAC correctness.
#[derive(Clone, Debug)]
pub struct Proof {
    /// Challenge scalar
    pub c: Scalar,
    /// Response for x
    pub s_x: Scalar,
    /// Responses for y_1..y_l (fixed size array)
    pub s_y_vec: [Scalar; MAX_ATTRS],
    /// Number of active responses
    pub(crate) num_attrs: usize,
}

impl Proof {
    /// Returns the active portion of s_y_vec
    #[inline]
    pub fn s_y_vec_slice(&self) -> &[Scalar] {
        &self.s_y_vec[..self.num_attrs]
    }

    /// Serialize Proof to bytes.
    ///
    /// Format: c (32) || s_x (32) || s_y_vec (MAX_ATTRS * 32) || num_attrs (1)
    pub fn to_bytes(&self) -> [u8; PROOF_SIZE] {
        let mut buf = [0u8; PROOF_SIZE];
        let mut offset = 0;

        // c
        buf[offset..offset + SCALAR_SIZE].copy_from_slice(&self.c.to_bytes());
        offset += SCALAR_SIZE;

        // s_x
        buf[offset..offset + SCALAR_SIZE].copy_from_slice(&self.s_x.to_bytes());
        offset += SCALAR_SIZE;

        // s_y_vec
        for j in 0..MAX_ATTRS {
            buf[offset..offset + SCALAR_SIZE].copy_from_slice(&self.s_y_vec[j].to_bytes());
            offset += SCALAR_SIZE;
        }

        // num_attrs
        buf[offset] = self.num_attrs as u8;

        buf
    }

    /// Deserialize Proof from bytes.
    pub fn from_bytes(bytes: &[u8; PROOF_SIZE]) -> Option<Self> {
        let mut offset = 0;
        let mut scalar_bytes = [0u8; SCALAR_SIZE];

        // c
        scalar_bytes.copy_from_slice(&bytes[offset..offset + SCALAR_SIZE]);
        let c = Scalar::from_bytes(&scalar_bytes)?;
        offset += SCALAR_SIZE;

        // s_x
        scalar_bytes.copy_from_slice(&bytes[offset..offset + SCALAR_SIZE]);
        let s_x = Scalar::from_bytes(&scalar_bytes)?;
        offset += SCALAR_SIZE;

        // s_y_vec
        let mut s_y_vec = [Scalar::ZERO; MAX_ATTRS];
        for j in 0..MAX_ATTRS {
            scalar_bytes.copy_from_slice(&bytes[offset..offset + SCALAR_SIZE]);
            s_y_vec[j] = Scalar::from_bytes(&scalar_bytes)?;
            offset += SCALAR_SIZE;
        }

        // num_attrs
        let num_attrs = bytes[offset] as usize;
        if num_attrs > MAX_ATTRS {
            return None;
        }

        Some(Self {
            c,
            s_x,
            s_y_vec,
            num_attrs,
        })
    }
}

/// A SAGA credential tag (MAC with NIZK proof).
#[derive(Clone, Debug)]
pub struct Tag {
    /// The MAC point A
    pub g_a: Point,
    /// The randomness scalar e
    pub e: Scalar,
    /// NIZK proof of correct construction
    pub proof: Proof,
}

impl Tag {
    /// Verify the tag using the public key (holder-side verification).
    ///
    /// This verifies the NIZK proof that the tag was correctly computed.
    pub fn verify(&self, params: &Parameters, pk: &PublicKey, messages: &[Point]) -> bool {
        verify_tag_proof(params, pk, &self.g_a, &self.e, messages, &self.proof)
    }

    /// Create an unlinkable presentation from this tag.
    ///
    /// # Arguments
    /// * `rng` - Random number generator
    /// * `params` - Public parameters
    /// * `pk` - Issuer's public key
    /// * `messages` - Original attribute values
    pub fn get_predicate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        params: &Parameters,
        pk: &PublicKey,
        messages: &[Point],
    ) -> Result<Predicate, SagaError> {
        compute_predicate(rng, params, pk, self, messages)
    }

    /// Serialize Tag to bytes.
    ///
    /// Format: g_a (32) || e (32) || proof (PROOF_SIZE)
    pub fn to_bytes(&self) -> [u8; TAG_SIZE] {
        let mut buf = [0u8; TAG_SIZE];
        let mut offset = 0;

        // g_a
        buf[offset..offset + POINT_SIZE].copy_from_slice(&self.g_a.to_bytes());
        offset += POINT_SIZE;

        // e
        buf[offset..offset + SCALAR_SIZE].copy_from_slice(&self.e.to_bytes());
        offset += SCALAR_SIZE;

        // proof
        buf[offset..offset + PROOF_SIZE].copy_from_slice(&self.proof.to_bytes());

        buf
    }

    /// Deserialize Tag from bytes.
    pub fn from_bytes(bytes: &[u8; TAG_SIZE]) -> Option<Self> {
        let mut offset = 0;

        // g_a
        let mut point_bytes = [0u8; POINT_SIZE];
        point_bytes.copy_from_slice(&bytes[offset..offset + POINT_SIZE]);
        let g_a = Point::from_bytes(&point_bytes)?;
        offset += POINT_SIZE;

        // e
        let mut scalar_bytes = [0u8; SCALAR_SIZE];
        scalar_bytes.copy_from_slice(&bytes[offset..offset + SCALAR_SIZE]);
        let e = Scalar::from_bytes(&scalar_bytes)?;
        offset += SCALAR_SIZE;

        // proof
        let proof_bytes: &[u8; PROOF_SIZE] = bytes[offset..offset + PROOF_SIZE].try_into().ok()?;
        let proof = Proof::from_bytes(proof_bytes)?;

        Some(Self { g_a, e, proof })
    }
}

/// Compute a MAC (credential) for the given messages.
///
/// This is the credential issuance operation, performed by the issuer.
///
/// # Algorithm
///
/// 1. Sample random e such that x + e != 0
/// 2. Compute S = G_0 + Σ y_j * M_j
/// 3. Compute A = (x + e)^(-1) * S
/// 4. Generate NIZK proof of correct construction
///
/// # Arguments
/// * `rng` - Cryptographically secure random number generator
/// * `params` - Public parameters
/// * `sk` - Issuer's secret key
/// * `pk` - Issuer's public key
/// * `messages` - Attribute values as curve points
pub fn compute_tag<R: RngCore + CryptoRng>(
    rng: &mut R,
    params: &Parameters,
    sk: &SecretKey,
    pk: &PublicKey,
    messages: &[Point],
) -> Result<Tag, SagaError> {
    let l = params.num_attrs;

    if messages.len() != l {
        return Err(SagaError::LengthMismatch {
            expected: l,
            got: messages.len(),
        });
    }
    if sk.num_attrs != l {
        return Err(SagaError::LengthMismatch {
            expected: l,
            got: sk.num_attrs,
        });
    }

    // Sample e such that x + e != 0
    let e = loop {
        let e_try = Scalar::rand(rng);
        let sum = sk.x + e_try;
        if sum != Scalar::ZERO {
            break e_try;
        }
    };

    // S = G_0 + Σ y_j * M_j
    let mut g_s = params.pp_saga;
    for j in 0..l {
        g_s += smul(&messages[j], &sk.y_vec[j]);
    }

    // A = (x + e)^(-1) * S
    let sum = sk.x + e;
    if sum == Scalar::ZERO {
        return Err(SagaError::NonInvertible);
    }
    let inv = sum.invert();
    let g_a = smul(&g_s, &inv);

    // Generate NIZK proof
    let proof = compute_tag_proof(rng, params, pk, sk, &g_a, &e, messages);

    Ok(Tag { g_a, e, proof })
}

/// Verify a MAC (issuer side, requires secret key).
///
/// Verifies: (x + e) * A == G_0 + Σ y_j * M_j
///
/// # Arguments
/// * `params` - Public parameters
/// * `sk` - Issuer's secret key
/// * `tag` - The MAC to verify
/// * `messages` - The original messages
pub fn verify_tag(
    params: &Parameters,
    sk: &SecretKey,
    tag: &Tag,
    messages: &[Point],
) -> Result<bool, SagaError> {
    let l = params.num_attrs;

    if messages.len() != l || sk.num_attrs != l {
        return Err(SagaError::LengthMismatch {
            expected: l,
            got: messages.len(),
        });
    }

    // LHS = (x + e) * A
    let lhs = smul(&tag.g_a, &(sk.x + tag.e));

    // RHS = G_0 + Σ y_j * M_j
    let mut rhs = params.pp_saga;
    for j in 0..l {
        rhs += smul(&messages[j], &sk.y_vec[j]);
    }

    Ok(lhs == rhs)
}
