//! Non-interactive zero-knowledge proofs for SAGA.
//!
//! Implements Schnorr-style NIZK proofs using the Fiat-Shamir transform.

use curve25519_dalek::traits::Identity;
use rand_core::{CryptoRng, RngCore};

use super::errors::SagaError;
use super::mac::{Proof, Tag};
use super::types::{
    Parameters, Point, PointExt, PublicKey, Scalar, ScalarExt, SecretKey, MAX_ATTRS, POINT_SIZE,
};
use super::{hash_to_scalar, smul, PROT_NAME_MAC};

/// Size of serialized Presentation: c_a (32) + t (32)
pub const PRESENTATION_SIZE: usize = POINT_SIZE + POINT_SIZE;

/// Compute the challenge for tag proof verification.
///
/// Uses Fiat-Shamir transform: c = H(protocol_name || statement || announcement)
fn compute_tag_challenge(
    // Statement
    x: &Point,
    y_vec: &[Point],
    e_a_minus_g0: &Point,
    // Announcement
    t1: &Point,
    t2_vec: &[Point],
    t3: &Point,
) -> Scalar {
    // Calculate required buffer size
    // Protocol name + statement points + announcement points
    // Each point serializes to 32 bytes
    let num_points = 1 + y_vec.len() + 1 + 1 + t2_vec.len() + 1;
    let _buf_size = PROT_NAME_MAC.len() + num_points * 32;

    // Use a stack-allocated buffer (max realistic size)
    // MAX_ATTRS * 2 for y_vec and t2_vec, plus 4 fixed points
    const MAX_BUF_SIZE: usize = 17 + (MAX_ATTRS * 2 + 4) * 32; // 17 for protocol name
    let mut buf = [0u8; MAX_BUF_SIZE];
    let mut offset = 0;

    // Protocol name
    buf[offset..offset + PROT_NAME_MAC.len()].copy_from_slice(PROT_NAME_MAC);
    offset += PROT_NAME_MAC.len();

    // Statement: X
    let bytes = x.compress().to_bytes();
    buf[offset..offset + 32].copy_from_slice(&bytes);
    offset += 32;

    // Statement: Y_j
    for yj in y_vec {
        let bytes = yj.compress().to_bytes();
        buf[offset..offset + 32].copy_from_slice(&bytes);
        offset += 32;
    }

    // Statement: eA - G0
    let bytes = e_a_minus_g0.compress().to_bytes();
    buf[offset..offset + 32].copy_from_slice(&bytes);
    offset += 32;

    // Announcement: T1
    let bytes = t1.compress().to_bytes();
    buf[offset..offset + 32].copy_from_slice(&bytes);
    offset += 32;

    // Announcement: T2_j
    for t2j in t2_vec {
        let bytes = t2j.compress().to_bytes();
        buf[offset..offset + 32].copy_from_slice(&bytes);
        offset += 32;
    }

    // Announcement: T3
    let bytes = t3.compress().to_bytes();
    buf[offset..offset + 32].copy_from_slice(&bytes);
    offset += 32;

    hash_to_scalar(&buf[..offset])
}

/// Prover for the SAGA NIZK.
///
/// Statement: (X, (Y_j)_{j=1..l}, eA - G0)
/// Witness: (x, (y_j)_{j=1..l})
/// Relation: X = xG, Y_j = y_j*G_j, eA - G0 = -xA + Σ y_j*M_j
pub fn compute_tag_proof<R: RngCore + CryptoRng>(
    rng: &mut R,
    params: &Parameters,
    pk: &PublicKey,
    sk: &SecretKey,
    g_a: &Point,
    e: &Scalar,
    messages: &[Point],
) -> Proof {
    let l = params.num_attrs;
    debug_assert_eq!(messages.len(), l);
    debug_assert_eq!(sk.num_attrs, l);
    debug_assert_eq!(pk.num_attrs, l);

    // 1) Sample random a = (a_x, a_y1..a_yl)
    let a_x = Scalar::rand(rng);
    let mut a_y_vec = [Scalar::ZERO; MAX_ATTRS];
    for j in 0..l {
        a_y_vec[j] = Scalar::rand(rng);
    }

    // 2) Compute announcement T = φ(a)
    // T1 = a_x * G
    let t1 = smul(&params.g, &a_x);

    // T2_j = a_yj * G_j
    let mut t2_vec = [Point::identity(); MAX_ATTRS];
    for j in 0..l {
        t2_vec[j] = smul(&params.g_vec[j], &a_y_vec[j]);
    }

    // T3 = -a_x * A + Σ a_yj * M_j
    let mut t3 = -smul(g_a, &a_x);
    for j in 0..l {
        t3 += smul(&messages[j], &a_y_vec[j]);
    }

    // Statement: S = (X, Y_vec, eA - G0)
    let mut e_a_minus_g0 = smul(g_a, e);
    e_a_minus_g0 -= params.pp_saga;

    // 3) Compute challenge c = H(ProtName, statement, announcement)
    let c = compute_tag_challenge(
        &pk.g_x,
        &pk.g_y_vec[..l],
        &e_a_minus_g0,
        &t1,
        &t2_vec[..l],
        &t3,
    );

    // 4) Compute response s = a + c * witness
    let s_x = a_x + c * sk.x;
    let mut s_y_vec = [Scalar::ZERO; MAX_ATTRS];
    for j in 0..l {
        s_y_vec[j] = a_y_vec[j] + c * sk.y_vec[j];
    }

    Proof {
        c,
        s_x,
        s_y_vec,
        num_attrs: l,
    }
}

/// Verifier for the SAGA NIZK.
///
/// Recomputes the announcement from the response and checks the challenge.
pub fn verify_tag_proof(
    params: &Parameters,
    pk: &PublicKey,
    g_a: &Point,
    e: &Scalar,
    messages: &[Point],
    proof: &Proof,
) -> bool {
    let l = params.num_attrs;

    if messages.len() != l || pk.num_attrs != l || proof.num_attrs != l {
        return false;
    }

    // Statement: S = (X, Y_vec, eA - G0)
    let mut e_a_minus_g0 = smul(g_a, e);
    e_a_minus_g0 -= params.pp_saga;

    // Recompute accepting announcement T' = φ(s) - c * S
    // φ(s) = (s_x*G, (s_yj*G_j), -s_x*A + Σ s_yj*M_j)

    let t1_s = smul(&params.g, &proof.s_x);
    let mut t2_s_vec = [Point::identity(); MAX_ATTRS];
    for j in 0..l {
        t2_s_vec[j] = smul(&params.g_vec[j], &proof.s_y_vec[j]);
    }
    let mut t3_s = -smul(g_a, &proof.s_x);
    for j in 0..l {
        t3_s += smul(&messages[j], &proof.s_y_vec[j]);
    }

    // Subtract c * S
    let t1 = t1_s - smul(&pk.g_x, &proof.c);
    let mut t2_vec = [Point::identity(); MAX_ATTRS];
    for j in 0..l {
        t2_vec[j] = t2_s_vec[j] - smul(&pk.g_y_vec[j], &proof.c);
    }
    let t3 = t3_s - smul(&e_a_minus_g0, &proof.c);

    // Recompute challenge: c' = H(ProtName, statement, T')
    let c_prime = compute_tag_challenge(
        &pk.g_x,
        &pk.g_y_vec[..l],
        &e_a_minus_g0,
        &t1,
        &t2_vec[..l],
        &t3,
    );

    c_prime == proof.c
}

/// An unlinkable presentation of a credential.
#[derive(Clone, Debug)]
pub struct Presentation {
    /// Randomized commitment to A: C_A = A + r*G
    pub c_a: Point,
    /// Proof term T
    pub t: Point,
}

impl Presentation {
    /// Serialize Presentation to bytes.
    ///
    /// Format: c_a (32) || t (32)
    pub fn to_bytes(&self) -> [u8; PRESENTATION_SIZE] {
        let mut buf = [0u8; PRESENTATION_SIZE];

        // c_a
        buf[0..POINT_SIZE].copy_from_slice(&self.c_a.to_bytes());

        // t
        buf[POINT_SIZE..POINT_SIZE + POINT_SIZE].copy_from_slice(&self.t.to_bytes());

        buf
    }

    /// Deserialize Presentation from bytes.
    pub fn from_bytes(bytes: &[u8; PRESENTATION_SIZE]) -> Option<Self> {
        let mut point_bytes = [0u8; POINT_SIZE];

        // c_a
        point_bytes.copy_from_slice(&bytes[0..POINT_SIZE]);
        let c_a = Point::from_bytes(&point_bytes)?;

        // t
        point_bytes.copy_from_slice(&bytes[POINT_SIZE..POINT_SIZE + POINT_SIZE]);
        let t = Point::from_bytes(&point_bytes)?;

        Some(Self { c_a, t })
    }
}

/// A predicate containing the presentation and private data.
///
/// The holder uses this to:
/// 1. Verify the predicate locally (check method)
/// 2. Extract the presentation to send to the verifier
/// 3. Provide the randomized commitments for verification
#[derive(Clone, Debug)]
pub struct Predicate {
    /// The presentation (C_A, T)
    presentation: Presentation,
    /// Randomized commitments to messages: C_j = M_j + ξ_j * G_j
    c_j_vec: [Point; MAX_ATTRS],
    /// Blinding scalars ξ_j
    xi_vec: [Scalar; MAX_ATTRS],
    /// Witness: random scalar r
    witness_r: Scalar,
    /// Witness: the e from the tag
    witness_e: Scalar,
    /// Number of active attributes
    num_attrs: usize,
}

impl Predicate {
    /// Holder-side predicate check.
    ///
    /// Verifies: T == r*X - e*C_A + e*r*G - Σ ξ_j*Y_j
    pub fn check(&self, params: &Parameters, pk: &PublicKey) -> Result<bool, SagaError> {
        let l = pk.num_attrs;
        if self.num_attrs != l {
            return Err(SagaError::LengthMismatch {
                expected: l,
                got: self.num_attrs,
            });
        }

        // RHS = r*X - e*C_A + e*r*G - Σ ξ_j*Y_j
        let mut rhs = smul(&pk.g_x, &self.witness_r);
        rhs -= smul(&self.presentation.c_a, &self.witness_e);
        rhs += smul(&params.g, &(self.witness_e * self.witness_r));
        for j in 0..l {
            rhs -= smul(&pk.g_y_vec[j], &self.xi_vec[j]);
        }

        Ok(rhs == self.presentation.t)
    }

    /// Get the presentation (C_A, T) to send to the verifier.
    #[inline]
    pub fn presentation(&self) -> Presentation {
        self.presentation.clone()
    }

    /// Get the randomized commitments to send to the verifier.
    #[inline]
    pub fn commitments(&self) -> &[Point] {
        &self.c_j_vec[..self.num_attrs]
    }

    /// Get the blinding scalars (ξ_j).
    #[inline]
    pub fn xi_vec(&self) -> &[Scalar] {
        &self.xi_vec[..self.num_attrs]
    }

    /// Get the witness r scalar.
    #[inline]
    pub fn witness_r(&self) -> Scalar {
        self.witness_r
    }

    /// Get the witness e scalar.
    #[inline]
    pub fn witness_e(&self) -> Scalar {
        self.witness_e
    }
}

/// Compute an unlinkable predicate/presentation for a tag.
///
/// This randomizes the credential so that different presentations
/// of the same credential cannot be linked.
///
/// # Algorithm
///
/// 1. Sample random r and ξ_j for each attribute
/// 2. Compute C_j = M_j + ξ_j * G_j (randomized message commitments)
/// 3. Compute C_A = A + r * G (randomized MAC commitment)
/// 4. Compute T = r*X - e*C_A + e*r*G - Σ ξ_j*Y_j
pub fn compute_predicate<R: RngCore + CryptoRng>(
    rng: &mut R,
    params: &Parameters,
    pk: &PublicKey,
    tag: &Tag,
    messages: &[Point],
) -> Result<Predicate, SagaError> {
    let l = params.num_attrs;

    if messages.len() != l {
        return Err(SagaError::LengthMismatch {
            expected: l,
            got: messages.len(),
        });
    }
    if pk.num_attrs != l {
        return Err(SagaError::LengthMismatch {
            expected: l,
            got: pk.num_attrs,
        });
    }

    // Verify the tag's proof first
    let ok = verify_tag_proof(params, pk, &tag.g_a, &tag.e, messages, &tag.proof);
    if !ok {
        return Err(SagaError::InvalidProof);
    }

    // Sample r and ξ_j
    let witness_r = Scalar::rand(rng);
    let mut xi_vec = [Scalar::ZERO; MAX_ATTRS];
    for j in 0..l {
        xi_vec[j] = Scalar::rand(rng);
    }

    // C_j = M_j + ξ_j * G_j
    let mut c_j_vec = [Point::identity(); MAX_ATTRS];
    for j in 0..l {
        c_j_vec[j] = messages[j] + smul(&params.g_vec[j], &xi_vec[j]);
    }

    // C_A = A + r * G
    let c_a = tag.g_a + smul(&params.g, &witness_r);

    // T = r*X - e*C_A + e*r*G - Σ ξ_j*Y_j
    let mut sum_y_xi = Point::identity();
    for j in 0..l {
        sum_y_xi += smul(&pk.g_y_vec[j], &xi_vec[j]);
    }

    let mut t = smul(&pk.g_x, &witness_r); // r*X
    t -= smul(&c_a, &tag.e); // - e*C_A
    t += smul(&params.g, &(tag.e * witness_r)); // + e*r*G
    t -= sum_y_xi; // - Σ ξ_j*Y_j

    Ok(Predicate {
        presentation: Presentation { c_a, t },
        c_j_vec,
        xi_vec,
        witness_r,
        witness_e: tag.e,
        num_attrs: l,
    })
}

/// Verify an unlinkable presentation (issuer/verifier side).
///
/// Verifies: x * C_A == G_0 + Σ y_j * C_j + T
///
/// This requires the secret key, so only the issuer (or a designated
/// verifier with the secret key) can verify presentations.
pub fn verify_presentation(
    params: &Parameters,
    sk: &SecretKey,
    presentation: &Presentation,
    c_j_vec: &[Point],
) -> Result<bool, SagaError> {
    let l = params.num_attrs;

    if c_j_vec.len() != l || sk.num_attrs != l {
        return Err(SagaError::LengthMismatch {
            expected: l,
            got: c_j_vec.len(),
        });
    }

    // LHS = x * C_A
    let lhs = smul(&presentation.c_a, &sk.x);

    // RHS = G_0 + Σ y_j * C_j + T
    let mut rhs = params.pp_saga;
    for j in 0..l {
        rhs += smul(&c_j_vec[j], &sk.y_vec[j]);
    }
    rhs += presentation.t;

    Ok(lhs == rhs)
}
