// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! SAGA Authorization Layer for PQ-Ratchet
//!
//! This module provides anonymous credential-based authorization for PQ-Ratchet
//! sessions. SAGA (a BBS-style MAC scheme) enables the MCU to act as both
//! issuer and verifier of credentials, providing:
//!
//! - **Anonymous authentication**: Relayers prove they hold valid credentials
//!   without revealing their identity
//! - **Unlinkable sessions**: Multiple sessions from the same relayer cannot
//!   be correlated
//! - **Credential binding**: Sessions are bound to valid credentials
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Secure-Relayer                                                 │
//! │  ┌───────────────────────────────────────────────────────────┐  │
//! │  │  SAGA Credential (Tag)                                    │  │
//! │  │  - Issued by MCU during provisioning                      │  │
//! │  │  - Contains device binding attributes                     │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! │                            │                                    │
//! │                            ▼                                    │
//! │  ┌───────────────────────────────────────────────────────────┐  │
//! │  │  Session Initialization                                   │  │
//! │  │  1. Generate X-Wing keypair                               │  │
//! │  │  2. Create SAGA presentation from credential              │  │
//! │  │  3. Send (X-Wing PK, SAGA Presentation) to MCU            │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  MCU (TrustZone)                                                │
//! │  ┌───────────────────────────────────────────────────────────┐  │
//! │  │  SAGA KeyPair (Issuer + Verifier)                         │  │
//! │  │  - Stored in TrustZone ITS                                │  │
//! │  │  - Secret key never leaves secure world                   │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! │                            │                                    │
//! │                            ▼                                    │
//! │  ┌───────────────────────────────────────────────────────────┐  │
//! │  │  Session Verification                                     │  │
//! │  │  1. Verify SAGA presentation                              │  │
//! │  │  2. If valid, proceed with X-Wing encapsulation           │  │
//! │  │  3. Bind session to credential (include in KDF context    │  │
//! │  └───────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Attributes
//!
//! SAGA credentials can include attributes for authorization policies:
//!
//! | Attribute | Description                          |
//! |-----------|--------------------------------------|
//! | device_id | Hash of device public key            |
//! | expiry    | Credential expiration timestamp      |
//! | role      | Authorization level (e.g., 0=guest)  |
//!
//! # Example
//!
//! ```rust,ignore
//! use dragonwing_crypto::experimental::pq_ratchet::saga_auth::*;
//! use dragonwing_crypto::saga::KeyPair;
//!
//! // === MCU (Issuer) Side ===
//!
//! // During provisioning: issue credential to relayer
//! let issuer = SagaIssuer::new(&mut rng, 3)?;
//! let attributes = [device_id_point, expiry_point, role_point];
//! let credential = issuer.issue_credential(&mut rng, &attributes)?;
//!
//! // Store issuer keypair in TrustZone ITS
//! issuer.store_keypair(UID_SAGA_KEYPAIR)?;
//!
//! // === Relayer (Holder) Side ===
//!
//! // Create presentation for session initiation
//! let holder = SagaHolder::new(credential, attributes);
//! let presentation = holder.create_presentation(&mut rng, issuer.params(), issuer.pk())?;
//!
//! // Send (xwing_pk, presentation, commitments) to MCU
//!
//! // === MCU (Verifier) Side ===
//!
//! // Verify presentation during session setup
//! let verifier = SagaVerifier::load_keypair(UID_SAGA_KEYPAIR)?;
//! if verifier.verify_presentation(&presentation, &commitments)? {
//!     // Proceed with X-Wing encapsulation and session establishment
//! }
//! ```

use super::kdf::KEY_SIZE;

// Conditionally import SAGA types
#[cfg(feature = "saga")]
use crate::saga::{
    Identity, KeyPair, Parameters, Point, PointExt, Presentation, PublicKey, Tag, MAX_ATTRS,
    PRESENTATION_SIZE,
};

#[cfg(feature = "saga")]
use rand_core::{CryptoRng, RngCore};

// ============================================================================
// Constants
// ============================================================================

/// Number of attributes used for PQ-Ratchet authorization
/// - Attribute 0: device_id (hash of device public key)
/// - Attribute 1: expiry (credential expiration)
/// - Attribute 2: role (authorization level)
pub const NUM_AUTH_ATTRS: usize = 3;

/// Size of serialized authorization context
pub const AUTH_CONTEXT_SIZE: usize = 32 + 8 + 1; // device_id + expiry + role = 41 bytes

/// Domain separation label for credential binding in KDF
pub const LABEL_CREDENTIAL_BIND: &[u8] = b"DragonWing PQ-Ratchet V1 Credential Bind";

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during SAGA authorization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SagaAuthError {
    /// SAGA operation failed
    SagaError,
    /// Invalid number of attributes
    InvalidAttributeCount,
    /// Credential verification failed
    VerificationFailed,
    /// Credential has expired
    CredentialExpired,
    /// Insufficient authorization level
    InsufficientRole,
    /// Storage operation failed
    StorageError,
    /// Serialization/deserialization failed
    SerializationError,
}

// ============================================================================
// Authorization Context
// ============================================================================

/// Authorization context extracted from credential attributes
#[derive(Debug, Clone, Copy)]
pub struct AuthContext {
    /// Device identifier (32-byte hash)
    pub device_id: [u8; 32],
    /// Credential expiry timestamp (Unix seconds)
    pub expiry: u64,
    /// Authorization role/level
    pub role: u8,
}

impl AuthContext {
    /// Create a new authorization context
    pub fn new(device_id: [u8; 32], expiry: u64, role: u8) -> Self {
        Self {
            device_id,
            expiry,
            role,
        }
    }

    /// Check if credential has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        self.expiry != 0 && current_time > self.expiry
    }

    /// Check if role meets minimum requirement
    pub fn has_role(&self, min_role: u8) -> bool {
        self.role >= min_role
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; AUTH_CONTEXT_SIZE] {
        let mut buf = [0u8; AUTH_CONTEXT_SIZE];
        buf[0..32].copy_from_slice(&self.device_id);
        buf[32..40].copy_from_slice(&self.expiry.to_be_bytes());
        buf[40] = self.role;
        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8; AUTH_CONTEXT_SIZE]) -> Self {
        let mut device_id = [0u8; 32];
        device_id.copy_from_slice(&bytes[0..32]);

        let expiry = u64::from_be_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]);

        Self {
            device_id,
            expiry,
            role: bytes[40],
        }
    }

    /// Convert to SAGA attribute points
    #[cfg(feature = "saga")]
    pub fn to_attribute_points(&self, params: &Parameters) -> [Point; NUM_AUTH_ATTRS] {
        use crate::saga::{hash_to_scalar, smul, Scalar};

        // Attribute 0: device_id as scalar * G
        let device_scalar = hash_to_scalar(&self.device_id);
        let device_point = smul(&params.g, &device_scalar);

        // Attribute 1: expiry as scalar * G
        let expiry_scalar = Scalar::from(self.expiry);
        let expiry_point = smul(&params.g, &expiry_scalar);

        // Attribute 2: role as scalar * G
        let role_scalar = Scalar::from(self.role as u64);
        let role_point = smul(&params.g, &role_scalar);

        [device_point, expiry_point, role_point]
    }
}

impl Default for AuthContext {
    fn default() -> Self {
        Self {
            device_id: [0u8; 32],
            expiry: 0,
            role: 0,
        }
    }
}

// ============================================================================
// SAGA Issuer (MCU Side)
// ============================================================================

/// SAGA credential issuer (runs on MCU in TrustZone)
///
/// The issuer creates and verifies credentials. The keypair is stored
/// in TrustZone ITS for persistence.
#[cfg(feature = "saga")]
pub struct SagaIssuer {
    keypair: KeyPair,
}

#[cfg(feature = "saga")]
impl SagaIssuer {
    /// Create a new issuer with fresh keypair
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        num_attrs: usize,
    ) -> Result<Self, SagaAuthError> {
        let keypair = KeyPair::setup(rng, num_attrs).map_err(|_| SagaAuthError::SagaError)?;
        Ok(Self { keypair })
    }

    /// Create issuer from existing keypair
    pub fn from_keypair(keypair: KeyPair) -> Self {
        Self { keypair }
    }

    /// Get the parameters (for sharing with holders)
    pub fn params(&self) -> &Parameters {
        self.keypair.params()
    }

    /// Get the public key (for sharing with holders)
    pub fn pk(&self) -> &PublicKey {
        self.keypair.pk()
    }

    /// Issue a credential (Tag) for the given attributes
    pub fn issue_credential<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        attributes: &[Point],
    ) -> Result<Tag, SagaAuthError> {
        self.keypair
            .mac(rng, attributes)
            .map_err(|_| SagaAuthError::SagaError)
    }

    /// Issue a credential for an authorization context
    pub fn issue_for_context<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        context: &AuthContext,
    ) -> Result<Tag, SagaAuthError> {
        let attrs = context.to_attribute_points(self.params());
        self.issue_credential(rng, &attrs[..NUM_AUTH_ATTRS])
    }

    /// Verify a presentation (for session authorization)
    pub fn verify_presentation(
        &self,
        presentation: &Presentation,
        commitments: &[Point],
    ) -> Result<bool, SagaAuthError> {
        self.keypair
            .verify_presentation(presentation, commitments)
            .map_err(|_| SagaAuthError::SagaError)
    }

    /// Serialize the keypair for storage
    pub fn keypair_bytes(&self) -> [u8; crate::saga::KEY_PAIR_SIZE] {
        self.keypair.to_bytes()
    }

    /// Deserialize keypair from storage
    pub fn from_keypair_bytes(
        bytes: &[u8; crate::saga::KEY_PAIR_SIZE],
    ) -> Result<Self, SagaAuthError> {
        let keypair = KeyPair::from_bytes(bytes).ok_or(SagaAuthError::SerializationError)?;
        Ok(Self { keypair })
    }

    /// Store keypair in PSA ITS
    #[cfg(feature = "psa")]
    pub fn store_keypair(&self, uid: crate::psa::StorageUid) -> Result<(), SagaAuthError> {
        use crate::psa::PsaStorable;
        self.keypair
            .psa_store(uid, crate::psa::StorageFlags::NONE)
            .map_err(|_| SagaAuthError::StorageError)
    }

    /// Load keypair from PSA ITS
    #[cfg(feature = "psa")]
    pub fn load_keypair(uid: crate::psa::StorageUid) -> Result<Self, SagaAuthError> {
        use crate::psa::PsaStorable;
        let keypair = KeyPair::psa_load(uid).map_err(|_| SagaAuthError::StorageError)?;
        Ok(Self { keypair })
    }
}

// ============================================================================
// SAGA Holder (Relayer Side)
// ============================================================================

/// SAGA credential holder (runs on Secure-Relayer)
///
/// The holder stores a credential and creates presentations for
/// session authorization.
#[cfg(feature = "saga")]
pub struct SagaHolder {
    /// The credential (Tag)
    credential: Tag,
    /// The attribute points used in the credential
    attributes: [Point; MAX_ATTRS],
    /// Number of active attributes
    num_attrs: usize,
}

#[cfg(feature = "saga")]
impl SagaHolder {
    /// Create a new holder with credential and attributes
    pub fn new(credential: Tag, attributes: &[Point]) -> Result<Self, SagaAuthError> {
        if attributes.len() > MAX_ATTRS {
            return Err(SagaAuthError::InvalidAttributeCount);
        }

        let mut attrs = [Point::identity(); MAX_ATTRS];
        attrs[..attributes.len()].copy_from_slice(attributes);

        Ok(Self {
            credential,
            attributes: attrs,
            num_attrs: attributes.len(),
        })
    }

    /// Create holder from authorization context
    pub fn from_context(
        credential: Tag,
        context: &AuthContext,
        params: &Parameters,
    ) -> Result<Self, SagaAuthError> {
        let attrs = context.to_attribute_points(params);
        Self::new(credential, &attrs[..NUM_AUTH_ATTRS])
    }

    /// Verify the credential locally (requires public key)
    pub fn verify_credential(&self, params: &Parameters, pk: &PublicKey) -> bool {
        self.credential
            .verify(params, pk, &self.attributes[..self.num_attrs])
    }

    /// Create an unlinkable presentation for session authorization
    pub fn create_presentation<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        params: &Parameters,
        pk: &PublicKey,
    ) -> Result<(Presentation, [Point; MAX_ATTRS]), SagaAuthError> {
        let predicate = self
            .credential
            .get_predicate(rng, params, pk, &self.attributes[..self.num_attrs])
            .map_err(|_| SagaAuthError::SagaError)?;

        let presentation = predicate.presentation().clone();

        let mut commitments = [Point::identity(); MAX_ATTRS];
        let comm_slice = predicate.commitments();
        commitments[..comm_slice.len()].copy_from_slice(comm_slice);

        Ok((presentation, commitments))
    }

    /// Get the credential for serialization
    pub fn credential(&self) -> &Tag {
        &self.credential
    }

    /// Get the attributes
    pub fn attributes(&self) -> &[Point] {
        &self.attributes[..self.num_attrs]
    }
}

// ============================================================================
// Session Authorization
// ============================================================================

/// Authorization request sent from relayer to MCU
#[cfg(feature = "saga")]
#[derive(Clone)]
pub struct AuthRequest {
    /// SAGA presentation (unlinkable proof of valid credential)
    pub presentation: Presentation,
    /// Randomized attribute commitments
    pub commitments: [Point; MAX_ATTRS],
    /// Number of active commitments
    pub num_commitments: usize,
}

#[cfg(feature = "saga")]
impl AuthRequest {
    /// Create a new authorization request
    pub fn new(presentation: Presentation, commitments: &[Point]) -> Result<Self, SagaAuthError> {
        if commitments.len() > MAX_ATTRS {
            return Err(SagaAuthError::InvalidAttributeCount);
        }

        let mut comm = [Point::identity(); MAX_ATTRS];
        comm[..commitments.len()].copy_from_slice(commitments);

        Ok(Self {
            presentation,
            commitments: comm,
            num_commitments: commitments.len(),
        })
    }

    /// Get the commitments slice
    pub fn commitments(&self) -> &[Point] {
        &self.commitments[..self.num_commitments]
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> [u8; PRESENTATION_SIZE + MAX_ATTRS * 32 + 1] {
        let mut buf = [0u8; PRESENTATION_SIZE + MAX_ATTRS * 32 + 1];
        let mut offset = 0;

        // Presentation
        buf[offset..offset + PRESENTATION_SIZE].copy_from_slice(&self.presentation.to_bytes());
        offset += PRESENTATION_SIZE;

        // Commitments
        for i in 0..MAX_ATTRS {
            buf[offset..offset + 32].copy_from_slice(&self.commitments[i].to_bytes());
            offset += 32;
        }

        // Number of commitments
        buf[offset] = self.num_commitments as u8;

        buf
    }

    /// Deserialize from bytes
    pub fn from_bytes(
        bytes: &[u8; PRESENTATION_SIZE + MAX_ATTRS * 32 + 1],
    ) -> Result<Self, SagaAuthError> {
        let mut offset = 0;

        // Presentation
        let pres_bytes: &[u8; PRESENTATION_SIZE] = bytes[offset..offset + PRESENTATION_SIZE]
            .try_into()
            .map_err(|_| SagaAuthError::SerializationError)?;
        let presentation =
            Presentation::from_bytes(pres_bytes).ok_or(SagaAuthError::SerializationError)?;
        offset += PRESENTATION_SIZE;

        // Commitments
        let mut commitments = [Point::identity(); MAX_ATTRS];
        for i in 0..MAX_ATTRS {
            let point_bytes: [u8; 32] = bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| SagaAuthError::SerializationError)?;
            commitments[i] =
                Point::from_bytes(&point_bytes).ok_or(SagaAuthError::SerializationError)?;
            offset += 32;
        }

        // Number of commitments
        let num_commitments = bytes[offset] as usize;
        if num_commitments > MAX_ATTRS {
            return Err(SagaAuthError::InvalidAttributeCount);
        }

        Ok(Self {
            presentation,
            commitments,
            num_commitments,
        })
    }
}

// ============================================================================
// Credential Binding for KDF
// ============================================================================

/// Derive additional key material that binds the session to the credential
///
/// This is mixed into the root key derivation to ensure the session
/// is cryptographically bound to a valid credential presentation.
pub fn derive_credential_binding(
    presentation_hash: &[u8; 32],
    session_context: &[u8],
) -> [u8; KEY_SIZE] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(LABEL_CREDENTIAL_BIND);
    hasher.update(presentation_hash);
    hasher.update(session_context);

    let hash = hasher.finalize();
    let mut result = [0u8; KEY_SIZE];
    result.copy_from_slice(&hash);
    result
}

/// Hash a presentation for binding
#[cfg(feature = "saga")]
pub fn hash_presentation(presentation: &Presentation) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(&presentation.to_bytes());

    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

// ============================================================================
// PSA Storage UIDs
// ============================================================================

/// Base UID for SAGA credential storage
pub const UID_SAGA_BASE: u32 = 0x0004_0000;

/// SAGA issuer keypair (MCU)
pub const UID_SAGA_KEYPAIR: u32 = UID_SAGA_BASE;

/// SAGA parameters (shared)
pub const UID_SAGA_PARAMS: u32 = UID_SAGA_BASE + 1;

/// SAGA public key (shared)
pub const UID_SAGA_PUBLIC_KEY: u32 = UID_SAGA_BASE + 2;

/// SAGA credential (holder - relayer)
pub const UID_SAGA_CREDENTIAL: u32 = UID_SAGA_BASE + 0x100;

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "saga"))]
mod tests {
    use super::*;
    use crate::saga::{smul, Scalar};

    // Mock RNG for testing
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
    fn test_auth_context_serialization() {
        let ctx = AuthContext {
            device_id: [0xAB; 32],
            expiry: 1234567890,
            role: 5,
        };

        let bytes = ctx.to_bytes();
        let restored = AuthContext::from_bytes(&bytes);

        assert_eq!(restored.device_id, ctx.device_id);
        assert_eq!(restored.expiry, ctx.expiry);
        assert_eq!(restored.role, ctx.role);
    }

    #[test]
    fn test_auth_context_expiry() {
        let ctx = AuthContext {
            device_id: [0; 32],
            expiry: 1000,
            role: 0,
        };

        assert!(!ctx.is_expired(500));
        assert!(!ctx.is_expired(1000));
        assert!(ctx.is_expired(1001));

        // Zero expiry means no expiration
        let no_expiry = AuthContext {
            device_id: [0; 32],
            expiry: 0,
            role: 0,
        };
        assert!(!no_expiry.is_expired(u64::MAX));
    }

    #[test]
    fn test_issuer_holder_flow() {
        let mut rng = MockRng::new(42);

        // 1. Issuer creates keypair
        let issuer = SagaIssuer::new(&mut rng, NUM_AUTH_ATTRS).unwrap();

        // 2. Create authorization context
        let ctx = AuthContext {
            device_id: [0x42; 32],
            expiry: u64::MAX, // No expiry
            role: 1,
        };

        // 3. Issue credential
        let credential = issuer.issue_for_context(&mut rng, &ctx).unwrap();

        // 4. Holder receives credential
        let holder = SagaHolder::from_context(credential, &ctx, issuer.params()).unwrap();

        // 5. Holder verifies credential locally
        assert!(holder.verify_credential(issuer.params(), issuer.pk()));

        // 6. Holder creates presentation
        let (presentation, commitments) = holder
            .create_presentation(&mut rng, issuer.params(), issuer.pk())
            .unwrap();

        // 7. Issuer verifies presentation
        let num_attrs = NUM_AUTH_ATTRS;
        let result = issuer
            .verify_presentation(&presentation, &commitments[..num_attrs])
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_credential_binding() {
        let presentation_hash = [0xAB; 32];
        let session_context = b"session-123";

        let binding1 = derive_credential_binding(&presentation_hash, session_context);
        let binding2 = derive_credential_binding(&presentation_hash, session_context);

        // Same inputs produce same output
        assert_eq!(binding1, binding2);

        // Different presentation produces different binding
        let different_hash = [0xCD; 32];
        let binding3 = derive_credential_binding(&different_hash, session_context);
        assert_ne!(binding1, binding3);

        // Different context produces different binding
        let binding4 = derive_credential_binding(&presentation_hash, b"session-456");
        assert_ne!(binding1, binding4);
    }

    #[test]
    fn test_auth_request_serialization() {
        let mut rng = MockRng::new(123);

        let issuer = SagaIssuer::new(&mut rng, NUM_AUTH_ATTRS).unwrap();
        let ctx = AuthContext::default();
        let credential = issuer.issue_for_context(&mut rng, &ctx).unwrap();
        let holder = SagaHolder::from_context(credential, &ctx, issuer.params()).unwrap();

        let (presentation, commitments) = holder
            .create_presentation(&mut rng, issuer.params(), issuer.pk())
            .unwrap();

        let request = AuthRequest::new(presentation, &commitments[..NUM_AUTH_ATTRS]).unwrap();
        let bytes = request.to_bytes();
        let restored = AuthRequest::from_bytes(&bytes).unwrap();

        assert_eq!(restored.num_commitments, request.num_commitments);
    }

    #[test]
    fn test_unlinkable_sessions() {
        let mut rng = MockRng::new(456);

        let issuer = SagaIssuer::new(&mut rng, NUM_AUTH_ATTRS).unwrap();
        let ctx = AuthContext::default();
        let credential = issuer.issue_for_context(&mut rng, &ctx).unwrap();
        let holder = SagaHolder::from_context(credential, &ctx, issuer.params()).unwrap();

        // Create two presentations from same credential
        let (pres1, comm1) = holder
            .create_presentation(&mut rng, issuer.params(), issuer.pk())
            .unwrap();
        let (pres2, comm2) = holder
            .create_presentation(&mut rng, issuer.params(), issuer.pk())
            .unwrap();

        // Both should verify
        assert!(issuer
            .verify_presentation(&pres1, &comm1[..NUM_AUTH_ATTRS])
            .unwrap());
        assert!(issuer
            .verify_presentation(&pres2, &comm2[..NUM_AUTH_ATTRS])
            .unwrap());

        // But they should be different (unlinkable)
        let hash1 = hash_presentation(&pres1);
        let hash2 = hash_presentation(&pres2);
        assert_ne!(hash1, hash2);
    }
}
