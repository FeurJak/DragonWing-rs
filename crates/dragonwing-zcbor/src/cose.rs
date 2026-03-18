// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// COSE (CBOR Object Signing and Encryption) Support
//
// Implements COSE_Sign1 structure (RFC 9052) for single-signer signed messages.
// Uses zcbor for CBOR encoding/decoding and dragonwing-crypto for ML-DSA.
//
// # COSE_Sign1 Structure
//
// ```text
// COSE_Sign1 = [
//     protected: bstr .cbor header_map,  // Protected headers (algorithm ID)
//     unprotected: header_map,           // Unprotected headers (empty)
//     payload: bstr / nil,               // The signed content
//     signature: bstr                    // The signature
// ]
// ```

use crate::{Decoder, Encoder, Error, Result};

/// COSE Algorithm identifiers
///
/// These are registered in the IANA COSE Algorithms registry.
/// ML-DSA algorithms use temporary/experimental values until IANA assigns official ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Algorithm {
    /// ML-DSA-44 (NIST Level 2) - Experimental algorithm ID
    MlDsa44 = -48,
    /// ML-DSA-65 (NIST Level 3) - Experimental algorithm ID  
    MlDsa65 = -49,
    /// ML-DSA-87 (NIST Level 5) - Experimental algorithm ID
    MlDsa87 = -50,
}

impl Algorithm {
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            -48 => Some(Algorithm::MlDsa44),
            -49 => Some(Algorithm::MlDsa65),
            -50 => Some(Algorithm::MlDsa87),
            _ => None,
        }
    }
}

/// COSE header labels
const HEADER_ALG: i32 = 1;

/// Errors specific to COSE operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseError {
    /// CBOR encoding/decoding failed
    Cbor(Error),
    /// Buffer too small
    BufferTooSmall,
    /// Invalid COSE structure
    InvalidStructure,
    /// Unsupported algorithm
    UnsupportedAlgorithm,
    /// Signature verification failed
    SignatureInvalid,
    /// Signing operation failed
    SigningFailed,
}

impl From<Error> for CoseError {
    fn from(e: Error) -> Self {
        CoseError::Cbor(e)
    }
}

/// COSE_Sign1 - Single signer signed message
pub struct CoseSign1;

impl CoseSign1 {
    /// Create the Sig_structure for signing/verification
    ///
    /// ```text
    /// Sig_structure = [
    ///     context: "Signature1",
    ///     body_protected: bstr,
    ///     external_aad: bstr,
    ///     payload: bstr
    /// ]
    /// ```
    fn create_sig_structure(
        protected_header: &[u8],
        payload: &[u8],
        buf: &mut [u8],
    ) -> core::result::Result<usize, CoseError> {
        let mut enc = Encoder::new(buf);

        enc.array(4)?;
        enc.str("Signature1")?;
        enc.bytes(protected_header)?;
        enc.bytes(&[])?; // external_aad (empty)
        enc.bytes(payload)?;

        Ok(enc.bytes_written())
    }

    /// Encode protected headers (algorithm ID)
    fn encode_protected_header(
        alg: Algorithm,
        buf: &mut [u8],
    ) -> core::result::Result<usize, CoseError> {
        let mut enc = Encoder::new(buf);

        // Protected header is a map with just the algorithm
        enc.map(1)?;
        enc.i32(HEADER_ALG)?;
        enc.i32(alg as i32)?;

        Ok(enc.bytes_written())
    }

    /// Sign a payload and produce a COSE_Sign1 message with ML-DSA-65
    ///
    /// # Arguments
    /// * `payload` - The data to sign
    /// * `signing_key` - The ML-DSA signing key
    /// * `rng` - Hardware RNG for signing randomness
    /// * `output` - Buffer for the output COSE_Sign1 message
    ///
    /// # Returns
    /// The number of bytes written to output, or an error
    pub fn sign_mldsa65(
        payload: &[u8],
        signing_key: &dragonwing_crypto::dsa::SigningKey,
        rng: &dragonwing_crypto::rng::HwRng,
        output: &mut [u8],
    ) -> core::result::Result<usize, CoseError> {
        use dragonwing_crypto::dsa;

        // Encode protected header
        let mut protected_buf = [0u8; 16];
        let protected_len = Self::encode_protected_header(Algorithm::MlDsa65, &mut protected_buf)?;
        let protected_header = &protected_buf[..protected_len];

        // Create Sig_structure for signing
        let mut sig_structure_buf = [0u8; 512];
        let sig_structure_len =
            Self::create_sig_structure(protected_header, payload, &mut sig_structure_buf)?;
        let sig_structure = &sig_structure_buf[..sig_structure_len];

        // Sign the Sig_structure
        let signing_randomness: [u8; dsa::SIGNING_RANDOMNESS_SIZE] = rng.random_array();
        let signature = dsa::sign(
            signing_key,
            sig_structure,
            b"", // empty context for COSE
            signing_randomness,
        )
        .map_err(|_| CoseError::SigningFailed)?;

        // Encode COSE_Sign1 structure
        let mut enc = Encoder::new(output);

        enc.array(4)?;
        enc.bytes(protected_header)?;
        enc.map(0)?; // empty unprotected headers
        enc.bytes(payload)?;
        enc.bytes(signature.as_ref())?;

        Ok(enc.bytes_written())
    }

    /// Verify a COSE_Sign1 message and return the payload
    ///
    /// # Arguments
    /// * `cose_sign1` - The COSE_Sign1 message bytes
    /// * `verification_key` - The ML-DSA verification key
    ///
    /// # Returns
    /// A reference to the payload within the input buffer, or an error
    pub fn verify_mldsa65<'a>(
        cose_sign1: &'a [u8],
        verification_key: &dragonwing_crypto::dsa::VerificationKey,
    ) -> core::result::Result<&'a [u8], CoseError> {
        use dragonwing_crypto::dsa;

        let mut dec = Decoder::new(cose_sign1);

        // Decode COSE_Sign1 array
        let len = dec.array()?.ok_or(CoseError::InvalidStructure)?;
        if len != 4 {
            return Err(CoseError::InvalidStructure);
        }

        // Get protected header bytes
        let protected_header = dec.bytes()?;

        // Skip unprotected headers (should be empty map)
        dec.skip()?;

        // Get payload
        let payload = dec.bytes()?;

        // Get signature
        let signature_bytes = dec.bytes()?;

        // Verify algorithm from protected header
        let mut header_dec = Decoder::new(protected_header);
        let header_len = header_dec.map()?.ok_or(CoseError::InvalidStructure)?;

        let mut found_alg = false;
        for _ in 0..header_len {
            let label = header_dec.i32()?;
            if label == HEADER_ALG {
                let alg_id = header_dec.i32()?;
                if Algorithm::from_i32(alg_id) != Some(Algorithm::MlDsa65) {
                    return Err(CoseError::UnsupportedAlgorithm);
                }
                found_alg = true;
            } else {
                header_dec.skip()?;
            }
        }
        if !found_alg {
            return Err(CoseError::InvalidStructure);
        }

        // Reconstruct Sig_structure for verification
        let mut sig_structure_buf = [0u8; 512];
        let sig_structure_len =
            Self::create_sig_structure(protected_header, payload, &mut sig_structure_buf)?;
        let sig_structure = &sig_structure_buf[..sig_structure_len];

        // Convert signature bytes to Signature type
        if signature_bytes.len() != dsa::SIGNATURE_SIZE {
            return Err(CoseError::SignatureInvalid);
        }
        let mut sig_array = [0u8; dsa::SIGNATURE_SIZE];
        sig_array.copy_from_slice(signature_bytes);
        let signature = dsa::signature_from_bytes(sig_array);

        // Verify signature
        dsa::verify(
            verification_key,
            sig_structure,
            b"", // empty context for COSE
            &signature,
        )
        .map_err(|_| CoseError::SignatureInvalid)?;

        Ok(payload)
    }

    /// Decode a COSE_Sign1 message without verification
    ///
    /// Useful for inspecting the payload or algorithm before verification.
    pub fn decode_unverified(
        cose_sign1: &[u8],
    ) -> core::result::Result<CoseSign1Parts<'_>, CoseError> {
        let mut dec = Decoder::new(cose_sign1);

        let len = dec.array()?.ok_or(CoseError::InvalidStructure)?;
        if len != 4 {
            return Err(CoseError::InvalidStructure);
        }

        let protected_header = dec.bytes()?;
        dec.skip()?; // unprotected headers
        let payload = dec.bytes()?;
        let signature = dec.bytes()?;

        // Parse algorithm from protected header
        let mut header_dec = Decoder::new(protected_header);
        let header_len = header_dec.map()?.ok_or(CoseError::InvalidStructure)?;

        let mut algorithm = None;
        for _ in 0..header_len {
            let label = header_dec.i32()?;
            if label == HEADER_ALG {
                let alg_id = header_dec.i32()?;
                algorithm = Algorithm::from_i32(alg_id);
            } else {
                header_dec.skip()?;
            }
        }

        Ok(CoseSign1Parts {
            algorithm,
            payload,
            signature,
        })
    }
}

/// Decoded parts of a COSE_Sign1 message
pub struct CoseSign1Parts<'a> {
    /// The signing algorithm (if recognized)
    pub algorithm: Option<Algorithm>,
    /// The signed payload
    pub payload: &'a [u8],
    /// The signature bytes
    pub signature: &'a [u8],
}
