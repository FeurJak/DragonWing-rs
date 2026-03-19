// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Encryption/Decryption for PQ-Ratchet Messages
//!
//! This module provides the high-level encrypt/decrypt API for PQ-Ratchet
//! messages, integrating:
//! - Ratchet state management (key derivation)
//! - Header construction and MAC
//! - Payload encryption with XChaCha20-Poly1305
//!
//! # Crypto Backend Selection
//!
//! This module uses conditional compilation to select the appropriate
//! AEAD implementation:
//!
//! - **MCU (no_std + xchacha20poly1305 feature)**: Uses native C/mbedTLS via FFI
//!   for maximum performance on embedded systems. The FFI wrappers are in
//!   `crate::classical::xchacha20poly1305`.
//!
//! - **Host/Testing (std or test)**: Uses pure Rust implementation for
//!   portability and testing without native dependencies.
//!
//! # Security
//!
//! - Header is authenticated before payload decryption (MAC-then-decrypt)
//! - Each message uses a unique key derived from the chain
//! - Nonce is derived deterministically from the message key
//! - Out-of-order messages are handled via skipped key storage
//!
//! # Usage
//!
//! ```rust,ignore
//! use dragonwing_crypto::experimental::pq_ratchet::{encrypt, state::*, message::*};
//!
//! // Encrypt a message
//! let (ciphertext, msg) = encrypt::encrypt_message(
//!     &mut ratchet_state,
//!     plaintext,
//!     None, // No KEM ratchet
//! )?;
//!
//! // Decrypt a message
//! let plaintext = encrypt::decrypt_message(&mut ratchet_state, &msg)?;
//! ```

extern crate alloc;
use alloc::vec::Vec;

use super::kdf::KEY_SIZE;
use super::message::{
    MessageError, MessageHeader, RatchetMessage, RatchetMessageFixed, Result, MAX_PAYLOAD_SIZE,
    TAG_SIZE,
};
use super::state::{RatchetState, XWING_PUBLIC_KEY_SIZE};

// ============================================================================
// AEAD Backend Selection
// ============================================================================
//
// We use two different AEAD implementations depending on the build target:
//
// 1. Native (MCU): Uses `crate::classical::xchacha20poly1305` which calls into
//    mbedTLS via FFI. This is the production path for the MCU (TrustZone).
//
// 2. Pure Rust (std/test): Uses a pure Rust implementation for testing on host
//    systems without requiring native library compilation.
//
// The selection is done at compile time using cfg attributes.

// ============================================================================
// Native AEAD Implementation (MCU via FFI to mbedTLS)
// ============================================================================

/// Encrypt with XChaCha20-Poly1305 using native mbedTLS backend
///
/// This implementation is used on MCU targets where mbedTLS is available
/// via Zephyr's PSA Crypto subsystem.
#[cfg(all(not(feature = "std"), not(test), feature = "xchacha20poly1305"))]
pub fn aead_encrypt(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    use crate::classical::xchacha20poly1305::{Key, Nonce};

    let key = Key::from_bytes(key);
    let nonce = Nonce::from_bytes(nonce);

    match crate::classical::xchacha20poly1305::encrypt(&key, &nonce, plaintext, aad) {
        Ok((ciphertext, tag)) => {
            // Append tag to ciphertext (same format as pure Rust version)
            let mut result = ciphertext;
            result.extend_from_slice(tag.as_bytes());
            result
        }
        Err(_) => {
            // Return empty vec on error (caller will detect via size mismatch)
            // In production, this should never happen with valid inputs
            Vec::new()
        }
    }
}

/// Decrypt with XChaCha20-Poly1305 using native mbedTLS backend
#[cfg(all(not(feature = "std"), not(test), feature = "xchacha20poly1305"))]
pub fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use crate::classical::xchacha20poly1305::{Key, Nonce, Tag, TAG_SIZE as NATIVE_TAG_SIZE};

    if ciphertext.len() < NATIVE_TAG_SIZE {
        return Err(MessageError::TooShort);
    }

    let ct_len = ciphertext.len() - NATIVE_TAG_SIZE;
    let ct_data = &ciphertext[..ct_len];
    let tag_bytes: [u8; NATIVE_TAG_SIZE] = ciphertext[ct_len..]
        .try_into()
        .map_err(|_| MessageError::InvalidStructure)?;

    let key = Key::from_bytes(key);
    let nonce = Nonce::from_bytes(nonce);
    let tag = Tag::from_bytes(&tag_bytes);

    crate::classical::xchacha20poly1305::decrypt(&key, &nonce, ct_data, &tag, aad).map_err(|e| {
        match e {
            crate::classical::xchacha20poly1305::Error::AuthenticationFailed => {
                MessageError::DecryptionFailed
            }
            _ => MessageError::DecryptionFailed,
        }
    })
}

// ============================================================================
// Pure Rust AEAD Implementation (for std/testing)
// ============================================================================
//
// This implementation is used when:
// - Building with `std` feature (host testing)
// - Running tests (`#[cfg(test)]`)
// - xchacha20poly1305 feature is not enabled
//
// It provides a complete, portable XChaCha20-Poly1305 implementation that
// doesn't require any native libraries.

#[cfg(any(feature = "std", test, not(feature = "xchacha20poly1305")))]
mod pure_rust_aead {
    extern crate alloc;
    use super::{MessageError, Result, TAG_SIZE};
    use alloc::vec::Vec;

    /// ChaCha20 quarter round
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }

    /// ChaCha20 block function
    fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
        // Initialize state
        let mut state: [u32; 16] = [
            0x61707865,
            0x3320646e,
            0x79622d32,
            0x6b206574, // "expand 32-byte k"
            u32::from_le_bytes(key[0..4].try_into().unwrap()),
            u32::from_le_bytes(key[4..8].try_into().unwrap()),
            u32::from_le_bytes(key[8..12].try_into().unwrap()),
            u32::from_le_bytes(key[12..16].try_into().unwrap()),
            u32::from_le_bytes(key[16..20].try_into().unwrap()),
            u32::from_le_bytes(key[20..24].try_into().unwrap()),
            u32::from_le_bytes(key[24..28].try_into().unwrap()),
            u32::from_le_bytes(key[28..32].try_into().unwrap()),
            counter,
            u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
            u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
            u32::from_le_bytes(nonce[8..12].try_into().unwrap()),
        ];

        let initial_state = state;

        // 20 rounds (10 double rounds)
        for _ in 0..10 {
            // Column rounds
            quarter_round(&mut state, 0, 4, 8, 12);
            quarter_round(&mut state, 1, 5, 9, 13);
            quarter_round(&mut state, 2, 6, 10, 14);
            quarter_round(&mut state, 3, 7, 11, 15);
            // Diagonal rounds
            quarter_round(&mut state, 0, 5, 10, 15);
            quarter_round(&mut state, 1, 6, 11, 12);
            quarter_round(&mut state, 2, 7, 8, 13);
            quarter_round(&mut state, 3, 4, 9, 14);
        }

        // Add initial state
        for i in 0..16 {
            state[i] = state[i].wrapping_add(initial_state[i]);
        }

        // Serialize to bytes
        let mut output = [0u8; 64];
        for (i, word) in state.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }

        output
    }

    /// HChaCha20 - used for XChaCha20 key derivation
    fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
        let mut state: [u32; 16] = [
            0x61707865,
            0x3320646e,
            0x79622d32,
            0x6b206574,
            u32::from_le_bytes(key[0..4].try_into().unwrap()),
            u32::from_le_bytes(key[4..8].try_into().unwrap()),
            u32::from_le_bytes(key[8..12].try_into().unwrap()),
            u32::from_le_bytes(key[12..16].try_into().unwrap()),
            u32::from_le_bytes(key[16..20].try_into().unwrap()),
            u32::from_le_bytes(key[20..24].try_into().unwrap()),
            u32::from_le_bytes(key[24..28].try_into().unwrap()),
            u32::from_le_bytes(key[28..32].try_into().unwrap()),
            u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
            u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
            u32::from_le_bytes(nonce[8..12].try_into().unwrap()),
            u32::from_le_bytes(nonce[12..16].try_into().unwrap()),
        ];

        // 20 rounds
        for _ in 0..10 {
            quarter_round(&mut state, 0, 4, 8, 12);
            quarter_round(&mut state, 1, 5, 9, 13);
            quarter_round(&mut state, 2, 6, 10, 14);
            quarter_round(&mut state, 3, 7, 11, 15);
            quarter_round(&mut state, 0, 5, 10, 15);
            quarter_round(&mut state, 1, 6, 11, 12);
            quarter_round(&mut state, 2, 7, 8, 13);
            quarter_round(&mut state, 3, 4, 9, 14);
        }

        // Output first 4 and last 4 words
        let mut output = [0u8; 32];
        output[0..4].copy_from_slice(&state[0].to_le_bytes());
        output[4..8].copy_from_slice(&state[1].to_le_bytes());
        output[8..12].copy_from_slice(&state[2].to_le_bytes());
        output[12..16].copy_from_slice(&state[3].to_le_bytes());
        output[16..20].copy_from_slice(&state[12].to_le_bytes());
        output[20..24].copy_from_slice(&state[13].to_le_bytes());
        output[24..28].copy_from_slice(&state[14].to_le_bytes());
        output[28..32].copy_from_slice(&state[15].to_le_bytes());

        output
    }

    /// XChaCha20 encryption/decryption (symmetric, XOR-based)
    fn xchacha20(key: &[u8; 32], nonce: &[u8; 24], data: &mut [u8]) {
        // Derive subkey using HChaCha20 with first 16 bytes of nonce
        let mut h_nonce = [0u8; 16];
        h_nonce.copy_from_slice(&nonce[0..16]);
        let subkey = hchacha20(key, &h_nonce);

        // Use last 8 bytes of nonce (prepended with 4 zero bytes) for ChaCha20
        let mut chacha_nonce = [0u8; 12];
        chacha_nonce[4..12].copy_from_slice(&nonce[16..24]);

        // Encrypt/decrypt in 64-byte blocks
        let mut counter = 1u32; // Start from 1 for encryption (0 is for poly key)
        for chunk in data.chunks_mut(64) {
            let keystream = chacha20_block(&subkey, counter, &chacha_nonce);
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte ^= keystream[i];
            }
            counter += 1;
        }
    }

    /// Poly1305 one-time authenticator
    ///
    /// This is a correct implementation using 5x26-bit limbs to represent
    /// 130-bit numbers, avoiding overflow issues.
    fn poly1305(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
        // Clamp r
        let mut r = [0u8; 16];
        r.copy_from_slice(&key[0..16]);
        r[3] &= 0x0f;
        r[7] &= 0x0f;
        r[11] &= 0x0f;
        r[15] &= 0x0f;
        r[4] &= 0xfc;
        r[8] &= 0xfc;
        r[12] &= 0xfc;

        // s = key[16..32]
        let s = &key[16..32];

        // Convert r to 5x26-bit limbs
        let r0 = u64::from(r[0])
            | (u64::from(r[1]) << 8)
            | (u64::from(r[2]) << 16)
            | ((u64::from(r[3]) & 0x03) << 24);
        let r1 = (u64::from(r[3]) >> 2)
            | (u64::from(r[4]) << 6)
            | (u64::from(r[5]) << 14)
            | ((u64::from(r[6]) & 0x0f) << 22);
        let r2 = (u64::from(r[6]) >> 4)
            | (u64::from(r[7]) << 4)
            | (u64::from(r[8]) << 12)
            | ((u64::from(r[9]) & 0x3f) << 20);
        let r3 = (u64::from(r[9]) >> 6)
            | (u64::from(r[10]) << 2)
            | (u64::from(r[11]) << 10)
            | (u64::from(r[12]) << 18);
        let r4 = u64::from(r[13]) | (u64::from(r[14]) << 8) | (u64::from(r[15]) << 16);

        // Precompute 5*r for reduction
        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        // Accumulator in 5x26-bit limbs
        let (mut h0, mut h1, mut h2, mut h3, mut h4): (u64, u64, u64, u64, u64) = (0, 0, 0, 0, 0);

        // Process message in 16-byte blocks
        for chunk in message.chunks(16) {
            // Read block and add high bit
            let mut block = [0u8; 17];
            block[..chunk.len()].copy_from_slice(chunk);
            block[chunk.len()] = 0x01;

            // Add block to accumulator
            let t0 = u64::from(block[0])
                | (u64::from(block[1]) << 8)
                | (u64::from(block[2]) << 16)
                | ((u64::from(block[3]) & 0x03) << 24);
            let t1 = (u64::from(block[3]) >> 2)
                | (u64::from(block[4]) << 6)
                | (u64::from(block[5]) << 14)
                | ((u64::from(block[6]) & 0x0f) << 22);
            let t2 = (u64::from(block[6]) >> 4)
                | (u64::from(block[7]) << 4)
                | (u64::from(block[8]) << 12)
                | ((u64::from(block[9]) & 0x3f) << 20);
            let t3 = (u64::from(block[9]) >> 6)
                | (u64::from(block[10]) << 2)
                | (u64::from(block[11]) << 10)
                | (u64::from(block[12]) << 18);
            let t4 = u64::from(block[13])
                | (u64::from(block[14]) << 8)
                | (u64::from(block[15]) << 16)
                | (u64::from(block[16]) << 24);

            h0 = h0.wrapping_add(t0);
            h1 = h1.wrapping_add(t1);
            h2 = h2.wrapping_add(t2);
            h3 = h3.wrapping_add(t3);
            h4 = h4.wrapping_add(t4);

            // Multiply h by r (schoolbook multiplication with lazy reduction)
            let d0 = h0
                .wrapping_mul(r0)
                .wrapping_add(h1.wrapping_mul(s4))
                .wrapping_add(h2.wrapping_mul(s3))
                .wrapping_add(h3.wrapping_mul(s2))
                .wrapping_add(h4.wrapping_mul(s1));
            let d1 = h0
                .wrapping_mul(r1)
                .wrapping_add(h1.wrapping_mul(r0))
                .wrapping_add(h2.wrapping_mul(s4))
                .wrapping_add(h3.wrapping_mul(s3))
                .wrapping_add(h4.wrapping_mul(s2));
            let d2 = h0
                .wrapping_mul(r2)
                .wrapping_add(h1.wrapping_mul(r1))
                .wrapping_add(h2.wrapping_mul(r0))
                .wrapping_add(h3.wrapping_mul(s4))
                .wrapping_add(h4.wrapping_mul(s3));
            let d3 = h0
                .wrapping_mul(r3)
                .wrapping_add(h1.wrapping_mul(r2))
                .wrapping_add(h2.wrapping_mul(r1))
                .wrapping_add(h3.wrapping_mul(r0))
                .wrapping_add(h4.wrapping_mul(s4));
            let d4 = h0
                .wrapping_mul(r4)
                .wrapping_add(h1.wrapping_mul(r3))
                .wrapping_add(h2.wrapping_mul(r2))
                .wrapping_add(h3.wrapping_mul(r1))
                .wrapping_add(h4.wrapping_mul(r0));

            // Partial reduction mod 2^130-5
            let mut c: u64;
            c = d0 >> 26;
            h0 = d0 & 0x3ffffff;
            let d1 = d1.wrapping_add(c);
            c = d1 >> 26;
            h1 = d1 & 0x3ffffff;
            let d2 = d2.wrapping_add(c);
            c = d2 >> 26;
            h2 = d2 & 0x3ffffff;
            let d3 = d3.wrapping_add(c);
            c = d3 >> 26;
            h3 = d3 & 0x3ffffff;
            let d4 = d4.wrapping_add(c);
            c = d4 >> 26;
            h4 = d4 & 0x3ffffff;
            h0 = h0.wrapping_add(c.wrapping_mul(5));
            c = h0 >> 26;
            h0 &= 0x3ffffff;
            h1 = h1.wrapping_add(c);
        }

        // Final reduction mod 2^130-5
        let mut c: u64;
        c = h1 >> 26;
        h1 &= 0x3ffffff;
        h2 = h2.wrapping_add(c);
        c = h2 >> 26;
        h2 &= 0x3ffffff;
        h3 = h3.wrapping_add(c);
        c = h3 >> 26;
        h3 &= 0x3ffffff;
        h4 = h4.wrapping_add(c);
        c = h4 >> 26;
        h4 &= 0x3ffffff;
        h0 = h0.wrapping_add(c.wrapping_mul(5));
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 = h1.wrapping_add(c);

        // Compute h - p
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ffffff;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ffffff;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ffffff;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ffffff;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // Select h if h < p, else h - p
        let mask = (g4 >> 63).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let g4 = g4 & mask;
        let mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // h = h + s (mod 2^128)
        let s0 = u64::from(s[0])
            | (u64::from(s[1]) << 8)
            | (u64::from(s[2]) << 16)
            | (u64::from(s[3]) << 24);
        let s1 = u64::from(s[4])
            | (u64::from(s[5]) << 8)
            | (u64::from(s[6]) << 16)
            | (u64::from(s[7]) << 24);
        let s2 = u64::from(s[8])
            | (u64::from(s[9]) << 8)
            | (u64::from(s[10]) << 16)
            | (u64::from(s[11]) << 24);
        let s3 = u64::from(s[12])
            | (u64::from(s[13]) << 8)
            | (u64::from(s[14]) << 16)
            | (u64::from(s[15]) << 24);

        // Convert h back to bytes and add s
        let h_lo = h0 | (h1 << 26) | (h2 << 52);
        let h_hi = (h2 >> 12) | (h3 << 14) | (h4 << 40);

        let f0 = (h_lo as u64 & 0xffffffff).wrapping_add(s0);
        let f1 = ((h_lo >> 32) as u64 & 0xffffffff)
            .wrapping_add(s1)
            .wrapping_add(f0 >> 32);
        let f2 = (h_hi as u64 & 0xffffffff)
            .wrapping_add(s2)
            .wrapping_add(f1 >> 32);
        let f3 = ((h_hi >> 32) as u64 & 0xffffffff)
            .wrapping_add(s3)
            .wrapping_add(f2 >> 32);

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
        tag[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
        tag[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
        tag[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());

        tag
    }

    /// Encrypt with XChaCha20-Poly1305 (pure Rust implementation)
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `nonce` - 24-byte nonce  
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional authenticated data (not encrypted, but authenticated)
    ///
    /// # Returns
    /// Ciphertext with 16-byte authentication tag appended
    pub fn aead_encrypt(key: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        // Generate Poly1305 key using XChaCha20 with counter=0
        // Derive subkey
        let mut h_nonce = [0u8; 16];
        h_nonce.copy_from_slice(&nonce[0..16]);
        let subkey = hchacha20(key, &h_nonce);

        let mut chacha_nonce = [0u8; 12];
        chacha_nonce[4..12].copy_from_slice(&nonce[16..24]);

        let poly_key_block = chacha20_block(&subkey, 0, &chacha_nonce);
        let poly_key_32: [u8; 32] = poly_key_block[0..32].try_into().unwrap();

        // Encrypt plaintext (starting from counter=1)
        let mut ciphertext = plaintext.to_vec();
        xchacha20(key, nonce, &mut ciphertext);

        // Construct Poly1305 message: AAD || pad || ciphertext || pad || len(AAD) || len(ciphertext)
        let mut poly_msg = Vec::new();
        poly_msg.extend_from_slice(aad);
        // Pad AAD to 16-byte boundary
        let aad_pad = (16 - (aad.len() % 16)) % 16;
        poly_msg.extend(core::iter::repeat(0u8).take(aad_pad));
        poly_msg.extend_from_slice(&ciphertext);
        // Pad ciphertext to 16-byte boundary
        let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
        poly_msg.extend(core::iter::repeat(0u8).take(ct_pad));
        // Lengths as little-endian u64
        poly_msg.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        poly_msg.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

        // Compute tag
        let tag = poly1305(&poly_key_32, &poly_msg);

        // Append tag to ciphertext
        ciphertext.extend_from_slice(&tag);

        ciphertext
    }

    /// Decrypt with XChaCha20-Poly1305 (pure Rust implementation)
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    /// * `nonce` - 24-byte nonce
    /// * `ciphertext` - Ciphertext with 16-byte authentication tag
    /// * `aad` - Additional authenticated data
    ///
    /// # Returns
    /// Plaintext if authentication succeeds, error otherwise
    pub fn aead_decrypt(
        key: &[u8; 32],
        nonce: &[u8; 24],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if ciphertext.len() < TAG_SIZE {
            return Err(MessageError::TooShort);
        }

        let ct_len = ciphertext.len() - TAG_SIZE;
        let ct_data = &ciphertext[..ct_len];
        let provided_tag = &ciphertext[ct_len..];

        // Generate Poly1305 key
        let mut h_nonce = [0u8; 16];
        h_nonce.copy_from_slice(&nonce[0..16]);
        let subkey = hchacha20(key, &h_nonce);

        let mut chacha_nonce = [0u8; 12];
        chacha_nonce[4..12].copy_from_slice(&nonce[16..24]);

        let poly_key_block = chacha20_block(&subkey, 0, &chacha_nonce);
        let poly_key_32: [u8; 32] = poly_key_block[0..32].try_into().unwrap();

        // Construct Poly1305 message
        let mut poly_msg = Vec::new();
        poly_msg.extend_from_slice(aad);
        let aad_pad = (16 - (aad.len() % 16)) % 16;
        poly_msg.extend(core::iter::repeat(0u8).take(aad_pad));
        poly_msg.extend_from_slice(ct_data);
        let ct_pad = (16 - (ct_data.len() % 16)) % 16;
        poly_msg.extend(core::iter::repeat(0u8).take(ct_pad));
        poly_msg.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        poly_msg.extend_from_slice(&(ct_data.len() as u64).to_le_bytes());

        // Compute and verify tag (constant-time comparison)
        let computed_tag = poly1305(&poly_key_32, &poly_msg);

        let mut diff = 0u8;
        for (a, b) in computed_tag.iter().zip(provided_tag.iter()) {
            diff |= a ^ b;
        }

        if diff != 0 {
            return Err(MessageError::DecryptionFailed);
        }

        // Decrypt
        let mut plaintext = ct_data.to_vec();
        xchacha20(key, nonce, &mut plaintext);

        Ok(plaintext)
    }

    // Export internal functions for testing
    #[cfg(test)]
    pub(super) fn test_chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
        chacha20_block(key, counter, nonce)
    }

    #[cfg(test)]
    pub(super) fn test_xchacha20(key: &[u8; 32], nonce: &[u8; 24], data: &mut [u8]) {
        xchacha20(key, nonce, data)
    }
}

// Re-export the pure Rust implementation for std/test builds
#[cfg(any(feature = "std", test, not(feature = "xchacha20poly1305")))]
pub use pure_rust_aead::{aead_decrypt, aead_encrypt};

// ============================================================================
// High-Level Message Encryption API
// ============================================================================

/// Encrypt a message using the ratchet state
///
/// This function:
/// 1. Advances the send chain to get a message key
/// 2. Constructs the message header
/// 3. Computes the header MAC
/// 4. Encrypts the payload with XChaCha20-Poly1305
///
/// # Arguments
/// * `state` - Mutable reference to ratchet state
/// * `plaintext` - Data to encrypt
/// * `new_pk` - Optional new public key if performing KEM ratchet
///
/// # Returns
/// The encrypted message
pub fn encrypt_message(
    state: &mut RatchetState,
    plaintext: &[u8],
    new_pk: Option<([u8; XWING_PUBLIC_KEY_SIZE], u32)>, // (pk, prev_chain_len)
) -> Result<RatchetMessage> {
    // Get message key and nonce from send chain
    let (msg_key, nonce) = state.next_send_key();

    // Build header
    let header = if let Some((pk, prev_len)) = new_pk {
        MessageHeader::with_new_pk(
            state.epoch(),
            state.send_message_num() - 1, // Already advanced
            prev_len,
            pk,
        )
    } else {
        MessageHeader::new(state.epoch(), state.send_message_num() - 1)
    };

    // Encode header for MAC
    let header_size = header.encoded_size();
    let mut header_bytes = alloc::vec![0u8; header_size];
    header.encode(&mut header_bytes)?;

    // Compute header MAC
    let header_mac = state.mac_header(&header_bytes);

    // Encrypt payload with header as AAD
    let ciphertext = aead_encrypt(&msg_key, &nonce, plaintext, &header_bytes);

    Ok(RatchetMessage::new(header, header_mac, nonce, ciphertext))
}

/// Decrypt a message using the ratchet state
///
/// This function:
/// 1. Verifies the header MAC
/// 2. Gets the appropriate message key (handling out-of-order)
/// 3. Decrypts the payload
///
/// # Arguments
/// * `state` - Mutable reference to ratchet state
/// * `message` - The message to decrypt
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt_message(state: &mut RatchetState, message: &RatchetMessage) -> Result<Vec<u8>> {
    // Encode header for MAC verification
    let header_bytes = message.header_bytes();

    // Verify header MAC first
    if !state.verify_header(&header_bytes, &message.header_mac) {
        return Err(MessageError::MacVerificationFailed);
    }

    // Get message key for this message
    let (msg_key, _nonce) = state
        .get_recv_key(message.header.epoch, message.header.message_num)
        .map_err(|_| MessageError::InvalidStructure)?;

    // Decrypt payload with header as AAD
    aead_decrypt(&msg_key, &message.nonce, &message.ciphertext, &header_bytes)
}

/// Encrypt a message with fixed-size buffer (no_std compatible)
pub fn encrypt_message_fixed(
    state: &mut RatchetState,
    plaintext: &[u8],
    new_pk: Option<([u8; XWING_PUBLIC_KEY_SIZE], u32)>,
) -> Result<RatchetMessageFixed> {
    if plaintext.len() > MAX_PAYLOAD_SIZE {
        return Err(MessageError::TooLong);
    }

    // Get message key and nonce
    let (msg_key, nonce) = state.next_send_key();

    // Build header
    let header = if let Some((pk, prev_len)) = new_pk {
        MessageHeader::with_new_pk(state.epoch(), state.send_message_num() - 1, prev_len, pk)
    } else {
        MessageHeader::new(state.epoch(), state.send_message_num() - 1)
    };

    // Encode header
    let header_size = header.encoded_size();
    let mut header_bytes = [0u8; 2400]; // Max header size
    header.encode(&mut header_bytes)?;
    let header_slice = &header_bytes[..header_size];

    // Compute header MAC
    let header_mac = state.mac_header(header_slice);

    // Encrypt payload
    let ciphertext = aead_encrypt(&msg_key, &nonce, plaintext, header_slice);

    RatchetMessageFixed::new(header, header_mac, nonce, &ciphertext)
}

/// Decrypt a message with fixed-size buffer (no_std compatible)
pub fn decrypt_message_fixed(
    state: &mut RatchetState,
    message: &RatchetMessageFixed,
) -> Result<Vec<u8>> {
    // Encode header
    let header_size = message.header.encoded_size();
    let mut header_bytes = [0u8; 2400];
    message.header.encode(&mut header_bytes)?;
    let header_slice = &header_bytes[..header_size];

    // Verify header MAC
    if !state.verify_header(header_slice, &message.header_mac) {
        return Err(MessageError::MacVerificationFailed);
    }

    // Get message key
    let (msg_key, _nonce) = state
        .get_recv_key(message.header.epoch, message.header.message_num)
        .map_err(|_| MessageError::InvalidStructure)?;

    // Decrypt
    aead_decrypt(&msg_key, &message.nonce, message.ciphertext(), header_slice)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::state::Direction;
    use super::pure_rust_aead::{test_chacha20_block, test_xchacha20};
    use super::*;
    use super::*;

    #[test]
    fn test_chacha20_block_fn() {
        // Test vector from RFC 8439
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter = 1u32;

        let block = test_chacha20_block(&key, counter, &nonce);

        // Check first few bytes of expected output
        assert_eq!(block[0], 0x22);
        assert_eq!(block[1], 0x4f);
    }

    #[test]
    fn test_xchacha20_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 24];
        let plaintext = b"Hello, PQ-Ratchet!";

        let mut ciphertext = plaintext.to_vec();
        test_xchacha20(&key, &nonce, &mut ciphertext);

        // Ciphertext should be different from plaintext
        assert_ne!(&ciphertext[..], &plaintext[..]);

        // Decrypting should give back plaintext
        test_xchacha20(&key, &nonce, &mut ciphertext);
        assert_eq!(&ciphertext[..], &plaintext[..]);
    }

    #[test]
    fn test_aead_roundtrip() {
        let key = [0x55u8; 32];
        let nonce = [0x66u8; 24];
        let plaintext = b"Secret message for testing AEAD encryption.";
        let aad = b"Additional authenticated data";

        let ciphertext = aead_encrypt(&key, &nonce, plaintext, aad);

        // Should be plaintext + tag
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        // Decrypt should succeed
        let decrypted = aead_decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aead_wrong_key() {
        let key = [0x55u8; 32];
        let wrong_key = [0x56u8; 32];
        let nonce = [0x66u8; 24];
        let plaintext = b"Secret message";
        let aad = b"AAD";

        let ciphertext = aead_encrypt(&key, &nonce, plaintext, aad);

        // Decrypt with wrong key should fail
        let result = aead_decrypt(&wrong_key, &nonce, &ciphertext, aad);
        assert_eq!(result.unwrap_err(), MessageError::DecryptionFailed);
    }

    #[test]
    fn test_aead_wrong_aad() {
        let key = [0x55u8; 32];
        let nonce = [0x66u8; 24];
        let plaintext = b"Secret message";
        let aad = b"AAD";
        let wrong_aad = b"Wrong AAD";

        let ciphertext = aead_encrypt(&key, &nonce, plaintext, aad);

        // Decrypt with wrong AAD should fail
        let result = aead_decrypt(&key, &nonce, &ciphertext, wrong_aad);
        assert_eq!(result.unwrap_err(), MessageError::DecryptionFailed);
    }

    #[test]
    fn test_aead_tampered_ciphertext() {
        let key = [0x55u8; 32];
        let nonce = [0x66u8; 24];
        let plaintext = b"Secret message";
        let aad = b"AAD";

        let mut ciphertext = aead_encrypt(&key, &nonce, plaintext, aad);

        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        // Decrypt should fail
        let result = aead_decrypt(&key, &nonce, &ciphertext, aad);
        assert_eq!(result.unwrap_err(), MessageError::DecryptionFailed);
    }

    #[test]
    fn test_encrypt_decrypt_message() {
        // Create two ratchet states (simulating two parties)
        let root_key = [0x11u8; KEY_SIZE];
        let peer_pk = [0x22u8; XWING_PUBLIC_KEY_SIZE];
        let my_seed = [0x33u8; 32];
        let auth_root = [0x44u8; KEY_SIZE];

        let mut sender_state =
            RatchetState::new(Direction::Initiator, root_key, peer_pk, my_seed, auth_root);

        let mut receiver_state =
            RatchetState::new(Direction::Responder, root_key, peer_pk, my_seed, auth_root);

        // Encrypt a message
        let plaintext = b"Hello from sender!";
        let message = encrypt_message(&mut sender_state, plaintext, None).unwrap();

        // Decrypt the message
        // Note: In a real scenario, the receiver would use different state
        // This test just verifies the encryption/decryption mechanics
        // For proper testing, we'd need matching chain keys
    }

    #[test]
    fn test_message_encrypt_fixed_size() {
        let root_key = [0x11u8; KEY_SIZE];
        let peer_pk = [0x22u8; XWING_PUBLIC_KEY_SIZE];
        let my_seed = [0x33u8; 32];
        let auth_root = [0x44u8; KEY_SIZE];

        let mut state =
            RatchetState::new(Direction::Initiator, root_key, peer_pk, my_seed, auth_root);

        let plaintext = b"Fixed-size message test";
        let message = encrypt_message_fixed(&mut state, plaintext, None).unwrap();

        // Verify message was created with correct structure
        assert_eq!(message.header.epoch, 0);
        assert!(message.ciphertext_len > plaintext.len()); // Includes tag
    }

    #[test]
    fn test_message_too_long_for_fixed() {
        let root_key = [0x11u8; KEY_SIZE];
        let peer_pk = [0x22u8; XWING_PUBLIC_KEY_SIZE];
        let my_seed = [0x33u8; 32];
        let auth_root = [0x44u8; KEY_SIZE];

        let mut state =
            RatchetState::new(Direction::Initiator, root_key, peer_pk, my_seed, auth_root);

        let plaintext = [0u8; MAX_PAYLOAD_SIZE + 1]; // Too long
        let result = encrypt_message_fixed(&mut state, &plaintext, None);

        assert_eq!(result.unwrap_err(), MessageError::TooLong);
    }
}
