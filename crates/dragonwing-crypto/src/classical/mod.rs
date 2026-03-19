// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Classical Cryptography Modules
//
// This module provides access to classical cryptographic primitives:
// - Ed25519 digital signatures (RFC 8032)
// - X25519 key agreement (RFC 7748)
// - ChaCha20-Poly1305 authenticated encryption (RFC 8439, 12-byte nonce)
// - XChaCha20-Poly1305 authenticated encryption (24-byte nonce)

/// Ed25519 digital signatures (RFC 8032).
///
/// Uses a standalone C implementation optimized for embedded systems.
#[cfg(feature = "ed25519")]
pub mod ed25519;

/// X25519 key agreement (RFC 7748).
///
/// Uses a standalone C implementation optimized for embedded systems.
#[cfg(feature = "x25519")]
pub mod x25519;

/// ChaCha20-Poly1305 authenticated encryption (RFC 8439).
///
/// Uses mbedTLS directly for standard ChaCha20-Poly1305 with 12-byte nonces.
/// This is the cipher used by TLS 1.3, QUIC, WireGuard, and BPP.
///
/// Note: 12-byte nonces are NOT safe for random generation. Use a counter
/// or hybrid scheme (e.g., timestamp + random as in BPP).
#[cfg(feature = "chacha20poly1305")]
pub mod chacha20poly1305;

/// XChaCha20-Poly1305 authenticated encryption.
///
/// Uses mbedTLS for ChaCha20-Poly1305 with HChaCha20 for extended nonces.
/// The 24-byte nonce is safe for random generation.
#[cfg(feature = "xchacha20poly1305")]
pub mod xchacha20poly1305;
