// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Classical Cryptography Modules
//
// This module provides access to classical cryptographic primitives:
// - Ed25519 digital signatures (RFC 8032)
// - X25519 key agreement (RFC 7748)
// - XChaCha20-Poly1305 authenticated encryption

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

/// XChaCha20-Poly1305 authenticated encryption.
///
/// Uses mbedTLS for ChaCha20-Poly1305 with HChaCha20 for extended nonces.
#[cfg(feature = "xchacha20poly1305")]
pub mod xchacha20poly1305;
