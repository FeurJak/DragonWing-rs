/*
 * SPDX-License-Identifier: MIT
 *
 * X25519 Key Agreement (RFC 7748)
 *
 * This is a minimal X25519 implementation for embedded systems.
 * X25519 is an Elliptic Curve Diffie-Hellman (ECDH) key agreement
 * protocol using Curve25519.
 *
 * Key sizes:
 *   - Secret key: 32 bytes
 *   - Public key: 32 bytes
 *   - Shared secret: 32 bytes
 *
 * Usage:
 *   1. Generate a 32-byte random secret key
 *   2. Call x25519_public_key() to derive the public key
 *   3. Exchange public keys with peer
 *   4. Call x25519_shared_secret() with your secret and peer's public key
 */

#ifndef X25519_H
#define X25519_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key and shared secret sizes */
#define X25519_KEY_SIZE        32
#define X25519_PUBLIC_KEY_SIZE 32
#define X25519_SECRET_KEY_SIZE 32
#define X25519_SHARED_SECRET_SIZE 32

/**
 * Initialize the X25519 library.
 * Must be called before any other X25519 functions.
 * Can be called multiple times safely.
 *
 * @return 0 on success, non-zero on failure
 */
int x25519_init(void);

/**
 * Derive a public key from a secret key.
 *
 * The secret key should be 32 random bytes. This function will
 * apply the necessary clamping (clear bits 0,1,2,255 and set bit 254).
 *
 * @param public_key Output buffer for public key (32 bytes)
 * @param secret_key Input secret key (32 bytes)
 */
void x25519_public_key(uint8_t public_key[X25519_PUBLIC_KEY_SIZE],
                       const uint8_t secret_key[X25519_SECRET_KEY_SIZE]);

/**
 * Compute the shared secret from your secret key and peer's public key.
 *
 * IMPORTANT: The output should be passed through a KDF (like HKDF) before
 * using as a symmetric key. Never use the raw output directly.
 *
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param secret_key Your secret key (32 bytes)
 * @param peer_public_key Peer's public key (32 bytes)
 * @return 0 on success, -1 if peer_public_key is a low-order point
 */
int x25519_shared_secret(uint8_t shared_secret[X25519_SHARED_SECRET_SIZE],
                         const uint8_t secret_key[X25519_SECRET_KEY_SIZE],
                         const uint8_t peer_public_key[X25519_PUBLIC_KEY_SIZE]);

/**
 * Perform X25519 scalar multiplication: result = scalar * point
 *
 * This is the core X25519 operation. Both x25519_public_key() and
 * x25519_shared_secret() are implemented using this function.
 *
 * @param result Output buffer (32 bytes)
 * @param scalar Input scalar (32 bytes, will be clamped)
 * @param point Input point (32 bytes)
 */
void x25519_scalarmult(uint8_t result[X25519_KEY_SIZE],
                       const uint8_t scalar[X25519_KEY_SIZE],
                       const uint8_t point[X25519_KEY_SIZE]);

/**
 * Generate a keypair using provided random bytes.
 *
 * @param public_key Output buffer for public key (32 bytes)
 * @param secret_key Input random bytes as secret key (32 bytes)
 */
void x25519_keypair(uint8_t public_key[X25519_PUBLIC_KEY_SIZE],
                    const uint8_t secret_key[X25519_SECRET_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* X25519_H */
