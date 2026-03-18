/*
 * SPDX-License-Identifier: MIT
 *
 * Ed25519 Digital Signatures (RFC 8032)
 *
 * This is a minimal Ed25519 implementation for embedded systems.
 * Based on the ref10 implementation from SUPERCOP/NaCl.
 *
 * Key sizes:
 *   - Secret key (seed): 32 bytes
 *   - Public key: 32 bytes  
 *   - Signature: 64 bytes
 *
 * Usage:
 *   1. Generate or import a 32-byte seed as the secret key
 *   2. Call ed25519_get_pubkey() to derive the public key
 *   3. Call ed25519_sign() to sign messages
 *   4. Call ed25519_verify() to verify signatures
 */

#ifndef ED25519_H
#define ED25519_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key and signature sizes */
#define ED25519_SECRET_KEY_SIZE  32
#define ED25519_PUBLIC_KEY_SIZE  32
#define ED25519_SIGNATURE_SIZE   64

/**
 * Initialize the Ed25519 library.
 * Must be called before any other Ed25519 functions.
 * Can be called multiple times safely.
 * 
 * @return 0 on success, non-zero on failure
 */
int ed25519_init(void);

/**
 * Derive the public key from a secret key (seed).
 *
 * @param public_key Output buffer for public key (32 bytes)
 * @param secret_key Input secret key/seed (32 bytes)
 */
void ed25519_get_pubkey(uint8_t public_key[ED25519_PUBLIC_KEY_SIZE],
                        const uint8_t secret_key[ED25519_SECRET_KEY_SIZE]);

/**
 * Sign a message with a secret key.
 *
 * @param signature Output buffer for signature (64 bytes)
 * @param message Message to sign
 * @param message_len Length of message in bytes
 * @param secret_key Secret key/seed (32 bytes)
 * @param public_key Public key (32 bytes) - must match secret_key
 */
void ed25519_sign(uint8_t signature[ED25519_SIGNATURE_SIZE],
                  const uint8_t *message, size_t message_len,
                  const uint8_t secret_key[ED25519_SECRET_KEY_SIZE],
                  const uint8_t public_key[ED25519_PUBLIC_KEY_SIZE]);

/**
 * Verify a signature on a message.
 *
 * @param signature Signature to verify (64 bytes)
 * @param message Message that was signed
 * @param message_len Length of message in bytes
 * @param public_key Public key of signer (32 bytes)
 * @return 1 if signature is valid, 0 if invalid
 */
int ed25519_verify(const uint8_t signature[ED25519_SIGNATURE_SIZE],
                   const uint8_t *message, size_t message_len,
                   const uint8_t public_key[ED25519_PUBLIC_KEY_SIZE]);

/**
 * Create a key pair using random bytes.
 *
 * @param public_key Output buffer for public key (32 bytes)
 * @param secret_key Input/output: random seed on input, unchanged on output (32 bytes)
 */
void ed25519_create_keypair(uint8_t public_key[ED25519_PUBLIC_KEY_SIZE],
                            const uint8_t secret_key[ED25519_SECRET_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* ED25519_H */
