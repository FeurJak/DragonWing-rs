/*
 * SPDX-License-Identifier: MIT
 *
 * XChaCha20-Poly1305 AEAD (RFC draft-irtf-cfrg-xchacha)
 *
 * This implementation provides XChaCha20-Poly1305 authenticated encryption
 * by extending mbedTLS's ChaCha20-Poly1305 with the HChaCha20 subkey
 * derivation function for 192-bit (24-byte) nonces.
 *
 * XChaCha20-Poly1305 advantages over ChaCha20-Poly1305:
 *   - 24-byte nonce (vs 12-byte) - safe for random nonces
 *   - No practical nonce collision risk with random generation
 *   - Same performance characteristics
 *
 * Key sizes:
 *   - Key: 32 bytes (256 bits)
 *   - Nonce: 24 bytes (192 bits)
 *   - Tag: 16 bytes (128 bits)
 *
 * Usage:
 *   1. Generate a 32-byte random key (once)
 *   2. Generate a 24-byte random nonce (for each message)
 *   3. Call xchacha20poly1305_encrypt() to encrypt + authenticate
 *   4. Call xchacha20poly1305_decrypt() to authenticate + decrypt
 */

#ifndef XCHACHA20POLY1305_H
#define XCHACHA20POLY1305_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Algorithm constants */
#define XCHACHA20POLY1305_KEY_SIZE   32  /* 256-bit key */
#define XCHACHA20POLY1305_NONCE_SIZE 24  /* 192-bit nonce */
#define XCHACHA20POLY1305_TAG_SIZE   16  /* 128-bit authentication tag */

/* Error codes */
#define XCHACHA20POLY1305_SUCCESS           0
#define XCHACHA20POLY1305_ERROR_INIT       -1
#define XCHACHA20POLY1305_ERROR_ENCRYPT    -2
#define XCHACHA20POLY1305_ERROR_DECRYPT    -3
#define XCHACHA20POLY1305_ERROR_AUTH       -4  /* Authentication failed */
#define XCHACHA20POLY1305_ERROR_PARAMS     -5  /* Invalid parameters */

/**
 * Initialize the XChaCha20-Poly1305 library.
 * Must be called before any other functions.
 *
 * @return XCHACHA20POLY1305_SUCCESS on success, error code otherwise
 */
int xchacha20poly1305_init(void);

/**
 * Encrypt and authenticate a message using XChaCha20-Poly1305.
 *
 * The ciphertext buffer must be at least plaintext_len bytes.
 * The tag buffer must be XCHACHA20POLY1305_TAG_SIZE (16) bytes.
 *
 * @param ciphertext    Output buffer for encrypted data (same size as plaintext)
 * @param tag           Output buffer for authentication tag (16 bytes)
 * @param plaintext     Input plaintext to encrypt
 * @param plaintext_len Length of plaintext in bytes
 * @param aad           Additional authenticated data (can be NULL if aad_len is 0)
 * @param aad_len       Length of AAD in bytes
 * @param nonce         24-byte nonce (must be unique for each encryption with same key)
 * @param key           32-byte encryption key
 *
 * @return XCHACHA20POLY1305_SUCCESS on success, error code otherwise
 */
int xchacha20poly1305_encrypt(
    uint8_t *ciphertext,
    uint8_t tag[XCHACHA20POLY1305_TAG_SIZE],
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t nonce[XCHACHA20POLY1305_NONCE_SIZE],
    const uint8_t key[XCHACHA20POLY1305_KEY_SIZE]);

/**
 * Authenticate and decrypt a message using XChaCha20-Poly1305.
 *
 * The plaintext buffer must be at least ciphertext_len bytes.
 *
 * IMPORTANT: If authentication fails (wrong key, corrupted data, or tampered
 * message), this function returns XCHACHA20POLY1305_ERROR_AUTH and does NOT
 * write any data to the plaintext buffer.
 *
 * @param plaintext      Output buffer for decrypted data (same size as ciphertext)
 * @param ciphertext     Input ciphertext to decrypt
 * @param ciphertext_len Length of ciphertext in bytes
 * @param tag            16-byte authentication tag
 * @param aad            Additional authenticated data (can be NULL if aad_len is 0)
 * @param aad_len        Length of AAD in bytes
 * @param nonce          24-byte nonce (same as used for encryption)
 * @param key            32-byte encryption key
 *
 * @return XCHACHA20POLY1305_SUCCESS on success
 * @return XCHACHA20POLY1305_ERROR_AUTH if authentication fails
 * @return Other error codes for other failures
 */
int xchacha20poly1305_decrypt(
    uint8_t *plaintext,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[XCHACHA20POLY1305_TAG_SIZE],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t nonce[XCHACHA20POLY1305_NONCE_SIZE],
    const uint8_t key[XCHACHA20POLY1305_KEY_SIZE]);

/**
 * Perform HChaCha20 subkey derivation.
 *
 * This is the core function that extends ChaCha20's 12-byte nonce to
 * XChaCha20's 24-byte nonce. It takes the first 16 bytes of the nonce
 * and derives a subkey.
 *
 * Most users should use xchacha20poly1305_encrypt/decrypt instead.
 *
 * @param subkey    Output buffer for derived subkey (32 bytes)
 * @param key       Input key (32 bytes)
 * @param nonce     First 16 bytes of the 24-byte XChaCha20 nonce
 */
void hchacha20(
    uint8_t subkey[XCHACHA20POLY1305_KEY_SIZE],
    const uint8_t key[XCHACHA20POLY1305_KEY_SIZE],
    const uint8_t nonce[16]);

#ifdef __cplusplus
}
#endif

#endif /* XCHACHA20POLY1305_H */
