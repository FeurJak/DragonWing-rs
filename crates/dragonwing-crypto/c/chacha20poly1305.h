/*
 * SPDX-License-Identifier: MIT
 *
 * ChaCha20-Poly1305 AEAD (RFC 8439)
 *
 * This implementation provides standard ChaCha20-Poly1305 authenticated
 * encryption using mbedTLS. Unlike XChaCha20-Poly1305, this uses a 96-bit
 * (12-byte) nonce as specified in RFC 8439.
 *
 * This is the cipher used by:
 *   - TLS 1.3
 *   - QUIC
 *   - WireGuard
 *   - BPP (Binary Packet Protocol)
 *
 * Key sizes:
 *   - Key: 32 bytes (256 bits)
 *   - Nonce: 12 bytes (96 bits)
 *   - Tag: 16 bytes (128 bits)
 *
 * IMPORTANT: Unlike XChaCha20-Poly1305, the 12-byte nonce is NOT safe for
 * random generation. Use a counter or hybrid scheme (timestamp + counter).
 */

#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Algorithm constants */
#define CHACHA20POLY1305_KEY_SIZE   32  /* 256-bit key */
#define CHACHA20POLY1305_NONCE_SIZE 12  /* 96-bit nonce */
#define CHACHA20POLY1305_TAG_SIZE   16  /* 128-bit authentication tag */

/* Error codes */
#define CHACHA20POLY1305_SUCCESS           0
#define CHACHA20POLY1305_ERROR_INIT       -1
#define CHACHA20POLY1305_ERROR_ENCRYPT    -2
#define CHACHA20POLY1305_ERROR_DECRYPT    -3
#define CHACHA20POLY1305_ERROR_AUTH       -4  /* Authentication failed */
#define CHACHA20POLY1305_ERROR_PARAMS     -5  /* Invalid parameters */

/**
 * Initialize the ChaCha20-Poly1305 library.
 * Must be called before any other functions.
 *
 * @return CHACHA20POLY1305_SUCCESS on success, error code otherwise
 */
int chacha20poly1305_init(void);

/**
 * Encrypt and authenticate a message using ChaCha20-Poly1305.
 *
 * The ciphertext buffer must be at least plaintext_len bytes.
 * The tag buffer must be CHACHA20POLY1305_TAG_SIZE (16) bytes.
 *
 * @param ciphertext    Output buffer for encrypted data (same size as plaintext)
 * @param tag           Output buffer for authentication tag (16 bytes)
 * @param plaintext     Input plaintext to encrypt
 * @param plaintext_len Length of plaintext in bytes
 * @param aad           Additional authenticated data (can be NULL if aad_len is 0)
 * @param aad_len       Length of AAD in bytes
 * @param nonce         12-byte nonce (must be unique for each encryption with same key)
 * @param key           32-byte encryption key
 *
 * @return CHACHA20POLY1305_SUCCESS on success, error code otherwise
 */
int chacha20poly1305_encrypt(
    uint8_t *ciphertext,
    uint8_t tag[CHACHA20POLY1305_TAG_SIZE],
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t nonce[CHACHA20POLY1305_NONCE_SIZE],
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE]);

/**
 * Authenticate and decrypt a message using ChaCha20-Poly1305.
 *
 * The plaintext buffer must be at least ciphertext_len bytes.
 *
 * IMPORTANT: If authentication fails (wrong key, corrupted data, or tampered
 * message), this function returns CHACHA20POLY1305_ERROR_AUTH and does NOT
 * write any data to the plaintext buffer.
 *
 * @param plaintext      Output buffer for decrypted data (same size as ciphertext)
 * @param ciphertext     Input ciphertext to decrypt
 * @param ciphertext_len Length of ciphertext in bytes
 * @param tag            16-byte authentication tag
 * @param aad            Additional authenticated data (can be NULL if aad_len is 0)
 * @param aad_len        Length of AAD in bytes
 * @param nonce          12-byte nonce (same as used for encryption)
 * @param key            32-byte encryption key
 *
 * @return CHACHA20POLY1305_SUCCESS on success
 * @return CHACHA20POLY1305_ERROR_AUTH if authentication fails
 * @return Other error codes for other failures
 */
int chacha20poly1305_decrypt(
    uint8_t *plaintext,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[CHACHA20POLY1305_TAG_SIZE],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t nonce[CHACHA20POLY1305_NONCE_SIZE],
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* CHACHA20POLY1305_H */
