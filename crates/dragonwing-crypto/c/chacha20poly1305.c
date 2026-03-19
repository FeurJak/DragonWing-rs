/*
 * SPDX-License-Identifier: MIT
 *
 * ChaCha20-Poly1305 AEAD Implementation (RFC 8439)
 *
 * This file implements standard ChaCha20-Poly1305 using mbedTLS.
 * It provides a simple wrapper around mbedTLS's chachapoly functions
 * with a clean C interface for Rust FFI.
 *
 * References:
 * - RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
 */

#include "chacha20poly1305.h"
#include <string.h>

#include <mbedtls/chachapoly.h>

/* Flag to track initialization */
static int initialized = 0;

int chacha20poly1305_init(void)
{
    /* mbedTLS doesn't require explicit initialization for ChaCha20-Poly1305 */
    initialized = 1;
    return CHACHA20POLY1305_SUCCESS;
}

int chacha20poly1305_encrypt(
    uint8_t *ciphertext,
    uint8_t tag[CHACHA20POLY1305_TAG_SIZE],
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t nonce[CHACHA20POLY1305_NONCE_SIZE],
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE])
{
    int ret;
    
    /* Validate parameters */
    if (ciphertext == NULL || tag == NULL || nonce == NULL || key == NULL) {
        return CHACHA20POLY1305_ERROR_PARAMS;
    }
    if (plaintext_len > 0 && plaintext == NULL) {
        return CHACHA20POLY1305_ERROR_PARAMS;
    }
    if (aad_len > 0 && aad == NULL) {
        return CHACHA20POLY1305_ERROR_PARAMS;
    }
    
    /* Initialize mbedTLS context */
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    
    ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret != 0) {
        mbedtls_chachapoly_free(&ctx);
        return CHACHA20POLY1305_ERROR_INIT;
    }
    
    /* Encrypt and compute authentication tag */
    ret = mbedtls_chachapoly_encrypt_and_tag(&ctx,
                                              plaintext_len,
                                              nonce,
                                              aad,
                                              aad_len,
                                              plaintext,
                                              ciphertext,
                                              tag);
    
    mbedtls_chachapoly_free(&ctx);
    
    return (ret == 0) ? CHACHA20POLY1305_SUCCESS : CHACHA20POLY1305_ERROR_ENCRYPT;
}

int chacha20poly1305_decrypt(
    uint8_t *plaintext,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[CHACHA20POLY1305_TAG_SIZE],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t nonce[CHACHA20POLY1305_NONCE_SIZE],
    const uint8_t key[CHACHA20POLY1305_KEY_SIZE])
{
    int ret;
    
    /* Validate parameters */
    if (plaintext == NULL || tag == NULL || nonce == NULL || key == NULL) {
        return CHACHA20POLY1305_ERROR_PARAMS;
    }
    if (ciphertext_len > 0 && ciphertext == NULL) {
        return CHACHA20POLY1305_ERROR_PARAMS;
    }
    if (aad_len > 0 && aad == NULL) {
        return CHACHA20POLY1305_ERROR_PARAMS;
    }
    
    /* Initialize mbedTLS context */
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    
    ret = mbedtls_chachapoly_setkey(&ctx, key);
    if (ret != 0) {
        mbedtls_chachapoly_free(&ctx);
        return CHACHA20POLY1305_ERROR_INIT;
    }
    
    /* Authenticate and decrypt */
    ret = mbedtls_chachapoly_auth_decrypt(&ctx,
                                           ciphertext_len,
                                           nonce,
                                           aad,
                                           aad_len,
                                           tag,
                                           ciphertext,
                                           plaintext);
    
    mbedtls_chachapoly_free(&ctx);
    
    if (ret == MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED) {
        return CHACHA20POLY1305_ERROR_AUTH;
    }
    
    return (ret == 0) ? CHACHA20POLY1305_SUCCESS : CHACHA20POLY1305_ERROR_DECRYPT;
}
