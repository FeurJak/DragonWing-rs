/*
 * SPDX-License-Identifier: MIT
 *
 * XChaCha20-Poly1305 AEAD Implementation
 *
 * This file implements XChaCha20-Poly1305 by:
 * 1. Using HChaCha20 to derive a subkey from the first 16 bytes of the 24-byte nonce
 * 2. Using mbedTLS ChaCha20-Poly1305 with the derived subkey and remaining nonce bytes
 *
 * References:
 * - RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
 * - draft-irtf-cfrg-xchacha: XChaCha20 and XChaCha20-Poly1305
 */

#include "xchacha20poly1305.h"
#include <string.h>

#include <mbedtls/chachapoly.h>
#include <mbedtls/chacha20.h>

/* ChaCha20 quarter round */
#define QUARTERROUND(a, b, c, d) \
    do { \
        a += b; d ^= a; d = (d << 16) | (d >> 16); \
        c += d; b ^= c; b = (b << 12) | (b >> 20); \
        a += b; d ^= a; d = (d << 8) | (d >> 24); \
        c += d; b ^= c; b = (b << 7) | (b >> 25); \
    } while (0)

/* Load 32-bit little-endian value */
static inline uint32_t load32_le(const uint8_t *src)
{
    return ((uint32_t)src[0]) |
           ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

/* Store 32-bit little-endian value */
static inline void store32_le(uint8_t *dst, uint32_t val)
{
    dst[0] = (uint8_t)(val);
    dst[1] = (uint8_t)(val >> 8);
    dst[2] = (uint8_t)(val >> 16);
    dst[3] = (uint8_t)(val >> 24);
}

/*
 * HChaCha20 - Subkey derivation for XChaCha20
 *
 * HChaCha20 is the ChaCha20 hash function without the final addition.
 * It takes a 256-bit key and 128-bit nonce, and outputs a 256-bit subkey.
 *
 * The state is initialized as:
 *   "expa" "nd 3" "2-by" "te k"   (constant)
 *   key[0..3]                     (first 128 bits of key)
 *   key[4..7]                     (second 128 bits of key)
 *   nonce[0..3]                   (128-bit nonce)
 *
 * After 20 rounds, the output is:
 *   state[0..3] || state[12..15]  (256-bit subkey)
 */
void hchacha20(
    uint8_t subkey[XCHACHA20POLY1305_KEY_SIZE],
    const uint8_t key[XCHACHA20POLY1305_KEY_SIZE],
    const uint8_t nonce[16])
{
    uint32_t state[16];
    
    /* Initialize state with constants */
    state[0] = 0x61707865;  /* "expa" */
    state[1] = 0x3320646e;  /* "nd 3" */
    state[2] = 0x79622d32;  /* "2-by" */
    state[3] = 0x6b206574;  /* "te k" */
    
    /* Load key (256 bits = 8 x 32-bit words) */
    state[4] = load32_le(key + 0);
    state[5] = load32_le(key + 4);
    state[6] = load32_le(key + 8);
    state[7] = load32_le(key + 12);
    state[8] = load32_le(key + 16);
    state[9] = load32_le(key + 20);
    state[10] = load32_le(key + 24);
    state[11] = load32_le(key + 28);
    
    /* Load nonce (128 bits = 4 x 32-bit words) */
    state[12] = load32_le(nonce + 0);
    state[13] = load32_le(nonce + 4);
    state[14] = load32_le(nonce + 8);
    state[15] = load32_le(nonce + 12);
    
    /* 20 rounds (10 double rounds) */
    for (int i = 0; i < 10; i++) {
        /* Column rounds */
        QUARTERROUND(state[0], state[4], state[8], state[12]);
        QUARTERROUND(state[1], state[5], state[9], state[13]);
        QUARTERROUND(state[2], state[6], state[10], state[14]);
        QUARTERROUND(state[3], state[7], state[11], state[15]);
        
        /* Diagonal rounds */
        QUARTERROUND(state[0], state[5], state[10], state[15]);
        QUARTERROUND(state[1], state[6], state[11], state[12]);
        QUARTERROUND(state[2], state[7], state[8], state[13]);
        QUARTERROUND(state[3], state[4], state[9], state[14]);
    }
    
    /* Output: first 4 words and last 4 words (NOT adding initial state) */
    store32_le(subkey + 0, state[0]);
    store32_le(subkey + 4, state[1]);
    store32_le(subkey + 8, state[2]);
    store32_le(subkey + 12, state[3]);
    store32_le(subkey + 16, state[12]);
    store32_le(subkey + 20, state[13]);
    store32_le(subkey + 24, state[14]);
    store32_le(subkey + 28, state[15]);
    
    /* Clear state for security */
    memset(state, 0, sizeof(state));
}

/* Flag to track initialization */
static int initialized = 0;

int xchacha20poly1305_init(void)
{
    /* mbedTLS doesn't require explicit initialization for ChaCha20-Poly1305 */
    initialized = 1;
    return XCHACHA20POLY1305_SUCCESS;
}

int xchacha20poly1305_encrypt(
    uint8_t *ciphertext,
    uint8_t tag[XCHACHA20POLY1305_TAG_SIZE],
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t nonce[XCHACHA20POLY1305_NONCE_SIZE],
    const uint8_t key[XCHACHA20POLY1305_KEY_SIZE])
{
    int ret;
    
    /* Validate parameters */
    if (ciphertext == NULL || tag == NULL || nonce == NULL || key == NULL) {
        return XCHACHA20POLY1305_ERROR_PARAMS;
    }
    if (plaintext_len > 0 && plaintext == NULL) {
        return XCHACHA20POLY1305_ERROR_PARAMS;
    }
    if (aad_len > 0 && aad == NULL) {
        return XCHACHA20POLY1305_ERROR_PARAMS;
    }
    
    /* Step 1: Derive subkey using HChaCha20 with first 16 bytes of nonce */
    uint8_t subkey[32];
    hchacha20(subkey, key, nonce);
    
    /* Step 2: Construct the 12-byte nonce for ChaCha20-Poly1305
     * The nonce is: 4 zero bytes || last 8 bytes of XChaCha20 nonce
     */
    uint8_t chacha_nonce[12];
    memset(chacha_nonce, 0, 4);
    memcpy(chacha_nonce + 4, nonce + 16, 8);
    
    /* Step 3: Use mbedTLS ChaCha20-Poly1305 with derived subkey */
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    
    ret = mbedtls_chachapoly_setkey(&ctx, subkey);
    if (ret != 0) {
        mbedtls_chachapoly_free(&ctx);
        memset(subkey, 0, sizeof(subkey));
        return XCHACHA20POLY1305_ERROR_INIT;
    }
    
    ret = mbedtls_chachapoly_encrypt_and_tag(&ctx,
                                              plaintext_len,
                                              chacha_nonce,
                                              aad,
                                              aad_len,
                                              plaintext,
                                              ciphertext,
                                              tag);
    
    mbedtls_chachapoly_free(&ctx);
    
    /* Clear sensitive data */
    memset(subkey, 0, sizeof(subkey));
    memset(chacha_nonce, 0, sizeof(chacha_nonce));
    
    return (ret == 0) ? XCHACHA20POLY1305_SUCCESS : XCHACHA20POLY1305_ERROR_ENCRYPT;
}

int xchacha20poly1305_decrypt(
    uint8_t *plaintext,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[XCHACHA20POLY1305_TAG_SIZE],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t nonce[XCHACHA20POLY1305_NONCE_SIZE],
    const uint8_t key[XCHACHA20POLY1305_KEY_SIZE])
{
    int ret;
    
    /* Validate parameters */
    if (plaintext == NULL || tag == NULL || nonce == NULL || key == NULL) {
        return XCHACHA20POLY1305_ERROR_PARAMS;
    }
    if (ciphertext_len > 0 && ciphertext == NULL) {
        return XCHACHA20POLY1305_ERROR_PARAMS;
    }
    if (aad_len > 0 && aad == NULL) {
        return XCHACHA20POLY1305_ERROR_PARAMS;
    }
    
    /* Step 1: Derive subkey using HChaCha20 with first 16 bytes of nonce */
    uint8_t subkey[32];
    hchacha20(subkey, key, nonce);
    
    /* Step 2: Construct the 12-byte nonce for ChaCha20-Poly1305
     * The nonce is: 4 zero bytes || last 8 bytes of XChaCha20 nonce
     */
    uint8_t chacha_nonce[12];
    memset(chacha_nonce, 0, 4);
    memcpy(chacha_nonce + 4, nonce + 16, 8);
    
    /* Step 3: Use mbedTLS ChaCha20-Poly1305 with derived subkey */
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    
    ret = mbedtls_chachapoly_setkey(&ctx, subkey);
    if (ret != 0) {
        mbedtls_chachapoly_free(&ctx);
        memset(subkey, 0, sizeof(subkey));
        return XCHACHA20POLY1305_ERROR_INIT;
    }
    
    ret = mbedtls_chachapoly_auth_decrypt(&ctx,
                                           ciphertext_len,
                                           chacha_nonce,
                                           aad,
                                           aad_len,
                                           tag,
                                           ciphertext,
                                           plaintext);
    
    mbedtls_chachapoly_free(&ctx);
    
    /* Clear sensitive data */
    memset(subkey, 0, sizeof(subkey));
    memset(chacha_nonce, 0, sizeof(chacha_nonce));
    
    if (ret == MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED) {
        return XCHACHA20POLY1305_ERROR_AUTH;
    }
    
    return (ret == 0) ? XCHACHA20POLY1305_SUCCESS : XCHACHA20POLY1305_ERROR_DECRYPT;
}
