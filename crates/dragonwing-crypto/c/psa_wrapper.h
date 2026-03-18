/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * PSA Secure Storage and Crypto wrapper - Header
 *
 * FFI-safe declarations for PSA ITS and PSA Crypto wrappers.
 */

#ifndef PSA_WRAPPER_H
#define PSA_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * PSA ITS (Internal Trusted Storage) Wrappers
 * ============================================================================ */

/**
 * Storage info structure for FFI.
 */
struct psa_storage_info_ffi {
    size_t capacity;
    size_t size;
    uint32_t flags;
};

/**
 * Store data in ITS.
 */
int psa_its_set_wrapper(uint32_t uid, size_t data_length, const uint8_t *p_data,
                        uint32_t create_flags);

/**
 * Retrieve data from ITS.
 */
int psa_its_get_wrapper(uint32_t uid, size_t data_offset, size_t data_size,
                        uint8_t *p_data, size_t *p_data_length);

/**
 * Get metadata about an ITS entry.
 */
int psa_its_get_info_wrapper(uint32_t uid, struct psa_storage_info_ffi *p_info);

/**
 * Remove an entry from ITS.
 */
int psa_its_remove_wrapper(uint32_t uid);

/* ============================================================================
 * PSA Crypto Key Management Wrappers
 * ============================================================================ */

/**
 * Initialize PSA Crypto subsystem.
 */
int psa_crypto_init_wrapper(void);

/**
 * Generate a random key.
 */
int psa_generate_key_wrapper(uint32_t key_type, size_t bits, uint32_t algorithm,
                             uint32_t usage, uint32_t lifetime, uint32_t key_id,
                             uint32_t *out_key_id);

/**
 * Import key material.
 */
int psa_import_key_wrapper(uint32_t key_type, size_t bits, uint32_t algorithm,
                           uint32_t usage, uint32_t lifetime, uint32_t key_id,
                           const uint8_t *data, size_t data_length,
                           uint32_t *out_key_id);

/**
 * Export a key's material.
 */
int psa_export_key_wrapper(uint32_t key_id, uint8_t *data, size_t data_size,
                           size_t *data_length);

/**
 * Export public key from a key pair.
 */
int psa_export_public_key_wrapper(uint32_t key_id, uint8_t *data, size_t data_size,
                                  size_t *data_length);

/**
 * Destroy a key.
 */
int psa_destroy_key_wrapper(uint32_t key_id);

/**
 * Purge a key from volatile memory.
 */
int psa_purge_key_wrapper(uint32_t key_id);

/**
 * Get key attributes.
 */
int psa_get_key_attributes_wrapper(uint32_t key_id, uint32_t *out_type,
                                   size_t *out_bits, uint32_t *out_algorithm,
                                   uint32_t *out_usage, uint32_t *out_lifetime);

#ifdef __cplusplus
}
#endif

#endif /* PSA_WRAPPER_H */
