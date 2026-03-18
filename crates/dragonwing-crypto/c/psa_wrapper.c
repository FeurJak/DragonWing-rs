/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * PSA Secure Storage and Crypto wrapper for Zephyr
 *
 * This file provides C wrappers around Zephyr's PSA ITS (Internal Trusted
 * Storage) and PSA Crypto APIs that can be called from Rust via FFI.
 *
 * The wrapper handles the translation between Rust and C types, managing
 * PSA key attributes structures, and providing a stable ABI for FFI.
 *
 * Usage:
 *   1. Copy this file to your Zephyr application's C source directory
 *   2. Add to CMakeLists.txt: target_sources(app PRIVATE src/c/psa_wrapper.c)
 *   3. Enable in prj.conf (see psa/mod.rs for full config)
 *
 * Features:
 *   - PSA ITS: Store/retrieve encrypted data (set, get, get_info, remove)
 *   - PSA Crypto: Key management (init, generate, import, export, destroy)
 */

#include <zephyr/kernel.h>
#include <string.h>

/* PSA ITS API - Zephyr Secure Storage */
#include <psa/internal_trusted_storage.h>

/* PSA Crypto API - mbedTLS */
#include <psa/crypto.h>

/* ============================================================================
 * PSA ITS (Internal Trusted Storage) Wrappers
 * ============================================================================ */

/**
 * Store data in ITS.
 *
 * @param uid           Unique identifier for the entry
 * @param data_length   Size of data to store
 * @param p_data        Pointer to data to store
 * @param create_flags  Storage flags (write-once, etc.)
 * @return PSA status code (0 = success)
 */
int psa_its_set_wrapper(uint32_t uid, size_t data_length, const uint8_t *p_data,
                        uint32_t create_flags)
{
    psa_storage_uid_t psa_uid = (psa_storage_uid_t)uid;
    psa_storage_create_flags_t flags = (psa_storage_create_flags_t)create_flags;

    return (int)psa_its_set(psa_uid, data_length, p_data, flags);
}

/**
 * Retrieve data from ITS.
 *
 * @param uid            Unique identifier for the entry
 * @param data_offset    Byte offset to start reading from
 * @param data_size      Maximum bytes to read (buffer size)
 * @param p_data         Buffer to receive the data
 * @param p_data_length  Output: actual bytes read
 * @return PSA status code (0 = success)
 */
int psa_its_get_wrapper(uint32_t uid, size_t data_offset, size_t data_size,
                        uint8_t *p_data, size_t *p_data_length)
{
    psa_storage_uid_t psa_uid = (psa_storage_uid_t)uid;

    return (int)psa_its_get(psa_uid, data_offset, data_size, p_data, p_data_length);
}

/**
 * Storage info structure for FFI.
 */
struct psa_storage_info_ffi {
    size_t capacity;
    size_t size;
    uint32_t flags;
};

/**
 * Get metadata about an ITS entry.
 *
 * @param uid     Unique identifier for the entry
 * @param p_info  Output: entry metadata
 * @return PSA status code (0 = success)
 */
int psa_its_get_info_wrapper(uint32_t uid, struct psa_storage_info_ffi *p_info)
{
    psa_storage_uid_t psa_uid = (psa_storage_uid_t)uid;
    struct psa_storage_info_t info;

    psa_status_t status = psa_its_get_info(psa_uid, &info);

    if (status == PSA_SUCCESS) {
        p_info->capacity = info.capacity;
        p_info->size = info.size;
        p_info->flags = (uint32_t)info.flags;
    }

    return (int)status;
}

/**
 * Remove an entry from ITS.
 *
 * @param uid  Unique identifier for the entry to remove
 * @return PSA status code (0 = success)
 */
int psa_its_remove_wrapper(uint32_t uid)
{
    psa_storage_uid_t psa_uid = (psa_storage_uid_t)uid;

    return (int)psa_its_remove(psa_uid);
}

/* ============================================================================
 * PSA Crypto Key Management Wrappers
 * ============================================================================ */

/**
 * Initialize PSA Crypto subsystem.
 *
 * Must be called before any other PSA Crypto functions.
 * Safe to call multiple times.
 *
 * @return PSA status code (0 = success)
 */
int psa_crypto_init_wrapper(void)
{
    return (int)psa_crypto_init();
}

/**
 * Generate a random key.
 *
 * @param key_type    PSA key type (e.g., PSA_KEY_TYPE_AES)
 * @param bits        Key size in bits
 * @param algorithm   Permitted algorithm
 * @param usage       Usage flags (encrypt, decrypt, etc.)
 * @param lifetime    Volatile (0) or Persistent (1)
 * @param key_id      Requested key ID (for persistent keys)
 * @param out_key_id  Output: assigned key ID
 * @return PSA status code (0 = success)
 */
int psa_generate_key_wrapper(uint32_t key_type, size_t bits, uint32_t algorithm,
                             uint32_t usage, uint32_t lifetime, uint32_t key_id,
                             uint32_t *out_key_id)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(&attributes, (psa_key_type_t)key_type);
    psa_set_key_bits(&attributes, bits);
    psa_set_key_algorithm(&attributes, (psa_algorithm_t)algorithm);
    psa_set_key_usage_flags(&attributes, (psa_key_usage_t)usage);

    if (lifetime != 0) {
        /* Persistent key */
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_id(&attributes, (psa_key_id_t)key_id);
    } else {
        /* Volatile key */
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
    }

    psa_key_id_t generated_id;
    psa_status_t status = psa_generate_key(&attributes, &generated_id);

    if (status == PSA_SUCCESS) {
        *out_key_id = (uint32_t)generated_id;
    }

    psa_reset_key_attributes(&attributes);
    return (int)status;
}

/**
 * Import key material.
 *
 * @param key_type    PSA key type
 * @param bits        Key size in bits (0 to auto-detect)
 * @param algorithm   Permitted algorithm
 * @param usage       Usage flags
 * @param lifetime    Volatile (0) or Persistent (1)
 * @param key_id      Requested key ID (for persistent keys)
 * @param data        Key material to import
 * @param data_length Size of key material
 * @param out_key_id  Output: assigned key ID
 * @return PSA status code (0 = success)
 */
int psa_import_key_wrapper(uint32_t key_type, size_t bits, uint32_t algorithm,
                           uint32_t usage, uint32_t lifetime, uint32_t key_id,
                           const uint8_t *data, size_t data_length,
                           uint32_t *out_key_id)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(&attributes, (psa_key_type_t)key_type);
    if (bits > 0) {
        psa_set_key_bits(&attributes, bits);
    }
    psa_set_key_algorithm(&attributes, (psa_algorithm_t)algorithm);
    psa_set_key_usage_flags(&attributes, (psa_key_usage_t)usage);

    if (lifetime != 0) {
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_id(&attributes, (psa_key_id_t)key_id);
    } else {
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
    }

    psa_key_id_t imported_id;
    psa_status_t status = psa_import_key(&attributes, data, data_length, &imported_id);

    if (status == PSA_SUCCESS) {
        *out_key_id = (uint32_t)imported_id;
    }

    psa_reset_key_attributes(&attributes);
    return (int)status;
}

/**
 * Export a key's material.
 *
 * @param key_id       Key to export
 * @param data         Buffer to receive key material
 * @param data_size    Buffer size
 * @param data_length  Output: actual bytes written
 * @return PSA status code (0 = success)
 */
int psa_export_key_wrapper(uint32_t key_id, uint8_t *data, size_t data_size,
                           size_t *data_length)
{
    return (int)psa_export_key((psa_key_id_t)key_id, data, data_size, data_length);
}

/**
 * Export public key from a key pair.
 *
 * @param key_id       Key pair to export from
 * @param data         Buffer to receive public key
 * @param data_size    Buffer size
 * @param data_length  Output: actual bytes written
 * @return PSA status code (0 = success)
 */
int psa_export_public_key_wrapper(uint32_t key_id, uint8_t *data, size_t data_size,
                                  size_t *data_length)
{
    return (int)psa_export_public_key((psa_key_id_t)key_id, data, data_size, data_length);
}

/**
 * Destroy a key.
 *
 * @param key_id  Key to destroy
 * @return PSA status code (0 = success)
 */
int psa_destroy_key_wrapper(uint32_t key_id)
{
    return (int)psa_destroy_key((psa_key_id_t)key_id);
}

/**
 * Purge a key from volatile memory.
 *
 * For persistent keys, removes from RAM but keeps in storage.
 * For volatile keys, equivalent to destroy.
 *
 * @param key_id  Key to purge
 * @return PSA status code (0 = success)
 */
int psa_purge_key_wrapper(uint32_t key_id)
{
    return (int)psa_purge_key((psa_key_id_t)key_id);
}

/**
 * Get key attributes.
 *
 * @param key_id        Key to query
 * @param out_type      Output: key type
 * @param out_bits      Output: key size in bits
 * @param out_algorithm Output: permitted algorithm
 * @param out_usage     Output: usage flags
 * @param out_lifetime  Output: lifetime (0=volatile, 1=persistent)
 * @return PSA status code (0 = success)
 */
int psa_get_key_attributes_wrapper(uint32_t key_id, uint32_t *out_type,
                                   size_t *out_bits, uint32_t *out_algorithm,
                                   uint32_t *out_usage, uint32_t *out_lifetime)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_status_t status = psa_get_key_attributes((psa_key_id_t)key_id, &attributes);

    if (status == PSA_SUCCESS) {
        *out_type = (uint32_t)psa_get_key_type(&attributes);
        *out_bits = psa_get_key_bits(&attributes);
        *out_algorithm = (uint32_t)psa_get_key_algorithm(&attributes);
        *out_usage = (uint32_t)psa_get_key_usage_flags(&attributes);

        psa_key_lifetime_t lt = psa_get_key_lifetime(&attributes);
        *out_lifetime = (lt == PSA_KEY_LIFETIME_VOLATILE) ? 0 : 1;
    }

    psa_reset_key_attributes(&attributes);
    return (int)status;
}
