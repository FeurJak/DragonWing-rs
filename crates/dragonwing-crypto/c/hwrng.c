/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Hardware RNG wrapper for Zephyr
 *
 * This file provides a C wrapper around Zephyr's sys_rand_get() function
 * that can be called from Rust via FFI. It is part of the arduino-cryptography
 * library and should be included in Zephyr applications that use HwRng.
 *
 * On STM32U585, this uses the True Random Number Generator (TRNG) peripheral
 * which provides cryptographically secure randomness from physical entropy
 * sources (thermal noise).
 *
 * Usage:
 *   1. Copy this file to your Zephyr application's C source directory
 *   2. Add to CMakeLists.txt: target_sources(app PRIVATE src/c/hwrng.c)
 *   3. Enable in prj.conf:
 *        CONFIG_ENTROPY_GENERATOR=y
 *        CONFIG_ENTROPY_DEVICE_RANDOM_GENERATOR=y
 *   4. (Optional) Enable RNG in device tree overlay:
 *        &rng { status = "okay"; };
 */

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>

/**
 * Fill a buffer with random bytes from the hardware RNG.
 *
 * This wraps Zephyr's sys_rand_get() which uses the entropy driver
 * configured in Kconfig. On STM32 devices with TRNG (like STM32U585),
 * this provides cryptographically secure randomness.
 *
 * @param dst Pointer to buffer to fill with random data
 * @param len Number of random bytes to generate
 */
void hwrng_fill_bytes(uint8_t *dst, size_t len)
{
    sys_rand_get(dst, len);
}
