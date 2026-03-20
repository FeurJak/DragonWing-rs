/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * DragonWing I2C - Zephyr I2C bindings for Rust
 *
 * This header provides C functions that wrap Zephyr's I2C API
 * for use from Rust FFI on the Arduino Uno Q (STM32U585).
 */

#ifndef DRAGONWING_I2C_H
#define DRAGONWING_I2C_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * I2C Bus index (matches Arduino Wire library convention)
 * Wire  = I2C2 (bus 0) - Arduino header pins SDA/SCL
 * Wire1 = I2C4 (bus 1) - Internal/camera connector
 */
#define DW_I2C_BUS_0 0  /* Wire - I2C2 */
#define DW_I2C_BUS_1 1  /* Wire1 - I2C4 */

/*
 * I2C clock frequencies
 */
#define DW_I2C_SPEED_STANDARD  100000   /* 100 kHz */
#define DW_I2C_SPEED_FAST      400000   /* 400 kHz */
#define DW_I2C_SPEED_FAST_PLUS 1000000  /* 1 MHz */

/*
 * Error codes
 */
#define DW_I2C_OK           0
#define DW_I2C_ERR_NACK    -1   /* Device not responding (NACK) */
#define DW_I2C_ERR_BUS     -2   /* Bus error */
#define DW_I2C_ERR_ARB     -3   /* Arbitration lost */
#define DW_I2C_ERR_TIMEOUT -4   /* Operation timeout */
#define DW_I2C_ERR_INVALID -5   /* Invalid parameter */
#define DW_I2C_ERR_BUSY    -6   /* Bus busy */

/**
 * Initialize an I2C bus.
 *
 * @param bus_index  Bus index (0 = Wire/I2C2, 1 = Wire1/I2C4)
 * @return 0 on success, negative error code on failure
 */
int dw_i2c_init(uint8_t bus_index);

/**
 * Deinitialize an I2C bus.
 *
 * @param bus_index  Bus index
 */
void dw_i2c_deinit(uint8_t bus_index);

/**
 * Configure I2C bus clock frequency.
 *
 * @param bus_index  Bus index
 * @param freq_hz    Clock frequency in Hz (100000, 400000, or 1000000)
 * @return 0 on success, negative error code on failure
 */
int dw_i2c_set_clock(uint8_t bus_index, uint32_t freq_hz);

/**
 * Write data to an I2C device.
 *
 * @param bus_index  Bus index
 * @param addr       7-bit device address
 * @param data       Pointer to data buffer
 * @param len        Number of bytes to write
 * @return 0 on success, negative error code on failure
 */
int dw_i2c_write(uint8_t bus_index, uint8_t addr, const uint8_t *data, size_t len);

/**
 * Read data from an I2C device.
 *
 * @param bus_index  Bus index
 * @param addr       7-bit device address
 * @param data       Pointer to receive buffer
 * @param len        Number of bytes to read
 * @return 0 on success, negative error code on failure
 */
int dw_i2c_read(uint8_t bus_index, uint8_t addr, uint8_t *data, size_t len);

/**
 * Write then read (combined transaction) to an I2C device.
 * This is commonly used for register reads.
 *
 * @param bus_index  Bus index
 * @param addr       7-bit device address
 * @param wr_data    Pointer to write data (e.g., register address)
 * @param wr_len     Number of bytes to write
 * @param rd_data    Pointer to receive buffer
 * @param rd_len     Number of bytes to read
 * @return 0 on success, negative error code on failure
 */
int dw_i2c_write_read(uint8_t bus_index, uint8_t addr,
                      const uint8_t *wr_data, size_t wr_len,
                      uint8_t *rd_data, size_t rd_len);

/**
 * Check if a device is present on the bus (probe).
 *
 * @param bus_index  Bus index
 * @param addr       7-bit device address to probe
 * @return true if device responds, false otherwise
 */
bool dw_i2c_probe(uint8_t bus_index, uint8_t addr);

/**
 * Scan the I2C bus for devices.
 * Probes addresses from start_addr to end_addr.
 *
 * @param bus_index   Bus index
 * @param start_addr  Start address (typically 0x08)
 * @param end_addr    End address (typically 0x77)
 * @param found       Array to store found addresses
 * @param max_found   Maximum number of addresses to store
 * @return Number of devices found
 */
int dw_i2c_scan(uint8_t bus_index, uint8_t start_addr, uint8_t end_addr,
                uint8_t *found, size_t max_found);

#ifdef __cplusplus
}
#endif

#endif /* DRAGONWING_I2C_H */
