// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// FFI bindings to the Zephyr I2C C functions.
//
// These functions are implemented in c/i2c.c and provide
// low-level access to the I2C hardware on Arduino Uno Q.

use core::ffi::c_int;

/// I2C Bus indices (matches Arduino Wire library)
pub const DW_I2C_BUS_0: u8 = 0; // Wire - I2C2
pub const DW_I2C_BUS_1: u8 = 1; // Wire1 - I2C4

/// I2C clock frequencies
pub const DW_I2C_SPEED_STANDARD: u32 = 100_000;
pub const DW_I2C_SPEED_FAST: u32 = 400_000;
pub const DW_I2C_SPEED_FAST_PLUS: u32 = 1_000_000;

/// Error codes
pub const DW_I2C_OK: c_int = 0;
pub const DW_I2C_ERR_NACK: c_int = -1;
pub const DW_I2C_ERR_BUS: c_int = -2;
pub const DW_I2C_ERR_ARB: c_int = -3;
pub const DW_I2C_ERR_TIMEOUT: c_int = -4;
pub const DW_I2C_ERR_INVALID: c_int = -5;
pub const DW_I2C_ERR_BUSY: c_int = -6;

extern "C" {
    /// Initialize an I2C bus.
    pub fn dw_i2c_init(bus_index: u8) -> c_int;

    /// Deinitialize an I2C bus.
    pub fn dw_i2c_deinit(bus_index: u8);

    /// Configure I2C bus clock frequency.
    pub fn dw_i2c_set_clock(bus_index: u8, freq_hz: u32) -> c_int;

    /// Write data to an I2C device.
    pub fn dw_i2c_write(bus_index: u8, addr: u8, data: *const u8, len: usize) -> c_int;

    /// Read data from an I2C device.
    pub fn dw_i2c_read(bus_index: u8, addr: u8, data: *mut u8, len: usize) -> c_int;

    /// Write then read (combined transaction) to an I2C device.
    pub fn dw_i2c_write_read(
        bus_index: u8,
        addr: u8,
        wr_data: *const u8,
        wr_len: usize,
        rd_data: *mut u8,
        rd_len: usize,
    ) -> c_int;

    /// Check if a device is present on the bus.
    pub fn dw_i2c_probe(bus_index: u8, addr: u8) -> bool;

    /// Scan the I2C bus for devices.
    pub fn dw_i2c_scan(
        bus_index: u8,
        start_addr: u8,
        end_addr: u8,
        found: *mut u8,
        max_found: usize,
    ) -> c_int;
}
