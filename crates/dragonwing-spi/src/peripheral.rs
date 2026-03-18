//! MCU SPI Peripheral (Slave) Implementation
//!
//! This module provides the SPI peripheral driver for the STM32U585 MCU,
//! acting as a slave device that responds to the Linux MPU controller.
//!
//! # Setup Requirements
//!
//! The MCU acts as SPI peripheral with the following configuration:
//! - SPI3 configured as slave
//! - 512-byte transfer buffers
//! - Framed protocol with magic header
//!
//! # Device Tree Configuration
//!
//! ```dts
//! &spi3 {
//!     status = "okay";
//!     cs-gpios = <&gpioa 15 GPIO_ACTIVE_LOW>;
//!     
//!     zephyr_spi_slave: spi-dev@0 {
//!         compatible = "zephyr,spi-slave";
//!         reg = <0>;
//!         spi-max-frequency = <1000000>;
//!     };
//! };
//! ```

use super::{FrameHeader, FRAME_HEADER_SIZE, MAX_PAYLOAD_SIZE, SPI_BUFFER_SIZE};

// FFI declarations for C driver
extern "C" {
    fn spi_peripheral_init() -> i32;
    fn spi_peripheral_populate(data: *const u8, len: usize) -> usize;
    fn spi_peripheral_transceive() -> i32;
    fn spi_peripheral_get_rx_payload(len: *mut usize) -> *const u8;
    fn spi_peripheral_buffer_size() -> usize;
    fn spi_peripheral_max_payload() -> usize;
}

/// SPI Transport for MCU peripheral mode
pub struct SpiTransport {
    initialized: bool,
    rx_offset: usize,
    rx_len: usize,
}

impl SpiTransport {
    /// Create a new SPI transport (uninitialized)
    pub const fn new() -> Self {
        Self {
            initialized: false,
            rx_offset: 0,
            rx_len: 0,
        }
    }

    /// Initialize the SPI peripheral
    ///
    /// Returns true on success, false on failure.
    pub fn init(&mut self) -> bool {
        if self.initialized {
            return true;
        }

        let ret = unsafe { spi_peripheral_init() };
        if ret == 0 {
            self.initialized = true;
            true
        } else {
            false
        }
    }

    /// Check if transport is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Prepare data for transmission
    ///
    /// Copies the data into the TX buffer with frame header.
    /// Returns the number of bytes that will be transmitted.
    pub fn prepare_tx(&mut self, data: &[u8]) -> usize {
        if !self.initialized {
            return 0;
        }

        let len = if data.len() > MAX_PAYLOAD_SIZE {
            MAX_PAYLOAD_SIZE
        } else {
            data.len()
        };

        unsafe { spi_peripheral_populate(data.as_ptr(), len) }
    }

    /// Perform a bidirectional SPI transfer
    ///
    /// This blocks until the Linux controller initiates a transfer.
    /// After this returns, use `read()` to get received data.
    ///
    /// Returns the number of bytes received, or 0 on error.
    pub fn transceive(&mut self) -> usize {
        if !self.initialized {
            return 0;
        }

        let ret = unsafe { spi_peripheral_transceive() };
        if ret < 0 {
            self.rx_len = 0;
            self.rx_offset = 0;
            return 0;
        }

        // Get received payload
        let mut len: usize = 0;
        let payload_ptr = unsafe { spi_peripheral_get_rx_payload(&mut len) };

        if payload_ptr.is_null() {
            self.rx_len = 0;
            self.rx_offset = 0;
            return 0;
        }

        self.rx_len = len;
        self.rx_offset = 0;
        len
    }

    /// Read received data from the buffer
    ///
    /// Copies up to `buf.len()` bytes from the receive buffer.
    /// Returns the number of bytes copied.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        if !self.initialized || self.rx_len == 0 {
            return 0;
        }

        let mut len: usize = 0;
        let payload_ptr = unsafe { spi_peripheral_get_rx_payload(&mut len) };

        if payload_ptr.is_null() || len == 0 {
            return 0;
        }

        // Calculate how much to read
        let available = if self.rx_offset >= len {
            0
        } else {
            len - self.rx_offset
        };

        let to_copy = if buf.len() < available {
            buf.len()
        } else {
            available
        };

        if to_copy > 0 {
            unsafe {
                let src = payload_ptr.add(self.rx_offset);
                core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), to_copy);
            }
            self.rx_offset += to_copy;
        }

        to_copy
    }

    /// Get the maximum buffer size
    pub fn buffer_size(&self) -> usize {
        unsafe { spi_peripheral_buffer_size() }
    }

    /// Get the maximum payload size
    pub fn max_payload(&self) -> usize {
        unsafe { spi_peripheral_max_payload() }
    }
}

impl Default for SpiTransport {
    fn default() -> Self {
        Self::new()
    }
}
