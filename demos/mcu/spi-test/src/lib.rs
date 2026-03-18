// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// SPI Peripheral Test for Arduino Uno Q
//
// This example tests SPI communication between the MCU (peripheral/slave)
// and the Linux MPU (controller/master).
//
// The MCU prepares data in its TX buffer, then waits for the Linux side
// to initiate a transfer. During the transfer, data is exchanged bidirectionally.

#![no_std]
#![allow(unexpected_cfgs)]

use log::warn;
use zephyr::time::{sleep, Duration};

// FFI bindings to C SPI driver
extern "C" {
    fn spi_peripheral_init() -> i32;
    fn spi_peripheral_populate(data: *const u8, len: usize) -> usize;
    fn spi_peripheral_transceive() -> i32;
    fn spi_peripheral_get_rx_payload(len: *mut usize) -> *const u8;
    fn spi_peripheral_max_payload() -> usize;
}

// Simple frame header for our protocol
const FRAME_MAGIC: u16 = 0xAA55;

/// Main entry point
#[no_mangle]
extern "C" fn rust_main() {
    unsafe {
        zephyr::set_logger().unwrap();
    }

    warn!("===========================================");
    warn!("  SPI Peripheral Test - Arduino Uno Q");
    warn!("===========================================");

    // Initialize SPI peripheral
    warn!("Initializing SPI peripheral...");
    let result = unsafe { spi_peripheral_init() };
    if result != 0 {
        warn!("Failed to initialize SPI: {}", result);
        loop {
            sleep(Duration::millis_at_least(1000));
        }
    }
    warn!("SPI initialized!");

    let max_payload = unsafe { spi_peripheral_max_payload() };
    warn!("Max payload size: {} bytes", max_payload);

    let mut counter: u32 = 0;

    // Main loop: prepare data and wait for transfers
    loop {
        counter = counter.wrapping_add(1);

        // Prepare test data: [counter (4 bytes), "Hello from MCU!"]
        let mut tx_data = [0u8; 64];
        tx_data[0] = (counter >> 24) as u8;
        tx_data[1] = (counter >> 16) as u8;
        tx_data[2] = (counter >> 8) as u8;
        tx_data[3] = counter as u8;

        let msg = b"Hello from MCU!";
        tx_data[4..4 + msg.len()].copy_from_slice(msg);
        let total_len = 4 + msg.len();

        // Populate TX buffer
        let populated = unsafe { spi_peripheral_populate(tx_data.as_ptr(), total_len) };
        warn!(
            "[{}] TX buffer ready ({} bytes), waiting for transfer...",
            counter, populated
        );

        // Wait for controller to initiate transfer (blocking)
        let ret = unsafe { spi_peripheral_transceive() };
        if ret < 0 {
            warn!("Transceive error: {}", ret);
            sleep(Duration::millis_at_least(100));
            continue;
        }

        // Check received data
        let mut rx_len: usize = 0;
        let rx_ptr = unsafe { spi_peripheral_get_rx_payload(&mut rx_len as *mut usize) };

        if !rx_ptr.is_null() && rx_len > 0 {
            let rx_data = unsafe { core::slice::from_raw_parts(rx_ptr, rx_len.min(64)) };
            // Try to display as string if it's printable ASCII
            if rx_data
                .iter()
                .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace() || b == 0)
            {
                let end = rx_data
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(rx_data.len());
                if let Ok(s) = core::str::from_utf8(&rx_data[..end]) {
                    warn!("RX ({} bytes): \"{}\"", rx_len, s);
                } else {
                    warn!("RX ({} bytes): {:02x?}", rx_len, &rx_data[..rx_len.min(32)]);
                }
            } else {
                warn!("RX ({} bytes): {:02x?}", rx_len, &rx_data[..rx_len.min(32)]);
            }
        } else {
            // Empty frame from controller (polling)
        }
    }
}
