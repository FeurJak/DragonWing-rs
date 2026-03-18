// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// RPC Server Example for Arduino Uno Q
//
// This example implements an RPC server on the MCU that:
// - Receives RPC requests from Linux via SPI
// - Handles LED matrix control methods
// - Responds with results back to Linux
//
// Supported RPC methods:
// - ping() -> "pong"
// - version() -> firmware version string
// - led_matrix.clear() -> clear all LEDs
// - led_matrix.fill() -> turn on all LEDs
// - led_matrix.set_pixel(row, col, on) -> set single pixel
// - led_matrix.set_row(row, bitmap) -> set entire row
// - led_matrix.set_frame(d0, d1, d2, d3) -> set full 104-bit frame
// - led_matrix.set_brightness(row, col, level) -> set pixel brightness

#![no_std]
#![allow(unexpected_cfgs)]

use log::warn;

use dragonwing_led_matrix::{Frame, GrayscaleFrame, LedMatrix};
use dragonwing_rpc::{RpcResult, RpcServer, SpiTransport, Transport, PARAMS};
use zephyr::time::{sleep, Duration};

// Global state for RPC handlers (static mutable since we're single-threaded on MCU)
static mut MATRIX: Option<LedMatrix> = None;
static mut BITMAP: [[u8; 13]; 8] = [[0u8; 13]; 8];
static mut GRAYSCALE: [u8; 104] = [0u8; 104];

/// Get mutable reference to the global matrix
///
/// # Safety
/// Only safe to call from single-threaded context (MCU main loop)
unsafe fn matrix() -> &'static mut LedMatrix {
    MATRIX.as_mut().expect("Matrix not initialized")
}

// === RPC Handlers ===
// All handlers read parameters from the global PARAMS buffer

/// Handle ping request - returns "pong"
fn handle_ping(_count: usize) -> RpcResult {
    RpcResult::Str("pong")
}

/// Handle version request - returns firmware version
fn handle_version(_count: usize) -> RpcResult {
    RpcResult::Str("rpc-server 0.1.0")
}

/// Handle led_matrix.clear - turn off all LEDs
fn handle_matrix_clear(_count: usize) -> RpcResult {
    unsafe {
        // Clear the bitmap
        for row in BITMAP.iter_mut() {
            for col in row.iter_mut() {
                *col = 0;
            }
        }
        matrix().clear();
    }
    RpcResult::Bool(true)
}

/// Handle led_matrix.fill - turn on all LEDs
fn handle_matrix_fill(_count: usize) -> RpcResult {
    unsafe {
        // Fill the bitmap
        for row in BITMAP.iter_mut() {
            for col in row.iter_mut() {
                *col = 1;
            }
        }
        let frame = Frame::all_on();
        matrix().load_frame(&frame);
    }
    RpcResult::Bool(true)
}

/// Handle led_matrix.set_pixel(row, col, on)
fn handle_matrix_set_pixel(count: usize) -> RpcResult {
    if count < 3 {
        return RpcResult::Error(-1, "Need 3 params");
    }

    unsafe {
        let row = PARAMS.ints[0];
        let col = PARAMS.ints[1];
        let on = PARAMS.ints[2] != 0;

        if row < 0 || row >= 8 || col < 0 || col >= 13 {
            return RpcResult::Error(-2, "Invalid coords");
        }

        BITMAP[row as usize][col as usize] = if on { 1 } else { 0 };
        let frame = Frame::from_bitmap(&BITMAP);
        matrix().load_frame(&frame);
    }

    RpcResult::Bool(true)
}

/// Handle led_matrix.set_row(row, bitmap) - bitmap is 13 bits
fn handle_matrix_set_row(count: usize) -> RpcResult {
    if count < 2 {
        return RpcResult::Error(-1, "Need 2 params");
    }

    unsafe {
        let row = PARAMS.ints[0];
        let bitmap = PARAMS.ints[1] as u16;

        if row < 0 || row >= 8 {
            return RpcResult::Error(-2, "Invalid row");
        }

        for col in 0..13 {
            BITMAP[row as usize][col] = if bitmap & (1 << (12 - col)) != 0 {
                1
            } else {
                0
            };
        }
        let frame = Frame::from_bitmap(&BITMAP);
        matrix().load_frame(&frame);
    }

    RpcResult::Bool(true)
}

/// Handle led_matrix.set_frame(d0, d1, d2, d3) - 4 u32 values packed
fn handle_matrix_set_frame(count: usize) -> RpcResult {
    if count < 4 {
        return RpcResult::Error(-1, "Need 4 params");
    }

    unsafe {
        let frame_data = [
            PARAMS.ints[0] as u32,
            PARAMS.ints[1] as u32,
            PARAMS.ints[2] as u32,
            PARAMS.ints[3] as u32,
        ];

        let frame = Frame::new(frame_data);
        matrix().load_frame(&frame);

        // Update our bitmap cache from the frame
        for row in 0..8 {
            for col in 0..13 {
                let bit_index = row * 13 + col;
                let word = bit_index / 32;
                let bit = 31 - (bit_index % 32);
                BITMAP[row][col] = if frame_data[word] & (1 << bit) != 0 {
                    1
                } else {
                    0
                };
            }
        }
    }

    RpcResult::Bool(true)
}

/// Handle led_matrix.set_grayscale(brightness) - fill all LEDs with brightness
fn handle_matrix_set_grayscale(count: usize) -> RpcResult {
    if count < 1 {
        return RpcResult::Error(-1, "Need 1 param");
    }

    unsafe {
        let brightness = (PARAMS.ints[0] as u8).min(7);

        for i in 0..104 {
            GRAYSCALE[i] = brightness;
        }
        matrix().set_grayscale_bits(3);
        let frame = GrayscaleFrame::new(GRAYSCALE);
        matrix().draw(&frame);
    }

    RpcResult::Bool(true)
}

/// Handle led_matrix.set_brightness(row, col, brightness)
fn handle_matrix_set_brightness(count: usize) -> RpcResult {
    if count < 3 {
        return RpcResult::Error(-1, "Need 3 params");
    }

    unsafe {
        let row = PARAMS.ints[0];
        let col = PARAMS.ints[1];
        let brightness = (PARAMS.ints[2] as u8).min(7);

        if row < 0 || row >= 8 || col < 0 || col >= 13 {
            return RpcResult::Error(-2, "Invalid coords");
        }

        let idx = row as usize * 13 + col as usize;
        GRAYSCALE[idx] = brightness;
        matrix().set_grayscale_bits(3);
        let frame = GrayscaleFrame::new(GRAYSCALE);
        matrix().draw(&frame);
    }

    RpcResult::Bool(true)
}

/// Main entry point
#[no_mangle]
extern "C" fn rust_main() {
    unsafe {
        zephyr::set_logger().unwrap();
    }

    warn!("===========================================");
    warn!("  RPC Server - Arduino Uno Q");
    warn!("  SPI-based MessagePack-RPC");
    warn!("===========================================");

    // Initialize LED matrix
    warn!("Initializing LED matrix...");
    unsafe {
        MATRIX = Some(LedMatrix::new());
        if !matrix().begin() {
            warn!("Failed to initialize LED matrix!");
            loop {
                sleep(Duration::millis_at_least(1000));
            }
        }
    }
    warn!("LED matrix initialized!");

    // Quick visual indicator that we're starting
    unsafe {
        let frame = Frame::all_on();
        matrix().load_frame(&frame);
        sleep(Duration::millis_at_least(200));
        matrix().clear();
    }

    // Initialize SPI transport
    warn!("Initializing SPI transport...");
    let mut spi = SpiTransport::new();
    if !spi.init() {
        warn!("Failed to initialize SPI!");
        loop {
            sleep(Duration::millis_at_least(1000));
        }
    }
    warn!("SPI initialized!");

    // Create RPC server and register handlers
    warn!("Registering RPC handlers...");
    let mut server = RpcServer::new();

    // Core methods
    server.register("ping", handle_ping);
    server.register("version", handle_version);

    // LED matrix methods
    server.register("led_matrix.clear", handle_matrix_clear);
    server.register("led_matrix.fill", handle_matrix_fill);
    server.register("led_matrix.set_pixel", handle_matrix_set_pixel);
    server.register("led_matrix.set_row", handle_matrix_set_row);
    server.register("led_matrix.set_frame", handle_matrix_set_frame);
    server.register("led_matrix.set_grayscale", handle_matrix_set_grayscale);
    server.register("led_matrix.set_brightness", handle_matrix_set_brightness);

    warn!("RPC server ready, waiting for requests...");

    // Prepare initial empty response (ready signal)
    let empty_response: [u8; 0] = [];
    spi.prepare_tx(&empty_response);

    let mut request_count: u32 = 0;

    // Main loop: wait for SPI transfers and process RPC requests
    loop {
        // Wait for SPI transfer from Linux (blocking)
        let rx_len = spi.transceive();

        if rx_len == 0 {
            // Empty transfer (polling from Linux), continue
            spi.prepare_tx(&empty_response);
            continue;
        }

        request_count = request_count.wrapping_add(1);

        // Read the received data
        let mut rx_buffer = [0u8; 512];
        let mut total_read = 0;
        while total_read < rx_len && total_read < rx_buffer.len() {
            let mut byte_buf = [0u8; 1];
            if spi.read(&mut byte_buf) > 0 {
                rx_buffer[total_read] = byte_buf[0];
                total_read += 1;
            } else {
                break;
            }
        }

        warn!("[{}] RX {} bytes", request_count, total_read);

        // Process the RPC message
        if let Some(response) = server.process(&rx_buffer[..total_read]) {
            warn!("[{}] TX {} bytes response", request_count, response.len());
            spi.prepare_tx(response);
        } else {
            // No response needed (notification or error)
            warn!("[{}] No response", request_count);
            spi.prepare_tx(&empty_response);
        }
    }
}
