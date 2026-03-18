// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// LED Matrix Demo for Arduino Uno Q (STM32U585)
//
// This example demonstrates the arduino-led-matrix Rust library by showing
// various patterns and animations on the 8x13 LED matrix.
//
// The demo cycles through:
// 1. All LEDs on/off blink
// 2. Row-by-row scan
// 3. Column-by-column scan
// 4. Grayscale gradient
// 5. Custom animation sequence

#![no_std]
#![allow(unexpected_cfgs)]

use log::warn;

use dragonwing_led_matrix::{animation, Frame, GrayscaleFrame, LedMatrix};
use zephyr::time::{sleep, Duration};

// Define a custom scrolling animation
animation!(
    SCROLL_ANIMATION,
    [
        [0x38022020, 0x810408a0, 0x2200e800, 0x20000000, 66],
        [0x1c011010, 0x40820450, 0x11007400, 0x10000000, 66],
        [0x0e008808, 0x20410228, 0x08803a00, 0x08000000, 66],
        [0x07004404, 0x10208114, 0x04401d00, 0x04000000, 66],
        [0x03802202, 0x0810408a, 0x02200e80, 0x02000000, 66],
        [0x01c01101, 0x04082045, 0x01100740, 0x01000000, 66],
        [0x00e00880, 0x82041022, 0x808803a0, 0x00000000, 66],
        [0x00700440, 0x40020011, 0x004401c0, 0x00000000, 66],
        [0x00380200, 0x20010008, 0x802000e0, 0x00000000, 66],
        [0x00180100, 0x10008004, 0x00100060, 0x00000000, 66],
        [0x00080080, 0x08004002, 0x00080020, 0x00000000, 66],
        [0x00000040, 0x04002001, 0x00040000, 0x00000000, 66],
        [0x00000000, 0x02001000, 0x80000000, 0x00000000, 66],
        [0x00000000, 0x00000000, 0x00000000, 0x00000000, 66],
    ]
);

/// Main entry point called from C/Zephyr.
#[no_mangle]
extern "C" fn rust_main() {
    // Initialize the Zephyr logger
    unsafe {
        zephyr::set_logger().unwrap();
    }

    warn!("===========================================");
    warn!("  LED Matrix Demo - Arduino Uno Q");
    warn!("  Using arduino-led-matrix Rust library");
    warn!("===========================================");

    // Create and initialize the LED matrix
    let mut matrix = LedMatrix::new();

    if !matrix.begin() {
        warn!("Failed to initialize LED matrix!");
        loop {}
    }

    warn!("LED Matrix initialized successfully!");

    let delay_short = Duration::millis_at_least(100);
    let delay_medium = Duration::millis_at_least(500);
    let delay_long = Duration::millis_at_least(1000);

    loop {
        // Demo 1: Blink all LEDs
        warn!("Demo 1: Blink all LEDs");
        for _ in 0..3 {
            let on_frame = Frame::all_on();
            matrix.load_frame(&on_frame);
            sleep(delay_medium);

            matrix.clear();
            sleep(delay_medium);
        }

        // Demo 2: Row scan
        warn!("Demo 2: Row scan");
        for row in 0..8 {
            let mut bitmap = [[0u8; 13]; 8];
            for col in 0..13 {
                bitmap[row][col] = 1;
            }
            let frame = Frame::from_bitmap(&bitmap);
            matrix.load_frame(&frame);
            sleep(delay_short);
        }
        sleep(delay_medium);
        matrix.clear();

        // Demo 3: Column scan
        warn!("Demo 3: Column scan");
        for col in 0..13 {
            let mut bitmap = [[0u8; 13]; 8];
            for row in 0..8 {
                bitmap[row][col] = 1;
            }
            let frame = Frame::from_bitmap(&bitmap);
            matrix.load_frame(&frame);
            sleep(delay_short);
        }
        sleep(delay_medium);
        matrix.clear();

        // Demo 4: Grayscale gradient
        warn!("Demo 4: Grayscale gradient");
        matrix.set_grayscale_bits(3);

        // Create a gradient where each row has different brightness
        let mut gray_frame = GrayscaleFrame::all_off();
        for row in 0..8 {
            for col in 0..13 {
                gray_frame.set(row, col, row as u8);
            }
        }
        matrix.draw(&gray_frame);
        sleep(delay_long);
        sleep(delay_long);

        // Demo 5: Grayscale wave animation
        warn!("Demo 5: Grayscale wave");
        for wave in 0..26 {
            let mut gray_frame = GrayscaleFrame::all_off();
            for row in 0..8 {
                for col in 0..13 {
                    // Create a moving wave pattern
                    let dist =
                        ((col as i32 - wave as i32 % 13).abs() + (row as i32 - 4).abs()) as u8;
                    let brightness = if dist < 7 { 7 - dist } else { 0 };
                    gray_frame.set(row, col, brightness);
                }
            }
            matrix.draw(&gray_frame);
            sleep(delay_short);
        }

        // Demo 6: Custom animation sequence
        warn!("Demo 6: Animation sequence");
        matrix.load_sequence(&SCROLL_ANIMATION);

        // Play the animation 3 times
        for _ in 0..3 {
            loop {
                matrix.next();
                let interval = matrix.interval();
                if interval > 0 {
                    sleep(Duration::millis_at_least(interval as u64));
                }
                if matrix.sequence_done() {
                    break;
                }
            }
        }

        // Demo 7: Checkerboard pattern
        warn!("Demo 7: Checkerboard");
        let mut bitmap = [[0u8; 13]; 8];
        for row in 0..8 {
            for col in 0..13 {
                bitmap[row][col] = ((row + col) % 2) as u8;
            }
        }
        let checker_frame = Frame::from_bitmap(&bitmap);
        matrix.load_frame(&checker_frame);
        sleep(delay_long);

        // Invert checkerboard
        for row in 0..8 {
            for col in 0..13 {
                bitmap[row][col] = 1 - bitmap[row][col];
            }
        }
        let inv_checker_frame = Frame::from_bitmap(&bitmap);
        matrix.load_frame(&inv_checker_frame);
        sleep(delay_long);

        // Demo 8: Diagonal wipe
        warn!("Demo 8: Diagonal wipe");
        for diag in 0..21 {
            let mut bitmap = [[0u8; 13]; 8];
            for row in 0..8 {
                for col in 0..13 {
                    if row + col <= diag {
                        bitmap[row][col] = 1;
                    }
                }
            }
            let frame = Frame::from_bitmap(&bitmap);
            matrix.load_frame(&frame);
            sleep(Duration::millis_at_least(50));
        }
        sleep(delay_medium);

        // Clear and pause before restarting
        matrix.clear();
        warn!("Demo cycle complete, restarting in 2 seconds...");
        sleep(delay_long);
        sleep(delay_long);
    }
}
