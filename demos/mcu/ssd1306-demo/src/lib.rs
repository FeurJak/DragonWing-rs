// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// SSD1306 OLED Display Demo for Arduino Uno Q (STM32U585)
//
// This example demonstrates the dragonwing-i2c library by driving
// an SSD1306 OLED display connected via I2C.
//
// Hardware Setup:
//   - SSD1306 display (128x64 or 128x32) connected to Arduino header I2C pins
//   - SDA: Pin D20 (PB11)
//   - SCL: Pin D21 (PB10)
//   - VCC: 3.3V
//   - GND: GND
//
// The demo cycles through:
// 1. I2C bus scan to find the display
// 2. Display initialization
// 3. "Hello Rust!" text display
// 4. Counter animation
// 5. Graphics primitives demo

#![no_std]
#![allow(unexpected_cfgs)]

use core::fmt::Write;
use log::warn;

use dragonwing_i2c::{I2c, I2cBus, I2cSpeed};
use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyleBuilder},
    pixelcolor::BinaryColor,
    prelude::*,
    primitives::{Circle, Line, PrimitiveStyle, Rectangle},
    text::{Baseline, Text},
};
use ssd1306::{prelude::*, I2CDisplayInterface, Ssd1306};
use zephyr::time::{sleep, Duration};

/// SSD1306 default I2C address
const SSD1306_ADDR: u8 = 0x3C;

/// Main entry point called from C/Zephyr.
#[no_mangle]
extern "C" fn rust_main() {
    // Initialize the Zephyr logger
    unsafe {
        zephyr::set_logger().unwrap();
    }

    warn!("===========================================");
    warn!("  SSD1306 OLED Display Demo - Arduino Uno Q");
    warn!("  Using dragonwing-i2c + ssd1306 crates");
    warn!("===========================================");

    // Create and initialize I2C
    let mut i2c = I2c::new(I2cBus::Wire);

    warn!("Initializing I2C bus...");
    if let Err(e) = i2c.init() {
        warn!("Failed to initialize I2C: {:?}", e);
        loop {}
    }

    // Set I2C speed to 400 kHz (Fast mode)
    if let Err(e) = i2c.set_speed(I2cSpeed::Fast) {
        warn!("Failed to set I2C speed: {:?}", e);
    }

    warn!("I2C initialized at 400 kHz");

    // Scan the I2C bus for devices
    warn!("Scanning I2C bus...");
    let scan_result = i2c.scan();

    if scan_result.is_empty() {
        warn!("No I2C devices found!");
        warn!("Please check your SSD1306 display connection:");
        warn!("  - SDA -> D20 (PB11)");
        warn!("  - SCL -> D21 (PB10)");
        warn!("  - VCC -> 3.3V");
        warn!("  - GND -> GND");
        loop {}
    }

    warn!("Found {} I2C device(s):", scan_result.count());
    for addr in scan_result.iter() {
        warn!("  - 0x{:02X}", addr);
    }

    // Check for SSD1306 at expected address
    if !i2c.probe(SSD1306_ADDR) {
        warn!("SSD1306 not found at address 0x{:02X}", SSD1306_ADDR);
        warn!("Try address 0x3D if SA0 pin is high");
        loop {}
    }

    warn!("SSD1306 found at 0x{:02X}", SSD1306_ADDR);

    // Create display interface and driver
    // Note: We need to give ownership of i2c to the display interface
    let interface = I2CDisplayInterface::new(i2c);
    let mut display = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
        .into_buffered_graphics_mode();

    // Initialize the display
    warn!("Initializing SSD1306 display...");
    if let Err(_e) = display.init() {
        warn!("Failed to initialize display");
        loop {}
    }

    warn!("Display initialized successfully!");

    // Create text style
    let text_style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(BinaryColor::On)
        .build();

    // Demo loop
    let delay_short = Duration::millis_at_least(100);
    let delay_medium = Duration::millis_at_least(500);
    let delay_long = Duration::millis_at_least(2000);

    loop {
        // Demo 1: Hello World
        warn!("Demo 1: Hello World");
        display.clear_buffer();

        Text::with_baseline("Hello Rust!", Point::new(20, 10), text_style, Baseline::Top)
            .draw(&mut display)
            .unwrap();

        Text::with_baseline(
            "Arduino Uno Q",
            Point::new(15, 25),
            text_style,
            Baseline::Top,
        )
        .draw(&mut display)
        .unwrap();

        Text::with_baseline(
            "SSD1306 Demo",
            Point::new(18, 40),
            text_style,
            Baseline::Top,
        )
        .draw(&mut display)
        .unwrap();

        display.flush().unwrap();
        sleep(delay_long);

        // Demo 2: Counter
        warn!("Demo 2: Counter");
        for i in 0..10 {
            display.clear_buffer();

            Text::with_baseline("Counter:", Point::new(35, 15), text_style, Baseline::Top)
                .draw(&mut display)
                .unwrap();

            // Create a buffer for the number
            let mut buf = [0u8; 16];
            let s = format_u32(i, &mut buf);

            Text::with_baseline(s, Point::new(58, 35), text_style, Baseline::Top)
                .draw(&mut display)
                .unwrap();

            display.flush().unwrap();
            sleep(delay_medium);
        }

        // Demo 3: Graphics primitives
        warn!("Demo 3: Graphics primitives");
        display.clear_buffer();

        // Draw rectangle
        Rectangle::new(Point::new(5, 5), Size::new(50, 30))
            .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, 1))
            .draw(&mut display)
            .unwrap();

        // Draw filled rectangle
        Rectangle::new(Point::new(70, 5), Size::new(50, 30))
            .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
            .draw(&mut display)
            .unwrap();

        // Draw circle
        Circle::new(Point::new(20, 40), 20)
            .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, 1))
            .draw(&mut display)
            .unwrap();

        // Draw filled circle
        Circle::new(Point::new(80, 40), 20)
            .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
            .draw(&mut display)
            .unwrap();

        display.flush().unwrap();
        sleep(delay_long);

        // Demo 4: Lines
        warn!("Demo 4: Lines");
        display.clear_buffer();

        for i in 0..8 {
            let y = i * 8;
            Line::new(Point::new(0, y as i32), Point::new(127, 63 - y as i32))
                .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, 1))
                .draw(&mut display)
                .unwrap();
        }

        display.flush().unwrap();
        sleep(delay_long);

        // Demo 5: Animation - bouncing pixel
        warn!("Demo 5: Bouncing pixel");
        let mut x: i32 = 64;
        let mut y: i32 = 32;
        let mut dx: i32 = 2;
        let mut dy: i32 = 1;

        for _ in 0..100 {
            display.clear_buffer();

            // Draw bouncing "ball"
            Circle::new(Point::new(x - 3, y - 3), 6)
                .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
                .draw(&mut display)
                .unwrap();

            // Update position
            x += dx;
            y += dy;

            // Bounce off edges
            if x <= 3 || x >= 124 {
                dx = -dx;
            }
            if y <= 3 || y >= 60 {
                dy = -dy;
            }

            display.flush().unwrap();
            sleep(delay_short);
        }

        // Demo 6: I2C info
        warn!("Demo 6: I2C info");
        display.clear_buffer();

        Text::with_baseline(
            "I2C Bus: Wire",
            Point::new(10, 10),
            text_style,
            Baseline::Top,
        )
        .draw(&mut display)
        .unwrap();

        Text::with_baseline(
            "Speed: 400kHz",
            Point::new(10, 25),
            text_style,
            Baseline::Top,
        )
        .draw(&mut display)
        .unwrap();

        Text::with_baseline("Addr: 0x3C", Point::new(10, 40), text_style, Baseline::Top)
            .draw(&mut display)
            .unwrap();

        Text::with_baseline(
            "DragonWing I2C",
            Point::new(10, 55),
            text_style,
            Baseline::Top,
        )
        .draw(&mut display)
        .unwrap();

        display.flush().unwrap();
        sleep(delay_long);

        warn!("Demo cycle complete, restarting...");
    }
}

/// Format a u32 as a decimal string.
/// Returns a string slice pointing into the provided buffer.
fn format_u32(mut n: u32, buf: &mut [u8; 16]) -> &str {
    if n == 0 {
        buf[0] = b'0';
        return unsafe { core::str::from_utf8_unchecked(&buf[..1]) };
    }

    let mut i = 0;
    let mut temp = [0u8; 16];

    while n > 0 {
        temp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }

    // Reverse into output buffer
    for j in 0..i {
        buf[j] = temp[i - 1 - j];
    }

    unsafe { core::str::from_utf8_unchecked(&buf[..i]) }
}
