// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Display Server for Arduino Uno Q (STM32U585)
//
// RPC server that controls both displays:
// - SSD1306 OLED (128x64, yellow top 16 rows, blue bottom 48 rows) via I2C
// - LED Matrix (8x13, 104 LEDs) via charlieplexing
//
// Hardware Setup:
//   SSD1306 OLED (I2C):
//     - SDA: Pin D20 (PB11)
//     - SCL: Pin D21 (PB10)
//     - VCC: 3.3V
//     - GND: GND
//     - I2C Address: 0x3C
//
//   LED Matrix:
//     - Built-in on Arduino Uno Q (PF0-PF10)
//
//   SPI (RPC from Linux MPU):
//     - Internal SPI3 bus to QRB2210
//
// RPC Methods:
//   Core:
//     - ping() -> "pong"
//     - version() -> firmware version
//
//   OLED Display (oled.*):
//     - oled.clear() - clear display
//     - oled.text(x, y, zone, text_id) - draw predefined text
//     - oled.line1(text_id) - set line 1 text (yellow zone)
//     - oled.line2(text_id) - set line 2 text (blue zone)
//     - oled.line3(text_id) - set line 3 text (blue zone)
//     - oled.progress(percent) - show progress bar
//     - oled.value(label_id, value) - show label: value
//
//   LED Matrix (led_matrix.*):
//     - led_matrix.clear() - clear all LEDs
//     - led_matrix.fill() - turn on all LEDs
//     - led_matrix.set_frame(d0, d1, d2, d3) - set full frame
//     - led_matrix.set_icon(icon_id) - show predefined icon
//     - led_matrix.set_number(num) - display a number

#![no_std]
#![allow(unexpected_cfgs)]

use log::warn;

use dragonwing_i2c::{I2c, I2cBus, I2cSpeed};
use dragonwing_led_matrix::{Frame, LedMatrix};
use dragonwing_rpc::{RpcResult, RpcServer, SpiTransport, Transport, PARAMS};
use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyleBuilder},
    pixelcolor::BinaryColor,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    text::{Baseline, Text},
};
use ssd1306::{prelude::*, I2CDisplayInterface, Ssd1306};
use zephyr::time::{sleep, Duration};

/// SSD1306 I2C address
const SSD1306_ADDR: u8 = 0x3C;

/// Display zones for the yellow/blue OLED
/// Yellow zone: rows 0-15 (top 16 pixels)
/// Blue zone: rows 16-63 (bottom 48 pixels)
const YELLOW_ZONE_HEIGHT: i32 = 16;

// Type alias for our display
type OledDisplay = Ssd1306<
    ssd1306::prelude::I2CInterface<I2c>,
    ssd1306::prelude::DisplaySize128x64,
    ssd1306::mode::BufferedGraphicsMode<ssd1306::prelude::DisplaySize128x64>,
>;

// Global state (single-threaded MCU)
static mut MATRIX: Option<LedMatrix> = None;
static mut DISPLAY: Option<OledDisplay> = None;

// Current display state
static mut OLED_LINE1: &str = "";
static mut OLED_LINE2: &str = "";
static mut OLED_LINE3: &str = "";
static mut OLED_PROGRESS: i32 = -1; // -1 = hidden

/// Predefined text strings (to avoid dynamic allocation)
const TEXTS: [&str; 32] = [
    "",               // 0: empty
    "System Monitor", // 1
    "CPU:",           // 2
    "MEM:",           // 3
    "DISK:",          // 4
    "NET:",           // 5
    "TEMP:",          // 6
    "Arduino Uno Q",  // 7
    "Display Server", // 8
    "Ready",          // 9
    "Waiting...",     // 10
    "Connected",      // 11
    "Error",          // 12
    "OK",             // 13
    "Loading",        // 14
    "0%",
    "10%",
    "20%",
    "30%",
    "40%",
    "50%",
    "60%",
    "70%",
    "80%",
    "90%",
    "100%", // 15-25
    "LOW",
    "MED",
    "HIGH",
    "CRIT",       // 26-29
    "RPC Active", // 30
    "DragonWing", // 31
];

/// LED Matrix icons
mod icons {
    // Check mark
    pub const CHECK: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0],
    ];

    // X mark (error)
    pub const CROSS: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
    ];

    // Heart
    pub const HEART: [[u8; 13]; 8] = [
        [0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0],
        [0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0],
        [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
        [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0],
    ];

    // CPU chip
    pub const CPU: [[u8; 13]; 8] = [
        [0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0],
        [0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0],
        [0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0],
        [0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ];

    // Memory chip
    pub const MEMORY: [[u8; 13]; 8] = [
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0],
        [0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0],
        [0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0],
        [0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ];

    // Network/WiFi
    pub const NETWORK: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ];

    // Bar graph levels (0-7)
    pub const BARS: [[[u8; 13]; 8]; 8] = [
        // Level 0
        [[0; 13]; 8],
        // Level 1
        [
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ],
        // Level 2
        [
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        ],
        // Level 3
        [
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0],
        ],
        // Level 4
        [
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0],
        ],
        // Level 5
        [
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
        ],
        // Level 6
        [
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
        ],
        // Level 7 (full)
        [
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
            [1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1],
        ],
    ];
}

// === Helper Functions ===

/// Get mutable reference to the global matrix
unsafe fn matrix() -> &'static mut LedMatrix {
    MATRIX.as_mut().expect("Matrix not initialized")
}

/// Get mutable reference to the global display
unsafe fn display() -> &'static mut OledDisplay {
    DISPLAY.as_mut().expect("Display not initialized")
}

/// Convert 8x13 bitmap to frame data
fn bitmap_to_frame(bitmap: &[[u8; 13]; 8]) -> [u32; 4] {
    let mut frame = [0u32; 4];
    for row in 0..8 {
        for col in 0..13 {
            if bitmap[row][col] != 0 {
                let bit_index = row * 13 + col;
                let word = bit_index / 32;
                let bit = 31 - (bit_index % 32);
                frame[word] |= 1 << bit;
            }
        }
    }
    frame
}

/// Refresh the OLED display with current state
fn refresh_oled() {
    unsafe {
        let disp = display();
        disp.clear_buffer();

        let text_style = MonoTextStyleBuilder::new()
            .font(&FONT_6X10)
            .text_color(BinaryColor::On)
            .build();

        // Line 1: Yellow zone (y=0-15), centered
        if !OLED_LINE1.is_empty() {
            let x = (128 - OLED_LINE1.len() as i32 * 6) / 2;
            Text::with_baseline(
                OLED_LINE1,
                Point::new(x.max(0), 3),
                text_style,
                Baseline::Top,
            )
            .draw(disp)
            .ok();
        }

        // Line 2: Blue zone top (y=16+)
        if !OLED_LINE2.is_empty() {
            Text::with_baseline(
                OLED_LINE2,
                Point::new(4, YELLOW_ZONE_HEIGHT + 4),
                text_style,
                Baseline::Top,
            )
            .draw(disp)
            .ok();
        }

        // Line 3: Blue zone middle
        if !OLED_LINE3.is_empty() {
            Text::with_baseline(
                OLED_LINE3,
                Point::new(4, YELLOW_ZONE_HEIGHT + 18),
                text_style,
                Baseline::Top,
            )
            .draw(disp)
            .ok();
        }

        // Progress bar (if enabled)
        if OLED_PROGRESS >= 0 {
            let bar_y = YELLOW_ZONE_HEIGHT + 34;
            let bar_width = 120;
            let bar_height = 10;
            let bar_x = 4;

            // Outline
            Rectangle::new(
                Point::new(bar_x, bar_y),
                Size::new(bar_width as u32, bar_height as u32),
            )
            .into_styled(PrimitiveStyle::with_stroke(BinaryColor::On, 1))
            .draw(disp)
            .ok();

            // Fill
            let fill_width = (bar_width - 4) * OLED_PROGRESS / 100;
            if fill_width > 0 {
                Rectangle::new(
                    Point::new(bar_x + 2, bar_y + 2),
                    Size::new(fill_width as u32, (bar_height - 4) as u32),
                )
                .into_styled(PrimitiveStyle::with_fill(BinaryColor::On))
                .draw(disp)
                .ok();
            }
        }

        disp.flush().ok();
    }
}

// === RPC Handlers ===

fn handle_ping(_count: usize) -> RpcResult {
    RpcResult::Str("pong")
}

fn handle_version(_count: usize) -> RpcResult {
    RpcResult::Str("display-server 0.1.0")
}

// OLED handlers

fn handle_oled_clear(_count: usize) -> RpcResult {
    unsafe {
        OLED_LINE1 = "";
        OLED_LINE2 = "";
        OLED_LINE3 = "";
        OLED_PROGRESS = -1;
        display().clear_buffer();
        display().flush().ok();
    }
    RpcResult::Bool(true)
}

fn handle_oled_line1(count: usize) -> RpcResult {
    if count < 1 {
        return RpcResult::Error(-1, "Need text_id");
    }
    unsafe {
        let text_id = PARAMS.ints[0] as usize;
        if text_id < TEXTS.len() {
            OLED_LINE1 = TEXTS[text_id];
            refresh_oled();
        }
    }
    RpcResult::Bool(true)
}

fn handle_oled_line2(count: usize) -> RpcResult {
    if count < 1 {
        return RpcResult::Error(-1, "Need text_id");
    }
    unsafe {
        let text_id = PARAMS.ints[0] as usize;
        if text_id < TEXTS.len() {
            OLED_LINE2 = TEXTS[text_id];
            refresh_oled();
        }
    }
    RpcResult::Bool(true)
}

fn handle_oled_line3(count: usize) -> RpcResult {
    if count < 1 {
        return RpcResult::Error(-1, "Need text_id");
    }
    unsafe {
        let text_id = PARAMS.ints[0] as usize;
        if text_id < TEXTS.len() {
            OLED_LINE3 = TEXTS[text_id];
            refresh_oled();
        }
    }
    RpcResult::Bool(true)
}

fn handle_oled_progress(count: usize) -> RpcResult {
    if count < 1 {
        return RpcResult::Error(-1, "Need percent");
    }
    unsafe {
        let percent = PARAMS.ints[0] as i32;
        OLED_PROGRESS = percent.max(-1).min(100);
        refresh_oled();
    }
    RpcResult::Bool(true)
}

// LED Matrix handlers

fn handle_matrix_clear(_count: usize) -> RpcResult {
    unsafe {
        matrix().clear();
    }
    RpcResult::Bool(true)
}

fn handle_matrix_fill(_count: usize) -> RpcResult {
    unsafe {
        let frame = Frame::all_on();
        matrix().load_frame(&frame);
    }
    RpcResult::Bool(true)
}

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
    }
    RpcResult::Bool(true)
}

fn handle_matrix_set_icon(count: usize) -> RpcResult {
    if count < 1 {
        return RpcResult::Error(-1, "Need icon_id");
    }
    unsafe {
        let icon_id = PARAMS.ints[0];
        let bitmap = match icon_id {
            0 => &icons::CHECK,
            1 => &icons::CROSS,
            2 => &icons::HEART,
            3 => &icons::CPU,
            4 => &icons::MEMORY,
            5 => &icons::NETWORK,
            _ => return RpcResult::Error(-2, "Unknown icon"),
        };
        let frame_data = bitmap_to_frame(bitmap);
        let frame = Frame::new(frame_data);
        matrix().load_frame(&frame);
    }
    RpcResult::Bool(true)
}

fn handle_matrix_set_level(count: usize) -> RpcResult {
    if count < 1 {
        return RpcResult::Error(-1, "Need level 0-7");
    }
    unsafe {
        let level = (PARAMS.ints[0] as usize).min(7);
        let bitmap = &icons::BARS[level];
        let frame_data = bitmap_to_frame(bitmap);
        let frame = Frame::new(frame_data);
        matrix().load_frame(&frame);
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
    warn!("  Display Server - Arduino Uno Q");
    warn!("  SSD1306 OLED + LED Matrix via RPC");
    warn!("===========================================");

    // === Initialize I2C and SSD1306 ===
    warn!("Initializing I2C bus...");
    let mut i2c = I2c::new(I2cBus::Wire);
    if let Err(e) = i2c.init() {
        warn!("Failed to initialize I2C: {:?}", e);
        loop {
            sleep(Duration::millis_at_least(1000));
        }
    }
    i2c.set_speed(I2cSpeed::Fast).ok();

    // Scan for SSD1306
    if !i2c.probe(SSD1306_ADDR) {
        warn!("SSD1306 not found at 0x{:02X}!", SSD1306_ADDR);
        warn!("Connect SSD1306: SDA->D20, SCL->D21");
        loop {
            sleep(Duration::millis_at_least(1000));
        }
    }
    warn!("SSD1306 found at 0x{:02X}", SSD1306_ADDR);

    // Initialize display
    let interface = I2CDisplayInterface::new(i2c);
    let mut disp = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
        .into_buffered_graphics_mode();

    if disp.init().is_err() {
        warn!("Failed to initialize SSD1306!");
        loop {
            sleep(Duration::millis_at_least(1000));
        }
    }
    warn!("SSD1306 initialized!");

    // Store global reference
    unsafe {
        DISPLAY = Some(disp);
    }

    // === Initialize LED Matrix ===
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

    // Show startup screen
    unsafe {
        OLED_LINE1 = "Display Server";
        OLED_LINE2 = "Waiting for RPC...";
        OLED_LINE3 = "";
        OLED_PROGRESS = -1;
        refresh_oled();

        // Flash LED matrix
        let frame = Frame::all_on();
        matrix().load_frame(&frame);
        sleep(Duration::millis_at_least(200));
        matrix().clear();
    }

    // === Initialize SPI Transport ===
    warn!("Initializing SPI transport...");
    let mut spi = SpiTransport::new();
    if !spi.init() {
        warn!("Failed to initialize SPI!");
        loop {
            sleep(Duration::millis_at_least(1000));
        }
    }
    warn!("SPI initialized!");

    // === Register RPC Handlers ===
    warn!("Registering RPC handlers...");
    let mut server = RpcServer::new();

    // Core
    server.register("ping", handle_ping);
    server.register("version", handle_version);

    // OLED
    server.register("oled.clear", handle_oled_clear);
    server.register("oled.line1", handle_oled_line1);
    server.register("oled.line2", handle_oled_line2);
    server.register("oled.line3", handle_oled_line3);
    server.register("oled.progress", handle_oled_progress);

    // LED Matrix
    server.register("led_matrix.clear", handle_matrix_clear);
    server.register("led_matrix.fill", handle_matrix_fill);
    server.register("led_matrix.set_frame", handle_matrix_set_frame);
    server.register("led_matrix.set_icon", handle_matrix_set_icon);
    server.register("led_matrix.set_level", handle_matrix_set_level);

    warn!("RPC server ready!");

    // Update display
    unsafe {
        OLED_LINE2 = "RPC Active";
        OLED_LINE3 = "Ready";
        refresh_oled();
    }

    // Prepare empty response
    let empty_response: [u8; 0] = [];
    spi.prepare_tx(&empty_response);

    let mut request_count: u32 = 0;

    // === Main RPC Loop ===
    loop {
        let rx_len = spi.transceive();

        if rx_len == 0 {
            spi.prepare_tx(&empty_response);
            continue;
        }

        request_count = request_count.wrapping_add(1);

        // Read received data
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

        // Process RPC
        if let Some(response) = server.process(&rx_buffer[..total_read]) {
            warn!("[{}] TX {} bytes", request_count, response.len());
            spi.prepare_tx(response);
        } else {
            spi.prepare_tx(&empty_response);
        }
    }
}
