// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// System Monitor for Arduino Uno Q Display Server
//
// Reads CPU, memory, and system metrics and displays them on:
// - SSD1306 OLED (128x64, yellow top / blue bottom)
// - LED Matrix (8x13, 104 LEDs)
//
// The MCU runs display-server firmware that accepts RPC commands.

use anyhow::{Context, Result};
use arduino_rpc_client::RpcClientSync;
use clap::Parser;
use log::{debug, error, info, warn};
use std::thread;
use std::time::Duration;
use sysinfo::System;

/// System Monitor CLI arguments
#[derive(Parser, Debug)]
#[command(name = "system-monitor")]
#[command(about = "Display system metrics on Arduino Uno Q displays")]
struct Args {
    /// RPC socket path
    #[arg(short, long, default_value = "/tmp/arduino-spi-router.sock")]
    socket: String,

    /// Update interval in milliseconds
    #[arg(short, long, default_value_t = 1000)]
    interval: u64,

    /// Run once and exit
    #[arg(short, long)]
    once: bool,

    /// Demo mode (cycle through patterns without reading system stats)
    #[arg(short, long)]
    demo: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

/// 8x13 LED matrix patterns for system icons
mod icons {
    // CPU icon (chip-like pattern)
    pub const CPU: [[u8; 13]; 8] = [
        [0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0],
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        [0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0],
        [1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1],
        [0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0],
        [1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1],
        [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0],
        [0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0],
    ];

    // Memory icon (RAM stick pattern)
    pub const MEMORY: [[u8; 13]; 8] = [
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
        [0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0],
        [0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0],
        [0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0],
        [0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0],
        [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0],
        [0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0],
        [0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0],
    ];

    // OK/checkmark icon
    pub const OK: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0],
        [1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0],
        [0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0],
        [0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0],
    ];

    // Warning icon (exclamation mark)
    pub const WARNING: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0],
        [0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0],
        [0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0],
        [0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0],
        [0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0],
        [0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0],
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
    ];

    // Error icon (X mark)
    pub const ERROR: [[u8; 13]; 8] = [
        [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1],
        [0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0],
        [0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0],
        [0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0],
        [0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0],
        [0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0],
    ];
}

/// 3x5 digit font for displaying numbers
mod digits {
    pub const ZERO: [[u8; 3]; 5] = [[1, 1, 1], [1, 0, 1], [1, 0, 1], [1, 0, 1], [1, 1, 1]];
    pub const ONE: [[u8; 3]; 5] = [[0, 1, 0], [1, 1, 0], [0, 1, 0], [0, 1, 0], [1, 1, 1]];
    pub const TWO: [[u8; 3]; 5] = [[1, 1, 1], [0, 0, 1], [1, 1, 1], [1, 0, 0], [1, 1, 1]];
    pub const THREE: [[u8; 3]; 5] = [[1, 1, 1], [0, 0, 1], [1, 1, 1], [0, 0, 1], [1, 1, 1]];
    pub const FOUR: [[u8; 3]; 5] = [[1, 0, 1], [1, 0, 1], [1, 1, 1], [0, 0, 1], [0, 0, 1]];
    pub const FIVE: [[u8; 3]; 5] = [[1, 1, 1], [1, 0, 0], [1, 1, 1], [0, 0, 1], [1, 1, 1]];
    pub const SIX: [[u8; 3]; 5] = [[1, 1, 1], [1, 0, 0], [1, 1, 1], [1, 0, 1], [1, 1, 1]];
    pub const SEVEN: [[u8; 3]; 5] = [[1, 1, 1], [0, 0, 1], [0, 1, 0], [0, 1, 0], [0, 1, 0]];
    pub const EIGHT: [[u8; 3]; 5] = [[1, 1, 1], [1, 0, 1], [1, 1, 1], [1, 0, 1], [1, 1, 1]];
    pub const NINE: [[u8; 3]; 5] = [[1, 1, 1], [1, 0, 1], [1, 1, 1], [0, 0, 1], [1, 1, 1]];
    pub const PERCENT: [[u8; 3]; 5] = [[1, 0, 1], [0, 0, 1], [0, 1, 0], [1, 0, 0], [1, 0, 1]];

    pub fn get_digit(n: u8) -> &'static [[u8; 3]; 5] {
        match n {
            0 => &ZERO,
            1 => &ONE,
            2 => &TWO,
            3 => &THREE,
            4 => &FOUR,
            5 => &FIVE,
            6 => &SIX,
            7 => &SEVEN,
            8 => &EIGHT,
            9 => &NINE,
            _ => &ZERO,
        }
    }
}

/// Convert 8x13 bitmap to frame data (4 x u32)
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

/// Draw a percentage value (0-100) on the LED matrix bitmap
fn draw_percentage(bitmap: &mut [[u8; 13]; 8], value: u8) {
    // Clear bitmap
    for row in bitmap.iter_mut() {
        for col in row.iter_mut() {
            *col = 0;
        }
    }

    let value = value.min(100);
    let mut x_offset = 0;

    // Draw digits
    if value >= 100 {
        // Three digits: 100%
        for d in [1u8, 0, 0] {
            let digit = digits::get_digit(d);
            for (dy, row) in digit.iter().enumerate() {
                for (dx, &val) in row.iter().enumerate() {
                    if dy + 1 < 8 && dx + x_offset < 13 {
                        bitmap[dy + 1][dx + x_offset] = val;
                    }
                }
            }
            x_offset += 4;
        }
    } else if value >= 10 {
        // Two digits
        let d1 = value / 10;
        let d2 = value % 10;

        for d in [d1, d2] {
            let digit = digits::get_digit(d);
            for (dy, row) in digit.iter().enumerate() {
                for (dx, &val) in row.iter().enumerate() {
                    if dy + 1 < 8 && dx + x_offset < 13 {
                        bitmap[dy + 1][dx + x_offset] = val;
                    }
                }
            }
            x_offset += 4;
        }
    } else {
        // Single digit with leading space
        x_offset = 4;
        let digit = digits::get_digit(value);
        for (dy, row) in digit.iter().enumerate() {
            for (dx, &val) in row.iter().enumerate() {
                if dy + 1 < 8 && dx + x_offset < 13 {
                    bitmap[dy + 1][dx + x_offset] = val;
                }
            }
        }
        x_offset += 4;
    }

    // Draw percent symbol
    let pct = &digits::PERCENT;
    for (dy, row) in pct.iter().enumerate() {
        for (dx, &val) in row.iter().enumerate() {
            if dy + 1 < 8 && dx + x_offset < 13 {
                bitmap[dy + 1][dx + x_offset] = val;
            }
        }
    }
}

/// Set LED matrix to show a level indicator (bar graph)
fn set_level(client: &RpcClientSync, level: u8) -> Result<()> {
    client.call(
        "led_matrix.set_level",
        vec![rmpv::Value::Integer(level.into())],
    )?;
    Ok(())
}

/// Set LED matrix frame
fn set_frame(client: &RpcClientSync, frame: &[u32; 4]) -> Result<()> {
    client.call(
        "led_matrix.set_frame",
        vec![
            rmpv::Value::Integer(frame[0].into()),
            rmpv::Value::Integer(frame[1].into()),
            rmpv::Value::Integer(frame[2].into()),
            rmpv::Value::Integer(frame[3].into()),
        ],
    )?;
    Ok(())
}

/// Set OLED line text
fn set_oled_line(client: &RpcClientSync, line: u8, text: &str) -> Result<()> {
    let method = match line {
        1 => "oled.line1",
        2 => "oled.line2",
        3 => "oled.line3",
        _ => return Ok(()),
    };
    client.call(method, vec![rmpv::Value::String(text.into())])?;
    Ok(())
}

/// Set OLED progress bar
fn set_oled_progress(client: &RpcClientSync, percent: i32) -> Result<()> {
    client.call("oled.progress", vec![rmpv::Value::Integer(percent.into())])?;
    Ok(())
}

/// Clear OLED display
fn clear_oled(client: &RpcClientSync) -> Result<()> {
    client.call("oled.clear", vec![])?;
    Ok(())
}

/// System metrics
struct SystemMetrics {
    cpu_usage: f32,
    memory_used_percent: f32,
    memory_total_gb: f32,
    memory_used_gb: f32,
    uptime_secs: u64,
}

/// Get current system metrics
fn get_system_metrics(sys: &mut System) -> SystemMetrics {
    sys.refresh_all();

    let cpu_usage = sys.global_cpu_usage();

    let total_memory = sys.total_memory() as f32;
    let used_memory = sys.used_memory() as f32;
    let memory_used_percent = if total_memory > 0.0 {
        (used_memory / total_memory) * 100.0
    } else {
        0.0
    };

    SystemMetrics {
        cpu_usage,
        memory_used_percent,
        memory_total_gb: total_memory / (1024.0 * 1024.0 * 1024.0),
        memory_used_gb: used_memory / (1024.0 * 1024.0 * 1024.0),
        uptime_secs: System::uptime(),
    }
}

/// Format uptime as HH:MM:SS
fn format_uptime(secs: u64) -> String {
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;
    format!("{}:{:02}:{:02}", hours, mins, secs)
}

/// Run demo mode
fn run_demo(client: &RpcClientSync, once: bool) -> Result<()> {
    info!("Running demo mode...");

    // Clear displays
    clear_oled(client)?;
    client.call("led_matrix.clear", vec![])?;
    thread::sleep(Duration::from_millis(500));

    loop {
        // Show OLED text demo
        info!("OLED: Showing text lines");
        set_oled_line(client, 1, "DragonWing")?;
        set_oled_line(client, 2, "Display Server")?;
        set_oled_line(client, 3, "Demo Mode")?;
        set_oled_progress(client, -1)?; // Hide progress bar
        thread::sleep(Duration::from_secs(3));

        // Show progress bar demo
        info!("OLED: Progress bar animation");
        set_oled_line(client, 1, "Progress Bar")?;
        set_oled_line(client, 2, "")?;
        set_oled_line(client, 3, "")?;
        for pct in (0..=100).step_by(5) {
            set_oled_progress(client, pct)?;
            thread::sleep(Duration::from_millis(50));
        }
        thread::sleep(Duration::from_secs(1));

        // Show LED matrix icons
        let patterns = [
            ("CPU", &icons::CPU),
            ("Memory", &icons::MEMORY),
            ("OK", &icons::OK),
            ("Warning", &icons::WARNING),
            ("Error", &icons::ERROR),
        ];

        for (name, icon) in &patterns {
            info!("LED Matrix: {}", name);
            set_oled_line(client, 1, "LED Matrix")?;
            set_oled_line(client, 2, name)?;
            set_oled_progress(client, -1)?;

            let frame = bitmap_to_frame(icon);
            set_frame(client, &frame)?;
            thread::sleep(Duration::from_secs(2));
        }

        // Show level meter
        info!("LED Matrix: Level meter");
        set_oled_line(client, 1, "Level Meter")?;
        for level in (0..=100).step_by(10) {
            set_oled_line(client, 2, &format!("{}%", level))?;
            set_level(client, level as u8)?;
            thread::sleep(Duration::from_millis(300));
        }
        thread::sleep(Duration::from_secs(1));

        // Show percentage numbers on LED matrix
        info!("LED Matrix: Percentage display");
        set_oled_line(client, 1, "Percentage")?;
        for pct in [0, 25, 50, 75, 100] {
            set_oled_line(client, 2, &format!("{}%", pct))?;
            let mut bitmap = [[0u8; 13]; 8];
            draw_percentage(&mut bitmap, pct);
            let frame = bitmap_to_frame(&bitmap);
            set_frame(client, &frame)?;
            thread::sleep(Duration::from_secs(1));
        }

        if once {
            info!("Demo complete, exiting");
            break;
        }
    }

    Ok(())
}

/// Main monitoring loop
fn run_monitor(client: &RpcClientSync, args: &Args) -> Result<()> {
    info!("Starting system monitor...");

    let mut sys = System::new_all();
    let mut display_mode = 0; // 0 = CPU on matrix, 1 = Memory on matrix

    // Initial display setup
    clear_oled(client)?;

    loop {
        // Get system metrics
        let metrics = get_system_metrics(&mut sys);

        debug!(
            "CPU: {:.1}%, Memory: {:.1}% ({:.1}/{:.1} GB), Uptime: {}s",
            metrics.cpu_usage,
            metrics.memory_used_percent,
            metrics.memory_used_gb,
            metrics.memory_total_gb,
            metrics.uptime_secs
        );

        // Update OLED display
        // Line 1 (yellow area): Title
        set_oled_line(client, 1, "System Monitor")?;

        // Line 2 (blue area): CPU usage
        let cpu_text = format!("CPU: {:.1}%", metrics.cpu_usage);
        set_oled_line(client, 2, &cpu_text)?;

        // Line 3 (blue area): Memory usage
        let mem_text = format!(
            "MEM: {:.1}G/{:.1}G",
            metrics.memory_used_gb, metrics.memory_total_gb
        );
        set_oled_line(client, 3, &mem_text)?;

        // Progress bar shows CPU or Memory depending on mode
        let progress_value = match display_mode {
            0 => metrics.cpu_usage as i32,
            _ => metrics.memory_used_percent as i32,
        };
        set_oled_progress(client, progress_value.clamp(0, 100))?;

        // Update LED matrix
        match display_mode {
            0 => {
                // Show CPU percentage on LED matrix
                let mut bitmap = [[0u8; 13]; 8];
                draw_percentage(&mut bitmap, metrics.cpu_usage.round() as u8);
                let frame = bitmap_to_frame(&bitmap);
                set_frame(client, &frame)?;
            }
            _ => {
                // Show memory as level bar
                set_level(client, metrics.memory_used_percent.round() as u8)?;
            }
        }

        // Toggle display mode every 5 seconds (every 5 iterations with 1s interval)
        static mut COUNTER: u32 = 0;
        unsafe {
            COUNTER += 1;
            if COUNTER >= 5 {
                COUNTER = 0;
                display_mode = (display_mode + 1) % 2;
                debug!("Switching display mode to {}", display_mode);
            }
        }

        if args.once {
            info!("Single run complete, exiting");
            break;
        }

        thread::sleep(Duration::from_millis(args.interval));
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    info!("System Monitor for Arduino Uno Q Display Server");

    // Connect to RPC server
    info!("Connecting to RPC server at {}...", args.socket);
    let client = RpcClientSync::connect(&args.socket).context("Failed to connect to RPC server")?;

    // Test connection
    match client.call("ping", vec![]) {
        Ok(_) => info!("RPC connection established"),
        Err(e) => {
            error!("Failed to ping MCU: {}", e);
            return Err(e.into());
        }
    }

    // Get version
    match client.call("version", vec![]) {
        Ok(result) => {
            if let Some(version) = result.as_str() {
                info!("Display Server version: {}", version);
            }
        }
        Err(e) => {
            warn!("Failed to get version: {}", e);
        }
    }

    // Run demo mode if requested
    if args.demo {
        return run_demo(&client, args.once);
    }

    // Run main monitoring loop
    run_monitor(&client, &args)
}
