// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Weather Display for Arduino Uno Q
//
// Fetches weather data from Open-Meteo API and displays temperature
// and weather conditions on the LED matrix via RPC.

use anyhow::{Context, Result};
use clap::Parser;
use dragonwing_rpc::RpcClientSync;
use log::{debug, error, info, warn};
use serde::Deserialize;
use std::thread;
use std::time::Duration;

/// Weather display CLI arguments
#[derive(Parser, Debug)]
#[command(name = "weather-display")]
#[command(about = "Display weather on Arduino LED matrix")]
struct Args {
    /// RPC socket path
    #[arg(short, long, default_value = "/tmp/arduino-spi-router.sock")]
    socket: String,

    /// Latitude for weather location
    #[arg(long, default_value_t = 37.7749)]
    lat: f64,

    /// Longitude for weather location
    #[arg(long, default_value_t = -122.4194)]
    lon: f64,

    /// Update interval in seconds
    #[arg(short, long, default_value_t = 300)]
    interval: u64,

    /// Run once and exit
    #[arg(short, long)]
    once: bool,

    /// Demo mode (cycle through patterns without fetching weather)
    #[arg(short, long)]
    demo: bool,
}

/// Open-Meteo API response
#[derive(Debug, Deserialize)]
struct WeatherResponse {
    current: CurrentWeather,
}

#[derive(Debug, Deserialize)]
struct CurrentWeather {
    temperature_2m: f64,
    weather_code: u32,
    wind_speed_10m: f64,
}

/// Weather condition codes (WMO)
#[derive(Debug, Clone, Copy)]
enum WeatherCondition {
    Clear,
    PartlyCloudy,
    Cloudy,
    Fog,
    Drizzle,
    Rain,
    Snow,
    Thunderstorm,
    Unknown,
}

impl From<u32> for WeatherCondition {
    fn from(code: u32) -> Self {
        match code {
            0 => WeatherCondition::Clear,
            1..=3 => WeatherCondition::PartlyCloudy,
            45 | 48 => WeatherCondition::Fog,
            51..=55 => WeatherCondition::Drizzle,
            56..=57 => WeatherCondition::Drizzle, // Freezing drizzle
            61..=65 => WeatherCondition::Rain,
            66..=67 => WeatherCondition::Rain, // Freezing rain
            71..=77 => WeatherCondition::Snow,
            80..=82 => WeatherCondition::Rain, // Rain showers
            85..=86 => WeatherCondition::Snow, // Snow showers
            95..=99 => WeatherCondition::Thunderstorm,
            _ => WeatherCondition::Unknown,
        }
    }
}

/// 8x13 LED matrix patterns for weather icons
mod icons {
    // Sun icon (clear weather)
    pub const SUN: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0],
        [1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1],
        [0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0],
        [0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0],
        [0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
    ];

    // Cloud icon (partly cloudy)
    pub const CLOUD: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
        [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ];

    // Rain icon
    pub const RAIN: [[u8; 13]; 8] = [
        [0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0],
        [0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0],
        [0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0],
    ];

    // Snow icon
    pub const SNOW: [[u8; 13]; 8] = [
        [0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0],
        [0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0],
    ];

    // Thunder icon
    pub const THUNDER: [[u8; 13]; 8] = [
        [0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
    ];

    // Fog icon
    pub const FOG: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
    ];
}

/// 3x5 digit font for displaying temperature
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
    pub const MINUS: [[u8; 3]; 5] = [[0, 0, 0], [0, 0, 0], [1, 1, 1], [0, 0, 0], [0, 0, 0]];
    pub const DEGREE: [[u8; 3]; 5] = [[0, 1, 0], [1, 0, 1], [0, 1, 0], [0, 0, 0], [0, 0, 0]];

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

/// Draw temperature on bitmap
fn draw_temperature(bitmap: &mut [[u8; 13]; 8], temp: i32) {
    // Clear bitmap
    for row in bitmap.iter_mut() {
        for col in row.iter_mut() {
            *col = 0;
        }
    }

    let mut x_offset = 0;

    // Draw minus sign if negative
    if temp < 0 {
        let digit = &digits::MINUS;
        for (dy, row) in digit.iter().enumerate() {
            for (dx, &val) in row.iter().enumerate() {
                if dy + 1 < 8 && dx + x_offset < 13 {
                    bitmap[dy + 1][dx + x_offset] = val;
                }
            }
        }
        x_offset += 4;
    }

    let abs_temp = temp.abs() as u32;

    // Draw digits
    if abs_temp >= 100 {
        // Three digits
        let d1 = ((abs_temp / 100) % 10) as u8;
        let d2 = ((abs_temp / 10) % 10) as u8;
        let d3 = (abs_temp % 10) as u8;

        for d in [d1, d2, d3] {
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
    } else if abs_temp >= 10 {
        // Two digits
        let d1 = ((abs_temp / 10) % 10) as u8;
        let d2 = (abs_temp % 10) as u8;

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
        // Single digit
        let digit = digits::get_digit(abs_temp as u8);
        for (dy, row) in digit.iter().enumerate() {
            for (dx, &val) in row.iter().enumerate() {
                if dy + 1 < 8 && dx + x_offset < 13 {
                    bitmap[dy + 1][dx + x_offset] = val;
                }
            }
        }
        x_offset += 4;
    }

    // Draw degree symbol
    let degree = &digits::DEGREE;
    for (dy, row) in degree.iter().enumerate() {
        for (dx, &val) in row.iter().enumerate() {
            if dy + 1 < 8 && dx + x_offset < 13 {
                bitmap[dy + 1][dx + x_offset] = val;
            }
        }
    }
}

/// Fetch weather from Open-Meteo API
fn fetch_weather(lat: f64, lon: f64) -> Result<(f64, WeatherCondition)> {
    let url = format!(
        "https://api.open-meteo.com/v1/forecast?latitude={}&longitude={}&current=temperature_2m,weather_code,wind_speed_10m",
        lat, lon
    );

    debug!("Fetching weather from: {}", url);

    let response: WeatherResponse = reqwest::blocking::get(&url)
        .context("Failed to fetch weather")?
        .json()
        .context("Failed to parse weather response")?;

    let condition = WeatherCondition::from(response.current.weather_code);

    Ok((response.current.temperature_2m, condition))
}

/// Display weather icon on LED matrix
fn display_icon(client: &RpcClientSync, condition: WeatherCondition) -> Result<()> {
    let icon = match condition {
        WeatherCondition::Clear => &icons::SUN,
        WeatherCondition::PartlyCloudy | WeatherCondition::Cloudy => &icons::CLOUD,
        WeatherCondition::Fog => &icons::FOG,
        WeatherCondition::Drizzle | WeatherCondition::Rain => &icons::RAIN,
        WeatherCondition::Snow => &icons::SNOW,
        WeatherCondition::Thunderstorm => &icons::THUNDER,
        WeatherCondition::Unknown => &icons::CLOUD,
    };

    let frame = bitmap_to_frame(icon);

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

/// Display temperature on LED matrix
fn display_temperature(client: &RpcClientSync, temp: f64) -> Result<()> {
    let mut bitmap = [[0u8; 13]; 8];
    draw_temperature(&mut bitmap, temp.round() as i32);

    let frame = bitmap_to_frame(&bitmap);

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

/// Run demo mode
fn run_demo(client: &RpcClientSync, once: bool) -> Result<()> {
    info!("Running demo mode...");

    let patterns = [
        ("Sun", &icons::SUN),
        ("Cloud", &icons::CLOUD),
        ("Rain", &icons::RAIN),
        ("Snow", &icons::SNOW),
        ("Thunder", &icons::THUNDER),
        ("Fog", &icons::FOG),
    ];

    loop {
        // Show icons
        for (name, icon) in &patterns {
            info!("Showing: {}", name);
            let frame = bitmap_to_frame(icon);
            client.call(
                "led_matrix.set_frame",
                vec![
                    rmpv::Value::Integer(frame[0].into()),
                    rmpv::Value::Integer(frame[1].into()),
                    rmpv::Value::Integer(frame[2].into()),
                    rmpv::Value::Integer(frame[3].into()),
                ],
            )?;
            thread::sleep(Duration::from_secs(2));
        }

        // Show some temperatures
        for temp in [-10, 0, 15, 25, 72, 100].iter() {
            info!("Showing temperature: {}°", temp);
            let mut bitmap = [[0u8; 13]; 8];
            draw_temperature(&mut bitmap, *temp);
            let frame = bitmap_to_frame(&bitmap);
            client.call(
                "led_matrix.set_frame",
                vec![
                    rmpv::Value::Integer(frame[0].into()),
                    rmpv::Value::Integer(frame[1].into()),
                    rmpv::Value::Integer(frame[2].into()),
                    rmpv::Value::Integer(frame[3].into()),
                ],
            )?;
            thread::sleep(Duration::from_secs(2));
        }

        if once {
            info!("Demo complete, exiting");
            break;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("Weather Display starting...");
    info!("Location: ({}, {})", args.lat, args.lon);

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

    // Run demo mode if requested
    if args.demo {
        return run_demo(&client, args.once);
    }

    // Main loop
    loop {
        // Fetch weather
        match fetch_weather(args.lat, args.lon) {
            Ok((temp, condition)) => {
                info!("Weather: {:.1}°C, {:?}", temp, condition);

                // Display weather icon
                if let Err(e) = display_icon(&client, condition) {
                    warn!("Failed to display icon: {}", e);
                }
                thread::sleep(Duration::from_secs(3));

                // Display temperature
                if let Err(e) = display_temperature(&client, temp) {
                    warn!("Failed to display temperature: {}", e);
                }
            }
            Err(e) => {
                warn!("Failed to fetch weather: {}", e);
                // Show error pattern (all LEDs on briefly)
                let _ = client.call("led_matrix.fill", vec![]);
                thread::sleep(Duration::from_millis(500));
                let _ = client.call("led_matrix.clear", vec![]);
            }
        }

        if args.once {
            info!("Single run complete, exiting");
            break;
        }

        // Wait for next update
        info!("Next update in {} seconds", args.interval);
        thread::sleep(Duration::from_secs(args.interval));
    }

    Ok(())
}
