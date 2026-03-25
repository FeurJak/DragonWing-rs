# System Monitor for Arduino Uno Q Display Server

A Linux application that reads system metrics and displays them on the Arduino Uno Q's displays via RPC.

## Features

- **SSD1306 OLED Display** (128x64, yellow top / blue bottom):
    - Line 1 (yellow): Title
    - Line 2 (blue): CPU usage
    - Line 3 (blue): Memory usage
    - Progress bar: Alternates between CPU and memory

- **LED Matrix** (8x13, 104 LEDs):
    - CPU percentage display
    - Memory level bar graph
    - Status icons

## Requirements

1. **Arduino Uno Q** with `display-server` firmware flashed on MCU
2. **SPI Router** running on the MPU (`arduino-spi-router`)
3. **Hardware**:
    - SSD1306 OLED connected via I2C (Wire bus: SDA=D20, SCL=D21)
    - LED Matrix connected via charlieplexing

## Building

```bash
# Cross-compile for QRB2210 (aarch64)
cargo build --release --target aarch64-unknown-linux-gnu

# Or build natively on the device
cargo build --release
```

## Usage

```bash
# Run with default settings
./system-monitor

# Demo mode (cycle through patterns)
./system-monitor --demo

# Custom update interval (500ms)
./system-monitor --interval 500

# Run once and exit
./system-monitor --once

# Verbose output
./system-monitor --verbose
```

## RPC Methods Used

### OLED Display

- `oled.clear` - Clear the display
- `oled.line1 <text>` - Set line 1 (yellow area, centered)
- `oled.line2 <text>` - Set line 2 (blue area)
- `oled.line3 <text>` - Set line 3 (blue area)
- `oled.progress <percent>` - Show progress bar (-1 to hide)

### LED Matrix

- `led_matrix.clear` - Clear the matrix
- `led_matrix.fill` - Fill all LEDs
- `led_matrix.set_frame <w0> <w1> <w2> <w3>` - Set frame data (4 x u32)
- `led_matrix.set_level <percent>` - Show level bar (0-100)

## Architecture

```
┌─────────────────┐          ┌─────────────────┐
│  Linux (MPU)    │   SPI    │   MCU (Zephyr)  │
│                 │◄────────►│                 │
│ system-monitor  │          │ display-server  │
│       ↓         │          │       ↓         │
│ RpcClientSync   │          │   RpcServer     │
│       ↓         │          │       ↓         │
│ spi-router.sock │          │ ┌─────┴─────┐   │
└─────────────────┘          │ │           │   │
                             │ I2C       GPIO  │
                             │ ↓           ↓   │
                             │ SSD1306   LED   │
                             │ OLED    Matrix  │
                             └─────────────────┘
```
