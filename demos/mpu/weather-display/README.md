# Weather Display

A Linux application that fetches weather data and displays it on the Arduino Uno Q's LED matrix via RPC.

## Features

- Fetches real-time weather data from [Open-Meteo API](https://open-meteo.com/)
- Displays weather icons (sun, cloud, rain, snow, thunder, fog)
- Displays temperature with custom 3x5 digit font
- Alternates between icon and temperature display
- Configurable location and update interval
- Demo mode for testing without internet

## Architecture

```
┌─────────────────┐     HTTP     ┌──────────────────┐
│  Open-Meteo API │◄─────────────│  weather-display │
└─────────────────┘              │  (Linux app)     │
                                 └────────┬─────────┘
                                          │ Unix Socket
                                 ┌────────▼─────────┐
                                 │  spi-router      │
                                 │  (Linux daemon)  │
                                 └────────┬─────────┘
                                          │ SPI
                                 ┌────────▼─────────┐
                                 │  rpc-server      │
                                 │  (MCU firmware)  │
                                 └────────┬─────────┘
                                          │
                                 ┌────────▼─────────┐
                                 │  8x13 LED Matrix │
                                 └──────────────────┘
```

## Prerequisites

### 1. MCU Firmware

Flash the `rpc-server` firmware to the STM32U585 MCU:

```bash
make build APP=rpc-server
make flash
```

### 2. SPI Router (Linux MPU)

The `arduino-spi-router` daemon must be running on the Linux MPU. It bridges communication between Linux applications and the MCU over SPI.

#### First-time setup

Run this single command to build, deploy, and install as a systemd service:

```bash
make setup-spi-router
```

This will:
- Build spi-router for aarch64
- Deploy to `/home/arduino/spi-router` on the board
- Install the systemd service
- Enable auto-start on boot
- Start the service

#### Verify it's running

```bash
# Check service status
make ssh-board
# Then run: systemctl status arduino-spi-router

# Or directly via SSH
ssh arduino@<board-ip> "systemctl status arduino-spi-router"
```

#### Manual setup (alternative)

If you prefer step-by-step:

```bash
# 1. Build for aarch64
make build-linux APP=spi-router

# 2. Deploy binary to board
make deploy-linux APP=spi-router

# 3. Install and enable systemd service
make install-spi-router
```

#### After reboot

The spi-router will auto-start on boot. Verify with:

```bash
ssh arduino@<board-ip> "systemctl is-active arduino-spi-router"
# Should print: active
```

### 3. Build Tools (on your development machine)

- Rust toolchain
- cargo-zigbuild: `cargo install cargo-zigbuild`
- sshpass: `brew install hudochenkov/sshpass/sshpass`

## Building

From the repository root:

```bash
# Build for aarch64 Linux
make build-linux APP=weather-display
```

Or manually:

```bash
cd examples/weather-display
cargo zigbuild --target aarch64-unknown-linux-gnu --release
```

## Deploying

```bash
# Deploy to the board
make deploy-linux APP=weather-display
```

Or manually:

```bash
scp target/aarch64-unknown-linux-gnu/release/weather-display arduino@<board-ip>:/home/arduino/
```

## Running

### Single Update

```bash
make run-linux APP=weather-display
# or
ssh arduino@<board-ip> "/home/arduino/weather-display --once"
```

### Demo Mode (no internet required)

```bash
make run-linux APP=weather-display ARGS='--demo --once'
```

### Continuous Updates

```bash
ssh arduino@<board-ip> "/home/arduino/weather-display --interval 300"
```

## Command Line Options

```
Usage: weather-display [OPTIONS]

Options:
  -s, --socket <SOCKET>      RPC socket path [default: /tmp/arduino-spi-router.sock]
      --lat <LAT>            Latitude for weather location [default: 37.7749]
      --lon <LON>            Longitude for weather location [default: -122.4194]
  -i, --interval <INTERVAL>  Update interval in seconds [default: 300]
  -o, --once                 Run once and exit
  -d, --demo                 Demo mode (cycle through patterns without fetching weather)
  -h, --help                 Print help
```

## Example: Set Location to New York

```bash
ssh arduino@<board-ip> "/home/arduino/weather-display --lat 40.7128 --lon -74.0060 --once"
```

## Weather Icons

The app displays 8x13 pixel icons for different weather conditions:

| Condition     | WMO Codes    | Icon    |
| ------------- | ------------ | ------- |
| Clear         | 0            | Sun     |
| Partly Cloudy | 1-3          | Cloud   |
| Fog           | 45, 48       | Fog     |
| Drizzle       | 51-57        | Rain    |
| Rain          | 61-67, 80-82 | Rain    |
| Snow          | 71-77, 85-86 | Snow    |
| Thunderstorm  | 95-99        | Thunder |

## Troubleshooting

### "Connection refused" error

The SPI router may not be running. Check and start it:

```bash
# Check status
ssh arduino@<board-ip> "systemctl status arduino-spi-router"

# Start if not running
ssh arduino@<board-ip> "sudo systemctl start arduino-spi-router"

# If service doesn't exist, install it
make install-spi-router
```

### "Permission denied" on socket

The systemd service should set permissions automatically. If not:

```bash
ssh arduino@<board-ip> "sudo chmod 666 /tmp/arduino-spi-router.sock"
```

To fix permanently, reinstall the service:

```bash
make install-spi-router
```

### SPI router not starting on boot

Enable the systemd service:

```bash
ssh arduino@<board-ip> "sudo systemctl enable arduino-spi-router"
```

Or reinstall:

```bash
make install-spi-router
```

### No display on LED matrix

Ensure the `rpc-server` firmware is flashed to the MCU:

```bash
make build APP=rpc-server
make flash
```

### Network errors

Check that the board has internet connectivity:

```bash
ssh arduino@<board-ip> "curl -s https://api.open-meteo.com/v1/forecast?latitude=0&longitude=0&current=temperature_2m"
```

### View spi-router logs

```bash
ssh arduino@<board-ip> "journalctl -u arduino-spi-router -f"
```

## License

Apache-2.0 OR MIT
