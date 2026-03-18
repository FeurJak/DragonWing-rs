# dragonwing-spi-router

SPI-based RPC router for DragonWing that runs on the QRB2210 Linux MPU.

## Platform

**MPU-only** — This crate targets Linux (aarch64) on the QRB2210 processor. It is not intended for MCU or no_std environments.

## Overview

The SPI router bridges communication between:
- Linux user-space applications (via Unix domain socket)
- The STM32U585 MCU (via SPI)

It implements a MessagePack-RPC protocol compatible with the MCU firmware.

## Usage

```bash
# Run with default settings
spi-router

# Custom SPI device and speed
spi-router --spi-device /dev/spidev0.0 --spi-speed 1000000

# Test mode (sends ping messages to MCU)
spi-router --test-mode --verbose
```

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `--spi-device` | `/dev/spidev0.0` | SPI device path |
| `--spi-speed` | `1000000` | SPI clock speed in Hz |
| `--unix-socket` | `/var/run/dragonwing-spi-router.sock` | Unix socket path |
| `--poll-interval` | `10` | Polling interval in ms |
| `--verbose` | false | Enable debug logging |
| `--test-mode` | false | Send test RPC messages |

## License

Apache-2.0 OR MIT
