# pq-proxy MPU Demo

WebSocket-to-SPI proxy for PQ-Ratchet encrypted data streams.

## Overview

This application runs on the Arduino Uno Q's MPU (Linux) and bridges WebSocket
connections from the Secure-Relayer to the MCU via SPI. **It cannot decrypt the
data** - it simply forwards encrypted chunks.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  pq-proxy (this demo)                                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐         ┌─────────────────────────┐    │
│  │  WebSocket      │         │  SPI Controller         │    │
│  │  Server         │────────►│  /dev/spidev0.0         │    │
│  │  :8080          │         │  1 MHz clock            │    │
│  └─────────────────┘         └─────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
           ▲                              │
           │ WebSocket                    │ SPI
           │ (binary frames)              ▼
    Secure-Relayer                   MCU (TrustZone)
```

## Building

```bash
# Cross-compile for aarch64 (from host)
cargo build --release -p pq-proxy --target aarch64-unknown-linux-gnu

# Or with cargo-zigbuild
cargo zigbuild --release -p pq-proxy --target aarch64-unknown-linux-gnu
```

## Deployment

```bash
# Copy to board
scp target/aarch64-unknown-linux-gnu/release/pq-proxy arduino@192.168.1.199:~/

# SSH to board and run
ssh arduino@192.168.1.199
./pq-proxy --listen 0.0.0.0:8080 --spi-device /dev/spidev0.0
```

## Usage

```
pq-proxy [OPTIONS]

Options:
  -l, --listen <ADDR>       WebSocket listen address [default: 0.0.0.0:8080]
  -s, --spi-device <PATH>   SPI device path [default: /dev/spidev0.0]
  -c, --spi-speed <HZ>      SPI clock speed [default: 1000000]
      --mock-spi            Use mock SPI (for testing)
  -v, --verbose             Enable verbose logging
  -h, --help                Print help
```

## Testing

### With Mock SPI (no hardware)

```bash
# Run with mock SPI
cargo run -p pq-proxy -- --mock-spi --verbose

# Test from another terminal
cargo run -p pq-relayer-demo -- --url ws://localhost:8080 --handshake
```

### With Real Hardware

```bash
# On the Arduino Uno Q
./pq-proxy --listen 0.0.0.0:8080 --spi-device /dev/spidev0.0 --verbose

# From host machine
cargo run -p pq-relayer-demo -- --url ws://192.168.1.199:8080 --handshake
```

## Protocol

The proxy forwards frames bidirectionally without modification:

### WebSocket → SPI (Relayer to MCU)

1. Receive binary WebSocket message
2. Forward directly to SPI as-is
3. Wait for SPI response
4. Forward response back via WebSocket

### Frame Format

Frames are passed through unchanged. See `secure-access` demo for frame format details.

## Security Notes

- This proxy **cannot read plaintext** - all data is end-to-end encrypted
- Even with root access on the MPU, an attacker cannot decrypt the stream
- The proxy is intentionally simple to minimize attack surface

## Dependencies

- `tokio` - Async runtime
- `tokio-tungstenite` - WebSocket server
- `dragonwing-spi` (optional) - SPI communication (feature: `spi`)
- `clap` - Command line parsing
- `log` / `env_logger` - Logging

## License

Licensed under Apache-2.0 OR MIT.
