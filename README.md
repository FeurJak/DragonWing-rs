```rust
ooo.                                    o      o  o
8  `8.                                  8      8
8   `8 oPYo. .oPYo. .oPYo. .oPYo. odYo. 8      8 o8 odYo. .oPYo.
8    8 8  `' .oooo8 8    8 8    8 8' `8 8  db  8  8 8' `8 8    8
8   .P 8     8    8 8    8 8    8 8   8 `b.PY.d'  8 8   8 8    8
8ooo'  8     `YooP8 `YooP8 `YooP' 8   8  `8  8'   8 8   8 `YooP8
.....::..:::::.....::....8 :.....:..::..::..:..:::....::..:....8
::::::::::::::::::::::ooP'.:::::::::::::::::::::::::::::::::ooP'.
::::::::::::::::::::::...:::::::::::::::::::::::::::::::::::...::
```

# DragonWing-rs

> Rust libraries for the Arduino Uno Q platform featuring post-quantum cryptography, anonymous credentials, and secure storage.

The **Arduino Uno Q** is a dual-processor board:

- **STM32U585 MCU** - ARM Cortex-M33 running Zephyr RTOS (no_std Rust)
- **QRB2210 MPU** - Qualcomm processor running Linux (std Rust)

## Features

- **Post-Quantum Cryptography**: ML-KEM 768, ML-DSA 65, X-Wing hybrid KEM
- **Classical Cryptography**: Ed25519, X25519, XChaCha20-Poly1305
- **Anonymous Credentials**: SAGA (BBS-style MAC scheme)
- **Secure Storage**: PSA-compliant encrypted storage
- **Cross-Platform RPC**: MessagePack-RPC over SPI

## Quick Start

```bash
# Clone the repository
git clone https://github.com/AnomalyCo/DragonWing-rs.git
cd DragonWing-rs

# Set up board credentials
cp .env.example .env
# Edit .env with your board's IP and password

# Build Docker image (for MCU builds)
make docker-build

# Build and flash MCU firmware
make build-mcu DEMO=pqc-demo
source .env && make flash

# Build and deploy MPU client
make build-mpu APP=pqc-client
source .env && make deploy APP=pqc-client

# Run a demo
source .env && make ssh
./spi-router &
./pqc-client --xwing-demo
```

## Project Structure

```
DragonWing-rs/
├── crates/                      # Reusable libraries
│   ├── dragonwing-crypto/       # PQ & classical cryptography
│   ├── dragonwing-led-matrix/   # 8x13 LED matrix driver
│   ├── dragonwing-rpc/          # Cross-platform RPC
│   ├── dragonwing-spi/          # SPI communication
│   ├── dragonwing-spi-router/   # SPI router daemon
│   └── dragonwing-zcbor/        # CBOR/COSE encoding
├── demos/
│   ├── mcu/                     # MCU firmware demos
│   │   ├── pqc-demo/            # Post-quantum showcase
│   │   ├── led-matrix-demo/     # LED animations
│   │   └── ...
│   └── mpu/                     # Linux application demos
│       ├── pqc-client/          # PQC demo controller
│       ├── weather-display/     # Weather on LED matrix
│       └── ...
├── docs/                        # Documentation
├── docker/                      # Zephyr build environment
└── config/                      # Board configurations
```

## Available Demos

### MCU Firmware

| Demo              | Description                                                             |
| ----------------- | ----------------------------------------------------------------------- |
| `pqc-demo`        | Full cryptography showcase (ML-KEM, X-Wing, SAGA, Ed25519, PSA storage) |
| `led-matrix-demo` | LED matrix animations and patterns                                      |
| `mlkem-demo`      | ML-KEM 768 key encapsulation                                            |
| `rpc-server`      | RPC server with LED matrix control                                      |

### MPU Applications

| App               | Description                             |
| ----------------- | --------------------------------------- |
| `pqc-client`      | Control MCU demos via RPC               |
| `mlkem-client`    | ML-KEM key exchange client              |
| `weather-display` | Fetch weather and display on LED matrix |
| `spi-router`      | SPI router daemon (required for RPC)    |

### Demo Commands

```bash
# After flashing pqc-demo and starting spi-router:

./pqc-client --psa-demo           # PSA secure storage
./pqc-client --xwing-demo         # X-Wing hybrid PQ KEM
./pqc-client --saga-demo          # SAGA anonymous credentials
./pqc-client --saga-xwing-demo    # Combined credential + key exchange
./pqc-client --persistence-demo   # Persistent credential storage
./pqc-client --ed25519-demo       # Ed25519 signatures (fast)
./pqc-client --mlkem-demo         # ML-KEM 768 (medium)
./pqc-client --mldsa-demo         # ML-DSA 65 (slow)
```

## Cryptographic Algorithms

| Algorithm          | Type                   | Standard   | Performance (MCU) |
| ------------------ | ---------------------- | ---------- | ----------------- |
| ML-KEM 768         | Post-Quantum KEM       | FIPS 203   | ~60ms             |
| ML-DSA 65          | Post-Quantum Signature | FIPS 204   | ~30-60s           |
| X-Wing             | Hybrid PQ KEM          | IETF Draft | ~100ms            |
| Ed25519            | Signature              | RFC 8032   | <10ms             |
| X25519             | Key Agreement          | RFC 7748   | <10ms             |
| XChaCha20-Poly1305 | AEAD                   | RFC 8439+  | <5ms              |
| SAGA               | Anonymous Credentials  | Research   | ~100ms            |

## Documentation

- [Getting Started](docs/GETTING_STARTED.md) - Setup and first steps
- [Architecture](docs/ARCHITECTURE.md) - System design and data flow
- [Cryptography](docs/CRYPTOGRAPHY.md) - Algorithm details and usage

## Building

### Prerequisites

- **Rust**: `rustup` with `aarch64-unknown-linux-gnu` target
- **Docker**: For MCU builds with Zephyr SDK
- **cargo-zigbuild**: For MPU cross-compilation

### MCU (Zephyr)

```bash
make docker-build              # Build Docker image (once)
make build-mcu DEMO=pqc-demo   # Build firmware
make flash                     # Flash via OpenOCD
```

### MPU (Linux)

```bash
make build-mpu APP=pqc-client  # Cross-compile for aarch64
make deploy APP=pqc-client     # Deploy via SSH
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
