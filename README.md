```
 ██████████
▒▒███▒▒▒▒███
 ▒███   ▒▒███ ████████   ██████    ███████  ██████  ████████
 ▒███    ▒███▒▒███▒▒███ ▒▒▒▒▒███  ███▒▒███ ███▒▒███▒▒███▒▒███
 ▒███    ▒███ ▒███ ▒▒▒   ███████ ▒███ ▒███▒███ ▒███ ▒███ ▒███
 ▒███    ███  ▒███      ███▒▒███ ▒███ ▒███▒███ ▒███ ▒███ ▒███
 ██████████   █████    ▒▒████████▒▒███████▒▒██████  ████ █████
▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒      ▒▒▒▒▒▒▒▒  ▒▒▒▒▒███ ▒▒▒▒▒▒  ▒▒▒▒ ▒▒▒▒▒
                                  ███ ▒███
                                 ▒▒██████
                                  ▒▒▒▒▒▒
 █████   ███   █████  ███
▒▒███   ▒███  ▒▒███  ▒▒▒
 ▒███   ▒███   ▒███  ████  ████████    ███████            ████████   █████
 ▒███   ▒███   ▒███ ▒▒███ ▒▒███▒▒███  ███▒▒███ ██████████▒▒███▒▒███ ███▒▒
 ▒▒███  █████  ███   ▒███  ▒███ ▒███ ▒███ ▒███▒▒▒▒▒▒▒▒▒▒  ▒███ ▒▒▒ ▒▒█████
  ▒▒▒█████▒█████▒    ▒███  ▒███ ▒███ ▒███ ▒███            ▒███      ▒▒▒▒███
    ▒▒███ ▒▒███      █████ ████ █████▒▒███████            █████     ██████
     ▒▒▒   ▒▒▒      ▒▒▒▒▒ ▒▒▒▒ ▒▒▒▒▒  ▒▒▒▒▒███           ▒▒▒▒▒     ▒▒▒▒▒▒
                                      ███ ▒███
                                     ▒▒██████
                                      ▒▒▒▒▒▒


Rust libraries for the Arduino Uno Q platform
featuring:

* Post-Quantum Cryptography
* Anonymous credentials
* Secure storage
* Phone integration via Arduino IoT Companion App
```

## Features

- **Post-Quantum Cryptography**: ML-KEM 768, ML-DSA 65, X-Wing hybrid KEM
- **Classical Cryptography**: Ed25519, X25519, XChaCha20-Poly1305
- **Anonymous Credentials**: SAGA (BBS-style MAC scheme)
- **Secure Storage**: PSA-compliant encrypted storage
- **Cross-Platform RPC**: MessagePack-RPC over SPI
- **Phone Integration**: Stream video from phones via Arduino IoT Companion App

## Quick Start

### If Firmware is Already Flashed

If your board already has MCU firmware flashed (e.g., from previous development):

```bash
# Set up board credentials
cp .env.example .env
# Edit .env with your board's IP and password

# Run a demo directly (no build required)
source .env && make run DEMO=pqc/psa
```

### Full Build from Scratch

If you need to build and flash everything:

```bash
# Clone the repository
git clone https://github.com/AnomalyCo/DragonWing-rs.git
cd DragonWing-rs

# Set up board credentials
cp .env.example .env
# Edit .env with your board's IP and password

# Build Docker image (for MCU builds) - first time only
make docker-build

# Build and flash MCU firmware
make build-mcu DEMO=pqc-demo
source .env && make flash

# Build and deploy MPU client
make build-mpu APP=pqc-client
source .env && make deploy APP=pqc-client

# Run a demo
source .env && make run DEMO=pqc/psa
```

### Make Commands

| Command                   | Description                                  |
| ------------------------- | -------------------------------------------- |
| `make run DEMO=pqc/psa`   | Run demo on **already flashed** firmware     |
| `make demo DEMO=pqc/psa`  | Full workflow: build, flash, deploy, and run |
| `make build-mcu DEMO=...` | Build MCU firmware only (requires Docker)    |
| `make flash`              | Flash firmware to board                      |
| `make build-mpu APP=...`  | Build MPU application                        |
| `make deploy APP=...`     | Deploy MPU app to board                      |

## Project Structure

```
DragonWing-rs/
├── crates/                      # Reusable libraries
│   ├── dragonwing-crypto/       # PQ & classical cryptography + PQ-Ratchet
│   ├── dragonwing-secure-relayer/ # Secure data relay (macOS → Arduino)
│   ├── dragonwing-led-matrix/   # 8x13 LED matrix driver
│   ├── dragonwing-rpc/          # Cross-platform RPC
│   ├── dragonwing-spi/          # SPI communication
│   ├── dragonwing-spi-router/   # SPI router daemon
│   └── dragonwing-zcbor/        # CBOR/COSE encoding
├── demos/
│   ├── mcu/                     # MCU firmware demos (Zephyr + Rust)
│   │   ├── secure-access/       # PQ-Ratchet secure data receiver
│   │   ├── pqc-demo/            # Post-quantum showcase
│   │   ├── led-matrix-demo/     # LED animations
│   │   └── ...
│   ├── mpu/                     # Linux application demos (aarch64)
│   │   ├── pq-proxy/            # WebSocket→SPI encrypted proxy
│   │   ├── pqc-client/          # PQC demo controller
│   │   ├── weather-display/     # Weather on LED matrix
│   │   └── ...
│   └── host/                    # Host machine demos (macOS/Linux x86_64)
│       └── pq-relayer-demo/     # Test client for secure-relayer
├── docs/                        # Documentation
├── docker/                      # Zephyr build environment
└── config/                      # Board configurations
```

## Available Demos

### MCU Firmware

| Demo              | Description                                                             |
| ----------------- | ----------------------------------------------------------------------- |
| `secure-access`   | **PQ-Ratchet receiver** - Decrypts streaming data in TrustZone          |
| `pqc-demo`        | Full cryptography showcase (ML-KEM, X-Wing, SAGA, Ed25519, PSA storage) |
| `led-matrix-demo` | LED matrix animations and patterns                                      |
| `mlkem-demo`      | ML-KEM 768 key encapsulation                                            |
| `rpc-server`      | RPC server with LED matrix control                                      |

### MPU Applications

| App               | Description                                         |
| ----------------- | --------------------------------------------------- |
| `pq-proxy`        | **WebSocket→SPI proxy** - Forwards encrypted frames |
| `pqc-client`      | Control MCU demos via RPC                           |
| `mlkem-client`    | ML-KEM key exchange client                          |
| `weather-display` | Fetch weather and display on LED matrix             |
| `spi-router`      | SPI router daemon (required for RPC)                |

### Host Applications

| App               | Description                                            |
| ----------------- | ------------------------------------------------------ |
| `pq-relayer-demo` | Test client for secure-relayer handshake and streaming |

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

## Secure Data Streaming (PQ-Ratchet)

Stream encrypted data from phones to the Arduino Uno Q with **post-quantum forward secrecy**. The MCU decrypts data in TrustZone - the MPU (Linux) never sees plaintext.

### Architecture

```
Phone (IoT App)                    Secure-Relayer (macOS)           Arduino Uno Q
     │                                    │                              │
     │  BPP encrypted frames              │                              │
     ├───────────────────────────────────►│                              │
     │                                    │  PQ-Ratchet re-encrypted     │
     │                                    ├─────────────────────────────►│
     │                                    │                         MPU (Linux)
     │                                    │                              │ SPI
     │                                    │                         MCU (TrustZone)
     │                                    │                              │ Decrypt
```

### Quick Start

```bash
# 1. Build and flash MCU firmware
make build-mcu DEMO=secure-access
make flash

# 2. Deploy proxy to MPU (on the board)
cargo build --release -p pq-proxy --target aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/pq-proxy arduino@192.168.1.199:~/

# 3. Start proxy on MPU
ssh arduino@192.168.1.199 "./pq-proxy --listen 0.0.0.0:8080"

# 4. Test from host
cargo run -p pq-relayer-demo -- --url ws://192.168.1.199:8080 --handshake
```

### Security Model

| Component              | Trust Level   | Has Keys?                        |
| ---------------------- | ------------- | -------------------------------- |
| Phone (IoT App)        | Untrusted     | BPP session key only             |
| Secure-Relayer (macOS) | Trusted       | PQ-Ratchet keys (Secure Enclave) |
| MPU (Linux)            | **Untrusted** | **None** - encrypted proxy only  |
| MCU (TrustZone)        | Trusted       | PQ-Ratchet keys (ITS)            |

### Protocol Details

The `dragonwing-secure-relayer` crate implements **PQ-Ratchet**, a post-quantum Double Ratchet protocol:

| Feature           | Description                                           |
| ----------------- | ----------------------------------------------------- |
| KEM               | X-Wing (ML-KEM-768 + X25519 hybrid)                   |
| AEAD              | XChaCha20-Poly1305 (24-byte nonce)                    |
| Forward Secrecy   | Per-epoch KEM ratchet + per-message symmetric ratchet |
| Chunking          | 2KB chunks for SPI transport                          |
| State Persistence | TrustZone ITS with lazy persistence                   |

See [docs/SECURE_ACCESS.md](docs/SECURE_ACCESS.md) for the full protocol specification.

## Cryptographic Algorithms

| Algorithm          | Type                   | Standard   | Performance (MCU) |
| ------------------ | ---------------------- | ---------- | ----------------- |
| ML-KEM 768         | Post-Quantum KEM       | FIPS 203   | ~60ms             |
| ML-DSA 65          | Post-Quantum Signature | FIPS 204   | ~30-60s           |
| X-Wing             | Hybrid PQ KEM          | IETF Draft | ~100ms            |
| Ed25519            | Signature              | RFC 8032   | <10ms             |
| X25519             | Key Agreement          | RFC 7748   | <10ms             |
| XChaCha20-Poly1305 | AEAD                   | RFC 8439+  | <5ms              |
| ChaCha20-Poly1305  | AEAD (BPP)             | RFC 8439   | <5ms              |
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
