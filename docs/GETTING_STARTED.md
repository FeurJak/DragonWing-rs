# Getting Started with DragonWing-rs

## Prerequisites

### For MPU Development (Linux apps)

- Rust toolchain: `rustup`
- Cross-compilation: `cargo-zigbuild`
- Target: `rustup target add aarch64-unknown-linux-gnu`

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add aarch64 target
rustup target add aarch64-unknown-linux-gnu

# Install cargo-zigbuild for cross-compilation
cargo install cargo-zigbuild
```

### For MCU Development (Zephyr firmware)

- Docker Desktop
- Make

```bash
# Build the Docker image with Zephyr SDK
make docker-build
```

### Board Setup

1. Connect Arduino Uno Q to your network
2. Note the board's IP address
3. Create environment file:

```bash
cp .env.example .env
# Edit .env with your board's IP and credentials
```

## Quick Start

### If Firmware is Already Flashed

If your board already has MCU firmware and the MPU apps deployed (e.g., from previous development), you can run demos directly:

```bash
# Source environment variables
source .env

# Run a demo (no build required)
make run DEMO=pqc/psa
```

This uses `make run` which only requires SSH access to the board - no Docker or build tools needed.

### Full Build from Scratch

#### 1. Build and Deploy MPU Apps

```bash
# Source environment variables
source .env

# Build the PQC client
make build-mpu APP=pqc-client

# Deploy to board
make deploy APP=pqc-client

# Build and deploy the SPI router
make build-mpu APP=spi-router
make deploy APP=spi-router
```

#### 2. Build and Flash MCU Firmware

```bash
# Build MCU firmware (requires Docker)
make build-mcu DEMO=pqc-demo

# Flash to board via OpenOCD
source .env && make flash
```

#### 3. Run a Demo

```bash
# Run demo via make (recommended)
source .env && make run DEMO=pqc/psa

# Or SSH to board and run manually:
make ssh
./spi-router &
./pqc-client --psa-demo
```

### Make Commands Reference

| Command | Description | Requirements |
|---------|-------------|--------------|
| `make run DEMO=pqc/psa` | Run demo on **already flashed** firmware | SSH only |
| `make demo DEMO=pqc/psa` | Full workflow: build, flash, deploy, run | Docker + SSH |
| `make build-mcu DEMO=...` | Build MCU firmware | Docker |
| `make flash` | Flash firmware to board | SSH + ADB |
| `make build-mpu APP=...` | Build MPU application | cargo-zigbuild |
| `make deploy APP=...` | Deploy MPU app to board | SSH |
| `make ssh` | Open SSH session to board | SSH |

> **Note:** `make run` is for running demos on already-flashed firmware. Use `make demo` only if you need to rebuild and reflash everything.

## Available Demos

### MCU Demos (STM32U585)

| Demo | Description | Command |
|------|-------------|---------|
| **secure-access** | PQ-Ratchet receiver (TrustZone) | `make build-mcu DEMO=secure-access` |
| pqc-demo | Full PQC showcase | `make build-mcu DEMO=pqc-demo` |
| led-matrix-demo | LED animations | `make build-mcu DEMO=led-matrix-demo` |
| mlkem-demo | ML-KEM key exchange | `make build-mcu DEMO=mlkem-demo` |
| rpc-server | RPC with LED control | `make build-mcu DEMO=rpc-server` |

### MPU Apps (QRB2210 Linux)

| App | Description | Command |
|-----|-------------|---------|
| **pq-proxy** | WebSocket→SPI encrypted proxy | `cargo build -p pq-proxy --target aarch64-unknown-linux-gnu` |
| pqc-client | PQC demo controller | `make build-mpu APP=pqc-client` |
| mlkem-client | ML-KEM client | `make build-mpu APP=mlkem-client` |
| weather-display | Weather on LED matrix | `make build-mpu APP=weather-display` |
| spi-router | SPI router daemon | `make build-mpu APP=spi-router` |

### Host Apps (macOS/Linux x86_64)

| App | Description | Command |
|-----|-------------|---------|
| **pq-relayer-demo** | Test client for PQ-Ratchet | `cargo run -p pq-relayer-demo` |

### Demo Commands (via pqc-client)

After flashing `pqc-demo` firmware:

```bash
# PSA Secure Storage demo
./pqc-client --psa-demo

# X-Wing hybrid PQ key exchange
./pqc-client --xwing-demo

# SAGA anonymous credentials
./pqc-client --saga-demo

# SAGA + X-Wing combined
./pqc-client --saga-xwing-demo

# Persistent credential storage
./pqc-client --persistence-demo

# Classical crypto (fast)
./pqc-client --ed25519-demo
./pqc-client --x25519-demo
./pqc-client --xchacha20-demo

# Post-quantum (slower)
./pqc-client --mlkem-demo
./pqc-client --mldsa-demo  # Very slow on MCU
```

## Project Structure

```
DragonWing-rs/
├── crates/                        # Reusable libraries
│   ├── dragonwing-crypto/         # PQ + Classical Crypto + PQ-Ratchet
│   ├── dragonwing-secure-relayer/ # Host-to-MCU secure bridge
│   ├── dragonwing-led-matrix/     # LED matrix driver
│   ├── dragonwing-rpc/            # RPC protocol
│   ├── dragonwing-spi/            # SPI communication
│   ├── dragonwing-spi-router/     # SPI daemon
│   └── dragonwing-zcbor/          # CBOR encoding
├── demos/
│   ├── mcu/                       # MCU firmware (Zephyr + Rust)
│   │   └── secure-access/         # PQ-Ratchet receiver
│   ├── mpu/                       # MPU apps (Linux aarch64)
│   │   └── pq-proxy/              # WebSocket→SPI proxy
│   └── host/                      # Host apps (macOS/Linux x86_64)
│       └── pq-relayer-demo/       # PQ-Ratchet test client
├── docker/                        # Zephyr build environment
├── config/                        # Board configurations
└── docs/                          # Documentation
```

## Troubleshooting

### MCU build fails

```bash
# Rebuild Docker image
make docker-build

# Clean and rebuild
make clean
make build-mcu DEMO=pqc-demo
```

### Can't connect to board

```bash
# Check board is reachable
ping $BOARD_IP

# Test SSH
ssh $BOARD_USER@$BOARD_IP
```

### SPI communication fails

```bash
# On the board, check SPI device exists
ls -la /dev/spidev*

# Restart SPI router
pkill spi-router
./spi-router &

# Check MCU is running (LED matrix should show activity)
```

### Flash fails

```bash
# Ensure OpenOCD config is on board
scp config/QRB2210_swd.cfg $BOARD_USER@$BOARD_IP:~/

# Try manual flash via SSH
make ssh
# Then run OpenOCD commands manually
```

## Secure Data Streaming Quick Start

For post-quantum secure data streaming from phones to the MCU:

```bash
# 1. Build and flash MCU firmware
make build-mcu DEMO=secure-access
make flash

# 2. Deploy proxy to MPU
cargo build --release -p pq-proxy --target aarch64-unknown-linux-gnu
scp target/aarch64-unknown-linux-gnu/release/pq-proxy arduino@$BOARD_IP:~/

# 3. Start proxy on MPU (via SSH)
ssh arduino@$BOARD_IP "./pq-proxy --listen 0.0.0.0:8080"

# 4. Test from host
cargo run -p pq-relayer-demo -- --url ws://$BOARD_IP:8080 --handshake
```

See [SECURE_ACCESS.md](SECURE_ACCESS.md) for the full protocol specification.

## Next Steps

- Read [ARCHITECTURE.md](ARCHITECTURE.md) for system design
- Read [CRYPTOGRAPHY.md](CRYPTOGRAPHY.md) for crypto details
- Read [SECURE_ACCESS.md](SECURE_ACCESS.md) for secure streaming protocol
- Explore the crate READMEs in `crates/*/README.md`
