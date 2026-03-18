# DragonWing-rs Architecture

## Overview

DragonWing-rs provides Rust libraries and demos for the **Arduino Uno Q** platform, a dual-processor board combining:

- **STM32U585 MCU** - ARM Cortex-M33 running Zephyr RTOS (no_std Rust)
- **QRB2210 MPU** - Qualcomm processor running Linux (std Rust)

```
┌─────────────────────────────────────────────────────────────┐
│                     Arduino Uno Q                            │
│                                                              │
│  ┌──────────────────┐         ┌──────────────────────────┐  │
│  │   STM32U585 MCU  │   SPI   │      QRB2210 MPU         │  │
│  │   (Cortex-M33)   │◄───────►│      (Linux aarch64)     │  │
│  │                  │         │                          │  │
│  │  - Zephyr RTOS   │         │  - Linux kernel          │  │
│  │  - no_std Rust   │         │  - std Rust              │  │
│  │  - Real-time     │         │  - Network stack         │  │
│  │  - Crypto HW     │         │  - File system           │  │
│  │  - LED Matrix    │         │  - SSH access            │  │
│  └──────────────────┘         └──────────────────────────┘  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Communication

### SPI Protocol

The MCU and MPU communicate via SPI with a custom framing protocol:

```
┌─────────┬─────────┬──────────────────────────────────┐
│  Magic  │ Length  │            Payload               │
│ (2 bytes)│(2 bytes)│         (up to 508 bytes)        │
├─────────┼─────────┼──────────────────────────────────┤
│  0xAA55 │  0x00XX │  MessagePack-RPC encoded data    │
└─────────┴─────────┴──────────────────────────────────┘

Total frame size: 512 bytes (fixed)
```

### RPC Protocol

MessagePack-RPC is used for structured communication:

```
Request:  [0, msg_id, "method_name", [params...]]
Response: [1, msg_id, error, result]
Notify:   [2, "method_name", [params...]]
```

## Crate Architecture

```
dragonwing-rs/
├── crates/
│   ├── dragonwing-crypto     # Cryptography (PQ + classical)
│   ├── dragonwing-led-matrix # LED matrix driver
│   ├── dragonwing-rpc        # Cross-platform RPC
│   ├── dragonwing-spi        # Cross-platform SPI
│   ├── dragonwing-spi-router # MPU SPI daemon
│   └── dragonwing-zcbor      # CBOR/COSE encoding
└── demos/
    ├── mcu/                  # MCU firmware demos
    └── mpu/                  # MPU application demos
```

### Cross-Platform Crates

Some crates support both MCU and MPU with feature flags:

**dragonwing-rpc**
- `mcu` feature: SPI transport, no_std, Zephyr integration
- `mpu` feature: Unix socket client, tokio async, std

**dragonwing-spi**
- `mcu` feature: SPI peripheral (slave) mode via Zephyr
- `mpu` feature: SPI controller (master) mode via spidev

## Build System

### MCU Builds (Zephyr + Docker)

MCU firmware requires the Zephyr SDK, provided via Docker:

```bash
make docker-build          # Build Docker image (once)
make build-mcu DEMO=pqc-demo  # Build MCU firmware
make flash                 # Flash to board via OpenOCD
```

Build flow:
1. Docker container with Zephyr SDK
2. West (Zephyr meta-tool) configures build
3. CMake builds C and Rust components
4. Cargo builds Rust as static library
5. Final ELF linked by Zephyr toolchain

### MPU Builds (cargo-zigbuild)

MPU apps cross-compile for aarch64 Linux:

```bash
make build-mpu APP=pqc-client  # Cross-compile
make deploy APP=pqc-client     # Deploy via SSH
```

Build flow:
1. cargo-zigbuild with aarch64-unknown-linux-gnu target
2. Zig provides cross-compilation toolchain
3. Binary copied to board via SCP

## Data Flow Example

Typical crypto demo flow:

```
┌─────────────┐                              ┌─────────────┐
│  pqc-client │                              │  pqc-demo   │
│    (MPU)    │                              │    (MCU)    │
└──────┬──────┘                              └──────┬──────┘
       │                                            │
       │  1. Connect to Unix socket                 │
       ▼                                            │
┌──────────────┐                                    │
│  spi-router  │                                    │
│    (MPU)     │                                    │
└──────┬───────┘                                    │
       │                                            │
       │  2. RPC Request via SPI                    │
       │     [0, 1, "xwing.run_demo", []]           │
       ├───────────────────────────────────────────►│
       │                                            │
       │                              3. MCU runs   │
       │                                 X-Wing KEM │
       │                                            │
       │  4. RPC Response via SPI                   │
       │     [1, 1, null, "success"]                │
       │◄───────────────────────────────────────────┤
       │                                            │
       ▼                                            ▼
   Display                                    LED Matrix
   Result                                     Animation
```

## Security Architecture

### Cryptographic Primitives

| Algorithm | Type | Use Case |
|-----------|------|----------|
| ML-KEM 768 | Post-Quantum KEM | Key encapsulation |
| ML-DSA 65 | Post-Quantum Signature | Digital signatures |
| X-Wing | Hybrid PQ KEM | ML-KEM + X25519 |
| Ed25519 | Classical Signature | Fast signing |
| X25519 | Classical ECDH | Key agreement |
| XChaCha20-Poly1305 | AEAD | Authenticated encryption |
| SAGA | Anonymous Credentials | Unlinkable presentations |

### PSA Secure Storage

The MCU uses Zephyr's PSA Crypto implementation:

- **ITS** (Internal Trusted Storage): Encrypted at rest
- **Key Management**: Hardware-backed key storage
- **Device-unique keys**: Derived from hardware ID

```
┌─────────────────────────────────────────┐
│           Application Layer             │
├─────────────────────────────────────────┤
│         dragonwing-crypto/psa           │
├─────────────────────────────────────────┤
│         Zephyr PSA Crypto API           │
├─────────────────────────────────────────┤
│    TF-M / Secure Storage Backend        │
├─────────────────────────────────────────┤
│         Flash with AEAD Transform       │
└─────────────────────────────────────────┘
```
