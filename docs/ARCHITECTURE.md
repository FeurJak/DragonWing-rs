# DragonWing-rs Architecture

## Overview

DragonWing-rs provides Rust libraries and demos for the **Arduino Uno Q** platform, a dual-processor board combining:

- **STM32U585 MCU** - ARM Cortex-M33 running Zephyr RTOS (no_std Rust)
- **QRB2210 MPU** - Qualcomm processor running Linux (std Rust)

```mermaid
block-beta
    columns 3
    
    block:board:3
        columns 2
        
        block:mcu:1
            columns 1
            A["STM32U585 MCU<br/>(Cortex-M33)"]
            B["Zephyr RTOS"]
            C["no_std Rust"]
            D["Crypto HW"]
            E["LED Matrix"]
        end
        
        block:mpu:1
            columns 1
            F["QRB2210 MPU<br/>(Linux aarch64)"]
            G["Linux Kernel"]
            H["std Rust"]
            I["Network Stack"]
            J["SSH Access"]
        end
    end
    
    mcu <-- "SPI" --> mpu
```

## Communication

### SPI Protocol

The MCU and MPU communicate via SPI with a custom framing protocol:

```mermaid
packet-beta
  0-15: "Magic (0xAA55)"
  16-31: "Length"
  32-95: "Payload (MessagePack-RPC)"
```

**Frame Details:**
- **Magic**: 2 bytes (`0xAA55`) - Frame sync marker
- **Length**: 2 bytes - Payload length
- **Payload**: Up to 508 bytes - MessagePack-RPC encoded data
- **Total frame size**: 512 bytes (fixed)

### RPC Protocol

MessagePack-RPC is used for structured communication:

| Type | Format | Example |
|------|--------|---------|
| Request | `[0, msg_id, "method", [params...]]` | `[0, 1, "ping", []]` |
| Response | `[1, msg_id, error, result]` | `[1, 1, null, "pong"]` |
| Notify | `[2, "method", [params...]]` | `[2, "log", ["hello"]]` |

## Crate Architecture

```mermaid
graph TB
    subgraph Crates["crates/"]
        crypto["dragonwing-crypto<br/>PQ + Classical Crypto"]
        led["dragonwing-led-matrix<br/>LED Matrix Driver"]
        rpc["dragonwing-rpc<br/>Cross-platform RPC"]
        spi["dragonwing-spi<br/>Cross-platform SPI"]
        router["dragonwing-spi-router<br/>MPU SPI Daemon"]
        zcbor["dragonwing-zcbor<br/>CBOR/COSE Encoding"]
    end
    
    subgraph Demos["demos/"]
        mcu["mcu/<br/>MCU Firmware"]
        mpu["mpu/<br/>MPU Applications"]
    end
    
    mcu --> crypto
    mcu --> led
    mcu --> rpc
    mcu --> spi
    mcu --> zcbor
    
    mpu --> rpc
    mpu --> router
```

### Cross-Platform Crates

Some crates support both MCU and MPU with feature flags:

```mermaid
graph LR
    subgraph dragonwing-rpc
        rpc_mcu["mcu feature<br/>SPI transport<br/>no_std<br/>Zephyr"]
        rpc_mpu["mpu feature<br/>Unix socket<br/>tokio async<br/>std"]
    end
    
    subgraph dragonwing-spi
        spi_mcu["mcu feature<br/>SPI peripheral<br/>(slave mode)"]
        spi_mpu["mpu feature<br/>SPI controller<br/>(master mode)"]
    end
```

## Build System

### MCU Builds (Zephyr + Docker)

MCU firmware requires the Zephyr SDK, provided via Docker:

```bash
make docker-build          # Build Docker image (once)
make build-mcu DEMO=pqc-demo  # Build MCU firmware
make flash                 # Flash to board via OpenOCD
```

```mermaid
flowchart LR
    A[Docker Container] --> B[West Config]
    B --> C[CMake Build]
    C --> D[Cargo Build]
    D --> E[Zephyr Link]
    E --> F[ELF Binary]
```

### MPU Builds (cargo-zigbuild)

MPU apps cross-compile for aarch64 Linux:

```bash
make build-mpu APP=pqc-client  # Cross-compile
make deploy APP=pqc-client     # Deploy via SSH
```

```mermaid
flowchart LR
    A[cargo-zigbuild] --> B[Zig Toolchain]
    B --> C[aarch64 Binary]
    C --> D[SCP to Board]
```

## Data Flow Example

Typical crypto demo flow:

```mermaid
sequenceDiagram
    participant Client as pqc-client<br/>(MPU)
    participant Router as spi-router<br/>(MPU)
    participant MCU as pqc-demo<br/>(MCU)
    participant LED as LED Matrix
    
    Client->>Router: 1. Connect (Unix socket)
    Client->>Router: 2. RPC Request<br/>[0, 1, "xwing.run_demo", []]
    Router->>MCU: 3. SPI Transfer
    
    MCU->>MCU: 4. Run X-Wing KEM
    MCU->>LED: 5. Show animation
    
    MCU->>Router: 6. SPI Response
    Router->>Client: 7. RPC Response<br/>[1, 1, null, "success"]
    
    Client->>Client: 8. Display result
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

```mermaid
graph TB
    subgraph Storage Stack
        A[Application Layer]
        B[dragonwing-crypto/psa]
        C[Zephyr PSA Crypto API]
        D[TF-M / Secure Storage]
        E[Flash + AEAD Transform]
    end
    
    A --> B --> C --> D --> E
```
