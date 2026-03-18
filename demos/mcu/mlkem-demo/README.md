# ML-KEM Demo

Post-quantum key encapsulation (ML-KEM 768) demonstration for the Arduino Uno Q, enabling secure key exchange between the STM32U585 MCU and QRB2210 Linux MPU.

## Overview

This example demonstrates **ML-KEM (FIPS 203)**, a post-quantum key encapsulation mechanism that is resistant to attacks from quantum computers. ML-KEM is the NIST-standardized successor to Kyber.

### ML-KEM 768 Parameters

| Parameter | Size |
|-----------|------|
| Public Key | 1184 bytes |
| Private Key | 2400 bytes |
| Ciphertext | 1088 bytes |
| Shared Secret | 32 bytes |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      ML-KEM Key Exchange                                │
├────────────────────────────┬────────────────────────────────────────────┤
│     STM32U585 MCU          │           QRB2210 Linux MPU                │
│                            │                                            │
│  1. Generate key pair      │                                            │
│     (pk, sk)               │                                            │
│                            │                                            │
│  2. Send public key ──────►│  3. Receive public key                     │
│                            │                                            │
│                            │  4. Encapsulate:                           │
│                            │     (ct, ss) = Encaps(pk)                  │
│                            │                                            │
│  6. Receive ciphertext ◄───│  5. Send ciphertext                        │
│                            │                                            │
│  7. Decapsulate:           │                                            │
│     ss = Decaps(sk, ct)    │                                            │
│                            │                                            │
│  ═══════════════════════════════════════════════════════════════════    │
│  Both parties now share the same 32-byte secret (ss)                    │
└────────────────────────────┴────────────────────────────────────────────┘
```

## Prerequisites

1. **SPI Router**: Ensure `arduino-spi-router` is running:
   ```bash
   make setup-spi-router
   ```

2. **Build Tools**:
   - Docker (for MCU firmware)
   - cargo-zigbuild (for Linux client)

## Building

### MCU Firmware (mlkem-demo)

```bash
# Build the ML-KEM RPC server firmware
make build APP=mlkem-demo

# Flash to the MCU
make flash
```

### Linux Client (mlkem-client)

```bash
# Build for aarch64
make build-linux APP=mlkem-client

# Deploy to board
make deploy-linux APP=mlkem-client
```

## Running

### Test Connection

```bash
make run-linux APP=mlkem-client ARGS='--ping'
```

### Generate Key Pair on MCU

```bash
make run-linux APP=mlkem-client ARGS='--keygen'
```

### Run Full Demo

```bash
make run-linux APP=mlkem-client ARGS='--demo'
```

## RPC Methods

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `ping` | - | "pong" | Test connection |
| `version` | - | string | Firmware version |
| `mlkem.generate_keypair` | - | bool | Generate new key pair |
| `mlkem.get_public_key` | - | int (size) | Get public key |
| `mlkem.decapsulate` | ciphertext | int (size) | Decapsulate to get shared secret |
| `mlkem.get_shared_secret` | - | int (size) | Get last shared secret |
| `led_matrix.clear` | - | bool | Clear LED matrix |

## LED Matrix Status Indicators

| Pattern | Meaning |
|---------|---------|
| Key icon | Generating key pair |
| Lock icon | Decapsulating |
| Checkmark | Success |
| X | Error |

## Security Notes

- This demo uses a simple PRNG for randomness. **Production use requires hardware RNG.**
- ML-KEM 768 provides NIST Level 3 security (equivalent to AES-192).
- The shared secret can be used as input to a KDF for deriving encryption keys.

## Technical Details

### Stack Requirements

ML-KEM 768 operations require significant stack space:
- Key generation: ~8 KB
- Encapsulation: ~4 KB
- Decapsulation: ~4 KB

The MCU firmware is configured with 32 KB stack (`CONFIG_MAIN_STACK_SIZE=32768`).

### Implementation

The cryptographic implementation uses [libcrux-iot](https://github.com/cryspen/libcrux-iot), a formally verified, embedded-optimized ML-KEM implementation from Cryspen.

## License

Apache-2.0 OR MIT
