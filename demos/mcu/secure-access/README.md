# secure-access MCU Demo

PQ-Ratchet secure data receiver for Arduino Uno Q (STM32U585 MCU).

## Overview

This firmware receives encrypted data streams via SPI and decrypts them in TrustZone.
The MPU (Linux) acts as a dumb proxy - it forwards encrypted chunks without being able
to read the plaintext.

## Features

- **X-Wing Handshake**: Post-quantum key exchange with Secure-Relayer
- **PQ-Ratchet Decryption**: Double-ratchet with per-message forward secrecy
- **Chunk Reassembly**: Reassemble large messages from 2KB SPI chunks
- **TrustZone Storage**: Persist ratchet state in PSA ITS (encrypted at rest)

## Building

```bash
# From repository root
make build-mcu DEMO=secure-access

# Flash to board
make flash
```

## Memory Usage

| Region | Used | Total | Usage |
|--------|------|-------|-------|
| FLASH | ~415KB | 2MB | 20% |
| RAM | ~490KB | 768KB | 64% |

## Protocol

### SPI Frame Types

| Type | Code | Description |
|------|------|-------------|
| Handshake Init | `0x20` | X-Wing public key from relayer |
| Handshake Response | `0x21` | X-Wing ciphertext + MCU public key |
| Ratchet Chunk | `0x30` | Encrypted ratchet message chunk |
| Ratchet ACK | `0x31` | Chunk acknowledgment |

### Handshake Flow

```
Relayer                    MPU (Proxy)               MCU (TrustZone)
   │                           │                           │
   │  X-Wing PK (1216 bytes)   │                           │
   ├──────────────────────────►├──────────────────────────►│
   │                           │                           │ Generate shared secret
   │                           │                           │ Initialize ratchet
   │                           │  CT (1120) + PK (1216)    │
   │◄──────────────────────────┤◄──────────────────────────┤
   │                           │                           │
```

### Data Flow

```
Relayer                    MPU (Proxy)               MCU (TrustZone)
   │                           │                           │
   │  Chunk 0/N                │                           │
   ├──────────────────────────►├──────────────────────────►│
   │                           │  ACK 0                    │
   │                           │◄──────────────────────────┤
   │  Chunk 1/N                │                           │
   ├──────────────────────────►├──────────────────────────►│
   │  ...                      │                           │
   │  Chunk N/N (last)         │                           │
   ├──────────────────────────►├──────────────────────────►│
   │                           │                           │ Reassemble
   │                           │                           │ Decrypt (XChaCha20)
   │                           │                           │ Process plaintext
   │                           │  Complete                 │
   │◄──────────────────────────┤◄──────────────────────────┤
```

## PSA Storage UIDs

| UID | Content | Size |
|-----|---------|------|
| `0x3000` | Ratchet state (primary) | 3692 bytes |
| `0x3001` | Ratchet state (backup) | 3692 bytes |
| `0x3002` | Ratchet metadata | 24 bytes |

## Configuration

Edit `prj.conf` to adjust:

```ini
# Heap for crypto operations
CONFIG_HEAP_MEM_POOL_SIZE=65536

# PSA storage
CONFIG_SECURE_STORAGE=y
CONFIG_SECURE_STORAGE_ITS_MAX_DATA_SIZE=4096

# SPI peripheral
CONFIG_SPI=y
CONFIG_SPI_STM32_INTERRUPT=y
```

## Debugging

```bash
# Open serial console
make serial

# View logs (115200 baud)
# Logs show: handshake progress, chunk reception, decryption status
```

## License

Licensed under Apache-2.0 OR MIT.
