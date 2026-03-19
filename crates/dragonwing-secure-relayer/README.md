# dragonwing-secure-relayer

Secure data relay from host devices to Arduino MCU using the PQ-Ratchet protocol.

## Overview

The Secure-Relayer bridges encrypted data streams to the Arduino Uno Q, providing:

- **Post-Quantum Forward Secrecy**: X-Wing (ML-KEM-768 + X25519) key exchange
- **Double Ratchet**: Signal-style ratcheting for per-message keys
- **Chunking**: Split large messages for SPI transport (2KB chunks)
- **MCU-Rooted Trust**: Only the MCU (TrustZone) can decrypt - MPU is a dumb proxy

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Secure-Relayer (this crate)                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐  │
│  │  RatchetSession │    │  Protocol       │    │  Transport  │  │
│  │  - X-Wing KEM   │───►│  - Frame format │───►│  - WebSocket│  │
│  │  - Ratchet state│    │  - Chunking     │    │  - Binary   │  │
│  └─────────────────┘    └─────────────────┘    └─────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
         │                                              │
         │ Plaintext                                    │ Encrypted chunks
         ▼                                              ▼
    User Device                                   MPU (pq-proxy)
                                                       │ SPI
                                                       ▼
                                                 MCU (TrustZone)
```

## Usage

```rust
use dragonwing_secure_relayer::{RatchetSession, MpuTransport, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Connect to MPU proxy
    let transport = MpuTransport::connect("ws://192.168.1.199:8080").await?;

    // Create ratchet session
    let mut session = RatchetSession::new();

    // Perform X-Wing handshake with MCU
    let (init_msg, _) = session.create_handshake_init()?;
    transport.send(&init_msg).await?;

    let response = transport.receive().await?;
    session.complete_handshake(&response)?;

    // Now we can send encrypted data
    let plaintext = b"Hello, secure world!";
    let (chunks, _) = session.encrypt_and_chunk(plaintext)?;

    for chunk in chunks {
        transport.send(&chunk).await?;
    }

    Ok(())
}
```

## Protocol

### Handshake

1. **Relayer → MCU**: X-Wing public key (1216 bytes)
2. **MCU → Relayer**: X-Wing ciphertext (1120 bytes) + MCU's public key (1216 bytes)
3. Both derive shared secret and initialize ratchet state

### Message Format

```
┌──────────────────────────────────────────────────────────────┐
│ Frame Header (8 bytes)                                       │
│   Magic (2) + Type (1) + Flags (1) + Length (2) + Seq (2)    │
├──────────────────────────────────────────────────────────────┤
│ Payload (variable)                                           │
│   - Handshake: X-Wing PK or Ciphertext                       │
│   - Data: Ratchet message chunks                             │
└──────────────────────────────────────────────────────────────┘
```

### Ratchet Message

```
┌──────────────────────────────────────────────────────────────┐
│ Header: Version + Flags + Epoch + MsgNum [+ NewPK] [+ CT]    │
├──────────────────────────────────────────────────────────────┤
│ Header MAC (32 bytes)                                        │
├──────────────────────────────────────────────────────────────┤
│ Nonce (24 bytes) + Ciphertext + Tag (16 bytes)               │
└──────────────────────────────────────────────────────────────┘
```

## Testing

```bash
# Run unit and integration tests
cargo test

# Test against mock MPU
cargo test --features mock-transport
```

## Dependencies

- `dragonwing-crypto` - X-Wing KEM and PQ-Ratchet protocol
- `tokio` - Async runtime
- `tokio-tungstenite` - WebSocket client
- `anyhow` - Error handling

## License

Licensed under Apache-2.0 OR MIT.
