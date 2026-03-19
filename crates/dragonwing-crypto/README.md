# dragonwing-crypto

Post-quantum and classical cryptography for Arduino Uno Q (STM32U585 MCU).

**This crate is `no_std` compatible and designed for embedded targets.**

## Features

### Post-Quantum Cryptography
- **ML-KEM** (FIPS 203) - Key encapsulation mechanism
- **ML-DSA** (FIPS 204) - Digital signatures
- **X-Wing** - Hybrid PQ KEM (ML-KEM-768 + X25519)

### Classical Cryptography
- **Ed25519** - Digital signatures (RFC 8032)
- **X25519** - Key agreement (RFC 7748)
- **XChaCha20-Poly1305** - Authenticated encryption (24-byte nonce)
- **ChaCha20-Poly1305** - AEAD for BPP protocol compatibility

### Anonymous Credentials
- **SAGA** - BBS-style MAC scheme for unlinkable credentials
- **SAGA+X-Wing** - Credential-protected PQ key exchange

### PQ-Ratchet Protocol (Experimental)
- **Double Ratchet** - Signal-style ratchet with X-Wing KEM
- **Chunking** - Split large messages for SPI transport (2KB chunks)
- **PSA Storage** - Persist ratchet state to TrustZone ITS
- **SAGA Auth** - Optional credential-based session authorization

### Storage & Key Management
- **PSA ITS** - Internal Trusted Storage (encrypted at rest)
- **PSA Crypto** - Key generation, import, export
- **PsaStorable** - Trait for custom type persistence

## Usage

```toml
[dependencies]
dragonwing-crypto = { version = "0.1", features = ["xwing", "saga"] }

# For PQ-Ratchet protocol
dragonwing-crypto = { version = "0.1", features = ["pq_ratchet", "xwing"] }
```

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `std` | Enable standard library (for tests/host) | No |
| `xwing` | X-Wing hybrid KEM (ML-KEM-768 + X25519) | No |
| `saga` | SAGA anonymous credentials | No |
| `pq_ratchet` | PQ-Ratchet double ratchet protocol | No |
| `psa` | PSA secure storage integration | No |

## Module Structure

```
dragonwing-crypto/
├── src/
│   ├── post_quantum/       # ML-KEM, ML-DSA, X-Wing
│   ├── classical/          # Ed25519, X25519, ChaCha20-Poly1305
│   ├── saga/               # Anonymous credentials
│   ├── psa/                # PSA ITS and Crypto APIs
│   ├── experimental/
│   │   └── pq_ratchet/     # Double Ratchet protocol
│   │       ├── state.rs    # Ratchet state machine
│   │       ├── kdf.rs      # Key derivation (HKDF-SHA256)
│   │       ├── encrypt.rs  # XChaCha20-Poly1305 AEAD
│   │       ├── message.rs  # Wire format encoding
│   │       ├── chunking.rs # Message chunking
│   │       └── serialize.rs # State serialization
│   └── rng.rs              # Hardware RNG wrapper
└── c/                      # C wrappers for Zephyr
```

## Requirements

- **MCU builds**: Zephyr RTOS with C wrappers from `c/` directory
- **Host builds**: Rust standard library (`std` feature)

## Testing

```bash
# Run all tests (requires std)
cargo test --features "std,xwing,saga,pq_ratchet"

# Run PQ-Ratchet tests only
cargo test --features "std,xwing,pq_ratchet" pq_ratchet
```

## License

Licensed under Apache-2.0 OR MIT.
