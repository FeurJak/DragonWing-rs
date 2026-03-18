# dragonwing-crypto

Post-quantum and classical cryptography for Arduino Uno Q (STM32U585 MCU).

**This crate is `no_std` and designed exclusively for MCU targets.**

## Features

### Post-Quantum Cryptography
- **ML-KEM** (FIPS 203) - Key encapsulation mechanism
- **ML-DSA** (FIPS 204) - Digital signatures
- **X-Wing** - Hybrid PQ KEM (ML-KEM-768 + X25519)

### Classical Cryptography
- **Ed25519** - Digital signatures (RFC 8032)
- **X25519** - Key agreement (RFC 7748)
- **XChaCha20-Poly1305** - Authenticated encryption

### Anonymous Credentials
- **SAGA** - BBS-style MAC scheme for unlinkable credentials
- **SAGA+X-Wing** - Credential-protected PQ key exchange

### Storage & Key Management
- **PSA ITS** - Internal Trusted Storage (encrypted at rest)
- **PSA Crypto** - Key generation, import, export

## Usage

```toml
[dependencies]
dragonwing-crypto = { version = "0.1", features = ["xwing", "saga"] }
```

## Documentation

For detailed documentation, see [docs/cryptography.md](../../docs/cryptography.md).

## Requirements

This crate requires Zephyr RTOS and the associated C wrappers in the `c/`
directory to be compiled into your application.

## License

Licensed under Apache-2.0 OR MIT.
