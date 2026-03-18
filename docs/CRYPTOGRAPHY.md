# Cryptography in DragonWing-rs

## Overview

DragonWing-rs provides a comprehensive cryptography library (`dragonwing-crypto`) supporting both **post-quantum** and **classical** algorithms, designed to run on resource-constrained MCUs.

## Algorithm Summary

| Algorithm | Standard | Security Level | Key Size | Use Case |
|-----------|----------|----------------|----------|----------|
| ML-KEM 768 | FIPS 203 | 128-bit PQ | 1184 bytes (pk) | Key encapsulation |
| ML-DSA 65 | FIPS 204 | 128-bit PQ | 1952 bytes (pk) | Digital signatures |
| X-Wing | IETF Draft | Hybrid PQ | 1216 bytes (pk) | ML-KEM + X25519 |
| Ed25519 | RFC 8032 | 128-bit | 32 bytes (pk) | Fast signatures |
| X25519 | RFC 7748 | 128-bit | 32 bytes (pk) | Key agreement |
| XChaCha20-Poly1305 | RFC 8439+ | 256-bit | 32 bytes | AEAD encryption |
| SAGA | Research | 128-bit | Variable | Anonymous credentials |

## Post-Quantum Cryptography

### ML-KEM 768 (FIPS 203)

Module-Lattice Key Encapsulation Mechanism, the NIST PQC standard for key exchange.

```rust
use dragonwing_crypto::kem;

// Generate key pair
let keypair = kem::generate_keypair(&mut rng);

// Encapsulate (sender)
let (ciphertext, shared_secret) = kem::encapsulate(keypair.public_key(), &mut rng);

// Decapsulate (receiver)
let shared_secret = kem::decapsulate(keypair.private_key(), &ciphertext);
```

**Performance on STM32U585 (Cortex-M33 @ 160MHz):**
- Key generation: ~50ms
- Encapsulation: ~60ms
- Decapsulation: ~70ms

### ML-DSA 65 (FIPS 204)

Module-Lattice Digital Signature Algorithm, the NIST PQC standard for signatures.

```rust
use dragonwing_crypto::dsa;

// Generate key pair
let keypair = dsa::generate_keypair(&mut rng);

// Sign
let signature = dsa::sign(keypair.private_key(), message);

// Verify
let valid = dsa::verify(keypair.public_key(), message, &signature);
```

**Performance on STM32U585:**
- Key generation: ~30-60 seconds (!)
- Signing: ~15-30 seconds
- Verification: ~5-10 seconds

> **Note:** ML-DSA is computationally intensive on Cortex-M. Consider Ed25519 for time-sensitive applications.

### X-Wing Hybrid KEM

X-Wing combines ML-KEM-768 with X25519 for defense-in-depth: security holds if *either* algorithm is secure.

```rust
use dragonwing_crypto::xwing;

// Generate hybrid key pair
let keypair = xwing::generate_keypair(&mut rng);

// Encapsulate (combines ML-KEM + X25519)
let (ciphertext, shared_secret) = xwing::encapsulate(&keypair.public_key, &mut rng);

// Decapsulate
let shared_secret = xwing::decapsulate(&keypair.secret_key, &ciphertext);
```

**Key sizes:**
- Public key: 1216 bytes (1184 ML-KEM + 32 X25519)
- Secret key: 2464 bytes
- Ciphertext: 1120 bytes (1088 ML-KEM + 32 X25519)
- Shared secret: 32 bytes

## Classical Cryptography

### Ed25519 (RFC 8032)

Fast elliptic curve signatures, ideal for MCU applications.

```rust
use dragonwing_crypto::ed25519;

// Generate key pair
let keypair = ed25519::generate_keypair(&mut rng);

// Sign
let signature = ed25519::sign(&keypair.secret_key, message);

// Verify  
let valid = ed25519::verify(&keypair.public_key, message, &signature);
```

**Performance on STM32U585:**
- Key generation: <10ms
- Signing: <10ms
- Verification: <20ms

### X25519 (RFC 7748)

Elliptic curve Diffie-Hellman for key agreement.

```rust
use dragonwing_crypto::x25519;

// Alice generates key pair
let alice_keypair = x25519::generate_keypair(&mut rng);

// Bob generates key pair
let bob_keypair = x25519::generate_keypair(&mut rng);

// Compute shared secret (both sides get same result)
let alice_shared = x25519::diffie_hellman(&alice_keypair.secret_key, &bob_keypair.public_key);
let bob_shared = x25519::diffie_hellman(&bob_keypair.secret_key, &alice_keypair.public_key);
assert_eq!(alice_shared, bob_shared);
```

### XChaCha20-Poly1305

Authenticated encryption with extended nonce (safe for random nonces).

```rust
use dragonwing_crypto::xchacha20poly1305;

// Encrypt with authentication
let nonce = xchacha20poly1305::generate_nonce(&mut rng);
let ciphertext = xchacha20poly1305::encrypt(&key, &nonce, plaintext, aad);

// Decrypt and verify
let plaintext = xchacha20poly1305::decrypt(&key, &nonce, &ciphertext, aad)?;
```

**Properties:**
- Key: 256 bits
- Nonce: 192 bits (safe for random generation)
- Tag: 128 bits
- Max message: 256 GB

## SAGA Anonymous Credentials

SAGA is a BBS-style MAC scheme enabling unlinkable credential presentations.

### Concepts

- **Issuer**: Creates credentials with attributes
- **Holder**: Receives credentials, creates presentations
- **Verifier**: Verifies presentations without learning holder identity

### Usage

```rust
use dragonwing_crypto::saga::{Issuer, Holder, Verifier};

// Issuer setup
let issuer = Issuer::new(&mut rng, num_attributes);
let public_params = issuer.public_params();

// Issue credential to holder
let attributes = vec![attr1, attr2, attr3];
let credential = issuer.issue(&attributes, &mut rng);

// Holder creates unlinkable presentation
let holder = Holder::new(public_params.clone());
let presentation = holder.present(&credential, &mut rng);

// Verifier checks presentation
let verifier = Verifier::new(public_params);
let valid = verifier.verify(&presentation);
```

### Properties

- **Unlinkability**: Multiple presentations of the same credential cannot be linked
- **Selective disclosure**: Holder can reveal only chosen attributes
- **Efficiency**: ~100ms for presentation on Cortex-M33

## SAGA + X-Wing Protocol

Combines anonymous credentials with post-quantum key exchange:

1. Device holds a SAGA credential
2. Device initiates X-Wing key exchange with credential presentation
3. Server verifies presentation and completes key exchange
4. Both parties derive authenticated session key

```rust
use dragonwing_crypto::saga_xwing::{DeviceState, ServerState};

// Device initiates (proves credential + starts key exchange)
let (device_state, init_message) = DeviceState::initiate(&credential, &mut rng);

// Server responds (verifies credential + encapsulates secret)
let (server_state, response) = ServerState::respond(&issuer_params, &init_message, &mut rng)?;

// Device completes (decapsulates + derives session key)
let device_session_key = device_state.complete(&response)?;

// Both now have matching session keys
assert_eq!(device_session_key, server_state.session_key());
```

## PSA Secure Storage

The `psa` module provides persistent storage for cryptographic materials using Zephyr's PSA implementation.

### Internal Trusted Storage (ITS)

```rust
use dragonwing_crypto::psa::its;

// Store data (encrypted at rest)
its::set(uid, &data, flags)?;

// Retrieve data
let data = its::get(uid)?;

// Remove data
its::remove(uid)?;
```

### Storable Credentials

```rust
use dragonwing_crypto::psa::{StorableSagaCredential, StorableXWingSeed};

// Store SAGA credential persistently
let storable = StorableSagaCredential::new(credential);
storable.store(CREDENTIAL_UID)?;

// Load on next boot
let credential = StorableSagaCredential::load(CREDENTIAL_UID)?;

// Store X-Wing seed (regenerate full keypair from 32 bytes)
let seed = StorableXWingSeed::generate(&mut rng);
seed.store(SEED_UID)?;
let keypair = seed.to_keypair();
```

## Implementation Notes

### libcrux-iot

Post-quantum algorithms use [libcrux-iot](https://github.com/FeurJak/libcrux-iot), a fork of libcrux optimized for embedded systems:

- No heap allocation
- Constant-time implementations
- Optimized for Cortex-M

Pinned to commit `e223df3b37aa76298716c02d77b4d8af96fd2111` for reproducibility.

### C FFI

Classical crypto (Ed25519, X25519, XChaCha20-Poly1305) uses C implementations via FFI for performance:

- `ed25519.c` - TweetNaCl-derived implementation
- `x25519.c` - TweetNaCl-derived implementation  
- `xchacha20poly1305.c` - mbedTLS wrapper

### Hardware RNG

The MCU uses the STM32U585's hardware RNG:

```rust
use dragonwing_crypto::rng::HwRng;

let mut rng = HwRng::new();
let random_bytes = rng.fill_bytes(&mut buffer);
```
