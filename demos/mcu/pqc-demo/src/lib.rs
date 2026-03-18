// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Cryptography Demo for Arduino Uno Q
//
// This example demonstrates cryptographic operations:
//
// Post-Quantum Cryptography:
// - ML-KEM 768 (FIPS 203) for key encapsulation
// - ML-DSA 65 (FIPS 204) for digital signatures [performance issue]
//
// Classical Cryptography:
// - Ed25519 (RFC 8032) for digital signatures
//
// The demo runs entirely on the MCU - no binary data transfer from Linux needed.
// This makes the demo self-contained and easy to trigger via simple RPC calls.
//
// The LED matrix displays status:
// - Key icon: Generating keys
// - Lock icon: Encryption/decryption
// - Pen icon: Signing
// - Checkmark: Success
// - X: Failure
//
// RPC Methods:
// - ping() -> "pong"
// - version() -> firmware version
// - pqc.run_demo() -> complete ML-KEM + ML-DSA demo with verification
// - mlkem.run_demo() -> ML-KEM only demo (keygen, encaps, decaps)
// - mldsa.run_demo() -> ML-DSA only demo (keygen, sign) [slow]
// - ed25519.run_demo() -> Ed25519 demo (keygen, sign, verify)
// - led_matrix.clear() -> clear the LED display

#![no_std]
#![allow(unexpected_cfgs)]

use log::warn;

use dragonwing_crypto::{
    dsa, ed25519, kem, psa, rng::HwRng, saga, saga_xwing, x25519, xchacha20poly1305, xwing,
};
use dragonwing_led_matrix::{Frame, LedMatrix};
use dragonwing_rpc::{RpcResult, RpcServer, SpiTransport, Transport};
use saga::Identity; // Re-exported from saga module for Point::identity()
use zephyr::time::{sleep, Duration};

// Global state
static mut MATRIX: Option<LedMatrix> = None;

/// Get mutable reference to the global matrix
unsafe fn matrix() -> &'static mut LedMatrix {
    MATRIX.as_mut().expect("Matrix not initialized")
}

// === LED Matrix Patterns ===

/// Show a checkmark pattern (success)
fn show_checkmark() {
    let pattern: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
        [1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
        [0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    ];
    unsafe {
        let frame = Frame::from_bitmap(&pattern);
        matrix().load_frame(&frame);
    }
}

/// Show an X pattern (failure)
fn show_x() {
    let pattern: [[u8; 13]; 8] = [
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0],
    ];
    unsafe {
        let frame = Frame::from_bitmap(&pattern);
        matrix().load_frame(&frame);
    }
}

/// Show a key icon (key generation)
fn show_key() {
    let pattern: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0],
    ];
    unsafe {
        let frame = Frame::from_bitmap(&pattern);
        matrix().load_frame(&frame);
    }
}

/// Show a lock icon (encryption/decryption)
fn show_lock() {
    let pattern: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
    ];
    unsafe {
        let frame = Frame::from_bitmap(&pattern);
        matrix().load_frame(&frame);
    }
}

/// Show a pen/signature icon
fn show_signature() {
    let pattern: [[u8; 13]; 8] = [
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0],
        [1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    ];
    unsafe {
        let frame = Frame::from_bitmap(&pattern);
        matrix().load_frame(&frame);
    }
}

/// Show shield icon (verification)
fn show_shield() {
    let pattern: [[u8; 13]; 8] = [
        [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0],
        [0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
        [0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0],
        [0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0],
    ];
    unsafe {
        let frame = Frame::from_bitmap(&pattern);
        matrix().load_frame(&frame);
    }
}

// === RPC Handlers ===

/// Handle ping request
fn handle_ping(_count: usize) -> RpcResult {
    RpcResult::Str("pong")
}

/// Handle version request
fn handle_version(_count: usize) -> RpcResult {
    RpcResult::Str("crypto-demo 0.6.0")
}

/// Run complete ML-KEM demo on-device
/// Demonstrates: key generation, encapsulation, decapsulation
fn handle_mlkem_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  ML-KEM 768 Demo (FIPS 203)");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");

    // Initialize hardware RNG (uses STM32U585 TRNG)
    let rng = HwRng::new();

    // Step 1: Generate key pair
    warn!("Step 1: Generating ML-KEM 768 key pair...");
    warn!("  (Using hardware TRNG for randomness)");
    show_key();
    sleep(Duration::millis_at_least(500));

    let keygen_randomness: [u8; kem::KEYGEN_SEED_SIZE] = rng.random_array();

    let key_pair = kem::generate_key_pair(keygen_randomness);
    warn!("  Public key:  {} bytes", kem::PUBLIC_KEY_SIZE);
    warn!("  Private key: {} bytes", kem::PRIVATE_KEY_SIZE);
    warn!("  Key pair generated!");

    // Step 2: Encapsulate (simulate sender creating shared secret)
    warn!("");
    warn!("Step 2: Encapsulating shared secret...");
    show_lock();
    sleep(Duration::millis_at_least(500));

    let encaps_randomness: [u8; kem::ENCAPS_SEED_SIZE] = rng.random_array();

    let (ciphertext, shared_secret_sender) =
        kem::encapsulate(key_pair.public_key(), encaps_randomness);
    warn!("  Ciphertext:     {} bytes", kem::CIPHERTEXT_SIZE);
    warn!("  Shared secret:  {} bytes", kem::SHARED_SECRET_SIZE);
    warn!("  Encapsulation complete!");

    // Step 3: Decapsulate (receiver recovers shared secret)
    warn!("");
    warn!("Step 3: Decapsulating to recover shared secret...");
    show_lock();
    sleep(Duration::millis_at_least(500));

    let shared_secret_receiver = kem::decapsulate(key_pair.private_key(), &ciphertext);
    warn!("  Decapsulation complete!");

    // Step 4: Verify shared secrets match
    warn!("");
    warn!("Step 4: Verifying shared secrets match...");
    show_shield();
    sleep(Duration::millis_at_least(300));

    let sender_bytes = shared_secret_sender.as_slice();
    let receiver_bytes = shared_secret_receiver.as_slice();

    let mut secrets_match = true;
    for i in 0..32 {
        if sender_bytes[i] != receiver_bytes[i] {
            secrets_match = false;
            break;
        }
    }

    if secrets_match {
        warn!("  SUCCESS: Shared secrets match!");
        warn!("");
        warn!("  First 8 bytes of shared secret:");
        warn!(
            "    {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            sender_bytes[0],
            sender_bytes[1],
            sender_bytes[2],
            sender_bytes[3],
            sender_bytes[4],
            sender_bytes[5],
            sender_bytes[6],
            sender_bytes[7]
        );
        warn!("");
        warn!("========================================");
        warn!("  ML-KEM 768 Demo Complete!");
        warn!("========================================");
        show_checkmark();
        RpcResult::Bool(true)
    } else {
        warn!("  FAILURE: Shared secrets do not match!");
        show_x();
        RpcResult::Error(-1, "Secrets mismatch")
    }
}

/// Run complete ML-DSA demo on-device
/// Demonstrates: key generation, signing (verification skipped for speed)
///
/// WARNING: ML-DSA operations currently experience significant performance
/// issues on this platform, causing timeouts (>3 minutes). This is a known
/// issue under investigation - the ML-DSA implementation itself is correct,
/// but there appears to be a performance regression in the libcrux-iot library
/// or its integration. ML-KEM operations work correctly (~2 seconds).
fn handle_mldsa_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  ML-DSA 65 Demo (FIPS 204)");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");
    warn!("WARNING: ML-DSA operations are currently");
    warn!("experiencing performance issues (>3 min).");
    warn!("This is a known issue - the implementation");
    warn!("is correct but performance is degraded.");
    warn!("See backlog for investigation status.");
    warn!("");

    // Initialize hardware RNG (uses STM32U585 TRNG)
    let rng = HwRng::new();

    // Step 1: Generate key pair
    warn!("Step 1: Generating ML-DSA 65 key pair...");
    warn!("  (Using hardware TRNG for randomness)");
    show_key();
    sleep(Duration::millis_at_least(300));

    let keygen_randomness: [u8; dsa::KEYGEN_RANDOMNESS_SIZE] = rng.random_array();

    let key_pair = dsa::generate_key_pair(keygen_randomness);
    warn!("  Verification key: {} bytes", dsa::VERIFICATION_KEY_SIZE);
    warn!("  Signing key:      {} bytes", dsa::SIGNING_KEY_SIZE);
    warn!("  Key pair generated!");

    // Step 2: Sign a message
    warn!("");
    warn!("Step 2: Signing message...");
    show_signature();
    sleep(Duration::millis_at_least(300));

    let message = b"Hello from Arduino Uno Q!";
    let context: &[u8] = b"";

    let sign_randomness: [u8; dsa::SIGNING_RANDOMNESS_SIZE] = rng.random_array();

    match dsa::sign(&key_pair.signing_key, message, context, sign_randomness) {
        Ok(signature) => {
            warn!("  Message:   \"Hello from Arduino Uno Q!\"");
            warn!("  Signature: {} bytes", dsa::SIGNATURE_SIZE);
            warn!("  Signing complete!");
            warn!("");
            warn!("  (Verification skipped for demo speed)");
            warn!("");
            warn!("========================================");
            warn!("  ML-DSA 65 Demo Complete!");
            warn!("========================================");
            show_checkmark();
            RpcResult::Bool(true)
        }
        Err(_) => {
            warn!("  FAILURE: Signing failed!");
            show_x();
            RpcResult::Error(-1, "Sign failed")
        }
    }
}

/// Run complete PQC demo combining ML-KEM and ML-DSA
/// This is the full demonstration showing how PQC can protect communications
fn handle_pqc_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("╔══════════════════════════════════════════════════════════════╗");
    warn!("║                                                              ║");
    warn!("║           POST-QUANTUM CRYPTOGRAPHY DEMO                     ║");
    warn!("║                                                              ║");
    warn!("║   ML-KEM 768 (FIPS 203) + ML-DSA 65 (FIPS 204)              ║");
    warn!("║   Running on Arduino Uno Q (STM32U585 MCU)                   ║");
    warn!("║   Using Hardware TRNG for cryptographic randomness          ║");
    warn!("║                                                              ║");
    warn!("╚══════════════════════════════════════════════════════════════╝");
    warn!("");

    // Initialize hardware RNG (uses STM32U585 TRNG)
    let rng = HwRng::new();
    warn!("Hardware TRNG initialized");
    warn!("");

    // ==========================================
    // Phase 1: Key Exchange with ML-KEM 768
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 1: Post-Quantum Key Exchange (ML-KEM 768)            │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");

    // Step 1.1: Generate ML-KEM key pair
    warn!("  [1.1] Generating ML-KEM 768 key pair...");
    warn!("        (Using hardware TRNG for randomness)");
    show_key();
    sleep(Duration::millis_at_least(600));

    let kem_keygen_rand: [u8; kem::KEYGEN_SEED_SIZE] = rng.random_array();

    let kem_keypair = kem::generate_key_pair(kem_keygen_rand);
    warn!("        Public key:  {} bytes", kem::PUBLIC_KEY_SIZE);
    warn!("        Private key: {} bytes", kem::PRIVATE_KEY_SIZE);

    // Step 1.2: Encapsulate shared secret
    warn!("");
    warn!("  [1.2] Encapsulating shared secret...");
    show_lock();
    sleep(Duration::millis_at_least(400));

    let encaps_rand: [u8; kem::ENCAPS_SEED_SIZE] = rng.random_array();

    let (ciphertext, shared_secret_enc) = kem::encapsulate(kem_keypair.public_key(), encaps_rand);
    warn!("        Ciphertext:    {} bytes", kem::CIPHERTEXT_SIZE);
    warn!("        Shared secret: {} bytes", kem::SHARED_SECRET_SIZE);

    // Step 1.3: Decapsulate
    warn!("");
    warn!("  [1.3] Decapsulating shared secret...");
    show_lock();
    sleep(Duration::millis_at_least(400));

    let shared_secret_dec = kem::decapsulate(kem_keypair.private_key(), &ciphertext);

    // Verify shared secrets match
    let enc_bytes = shared_secret_enc.as_slice();
    let dec_bytes = shared_secret_dec.as_slice();
    let mut kem_success = true;
    for i in 0..32 {
        if enc_bytes[i] != dec_bytes[i] {
            kem_success = false;
            break;
        }
    }

    if !kem_success {
        warn!("        FAILURE: Key exchange failed!");
        show_x();
        return RpcResult::Error(-1, "KEM failed");
    }

    warn!("        Shared secrets match!");
    warn!("");
    warn!("  ✓ ML-KEM 768 key exchange successful");
    warn!("");

    // ==========================================
    // Phase 2: Digital Signatures with ML-DSA 65
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 2: Post-Quantum Digital Signatures (ML-DSA 65)       │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");
    warn!("  WARNING: ML-DSA currently has performance issues (>3 min).");
    warn!("  This demo may timeout. ML-KEM above completed successfully.");
    warn!("");

    // Step 2.1: Generate ML-DSA key pair
    warn!("  [2.1] Generating ML-DSA 65 key pair...");
    warn!("        (Using hardware TRNG for randomness)");
    show_key();
    sleep(Duration::millis_at_least(600));

    let dsa_keygen_rand: [u8; dsa::KEYGEN_RANDOMNESS_SIZE] = rng.random_array();

    let dsa_keypair = dsa::generate_key_pair(dsa_keygen_rand);
    warn!(
        "        Verification key: {} bytes",
        dsa::VERIFICATION_KEY_SIZE
    );
    warn!("        Signing key:      {} bytes", dsa::SIGNING_KEY_SIZE);

    // Step 2.2: Sign a message
    warn!("");
    warn!("  [2.2] Signing message...");
    show_signature();
    sleep(Duration::millis_at_least(500));

    let message = b"Quantum-safe message from Arduino Uno Q";
    let context: &[u8] = b"pqc-demo-v2";

    let sign_rand: [u8; dsa::SIGNING_RANDOMNESS_SIZE] = rng.random_array();

    match dsa::sign(&dsa_keypair.signing_key, message, context, sign_rand) {
        Ok(_signature) => {
            warn!("        Message: \"Quantum-safe message from Arduino Uno Q\"");
            warn!("        Signature: {} bytes", dsa::SIGNATURE_SIZE);
            warn!("");
            warn!("  ✓ ML-DSA 65 signing successful");
        }
        Err(_) => {
            warn!("        FAILURE: Signing failed!");
            show_x();
            return RpcResult::Error(-2, "Sign failed");
        }
    };

    // ==========================================
    // Summary
    // ==========================================
    warn!("");
    warn!("╔══════════════════════════════════════════════════════════════╗");
    warn!("║                      DEMO COMPLETE                           ║");
    warn!("╠══════════════════════════════════════════════════════════════╣");
    warn!("║  ML-KEM 768:  Key exchange verified                          ║");
    warn!("║  ML-DSA 65:   Signature generated                            ║");
    warn!("║                                                              ║");
    warn!("║  This MCU is now quantum-resistant!                          ║");
    warn!("╚══════════════════════════════════════════════════════════════╝");
    warn!("");

    show_checkmark();
    RpcResult::Bool(true)
}

/// Clear LED matrix
fn handle_matrix_clear(_count: usize) -> RpcResult {
    unsafe {
        matrix().clear();
    }
    RpcResult::Bool(true)
}

/// Run Ed25519 demo on-device
/// Demonstrates: key generation, signing, verification
fn handle_ed25519_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  Ed25519 Demo (RFC 8032)");
    warn!("  Classical Digital Signatures");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");

    // Initialize hardware RNG (uses STM32U585 TRNG)
    let rng = HwRng::new();

    // Step 1: Generate key pair
    warn!("Step 1: Generating Ed25519 key pair...");
    warn!("  (Using hardware TRNG for seed)");
    show_key();
    sleep(Duration::millis_at_least(300));

    let seed: [u8; ed25519::SECRET_KEY_SIZE] = rng.random_array();
    let secret_key = ed25519::SecretKey::from_seed(&seed);
    let public_key = secret_key.public_key();

    warn!("  Seed (secret):  {} bytes", ed25519::SECRET_KEY_SIZE);
    warn!("  Public key:     {} bytes", ed25519::PUBLIC_KEY_SIZE);
    warn!("  Key pair generated!");

    // Log first 8 bytes of public key
    let pk_bytes = public_key.to_bytes();
    warn!(
        "  Public key prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        pk_bytes[0],
        pk_bytes[1],
        pk_bytes[2],
        pk_bytes[3],
        pk_bytes[4],
        pk_bytes[5],
        pk_bytes[6],
        pk_bytes[7]
    );

    // Step 2: Sign a message
    warn!("");
    warn!("Step 2: Signing message...");
    show_signature();
    sleep(Duration::millis_at_least(300));

    let message = b"Hello from Arduino Uno Q with Ed25519!";
    let signature = secret_key.sign(message);

    warn!("  Message:   \"Hello from Arduino Uno Q with Ed25519!\"");
    warn!("  Signature: {} bytes", ed25519::SIGNATURE_SIZE);
    warn!("  Signing complete!");

    // Log first 8 bytes of signature
    let sig_bytes = signature.to_bytes();
    warn!(
        "  Signature prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        sig_bytes[0],
        sig_bytes[1],
        sig_bytes[2],
        sig_bytes[3],
        sig_bytes[4],
        sig_bytes[5],
        sig_bytes[6],
        sig_bytes[7]
    );

    // Step 3: Verify signature
    warn!("");
    warn!("Step 3: Verifying signature...");
    show_shield();
    sleep(Duration::millis_at_least(300));

    if public_key.verify(message, &signature) {
        warn!("  SUCCESS: Signature verified!");
        warn!("");
        warn!("========================================");
        warn!("  Ed25519 Demo Complete!");
        warn!("========================================");
        show_checkmark();
        RpcResult::Bool(true)
    } else {
        warn!("  FAILURE: Signature verification failed!");
        show_x();
        RpcResult::Error(-1, "Verification failed")
    }
}

/// Run X25519 demo on-device
/// Demonstrates: key generation, Diffie-Hellman key agreement
fn handle_x25519_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  X25519 Demo (RFC 7748)");
    warn!("  Elliptic Curve Diffie-Hellman");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");

    // Initialize hardware RNG
    let rng = HwRng::new();

    // Step 1: Generate Alice's key pair
    warn!("Step 1: Generating Alice's X25519 key pair...");
    show_key();
    sleep(Duration::millis_at_least(300));

    let alice_seed: [u8; x25519::SECRET_KEY_SIZE] = rng.random_array();
    let alice_sk = x25519::SecretKey::from_bytes(&alice_seed);
    let alice_pk = alice_sk.public_key();

    warn!("  Alice's public key: {} bytes", x25519::PUBLIC_KEY_SIZE);
    let alice_pk_bytes = alice_pk.to_bytes();
    warn!(
        "  Prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        alice_pk_bytes[0],
        alice_pk_bytes[1],
        alice_pk_bytes[2],
        alice_pk_bytes[3],
        alice_pk_bytes[4],
        alice_pk_bytes[5],
        alice_pk_bytes[6],
        alice_pk_bytes[7]
    );

    // Step 2: Generate Bob's key pair
    warn!("");
    warn!("Step 2: Generating Bob's X25519 key pair...");
    sleep(Duration::millis_at_least(200));

    let bob_seed: [u8; x25519::SECRET_KEY_SIZE] = rng.random_array();
    let bob_sk = x25519::SecretKey::from_bytes(&bob_seed);
    let bob_pk = bob_sk.public_key();

    warn!("  Bob's public key: {} bytes", x25519::PUBLIC_KEY_SIZE);
    let bob_pk_bytes = bob_pk.to_bytes();
    warn!(
        "  Prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bob_pk_bytes[0],
        bob_pk_bytes[1],
        bob_pk_bytes[2],
        bob_pk_bytes[3],
        bob_pk_bytes[4],
        bob_pk_bytes[5],
        bob_pk_bytes[6],
        bob_pk_bytes[7]
    );

    // Step 3: Compute shared secrets
    warn!("");
    warn!("Step 3: Computing shared secrets...");
    show_lock();
    sleep(Duration::millis_at_least(300));

    let alice_shared = match alice_sk.diffie_hellman(&bob_pk) {
        Ok(ss) => ss,
        Err(_) => {
            warn!("  FAILURE: Alice's DH failed!");
            show_x();
            return RpcResult::Error(-1, "X25519 DH failed");
        }
    };

    let bob_shared = match bob_sk.diffie_hellman(&alice_pk) {
        Ok(ss) => ss,
        Err(_) => {
            warn!("  FAILURE: Bob's DH failed!");
            show_x();
            return RpcResult::Error(-2, "X25519 DH failed");
        }
    };

    // Step 4: Verify shared secrets match
    warn!("");
    warn!("Step 4: Verifying shared secrets match...");

    let alice_ss_bytes = alice_shared.as_bytes();
    let bob_ss_bytes = bob_shared.as_bytes();

    if alice_ss_bytes == bob_ss_bytes {
        warn!("  Shared secret: {} bytes", x25519::SHARED_SECRET_SIZE);
        warn!(
            "  Prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            alice_ss_bytes[0],
            alice_ss_bytes[1],
            alice_ss_bytes[2],
            alice_ss_bytes[3],
            alice_ss_bytes[4],
            alice_ss_bytes[5],
            alice_ss_bytes[6],
            alice_ss_bytes[7]
        );
        warn!("  SUCCESS: Shared secrets match!");
        warn!("");
        warn!("========================================");
        warn!("  X25519 Demo Complete!");
        warn!("========================================");
        show_checkmark();
        RpcResult::Bool(true)
    } else {
        warn!("  FAILURE: Shared secrets don't match!");
        show_x();
        RpcResult::Error(-3, "Shared secrets mismatch")
    }
}

/// Run X-Wing demo on-device
/// Demonstrates: hybrid PQ KEM (ML-KEM-768 + X25519)
fn handle_xwing_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  X-Wing Demo (Hybrid PQ KEM)");
    warn!("  ML-KEM-768 + X25519 Hybrid");
    warn!("  Post-Quantum Secure Key Encapsulation");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");

    // Initialize hardware RNG
    let rng = HwRng::new();

    // Step 1: Generate recipient's key pair
    warn!("Step 1: Generating X-Wing key pair...");
    warn!("  (This combines ML-KEM-768 + X25519)");
    show_key();
    sleep(Duration::millis_at_least(500));

    let seed: [u8; xwing::SECRET_KEY_SIZE] = rng.random_array();
    let secret_key = xwing::SecretKey::from_seed(&seed);
    let public_key = secret_key.public_key();

    warn!("  Secret key seed: {} bytes", xwing::SECRET_KEY_SIZE);
    warn!("  Public key:      {} bytes", xwing::PUBLIC_KEY_SIZE);
    warn!("  Key pair generated!");

    // Log first 8 bytes of public key
    let pk_bytes = public_key.as_bytes();
    warn!(
        "  Public key prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        pk_bytes[0],
        pk_bytes[1],
        pk_bytes[2],
        pk_bytes[3],
        pk_bytes[4],
        pk_bytes[5],
        pk_bytes[6],
        pk_bytes[7]
    );

    // Step 2: Encapsulate (sender side)
    warn!("");
    warn!("Step 2: Encapsulating shared secret...");
    warn!("  (Sender creates ciphertext + shared secret)");
    show_lock();
    sleep(Duration::millis_at_least(500));

    let encaps_seed: [u8; xwing::ENCAPS_SEED_SIZE] = rng.random_array();
    let (ciphertext, sender_shared) = xwing::encapsulate(public_key, encaps_seed);

    warn!("  Ciphertext:      {} bytes", xwing::CIPHERTEXT_SIZE);
    warn!("  Shared secret:   {} bytes", xwing::SHARED_SECRET_SIZE);
    warn!("  Encapsulation complete!");

    // Log first 8 bytes of ciphertext
    let ct_bytes = ciphertext.as_bytes();
    warn!(
        "  Ciphertext prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        ct_bytes[0],
        ct_bytes[1],
        ct_bytes[2],
        ct_bytes[3],
        ct_bytes[4],
        ct_bytes[5],
        ct_bytes[6],
        ct_bytes[7]
    );

    // Log first 8 bytes of sender's shared secret
    let sender_ss_bytes = sender_shared.as_bytes();
    warn!(
        "  Sender SS prefix:  {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        sender_ss_bytes[0],
        sender_ss_bytes[1],
        sender_ss_bytes[2],
        sender_ss_bytes[3],
        sender_ss_bytes[4],
        sender_ss_bytes[5],
        sender_ss_bytes[6],
        sender_ss_bytes[7]
    );

    // Step 3: Decapsulate (receiver side)
    warn!("");
    warn!("Step 3: Decapsulating shared secret...");
    warn!("  (Receiver recovers shared secret from ciphertext)");
    show_shield();
    sleep(Duration::millis_at_least(500));

    let receiver_shared = xwing::decapsulate(&secret_key, &ciphertext);

    // Log first 8 bytes of receiver's shared secret
    let receiver_ss_bytes = receiver_shared.as_bytes();
    warn!(
        "  Receiver SS prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        receiver_ss_bytes[0],
        receiver_ss_bytes[1],
        receiver_ss_bytes[2],
        receiver_ss_bytes[3],
        receiver_ss_bytes[4],
        receiver_ss_bytes[5],
        receiver_ss_bytes[6],
        receiver_ss_bytes[7]
    );

    // Step 4: Verify shared secrets match
    warn!("");
    warn!("Step 4: Verifying shared secrets match...");

    if sender_ss_bytes == receiver_ss_bytes {
        warn!("  SUCCESS: Shared secrets match!");
        warn!("");
        warn!("========================================");
        warn!("  X-Wing Demo Complete!");
        warn!("  Hybrid PQ Key Encapsulation Verified!");
        warn!("========================================");
        show_checkmark();
        RpcResult::Bool(true)
    } else {
        warn!("  FAILURE: Shared secrets don't match!");
        show_x();
        RpcResult::Error(-1, "X-Wing shared secrets mismatch")
    }
}

/// Run XChaCha20-Poly1305 demo on-device
/// Demonstrates: authenticated encryption with 24-byte nonces
fn handle_xchacha20_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  XChaCha20-Poly1305 Demo");
    warn!("  Authenticated Encryption (AEAD)");
    warn!("  24-byte nonces (safe for random gen)");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");

    // Initialize hardware RNG
    let rng = HwRng::new();

    // Step 1: Generate encryption key
    warn!("Step 1: Generating 256-bit encryption key...");
    show_key();
    sleep(Duration::millis_at_least(300));

    let key_bytes: [u8; xchacha20poly1305::KEY_SIZE] = rng.random_array();
    let key = xchacha20poly1305::Key::from_bytes(&key_bytes);

    warn!(
        "  Key size: {} bytes (256 bits)",
        xchacha20poly1305::KEY_SIZE
    );
    warn!(
        "  Key prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        key_bytes[0],
        key_bytes[1],
        key_bytes[2],
        key_bytes[3],
        key_bytes[4],
        key_bytes[5],
        key_bytes[6],
        key_bytes[7]
    );

    // Step 2: Generate random nonce
    warn!("");
    warn!("Step 2: Generating random 24-byte nonce...");
    sleep(Duration::millis_at_least(200));

    let nonce_bytes: [u8; xchacha20poly1305::NONCE_SIZE] = rng.random_array();
    let nonce = xchacha20poly1305::Nonce::from_bytes(&nonce_bytes);

    warn!(
        "  Nonce size: {} bytes (192 bits)",
        xchacha20poly1305::NONCE_SIZE
    );
    warn!(
        "  Nonce prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        nonce_bytes[0],
        nonce_bytes[1],
        nonce_bytes[2],
        nonce_bytes[3],
        nonce_bytes[4],
        nonce_bytes[5],
        nonce_bytes[6],
        nonce_bytes[7]
    );

    // Step 3: Encrypt a message
    warn!("");
    warn!("Step 3: Encrypting message...");
    show_lock();
    sleep(Duration::millis_at_least(300));

    let plaintext = b"Hello from Arduino Uno Q with XChaCha20-Poly1305!";
    let aad = b"authenticated-but-not-encrypted";

    warn!("  Plaintext: \"Hello from Arduino Uno Q with XChaCha20-Poly1305!\"");
    warn!("  Plaintext size: {} bytes", plaintext.len());
    warn!("  AAD: \"authenticated-but-not-encrypted\"");
    warn!("  AAD size: {} bytes", aad.len());

    let (ciphertext, tag) = match xchacha20poly1305::encrypt(&key, &nonce, plaintext, aad) {
        Ok(result) => result,
        Err(e) => {
            warn!("  FAILURE: Encryption failed: {:?}", e);
            show_x();
            return RpcResult::Error(-1, "Encryption failed");
        }
    };

    warn!("  Ciphertext size: {} bytes", ciphertext.len());
    warn!("  Tag size: {} bytes", xchacha20poly1305::TAG_SIZE);
    warn!(
        "  Ciphertext prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        ciphertext[0],
        ciphertext[1],
        ciphertext[2],
        ciphertext[3],
        ciphertext[4],
        ciphertext[5],
        ciphertext[6],
        ciphertext[7]
    );

    let tag_bytes = tag.to_bytes();
    warn!(
        "  Tag: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...",
        tag_bytes[0],
        tag_bytes[1],
        tag_bytes[2],
        tag_bytes[3],
        tag_bytes[4],
        tag_bytes[5],
        tag_bytes[6],
        tag_bytes[7]
    );

    // Step 4: Decrypt the message
    warn!("");
    warn!("Step 4: Decrypting and authenticating...");
    show_shield();
    sleep(Duration::millis_at_least(300));

    let decrypted = match xchacha20poly1305::decrypt(&key, &nonce, &ciphertext, &tag, aad) {
        Ok(result) => result,
        Err(xchacha20poly1305::Error::AuthenticationFailed) => {
            warn!("  FAILURE: Authentication failed (data tampered?)");
            show_x();
            return RpcResult::Error(-2, "Authentication failed");
        }
        Err(e) => {
            warn!("  FAILURE: Decryption failed: {:?}", e);
            show_x();
            return RpcResult::Error(-3, "Decryption failed");
        }
    };

    // Step 5: Verify plaintext matches
    warn!("");
    warn!("Step 5: Verifying decrypted plaintext...");

    if decrypted.as_slice() == plaintext {
        warn!("  SUCCESS: Decrypted plaintext matches original!");
        warn!("");
        warn!("========================================");
        warn!("  XChaCha20-Poly1305 Demo Complete!");
        warn!("  Encryption + Authentication Verified!");
        warn!("========================================");
        show_checkmark();
        RpcResult::Bool(true)
    } else {
        warn!("  FAILURE: Decrypted plaintext doesn't match!");
        show_x();
        RpcResult::Error(-4, "Plaintext mismatch")
    }
}

/// Run SAGA anonymous credential demo on-device
/// Demonstrates: keygen, MAC issuance, unlinkable presentation
fn handle_saga_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  SAGA Demo (BBS-style MAC)");
    warn!("  Anonymous Credentials");
    warn!("  Unlinkable Presentations");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");

    // Initialize hardware RNG (mut because SAGA needs mutable reference)
    let mut rng = HwRng::new();

    // Use 3 attributes for this demo
    let num_attrs = 3;

    // Step 1: Setup key pair (issuer side)
    warn!("Step 1: Setting up SAGA parameters and key pair...");
    warn!("  (Number of attributes: {})", num_attrs);
    show_key();
    sleep(Duration::millis_at_least(500));

    let keypair = match saga::KeyPair::setup(&mut rng, num_attrs) {
        Ok(kp) => kp,
        Err(e) => {
            warn!("  FAILURE: Setup failed: {:?}", e);
            show_x();
            return RpcResult::Error(-1, "SAGA setup failed");
        }
    };

    let params = keypair.params();
    let pk = keypair.pk();

    warn!("  Parameters generated!");
    warn!("  Max attributes: {}", saga::MAX_ATTRS);
    warn!("  Active attributes: {}", num_attrs);

    // Step 2: Create messages (attributes) as curve points
    warn!("");
    warn!("Step 2: Creating credential attributes...");
    sleep(Duration::millis_at_least(300));

    // Create attribute points: M_j = scalar_j * G
    // In real use, these would be hash-to-curve of actual attribute values
    let mut messages = [saga::Point::identity(); saga::MAX_ATTRS];
    for i in 0..num_attrs {
        let scalar = saga::Scalar::from((i + 1) as u64);
        messages[i] = saga::smul(&params.g, &scalar);
    }

    warn!("  Attribute 0: device_class (encoded as 1*G)");
    warn!("  Attribute 1: permission_level (encoded as 2*G)");
    warn!("  Attribute 2: issued_epoch (encoded as 3*G)");

    // Step 3: Issue credential (compute MAC)
    warn!("");
    warn!("Step 3: Issuing credential (computing MAC)...");
    show_signature();
    sleep(Duration::millis_at_least(500));

    let tag = match keypair.mac(&mut rng, &messages[..num_attrs]) {
        Ok(t) => t,
        Err(e) => {
            warn!("  FAILURE: MAC computation failed: {:?}", e);
            show_x();
            return RpcResult::Error(-2, "MAC failed");
        }
    };

    warn!("  Credential issued!");
    warn!("  Tag contains:");
    warn!("    - MAC point A (32 bytes compressed)");
    warn!("    - Randomness scalar e (32 bytes)");
    warn!("    - NIZK proof of correctness");

    // Step 4: Verify credential (holder side, using public key)
    warn!("");
    warn!("Step 4: Holder verifying credential (with public key)...");
    show_shield();
    sleep(Duration::millis_at_least(300));

    if tag.verify(params, pk, &messages[..num_attrs]) {
        warn!("  Credential verified by holder!");
    } else {
        warn!("  FAILURE: Credential verification failed!");
        show_x();
        return RpcResult::Error(-3, "Holder verification failed");
    }

    // Step 5: Create unlinkable presentation
    warn!("");
    warn!("Step 5: Creating unlinkable presentation...");
    warn!("  (Randomizing credential for privacy)");
    show_lock();
    sleep(Duration::millis_at_least(500));

    let predicate = match tag.get_predicate(&mut rng, params, pk, &messages[..num_attrs]) {
        Ok(p) => p,
        Err(e) => {
            warn!("  FAILURE: Presentation creation failed: {:?}", e);
            show_x();
            return RpcResult::Error(-4, "Presentation failed");
        }
    };

    let presentation = predicate.presentation();
    let commitments = predicate.commitments();

    warn!("  Presentation created!");
    warn!("  Contains:");
    warn!("    - Randomized MAC commitment C_A");
    warn!("    - Proof term T");
    warn!("    - {} randomized attribute commitments", num_attrs);

    // Step 6: Holder checks predicate
    warn!("");
    warn!("Step 6: Holder verifying predicate consistency...");
    sleep(Duration::millis_at_least(200));

    match predicate.check(params, pk) {
        Ok(true) => warn!("  Predicate check passed!"),
        Ok(false) => {
            warn!("  FAILURE: Predicate check failed!");
            show_x();
            return RpcResult::Error(-5, "Predicate check failed");
        }
        Err(e) => {
            warn!("  FAILURE: Predicate check error: {:?}", e);
            show_x();
            return RpcResult::Error(-6, "Predicate error");
        }
    }

    // Step 7: Verify presentation (issuer/verifier side)
    warn!("");
    warn!("Step 7: Issuer verifying presentation...");
    warn!("  (Using secret key to verify randomized credential)");
    show_shield();
    sleep(Duration::millis_at_least(500));

    match keypair.verify_presentation(&presentation, commitments) {
        Ok(true) => {
            warn!("  Presentation verified by issuer!");
        }
        Ok(false) => {
            warn!("  FAILURE: Presentation verification failed!");
            show_x();
            return RpcResult::Error(-7, "Presentation invalid");
        }
        Err(e) => {
            warn!("  FAILURE: Presentation verification error: {:?}", e);
            show_x();
            return RpcResult::Error(-8, "Verification error");
        }
    }

    // Step 8: Demonstrate unlinkability
    warn!("");
    warn!("Step 8: Demonstrating unlinkability...");
    warn!("  (Creating second presentation from same credential)");
    sleep(Duration::millis_at_least(300));

    let predicate2 = match tag.get_predicate(&mut rng, params, pk, &messages[..num_attrs]) {
        Ok(p) => p,
        Err(_) => {
            warn!("  FAILURE: Second presentation failed!");
            show_x();
            return RpcResult::Error(-9, "Second presentation failed");
        }
    };

    let presentation2 = predicate2.presentation();

    // Compare the two presentations
    let p1_bytes = presentation.c_a.compress().to_bytes();
    let p2_bytes = presentation2.c_a.compress().to_bytes();

    let different = p1_bytes != p2_bytes;

    if different {
        warn!("  Two presentations from same credential are DIFFERENT!");
        warn!(
            "  Presentation 1 C_A: {:02x}{:02x}{:02x}{:02x}...",
            p1_bytes[0], p1_bytes[1], p1_bytes[2], p1_bytes[3]
        );
        warn!(
            "  Presentation 2 C_A: {:02x}{:02x}{:02x}{:02x}...",
            p2_bytes[0], p2_bytes[1], p2_bytes[2], p2_bytes[3]
        );
        warn!("");
        warn!("  => Presentations are UNLINKABLE!");
    } else {
        warn!("  WARNING: Presentations appear identical (check RNG)");
    }

    // Verify second presentation works too
    match keypair.verify_presentation(&presentation2, predicate2.commitments()) {
        Ok(true) => {
            warn!("  Both presentations verify correctly!");
        }
        _ => {
            warn!("  FAILURE: Second presentation didn't verify!");
            show_x();
            return RpcResult::Error(-10, "Second verify failed");
        }
    }

    warn!("");
    warn!("========================================");
    warn!("  SAGA Demo Complete!");
    warn!("  Anonymous Credential System Working!");
    warn!("========================================");
    warn!("");
    warn!("  Properties demonstrated:");
    warn!("    - Credential issuance");
    warn!("    - Holder-side verification");
    warn!("    - Unlinkable presentations");
    warn!("    - Issuer-side verification");
    warn!("");

    show_checkmark();
    RpcResult::Bool(true)
}

/// Run SAGA + X-Wing hybrid demo on-device
/// Demonstrates: credential-protected post-quantum key exchange
fn handle_saga_xwing_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  SAGA + X-Wing Hybrid Demo");
    warn!("  Credential-Protected PQ Key Exchange");
    warn!("  Anonymous Auth + Post-Quantum Keys");
    warn!("  Using Hardware TRNG for randomness");
    warn!("========================================");
    warn!("");

    // Initialize hardware RNG
    let mut rng = HwRng::new();

    // Use 2 attributes for this demo (simpler)
    let num_attrs = 2;

    // ==========================================
    // Phase 1: Setup (Issuer creates parameters)
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 1: Issuer Setup                                       │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");

    warn!("  [1.1] Creating SAGA parameters and key pair...");
    show_key();
    sleep(Duration::millis_at_least(500));

    let saga_keypair = match saga::KeyPair::setup(&mut rng, num_attrs) {
        Ok(kp) => kp,
        Err(e) => {
            warn!("  FAILURE: SAGA setup failed: {:?}", e);
            show_x();
            return RpcResult::Error(-1, "SAGA setup failed");
        }
    };

    let saga_params = saga_keypair.params();
    let saga_pk = saga_keypair.pk();

    warn!("  SAGA parameters created!");
    warn!("  Active attributes: {}", num_attrs);

    // ==========================================
    // Phase 2: Credential Issuance (to Device)
    // ==========================================
    warn!("");
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 2: Credential Issuance                                │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");

    warn!("  [2.1] Creating device attributes...");

    let mut messages = [saga::Point::identity(); saga::MAX_ATTRS];
    for i in 0..num_attrs {
        let scalar = saga::Scalar::from((i + 100) as u64); // Device-specific values
        messages[i] = saga::smul(&saga_params.g, &scalar);
    }

    warn!("  Attribute 0: device_id (encoded)");
    warn!("  Attribute 1: access_level (encoded)");

    warn!("");
    warn!("  [2.2] Issuing credential to device...");
    show_signature();
    sleep(Duration::millis_at_least(400));

    let credential = match saga_keypair.mac(&mut rng, &messages[..num_attrs]) {
        Ok(t) => t,
        Err(e) => {
            warn!("  FAILURE: Credential issuance failed: {:?}", e);
            show_x();
            return RpcResult::Error(-2, "Credential issuance failed");
        }
    };

    warn!("  Credential issued to device!");

    // ==========================================
    // Phase 3: Credential-Protected Key Exchange
    // ==========================================
    warn!("");
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 3: Credential-Protected Key Exchange                  │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");
    warn!("  Protocol: Device proves credential + gets PQ-secure channel");
    warn!("");

    // Step 3.1: Device initiates (creates X-Wing keypair + SAGA presentation)
    warn!("  [3.1] Device: Initiating key exchange...");
    warn!("        - Generating X-Wing (ML-KEM-768 + X25519) keypair");
    warn!("        - Creating SAGA presentation (proving credential)");
    show_lock();
    sleep(Duration::millis_at_least(600));

    let (request, device_state) = match saga_xwing::CredentialKeyExchange::initiate(
        &mut rng,
        saga_params,
        saga_pk,
        &credential,
        &messages[..num_attrs],
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!("  FAILURE: Initiate failed: {:?}", e);
            show_x();
            return RpcResult::Error(-3, "Initiate failed");
        }
    };

    warn!(
        "        X-Wing public key: {} bytes",
        xwing::PUBLIC_KEY_SIZE
    );
    warn!("        SAGA presentation created!");

    // Step 3.2: Server responds (verifies presentation + encapsulates)
    warn!("");
    warn!("  [3.2] Server: Processing request...");
    warn!("        - Verifying SAGA presentation");
    warn!("        - Encapsulating shared secret with X-Wing");
    show_shield();
    sleep(Duration::millis_at_least(600));

    // Prepare optional payload to send to device
    let payload = b"Access granted: level=admin";

    let (response, server_keys) = match saga_xwing::CredentialKeyExchange::respond(
        &mut rng,
        &saga_keypair,
        &request,
        Some(payload),
    ) {
        Ok(r) => r,
        Err(saga_xwing::Error::PresentationInvalid) => {
            warn!("  FAILURE: Presentation verification failed!");
            show_x();
            return RpcResult::Error(-4, "Presentation invalid");
        }
        Err(e) => {
            warn!("  FAILURE: Server respond failed: {:?}", e);
            show_x();
            return RpcResult::Error(-5, "Server respond failed");
        }
    };

    warn!("        Presentation verified!");
    warn!(
        "        X-Wing ciphertext: {} bytes",
        xwing::CIPHERTEXT_SIZE
    );
    warn!("        Encrypted payload attached");

    // Step 3.3: Device completes (decapsulates + decrypts payload)
    warn!("");
    warn!("  [3.3] Device: Completing key exchange...");
    warn!("        - Decapsulating shared secret");
    warn!("        - Decrypting payload");
    show_lock();
    sleep(Duration::millis_at_least(400));

    let (device_keys, decrypted_payload) =
        match saga_xwing::CredentialKeyExchange::complete(&device_state, &response) {
            Ok(r) => r,
            Err(e) => {
                warn!("  FAILURE: Complete failed: {:?}", e);
                show_x();
                return RpcResult::Error(-6, "Complete failed");
            }
        };

    warn!("        Shared secret derived!");

    // ==========================================
    // Phase 4: Verification
    // ==========================================
    warn!("");
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 4: Verification                                       │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");

    // Check shared secrets match
    warn!("  [4.1] Verifying shared secrets match...");

    let server_ss = server_keys.shared_secret.as_bytes();
    let device_ss = device_keys.shared_secret.as_bytes();

    if server_ss != device_ss {
        warn!("  FAILURE: Shared secrets don't match!");
        show_x();
        return RpcResult::Error(-7, "Shared secrets mismatch");
    }

    warn!("        Shared secrets match!");
    warn!(
        "        SS prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        server_ss[0],
        server_ss[1],
        server_ss[2],
        server_ss[3],
        server_ss[4],
        server_ss[5],
        server_ss[6],
        server_ss[7]
    );

    // Check decrypted payload
    warn!("");
    warn!("  [4.2] Verifying decrypted payload...");

    if let Some(decrypted) = decrypted_payload {
        if &decrypted[..payload.len()] == payload {
            warn!("        Payload decrypted correctly!");
            warn!("        Message: \"Access granted: level=admin\"");
        } else {
            warn!("  FAILURE: Payload mismatch!");
            show_x();
            return RpcResult::Error(-8, "Payload mismatch");
        }
    } else {
        warn!("  FAILURE: No payload received!");
        show_x();
        return RpcResult::Error(-9, "No payload");
    }

    // ==========================================
    // Summary
    // ==========================================
    warn!("");
    warn!("╔══════════════════════════════════════════════════════════════╗");
    warn!("║             SAGA + X-Wing Demo Complete!                     ║");
    warn!("╠══════════════════════════════════════════════════════════════╣");
    warn!("║  SAGA:   Anonymous credential presentation verified          ║");
    warn!("║  X-Wing: Post-quantum key encapsulation successful           ║");
    warn!("║  AEAD:   Encrypted payload delivered and decrypted           ║");
    warn!("║                                                              ║");
    warn!("║  Security Properties:                                        ║");
    warn!("║  - Post-quantum forward secrecy (ML-KEM-768)                 ║");
    warn!("║  - Classical forward secrecy (X25519)                        ║");
    warn!("║  - Anonymous authentication (SAGA unlinkable)                ║");
    warn!("║  - Authenticated encryption (XChaCha20-Poly1305)             ║");
    warn!("╚══════════════════════════════════════════════════════════════╝");
    warn!("");

    show_checkmark();
    RpcResult::Bool(true)
}

/// Run PSA Secure Storage demo on-device
/// Demonstrates: ITS storage, crypto key management, persistence
fn handle_psa_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  PSA Secure Storage Demo");
    warn!("  Internal Trusted Storage (ITS)");
    warn!("  PSA Crypto Key Management");
    warn!("  Encrypted Persistent Storage");
    warn!("========================================");
    warn!("");

    // ==========================================
    // Phase 1: Initialize PSA Crypto
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 1: Initialize PSA Crypto                              │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");

    warn!("  [1.1] Initializing PSA Crypto subsystem...");
    show_key();
    sleep(Duration::millis_at_least(300));

    if let Err(e) = psa::crypto::init() {
        warn!("  FAILURE: PSA Crypto init failed: {}", e);
        show_x();
        return RpcResult::Error(-1, "PSA init failed");
    }

    warn!("        PSA Crypto initialized!");
    warn!("");

    // ==========================================
    // Phase 2: ITS - Store and Retrieve Data
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 2: Internal Trusted Storage (ITS)                     │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");

    // Demo UIDs - applications should define their own strategy
    const DEMO_UID_SECRET: psa::StorageUid = 0x0000_1000;
    const DEMO_UID_CONFIG: psa::StorageUid = 0x0000_1001;

    // Step 2.1: Store secret data
    warn!(
        "  [2.1] Storing secret data (UID: 0x{:08X})...",
        DEMO_UID_SECRET
    );
    show_lock();
    sleep(Duration::millis_at_least(300));

    let secret_data = b"my-secret-credential-key-material-32b";

    // First, remove if exists from previous run
    let _ = psa::its::remove(DEMO_UID_SECRET);

    if let Err(e) = psa::its::set(DEMO_UID_SECRET, secret_data, psa::StorageFlags::NONE) {
        warn!("  FAILURE: ITS set failed: {}", e);
        show_x();
        return RpcResult::Error(-2, "ITS set failed");
    }

    warn!(
        "        Stored {} bytes (encrypted at rest)",
        secret_data.len()
    );

    // Step 2.2: Retrieve and verify
    warn!("");
    warn!("  [2.2] Retrieving and verifying data...");
    show_shield();
    sleep(Duration::millis_at_least(300));

    let mut read_buffer = [0u8; 64];
    let read_len = match psa::its::get(DEMO_UID_SECRET, 0, &mut read_buffer) {
        Ok(len) => len,
        Err(e) => {
            warn!("  FAILURE: ITS get failed: {}", e);
            show_x();
            return RpcResult::Error(-3, "ITS get failed");
        }
    };

    if &read_buffer[..read_len] != secret_data {
        warn!("  FAILURE: Data mismatch!");
        show_x();
        return RpcResult::Error(-4, "Data mismatch");
    }

    warn!("        Retrieved {} bytes - data verified!", read_len);

    // Step 2.3: Get storage info
    warn!("");
    warn!("  [2.3] Getting storage info...");

    let info = match psa::its::get_info(DEMO_UID_SECRET) {
        Ok(i) => i,
        Err(e) => {
            warn!("  FAILURE: ITS get_info failed: {}", e);
            show_x();
            return RpcResult::Error(-5, "ITS get_info failed");
        }
    };

    warn!(
        "        Entry info: size={}, capacity={}",
        info.size, info.capacity
    );

    // Step 2.4: Store configuration data
    warn!("");
    warn!(
        "  [2.4] Storing configuration data (UID: 0x{:08X})...",
        DEMO_UID_CONFIG
    );

    let _ = psa::its::remove(DEMO_UID_CONFIG);
    let config_data = b"device_id=UnoQ-001;access=admin";

    if let Err(e) = psa::its::set(DEMO_UID_CONFIG, config_data, psa::StorageFlags::NONE) {
        warn!("  FAILURE: ITS set config failed: {}", e);
        show_x();
        return RpcResult::Error(-6, "ITS set config failed");
    }

    warn!("        Stored configuration ({} bytes)", config_data.len());
    warn!("");
    warn!("  ✓ ITS operations successful!");
    warn!("");

    // ==========================================
    // Phase 3: PSA Crypto Key Management
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 3: PSA Crypto Key Management                          │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");

    // Demo key ID - applications should define their own strategy
    const DEMO_KEY_ID: psa::KeyId = 0x0001_0001;

    // Step 3.1: Generate persistent AES-256 key
    warn!(
        "  [3.1] Generating persistent AES-256 key (ID: 0x{:08X})...",
        DEMO_KEY_ID
    );
    show_key();
    sleep(Duration::millis_at_least(400));

    // First destroy if exists from previous run
    let _ = psa::crypto::destroy_key(DEMO_KEY_ID);

    let attrs = psa::KeyAttributes::new()
        .with_type(psa::KeyType::Aes)
        .with_bits(256)
        .with_algorithm(psa::Algorithm::AesGcm)
        .with_usage(
            psa::KeyUsageFlags::ENCRYPT | psa::KeyUsageFlags::DECRYPT | psa::KeyUsageFlags::EXPORT,
        )
        .persistent(DEMO_KEY_ID);

    let generated_id = match psa::crypto::generate_key(&attrs) {
        Ok(id) => id,
        Err(e) => {
            warn!("  FAILURE: Key generation failed: {}", e);
            show_x();
            return RpcResult::Error(-7, "Key generation failed");
        }
    };

    warn!(
        "        Generated persistent key ID: 0x{:08X}",
        generated_id
    );
    warn!("        Key type: AES-256");
    warn!("        Algorithm: AES-GCM");
    warn!("        Lifetime: Persistent (survives reboot)");

    // Step 3.2: Export key (to verify generation)
    warn!("");
    warn!("  [3.2] Exporting key to verify...");
    show_lock();
    sleep(Duration::millis_at_least(300));

    let mut key_buffer = [0u8; 32];
    let key_len = match psa::crypto::export_key(generated_id, &mut key_buffer) {
        Ok(len) => len,
        Err(e) => {
            warn!("  FAILURE: Key export failed: {}", e);
            show_x();
            return RpcResult::Error(-8, "Key export failed");
        }
    };

    warn!("        Exported key: {} bytes", key_len);
    warn!(
        "        Key prefix: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}...",
        key_buffer[0],
        key_buffer[1],
        key_buffer[2],
        key_buffer[3],
        key_buffer[4],
        key_buffer[5],
        key_buffer[6],
        key_buffer[7]
    );

    // Step 3.3: Get key attributes
    warn!("");
    warn!("  [3.3] Reading key attributes...");

    let read_attrs = match psa::crypto::get_key_attributes(generated_id) {
        Ok(a) => a,
        Err(e) => {
            warn!("  FAILURE: Get attributes failed: {}", e);
            show_x();
            return RpcResult::Error(-9, "Get attributes failed");
        }
    };

    warn!("        Key bits: {}", read_attrs.bits);
    warn!("        Lifetime: {:?}", read_attrs.lifetime);
    warn!("");
    warn!("  ✓ Key management successful!");
    warn!("");

    // ==========================================
    // Phase 4: Cleanup
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 4: Cleanup (Demo Only)                                │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");

    warn!("  [4.1] Removing demo ITS entries...");

    if let Err(e) = psa::its::remove(DEMO_UID_SECRET) {
        warn!("        Warning: Remove secret failed: {}", e);
    }
    if let Err(e) = psa::its::remove(DEMO_UID_CONFIG) {
        warn!("        Warning: Remove config failed: {}", e);
    }

    warn!("        ITS entries removed");

    warn!("");
    warn!("  [4.2] Destroying demo key...");

    if let Err(e) = psa::crypto::destroy_key(generated_id) {
        warn!("        Warning: Key destroy failed: {}", e);
    }

    warn!("        Key destroyed");
    warn!("");

    // ==========================================
    // Summary
    // ==========================================
    warn!("╔══════════════════════════════════════════════════════════════╗");
    warn!("║                PSA Secure Storage Demo Complete!             ║");
    warn!("╠══════════════════════════════════════════════════════════════╣");
    warn!("║  ITS:    Stored and retrieved encrypted data                 ║");
    warn!("║  Crypto: Generated persistent AES-256 key                    ║");
    warn!("║                                                              ║");
    warn!("║  Features Demonstrated:                                      ║");
    warn!("║  - Data encrypted at rest (AEAD transform)                   ║");
    warn!("║  - Device-unique encryption key                              ║");
    warn!("║  - Persistent storage across reboots                         ║");
    warn!("║  - PSA Certified API compliance                              ║");
    warn!("╚══════════════════════════════════════════════════════════════╝");
    warn!("");

    show_checkmark();
    RpcResult::Bool(true)
}

/// Run PSA Persistence demo on-device
/// Demonstrates: storing SAGA credentials and X-Wing seeds persistently
fn handle_persistence_demo(_count: usize) -> RpcResult {
    warn!("");
    warn!("========================================");
    warn!("  PSA Persistence Demo");
    warn!("  Store SAGA + X-Wing Keys");
    warn!("  Survive Reboots!");
    warn!("========================================");
    warn!("");

    // Initialize hardware RNG
    let mut rng = HwRng::new();

    // ==========================================
    // Phase 1: Initialize PSA
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 1: Initialize PSA                                      │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");

    warn!("  [1.1] Initializing PSA Crypto subsystem...");
    show_key();
    sleep(Duration::millis_at_least(300));

    if let Err(e) = psa::crypto::init() {
        warn!("  FAILURE: PSA Crypto init failed: {}", e);
        show_x();
        return RpcResult::Error(-1, "PSA init failed");
    }

    warn!("        PSA Crypto initialized!");
    warn!("");

    // Demo UIDs - applications should define their own strategy
    const SAGA_TAG_UID: psa::StorageUid = 0x0002_0001;
    const XWING_SEED_UID: psa::StorageUid = 0x0003_0001;

    // ==========================================
    // Phase 2: Check for existing stored data
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 2: Check for Existing Stored Data                      │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");

    let saga_tag_exists = psa::its::exists(SAGA_TAG_UID);
    let xwing_seed_exists = psa::its::exists(XWING_SEED_UID);

    warn!(
        "  SAGA credential (UID 0x{:08X}): {}",
        SAGA_TAG_UID,
        if saga_tag_exists {
            "EXISTS"
        } else {
            "not found"
        }
    );
    warn!(
        "  X-Wing seed (UID 0x{:08X}): {}",
        XWING_SEED_UID,
        if xwing_seed_exists {
            "EXISTS"
        } else {
            "not found"
        }
    );
    warn!("");

    // ==========================================
    // Phase 3: SAGA Credential Storage
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 3: SAGA Credential Storage                             │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");

    let num_attrs = 2;

    // Setup SAGA keypair (normally done by issuer)
    warn!("  [3.1] Setting up SAGA issuer keypair...");
    show_key();
    sleep(Duration::millis_at_least(400));

    let saga_keypair = match saga::KeyPair::setup(&mut rng, num_attrs) {
        Ok(kp) => kp,
        Err(e) => {
            warn!("  FAILURE: SAGA setup failed: {:?}", e);
            show_x();
            return RpcResult::Error(-2, "SAGA setup failed");
        }
    };

    let saga_params = saga_keypair.params();
    let saga_pk = saga_keypair.pk();
    warn!("        Keypair created ({} attributes)", num_attrs);

    // Create attributes
    let mut messages = [saga::Point::identity(); saga::MAX_ATTRS];
    for i in 0..num_attrs {
        let scalar = saga::Scalar::from((i + 42) as u64);
        messages[i] = saga::smul(&saga_params.g, &scalar);
    }

    // Issue credential
    warn!("");
    warn!("  [3.2] Issuing SAGA credential...");
    show_signature();
    sleep(Duration::millis_at_least(400));

    let credential = match saga_keypair.mac(&mut rng, &messages[..num_attrs]) {
        Ok(t) => t,
        Err(e) => {
            warn!("  FAILURE: Credential issuance failed: {:?}", e);
            show_x();
            return RpcResult::Error(-3, "Credential failed");
        }
    };

    warn!("        Credential issued!");

    // Store credential in PSA ITS
    warn!("");
    warn!("  [3.3] Storing credential in PSA ITS...");
    show_lock();
    sleep(Duration::millis_at_least(300));

    // Remove if exists from previous run
    let _ = psa::its::remove(SAGA_TAG_UID);

    // Serialize and store
    let tag_bytes = credential.to_bytes();
    warn!("        Serialized size: {} bytes", tag_bytes.len());

    if let Err(e) = psa::its::set(SAGA_TAG_UID, &tag_bytes, psa::StorageFlags::NONE) {
        warn!("  FAILURE: ITS store failed: {}", e);
        show_x();
        return RpcResult::Error(-4, "ITS store failed");
    }

    warn!("        Credential stored!");

    // Load it back and verify
    warn!("");
    warn!("  [3.4] Loading credential back...");
    show_shield();
    sleep(Duration::millis_at_least(300));

    let mut loaded_bytes = [0u8; 512]; // TAG_SIZE is within this
    let loaded_len = match psa::its::get(SAGA_TAG_UID, 0, &mut loaded_bytes) {
        Ok(len) => len,
        Err(e) => {
            warn!("  FAILURE: ITS load failed: {}", e);
            show_x();
            return RpcResult::Error(-5, "ITS load failed");
        }
    };

    warn!("        Loaded {} bytes", loaded_len);

    // Deserialize
    let loaded_tag_bytes: [u8; saga::TAG_SIZE] = match loaded_bytes[..saga::TAG_SIZE].try_into() {
        Ok(arr) => arr,
        Err(_) => {
            warn!("  FAILURE: Invalid tag size!");
            show_x();
            return RpcResult::Error(-6, "Invalid tag size");
        }
    };

    let loaded_tag = match saga::Tag::from_bytes(&loaded_tag_bytes) {
        Some(t) => t,
        None => {
            warn!("  FAILURE: Tag deserialization failed!");
            show_x();
            return RpcResult::Error(-7, "Deserialize failed");
        }
    };

    // Verify loaded credential works
    if !loaded_tag.verify(saga_params, saga_pk, &messages[..num_attrs]) {
        warn!("  FAILURE: Loaded credential invalid!");
        show_x();
        return RpcResult::Error(-8, "Credential invalid");
    }

    warn!("        Credential verified after load!");
    warn!("");
    warn!("  ✓ SAGA credential persisted successfully!");
    warn!("");

    // ==========================================
    // Phase 4: X-Wing Seed Storage
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 4: X-Wing Seed Storage                                 │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");

    // Generate X-Wing seed
    warn!("  [4.1] Generating X-Wing seed...");
    show_key();
    sleep(Duration::millis_at_least(300));

    let seed: [u8; xwing::SECRET_KEY_SIZE] = rng.random_array();
    warn!("        Seed generated ({} bytes)", xwing::SECRET_KEY_SIZE);
    warn!(
        "        Seed prefix: {:02x}{:02x}{:02x}{:02x}...",
        seed[0], seed[1], seed[2], seed[3]
    );

    // Store seed
    warn!("");
    warn!("  [4.2] Storing seed in PSA ITS...");
    show_lock();
    sleep(Duration::millis_at_least(300));

    // Remove if exists from previous run
    let _ = psa::its::remove(XWING_SEED_UID);

    if let Err(e) = psa::its::set(XWING_SEED_UID, &seed, psa::StorageFlags::NONE) {
        warn!("  FAILURE: Seed store failed: {}", e);
        show_x();
        return RpcResult::Error(-9, "Seed store failed");
    }

    warn!("        Seed stored!");

    // Load seed and regenerate keypair
    warn!("");
    warn!("  [4.3] Loading seed and regenerating keypair...");
    show_shield();
    sleep(Duration::millis_at_least(300));

    let loaded_seed: [u8; xwing::SECRET_KEY_SIZE] = match psa::its::load(XWING_SEED_UID) {
        Ok(s) => s,
        Err(e) => {
            warn!("  FAILURE: Seed load failed: {}", e);
            show_x();
            return RpcResult::Error(-10, "Seed load failed");
        }
    };

    warn!(
        "        Loaded seed prefix: {:02x}{:02x}{:02x}{:02x}...",
        loaded_seed[0], loaded_seed[1], loaded_seed[2], loaded_seed[3]
    );

    // Verify seeds match
    if seed != loaded_seed {
        warn!("  FAILURE: Seeds don't match!");
        show_x();
        return RpcResult::Error(-11, "Seed mismatch");
    }

    warn!("        Seeds match!");

    // Regenerate keypair from loaded seed
    let secret_key = xwing::SecretKey::from_seed(&loaded_seed);
    let public_key = secret_key.public_key();

    let pk_bytes = public_key.as_bytes();
    warn!(
        "        Regenerated PK prefix: {:02x}{:02x}{:02x}{:02x}...",
        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]
    );
    warn!("");
    warn!("  ✓ X-Wing seed persisted successfully!");
    warn!("");

    // ==========================================
    // Phase 5: Demonstrate Usage After "Reboot"
    // ==========================================
    warn!("┌──────────────────────────────────────────────────────────────┐");
    warn!("│  PHASE 5: Simulated Reboot Scenario                           │");
    warn!("└──────────────────────────────────────────────────────────────┘");
    warn!("");
    warn!("  In a real scenario:");
    warn!("  1. Device stores credential + seed");
    warn!("  2. Device powers off");
    warn!("  3. Device powers on");
    warn!("  4. Device loads credential + seed from ITS");
    warn!("  5. Device can immediately use credential for auth");
    warn!("  6. Device can immediately do X-Wing key exchange");
    warn!("");

    // Demonstrate loaded credential can create presentation
    warn!("  [5.1] Creating presentation from loaded credential...");
    show_signature();
    sleep(Duration::millis_at_least(400));

    let predicate =
        match loaded_tag.get_predicate(&mut rng, saga_params, saga_pk, &messages[..num_attrs]) {
            Ok(p) => p,
            Err(e) => {
                warn!("  FAILURE: Presentation failed: {:?}", e);
                show_x();
                return RpcResult::Error(-12, "Presentation failed");
            }
        };

    match saga_keypair.verify_presentation(&predicate.presentation(), predicate.commitments()) {
        Ok(true) => {
            warn!("        Presentation verified!");
        }
        _ => {
            warn!("  FAILURE: Presentation verification failed!");
            show_x();
            return RpcResult::Error(-13, "Verify failed");
        }
    }

    // Demonstrate loaded X-Wing key works
    warn!("");
    warn!("  [5.2] Performing X-Wing encapsulation with loaded key...");
    show_lock();
    sleep(Duration::millis_at_least(400));

    let encaps_seed: [u8; xwing::ENCAPS_SEED_SIZE] = rng.random_array();
    let (ciphertext, sender_ss) = xwing::encapsulate(&public_key, encaps_seed);

    let receiver_ss = xwing::decapsulate(&secret_key, &ciphertext);

    if sender_ss.as_bytes() != receiver_ss.as_bytes() {
        warn!("  FAILURE: Shared secrets don't match!");
        show_x();
        return RpcResult::Error(-14, "SS mismatch");
    }

    warn!("        Key exchange successful!");
    warn!(
        "        Shared secret: {:02x}{:02x}{:02x}{:02x}...",
        sender_ss.as_bytes()[0],
        sender_ss.as_bytes()[1],
        sender_ss.as_bytes()[2],
        sender_ss.as_bytes()[3]
    );
    warn!("");

    // Cleanup (for demo purposes)
    warn!("  [5.3] Cleanup (demo only)...");
    let _ = psa::its::remove(SAGA_TAG_UID);
    let _ = psa::its::remove(XWING_SEED_UID);
    warn!("        Entries removed");
    warn!("");

    // ==========================================
    // Summary
    // ==========================================
    warn!("╔══════════════════════════════════════════════════════════════╗");
    warn!("║              PSA Persistence Demo Complete!                   ║");
    warn!("╠══════════════════════════════════════════════════════════════╣");
    warn!("║  SAGA:   Credential stored → loaded → verified → presented   ║");
    warn!("║  X-Wing: Seed stored → loaded → keypair regenerated → used   ║");
    warn!("║                                                              ║");
    warn!("║  Key Takeaways:                                              ║");
    warn!("║  - Credentials survive reboots (encrypted at rest)           ║");
    warn!("║  - Only 32-byte seed needed for X-Wing (not 1.2KB pubkey)    ║");
    warn!("║  - Device can immediately authenticate after power-on        ║");
    warn!("║  - Post-quantum secure channel established instantly         ║");
    warn!("╚══════════════════════════════════════════════════════════════╝");
    warn!("");

    show_checkmark();
    RpcResult::Bool(true)
}

// NOTE: COSE_Sign1 demo temporarily disabled due to ML-DSA performance issues.
// The arduino-zcbor crate with COSE support is ready and working, but ML-DSA
// operations currently timeout (>3 minutes). Once the ML-DSA performance
// regression is resolved, re-enable the COSE demo.
//
// To re-enable:
// 1. Add import: use arduino_zcbor::cose::CoseSign1;
// 2. Uncomment handle_cose_demo function below
// 3. Register handler: server.register("cose.run_demo", handle_cose_demo);

/*
// Static buffer for COSE output to avoid stack overflow
static mut COSE_OUTPUT: [u8; 3500] = [0u8; 3500];

/// Run COSE_Sign1 demo with ML-DSA 65
fn handle_cose_demo(_count: usize) -> RpcResult {
    // ... COSE demo code here (depends on ML-DSA working) ...
    RpcResult::Error(-1, "COSE demo disabled - ML-DSA timeout")
}
*/

/// Main entry point
#[no_mangle]
extern "C" fn rust_main() {
    unsafe {
        zephyr::set_logger().unwrap();
    }

    warn!("");
    warn!("╔══════════════════════════════════════════════════════════════╗");
    warn!("║                                                              ║");
    warn!("║           Crypto Demo - Arduino Uno Q                        ║");
    warn!("║           Post-Quantum + Classical Cryptography              ║");
    warn!("║                                                              ║");
    warn!("║           ML-KEM 768 (FIPS 203)                              ║");
    warn!("║           ML-DSA 65  (FIPS 204) [performance issue]          ║");
    warn!("║           X-Wing (ML-KEM + X25519 Hybrid KEM)                ║");
    warn!("║           XChaCha20-Poly1305 (AEAD Encryption)               ║");
    warn!("║           SAGA (Anonymous Credentials / BBS-MAC)             ║");
    warn!("║           SAGA+X-Wing (Credential-Protected PQ KEM)         ║");
    warn!("║           Ed25519 / X25519 (RFC 8032/7748)                   ║");
    warn!("║           Hardware TRNG (STM32U585)                          ║");
    warn!("║                                                              ║");
    warn!("╚══════════════════════════════════════════════════════════════╝");
    warn!("");
    warn!("Algorithm Parameters:");
    warn!("");
    warn!("  ML-KEM 768 (Post-Quantum Key Encapsulation):");
    warn!("    Public Key:    {:>5} bytes", kem::PUBLIC_KEY_SIZE);
    warn!("    Private Key:   {:>5} bytes", kem::PRIVATE_KEY_SIZE);
    warn!("    Ciphertext:    {:>5} bytes", kem::CIPHERTEXT_SIZE);
    warn!("    Shared Secret: {:>5} bytes", kem::SHARED_SECRET_SIZE);
    warn!("");
    warn!("  ML-DSA 65 (Post-Quantum Signatures):");
    warn!(
        "    Verification Key: {:>5} bytes",
        dsa::VERIFICATION_KEY_SIZE
    );
    warn!("    Signing Key:      {:>5} bytes", dsa::SIGNING_KEY_SIZE);
    warn!("    Signature:        {:>5} bytes", dsa::SIGNATURE_SIZE);
    warn!("");
    warn!("  Ed25519 (Classical Signatures):");
    warn!(
        "    Public Key:       {:>5} bytes",
        ed25519::PUBLIC_KEY_SIZE
    );
    warn!(
        "    Secret Key:       {:>5} bytes",
        ed25519::SECRET_KEY_SIZE
    );
    warn!("    Signature:        {:>5} bytes", ed25519::SIGNATURE_SIZE);
    warn!("");

    // Initialize LED matrix
    warn!("Initializing LED matrix...");
    unsafe {
        MATRIX = Some(LedMatrix::new());
        if !matrix().begin() {
            warn!("Failed to initialize LED matrix!");
            loop {
                sleep(Duration::millis_at_least(1000));
            }
        }
    }
    warn!("LED matrix initialized!");

    // Show key icon briefly at startup
    show_key();
    sleep(Duration::millis_at_least(800));
    unsafe {
        matrix().clear();
    }

    // Initialize SPI transport
    warn!("Initializing SPI transport...");
    let mut spi = SpiTransport::new();
    if !spi.init() {
        warn!("Failed to initialize SPI!");
        show_x();
        loop {
            sleep(Duration::millis_at_least(1000));
        }
    }
    warn!("SPI initialized!");

    // Create RPC server and register handlers
    warn!("");
    warn!("Registering RPC handlers...");
    let mut server = RpcServer::new();

    // Core methods
    server.register("ping", handle_ping);
    server.register("version", handle_version);

    // Demo methods (self-contained, no binary data needed)
    server.register("pqc.run_demo", handle_pqc_demo);
    server.register("mlkem.run_demo", handle_mlkem_demo);
    server.register("mldsa.run_demo", handle_mldsa_demo);
    server.register("ed25519.run_demo", handle_ed25519_demo);
    server.register("x25519.run_demo", handle_x25519_demo);
    server.register("xwing.run_demo", handle_xwing_demo);
    server.register("xchacha20.run_demo", handle_xchacha20_demo);
    server.register("saga.run_demo", handle_saga_demo);
    server.register("saga_xwing.run_demo", handle_saga_xwing_demo);
    server.register("psa.run_demo", handle_psa_demo);
    server.register("persistence.run_demo", handle_persistence_demo);
    // NOTE: cose.run_demo disabled due to ML-DSA performance issues

    // LED matrix control
    server.register("led_matrix.clear", handle_matrix_clear);

    warn!("");
    warn!("Available RPC methods:");
    warn!("  - ping              -> \"pong\"");
    warn!("  - version           -> firmware version");
    warn!("  - pqc.run_demo      -> full ML-KEM + ML-DSA demo");
    warn!("  - mlkem.run_demo    -> ML-KEM 768 demo only");
    warn!("  - mldsa.run_demo    -> ML-DSA 65 demo only (WARNING: slow)");
    warn!("  - ed25519.run_demo  -> Ed25519 demo (fast!)");
    warn!("  - x25519.run_demo   -> X25519 ECDH demo (fast!)");
    warn!("  - xwing.run_demo    -> X-Wing hybrid PQ KEM demo");
    warn!("  - xchacha20.run_demo -> XChaCha20-Poly1305 AEAD demo");
    warn!("  - saga.run_demo     -> SAGA anonymous credentials demo");
    warn!("  - saga_xwing.run_demo -> SAGA+X-Wing credential key exchange");
    warn!("  - psa.run_demo      -> PSA Secure Storage + Key Management");
    warn!("  - persistence.run_demo -> SAGA + X-Wing PSA persistence demo");
    warn!("  - led_matrix.clear  -> clear LED display");
    warn!("");
    warn!("NOTE: ML-DSA operations have a known performance issue");
    warn!("      causing timeouts (>3 min). Ed25519 works normally.");
    warn!("");
    warn!("PQC RPC server ready!");
    warn!("Waiting for requests from Linux...");

    // Prepare initial empty response
    let empty_response: [u8; 0] = [];
    spi.prepare_tx(&empty_response);

    let mut request_count: u32 = 0;

    // Main loop
    loop {
        let rx_len = spi.transceive();

        if rx_len == 0 {
            spi.prepare_tx(&empty_response);
            continue;
        }

        request_count = request_count.wrapping_add(1);

        // Read received data
        let mut rx_buffer = [0u8; 512];
        let mut total_read = 0;
        while total_read < rx_len && total_read < rx_buffer.len() {
            let mut byte_buf = [0u8; 1];
            if spi.read(&mut byte_buf) > 0 {
                rx_buffer[total_read] = byte_buf[0];
                total_read += 1;
            } else {
                break;
            }
        }

        warn!("[{}] RX {} bytes", request_count, total_read);

        // Process RPC message
        if let Some(response) = server.process(&rx_buffer[..total_read]) {
            warn!("[{}] TX {} bytes response", request_count, response.len());
            spi.prepare_tx(response);
        } else {
            warn!("[{}] No response", request_count);
            spi.prepare_tx(&empty_response);
        }
    }
}
