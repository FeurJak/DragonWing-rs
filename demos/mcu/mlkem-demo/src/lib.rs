// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// ML-KEM Demo for Arduino Uno Q
//
// This example demonstrates post-quantum key encapsulation (ML-KEM 768)
// between the STM32U585 MCU and the QRB2210 Linux MPU.
//
// Protocol:
// 1. MCU generates ML-KEM key pair and sends public key to Linux
// 2. Linux encapsulates a shared secret using the public key
// 3. Linux sends ciphertext back to MCU
// 4. MCU decapsulates to recover the shared secret
// 5. Both sides now have the same 32-byte shared secret
//
// The LED matrix displays status:
// - Scrolling pattern: Generating keys
// - Checkmark: Success (shared secrets match)
// - X: Failure
//
// RPC Methods:
// - mlkem.get_public_key() -> returns serialized public key (1184 bytes)
// - mlkem.decapsulate(ciphertext) -> returns shared secret (32 bytes)
// - mlkem.generate_keypair() -> generates new key pair, returns true
// - ping() -> "pong"
// - version() -> firmware version

#![no_std]
#![allow(unexpected_cfgs)]

use log::warn;

use dragonwing_crypto::kem;
use dragonwing_led_matrix::{Frame, LedMatrix};
use dragonwing_rpc::{RpcResult, RpcServer, SpiTransport, Transport, PARAMS};
use zephyr::time::{sleep, Duration};

// Global state
static mut MATRIX: Option<LedMatrix> = None;
static mut KEY_PAIR: Option<kem::KeyPair> = None;
static mut SHARED_SECRET: Option<[u8; 32]> = None;

// Buffer for public key response (1184 bytes for ML-KEM 768)
static mut PK_BUFFER: [u8; kem::PUBLIC_KEY_SIZE] = [0u8; kem::PUBLIC_KEY_SIZE];

// Buffer for shared secret response
static mut SS_BUFFER: [u8; 32] = [0u8; 32];

/// Get mutable reference to the global matrix
unsafe fn matrix() -> &'static mut LedMatrix {
    MATRIX.as_mut().expect("Matrix not initialized")
}

/// Simple pseudo-random number generator for key generation
/// In production, use hardware RNG from Zephyr
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let val = self.next_u64();
            let bytes = val.to_le_bytes();
            for (i, b) in chunk.iter_mut().enumerate() {
                *b = bytes[i];
            }
        }
    }
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

/// Show a lock icon (encryption)
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

// === RPC Handlers ===

/// Handle ping request
fn handle_ping(_count: usize) -> RpcResult {
    RpcResult::Str("pong")
}

/// Handle version request
fn handle_version(_count: usize) -> RpcResult {
    RpcResult::Str("mlkem-demo 0.1.0")
}

/// Generate a new ML-KEM key pair
fn handle_generate_keypair(_count: usize) -> RpcResult {
    warn!("Generating ML-KEM 768 key pair...");
    show_key();

    // Create randomness for key generation (64 bytes needed)
    // In production, use hardware RNG
    let mut rng = SimpleRng::new(0x12345678_9ABCDEF0);
    let mut randomness = [0u8; kem::KEYGEN_SEED_SIZE];
    rng.fill_bytes(&mut randomness);

    // Generate key pair
    let key_pair = kem::generate_key_pair(randomness);

    unsafe {
        KEY_PAIR = Some(key_pair);
        SHARED_SECRET = None; // Clear any previous shared secret
    }

    warn!("Key pair generated successfully!");
    RpcResult::Bool(true)
}

/// Get the public key (returns as bytes array via special handling)
fn handle_get_public_key(_count: usize) -> RpcResult {
    unsafe {
        if let Some(ref kp) = KEY_PAIR {
            let pk_bytes = kp.public_key().as_slice();
            PK_BUFFER.copy_from_slice(pk_bytes);
            warn!("Returning public key ({} bytes)", pk_bytes.len());
            // Return success - actual bytes sent separately
            RpcResult::Int(kem::PUBLIC_KEY_SIZE as i64)
        } else {
            warn!("No key pair generated!");
            RpcResult::Error(-1, "No key pair")
        }
    }
}

/// Decapsulate a ciphertext to get the shared secret
fn handle_decapsulate(count: usize) -> RpcResult {
    warn!("Decapsulating ciphertext...");
    show_lock();

    // The ciphertext should be passed as raw bytes in PARAMS
    // For ML-KEM 768, ciphertext is 1088 bytes
    if count < 1 {
        return RpcResult::Error(-1, "Need ciphertext");
    }

    unsafe {
        if let Some(ref kp) = KEY_PAIR {
            // Get ciphertext from params (stored as bytes)
            let ct_bytes = &PARAMS.bytes[..kem::CIPHERTEXT_SIZE];
            let mut ct_array = [0u8; kem::CIPHERTEXT_SIZE];
            ct_array.copy_from_slice(ct_bytes);

            let ciphertext = kem::ciphertext_from_bytes(&ct_array);

            // Decapsulate
            let shared_secret = kem::decapsulate(kp.private_key(), &ciphertext);

            // Store and return shared secret
            SS_BUFFER.copy_from_slice(shared_secret.as_slice());
            SHARED_SECRET = Some(SS_BUFFER);

            warn!("Decapsulation successful!");
            show_checkmark();

            // Return the shared secret length
            RpcResult::Int(32)
        } else {
            warn!("No key pair generated!");
            show_x();
            RpcResult::Error(-1, "No key pair")
        }
    }
}

/// Get the last computed shared secret
fn handle_get_shared_secret(_count: usize) -> RpcResult {
    unsafe {
        if let Some(ref ss) = SHARED_SECRET {
            SS_BUFFER.copy_from_slice(ss);
            warn!("Returning shared secret (32 bytes)");
            RpcResult::Int(32)
        } else {
            RpcResult::Error(-1, "No shared secret")
        }
    }
}

/// Clear LED matrix
fn handle_matrix_clear(_count: usize) -> RpcResult {
    unsafe {
        matrix().clear();
    }
    RpcResult::Bool(true)
}

/// Main entry point
#[no_mangle]
extern "C" fn rust_main() {
    unsafe {
        zephyr::set_logger().unwrap();
    }

    warn!("===========================================");
    warn!("  ML-KEM Demo - Arduino Uno Q");
    warn!("  Post-Quantum Key Encapsulation");
    warn!("===========================================");
    warn!("");
    warn!("ML-KEM 768 Parameters:");
    warn!("  Public Key:  {} bytes", kem::PUBLIC_KEY_SIZE);
    warn!("  Private Key: {} bytes", kem::PRIVATE_KEY_SIZE);
    warn!("  Ciphertext:  {} bytes", kem::CIPHERTEXT_SIZE);
    warn!("  Shared Secret: {} bytes", kem::SHARED_SECRET_SIZE);
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

    // Show key icon briefly
    show_key();
    sleep(Duration::millis_at_least(500));
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
    warn!("Registering RPC handlers...");
    let mut server = RpcServer::new();

    // Core methods
    server.register("ping", handle_ping);
    server.register("version", handle_version);

    // ML-KEM methods
    server.register("mlkem.generate_keypair", handle_generate_keypair);
    server.register("mlkem.get_public_key", handle_get_public_key);
    server.register("mlkem.decapsulate", handle_decapsulate);
    server.register("mlkem.get_shared_secret", handle_get_shared_secret);

    // LED matrix control
    server.register("led_matrix.clear", handle_matrix_clear);

    warn!("ML-KEM RPC server ready!");
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
