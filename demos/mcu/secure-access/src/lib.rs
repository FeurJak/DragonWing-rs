// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Secure Access Responder for Arduino Uno Q
//!
//! This MCU application implements the Post-Quantum Double Ratchet protocol
//! for secure end-to-end encrypted data streaming from a Relayer to MCU.
//!
//! # Architecture
//!
//! ```text
//!        Relayer          MPU (Linux)             MCU (TrustZone)
//! ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
//! │   Encrypt   │   BPP   │   Forward   │   SPI   │   Decrypt   │
//! │  PQ-Ratchet │────────►│  (proxy)    │────────►│  in Secure  │
//! │   + Chunk   │         │  NO decrypt │         │   World     │
//! └─────────────┘         └─────────────┘         └─────────────┘
//! ```
//!
//! # Protocol
//!
//! 1. Relayer sends HandshakeInit with X-Wing public key + SAGA presentation
//! 2. MCU verifies SAGA presentation, performs X-Wing encapsulation
//! 3. MCU initializes PQ-Ratchet state, stores in TrustZone ITS
//! 4. MCU returns HandshakeResponse with X-Wing ciphertext + own public key
//! 5. Relayer sends PQ-Ratchet encrypted chunks (proxied through MPU)
//! 6. MCU reassembles chunks, decrypts with ratchet, processes plaintext

#![no_std]
#![allow(unexpected_cfgs)]

mod protocol;
mod ratchet_handler;

use log::warn;

use dragonwing_led_matrix::{Frame, LedMatrix};
use dragonwing_rpc::{SpiTransport, Transport};
use zephyr::time::{sleep, Duration};

use dragonwing_crypto::rng::HwRng;

use protocol::*;
use ratchet_handler::RatchetHandler;

// ============================================================================
// Global State
// ============================================================================

/// Global state for the secure access responder
struct SecureState {
    /// PQ-Ratchet handler (manages state, reassembly, decryption)
    ratchet: RatchetHandler,
    /// RNG instance
    rng: HwRng,
    /// Request counter for stats
    request_count: u32,
    /// Successfully decrypted message count
    decrypted_count: u32,
}

impl SecureState {
    fn new() -> Self {
        Self {
            ratchet: RatchetHandler::new(),
            rng: HwRng::new(),
            request_count: 0,
            decrypted_count: 0,
        }
    }

    /// Initialize the ratchet handler (load state from ITS if exists)
    fn init(&mut self) -> bool {
        self.ratchet.init(&mut self.rng)
    }

    /// Process an incoming SPI frame
    fn process_frame(&mut self, data: &[u8]) -> Option<([u8; MAX_RESPONSE_SIZE], usize)> {
        if data.len() < FRAME_HEADER_SIZE {
            warn!("Frame too short: {} bytes", data.len());
            return self.make_error_response(0, "Frame too short");
        }

        // Check magic bytes
        if data[0..2] != FRAME_MAGIC {
            warn!("Invalid magic: {:02X}{:02X}", data[0], data[1]);
            return self.make_error_response(0, "Invalid magic");
        }

        let frame_type = data[2];
        let flags = data[3];
        let sequence = u16::from_be_bytes([data[4], data[5]]);
        let payload_len = u16::from_be_bytes([data[6], data[7]]) as usize;

        if data.len() < FRAME_HEADER_SIZE + payload_len {
            warn!("Payload truncated");
            return self.make_error_response(sequence, "Payload truncated");
        }

        let payload = &data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len];

        match frame_type {
            FRAME_HANDSHAKE_INIT => self.handle_handshake_init(sequence, payload),
            FRAME_RATCHET_CHUNK => self.handle_ratchet_chunk(sequence, flags, payload),
            FRAME_PING => self.handle_ping(sequence),
            _ => {
                warn!("Unknown frame type: 0x{:02X}", frame_type);
                self.make_error_response(sequence, "Unknown frame type")
            }
        }
    }

    /// Handle handshake initialization
    fn handle_handshake_init(
        &mut self,
        sequence: u16,
        payload: &[u8],
    ) -> Option<([u8; MAX_RESPONSE_SIZE], usize)> {
        warn!("Processing HandshakeInit (seq={})", sequence);

        match self.ratchet.handle_handshake_init(&mut self.rng, payload) {
            Ok(response_payload) => {
                // Build response frame
                let payload_len = response_payload.len();
                let total_len = FRAME_HEADER_SIZE + payload_len;

                let mut response = [0u8; MAX_RESPONSE_SIZE];
                response[0..2].copy_from_slice(&FRAME_MAGIC);
                response[2] = FRAME_HANDSHAKE_RESPONSE;
                response[3] = 0; // flags
                response[4..6].copy_from_slice(&sequence.to_be_bytes());
                response[6..8].copy_from_slice(&(payload_len as u16).to_be_bytes());
                response[FRAME_HEADER_SIZE..total_len].copy_from_slice(&response_payload);

                warn!("HandshakeResponse: {} bytes", total_len);
                Some((response, total_len))
            }
            Err(e) => {
                warn!("Handshake failed: {:?}", e);
                self.make_error_response(sequence, "Handshake failed")
            }
        }
    }

    /// Handle incoming ratchet chunk
    fn handle_ratchet_chunk(
        &mut self,
        sequence: u16,
        _flags: u8,
        payload: &[u8],
    ) -> Option<([u8; MAX_RESPONSE_SIZE], usize)> {
        match self.ratchet.handle_chunk(payload) {
            Ok(status) => {
                match status {
                    ChunkStatus::NeedMore { chunk_index } => {
                        // ACK this chunk, need more
                        self.make_chunk_ack(sequence, chunk_index)
                    }
                    ChunkStatus::Complete { plaintext_len } => {
                        self.decrypted_count += 1;
                        warn!(
                            "Message complete: {} bytes plaintext (total: {})",
                            plaintext_len, self.decrypted_count
                        );

                        // Process the decrypted data
                        self.process_decrypted_data(plaintext_len);

                        // Send completion ACK
                        self.make_complete_ack(sequence)
                    }
                    ChunkStatus::Duplicate { chunk_index } => {
                        // Already have this chunk, just ACK
                        self.make_chunk_ack(sequence, chunk_index)
                    }
                }
            }
            Err(e) => {
                warn!("Chunk processing failed: {:?}", e);
                self.make_error_response(sequence, "Chunk error")
            }
        }
    }

    /// Process decrypted data (e.g., run inference)
    fn process_decrypted_data(&mut self, len: usize) {
        // Get reference to decrypted data from ratchet handler
        let data = self.ratchet.get_plaintext(len);

        // TODO: Process the decrypted data (e.g., camera frame inference)
        // For now, just log
        if data.len() >= 4 {
            warn!(
                "Plaintext: {:02X}{:02X}{:02X}{:02X}... ({} bytes)",
                data[0], data[1], data[2], data[3], len
            );
        }
    }

    /// Handle ping
    fn handle_ping(&self, sequence: u16) -> Option<([u8; MAX_RESPONSE_SIZE], usize)> {
        let mut response = [0u8; MAX_RESPONSE_SIZE];
        response[0..2].copy_from_slice(&FRAME_MAGIC);
        response[2] = FRAME_PONG;
        response[3] = 0;
        response[4..6].copy_from_slice(&sequence.to_be_bytes());
        response[6..8].copy_from_slice(&0u16.to_be_bytes());

        Some((response, FRAME_HEADER_SIZE))
    }

    /// Make chunk ACK response
    fn make_chunk_ack(
        &self,
        sequence: u16,
        chunk_index: u16,
    ) -> Option<([u8; MAX_RESPONSE_SIZE], usize)> {
        let mut response = [0u8; MAX_RESPONSE_SIZE];
        response[0..2].copy_from_slice(&FRAME_MAGIC);
        response[2] = FRAME_RATCHET_ACK;
        response[3] = 0;
        response[4..6].copy_from_slice(&sequence.to_be_bytes());
        response[6..8].copy_from_slice(&2u16.to_be_bytes()); // payload = chunk_index
        response[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + 2]
            .copy_from_slice(&chunk_index.to_be_bytes());

        Some((response, FRAME_HEADER_SIZE + 2))
    }

    /// Make completion ACK response
    fn make_complete_ack(&self, sequence: u16) -> Option<([u8; MAX_RESPONSE_SIZE], usize)> {
        let mut response = [0u8; MAX_RESPONSE_SIZE];
        response[0..2].copy_from_slice(&FRAME_MAGIC);
        response[2] = FRAME_RATCHET_COMPLETE;
        response[3] = 0;
        response[4..6].copy_from_slice(&sequence.to_be_bytes());
        response[6..8].copy_from_slice(&0u16.to_be_bytes());

        Some((response, FRAME_HEADER_SIZE))
    }

    /// Make error response
    fn make_error_response(
        &self,
        sequence: u16,
        msg: &str,
    ) -> Option<([u8; MAX_RESPONSE_SIZE], usize)> {
        let msg_bytes = msg.as_bytes();
        let msg_len = msg_bytes.len().min(MAX_RESPONSE_SIZE - FRAME_HEADER_SIZE);

        let mut response = [0u8; MAX_RESPONSE_SIZE];
        response[0..2].copy_from_slice(&FRAME_MAGIC);
        response[2] = FRAME_ERROR;
        response[3] = 0;
        response[4..6].copy_from_slice(&sequence.to_be_bytes());
        response[6..8].copy_from_slice(&(msg_len as u16).to_be_bytes());
        response[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + msg_len]
            .copy_from_slice(&msg_bytes[..msg_len]);

        Some((response, FRAME_HEADER_SIZE + msg_len))
    }

    /// Get stats
    fn stats(&self) -> (u32, u32) {
        (self.request_count, self.decrypted_count)
    }
}

// Global state (single-threaded MCU)
static mut STATE: Option<SecureState> = None;
static mut MATRIX: Option<LedMatrix> = None;

/// Get mutable reference to global state
unsafe fn state() -> &'static mut SecureState {
    STATE.as_mut().expect("State not initialized")
}

/// Get mutable reference to the LED matrix
unsafe fn matrix() -> &'static mut LedMatrix {
    MATRIX.as_mut().expect("Matrix not initialized")
}

/// Show status on LED matrix
fn show_status(status: u8) {
    unsafe {
        let mut data: [[u8; 13]; 8] = [[0; 13]; 8];
        for i in 0..8 {
            data[0][i] = if status & (1 << (7 - i)) != 0 { 1 } else { 0 };
        }
        let frame = Frame::from_bitmap(&data);
        matrix().load_frame(&frame);
    }
}

/// Main entry point
#[no_mangle]
extern "C" fn rust_main() {
    unsafe {
        zephyr::set_logger().unwrap();
    }

    warn!("==============================================");
    warn!("  Secure Access - PQ-Ratchet for Arduino Uno Q");
    warn!("  Post-Quantum End-to-End Encrypted Streaming");
    warn!("==============================================");
    warn!("");
    warn!("Features:");
    warn!("  - X-Wing hybrid KEM (ML-KEM-768 + X25519)");
    warn!("  - PQ Double Ratchet with forward secrecy");
    warn!("  - SAGA anonymous credential verification");
    warn!("  - TrustZone ITS for state persistence");
    warn!("");

    // Initialize state
    warn!("Initializing secure state...");
    unsafe {
        STATE = Some(SecureState::new());
    }

    // Initialize ratchet handler (loads state from ITS if exists)
    warn!("Initializing PQ-Ratchet handler...");
    unsafe {
        if !state().init() {
            warn!("Failed to initialize ratchet handler!");
            loop {
                sleep(Duration::millis_at_least(1000));
            }
        }
    }
    warn!("PQ-Ratchet handler ready");

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

    // Show boot pattern
    show_status(0xFF);
    sleep(Duration::millis_at_least(200));
    show_status(0x00);

    // Initialize SPI transport
    warn!("Initializing SPI transport...");
    let mut spi = SpiTransport::new();
    if !spi.init() {
        warn!("Failed to initialize SPI!");
        loop {
            sleep(Duration::millis_at_least(1000));
        }
    }
    warn!("SPI initialized!");

    warn!("Secure Access responder ready, waiting for requests...");
    show_status(0x01); // Ready indicator

    // Prepare initial empty response
    let empty_response: [u8; 0] = [];
    spi.prepare_tx(&empty_response);

    let mut last_stats_time: u32 = 0;

    // Main loop
    loop {
        // Wait for SPI transfer from Linux (blocking)
        let rx_len = spi.transceive();

        if rx_len == 0 {
            // Empty transfer (polling from Linux)
            spi.prepare_tx(&empty_response);
            continue;
        }

        unsafe {
            state().request_count = state().request_count.wrapping_add(1);
        }

        // Read received data
        let mut rx_buffer = [0u8; MAX_FRAME_SIZE];
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

        let request_count = unsafe { state().request_count };

        // Log non-chunk frames
        let is_chunk = total_read >= 3 && rx_buffer[2] == FRAME_RATCHET_CHUNK;
        if !is_chunk || request_count % 30 == 0 {
            warn!("[{}] RX {} bytes", request_count, total_read);
        }

        // Process the frame
        unsafe {
            if let Some((response, response_len)) = state().process_frame(&rx_buffer[..total_read])
            {
                if !is_chunk || request_count % 30 == 0 {
                    warn!("[{}] TX {} bytes", request_count, response_len);
                }
                spi.prepare_tx(&response[..response_len]);

                // Update status LED
                match response[2] {
                    FRAME_HANDSHAKE_RESPONSE => {
                        show_status(0x0F); // Session established
                    }
                    FRAME_RATCHET_COMPLETE => {
                        let (_, decrypted) = state().stats();
                        show_status(if decrypted % 2 == 0 { 0x1F } else { 0x0F });
                    }
                    FRAME_ERROR => {
                        show_status(0x80); // Error
                    }
                    _ => {}
                }
            } else {
                spi.prepare_tx(&empty_response);
            }

            // Periodic stats logging
            if request_count - last_stats_time >= 100 {
                let (requests, decrypted) = state().stats();
                warn!(
                    "Stats: {} requests, {} messages decrypted",
                    requests, decrypted
                );
                last_stats_time = request_count;
            }
        }
    }
}
