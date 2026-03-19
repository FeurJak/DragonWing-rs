// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! SPI Frame Protocol for PQ-Ratchet Communication
//!
//! This module defines the wire format for communication between
//! the MPU (Linux proxy) and MCU (TrustZone secure world).
//!
//! # Frame Format
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  SPI Frame Header (8 bytes)                                     │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  [0..2]   Magic (0x5051 = "PQ")                                 │
//! │  [2]      Frame Type                                            │
//! │  [3]      Flags                                                 │
//! │  [4..6]   Sequence Number (u16 BE)                              │
//! │  [6..8]   Payload Length (u16 BE)                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Payload (variable length)                                      │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use dragonwing_crypto::post_quantum::xwing;

// ============================================================================
// Frame Constants
// ============================================================================

/// Magic bytes identifying a PQ-Ratchet frame ("PQ")
pub const FRAME_MAGIC: [u8; 2] = [0x50, 0x51];

/// Frame header size in bytes
pub const FRAME_HEADER_SIZE: usize = 8;

/// Maximum frame size (header + payload)
/// Large enough for X-Wing public key (1216) + SAGA presentation (~500) + header
pub const MAX_FRAME_SIZE: usize = 2048;

/// Maximum response size (header + X-Wing ciphertext + new PK)
/// X-Wing ciphertext (1120) + X-Wing public key (1216) + overhead
pub const MAX_RESPONSE_SIZE: usize = 2500;

// ============================================================================
// Frame Types
// ============================================================================

/// Handshake init: X-Wing PK + optional SAGA presentation
pub const FRAME_HANDSHAKE_INIT: u8 = 0x10;

/// Handshake response: X-Wing ciphertext + new PK for ratchet
pub const FRAME_HANDSHAKE_RESPONSE: u8 = 0x11;

/// PQ-Ratchet encrypted chunk
pub const FRAME_RATCHET_CHUNK: u8 = 0x20;

/// Chunk acknowledgment
pub const FRAME_RATCHET_ACK: u8 = 0x21;

/// Request retransmit of specific chunk
pub const FRAME_RATCHET_NACK: u8 = 0x22;

/// Message reassembly complete
pub const FRAME_RATCHET_COMPLETE: u8 = 0x23;

/// Ping request
pub const FRAME_PING: u8 = 0xF0;

/// Pong response
pub const FRAME_PONG: u8 = 0xF1;

/// Error response
pub const FRAME_ERROR: u8 = 0xFF;

// ============================================================================
// Handshake Payload Formats
// ============================================================================

/// Handshake init payload format:
/// ```text
/// [0..1216]    X-Wing Public Key (required)
/// [1216..]     SAGA Presentation (optional, for authenticated sessions)
/// ```
pub const HANDSHAKE_INIT_MIN_SIZE: usize = xwing::PUBLIC_KEY_SIZE;

/// Handshake response payload format:
/// ```text
/// [0..1120]    X-Wing Ciphertext
/// [1120..2336] New X-Wing Public Key (for ratchet)
/// ```
pub const HANDSHAKE_RESPONSE_SIZE: usize = xwing::CIPHERTEXT_SIZE + xwing::PUBLIC_KEY_SIZE;

// ============================================================================
// Chunk Status
// ============================================================================

/// Status returned after processing a chunk
#[derive(Debug, Clone, Copy)]
pub enum ChunkStatus {
    /// Need more chunks to complete message
    NeedMore { chunk_index: u16 },
    /// Message reassembly and decryption complete
    Complete { plaintext_len: usize },
    /// Duplicate chunk received
    Duplicate { chunk_index: u16 },
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during protocol handling
#[derive(Debug, Clone, Copy)]
pub enum ProtocolError {
    /// Invalid frame magic
    InvalidMagic,
    /// Frame too short
    FrameTooShort,
    /// Payload truncated
    PayloadTruncated,
    /// Invalid handshake payload
    InvalidHandshake,
    /// SAGA verification failed
    SagaVerificationFailed,
    /// X-Wing operation failed
    XWingError,
    /// Ratchet state error
    RatchetError,
    /// Chunk processing error
    ChunkError,
    /// ITS storage error
    StorageError,
    /// Session not established
    NoSession,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Encode a frame header
pub fn encode_header(
    frame_type: u8,
    flags: u8,
    sequence: u16,
    payload_len: u16,
    buf: &mut [u8],
) -> usize {
    if buf.len() < FRAME_HEADER_SIZE {
        return 0;
    }

    buf[0..2].copy_from_slice(&FRAME_MAGIC);
    buf[2] = frame_type;
    buf[3] = flags;
    buf[4..6].copy_from_slice(&sequence.to_be_bytes());
    buf[6..8].copy_from_slice(&payload_len.to_be_bytes());

    FRAME_HEADER_SIZE
}

/// Decode a frame header
pub fn decode_header(buf: &[u8]) -> Result<(u8, u8, u16, u16), ProtocolError> {
    if buf.len() < FRAME_HEADER_SIZE {
        return Err(ProtocolError::FrameTooShort);
    }

    if buf[0..2] != FRAME_MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }

    let frame_type = buf[2];
    let flags = buf[3];
    let sequence = u16::from_be_bytes([buf[4], buf[5]]);
    let payload_len = u16::from_be_bytes([buf[6], buf[7]]);

    Ok((frame_type, flags, sequence, payload_len))
}
