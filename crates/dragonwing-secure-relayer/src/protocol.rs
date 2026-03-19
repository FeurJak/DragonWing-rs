// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! SPI Frame Protocol for Secure Relayer
//!
//! This module mirrors the MCU protocol format for interoperability.
//! Frames are sent over WebSocket to the MPU proxy, which forwards
//! them over SPI to the MCU.
//!
//! # Frame Format
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Frame Header (8 bytes)                                         │
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

use crate::error::ProtocolError;

// ============================================================================
// Frame Constants (matching MCU protocol.rs)
// ============================================================================

/// Magic bytes identifying a PQ-Ratchet frame ("PQ")
pub const FRAME_MAGIC: [u8; 2] = [0x50, 0x51];

/// Frame header size in bytes
pub const FRAME_HEADER_SIZE: usize = 8;

/// Maximum frame size (header + payload)
pub const MAX_FRAME_SIZE: usize = 2048;

/// Maximum response size
pub const MAX_RESPONSE_SIZE: usize = 2500;

// ============================================================================
// Frame Types (matching MCU protocol.rs)
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
// Handshake Payload Sizes
// ============================================================================

/// Handshake init minimum size (X-Wing public key)
pub const HANDSHAKE_INIT_MIN_SIZE: usize = xwing::PUBLIC_KEY_SIZE;

/// Handshake response size (ciphertext + public key)
pub const HANDSHAKE_RESPONSE_SIZE: usize = xwing::CIPHERTEXT_SIZE + xwing::PUBLIC_KEY_SIZE;

// ============================================================================
// Frame Builder
// ============================================================================

/// Builder for constructing protocol frames
pub struct FrameBuilder {
    buffer: Vec<u8>,
    sequence: u16,
}

impl FrameBuilder {
    /// Create a new frame builder
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(MAX_FRAME_SIZE),
            sequence: 0,
        }
    }

    /// Get and increment sequence number
    pub fn next_sequence(&mut self) -> u16 {
        let seq = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        seq
    }

    /// Reset sequence counter
    pub fn reset_sequence(&mut self) {
        self.sequence = 0;
    }

    /// Build a handshake init frame
    pub fn build_handshake_init(&mut self, public_key: &[u8]) -> Vec<u8> {
        let seq = self.next_sequence();
        self.build_frame(FRAME_HANDSHAKE_INIT, 0, seq, public_key)
    }

    /// Build a ratchet chunk frame
    pub fn build_chunk(&mut self, chunk_data: &[u8]) -> Vec<u8> {
        let seq = self.next_sequence();
        self.build_frame(FRAME_RATCHET_CHUNK, 0, seq, chunk_data)
    }

    /// Build a ping frame
    pub fn build_ping(&mut self) -> Vec<u8> {
        let seq = self.next_sequence();
        self.build_frame(FRAME_PING, 0, seq, &[])
    }

    /// Build a generic frame
    fn build_frame(&mut self, frame_type: u8, flags: u8, sequence: u16, payload: &[u8]) -> Vec<u8> {
        self.buffer.clear();

        // Header
        self.buffer.extend_from_slice(&FRAME_MAGIC);
        self.buffer.push(frame_type);
        self.buffer.push(flags);
        self.buffer.extend_from_slice(&sequence.to_be_bytes());
        self.buffer
            .extend_from_slice(&(payload.len() as u16).to_be_bytes());

        // Payload
        self.buffer.extend_from_slice(payload);

        self.buffer.clone()
    }
}

impl Default for FrameBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Frame Parser
// ============================================================================

/// Parsed frame header
#[derive(Debug, Clone, Copy)]
pub struct FrameHeader {
    pub frame_type: u8,
    pub flags: u8,
    pub sequence: u16,
    pub payload_len: u16,
}

/// A complete parsed frame
#[derive(Debug)]
pub struct Frame<'a> {
    pub header: FrameHeader,
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Parse a frame from bytes
    pub fn parse(data: &'a [u8]) -> Result<Self, ProtocolError> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err(ProtocolError::FrameTooShort);
        }

        if data[0..2] != FRAME_MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }

        let header = FrameHeader {
            frame_type: data[2],
            flags: data[3],
            sequence: u16::from_be_bytes([data[4], data[5]]),
            payload_len: u16::from_be_bytes([data[6], data[7]]),
        };

        let expected_len = FRAME_HEADER_SIZE + header.payload_len as usize;
        if data.len() < expected_len {
            return Err(ProtocolError::PayloadTruncated);
        }

        let payload = &data[FRAME_HEADER_SIZE..expected_len];

        Ok(Frame { header, payload })
    }

    /// Check if this is a handshake response
    pub fn is_handshake_response(&self) -> bool {
        self.header.frame_type == FRAME_HANDSHAKE_RESPONSE
    }

    /// Check if this is an ACK
    pub fn is_ack(&self) -> bool {
        self.header.frame_type == FRAME_RATCHET_ACK
    }

    /// Check if this is a NACK
    pub fn is_nack(&self) -> bool {
        self.header.frame_type == FRAME_RATCHET_NACK
    }

    /// Check if this is an error
    pub fn is_error(&self) -> bool {
        self.header.frame_type == FRAME_ERROR
    }

    /// Check if this is a complete notification
    pub fn is_complete(&self) -> bool {
        self.header.frame_type == FRAME_RATCHET_COMPLETE
    }

    /// Get ACK chunk index from payload
    pub fn ack_chunk_index(&self) -> Option<u16> {
        if self.is_ack() && self.payload.len() >= 2 {
            Some(u16::from_be_bytes([self.payload[0], self.payload[1]]))
        } else {
            None
        }
    }

    /// Get NACK chunk index from payload
    pub fn nack_chunk_index(&self) -> Option<u16> {
        if self.is_nack() && self.payload.len() >= 2 {
            Some(u16::from_be_bytes([self.payload[0], self.payload[1]]))
        } else {
            None
        }
    }

    /// Get error code from payload
    pub fn error_code(&self) -> Option<u8> {
        if self.is_error() && !self.payload.is_empty() {
            Some(self.payload[0])
        } else {
            None
        }
    }
}

// ============================================================================
// Handshake Response Parser
// ============================================================================

/// Parsed handshake response from MCU
#[derive(Debug)]
pub struct HandshakeResponse {
    /// X-Wing ciphertext (1120 bytes)
    pub ciphertext: [u8; xwing::CIPHERTEXT_SIZE],
    /// MCU's X-Wing public key for future ratchet steps (1216 bytes)
    pub mcu_public_key: [u8; xwing::PUBLIC_KEY_SIZE],
}

impl HandshakeResponse {
    /// Parse a handshake response from the frame payload
    pub fn from_payload(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < HANDSHAKE_RESPONSE_SIZE {
            return Err(ProtocolError::InvalidHandshake);
        }

        let mut ciphertext = [0u8; xwing::CIPHERTEXT_SIZE];
        ciphertext.copy_from_slice(&payload[..xwing::CIPHERTEXT_SIZE]);

        let mut mcu_public_key = [0u8; xwing::PUBLIC_KEY_SIZE];
        mcu_public_key.copy_from_slice(
            &payload[xwing::CIPHERTEXT_SIZE..xwing::CIPHERTEXT_SIZE + xwing::PUBLIC_KEY_SIZE],
        );

        Ok(HandshakeResponse {
            ciphertext,
            mcu_public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let mut builder = FrameBuilder::new();

        let payload = b"Hello, MCU!";
        let frame_bytes = builder.build_chunk(payload);

        let frame = Frame::parse(&frame_bytes).unwrap();

        assert_eq!(frame.header.frame_type, FRAME_RATCHET_CHUNK);
        assert_eq!(frame.header.sequence, 0);
        assert_eq!(frame.header.payload_len, payload.len() as u16);
        assert_eq!(frame.payload, payload);
    }

    #[test]
    fn test_handshake_init_frame() {
        let mut builder = FrameBuilder::new();

        // Fake public key (normally 1216 bytes)
        let fake_pk = [0xAA; 32];
        let frame_bytes = builder.build_handshake_init(&fake_pk);

        let frame = Frame::parse(&frame_bytes).unwrap();

        assert_eq!(frame.header.frame_type, FRAME_HANDSHAKE_INIT);
        assert_eq!(frame.payload, &fake_pk);
    }

    #[test]
    fn test_sequence_increment() {
        let mut builder = FrameBuilder::new();

        let _ = builder.build_ping();
        assert_eq!(builder.sequence, 1);

        let _ = builder.build_ping();
        assert_eq!(builder.sequence, 2);

        builder.reset_sequence();
        assert_eq!(builder.sequence, 0);
    }

    #[test]
    fn test_invalid_magic() {
        let bad_frame = [0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = Frame::parse(&bad_frame);
        assert!(matches!(result, Err(ProtocolError::InvalidMagic)));
    }

    #[test]
    fn test_frame_too_short() {
        let short_frame = [0x50, 0x51, 0x10];
        let result = Frame::parse(&short_frame);
        assert!(matches!(result, Err(ProtocolError::FrameTooShort)));
    }
}
