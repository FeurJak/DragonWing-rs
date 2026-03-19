// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Error types for the Secure Relayer

use thiserror::Error;

/// Result type for relayer operations
pub type Result<T> = std::result::Result<T, RelayerError>;

/// Errors that can occur in the Secure Relayer
#[derive(Debug, Error)]
pub enum RelayerError {
    /// Not connected to MPU
    #[error("not connected to MPU")]
    NotConnected,

    /// No active PQ-Ratchet session
    #[error("no active PQ-Ratchet session")]
    NoSession,

    /// Connection error
    #[error("connection error: {0}")]
    Connection(String),

    /// WebSocket error
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    /// Handshake failed
    #[error("handshake failed: {0}")]
    Handshake(String),

    /// Protocol error
    #[error("protocol error: {0}")]
    Protocol(ProtocolError),

    /// Encryption error
    #[error("encryption error: {0}")]
    Encryption(String),

    /// Decryption error
    #[error("decryption error: {0}")]
    Decryption(String),

    /// X-Wing crypto error
    #[error("X-Wing error: {0}")]
    XWing(String),

    /// Chunking error
    #[error("chunking error: {0}")]
    Chunking(String),

    /// Timeout
    #[error("operation timed out")]
    Timeout,

    /// Invalid response from MCU
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// URL parse error
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
}

/// Protocol-level errors (matching MCU protocol.rs)
#[derive(Debug, Clone, Copy, Error)]
pub enum ProtocolError {
    /// Invalid frame magic
    #[error("invalid frame magic")]
    InvalidMagic,

    /// Frame too short
    #[error("frame too short")]
    FrameTooShort,

    /// Payload truncated
    #[error("payload truncated")]
    PayloadTruncated,

    /// Invalid handshake payload
    #[error("invalid handshake payload")]
    InvalidHandshake,

    /// SAGA verification failed
    #[error("SAGA verification failed")]
    SagaVerificationFailed,

    /// X-Wing operation failed
    #[error("X-Wing operation failed")]
    XWingError,

    /// Ratchet state error
    #[error("ratchet state error")]
    RatchetError,

    /// Chunk processing error
    #[error("chunk processing error")]
    ChunkError,

    /// Invalid frame type
    #[error("invalid frame type: {0}")]
    InvalidFrameType(u8),

    /// Unexpected response
    #[error("unexpected response type: expected {expected}, got {actual}")]
    UnexpectedResponse { expected: u8, actual: u8 },

    /// Sequence mismatch
    #[error("sequence mismatch: expected {expected}, got {actual}")]
    SequenceMismatch { expected: u16, actual: u16 },

    /// NACK received
    #[error("NACK received for chunk {chunk_index}")]
    NackReceived { chunk_index: u16 },

    /// Error response from MCU
    #[error("error response from MCU: code {code}")]
    McuError { code: u8 },
}

impl From<ProtocolError> for RelayerError {
    fn from(e: ProtocolError) -> Self {
        RelayerError::Protocol(e)
    }
}
