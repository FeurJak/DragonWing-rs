// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! WebSocket Transport for Secure Relayer
//!
//! This module provides the WebSocket client for communicating with the
//! MPU (Linux proxy) which forwards frames to the MCU over SPI.
//!
//! # Architecture
//!
//! ```text
//! Secure-Relayer (macOS)
//!       │
//!       │ WebSocket (binary frames)
//!       ▼
//! MPU Proxy (Linux)
//!       │
//!       │ SPI frames
//!       ▼
//! MCU (TrustZone)
//! ```
//!
//! The transport layer handles:
//! - WebSocket connection management
//! - Binary frame encoding/decoding
//! - Send/receive with protocol framing

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
};

use crate::error::{ProtocolError, RelayerError, Result};
use crate::protocol::{
    Frame, FrameBuilder, FRAME_ERROR, FRAME_HANDSHAKE_RESPONSE, FRAME_RATCHET_ACK,
    FRAME_RATCHET_COMPLETE, FRAME_RATCHET_NACK,
};

// ============================================================================
// MPU Transport
// ============================================================================

/// WebSocket transport to the MPU proxy
pub struct MpuTransport {
    /// WebSocket stream
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    /// Frame builder for constructing protocol frames
    frame_builder: FrameBuilder,
    /// Connection URL (for logging/reconnect)
    url: String,
}

impl MpuTransport {
    /// Connect to the MPU proxy via WebSocket
    pub async fn connect(url: &str) -> Result<Self> {
        log::debug!("Connecting to MPU at {}", url);

        let (ws, response) = connect_async(url)
            .await
            .map_err(|e| RelayerError::Connection(format!("WebSocket connect failed: {}", e)))?;

        log::debug!(
            "WebSocket connected (status: {})",
            response.status().as_u16()
        );

        Ok(Self {
            ws,
            frame_builder: FrameBuilder::new(),
            url: url.to_string(),
        })
    }

    /// Send handshake init and wait for response
    ///
    /// Returns the handshake response payload (ciphertext + MCU public key).
    pub async fn send_handshake_init(&mut self, public_key: &[u8]) -> Result<Vec<u8>> {
        // Build the handshake init frame
        let frame = self.frame_builder.build_handshake_init(public_key);

        log::debug!(
            "Sending handshake init ({} bytes, pk={} bytes)",
            frame.len(),
            public_key.len()
        );

        // Send the frame
        self.ws
            .send(Message::Binary(frame))
            .await
            .map_err(RelayerError::WebSocket)?;

        // Wait for handshake response
        let response = self.recv_frame().await?;

        // Validate response type
        if response.header.frame_type != FRAME_HANDSHAKE_RESPONSE {
            if response.header.frame_type == FRAME_ERROR {
                let code = response.error_code().unwrap_or(0);
                return Err(ProtocolError::McuError { code }.into());
            }
            return Err(ProtocolError::UnexpectedResponse {
                expected: FRAME_HANDSHAKE_RESPONSE,
                actual: response.header.frame_type,
            }
            .into());
        }

        log::debug!(
            "Received handshake response ({} bytes payload)",
            response.payload.len()
        );

        Ok(response.payload.to_vec())
    }

    /// Send a chunk and wait for ACK
    pub async fn send_chunk(&mut self, chunk_data: &[u8]) -> Result<()> {
        // Build chunk frame
        let frame = self.frame_builder.build_chunk(chunk_data);

        log::trace!(
            "Sending chunk ({} bytes data, {} bytes frame)",
            chunk_data.len(),
            frame.len()
        );

        // Send the frame
        self.ws
            .send(Message::Binary(frame))
            .await
            .map_err(RelayerError::WebSocket)?;

        // Wait for ACK
        let response = self.recv_frame().await?;

        match response.header.frame_type {
            FRAME_RATCHET_ACK => {
                log::trace!("Received ACK for chunk");
                Ok(())
            }
            FRAME_RATCHET_NACK => {
                let chunk_index = response.nack_chunk_index().unwrap_or(0);
                Err(ProtocolError::NackReceived { chunk_index }.into())
            }
            FRAME_RATCHET_COMPLETE => {
                // MCU has completed reassembly and decryption
                log::debug!("MCU signaled message complete");
                Ok(())
            }
            FRAME_ERROR => {
                let code = response.error_code().unwrap_or(0);
                Err(ProtocolError::McuError { code }.into())
            }
            _ => Err(ProtocolError::UnexpectedResponse {
                expected: FRAME_RATCHET_ACK,
                actual: response.header.frame_type,
            }
            .into()),
        }
    }

    /// Send a ping and wait for pong
    pub async fn ping(&mut self) -> Result<()> {
        let frame = self.frame_builder.build_ping();

        self.ws
            .send(Message::Binary(frame))
            .await
            .map_err(RelayerError::WebSocket)?;

        let response = self.recv_frame().await?;

        if response.header.frame_type == crate::protocol::FRAME_PONG {
            Ok(())
        } else {
            Err(ProtocolError::UnexpectedResponse {
                expected: crate::protocol::FRAME_PONG,
                actual: response.header.frame_type,
            }
            .into())
        }
    }

    /// Receive a frame from the WebSocket
    async fn recv_frame(&mut self) -> Result<OwnedFrame> {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Binary(data))) => {
                    // Parse the frame
                    let frame = Frame::parse(&data)?;
                    return Ok(OwnedFrame::from_frame(&frame, &data));
                }
                Some(Ok(Message::Ping(data))) => {
                    // Respond to ping
                    self.ws
                        .send(Message::Pong(data))
                        .await
                        .map_err(RelayerError::WebSocket)?;
                }
                Some(Ok(Message::Pong(_))) => {
                    // Ignore pongs
                    continue;
                }
                Some(Ok(Message::Close(frame))) => {
                    log::info!("WebSocket closed: {:?}", frame);
                    return Err(RelayerError::Connection("connection closed".to_string()));
                }
                Some(Ok(Message::Text(text))) => {
                    log::warn!("Unexpected text message: {}", text);
                    continue;
                }
                Some(Ok(Message::Frame(_))) => {
                    // Raw frame, ignore
                    continue;
                }
                Some(Err(e)) => {
                    return Err(RelayerError::WebSocket(e));
                }
                None => {
                    return Err(RelayerError::Connection("stream ended".to_string()));
                }
            }
        }
    }

    /// Close the WebSocket connection
    pub async fn close(mut self) -> Result<()> {
        log::debug!("Closing WebSocket connection");

        self.ws
            .close(None)
            .await
            .map_err(RelayerError::WebSocket)?;

        Ok(())
    }

    /// Get the connection URL
    pub fn url(&self) -> &str {
        &self.url
    }
}

// ============================================================================
// Owned Frame (for returning from recv)
// ============================================================================

/// An owned version of Frame for returning from async functions
#[derive(Debug)]
struct OwnedFrame {
    pub header: crate::protocol::FrameHeader,
    pub payload: Vec<u8>,
}

impl OwnedFrame {
    fn from_frame(frame: &Frame<'_>, _raw: &[u8]) -> Self {
        Self {
            header: frame.header,
            payload: frame.payload.to_vec(),
        }
    }

    fn error_code(&self) -> Option<u8> {
        if self.header.frame_type == FRAME_ERROR && !self.payload.is_empty() {
            Some(self.payload[0])
        } else {
            None
        }
    }

    fn nack_chunk_index(&self) -> Option<u16> {
        if self.header.frame_type == FRAME_RATCHET_NACK && self.payload.len() >= 2 {
            Some(u16::from_be_bytes([self.payload[0], self.payload[1]]))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    // Transport tests would require a mock WebSocket server
    // For now, we test the frame building/parsing in protocol.rs
}
