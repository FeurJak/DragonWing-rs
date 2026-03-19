// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! DragonWing Secure Relayer
//!
//! This crate provides the Secure-Relayer component that bridges encrypted
//! data from the user-devices to the Arduino MCU using the PQ-Ratchet protocol.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │  Secure-Relayer (this crate)                                        │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐  │
//! │  │  BPP Receiver   │    │  PQ-Ratchet     │    │  WebSocket      │  │
//! │  │ (from device)   │───►│  Encryptor      │───►│  Client         │  │
//! │  │                 │    │  + Chunker      │    │  (to MPU)       │  │
//! │  └─────────────────┘    └─────────────────┘    └─────────────────┘  │
//! │                                                                     │
//! │  ┌─────────────────┐                                                │
//! │  │  Session        │  Manages X-Wing keypair, ratchet state,        │
//! │  │  Manager        │  handshake with MCU                            │
//! │  └─────────────────┘                                                │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use dragonwing_secure_relayer::{SecureRelayer, Config};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = Config {
//!         mpu_address: "ws://192.168.1.100:8080".to_string(),
//!         ..Default::default()
//!     };
//!
//!     let mut relayer = SecureRelayer::new(config);
//!
//!     // Establish session with MCU
//!     relayer.connect().await?;
//!     relayer.handshake().await?;
//!
//!     // Send encrypted data
//!     let plaintext = b"Hello, MCU!";
//!     relayer.send_encrypted(plaintext).await?;
//!
//!     Ok(())
//! }
//! ```

pub mod error;
pub mod protocol;
pub mod ratchet_session;
pub mod transport;

pub use error::{RelayerError, Result};
pub use ratchet_session::RatchetSession;
pub use transport::MpuTransport;

/// Relayer configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// WebSocket address of the MPU proxy (e.g., "ws://192.168.1.100:8080")
    pub mpu_address: String,
    /// Connection timeout in seconds
    pub connect_timeout_secs: u64,
    /// Maximum message size before chunking (bytes)
    pub max_message_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mpu_address: "ws://localhost:8080".to_string(),
            connect_timeout_secs: 10,
            max_message_size: 128 * 1024, // 128KB
        }
    }
}

/// Main Secure Relayer service
pub struct SecureRelayer {
    config: Config,
    session: Option<RatchetSession>,
    transport: Option<MpuTransport>,
}

impl SecureRelayer {
    /// Create a new relayer with the given configuration
    pub fn new(config: Config) -> Self {
        Self {
            config,
            session: None,
            transport: None,
        }
    }

    /// Connect to the MPU proxy via WebSocket
    pub async fn connect(&mut self) -> Result<()> {
        log::info!("Connecting to MPU at {}", self.config.mpu_address);

        let transport = MpuTransport::connect(&self.config.mpu_address).await?;
        self.transport = Some(transport);

        log::info!("Connected to MPU");
        Ok(())
    }

    /// Perform handshake with MCU to establish PQ-Ratchet session
    pub async fn handshake(&mut self) -> Result<()> {
        let transport = self
            .transport
            .as_mut()
            .ok_or(RelayerError::NotConnected)?;

        log::info!("Initiating PQ-Ratchet handshake...");

        // Create new ratchet session (generates X-Wing keypair)
        let mut session = RatchetSession::new()?;

        // Build handshake init message
        let init_payload = session.build_handshake_init()?;

        // Send to MCU via MPU proxy
        let response = transport.send_handshake_init(&init_payload).await?;

        // Process response (X-Wing decapsulation, initialize ratchet)
        session.process_handshake_response(&response)?;

        log::info!("PQ-Ratchet session established");
        log::info!("  Epoch: {}", session.epoch());

        self.session = Some(session);
        Ok(())
    }

    /// Send encrypted data to MCU
    ///
    /// The data is encrypted with PQ-Ratchet, chunked, and sent via WebSocket.
    pub async fn send_encrypted(&mut self, plaintext: &[u8]) -> Result<()> {
        let session = self.session.as_mut().ok_or(RelayerError::NoSession)?;
        let transport = self
            .transport
            .as_mut()
            .ok_or(RelayerError::NotConnected)?;

        // Encrypt with ratchet
        let encrypted = session.encrypt(plaintext)?;

        // Chunk the encrypted message
        let chunks = session.chunk(&encrypted)?;

        log::debug!(
            "Sending {} bytes in {} chunks",
            plaintext.len(),
            chunks.len()
        );

        // Send each chunk
        for chunk in chunks {
            transport.send_chunk(&chunk).await?;
        }

        Ok(())
    }

    /// Check if session is established
    pub fn is_connected(&self) -> bool {
        self.session.is_some() && self.transport.is_some()
    }

    /// Get current ratchet epoch
    pub fn epoch(&self) -> Option<u64> {
        self.session.as_ref().map(|s| s.epoch())
    }

    /// Close the connection
    pub async fn close(&mut self) -> Result<()> {
        if let Some(transport) = self.transport.take() {
            transport.close().await?;
        }
        self.session = None;
        Ok(())
    }
}
