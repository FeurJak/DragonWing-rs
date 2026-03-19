// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! PQ-Ratchet Proxy for MPU
//!
//! WebSocket-to-SPI bridge that forwards PQ-Ratchet frames from the
//! Secure-Relayer to the MCU.
//!
//! # Architecture
//!
//! ```text
//! Secure-Relayer (macOS)
//!       │
//!       │ WebSocket (binary frames)
//!       ▼
//! ┌─────────────────────┐
//! │  pq-proxy (this)    │  MPU (QRB2210 Linux)
//! │  - WebSocket server │
//! │  - SPI controller   │
//! └─────────────────────┘
//!       │
//!       │ SPI (/dev/spidev0.0)
//!       ▼
//! MCU (STM32U585 TrustZone)
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};

#[cfg(feature = "spi")]
use dragonwing_spi::{SpiController, SpiFrame, FRAME_HEADER_SIZE, MAX_PAYLOAD_SIZE};

/// PQ-Ratchet WebSocket-to-SPI Proxy
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// WebSocket listen address
    #[arg(short, long, default_value = "0.0.0.0:8080")]
    listen: String,

    /// SPI device path
    #[arg(short, long, default_value = "/dev/spidev0.0")]
    spi_device: String,

    /// SPI clock speed in Hz
    #[arg(short = 'c', long, default_value = "1000000")]
    spi_speed: u32,

    /// Mock SPI (for testing without hardware)
    #[arg(long)]
    mock_spi: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

/// SPI interface abstraction (real or mock)
enum SpiInterface {
    #[cfg(feature = "spi")]
    Real(SpiController),
    Mock(MockSpi),
}

impl SpiInterface {
    fn transfer(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            #[cfg(feature = "spi")]
            SpiInterface::Real(spi) => spi
                .transfer(data)
                .map_err(|e| anyhow::anyhow!("SPI error: {}", e)),
            SpiInterface::Mock(mock) => mock.transfer(data),
        }
    }
}

/// Mock SPI for testing without hardware
struct MockSpi {
    /// Simulated MCU state
    handshake_done: bool,
}

impl MockSpi {
    fn new() -> Self {
        Self {
            handshake_done: false,
        }
    }

    fn transfer(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        // Parse PQ-Ratchet frame from data
        if data.len() < 8 {
            return Ok(vec![]);
        }

        // Check for "PQ" magic
        if data[0] == 0x50 && data[1] == 0x51 {
            let frame_type = data[2];

            match frame_type {
                0x10 => {
                    // HANDSHAKE_INIT - respond with mock handshake response
                    info!("[MockSPI] Received handshake init, sending mock response");
                    self.handshake_done = true;

                    // Build mock response: header + fake ciphertext + fake public key
                    let mut response = vec![0u8; 8 + 1120 + 1216]; // header + ct + pk

                    // PQ magic
                    response[0] = 0x50;
                    response[1] = 0x51;
                    // Frame type: HANDSHAKE_RESPONSE
                    response[2] = 0x11;
                    // Flags
                    response[3] = 0x00;
                    // Sequence
                    response[4] = 0x00;
                    response[5] = 0x00;
                    // Payload length (ct + pk = 2336)
                    let payload_len: u16 = 1120 + 1216;
                    response[6] = (payload_len >> 8) as u8;
                    response[7] = (payload_len & 0xFF) as u8;

                    // Fill with deterministic "random" data for testing
                    for i in 8..response.len() {
                        response[i] = ((i * 17 + 42) % 256) as u8;
                    }

                    Ok(response)
                }
                0x20 => {
                    // RATCHET_CHUNK - respond with ACK
                    debug!("[MockSPI] Received chunk, sending ACK");

                    let seq_hi = data[4];
                    let seq_lo = data[5];

                    // ACK response
                    let mut response = vec![0u8; 10];
                    response[0] = 0x50; // PQ
                    response[1] = 0x51;
                    response[2] = 0x21; // RATCHET_ACK
                    response[3] = 0x00;
                    response[4] = seq_hi;
                    response[5] = seq_lo;
                    response[6] = 0x00; // payload len = 2
                    response[7] = 0x02;
                    // Chunk index acknowledged
                    response[8] = data[8]; // Copy chunk index from incoming
                    response[9] = data[9];

                    Ok(response)
                }
                0xF0 => {
                    // PING - respond with PONG
                    debug!("[MockSPI] Received ping, sending pong");

                    let mut response = vec![0u8; 8];
                    response[0] = 0x50;
                    response[1] = 0x51;
                    response[2] = 0xF1; // PONG
                    response[3] = 0x00;
                    response[4] = data[4];
                    response[5] = data[5];
                    response[6] = 0x00;
                    response[7] = 0x00;

                    Ok(response)
                }
                _ => {
                    warn!("[MockSPI] Unknown frame type: 0x{:02X}", frame_type);
                    Ok(vec![])
                }
            }
        } else {
            debug!("[MockSPI] Non-PQ frame received");
            Ok(vec![])
        }
    }
}

/// Handle a single WebSocket connection
async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    spi: Arc<Mutex<SpiInterface>>,
) -> Result<()> {
    info!("New connection from {}", addr);

    let ws_stream = accept_async(stream)
        .await
        .context("Failed to accept WebSocket connection")?;

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    while let Some(msg) = ws_receiver.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                debug!("Received {} bytes from {}", data.len(), addr);

                // Forward to SPI
                let mut spi = spi.lock().await;
                match spi.transfer(&data) {
                    Ok(response) => {
                        if !response.is_empty() {
                            debug!("Sending {} bytes response to {}", response.len(), addr);
                            ws_sender
                                .send(Message::Binary(response))
                                .await
                                .context("Failed to send WebSocket response")?;
                        }
                    }
                    Err(e) => {
                        error!("SPI transfer error: {}", e);
                        // Send error frame back
                        let error_frame = build_error_frame(0x01);
                        ws_sender
                            .send(Message::Binary(error_frame))
                            .await
                            .context("Failed to send error response")?;
                    }
                }
            }
            Ok(Message::Ping(data)) => {
                ws_sender
                    .send(Message::Pong(data))
                    .await
                    .context("Failed to send pong")?;
            }
            Ok(Message::Close(_)) => {
                info!("Connection closed by {}", addr);
                break;
            }
            Ok(_) => {
                // Ignore text messages, pongs, etc.
            }
            Err(e) => {
                error!("WebSocket error from {}: {}", addr, e);
                break;
            }
        }
    }

    info!("Connection ended: {}", addr);
    Ok(())
}

/// Build a PQ-Ratchet error frame
fn build_error_frame(error_code: u8) -> Vec<u8> {
    vec![
        0x50, 0x51, // Magic "PQ"
        0xFF, // FRAME_ERROR
        0x00, // Flags
        0x00, 0x00, // Sequence
        0x00, 0x01, // Payload length = 1
        error_code, // Error code
    ]
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    info!("PQ-Ratchet Proxy starting...");
    info!("  WebSocket: {}", args.listen);
    info!("  SPI: {} @ {} Hz", args.spi_device, args.spi_speed);
    info!("  Mock SPI: {}", args.mock_spi);

    // Initialize SPI
    let spi: SpiInterface = if args.mock_spi {
        info!("Using mock SPI (no hardware)");
        SpiInterface::Mock(MockSpi::new())
    } else {
        #[cfg(feature = "spi")]
        {
            info!("Opening SPI device: {}", args.spi_device);
            let controller = SpiController::new(&args.spi_device, args.spi_speed)
                .map_err(|e| anyhow::anyhow!("Failed to open SPI: {}", e))?;
            SpiInterface::Real(controller)
        }
        #[cfg(not(feature = "spi"))]
        {
            warn!("SPI feature not enabled, using mock SPI");
            SpiInterface::Mock(MockSpi::new())
        }
    };

    let spi = Arc::new(Mutex::new(spi));

    // Start WebSocket server
    let listener = TcpListener::bind(&args.listen)
        .await
        .context("Failed to bind WebSocket listener")?;

    info!("Listening for connections on {}", args.listen);

    while let Ok((stream, addr)) = listener.accept().await {
        let spi = spi.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, addr, spi).await {
                error!("Connection handler error: {}", e);
            }
        });
    }

    Ok(())
}
