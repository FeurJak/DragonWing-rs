// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// DragonWing SPI Router
//
// A Rust-based SPI router for the DragonWing platform that communicates with
// the MCU via SPI and provides a Unix socket interface for RPC clients.
//
// Platform: MPU-only (Linux, aarch64 - QRB2210)

mod rpc;

use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info, warn};
use rpc::{decode_message, RpcMessage, RpcRequest, RpcResponse};
use spidev::{SpiModeFlags, Spidev, SpidevOptions, SpidevTransfer};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Frame protocol constants
const FRAME_MAGIC: u16 = 0xAA55;
const FRAME_HEADER_SIZE: usize = 4;
const SPI_BUFFER_SIZE: usize = 512;

/// CLI arguments
#[derive(Parser, Debug)]
#[command(name = "spi-router")]
#[command(about = "SPI-based RPC router for DragonWing (MPU)")]
struct Args {
    /// SPI device path
    #[arg(short, long, default_value = "/dev/spidev0.0")]
    spi_device: PathBuf,

    /// SPI speed in Hz
    #[arg(short = 'f', long, default_value_t = 1_000_000)]
    spi_speed: u32,

    /// Unix socket path for RPC clients
    #[arg(short, long, default_value = "/var/run/dragonwing-spi-router.sock")]
    unix_socket: PathBuf,

    /// Polling interval in milliseconds
    #[arg(short, long, default_value_t = 10)]
    poll_interval: u64,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Test mode: send test messages to MCU
    #[arg(short, long)]
    test_mode: bool,
}

/// Frame for SPI communication
#[derive(Debug, Clone)]
struct SpiFrame {
    magic: u16,
    length: u16,
    payload: Vec<u8>,
}

impl SpiFrame {
    fn new() -> Self {
        Self {
            magic: FRAME_MAGIC,
            length: 0,
            payload: Vec::new(),
        }
    }

    fn with_payload(payload: &[u8]) -> Self {
        Self {
            magic: FRAME_MAGIC,
            length: payload.len() as u16,
            payload: payload.to_vec(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; SPI_BUFFER_SIZE];
        buf[0] = (self.magic >> 8) as u8;
        buf[1] = self.magic as u8;
        buf[2] = (self.length >> 8) as u8;
        buf[3] = self.length as u8;

        let copy_len = self.payload.len().min(SPI_BUFFER_SIZE - FRAME_HEADER_SIZE);
        buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + copy_len]
            .copy_from_slice(&self.payload[..copy_len]);

        buf
    }

    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < FRAME_HEADER_SIZE {
            return None;
        }

        let magic = ((data[0] as u16) << 8) | (data[1] as u16);
        if magic != FRAME_MAGIC {
            return None;
        }

        let length = ((data[2] as u16) << 8) | (data[3] as u16);
        if length as usize > SPI_BUFFER_SIZE - FRAME_HEADER_SIZE {
            return None;
        }

        let payload = data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + length as usize].to_vec();

        Some(Self {
            magic,
            length,
            payload,
        })
    }

    fn is_empty(&self) -> bool {
        self.length == 0
    }
}

/// SPI communication handler
struct SpiHandler {
    spi: Spidev,
    tx_buffer: Vec<u8>,
    rx_buffer: Vec<u8>,
}

impl SpiHandler {
    fn new(device_path: &PathBuf, speed_hz: u32) -> Result<Self> {
        let mut spi = Spidev::open(device_path)
            .with_context(|| format!("Failed to open SPI device: {:?}", device_path))?;

        let options = SpidevOptions::new()
            .bits_per_word(8)
            .max_speed_hz(speed_hz)
            .mode(SpiModeFlags::SPI_MODE_0)
            .build();

        spi.configure(&options)
            .context("Failed to configure SPI device")?;

        Ok(Self {
            spi,
            tx_buffer: vec![0u8; SPI_BUFFER_SIZE],
            rx_buffer: vec![0u8; SPI_BUFFER_SIZE],
        })
    }

    /// Perform a full-duplex SPI transfer
    fn transfer(&mut self, tx_frame: &SpiFrame) -> Result<SpiFrame> {
        // Prepare TX buffer
        let tx_bytes = tx_frame.to_bytes();
        self.tx_buffer.copy_from_slice(&tx_bytes);

        // Clear RX buffer
        self.rx_buffer.fill(0);

        // Perform transfer
        let mut transfer = SpidevTransfer::read_write(&self.tx_buffer, &mut self.rx_buffer);
        self.spi
            .transfer(&mut transfer)
            .context("SPI transfer failed")?;

        // Parse received frame
        match SpiFrame::from_bytes(&self.rx_buffer) {
            Some(frame) => Ok(frame),
            None => Ok(SpiFrame::new()), // Return empty frame if invalid
        }
    }

    /// Poll for data from MCU (sends empty frame, receives data)
    fn poll(&mut self) -> Result<Option<SpiFrame>> {
        let empty_frame = SpiFrame::new();
        let rx_frame = self.transfer(&empty_frame)?;

        if rx_frame.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rx_frame))
        }
    }

    /// Send data to MCU
    fn send(&mut self, payload: &[u8]) -> Result<SpiFrame> {
        let tx_frame = SpiFrame::with_payload(payload);
        self.transfer(&tx_frame)
    }
}

/// Handle a client connection
fn handle_client(
    mut stream: UnixStream,
    spi_tx: std::sync::mpsc::Sender<Vec<u8>>,
    mcu_rx: std::sync::mpsc::Receiver<Vec<u8>>,
) {
    info!("New client connected");

    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(100)))
        .ok();

    let mut buffer = vec![0u8; 4096];

    loop {
        // Try to read from client
        match stream.read(&mut buffer) {
            Ok(0) => {
                info!("Client disconnected");
                break;
            }
            Ok(n) => {
                debug!("Received {} bytes from client", n);
                // Send to MCU via SPI
                if spi_tx.send(buffer[..n].to_vec()).is_err() {
                    error!("Failed to send to SPI handler");
                    break;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No data available, continue
            }
            Err(e) => {
                error!("Error reading from client: {}", e);
                break;
            }
        }

        // Try to receive data from MCU
        match mcu_rx.try_recv() {
            Ok(data) => {
                debug!("Sending {} bytes to client", data.len());
                if let Err(e) = stream.write_all(&data) {
                    error!("Error writing to client: {}", e);
                    break;
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                // No data available
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                error!("MCU channel disconnected");
                break;
            }
        }

        thread::sleep(Duration::from_millis(1));
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if args.verbose { "debug" } else { "info" }),
    )
    .init();

    info!("DragonWing SPI Router starting...");
    info!("SPI device: {:?}", args.spi_device);
    info!("SPI speed: {} Hz", args.spi_speed);
    info!("Unix socket: {:?}", args.unix_socket);

    // Initialize SPI
    let mut spi = SpiHandler::new(&args.spi_device, args.spi_speed)?;
    info!("SPI initialized");

    // Remove existing socket
    if args.unix_socket.exists() {
        fs::remove_file(&args.unix_socket)?;
    }

    // Create Unix socket listener
    let listener = UnixListener::bind(&args.unix_socket)
        .with_context(|| format!("Failed to bind Unix socket: {:?}", args.unix_socket))?;
    listener.set_nonblocking(true)?;
    info!("Unix socket created");

    // Shutdown flag
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Handle Ctrl+C
    ctrlc::set_handler(move || {
        info!("Shutting down...");
        r.store(false, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl+C handler")?;

    // Track active client
    let mut active_client: Option<(
        std::sync::mpsc::Sender<Vec<u8>>,
        std::sync::mpsc::Receiver<Vec<u8>>,
    )> = None;

    info!("Entering main loop");

    // Test mode counter
    let mut test_counter: u32 = 0;

    while running.load(Ordering::SeqCst) {
        // Accept new connections
        match listener.accept() {
            Ok((stream, _)) => {
                info!("Accepted new connection");

                // Create channels for this client
                let (to_spi, from_client) = std::sync::mpsc::channel::<Vec<u8>>();
                let (to_client, from_spi) = std::sync::mpsc::channel::<Vec<u8>>();

                // Store channels for SPI thread
                active_client = Some((to_client, from_client));

                // Spawn client handler thread
                thread::spawn(move || {
                    handle_client(stream, to_spi, from_spi);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No connection pending
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
            }
        }

        // In test mode, send test RPC messages; otherwise poll
        let rx_frame = if args.test_mode {
            test_counter = test_counter.wrapping_add(1);

            // Create an RPC request for "ping" method
            let request = RpcRequest::new(
                test_counter,
                "ping",
                vec![rmpv::Value::Integer(test_counter.into())],
            );

            match request.encode() {
                Ok(rpc_bytes) => {
                    debug!(
                        "Sending RPC request #{}: ping({})",
                        test_counter, test_counter
                    );
                    spi.send(&rpc_bytes)
                }
                Err(e) => {
                    error!("Failed to encode RPC request: {}", e);
                    spi.poll().map(|opt| opt.unwrap_or_else(SpiFrame::new))
                }
            }
        } else {
            spi.poll().map(|opt| opt.unwrap_or_else(SpiFrame::new))
        };

        // Process received frame
        match rx_frame {
            Ok(frame) if !frame.is_empty() => {
                debug!("Received frame from MCU: {} bytes", frame.payload.len());

                // Try to decode as RPC message
                match decode_message(&frame.payload) {
                    Ok(rpc_msg) => {
                        match rpc_msg {
                            RpcMessage::Request(req) => {
                                info!(
                                    "RPC Request: method={}, msgid={}, params={:?}",
                                    req.method, req.msg_id, req.params
                                );

                                // Handle built-in methods
                                let response = match req.method.as_str() {
                                    "echo" => {
                                        // Echo back the first parameter
                                        let result =
                                            req.params.first().cloned().unwrap_or(rmpv::Value::Nil);
                                        RpcResponse::success(req.msg_id, result)
                                    }
                                    "version" => RpcResponse::success(
                                        req.msg_id,
                                        rmpv::Value::String("spi-router 0.1.0".into()),
                                    ),
                                    _ => {
                                        // Forward to client or return error
                                        if let Some((ref tx, _)) = active_client {
                                            if tx.send(frame.payload.clone()).is_err() {
                                                warn!("Client disconnected");
                                                active_client = None;
                                            }
                                        }
                                        // Don't send response - client will handle it
                                        continue;
                                    }
                                };

                                // Send response back to MCU
                                if let Ok(resp_bytes) = response.encode() {
                                    debug!("Sending RPC response for msgid={}", req.msg_id);
                                    if let Err(e) = spi.send(&resp_bytes) {
                                        error!("Failed to send RPC response: {}", e);
                                    }
                                }
                            }
                            RpcMessage::Response(resp) => {
                                info!(
                                    "RPC Response: msgid={}, error={:?}, result={:?}",
                                    resp.msg_id, resp.error, resp.result
                                );

                                // Forward to client
                                if let Some((ref tx, _)) = active_client {
                                    if tx.send(frame.payload.clone()).is_err() {
                                        warn!("Client disconnected");
                                        active_client = None;
                                    }
                                }
                            }
                            RpcMessage::Notification(notif) => {
                                info!(
                                    "RPC Notification: method={}, params={:?}",
                                    notif.method, notif.params
                                );

                                // Forward to client
                                if let Some((ref tx, _)) = active_client {
                                    if tx.send(frame.payload.clone()).is_err() {
                                        warn!("Client disconnected");
                                        active_client = None;
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Not an RPC message, log as raw data
                        if frame
                            .payload
                            .iter()
                            .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                        {
                            debug!(
                                "  Raw payload (text): {:?}",
                                String::from_utf8_lossy(&frame.payload)
                            );
                        } else {
                            debug!(
                                "  Raw payload (hex): {:02x?}",
                                &frame.payload[..frame.payload.len().min(64)]
                            );
                        }

                        // Forward raw data to client
                        if let Some((ref tx, _)) = active_client {
                            if tx.send(frame.payload).is_err() {
                                warn!("Client disconnected, clearing active client");
                                active_client = None;
                            }
                        }
                    }
                }
            }
            Ok(_) => {
                // Empty frame from MCU
            }
            Err(e) => {
                error!("SPI error: {}", e);
            }
        }

        // Check for data to send to MCU
        if let Some((_, ref rx)) = active_client {
            match rx.try_recv() {
                Ok(data) => {
                    debug!("Sending {} bytes to MCU", data.len());
                    if let Err(e) = spi.send(&data) {
                        error!("Failed to send to MCU: {}", e);
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    // No data to send
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    warn!("Client channel disconnected");
                    active_client = None;
                }
            }
        }

        thread::sleep(Duration::from_millis(args.poll_interval));
    }

    // Cleanup
    fs::remove_file(&args.unix_socket).ok();
    info!("Shutdown complete");

    Ok(())
}
