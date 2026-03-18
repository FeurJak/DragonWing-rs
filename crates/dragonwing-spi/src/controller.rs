//! MPU SPI Controller (Master) Implementation
//!
//! This module provides the SPI controller driver for the QRB2210 MPU (Linux),
//! acting as the master device that initiates transfers with the MCU peripheral.
//!
//! # Setup Requirements
//!
//! The MPU acts as SPI controller via Linux spidev:
//! - `/dev/spidev0.0` (or configured device)
//! - 512-byte transfer buffers
//! - Framed protocol with magic header
//!
//! # Example
//!
//! ```ignore
//! use dragonwing_spi::SpiController;
//!
//! let mut spi = SpiController::new("/dev/spidev0.0", 1_000_000)?;
//!
//! // Send data and receive response
//! let response = spi.transfer(b"Hello from MPU!")?;
//!
//! // Or poll for data from MCU
//! if let Some(frame) = spi.poll()? {
//!     println!("Received {} bytes", frame.len());
//! }
//! ```

use super::{FRAME_HEADER_SIZE, FRAME_MAGIC, MAX_PAYLOAD_SIZE, SPI_BUFFER_SIZE};

use spidev::{SpiModeFlags, Spidev, SpidevOptions, SpidevTransfer};
use std::io;
use std::path::Path;

/// Error type for SPI controller operations
#[derive(Debug)]
pub enum SpiError {
    /// I/O error from spidev
    Io(io::Error),
    /// Invalid frame received
    InvalidFrame,
    /// Payload too large
    PayloadTooLarge,
}

impl std::fmt::Display for SpiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpiError::Io(e) => write!(f, "SPI I/O error: {}", e),
            SpiError::InvalidFrame => write!(f, "Invalid SPI frame received"),
            SpiError::PayloadTooLarge => write!(f, "Payload exceeds maximum size"),
        }
    }
}

impl std::error::Error for SpiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SpiError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for SpiError {
    fn from(err: io::Error) -> Self {
        SpiError::Io(err)
    }
}

/// Result type for SPI operations
pub type SpiResult<T> = Result<T, SpiError>;

/// SPI frame for communication
#[derive(Debug, Clone)]
pub struct SpiFrame {
    /// Frame magic number
    pub magic: u16,
    /// Payload length
    pub length: u16,
    /// Payload data
    pub payload: Vec<u8>,
}

impl SpiFrame {
    /// Create an empty frame (for polling)
    pub fn empty() -> Self {
        Self {
            magic: FRAME_MAGIC,
            length: 0,
            payload: Vec::new(),
        }
    }

    /// Create a frame with payload
    pub fn with_payload(payload: &[u8]) -> Self {
        let len = payload.len().min(MAX_PAYLOAD_SIZE);
        Self {
            magic: FRAME_MAGIC,
            length: len as u16,
            payload: payload[..len].to_vec(),
        }
    }

    /// Serialize frame to bytes (always SPI_BUFFER_SIZE)
    pub fn to_bytes(&self) -> [u8; SPI_BUFFER_SIZE] {
        let mut buf = [0u8; SPI_BUFFER_SIZE];

        // Write header
        buf[0] = (self.magic >> 8) as u8;
        buf[1] = self.magic as u8;
        buf[2] = (self.length >> 8) as u8;
        buf[3] = self.length as u8;

        // Copy payload
        let copy_len = self.payload.len().min(MAX_PAYLOAD_SIZE);
        buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + copy_len]
            .copy_from_slice(&self.payload[..copy_len]);

        buf
    }

    /// Parse frame from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < FRAME_HEADER_SIZE {
            return None;
        }

        let magic = ((data[0] as u16) << 8) | (data[1] as u16);
        if magic != FRAME_MAGIC {
            return None;
        }

        let length = ((data[2] as u16) << 8) | (data[3] as u16);
        if length as usize > MAX_PAYLOAD_SIZE {
            return None;
        }

        let payload_end = FRAME_HEADER_SIZE + length as usize;
        if data.len() < payload_end {
            return None;
        }

        let payload = data[FRAME_HEADER_SIZE..payload_end].to_vec();

        Some(Self {
            magic,
            length,
            payload,
        })
    }

    /// Check if frame has payload
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Get payload as slice
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// SPI Controller for MPU (Linux) side
pub struct SpiController {
    spi: Spidev,
    tx_buffer: [u8; SPI_BUFFER_SIZE],
    rx_buffer: [u8; SPI_BUFFER_SIZE],
}

impl SpiController {
    /// Create a new SPI controller
    ///
    /// # Arguments
    ///
    /// * `device` - Path to spidev device (e.g., "/dev/spidev0.0")
    /// * `speed_hz` - SPI clock speed in Hz
    pub fn new<P: AsRef<Path>>(device: P, speed_hz: u32) -> SpiResult<Self> {
        let mut spi = Spidev::open(device)?;

        let options = SpidevOptions::new()
            .bits_per_word(8)
            .max_speed_hz(speed_hz)
            .mode(SpiModeFlags::SPI_MODE_0)
            .build();

        spi.configure(&options)?;

        Ok(Self {
            spi,
            tx_buffer: [0u8; SPI_BUFFER_SIZE],
            rx_buffer: [0u8; SPI_BUFFER_SIZE],
        })
    }

    /// Perform a full-duplex SPI transfer
    ///
    /// Sends a frame and receives a response simultaneously.
    pub fn transfer_frame(&mut self, tx_frame: &SpiFrame) -> SpiResult<SpiFrame> {
        // Prepare TX buffer
        self.tx_buffer = tx_frame.to_bytes();

        // Clear RX buffer
        self.rx_buffer.fill(0);

        // Perform transfer
        let mut transfer = SpidevTransfer::read_write(&self.tx_buffer, &mut self.rx_buffer);
        self.spi.transfer(&mut transfer)?;

        // Parse received frame
        match SpiFrame::from_bytes(&self.rx_buffer) {
            Some(frame) => Ok(frame),
            None => Ok(SpiFrame::empty()),
        }
    }

    /// Send data to MCU and receive response
    ///
    /// # Arguments
    ///
    /// * `data` - Payload to send (max 508 bytes)
    ///
    /// # Returns
    ///
    /// Received payload, or empty if MCU had nothing to send
    pub fn transfer(&mut self, data: &[u8]) -> SpiResult<Vec<u8>> {
        if data.len() > MAX_PAYLOAD_SIZE {
            return Err(SpiError::PayloadTooLarge);
        }

        let tx_frame = SpiFrame::with_payload(data);
        let rx_frame = self.transfer_frame(&tx_frame)?;

        Ok(rx_frame.payload)
    }

    /// Poll MCU for data (sends empty frame)
    ///
    /// # Returns
    ///
    /// Some(payload) if MCU had data, None otherwise
    pub fn poll(&mut self) -> SpiResult<Option<Vec<u8>>> {
        let tx_frame = SpiFrame::empty();
        let rx_frame = self.transfer_frame(&tx_frame)?;

        if rx_frame.is_empty() {
            Ok(None)
        } else {
            Ok(Some(rx_frame.payload))
        }
    }

    /// Send data without caring about response
    pub fn send(&mut self, data: &[u8]) -> SpiResult<()> {
        self.transfer(data)?;
        Ok(())
    }

    /// Get the maximum payload size
    pub fn max_payload(&self) -> usize {
        MAX_PAYLOAD_SIZE
    }

    /// Get the buffer size
    pub fn buffer_size(&self) -> usize {
        SPI_BUFFER_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let payload = b"Hello, MCU!";
        let frame = SpiFrame::with_payload(payload);

        assert_eq!(frame.magic, FRAME_MAGIC);
        assert_eq!(frame.length, payload.len() as u16);
        assert_eq!(frame.payload(), payload);

        let bytes = frame.to_bytes();
        let parsed = SpiFrame::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.magic, frame.magic);
        assert_eq!(parsed.length, frame.length);
        assert_eq!(parsed.payload(), frame.payload());
    }

    #[test]
    fn test_empty_frame() {
        let frame = SpiFrame::empty();
        assert!(frame.is_empty());
        assert_eq!(frame.length, 0);
    }

    #[test]
    fn test_payload_truncation() {
        let large_payload = vec![0xAB; 1000];
        let frame = SpiFrame::with_payload(&large_payload);

        assert_eq!(frame.length as usize, MAX_PAYLOAD_SIZE);
        assert_eq!(frame.payload.len(), MAX_PAYLOAD_SIZE);
    }
}
