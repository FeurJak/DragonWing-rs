//! DragonWing SPI - Cross-platform SPI communication
//!
//! This crate provides SPI communication between the Arduino Uno Q's two processors:
//! - **MCU** (STM32U585): Acts as SPI peripheral (slave)
//! - **MPU** (QRB2210): Acts as SPI controller (master)
//!
//! # Features
//!
//! - `mcu`: Enable MCU peripheral mode (no_std, requires Zephyr)
//! - `mpu`: Enable MPU controller mode (std, Linux spidev)
//!
//! # Protocol
//!
//! All transfers use a framed format:
//!
//! ```text
//! +--------+--------+--------+--------+------------------+
//! | Magic (0xAA55)  |    Length      |     Payload      |
//! |   2 bytes       |    2 bytes     |   0-508 bytes    |
//! +--------+--------+--------+--------+------------------+
//! ```
//!
//! # Example (MCU)
//!
//! ```ignore
//! use dragonwing_spi::SpiTransport;
//!
//! let mut spi = SpiTransport::new();
//! spi.init()?;
//!
//! // Prepare response data
//! spi.prepare_tx(b"Hello from MCU!");
//!
//! // Wait for controller to initiate transfer
//! let rx_len = spi.transceive();
//!
//! // Read received data
//! let mut buf = [0u8; 64];
//! let len = spi.read(&mut buf);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

/// SPI buffer size (must match on both sides)
/// 2KB to match MCU SPI peripheral buffer size
/// Note: For larger transfers like camera frames, use multiple transfers
pub const SPI_BUFFER_SIZE: usize = 2048;

/// Frame header size (magic + length)
pub const FRAME_HEADER_SIZE: usize = 4;

/// Maximum payload size per frame
pub const MAX_PAYLOAD_SIZE: usize = SPI_BUFFER_SIZE - FRAME_HEADER_SIZE;

/// Frame magic number
pub const FRAME_MAGIC: u16 = 0xAA55;

/// Frame header for SPI transfers
#[derive(Debug, Clone, Copy)]
pub struct FrameHeader {
    /// Magic number (0xAA55)
    pub magic: u16,
    /// Payload length
    pub length: u16,
}

impl FrameHeader {
    /// Create a new frame header
    pub fn new(length: u16) -> Self {
        Self {
            magic: FRAME_MAGIC,
            length,
        }
    }

    /// Parse frame header from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < FRAME_HEADER_SIZE {
            return None;
        }

        let magic = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
        let length = ((bytes[2] as u16) << 8) | (bytes[3] as u16);

        if magic != FRAME_MAGIC {
            return None;
        }

        Some(Self { magic, length })
    }

    /// Serialize frame header to bytes
    pub fn to_bytes(&self) -> [u8; FRAME_HEADER_SIZE] {
        [
            (self.magic >> 8) as u8,
            (self.magic & 0xFF) as u8,
            (self.length >> 8) as u8,
            (self.length & 0xFF) as u8,
        ]
    }

    /// Check if this is a valid frame header
    pub fn is_valid(&self) -> bool {
        self.magic == FRAME_MAGIC && (self.length as usize) <= MAX_PAYLOAD_SIZE
    }
}

// MCU peripheral (slave) implementation
#[cfg(feature = "mcu")]
pub mod peripheral;

#[cfg(feature = "mcu")]
pub use peripheral::SpiTransport;

// MPU controller (master) implementation
#[cfg(feature = "mpu")]
pub mod controller;

#[cfg(feature = "mpu")]
pub use controller::SpiController;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_header() {
        let header = FrameHeader::new(100);
        assert_eq!(header.magic, FRAME_MAGIC);
        assert_eq!(header.length, 100);
        assert!(header.is_valid());

        let bytes = header.to_bytes();
        assert_eq!(bytes, [0xAA, 0x55, 0x00, 0x64]);

        let parsed = FrameHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.magic, header.magic);
        assert_eq!(parsed.length, header.length);
    }

    #[test]
    fn test_invalid_magic() {
        let bytes = [0x00, 0x00, 0x00, 0x10];
        assert!(FrameHeader::from_bytes(&bytes).is_none());
    }
}
