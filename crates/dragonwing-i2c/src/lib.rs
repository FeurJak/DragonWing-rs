// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// DragonWing I2C Library
//
// A Rust driver for I2C (Wire) communication on the Arduino Uno Q.
// The board has two I2C buses:
// - Wire (I2C2): Arduino header pins SDA/SCL (PB10/PB11)
// - Wire1 (I2C4): Camera/internal connector (PD12/PD13)
//
// This crate implements the `embedded-hal` I2C traits for compatibility
// with the embedded Rust ecosystem, including drivers like `ssd1306`.
//
// # Example
//
// ```no_run
// use dragonwing_i2c::{I2c, I2cBus};
// use embedded_hal::i2c::I2c as I2cTrait;
//
// // Create I2C instance for Wire (bus 0)
// let mut i2c = I2c::new(I2cBus::Wire);
// i2c.init().unwrap();
//
// // Write to a device at address 0x3C
// i2c.write(0x3C, &[0x00, 0x10]).unwrap();
//
// // Read from a device
// let mut buf = [0u8; 2];
// i2c.read(0x3C, &mut buf).unwrap();
// ```

#![no_std]

mod ffi;

pub use ffi::{
    DW_I2C_BUS_0, DW_I2C_BUS_1, DW_I2C_SPEED_FAST, DW_I2C_SPEED_FAST_PLUS, DW_I2C_SPEED_STANDARD,
};

use embedded_hal::i2c::{ErrorKind, ErrorType, Operation};

/// I2C bus selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum I2cBus {
    /// Wire - I2C2 on Arduino header pins SDA/SCL
    Wire = 0,
    /// Wire1 - I2C4 on camera/internal connector
    Wire1 = 1,
}

impl Default for I2cBus {
    fn default() -> Self {
        Self::Wire
    }
}

/// I2C clock speed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cSpeed {
    /// Standard mode: 100 kHz
    Standard,
    /// Fast mode: 400 kHz
    Fast,
    /// Fast mode plus: 1 MHz
    FastPlus,
}

impl Default for I2cSpeed {
    fn default() -> Self {
        Self::Fast
    }
}

impl I2cSpeed {
    /// Get the frequency in Hz
    pub const fn frequency_hz(&self) -> u32 {
        match self {
            Self::Standard => DW_I2C_SPEED_STANDARD,
            Self::Fast => DW_I2C_SPEED_FAST,
            Self::FastPlus => DW_I2C_SPEED_FAST_PLUS,
        }
    }
}

/// I2C error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I2cError {
    /// Device not responding (NACK)
    Nack,
    /// Bus error
    Bus,
    /// Arbitration lost
    ArbitrationLoss,
    /// Operation timeout
    Timeout,
    /// Invalid parameter
    InvalidParameter,
    /// Bus busy
    Busy,
}

impl embedded_hal::i2c::Error for I2cError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::Nack => ErrorKind::NoAcknowledge(embedded_hal::i2c::NoAcknowledgeSource::Unknown),
            Self::Bus => ErrorKind::Bus,
            Self::ArbitrationLoss => ErrorKind::ArbitrationLoss,
            Self::Timeout => ErrorKind::Other,
            Self::InvalidParameter => ErrorKind::Other,
            Self::Busy => ErrorKind::Bus,
        }
    }
}

impl I2cError {
    /// Convert from FFI error code
    fn from_ffi(code: i32) -> Result<(), Self> {
        match code {
            0 => Ok(()),
            ffi::DW_I2C_ERR_NACK => Err(Self::Nack),
            ffi::DW_I2C_ERR_BUS => Err(Self::Bus),
            ffi::DW_I2C_ERR_ARB => Err(Self::ArbitrationLoss),
            ffi::DW_I2C_ERR_TIMEOUT => Err(Self::Timeout),
            ffi::DW_I2C_ERR_INVALID => Err(Self::InvalidParameter),
            ffi::DW_I2C_ERR_BUSY => Err(Self::Busy),
            _ => Err(Self::Bus),
        }
    }
}

/// I2C controller for Arduino Uno Q.
///
/// Provides I2C master functionality with support for the `embedded-hal` I2C traits.
/// Compatible with drivers like `ssd1306`, `bme280`, etc.
///
/// # Hardware Details
///
/// The Arduino Uno Q has two I2C buses:
/// - **Wire (I2C2)**: Available on Arduino header pins SDA (PB10) and SCL (PB11)
/// - **Wire1 (I2C4)**: Available on internal/camera connector pins (PD12/PD13)
///
/// Both buses support standard mode (100 kHz), fast mode (400 kHz), and
/// fast mode plus (1 MHz).
///
/// # Example
///
/// ```no_run
/// use dragonwing_i2c::{I2c, I2cBus, I2cSpeed};
///
/// // Create and initialize I2C on Wire bus at 400 kHz
/// let mut i2c = I2c::new(I2cBus::Wire);
/// i2c.init().unwrap();
/// i2c.set_speed(I2cSpeed::Fast).unwrap();
///
/// // Scan for devices
/// let devices = i2c.scan();
/// for addr in devices {
///     // Found device at addr
/// }
/// ```
pub struct I2c {
    bus: I2cBus,
    initialized: bool,
}

impl I2c {
    /// Create a new I2C instance for the specified bus.
    ///
    /// Note: You must call `init()` before using the bus.
    pub const fn new(bus: I2cBus) -> Self {
        Self {
            bus,
            initialized: false,
        }
    }

    /// Initialize the I2C bus.
    ///
    /// This must be called before any I2C operations.
    pub fn init(&mut self) -> Result<(), I2cError> {
        let ret = unsafe { ffi::dw_i2c_init(self.bus as u8) };
        I2cError::from_ffi(ret)?;
        self.initialized = true;
        Ok(())
    }

    /// Deinitialize the I2C bus.
    pub fn deinit(&mut self) {
        if self.initialized {
            unsafe { ffi::dw_i2c_deinit(self.bus as u8) };
            self.initialized = false;
        }
    }

    /// Set the I2C clock speed.
    ///
    /// # Arguments
    ///
    /// * `speed` - The desired clock speed
    pub fn set_speed(&mut self, speed: I2cSpeed) -> Result<(), I2cError> {
        let ret = unsafe { ffi::dw_i2c_set_clock(self.bus as u8, speed.frequency_hz()) };
        I2cError::from_ffi(ret)
    }

    /// Check if a device is present at the given address.
    ///
    /// # Arguments
    ///
    /// * `addr` - 7-bit I2C address to probe
    ///
    /// # Returns
    ///
    /// `true` if a device responds at the address
    pub fn probe(&self, addr: u8) -> bool {
        unsafe { ffi::dw_i2c_probe(self.bus as u8, addr) }
    }

    /// Scan the bus for devices.
    ///
    /// Probes addresses from 0x08 to 0x77 (standard I2C address range).
    ///
    /// # Returns
    ///
    /// A `ScanResult` containing the found device addresses.
    pub fn scan(&self) -> ScanResult {
        let mut found = [0u8; 16];
        let count = unsafe {
            ffi::dw_i2c_scan(self.bus as u8, 0x08, 0x77, found.as_mut_ptr(), found.len())
        };
        ScanResult {
            addresses: found,
            count: count.max(0) as usize,
        }
    }

    /// Get the bus index.
    pub fn bus(&self) -> I2cBus {
        self.bus
    }
}

impl Drop for I2c {
    fn drop(&mut self) {
        self.deinit();
    }
}

impl Default for I2c {
    fn default() -> Self {
        Self::new(I2cBus::Wire)
    }
}

impl ErrorType for I2c {
    type Error = I2cError;
}

impl embedded_hal::i2c::I2c for I2c {
    fn transaction(
        &mut self,
        address: u8,
        operations: &mut [Operation<'_>],
    ) -> Result<(), Self::Error> {
        for op in operations {
            match op {
                Operation::Read(buffer) => {
                    let ret = unsafe {
                        ffi::dw_i2c_read(self.bus as u8, address, buffer.as_mut_ptr(), buffer.len())
                    };
                    I2cError::from_ffi(ret)?;
                }
                Operation::Write(buffer) => {
                    let ret = unsafe {
                        ffi::dw_i2c_write(self.bus as u8, address, buffer.as_ptr(), buffer.len())
                    };
                    I2cError::from_ffi(ret)?;
                }
            }
        }
        Ok(())
    }

    fn read(&mut self, address: u8, read: &mut [u8]) -> Result<(), Self::Error> {
        let ret =
            unsafe { ffi::dw_i2c_read(self.bus as u8, address, read.as_mut_ptr(), read.len()) };
        I2cError::from_ffi(ret)
    }

    fn write(&mut self, address: u8, write: &[u8]) -> Result<(), Self::Error> {
        let ret =
            unsafe { ffi::dw_i2c_write(self.bus as u8, address, write.as_ptr(), write.len()) };
        I2cError::from_ffi(ret)
    }

    fn write_read(
        &mut self,
        address: u8,
        write: &[u8],
        read: &mut [u8],
    ) -> Result<(), Self::Error> {
        let ret = unsafe {
            ffi::dw_i2c_write_read(
                self.bus as u8,
                address,
                write.as_ptr(),
                write.len(),
                read.as_mut_ptr(),
                read.len(),
            )
        };
        I2cError::from_ffi(ret)
    }
}

/// Result of an I2C bus scan.
#[derive(Debug)]
pub struct ScanResult {
    addresses: [u8; 16],
    count: usize,
}

impl ScanResult {
    /// Get the number of devices found.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Check if any devices were found.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get the found addresses as a slice.
    pub fn addresses(&self) -> &[u8] {
        &self.addresses[..self.count]
    }

    /// Iterate over found addresses.
    pub fn iter(&self) -> impl Iterator<Item = u8> + '_ {
        self.addresses[..self.count].iter().copied()
    }
}

/// Convenience type alias for Wire (I2C2)
pub type Wire = I2c;

/// Convenience type alias for Wire1 (I2C4)
pub type Wire1 = I2c;

/// Create a Wire (I2C2) instance.
///
/// This is the default I2C bus on the Arduino header.
pub fn wire() -> I2c {
    I2c::new(I2cBus::Wire)
}

/// Create a Wire1 (I2C4) instance.
///
/// This is the secondary I2C bus on the internal/camera connector.
pub fn wire1() -> I2c {
    I2c::new(I2cBus::Wire1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_speed_frequency() {
        assert_eq!(I2cSpeed::Standard.frequency_hz(), 100_000);
        assert_eq!(I2cSpeed::Fast.frequency_hz(), 400_000);
        assert_eq!(I2cSpeed::FastPlus.frequency_hz(), 1_000_000);
    }

    #[test]
    fn test_bus_default() {
        assert_eq!(I2cBus::default(), I2cBus::Wire);
    }
}
