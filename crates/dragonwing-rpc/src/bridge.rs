// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// MCU Bridge - RPC server/client for STM32U585 (no_std)
//
// This module provides the MCU-side RPC implementation including:
// - Bridge: High-level API for RPC communication
// - RpcClient: Low-level client for making RPC calls
// - RpcServer: Server for handling incoming RPC requests
// - RpcDecoder: Decoder for parsing incoming MessagePack-RPC messages
// - MsgPack: MessagePack encoding/decoding utilities
// - Transport: Transport abstractions (UART, SPI)

#![cfg(feature = "mcu")]
// Allow static mut refs for MCU single-threaded environment
#![allow(static_mut_refs)]

use crate::protocol::mcu::{RpcError, StrBuf};
use crate::protocol::{
    RpcErrorCode, RpcMessageType, DECODER_BUFFER_SIZE, DEFAULT_BAUD_RATE, MAX_METHOD_NAME_LEN,
    MIN_RPC_BYTES,
};

// ============================================================================
// MessagePack Encoding/Decoding
// ============================================================================

/// MessagePack format markers
mod format {
    // Positive fixint: 0x00 - 0x7f
    pub const POSITIVE_FIXINT_MAX: u8 = 0x7f;

    // Fixmap: 0x80 - 0x8f
    #[allow(dead_code)]
    pub const FIXMAP_MIN: u8 = 0x80;
    #[allow(dead_code)]
    pub const FIXMAP_MAX: u8 = 0x8f;

    // Fixarray: 0x90 - 0x9f
    pub const FIXARRAY_MIN: u8 = 0x90;
    #[allow(dead_code)]
    pub const FIXARRAY_MAX: u8 = 0x9f;

    // Fixstr: 0xa0 - 0xbf
    pub const FIXSTR_MIN: u8 = 0xa0;
    #[allow(dead_code)]
    pub const FIXSTR_MAX: u8 = 0xbf;

    // Nil, false, true
    pub const NIL: u8 = 0xc0;
    pub const FALSE: u8 = 0xc2;
    pub const TRUE: u8 = 0xc3;

    // Binary
    pub const BIN8: u8 = 0xc4;
    pub const BIN16: u8 = 0xc5;
    #[allow(dead_code)]
    pub const BIN32: u8 = 0xc6;

    // Extension
    pub const EXT8: u8 = 0xc7;
    #[allow(dead_code)]
    pub const EXT16: u8 = 0xc8;
    #[allow(dead_code)]
    pub const EXT32: u8 = 0xc9;

    // Float
    pub const FLOAT32: u8 = 0xca;
    pub const FLOAT64: u8 = 0xcb;

    // Unsigned integers
    pub const UINT8: u8 = 0xcc;
    pub const UINT16: u8 = 0xcd;
    pub const UINT32: u8 = 0xce;
    pub const UINT64: u8 = 0xcf;

    // Signed integers
    pub const INT8: u8 = 0xd0;
    pub const INT16: u8 = 0xd1;
    pub const INT32: u8 = 0xd2;
    pub const INT64: u8 = 0xd3;

    // Fixed extension
    pub const FIXEXT1: u8 = 0xd4;
    pub const FIXEXT2: u8 = 0xd5;
    pub const FIXEXT4: u8 = 0xd6;
    pub const FIXEXT8: u8 = 0xd7;
    pub const FIXEXT16: u8 = 0xd8;

    // Strings
    pub const STR8: u8 = 0xd9;
    pub const STR16: u8 = 0xda;
    #[allow(dead_code)]
    pub const STR32: u8 = 0xdb;

    // Arrays
    pub const ARRAY16: u8 = 0xdc;
    pub const ARRAY32: u8 = 0xdd;

    // Maps
    #[allow(dead_code)]
    pub const MAP16: u8 = 0xde;
    #[allow(dead_code)]
    pub const MAP32: u8 = 0xdf;

    // Negative fixint: 0xe0 - 0xff
    #[allow(dead_code)]
    pub const NEGATIVE_FIXINT_MIN: u8 = 0xe0;
}

/// A MessagePack value that can be sent/received in RPC calls
#[derive(Debug, Clone)]
pub enum MsgPackValue<'a> {
    /// Null value
    Nil,
    /// Boolean value
    Bool(bool),
    /// Signed integer (up to 64 bits)
    Int(i64),
    /// Unsigned integer (up to 64 bits)
    UInt(u64),
    /// 32-bit float
    Float32(f32),
    /// 64-bit float
    Float64(f64),
    /// String (borrowed)
    Str(&'a str),
    /// String (owned, for unpacking)
    StrOwned(StrBuf),
    /// Binary data (borrowed)
    Bin(&'a [u8]),
    /// Array header with length (elements must be read separately)
    ArrayHeader(usize),
    /// Map of key-value pairs (not commonly used in RPC)
    Map,
}

/// MessagePack packer for encoding values to bytes
pub struct MsgPackPacker {
    buffer: [u8; 512],
    pos: usize,
}

impl MsgPackPacker {
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; 512],
            pos: 0,
        }
    }

    pub fn reset(&mut self) {
        self.pos = 0;
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.pos]
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.pos
    }

    fn write_byte(&mut self, b: u8) -> bool {
        if self.pos < self.buffer.len() {
            self.buffer[self.pos] = b;
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> bool {
        if self.pos + bytes.len() <= self.buffer.len() {
            self.buffer[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
            self.pos += bytes.len();
            true
        } else {
            false
        }
    }

    /// Pack nil value
    pub fn pack_nil(&mut self) -> bool {
        self.write_byte(format::NIL)
    }

    /// Pack boolean value
    pub fn pack_bool(&mut self, value: bool) -> bool {
        self.write_byte(if value { format::TRUE } else { format::FALSE })
    }

    /// Pack unsigned integer (uses smallest encoding)
    pub fn pack_uint(&mut self, value: u64) -> bool {
        if value <= format::POSITIVE_FIXINT_MAX as u64 {
            self.write_byte(value as u8)
        } else if value <= u8::MAX as u64 {
            self.write_byte(format::UINT8) && self.write_byte(value as u8)
        } else if value <= u16::MAX as u64 {
            self.write_byte(format::UINT16) && self.write_bytes(&(value as u16).to_be_bytes())
        } else if value <= u32::MAX as u64 {
            self.write_byte(format::UINT32) && self.write_bytes(&(value as u32).to_be_bytes())
        } else {
            self.write_byte(format::UINT64) && self.write_bytes(&value.to_be_bytes())
        }
    }

    /// Pack signed integer (uses smallest encoding)
    pub fn pack_int(&mut self, value: i64) -> bool {
        if value >= 0 {
            self.pack_uint(value as u64)
        } else if value >= -32 {
            // Negative fixint
            self.write_byte(value as u8)
        } else if value >= i8::MIN as i64 {
            self.write_byte(format::INT8) && self.write_byte(value as u8)
        } else if value >= i16::MIN as i64 {
            self.write_byte(format::INT16) && self.write_bytes(&(value as i16).to_be_bytes())
        } else if value >= i32::MIN as i64 {
            self.write_byte(format::INT32) && self.write_bytes(&(value as i32).to_be_bytes())
        } else {
            self.write_byte(format::INT64) && self.write_bytes(&value.to_be_bytes())
        }
    }

    /// Pack 32-bit float
    pub fn pack_f32(&mut self, value: f32) -> bool {
        self.write_byte(format::FLOAT32) && self.write_bytes(&value.to_be_bytes())
    }

    /// Pack 64-bit float
    pub fn pack_f64(&mut self, value: f64) -> bool {
        self.write_byte(format::FLOAT64) && self.write_bytes(&value.to_be_bytes())
    }

    /// Pack string
    pub fn pack_str(&mut self, s: &str) -> bool {
        let bytes = s.as_bytes();
        let len = bytes.len();

        let header_ok = if len <= 31 {
            self.write_byte(format::FIXSTR_MIN | len as u8)
        } else if len <= u8::MAX as usize {
            self.write_byte(format::STR8) && self.write_byte(len as u8)
        } else if len <= u16::MAX as usize {
            self.write_byte(format::STR16) && self.write_bytes(&(len as u16).to_be_bytes())
        } else {
            return false; // Too long
        };

        header_ok && self.write_bytes(bytes)
    }

    /// Pack binary data
    pub fn pack_bin(&mut self, data: &[u8]) -> bool {
        let len = data.len();

        let header_ok = if len <= u8::MAX as usize {
            self.write_byte(format::BIN8) && self.write_byte(len as u8)
        } else if len <= u16::MAX as usize {
            self.write_byte(format::BIN16) && self.write_bytes(&(len as u16).to_be_bytes())
        } else {
            return false; // Too long
        };

        header_ok && self.write_bytes(data)
    }

    /// Pack array header (caller must pack N values after this)
    pub fn pack_array_header(&mut self, len: usize) -> bool {
        if len <= 15 {
            self.write_byte(format::FIXARRAY_MIN | len as u8)
        } else if len <= u16::MAX as usize {
            self.write_byte(format::ARRAY16) && self.write_bytes(&(len as u16).to_be_bytes())
        } else {
            false
        }
    }

    /// Pack a MsgPackValue
    pub fn pack_value(&mut self, value: &MsgPackValue) -> bool {
        match value {
            MsgPackValue::Nil => self.pack_nil(),
            MsgPackValue::Bool(b) => self.pack_bool(*b),
            MsgPackValue::Int(i) => self.pack_int(*i),
            MsgPackValue::UInt(u) => self.pack_uint(*u),
            MsgPackValue::Float32(f) => self.pack_f32(*f),
            MsgPackValue::Float64(f) => self.pack_f64(*f),
            MsgPackValue::Str(s) => self.pack_str(s),
            MsgPackValue::StrOwned(s) => self.pack_str(s.as_str()),
            MsgPackValue::Bin(b) => self.pack_bin(b),
            MsgPackValue::ArrayHeader(len) => self.pack_array_header(*len),
            MsgPackValue::Map => false, // Not implemented for now
        }
    }

    /// Pack an RPC request: [type=0, msgid, method, params]
    pub fn pack_rpc_request(&mut self, msg_id: u32, method: &str, params: &[MsgPackValue]) -> bool {
        self.pack_array_header(4)
            && self.pack_uint(0) // type = CALL
            && self.pack_uint(msg_id as u64)
            && self.pack_str(method)
            && self.pack_array_header(params.len())
            && params.iter().all(|p| self.pack_value(p))
    }

    /// Pack an RPC notification: [type=2, method, params]
    pub fn pack_rpc_notify(&mut self, method: &str, params: &[MsgPackValue]) -> bool {
        self.pack_array_header(3)
            && self.pack_uint(2) // type = NOTIFY
            && self.pack_str(method)
            && self.pack_array_header(params.len())
            && params.iter().all(|p| self.pack_value(p))
    }

    /// Pack an RPC response: [type=1, msgid, error, result]
    pub fn pack_rpc_response(
        &mut self,
        msg_id: u32,
        error: Option<(i32, &str)>,
        result: Option<&MsgPackValue>,
    ) -> bool {
        self.pack_array_header(4)
            && self.pack_uint(1) // type = RESPONSE
            && self.pack_uint(msg_id as u64)
            && match error {
                Some((code, msg)) => {
                    self.pack_array_header(2) && self.pack_int(code as i64) && self.pack_str(msg)
                }
                None => self.pack_nil(),
            }
            && match result {
                Some(v) => self.pack_value(v),
                None => self.pack_nil(),
            }
    }
}

impl Default for MsgPackPacker {
    fn default() -> Self {
        Self::new()
    }
}

/// MessagePack unpacker for decoding bytes to values
pub struct MsgPackUnpacker<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MsgPackUnpacker<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[allow(dead_code)]
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    fn read_byte(&mut self) -> Option<u8> {
        let b = self.data.get(self.pos).copied();
        if b.is_some() {
            self.pos += 1;
        }
        b
    }

    fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.pos + len <= self.data.len() {
            let slice = &self.data[self.pos..self.pos + len];
            self.pos += len;
            Some(slice)
        } else {
            None
        }
    }

    /// Unpack the next value
    pub fn unpack(&mut self) -> Option<MsgPackValue<'a>> {
        let marker = self.read_byte()?;

        match marker {
            // Positive fixint
            0x00..=0x7f => Some(MsgPackValue::UInt(marker as u64)),

            // Fixmap (skip for now)
            0x80..=0x8f => {
                let len = (marker & 0x0f) as usize;
                // Skip map entries
                for _ in 0..len * 2 {
                    self.unpack()?;
                }
                Some(MsgPackValue::Map)
            }

            // Fixarray - return header, caller must read elements
            0x90..=0x9f => {
                let len = (marker & 0x0f) as usize;
                Some(MsgPackValue::ArrayHeader(len))
            }

            // Fixstr
            0xa0..=0xbf => {
                let len = (marker & 0x1f) as usize;
                let bytes = self.read_bytes(len)?;
                let s = core::str::from_utf8(bytes).ok()?;
                Some(MsgPackValue::Str(s))
            }

            // Nil
            format::NIL => Some(MsgPackValue::Nil),

            // Bool
            format::FALSE => Some(MsgPackValue::Bool(false)),
            format::TRUE => Some(MsgPackValue::Bool(true)),

            // Binary
            format::BIN8 => {
                let len = self.read_byte()? as usize;
                let bytes = self.read_bytes(len)?;
                Some(MsgPackValue::Bin(bytes))
            }
            format::BIN16 => {
                let len = u16::from_be_bytes([self.read_byte()?, self.read_byte()?]) as usize;
                let bytes = self.read_bytes(len)?;
                Some(MsgPackValue::Bin(bytes))
            }

            // Float
            format::FLOAT32 => {
                let bytes = self.read_bytes(4)?;
                let f = f32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Some(MsgPackValue::Float32(f))
            }
            format::FLOAT64 => {
                let bytes = self.read_bytes(8)?;
                let f = f64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                Some(MsgPackValue::Float64(f))
            }

            // Unsigned integers
            format::UINT8 => Some(MsgPackValue::UInt(self.read_byte()? as u64)),
            format::UINT16 => {
                let bytes = self.read_bytes(2)?;
                Some(MsgPackValue::UInt(
                    u16::from_be_bytes([bytes[0], bytes[1]]) as u64
                ))
            }
            format::UINT32 => {
                let bytes = self.read_bytes(4)?;
                Some(MsgPackValue::UInt(
                    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
                ))
            }
            format::UINT64 => {
                let bytes = self.read_bytes(8)?;
                Some(MsgPackValue::UInt(u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])))
            }

            // Signed integers
            format::INT8 => Some(MsgPackValue::Int(self.read_byte()? as i8 as i64)),
            format::INT16 => {
                let bytes = self.read_bytes(2)?;
                Some(MsgPackValue::Int(
                    i16::from_be_bytes([bytes[0], bytes[1]]) as i64
                ))
            }
            format::INT32 => {
                let bytes = self.read_bytes(4)?;
                Some(MsgPackValue::Int(
                    i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64,
                ))
            }
            format::INT64 => {
                let bytes = self.read_bytes(8)?;
                Some(MsgPackValue::Int(i64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])))
            }

            // Strings
            format::STR8 => {
                let len = self.read_byte()? as usize;
                let bytes = self.read_bytes(len)?;
                let s = core::str::from_utf8(bytes).ok()?;
                Some(MsgPackValue::Str(s))
            }
            format::STR16 => {
                let len = u16::from_be_bytes([self.read_byte()?, self.read_byte()?]) as usize;
                let bytes = self.read_bytes(len)?;
                let s = core::str::from_utf8(bytes).ok()?;
                Some(MsgPackValue::Str(s))
            }

            // Arrays - return header, caller must read elements
            format::ARRAY16 => {
                let len = u16::from_be_bytes([self.read_byte()?, self.read_byte()?]) as usize;
                Some(MsgPackValue::ArrayHeader(len))
            }

            // Negative fixint
            0xe0..=0xff => Some(MsgPackValue::Int(marker as i8 as i64)),

            // Extension types - skip
            format::FIXEXT1 => {
                self.read_bytes(2)?;
                Some(MsgPackValue::Nil)
            }
            format::FIXEXT2 => {
                self.read_bytes(3)?;
                Some(MsgPackValue::Nil)
            }
            format::FIXEXT4 => {
                self.read_bytes(5)?;
                Some(MsgPackValue::Nil)
            }
            format::FIXEXT8 => {
                self.read_bytes(9)?;
                Some(MsgPackValue::Nil)
            }
            format::FIXEXT16 => {
                self.read_bytes(17)?;
                Some(MsgPackValue::Nil)
            }
            format::EXT8 => {
                let len = self.read_byte()? as usize;
                self.read_bytes(len + 1)?;
                Some(MsgPackValue::Nil)
            }

            _ => None,
        }
    }

    /// Unpack expecting an unsigned integer
    pub fn unpack_uint(&mut self) -> Option<u64> {
        match self.unpack()? {
            MsgPackValue::UInt(u) => Some(u),
            MsgPackValue::Int(i) if i >= 0 => Some(i as u64),
            _ => None,
        }
    }

    /// Unpack expecting a string
    pub fn unpack_str(&mut self) -> Option<&'a str> {
        match self.unpack()? {
            MsgPackValue::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Unpack expecting an array, returns the length
    pub fn unpack_array_header(&mut self) -> Option<usize> {
        let marker = self.read_byte()?;
        match marker {
            0x90..=0x9f => Some((marker & 0x0f) as usize),
            format::ARRAY16 => {
                let bytes = self.read_bytes(2)?;
                Some(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
            }
            format::ARRAY32 => {
                let bytes = self.read_bytes(4)?;
                Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
            }
            _ => None,
        }
    }
}

// ============================================================================
// Transport Layer
// ============================================================================

/// Transport interface for sending/receiving bytes
pub trait Transport {
    /// Write data to the transport
    fn write(&mut self, data: &[u8]) -> usize;

    /// Read data from the transport into buffer
    fn read(&mut self, buffer: &mut [u8]) -> usize;

    /// Read a single byte
    fn read_byte(&mut self) -> Option<u8>;

    /// Check if data is available to read
    fn available(&self) -> bool;

    /// Flush any buffered output
    fn flush(&mut self) {}
}

/// FFI functions for Zephyr UART access
pub mod uart_ffi {
    extern "C" {
        /// Initialize UART for RPC (Serial1 on Arduino Uno Q)
        pub fn rpc_uart_init(baud_rate: u32) -> i32;

        /// Write bytes to UART
        pub fn rpc_uart_write(data: *const u8, len: usize) -> usize;

        /// Read bytes from UART (non-blocking)
        pub fn rpc_uart_read(buffer: *mut u8, max_len: usize) -> usize;

        /// Check if data is available
        pub fn rpc_uart_available() -> i32;

        /// Flush UART TX buffer
        pub fn rpc_uart_flush();
    }
}

/// UART-based transport for Arduino Uno Q
pub struct UartTransport {
    initialized: bool,
}

impl UartTransport {
    /// Create a new UART transport (uninitialized)
    pub const fn new() -> Self {
        Self { initialized: false }
    }

    /// Initialize the UART with the specified baud rate
    pub fn init(&mut self, baud_rate: u32) -> bool {
        let result = unsafe { uart_ffi::rpc_uart_init(baud_rate) };
        self.initialized = result == 0;
        self.initialized
    }

    /// Check if the transport is initialized
    #[allow(dead_code)]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
}

impl Default for UartTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for UartTransport {
    fn write(&mut self, data: &[u8]) -> usize {
        if !self.initialized || data.is_empty() {
            return 0;
        }
        unsafe { uart_ffi::rpc_uart_write(data.as_ptr(), data.len()) }
    }

    fn read(&mut self, buffer: &mut [u8]) -> usize {
        if !self.initialized || buffer.is_empty() {
            return 0;
        }
        unsafe { uart_ffi::rpc_uart_read(buffer.as_mut_ptr(), buffer.len()) }
    }

    fn read_byte(&mut self) -> Option<u8> {
        if !self.initialized {
            return None;
        }
        let mut byte = 0u8;
        let read = unsafe { uart_ffi::rpc_uart_read(&mut byte as *mut u8, 1) };
        if read == 1 {
            Some(byte)
        } else {
            None
        }
    }

    fn available(&self) -> bool {
        if !self.initialized {
            return false;
        }
        unsafe { uart_ffi::rpc_uart_available() > 0 }
    }

    fn flush(&mut self) {
        if self.initialized {
            unsafe { uart_ffi::rpc_uart_flush() };
        }
    }
}

// ============================================================================
// SPI Transport
// ============================================================================

/// Frame protocol constants
pub const FRAME_MAGIC: u16 = 0xAA55;
pub const FRAME_HEADER_SIZE: usize = 4;
/// SPI buffer size - 2KB to support X-Wing key exchange (pub key: 1216 bytes, ciphertext: 1120 bytes)
pub const SPI_BUFFER_SIZE: usize = 2048;
pub const MAX_PAYLOAD_SIZE: usize = SPI_BUFFER_SIZE - FRAME_HEADER_SIZE;

/// FFI functions for Zephyr SPI peripheral access
pub mod spi_ffi {
    extern "C" {
        /// Initialize SPI peripheral
        pub fn spi_peripheral_init() -> i32;

        /// Populate TX buffer with data to send
        pub fn spi_peripheral_populate(data: *const u8, len: usize) -> usize;

        /// Wait for and perform SPI transaction (blocking)
        pub fn spi_peripheral_transceive() -> i32;

        /// Get pointer to received payload (after magic/length check)
        pub fn spi_peripheral_get_rx_payload(len: *mut usize) -> *const u8;

        /// Get maximum payload size
        pub fn spi_peripheral_max_payload() -> usize;
    }
}

/// SPI-based transport for Arduino Uno Q MCU
pub struct SpiTransport {
    initialized: bool,
    /// Internal TX buffer for building frames
    tx_buffer: [u8; SPI_BUFFER_SIZE],
    tx_len: usize,
    /// Cached RX data pointer and length
    rx_ptr: *const u8,
    rx_len: usize,
    rx_pos: usize,
}

impl SpiTransport {
    /// Create a new SPI transport (uninitialized)
    pub const fn new() -> Self {
        Self {
            initialized: false,
            tx_buffer: [0; SPI_BUFFER_SIZE],
            tx_len: 0,
            rx_ptr: core::ptr::null(),
            rx_len: 0,
            rx_pos: 0,
        }
    }

    /// Initialize the SPI peripheral
    pub fn init(&mut self) -> bool {
        let result = unsafe { spi_ffi::spi_peripheral_init() };
        self.initialized = result == 0;
        self.initialized
    }

    /// Check if the transport is initialized
    #[allow(dead_code)]
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Prepare data to be sent on next SPI transfer
    pub fn prepare_tx(&mut self, data: &[u8]) -> usize {
        if !self.initialized {
            return 0;
        }

        let payload_len = data.len().min(MAX_PAYLOAD_SIZE);

        if payload_len > 0 {
            self.tx_buffer[..payload_len].copy_from_slice(&data[..payload_len]);
        }

        self.tx_len = payload_len;

        unsafe {
            spi_ffi::spi_peripheral_populate(self.tx_buffer.as_ptr(), self.tx_len);
        }

        payload_len
    }

    /// Wait for and perform an SPI transaction
    pub fn transceive(&mut self) -> usize {
        if !self.initialized {
            return 0;
        }

        let result = unsafe { spi_ffi::spi_peripheral_transceive() };
        if result < 0 {
            self.rx_ptr = core::ptr::null();
            self.rx_len = 0;
            self.rx_pos = 0;
            return 0;
        }

        let mut len: usize = 0;
        self.rx_ptr = unsafe { spi_ffi::spi_peripheral_get_rx_payload(&mut len as *mut usize) };
        self.rx_len = len;
        self.rx_pos = 0;

        len
    }

    /// Get the maximum payload size
    #[allow(dead_code)]
    pub fn max_payload() -> usize {
        unsafe { spi_ffi::spi_peripheral_max_payload() }
    }
}

impl Default for SpiTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for SpiTransport {
    fn write(&mut self, data: &[u8]) -> usize {
        self.prepare_tx(data)
    }

    fn read(&mut self, buffer: &mut [u8]) -> usize {
        if !self.initialized || self.rx_ptr.is_null() || self.rx_pos >= self.rx_len {
            return 0;
        }

        let available = self.rx_len - self.rx_pos;
        let to_read = buffer.len().min(available);

        if to_read > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    self.rx_ptr.add(self.rx_pos),
                    buffer.as_mut_ptr(),
                    to_read,
                );
            }
            self.rx_pos += to_read;
        }

        to_read
    }

    fn read_byte(&mut self) -> Option<u8> {
        if !self.initialized || self.rx_ptr.is_null() || self.rx_pos >= self.rx_len {
            return None;
        }

        let byte = unsafe { *self.rx_ptr.add(self.rx_pos) };
        self.rx_pos += 1;
        Some(byte)
    }

    fn available(&self) -> bool {
        self.initialized && !self.rx_ptr.is_null() && self.rx_pos < self.rx_len
    }

    fn flush(&mut self) {
        // SPI transactions are atomic, nothing to flush
    }
}

// Safety: SpiTransport is only used on single-threaded MCU
unsafe impl Send for SpiTransport {}

// ============================================================================
// RPC Decoder
// ============================================================================

/// Parsed RPC response
#[derive(Debug)]
pub struct RpcResponse {
    /// Message ID this response is for
    pub msg_id: u32,
    /// Error (if any)
    pub error: RpcError,
    /// Result value (if no error) - stored as raw bytes for later parsing
    pub result_data: [u8; 256],
    pub result_len: usize,
}

impl RpcResponse {
    pub fn new() -> Self {
        Self {
            msg_id: 0,
            error: RpcError::none(),
            result_data: [0u8; 256],
            result_len: 0,
        }
    }
}

impl Default for RpcResponse {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed RPC request (incoming call from router)
#[derive(Debug)]
pub struct RpcRequest {
    /// Message ID
    pub msg_id: u32,
    /// Method name
    pub method: StrBuf,
    /// Parameters data (raw MessagePack)
    pub params_data: [u8; 256],
    pub params_len: usize,
    /// Whether this is a notification (no response needed)
    pub is_notify: bool,
}

impl RpcRequest {
    pub fn new() -> Self {
        Self {
            msg_id: 0,
            method: StrBuf::new(),
            params_data: [0u8; 256],
            params_len: 0,
            is_notify: false,
        }
    }
}

impl Default for RpcRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// RPC Decoder state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecoderState {
    /// Waiting for data
    Idle,
}

/// RPC Decoder for parsing MessagePack-RPC messages from the transport
pub struct RpcDecoder {
    /// Receive buffer
    buffer: [u8; DECODER_BUFFER_SIZE],
    /// Current position in buffer
    pos: usize,
    /// Current state
    #[allow(dead_code)]
    state: DecoderState,
    /// Detected packet type
    #[allow(dead_code)]
    packet_type: Option<RpcMessageType>,
    /// Expected packet size (if known)
    #[allow(dead_code)]
    expected_size: usize,
    /// Number of discarded packets (parse errors)
    discarded_packets: u32,
    /// Pending responses (simple queue - holds up to 4)
    pending_responses: [Option<RpcResponse>; 4],
    /// Pending requests (simple queue - holds up to 4)
    pending_requests: [Option<RpcRequest>; 4],
}

impl RpcDecoder {
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; DECODER_BUFFER_SIZE],
            pos: 0,
            state: DecoderState::Idle,
            packet_type: None,
            expected_size: 0,
            discarded_packets: 0,
            pending_responses: [None, None, None, None],
            pending_requests: [None, None, None, None],
        }
    }

    /// Get number of discarded packets
    pub fn discarded_packets(&self) -> u32 {
        self.discarded_packets
    }

    /// Get a response for the given message ID
    pub fn get_response(&mut self, msg_id: u32) -> Option<RpcResponse> {
        for slot in self.pending_responses.iter_mut() {
            if slot.as_ref().map_or(false, |r| r.msg_id == msg_id) {
                return slot.take();
            }
        }
        None
    }

    /// Check if any request is pending
    pub fn has_request(&self) -> bool {
        self.pending_requests.iter().any(|r| r.is_some())
    }

    /// Get the next pending request
    pub fn get_request(&mut self) -> Option<RpcRequest> {
        for slot in self.pending_requests.iter_mut() {
            if slot.is_some() {
                return slot.take();
            }
        }
        None
    }

    /// Process incoming data from transport
    pub fn decode<T: Transport>(&mut self, transport: &mut T) {
        // Read available data
        while transport.available() && self.pos < DECODER_BUFFER_SIZE {
            if let Some(byte) = transport.read_byte() {
                self.buffer[self.pos] = byte;
                self.pos += 1;
            } else {
                break;
            }
        }

        // Try to parse complete messages
        self.try_parse();
    }

    /// Try to parse buffered data as RPC messages
    fn try_parse(&mut self) {
        if self.pos < MIN_RPC_BYTES {
            return;
        }

        // Copy buffer data to avoid borrow issues
        let mut temp_buf = [0u8; DECODER_BUFFER_SIZE];
        temp_buf[..self.pos].copy_from_slice(&self.buffer[..self.pos]);
        let buf_len = self.pos;

        // Try to parse as MessagePack array
        let mut unpacker = MsgPackUnpacker::new(&temp_buf[..buf_len]);

        // Get array header
        let array_len = match unpacker.unpack_array_header() {
            Some(len) => len,
            None => {
                self.discard_byte();
                return;
            }
        };

        // First element should be message type
        let msg_type = match unpacker.unpack_uint() {
            Some(t) if t <= 2 => RpcMessageType::try_from(t as u8).ok(),
            _ => {
                self.discard_byte();
                return;
            }
        };

        // Validate array size for message type
        let expected_size = match msg_type {
            Some(RpcMessageType::Call) | Some(RpcMessageType::Response) => 4,
            Some(RpcMessageType::Notify) => 3,
            None => {
                self.discard_byte();
                return;
            }
        };

        if array_len != expected_size {
            self.discard_byte();
            return;
        }

        // Parse based on message type
        match msg_type {
            Some(RpcMessageType::Response) => {
                self.parse_response_from_buf(&temp_buf[..buf_len], &mut unpacker);
            }
            Some(RpcMessageType::Call) => {
                self.parse_request_from_buf(&temp_buf[..buf_len], &mut unpacker, false);
            }
            Some(RpcMessageType::Notify) => {
                self.parse_request_from_buf(&temp_buf[..buf_len], &mut unpacker, true);
            }
            None => {
                self.discard_byte();
            }
        }
    }

    /// Parse an RPC response message from temporary buffer
    fn parse_response_from_buf(&mut self, buf: &[u8], unpacker: &mut MsgPackUnpacker) {
        let msg_id = match unpacker.unpack_uint() {
            Some(id) => id as u32,
            None => {
                self.discard_byte();
                return;
            }
        };

        // Parse error (nil or array [code, message])
        let error = match unpacker.unpack() {
            Some(MsgPackValue::Nil) => RpcError::none(),
            Some(MsgPackValue::ArrayHeader(len)) if len >= 2 => {
                let code = match unpacker.unpack() {
                    Some(MsgPackValue::Int(i)) => i as u8,
                    Some(MsgPackValue::UInt(u)) => u as u8,
                    _ => 0xFF,
                };

                let msg = match unpacker.unpack() {
                    Some(MsgPackValue::Str(s)) => {
                        StrBuf::from_bytes(s.as_bytes()).unwrap_or_default()
                    }
                    _ => StrBuf::new(),
                };

                // Skip remaining array elements if any
                for _ in 2..len {
                    unpacker.unpack();
                }

                RpcError {
                    code: RpcErrorCode::from(code),
                    message: msg,
                }
            }
            _ => {
                self.discard_byte();
                return;
            }
        };

        // Store result position for later extraction
        let result_start = unpacker.position();

        // Skip the result value to get end position
        if unpacker.unpack().is_none() {
            self.discard_byte();
            return;
        }

        let result_end = unpacker.position();

        // Create response
        let mut response = RpcResponse::new();
        response.msg_id = msg_id;
        response.error = error;

        let result_len = (result_end - result_start).min(response.result_data.len());
        response.result_data[..result_len]
            .copy_from_slice(&buf[result_start..result_start + result_len]);
        response.result_len = result_len;

        // Queue the response
        self.queue_response(response);

        // Remove parsed data from buffer
        let consumed = unpacker.position();
        self.consume_buffer(consumed);
    }

    /// Parse an RPC request/notification message from temporary buffer
    fn parse_request_from_buf(
        &mut self,
        buf: &[u8],
        unpacker: &mut MsgPackUnpacker,
        is_notify: bool,
    ) {
        let msg_id = if !is_notify {
            match unpacker.unpack_uint() {
                Some(id) => id as u32,
                None => {
                    self.discard_byte();
                    return;
                }
            }
        } else {
            0
        };

        // Get method name
        let method = match unpacker.unpack_str() {
            Some(s) => match StrBuf::from_bytes(s.as_bytes()) {
                Some(buf) => buf,
                None => {
                    self.discard_byte();
                    return;
                }
            },
            None => {
                self.discard_byte();
                return;
            }
        };

        // Store params position
        let params_start = unpacker.position();

        // Skip params array
        match unpacker.unpack() {
            Some(MsgPackValue::ArrayHeader(len)) => {
                for _ in 0..len {
                    if unpacker.unpack().is_none() {
                        self.discard_byte();
                        return;
                    }
                }
            }
            None => {
                self.discard_byte();
                return;
            }
            _ => {
                // Not an array - that's OK, could be nil or other value
            }
        }

        let params_end = unpacker.position();

        // Create request
        let mut request = RpcRequest::new();
        request.msg_id = msg_id;
        request.method = method;
        request.is_notify = is_notify;

        let params_len = (params_end - params_start).min(request.params_data.len());
        request.params_data[..params_len]
            .copy_from_slice(&buf[params_start..params_start + params_len]);
        request.params_len = params_len;

        // Queue the request
        self.queue_request(request);

        // Remove parsed data from buffer
        let consumed = unpacker.position();
        self.consume_buffer(consumed);
    }

    /// Queue a response
    fn queue_response(&mut self, response: RpcResponse) {
        for slot in self.pending_responses.iter_mut() {
            if slot.is_none() {
                *slot = Some(response);
                return;
            }
        }
        // Queue full - discard oldest
        self.pending_responses[0] = Some(response);
        self.discarded_packets += 1;
    }

    /// Queue a request
    fn queue_request(&mut self, request: RpcRequest) {
        for slot in self.pending_requests.iter_mut() {
            if slot.is_none() {
                *slot = Some(request);
                return;
            }
        }
        // Queue full - discard oldest
        self.pending_requests[0] = Some(request);
        self.discarded_packets += 1;
    }

    /// Discard the first byte (invalid data)
    fn discard_byte(&mut self) {
        if self.pos > 0 {
            for i in 0..self.pos - 1 {
                self.buffer[i] = self.buffer[i + 1];
            }
            self.pos -= 1;
            self.discarded_packets += 1;
        }
    }

    /// Remove consumed bytes from buffer
    fn consume_buffer(&mut self, count: usize) {
        if count >= self.pos {
            self.pos = 0;
        } else {
            for i in 0..self.pos - count {
                self.buffer[i] = self.buffer[i + count];
            }
            self.pos -= count;
        }
    }
}

impl Default for RpcDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RPC Client
// ============================================================================

/// Maximum wait iterations for blocking calls
const MAX_WAIT_ITERATIONS: u32 = 100000;

/// RPC Client for calling methods on the Linux MPU
pub struct RpcClient {
    /// Message ID counter
    next_msg_id: u32,
    /// Last error from an RPC call
    pub last_error: RpcError,
}

impl RpcClient {
    pub const fn new() -> Self {
        Self {
            next_msg_id: 1,
            last_error: RpcError::none(),
        }
    }

    /// Get the next message ID
    fn next_id(&mut self) -> u32 {
        let id = self.next_msg_id;
        self.next_msg_id = self.next_msg_id.wrapping_add(1);
        if self.next_msg_id == 0 {
            self.next_msg_id = 1;
        }
        id
    }

    /// Send an RPC notification (fire-and-forget, no response expected)
    pub fn notify<T: Transport>(
        &mut self,
        transport: &mut T,
        method: &str,
        params: &[MsgPackValue],
    ) -> bool {
        let mut packer = MsgPackPacker::new();

        if !packer.pack_rpc_notify(method, params) {
            self.last_error = RpcError::new(RpcErrorCode::GenericError, "Pack failed");
            return false;
        }

        let bytes = packer.as_bytes();
        let written = transport.write(bytes);
        transport.flush();

        written == bytes.len()
    }

    /// Send an RPC call and return immediately (non-blocking)
    pub fn send_call<T: Transport>(
        &mut self,
        transport: &mut T,
        method: &str,
        params: &[MsgPackValue],
    ) -> u32 {
        let msg_id = self.next_id();
        let mut packer = MsgPackPacker::new();

        if !packer.pack_rpc_request(msg_id, method, params) {
            self.last_error = RpcError::new(RpcErrorCode::GenericError, "Pack failed");
            return 0;
        }

        let bytes = packer.as_bytes();
        let written = transport.write(bytes);
        transport.flush();

        if written == bytes.len() {
            msg_id
        } else {
            self.last_error = RpcError::new(RpcErrorCode::GenericError, "Write failed");
            0
        }
    }

    /// Wait for and get a response for a specific message ID
    pub fn get_response<T: Transport>(
        &mut self,
        transport: &mut T,
        decoder: &mut RpcDecoder,
        msg_id: u32,
        max_wait_ms: u32,
    ) -> Option<RpcResponse> {
        // First check if already received
        if let Some(resp) = decoder.get_response(msg_id) {
            return Some(resp);
        }

        // Wait for response
        let iterations = if max_wait_ms == 0 {
            1
        } else {
            max_wait_ms * 10
        };

        for _ in 0..iterations.min(MAX_WAIT_ITERATIONS) {
            // Process incoming data
            decoder.decode(transport);

            // Check for our response
            if let Some(resp) = decoder.get_response(msg_id) {
                return Some(resp);
            }
        }

        None
    }

    /// Make a blocking RPC call
    pub fn call<T: Transport>(
        &mut self,
        transport: &mut T,
        decoder: &mut RpcDecoder,
        method: &str,
        params: &[MsgPackValue],
        timeout_ms: u32,
    ) -> Option<RpcResponse> {
        let msg_id = self.send_call(transport, method, params);
        if msg_id == 0 {
            return None;
        }

        self.get_response(transport, decoder, msg_id, timeout_ms)
    }

    /// Make a blocking RPC call and extract an integer result
    pub fn call_get_int<T: Transport>(
        &mut self,
        transport: &mut T,
        decoder: &mut RpcDecoder,
        method: &str,
        params: &[MsgPackValue],
        timeout_ms: u32,
    ) -> Option<i64> {
        let response = self.call(transport, decoder, method, params, timeout_ms)?;

        if response.error.is_error() {
            self.last_error = response.error;
            return None;
        }

        let mut unpacker = MsgPackUnpacker::new(&response.result_data[..response.result_len]);
        match unpacker.unpack()? {
            MsgPackValue::Int(i) => Some(i),
            MsgPackValue::UInt(u) => Some(u as i64),
            _ => None,
        }
    }

    /// Make a blocking RPC call and extract a boolean result
    pub fn call_get_bool<T: Transport>(
        &mut self,
        transport: &mut T,
        decoder: &mut RpcDecoder,
        method: &str,
        params: &[MsgPackValue],
        timeout_ms: u32,
    ) -> Option<bool> {
        let response = self.call(transport, decoder, method, params, timeout_ms)?;

        if response.error.is_error() {
            self.last_error = response.error;
            return None;
        }

        let mut unpacker = MsgPackUnpacker::new(&response.result_data[..response.result_len]);
        match unpacker.unpack()? {
            MsgPackValue::Bool(b) => Some(b),
            MsgPackValue::Nil => Some(false),
            _ => None,
        }
    }
}

impl Default for RpcClient {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RPC Server
// ============================================================================

/// Maximum number of registered handlers
pub const MAX_HANDLERS: usize = 32;

/// Maximum number of parameters per RPC call
pub const MAX_PARAMS: usize = 8;

/// RPC method handler function type
pub type RpcHandler = fn(usize) -> RpcResult;

/// Result from an RPC handler
#[derive(Debug, Clone)]
pub enum RpcResult {
    /// Success with integer result
    Int(i64),
    /// Success with boolean result
    Bool(bool),
    /// Success with string result (static lifetime)
    Str(&'static str),
    /// Success with nil result
    Nil,
    /// Error with code and message
    Error(i32, &'static str),
}

/// Global parameter storage for RPC handlers
pub struct ParamBuffer {
    /// Integer parameters extracted from RPC call
    pub ints: [i64; MAX_PARAMS],
    /// Boolean parameters
    pub bools: [bool; MAX_PARAMS],
    /// Count of parameters
    pub count: usize,
}

impl ParamBuffer {
    pub const fn new() -> Self {
        Self {
            ints: [0; MAX_PARAMS],
            bools: [false; MAX_PARAMS],
            count: 0,
        }
    }

    pub fn clear(&mut self) {
        self.count = 0;
    }
}

/// Global parameter buffer - handlers read parameters from here
pub static mut PARAMS: ParamBuffer = ParamBuffer::new();

/// Handler registration entry
struct HandlerEntry {
    method: [u8; MAX_METHOD_NAME_LEN],
    method_len: usize,
    handler: RpcHandler,
}

impl HandlerEntry {
    const fn empty() -> Self {
        Self {
            method: [0; MAX_METHOD_NAME_LEN],
            method_len: 0,
            handler: empty_handler,
        }
    }
}

fn empty_handler(_count: usize) -> RpcResult {
    RpcResult::Error(-1, "No handler")
}

/// RPC Server for handling incoming requests
pub struct RpcServer {
    handlers: [HandlerEntry; MAX_HANDLERS],
    handler_count: usize,
    /// Response buffer
    response_buffer: [u8; 256],
}

impl RpcServer {
    /// Create a new RPC server
    pub const fn new() -> Self {
        Self {
            handlers: [const { HandlerEntry::empty() }; MAX_HANDLERS],
            handler_count: 0,
            response_buffer: [0; 256],
        }
    }

    /// Register a method handler
    pub fn register(&mut self, method: &str, handler: RpcHandler) -> bool {
        if self.handler_count >= MAX_HANDLERS {
            return false;
        }
        if method.len() > MAX_METHOD_NAME_LEN {
            return false;
        }

        let entry = &mut self.handlers[self.handler_count];
        entry.method[..method.len()].copy_from_slice(method.as_bytes());
        entry.method_len = method.len();
        entry.handler = handler;
        self.handler_count += 1;
        true
    }

    /// Find handler for a method
    fn find_handler(&self, method: &str) -> Option<RpcHandler> {
        for i in 0..self.handler_count {
            let entry = &self.handlers[i];
            if entry.method_len == method.len()
                && &entry.method[..entry.method_len] == method.as_bytes()
            {
                return Some(entry.handler);
            }
        }
        None
    }

    /// Process an RPC message
    pub fn process(&mut self, data: &[u8]) -> Option<&[u8]> {
        let mut unpacker = MsgPackUnpacker::new(data);

        let arr_len = match unpacker.unpack_array_header() {
            Some(len) => len,
            None => return None,
        };

        if arr_len < 3 {
            return None;
        }

        let msg_type = match unpacker.unpack_uint() {
            Some(t) => t as u8,
            None => return None,
        };

        match RpcMessageType::try_from(msg_type) {
            Ok(RpcMessageType::Call) => self.handle_request(&mut unpacker),
            Ok(RpcMessageType::Notify) => {
                self.handle_notification(&mut unpacker);
                None
            }
            Ok(RpcMessageType::Response) => None,
            Err(_) => None,
        }
    }

    /// Handle an RPC request
    fn handle_request(&mut self, unpacker: &mut MsgPackUnpacker) -> Option<&[u8]> {
        let msg_id = match unpacker.unpack_uint() {
            Some(id) => id as u32,
            None => return None,
        };

        let method = match unpacker.unpack_str() {
            Some(s) => s,
            None => return self.make_error_response(msg_id, -1, "Invalid method"),
        };

        let param_count = self.extract_params(unpacker);

        if let Some(handler) = self.find_handler(method) {
            match handler(param_count) {
                RpcResult::Int(i) => self.make_response(msg_id, &MsgPackValue::Int(i)),
                RpcResult::Bool(b) => self.make_response(msg_id, &MsgPackValue::Bool(b)),
                RpcResult::Str(s) => self.make_response(msg_id, &MsgPackValue::Str(s)),
                RpcResult::Nil => self.make_response(msg_id, &MsgPackValue::Nil),
                RpcResult::Error(code, msg) => self.make_error_response(msg_id, code, msg),
            }
        } else {
            self.make_error_response(msg_id, -3, "Method not found")
        }
    }

    /// Extract parameters from unpacker into global PARAMS buffer
    fn extract_params(&mut self, unpacker: &mut MsgPackUnpacker) -> usize {
        unsafe {
            PARAMS.clear();
        }

        let arr_len = match unpacker.unpack_array_header() {
            Some(len) => len.min(MAX_PARAMS),
            None => return 0,
        };

        for i in 0..arr_len {
            match unpacker.unpack() {
                Some(MsgPackValue::Int(v)) => unsafe {
                    PARAMS.ints[i] = v;
                    PARAMS.count = i + 1;
                },
                Some(MsgPackValue::UInt(v)) => unsafe {
                    PARAMS.ints[i] = v as i64;
                    PARAMS.count = i + 1;
                },
                Some(MsgPackValue::Bool(v)) => unsafe {
                    PARAMS.bools[i] = v;
                    PARAMS.ints[i] = if v { 1 } else { 0 };
                    PARAMS.count = i + 1;
                },
                _ => break,
            }
        }

        unsafe { PARAMS.count }
    }

    /// Handle an RPC notification (fire-and-forget)
    fn handle_notification(&mut self, unpacker: &mut MsgPackUnpacker) {
        let method = match unpacker.unpack_str() {
            Some(s) => s,
            None => return,
        };

        let param_count = self.extract_params(unpacker);

        if let Some(handler) = self.find_handler(method) {
            let _ = handler(param_count);
        }
    }

    /// Create a success response
    fn make_response(&mut self, msg_id: u32, result: &MsgPackValue) -> Option<&[u8]> {
        let mut packer = MsgPackPacker::new();

        packer.pack_array_header(4);
        packer.pack_int(RpcMessageType::Response as i64);
        packer.pack_uint(msg_id as u64);
        packer.pack_nil();
        packer.pack_value(result);

        let bytes = packer.as_bytes();
        let len = bytes.len().min(self.response_buffer.len());
        self.response_buffer[..len].copy_from_slice(&bytes[..len]);

        Some(&self.response_buffer[..len])
    }

    /// Create an error response
    fn make_error_response(&mut self, msg_id: u32, code: i32, message: &str) -> Option<&[u8]> {
        let mut packer = MsgPackPacker::new();

        packer.pack_rpc_response(msg_id, Some((code, message)), None);

        let bytes = packer.as_bytes();
        let len = bytes.len().min(self.response_buffer.len());
        self.response_buffer[..len].copy_from_slice(&bytes[..len]);

        Some(&self.response_buffer[..len])
    }
}

impl Default for RpcServer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Bridge (High-level API)
// ============================================================================

/// High-level RPC Bridge for Arduino Uno Q
pub struct Bridge {
    transport: UartTransport,
    decoder: RpcDecoder,
    client: RpcClient,
    started: bool,
    router_version: [u8; 32],
    router_version_len: usize,
}

impl Bridge {
    /// Create a new Bridge instance
    pub const fn new() -> Self {
        Self {
            transport: UartTransport::new(),
            decoder: RpcDecoder::new(),
            client: RpcClient::new(),
            started: false,
            router_version: [0u8; 32],
            router_version_len: 0,
        }
    }

    /// Initialize the bridge with default baud rate (115200)
    pub fn begin(&mut self) -> bool {
        self.begin_with_baud(DEFAULT_BAUD_RATE)
    }

    /// Initialize the bridge with a custom baud rate
    pub fn begin_with_baud(&mut self, baud_rate: u32) -> bool {
        if self.started {
            return true;
        }

        if !self.transport.init(baud_rate) {
            return false;
        }

        // Reset router state
        if !self.call_void("$/reset", &[]) {
            // Reset failed, but we might still be able to communicate
        }

        // Try to get router version
        self.get_router_version_internal();

        self.started = true;
        true
    }

    /// Check if the bridge is initialized and ready
    pub fn is_started(&self) -> bool {
        self.started
    }

    /// Get the router version string (if available)
    pub fn router_version(&self) -> Option<&str> {
        if self.router_version_len > 0 {
            core::str::from_utf8(&self.router_version[..self.router_version_len]).ok()
        } else {
            None
        }
    }

    /// Process incoming RPC messages
    pub fn update(&mut self) {
        self.decoder.decode(&mut self.transport);
    }

    /// Send an RPC notification (fire-and-forget)
    pub fn notify(&mut self, method: &str, params: &[MsgPackValue]) -> bool {
        if !self.started {
            return false;
        }
        self.client.notify(&mut self.transport, method, params)
    }

    /// Make a blocking RPC call (with default timeout)
    pub fn call_void(&mut self, method: &str, params: &[MsgPackValue]) -> bool {
        self.call_void_timeout(method, params, 5000)
    }

    /// Make a blocking RPC call with custom timeout
    pub fn call_void_timeout(
        &mut self,
        method: &str,
        params: &[MsgPackValue],
        timeout_ms: u32,
    ) -> bool {
        if !self.started && method != "$/reset" {
            return false;
        }

        let response = self.client.call(
            &mut self.transport,
            &mut self.decoder,
            method,
            params,
            timeout_ms,
        );

        match response {
            Some(r) => !r.error.is_error(),
            None => false,
        }
    }

    /// Make an RPC call that returns an integer
    pub fn call_int(&mut self, method: &str, params: &[MsgPackValue]) -> Option<i64> {
        self.call_int_timeout(method, params, 5000)
    }

    /// Make an RPC call that returns an integer with custom timeout
    pub fn call_int_timeout(
        &mut self,
        method: &str,
        params: &[MsgPackValue],
        timeout_ms: u32,
    ) -> Option<i64> {
        if !self.started {
            return None;
        }
        self.client.call_get_int(
            &mut self.transport,
            &mut self.decoder,
            method,
            params,
            timeout_ms,
        )
    }

    /// Make an RPC call that returns a boolean
    pub fn call_bool(&mut self, method: &str, params: &[MsgPackValue]) -> Option<bool> {
        self.call_bool_timeout(method, params, 5000)
    }

    /// Make an RPC call that returns a boolean with custom timeout
    pub fn call_bool_timeout(
        &mut self,
        method: &str,
        params: &[MsgPackValue],
        timeout_ms: u32,
    ) -> Option<bool> {
        if !self.started {
            return None;
        }
        self.client.call_get_bool(
            &mut self.transport,
            &mut self.decoder,
            method,
            params,
            timeout_ms,
        )
    }

    /// Get the last error from an RPC call
    pub fn last_error(&self) -> &RpcError {
        &self.client.last_error
    }

    /// Get the number of discarded packets (parse errors)
    pub fn discarded_packets(&self) -> u32 {
        self.decoder.discarded_packets()
    }

    /// Internal: Get router version
    fn get_router_version_internal(&mut self) {
        let response = self.client.call(
            &mut self.transport,
            &mut self.decoder,
            "$/version",
            &[],
            1000,
        );

        if let Some(r) = response {
            if !r.error.is_error() && r.result_len > 0 {
                let mut unpacker = MsgPackUnpacker::new(&r.result_data[..r.result_len]);
                if let Some(MsgPackValue::Str(s)) = unpacker.unpack() {
                    let bytes = s.as_bytes();
                    let len = bytes.len().min(self.router_version.len());
                    self.router_version[..len].copy_from_slice(&bytes[..len]);
                    self.router_version_len = len;
                }
            }
        }
    }

    /// Register a method name with the router
    pub fn register_method(&mut self, method: &str) -> bool {
        self.call_bool("$/register", &[MsgPackValue::Str(method)])
            .unwrap_or(false)
    }

    /// Check if there's an incoming RPC request to process
    pub fn has_incoming_request(&self) -> bool {
        self.decoder.has_request()
    }

    /// Get the next incoming RPC request (if any)
    pub fn get_incoming_request(&mut self) -> Option<RpcRequest> {
        self.decoder.get_request()
    }

    /// Send a response to an incoming request
    pub fn send_response(&mut self, msg_id: u32, result: &MsgPackValue) -> bool {
        let mut packer = MsgPackPacker::new();
        if !packer.pack_rpc_response(msg_id, None, Some(result)) {
            return false;
        }

        let bytes = packer.as_bytes();
        let written = self.transport.write(bytes);
        self.transport.flush();

        written == bytes.len()
    }

    /// Send an error response to an incoming request
    pub fn send_error_response(&mut self, msg_id: u32, error_code: i32, error_msg: &str) -> bool {
        let mut packer = MsgPackPacker::new();
        if !packer.pack_rpc_response(msg_id, Some((error_code, error_msg)), None) {
            return false;
        }

        let bytes = packer.as_bytes();
        let written = self.transport.write(bytes);
        self.transport.flush();

        written == bytes.len()
    }
}

impl Default for Bridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience type alias
pub type RpcValue<'a> = MsgPackValue<'a>;
