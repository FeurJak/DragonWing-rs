// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Shared protocol definitions for MessagePack-RPC
//
// This module contains types and constants shared between MCU and MPU sides.

// no_std compatibility: import core types
#[cfg(all(feature = "mcu", not(feature = "std")))]
use core::convert::{From, TryFrom};
#[cfg(all(feature = "mcu", not(feature = "std")))]
use core::result::Result::{self, Err, Ok};

/// RPC message types as defined in MessagePack-RPC spec
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RpcMessageType {
    /// Request: [type=0, msgid, method, params]
    Call = 0,
    /// Response: [type=1, msgid, error, result]
    Response = 1,
    /// Notification: [type=2, method, params]
    Notify = 2,
}

impl TryFrom<u8> for RpcMessageType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RpcMessageType::Call),
            1 => Ok(RpcMessageType::Response),
            2 => Ok(RpcMessageType::Notify),
            _ => Err(()),
        }
    }
}

/// Default serial baud rate for UART transport
pub const DEFAULT_BAUD_RATE: u32 = 115200;

/// Default decoder buffer size
pub const DECODER_BUFFER_SIZE: usize = 1024;

/// Default RPC buffer size
pub const DEFAULT_RPC_BUFFER_SIZE: usize = 256;

/// Minimum valid RPC message size
pub const MIN_RPC_BYTES: usize = 4;

/// Maximum method name length
pub const MAX_METHOD_NAME_LEN: usize = 64;

/// Maximum string value length
pub const MAX_STRING_LEN: usize = 256;

/// RPC error codes (shared between MCU and MPU)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RpcErrorCode {
    /// No error
    NoError = 0x00,
    /// Parsing error
    ParsingError = 0xFC,
    /// Malformed call
    MalformedCall = 0xFD,
    /// Function not found
    FunctionNotFound = 0xFE,
    /// Generic error
    GenericError = 0xFF,
}

impl From<u8> for RpcErrorCode {
    fn from(code: u8) -> Self {
        match code {
            0x00 => RpcErrorCode::NoError,
            0xFC => RpcErrorCode::ParsingError,
            0xFD => RpcErrorCode::MalformedCall,
            0xFE => RpcErrorCode::FunctionNotFound,
            _ => RpcErrorCode::GenericError,
        }
    }
}

// ============================================================================
// MCU-specific protocol types (no_std compatible)
// ============================================================================

#[cfg(feature = "mcu")]
pub mod mcu {
    use super::*;

    /// Fixed-size string buffer for no_std
    #[derive(Debug, Clone)]
    pub struct StrBuf {
        data: [u8; MAX_STRING_LEN],
        len: usize,
    }

    impl StrBuf {
        pub const fn new() -> Self {
            Self {
                data: [0u8; MAX_STRING_LEN],
                len: 0,
            }
        }

        pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
            if bytes.len() > MAX_STRING_LEN {
                return None;
            }
            let mut buf = Self::new();
            buf.data[..bytes.len()].copy_from_slice(bytes);
            buf.len = bytes.len();
            Some(buf)
        }

        pub fn as_str(&self) -> &str {
            // Safety: We only store valid UTF-8
            unsafe { core::str::from_utf8_unchecked(&self.data[..self.len]) }
        }

        pub fn as_bytes(&self) -> &[u8] {
            &self.data[..self.len]
        }

        pub fn len(&self) -> usize {
            self.len
        }

        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
    }

    impl Default for StrBuf {
        fn default() -> Self {
            Self::new()
        }
    }

    /// RPC error with code and message (MCU version)
    #[derive(Debug, Clone)]
    pub struct RpcError {
        /// Error code
        pub code: RpcErrorCode,
        /// Error message/traceback
        pub message: StrBuf,
    }

    impl RpcError {
        /// Create a new error
        pub fn new(code: RpcErrorCode, message: &str) -> Self {
            Self {
                code,
                message: StrBuf::from_bytes(message.as_bytes()).unwrap_or_default(),
            }
        }

        /// Create a "no error" result
        pub const fn none() -> Self {
            Self {
                code: RpcErrorCode::NoError,
                message: StrBuf::new(),
            }
        }

        /// Check if this is an error
        pub fn is_error(&self) -> bool {
            self.code != RpcErrorCode::NoError
        }
    }

    impl Default for RpcError {
        fn default() -> Self {
            Self::none()
        }
    }
}
