// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// PSA Secure Storage - Error Types
//
// This module defines error types for the PSA Secure Storage API,
// following the PSA Certified API error codes.

use core::fmt;

/// PSA API error codes.
///
/// These error codes follow the PSA Certified API specification and
/// are returned by both the ITS (Internal Trusted Storage) and
/// PSA Crypto APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsaError {
    /// An unspecified internal failure occurred.
    GenericError,

    /// The operation is not permitted.
    /// For ITS: The entry was created with `WRITE_ONCE` flag.
    /// For Crypto: The key doesn't have the required usage flags.
    NotPermitted,

    /// The operation or parameters are not supported.
    NotSupported,

    /// One or more arguments are invalid.
    InvalidArgument,

    /// An entry with the specified UID already exists.
    AlreadyExists,

    /// The specified UID was not found in storage.
    DoesNotExist,

    /// There is insufficient space in storage.
    InsufficientStorage,

    /// The physical storage has failed (fatal error).
    StorageFailure,

    /// The data failed authentication (integrity check failed).
    InvalidSignature,

    /// The stored data is corrupt.
    DataCorrupt,

    /// Insufficient memory for the operation.
    InsufficientMemory,

    /// Communication failure with the secure element.
    CommunicationFailure,

    /// Hardware failure.
    HardwareFailure,

    /// Insufficient entropy for random number generation.
    InsufficientEntropy,

    /// The signature or MAC is invalid.
    InvalidPadding,

    /// The data is invalid.
    DataInvalid,

    /// Bad state - operation not permitted in current state.
    BadState,

    /// Buffer too small for the output.
    BufferTooSmall,

    /// An unknown error code was returned.
    Unknown(i32),
}

impl PsaError {
    /// Convert from a raw PSA status code.
    pub fn from_status(status: i32) -> Result<(), Self> {
        if status == 0 {
            Ok(())
        } else {
            Err(Self::from(status))
        }
    }
}

impl From<i32> for PsaError {
    fn from(code: i32) -> Self {
        match code {
            0 => panic!("PSA_SUCCESS should not be converted to PsaError"),
            -132 => PsaError::GenericError,
            -133 => PsaError::NotPermitted,
            -134 => PsaError::NotSupported,
            -135 => PsaError::InvalidArgument,
            -136 => PsaError::InsufficientMemory,
            -137 => PsaError::CommunicationFailure,
            -138 => PsaError::HardwareFailure,
            -139 => PsaError::AlreadyExists,
            -140 => PsaError::DoesNotExist,
            -142 => PsaError::InsufficientStorage,
            -143 => PsaError::InsufficientEntropy,
            -144 => PsaError::InvalidSignature,
            -145 => PsaError::InvalidPadding,
            -146 => PsaError::StorageFailure,
            -147 => PsaError::DataInvalid,
            -148 => PsaError::DataCorrupt,
            -149 => PsaError::InvalidSignature, // Also used for invalid signature
            -150 => PsaError::BadState,
            -152 => PsaError::DataCorrupt,
            -200 => PsaError::BufferTooSmall,
            code => PsaError::Unknown(code),
        }
    }
}

impl fmt::Display for PsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PsaError::GenericError => write!(f, "Generic error"),
            PsaError::NotPermitted => write!(f, "Operation not permitted"),
            PsaError::NotSupported => write!(f, "Operation not supported"),
            PsaError::InvalidArgument => write!(f, "Invalid argument"),
            PsaError::AlreadyExists => write!(f, "Entry already exists"),
            PsaError::DoesNotExist => write!(f, "Entry does not exist"),
            PsaError::InsufficientStorage => write!(f, "Insufficient storage space"),
            PsaError::StorageFailure => write!(f, "Storage failure"),
            PsaError::InvalidSignature => write!(f, "Invalid signature or authentication"),
            PsaError::DataCorrupt => write!(f, "Data is corrupt"),
            PsaError::InsufficientMemory => write!(f, "Insufficient memory"),
            PsaError::CommunicationFailure => write!(f, "Communication failure"),
            PsaError::HardwareFailure => write!(f, "Hardware failure"),
            PsaError::InsufficientEntropy => write!(f, "Insufficient entropy"),
            PsaError::InvalidPadding => write!(f, "Invalid padding"),
            PsaError::DataInvalid => write!(f, "Data is invalid"),
            PsaError::BadState => write!(f, "Bad state"),
            PsaError::BufferTooSmall => write!(f, "Buffer too small"),
            PsaError::Unknown(code) => write!(f, "Unknown PSA error ({})", code),
        }
    }
}

/// Result type alias for PSA operations.
pub type PsaResult<T> = Result<T, PsaError>;
