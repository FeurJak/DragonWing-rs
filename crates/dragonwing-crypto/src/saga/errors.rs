//! Error types for the SAGA scheme.
//!
//! Uses manual error implementation instead of thiserror for no_std compatibility.

use core::fmt;

/// Error type for SAGA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SagaError {
    /// Length mismatch between expected and provided arrays
    LengthMismatch { expected: usize, got: usize },
    /// Requested more attributes than MAX_ATTRS allows
    TooManyAttributes { max: usize, requested: usize },
    /// Failed to invert scalar (x+e = 0, extremely rare)
    NonInvertible,
    /// Invalid NIZK proof
    InvalidProof,
}

impl fmt::Display for SagaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SagaError::LengthMismatch { expected, got } => {
                write!(f, "length mismatch: expected {}, got {}", expected, got)
            }
            SagaError::TooManyAttributes { max, requested } => {
                write!(
                    f,
                    "too many attributes: max {}, requested {}",
                    max, requested
                )
            }
            SagaError::NonInvertible => {
                write!(f, "failed to invert scalar (x+e)=0 - resample e and retry")
            }
            SagaError::InvalidProof => {
                write!(f, "invalid NIZK proof")
            }
        }
    }
}
