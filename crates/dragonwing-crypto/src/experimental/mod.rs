//! Experimental cryptographic protocols.
//!
//! This module contains protocols that are still under development or
//! are considered experimental. APIs may change without notice.
//!
//! # Protocols
//!
//! - [`saga_xwing`] - SAGA + X-Wing hybrid protocol for credential-protected
//!   post-quantum key exchange
//! - [`pq_ratchet`] - Post-quantum double ratchet protocol using X-Wing

#[cfg(feature = "saga_xwing")]
pub mod saga_xwing;

#[cfg(feature = "saga_xwing")]
pub use saga_xwing::*;

#[cfg(feature = "pq_ratchet")]
pub mod pq_ratchet;

#[cfg(feature = "pq_ratchet")]
pub use pq_ratchet::kdf;
