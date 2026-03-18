// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Error types for dragonwing-remote-iot

use thiserror::Error;

/// Result type for remote IoT operations
pub type Result<T> = std::result::Result<T, RemoteIotError>;

/// Errors that can occur in the remote IoT server
#[derive(Error, Debug)]
pub enum RemoteIotError {
    /// Failed to bind to network address
    #[error("Failed to bind to {address}: {source}")]
    BindError {
        address: String,
        #[source]
        source: std::io::Error,
    },

    /// WebSocket error
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    /// HTTP server error
    #[error("HTTP server error: {0}")]
    Http(String),

    /// Invalid OTP provided by client
    #[error("Invalid OTP: expected {expected}, got {received}")]
    InvalidOtp { expected: String, received: String },

    /// OTP has expired
    #[error("OTP expired after {timeout_secs} seconds")]
    OtpExpired { timeout_secs: u64 },

    /// Client disconnected unexpectedly
    #[error("Client disconnected")]
    ClientDisconnected,

    /// No local IP address found
    #[error("Could not determine local IP address")]
    NoLocalIp,

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Server is not in the expected state
    #[error("Invalid server state: {0}")]
    InvalidState(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// RPC bridge error (when rpc-bridge feature is enabled)
    #[cfg(feature = "rpc-bridge")]
    #[error("RPC bridge error: {0}")]
    RpcBridge(#[from] dragonwing_rpc::RpcError),
}
