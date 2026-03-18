// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// DragonWing Remote IoT - Arduino IoT Companion App integration
//
// Enables phones running the Arduino IoT Remote app to connect and stream
// sensor data (camera, IMU, etc.) to the Arduino Uno Q board.
//
// # Architecture
//
// ```text
// ┌─────────────────────┐              ┌─────────────────────┐
// │   Phone (IoT App)   │              │  Arduino Uno Q MPU  │
// │                     │              │   (QRB2210 Linux)   │
// │  1. Scan QR code    │              │                     │
// │     (OTP + WS URL)  │              │  ┌───────────────┐  │
// │                     │   WebSocket  │  │ RemoteServer  │  │
// │  2. Connect WS      │◄────────────►│  │               │  │
// │     (send OTP)      │   Control    │  │ - QR gen      │  │
// │                     │              │  │ - WS server   │  │
// │  3. Stream video    │     HTTP     │  │ - HTTP server │  │
// │     on port 4912    │─────────────►│  │ - RPC bridge  │  │
// │                     │    Data      │  └───────┬───────┘  │
// └─────────────────────┘              │          │          │
//                                      │          │ RPC      │
//                                      │          ▼          │
//                                      │  ┌───────────────┐  │
//                                      │  │  STM32U585    │  │
//                                      │  │    MCU        │  │
//                                      │  └───────────────┘  │
//                                      └─────────────────────┘
// ```
//
// # Protocol Details
//
// The Arduino IoT Companion App uses the following protocol:
//
// 1. **QR Code**: Contains URL `https://cloud.arduino.cc/installmobileapp?otp=XXXXXX&protocol=ws&ip=X.X.X.X&port=YYYY`
// 2. **WebSocket**: Control channel for pairing (OTP verification) and commands
// 3. **HTTP**: Data channel on port 4912 for video streaming
//
// Both devices must be on the same local network - no cloud involved.

pub mod bpp;
pub mod camera_server;
pub mod error;
pub mod otp;
pub mod qr;
pub mod server;
pub mod websocket;
pub mod http;
pub mod protocol;

#[cfg(feature = "rpc-bridge")]
pub mod bridge;

// Re-exports for convenience
pub use bpp::{BppCodec, BppError, SecurityMode};
pub use camera_server::{
    CameraServer, CameraServerBuilder, CameraEvent, CameraStatus, VideoFrame,
    generate_secret, DEFAULT_CAMERA_PORT,
};
pub use error::{RemoteIotError, Result};
pub use otp::Otp;
pub use qr::QrGenerator;
pub use server::{RemoteEvent, RemoteServer, RemoteServerConfig, RemoteServerBuilder};
pub use protocol::{ControlMessage, DataMessage, ConnectionState, SensorType};

/// Default port for the video data stream (matches Arduino IoT app)
pub const DEFAULT_DATA_PORT: u16 = 4912;

/// Default timeout for OTP validation (30 seconds)
pub const DEFAULT_OTP_TIMEOUT_SECS: u64 = 30;

/// Protocol version supported
pub const PROTOCOL_VERSION: &str = "1.0";
