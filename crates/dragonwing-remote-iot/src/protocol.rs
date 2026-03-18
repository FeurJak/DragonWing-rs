// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Protocol definitions for Arduino IoT Companion App communication

use serde::{Deserialize, Serialize};

/// Control messages sent over the WebSocket connection.
///
/// These messages handle pairing and control of the phone connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ControlMessage {
    /// Initial handshake from phone with OTP
    #[serde(rename = "auth")]
    Auth { otp: String },

    /// Authentication response
    #[serde(rename = "auth_response")]
    AuthResponse { success: bool, message: String },

    /// Phone is ready to stream data
    #[serde(rename = "ready")]
    Ready {
        #[serde(default)]
        capabilities: Vec<String>,
    },

    /// Server acknowledges phone is ready
    #[serde(rename = "ready_ack")]
    ReadyAck { data_port: u16 },

    /// Start streaming a specific sensor
    #[serde(rename = "start_stream")]
    StartStream { sensor: SensorType },

    /// Stop streaming a specific sensor
    #[serde(rename = "stop_stream")]
    StopStream { sensor: SensorType },

    /// Ping/keep-alive
    #[serde(rename = "ping")]
    Ping,

    /// Pong response to ping
    #[serde(rename = "pong")]
    Pong,

    /// Error message
    #[serde(rename = "error")]
    Error { code: u32, message: String },

    /// Phone disconnecting gracefully
    #[serde(rename = "disconnect")]
    Disconnect,
}

/// Types of sensors available on the phone
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SensorType {
    /// Camera video stream
    Camera,
    /// Accelerometer data
    Accelerometer,
    /// Gyroscope data
    Gyroscope,
    /// Magnetometer/compass data
    Magnetometer,
    /// GPS location data
    Gps,
    /// Microphone audio stream
    Microphone,
    /// Light sensor
    Light,
    /// Proximity sensor
    Proximity,
    /// Barometer/pressure sensor
    Barometer,
}

impl std::fmt::Display for SensorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SensorType::Camera => write!(f, "camera"),
            SensorType::Accelerometer => write!(f, "accelerometer"),
            SensorType::Gyroscope => write!(f, "gyroscope"),
            SensorType::Magnetometer => write!(f, "magnetometer"),
            SensorType::Gps => write!(f, "gps"),
            SensorType::Microphone => write!(f, "microphone"),
            SensorType::Light => write!(f, "light"),
            SensorType::Proximity => write!(f, "proximity"),
            SensorType::Barometer => write!(f, "barometer"),
        }
    }
}

/// Data messages received on the HTTP data channel.
///
/// Video frames and sensor data come through here.
#[derive(Debug, Clone)]
pub enum DataMessage {
    /// Video frame (JPEG or H.264 NAL unit)
    VideoFrame {
        /// Frame timestamp in milliseconds
        timestamp_ms: u64,
        /// Frame data
        data: Vec<u8>,
        /// Frame format
        format: VideoFormat,
    },

    /// IMU sensor reading
    ImuReading {
        /// Timestamp in milliseconds
        timestamp_ms: u64,
        /// Accelerometer [x, y, z] in m/s²
        accelerometer: Option<[f32; 3]>,
        /// Gyroscope [x, y, z] in rad/s
        gyroscope: Option<[f32; 3]>,
        /// Magnetometer [x, y, z] in µT
        magnetometer: Option<[f32; 3]>,
    },

    /// GPS location
    GpsLocation {
        timestamp_ms: u64,
        latitude: f64,
        longitude: f64,
        altitude: Option<f64>,
        accuracy: Option<f32>,
    },

    /// Generic sensor reading
    SensorReading {
        sensor: SensorType,
        timestamp_ms: u64,
        value: f64,
    },
}

/// Video frame formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoFormat {
    /// JPEG image frame
    Jpeg,
    /// H.264 NAL unit
    H264,
    /// Raw YUV420
    Yuv420,
}

/// Connection state of a phone client
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    /// Waiting for phone to connect
    #[default]
    WaitingForConnection,
    /// Connected, waiting for OTP authentication
    WaitingForAuth,
    /// Authenticated, waiting for ready signal
    Authenticated,
    /// Ready to stream data
    Ready,
    /// Actively streaming data
    Streaming,
    /// Disconnected
    Disconnected,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::WaitingForConnection => write!(f, "waiting_for_connection"),
            ConnectionState::WaitingForAuth => write!(f, "waiting_for_auth"),
            ConnectionState::Authenticated => write!(f, "authenticated"),
            ConnectionState::Ready => write!(f, "ready"),
            ConnectionState::Streaming => write!(f, "streaming"),
            ConnectionState::Disconnected => write!(f, "disconnected"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_message_serialization() {
        let auth = ControlMessage::Auth {
            otp: "123456".to_string(),
        };
        let json = serde_json::to_string(&auth).unwrap();
        assert!(json.contains("auth"));
        assert!(json.contains("123456"));

        let parsed: ControlMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ControlMessage::Auth { otp } => assert_eq!(otp, "123456"),
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_sensor_type_display() {
        assert_eq!(SensorType::Camera.to_string(), "camera");
        assert_eq!(SensorType::Accelerometer.to_string(), "accelerometer");
    }
}
