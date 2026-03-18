// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// RPC bridge for forwarding phone data to MCU via dragonwing-rpc

use std::sync::Arc;
use tokio::sync::mpsc;

use dragonwing_rpc::RpcClient;
use rmpv::Value;

use crate::error::Result;
use crate::protocol::{DataMessage, VideoFormat};

/// Bridge that forwards phone data to the MCU via RPC
pub struct RpcBridge {
    /// RPC client for communicating with MCU
    rpc_client: Arc<RpcClient>,
    /// Whether to forward video frames
    forward_video: bool,
    /// Whether to forward IMU data
    forward_imu: bool,
    /// Video frame downsample factor (1 = every frame, 2 = every other frame, etc.)
    video_downsample: u32,
    /// Frame counter for downsampling
    frame_counter: u32,
}

impl RpcBridge {
    /// Create a new RPC bridge with the given client
    pub fn new(rpc_client: RpcClient) -> Self {
        Self {
            rpc_client: Arc::new(rpc_client),
            forward_video: true,
            forward_imu: true,
            video_downsample: 1,
            frame_counter: 0,
        }
    }

    /// Enable/disable video forwarding
    pub fn with_video_forwarding(mut self, enabled: bool) -> Self {
        self.forward_video = enabled;
        self
    }

    /// Enable/disable IMU forwarding
    pub fn with_imu_forwarding(mut self, enabled: bool) -> Self {
        self.forward_imu = enabled;
        self
    }

    /// Set video downsample factor
    pub fn with_video_downsample(mut self, factor: u32) -> Self {
        self.video_downsample = factor.max(1);
        self
    }

    /// Process and forward a data message to the MCU
    pub async fn forward(&mut self, msg: DataMessage) -> Result<()> {
        match msg {
            DataMessage::VideoFrame { timestamp_ms, data, format } => {
                if !self.forward_video {
                    return Ok(());
                }

                // Downsample check
                self.frame_counter += 1;
                if self.frame_counter % self.video_downsample != 0 {
                    return Ok(());
                }

                self.forward_video_frame(timestamp_ms, &data, format).await
            }
            DataMessage::ImuReading { timestamp_ms, accelerometer, gyroscope, magnetometer } => {
                if !self.forward_imu {
                    return Ok(());
                }
                self.forward_imu_reading(timestamp_ms, accelerometer, gyroscope, magnetometer).await
            }
            DataMessage::GpsLocation { timestamp_ms, latitude, longitude, altitude, accuracy } => {
                self.forward_gps_location(timestamp_ms, latitude, longitude, altitude, accuracy).await
            }
            DataMessage::SensorReading { sensor, timestamp_ms, value } => {
                self.forward_sensor_reading(&sensor.to_string(), timestamp_ms, value).await
            }
        }
    }

    /// Forward a video frame to the MCU
    async fn forward_video_frame(
        &self,
        timestamp_ms: u64,
        data: &[u8],
        format: VideoFormat,
    ) -> Result<()> {
        let format_str = match format {
            VideoFormat::Jpeg => "jpeg",
            VideoFormat::H264 => "h264",
            VideoFormat::Yuv420 => "yuv420",
        };

        // For video, we might want to send metadata only (size, format) since
        // the full frame data might be too large for the MCU
        // The MCU can request specific frames or we can send thumbnails
        let params = vec![
            Value::Integer(timestamp_ms.into()),
            Value::String(format_str.into()),
            Value::Integer((data.len() as u64).into()),
            // Only send first N bytes as preview/thumbnail indicator
            Value::Binary(data.iter().take(64).copied().collect()),
        ];

        self.rpc_client
            .call("phone.video_frame", params)
            .await
            .map_err(|e| crate::error::RemoteIotError::RpcBridge(e))?;

        Ok(())
    }

    /// Forward IMU readings to the MCU
    async fn forward_imu_reading(
        &self,
        timestamp_ms: u64,
        accelerometer: Option<[f32; 3]>,
        gyroscope: Option<[f32; 3]>,
        magnetometer: Option<[f32; 3]>,
    ) -> Result<()> {
        let params = vec![
            Value::Integer(timestamp_ms.into()),
            Self::array_to_value(accelerometer),
            Self::array_to_value(gyroscope),
            Self::array_to_value(magnetometer),
        ];

        self.rpc_client
            .call("phone.imu", params)
            .await
            .map_err(|e| crate::error::RemoteIotError::RpcBridge(e))?;

        Ok(())
    }

    /// Forward GPS location to the MCU
    async fn forward_gps_location(
        &self,
        timestamp_ms: u64,
        latitude: f64,
        longitude: f64,
        altitude: Option<f64>,
        accuracy: Option<f32>,
    ) -> Result<()> {
        let params = vec![
            Value::Integer(timestamp_ms.into()),
            Value::F64(latitude),
            Value::F64(longitude),
            altitude.map(Value::F64).unwrap_or(Value::Nil),
            accuracy.map(|a| Value::F32(a)).unwrap_or(Value::Nil),
        ];

        self.rpc_client
            .call("phone.gps", params)
            .await
            .map_err(|e| crate::error::RemoteIotError::RpcBridge(e))?;

        Ok(())
    }

    /// Forward generic sensor reading to the MCU
    async fn forward_sensor_reading(
        &self,
        sensor: &str,
        timestamp_ms: u64,
        value: f64,
    ) -> Result<()> {
        let params = vec![
            Value::String(sensor.into()),
            Value::Integer(timestamp_ms.into()),
            Value::F64(value),
        ];

        self.rpc_client
            .call("phone.sensor", params)
            .await
            .map_err(|e| crate::error::RemoteIotError::RpcBridge(e))?;

        Ok(())
    }

    /// Convert an optional f32 array to MessagePack Value
    fn array_to_value(arr: Option<[f32; 3]>) -> Value {
        match arr {
            Some([x, y, z]) => Value::Array(vec![
                Value::F32(x),
                Value::F32(y),
                Value::F32(z),
            ]),
            None => Value::Nil,
        }
    }
}

/// Task that consumes data messages and forwards them via RPC
pub async fn run_bridge_task(
    mut bridge: RpcBridge,
    mut data_rx: mpsc::Receiver<DataMessage>,
) {
    log::info!("RPC bridge task started");
    
    while let Some(msg) = data_rx.recv().await {
        if let Err(e) = bridge.forward(msg).await {
            log::error!("Failed to forward data to MCU: {}", e);
        }
    }
    
    log::info!("RPC bridge task stopped");
}
