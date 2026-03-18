// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// HTTP server for Arduino IoT Companion App data channel (video streaming)

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex};
use tower_http::cors::{Any, CorsLayer};

use crate::error::{RemoteIotError, Result};
use crate::protocol::{DataMessage, VideoFormat};

/// Events emitted by the HTTP data server
#[derive(Debug, Clone)]
pub enum HttpEvent {
    /// Video frame received
    VideoFrameReceived { size: usize, format: VideoFormat },
    /// IMU data received
    ImuDataReceived,
    /// Client connected to data stream
    StreamClientConnected { addr: SocketAddr },
    /// Client disconnected from data stream
    StreamClientDisconnected { addr: SocketAddr },
}

/// HTTP server state
struct HttpState {
    /// Channel for forwarding received data
    data_tx: mpsc::Sender<DataMessage>,
    /// Event broadcast channel
    event_tx: broadcast::Sender<HttpEvent>,
    /// Flag indicating if streaming is active
    streaming: bool,
}

/// HTTP server for receiving data streams from the IoT app
pub struct HttpServer {
    state: Arc<Mutex<HttpState>>,
    /// Receiver for data messages (for consumers of this server)
    data_rx: Arc<Mutex<mpsc::Receiver<DataMessage>>>,
}

impl HttpServer {
    /// Create a new HTTP data server
    pub fn new() -> Self {
        let (data_tx, data_rx) = mpsc::channel(100);
        let (event_tx, _) = broadcast::channel(100);

        Self {
            state: Arc::new(Mutex::new(HttpState {
                data_tx,
                event_tx,
                streaming: false,
            })),
            data_rx: Arc::new(Mutex::new(data_rx)),
        }
    }

    /// Subscribe to server events
    pub async fn subscribe(&self) -> broadcast::Receiver<HttpEvent> {
        self.state.lock().await.event_tx.subscribe()
    }

    /// Take the data receiver (can only be called once)
    /// 
    /// Returns the receiver for consuming data messages from the phone.
    /// This can only be called once - subsequent calls will return None.
    pub fn take_data_receiver(&self) -> Option<mpsc::Receiver<DataMessage>> {
        // Try to get exclusive access to swap out the receiver
        let mut guard = self.data_rx.try_lock().ok()?;
        let (_, new_rx) = mpsc::channel(1);
        Some(std::mem::replace(&mut *guard, new_rx))
    }

    /// Run the HTTP server on the given address
    pub async fn run(&self, addr: SocketAddr) -> Result<()> {
        let state = self.state.clone();
        
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        let app = Router::new()
            // Video stream endpoint - receives MJPEG or H.264 frames
            .route("/video", post(Self::handle_video_frame))
            // IMU data endpoint
            .route("/imu", post(Self::handle_imu_data))
            // Health check
            .route("/health", get(Self::handle_health))
            // Status endpoint
            .route("/status", get(Self::handle_status))
            .layer(cors)
            .with_state(state);

        log::info!("HTTP data server listening on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| RemoteIotError::BindError {
                address: addr.to_string(),
                source: e,
            })?;

        axum::serve(listener, app)
            .await
            .map_err(|e| RemoteIotError::Http(e.to_string()))?;

        Ok(())
    }

    /// Handle incoming video frame
    async fn handle_video_frame(
        State(state): State<Arc<Mutex<HttpState>>>,
        headers: HeaderMap,
        body: Body,
    ) -> impl IntoResponse {
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream");

        let format = match content_type {
            "image/jpeg" => VideoFormat::Jpeg,
            "video/h264" => VideoFormat::H264,
            _ => VideoFormat::Jpeg, // Default to JPEG
        };

        // Get timestamp from header or use current time
        let timestamp_ms = headers
            .get("X-Timestamp")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0)
            });

        // Read body
        let data = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                log::error!("Failed to read video frame body: {}", e);
                return StatusCode::BAD_REQUEST;
            }
        };

        let size = data.len();
        log::debug!("Received video frame: {} bytes, format: {:?}", size, format);

        let state = state.lock().await;
        
        // Send event
        let _ = state.event_tx.send(HttpEvent::VideoFrameReceived { size, format });

        // Forward data
        let msg = DataMessage::VideoFrame {
            timestamp_ms,
            data,
            format,
        };
        
        if state.data_tx.send(msg).await.is_err() {
            log::warn!("No data receiver for video frame");
        }

        StatusCode::OK
    }

    /// Handle incoming IMU data
    async fn handle_imu_data(
        State(state): State<Arc<Mutex<HttpState>>>,
        headers: HeaderMap,
        body: Body,
    ) -> impl IntoResponse {
        let timestamp_ms = headers
            .get("X-Timestamp")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0)
            });

        // Read body as JSON
        let bytes = match axum::body::to_bytes(body, 4096).await {
            Ok(b) => b,
            Err(e) => {
                log::error!("Failed to read IMU data body: {}", e);
                return StatusCode::BAD_REQUEST;
            }
        };

        // Parse IMU data (expecting JSON with accel, gyro, mag arrays)
        #[derive(serde::Deserialize)]
        struct ImuPayload {
            #[serde(default)]
            accelerometer: Option<[f32; 3]>,
            #[serde(default)]
            gyroscope: Option<[f32; 3]>,
            #[serde(default)]
            magnetometer: Option<[f32; 3]>,
        }

        let payload: ImuPayload = match serde_json::from_slice(&bytes) {
            Ok(p) => p,
            Err(e) => {
                log::error!("Failed to parse IMU data: {}", e);
                return StatusCode::BAD_REQUEST;
            }
        };

        log::debug!(
            "Received IMU data: accel={:?}, gyro={:?}, mag={:?}",
            payload.accelerometer,
            payload.gyroscope,
            payload.magnetometer
        );

        let state = state.lock().await;

        // Send event
        let _ = state.event_tx.send(HttpEvent::ImuDataReceived);

        // Forward data
        let msg = DataMessage::ImuReading {
            timestamp_ms,
            accelerometer: payload.accelerometer,
            gyroscope: payload.gyroscope,
            magnetometer: payload.magnetometer,
        };

        if state.data_tx.send(msg).await.is_err() {
            log::warn!("No data receiver for IMU data");
        }

        StatusCode::OK
    }

    /// Health check endpoint
    async fn handle_health() -> impl IntoResponse {
        (StatusCode::OK, "OK")
    }

    /// Status endpoint
    async fn handle_status(
        State(state): State<Arc<Mutex<HttpState>>>,
    ) -> impl IntoResponse {
        let state = state.lock().await;
        let status = serde_json::json!({
            "streaming": state.streaming,
            "status": "ready"
        });
        (StatusCode::OK, axum::Json(status))
    }
}

impl Default for HttpServer {
    fn default() -> Self {
        Self::new()
    }
}
