// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// WebSocket Camera Server for Arduino IoT Companion App
//
// This module implements a WebSocket server that receives video frames from
// the Arduino IoT Remote app using the BPP (Binary Peripheral Protocol).
//
// The server:
// - Accepts one client at a time
// - Uses BPP for secure communication (encryption or signing)
// - Receives JPEG video frames from the phone
// - Emits events for connection state changes and received frames

use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio_tungstenite::{accept_async, tungstenite::Message};

use crate::bpp::{BppCodec, SecurityMode};
use crate::error::{RemoteIotError, Result};

/// Default WebSocket camera port
pub const DEFAULT_CAMERA_PORT: u16 = 8080;

/// Camera connection status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CameraStatus {
    /// Waiting for a client to connect
    #[default]
    Disconnected,
    /// Client connected, waiting for frames
    Connected,
    /// Client is actively streaming frames
    Streaming,
}

impl std::fmt::Display for CameraStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CameraStatus::Disconnected => write!(f, "disconnected"),
            CameraStatus::Connected => write!(f, "connected"),
            CameraStatus::Streaming => write!(f, "streaming"),
        }
    }
}

/// Events emitted by the camera server
#[derive(Debug, Clone)]
pub enum CameraEvent {
    /// Client connected
    Connected {
        client_address: String,
        client_name: String,
    },
    /// Client disconnected
    Disconnected {
        client_address: String,
        client_name: String,
    },
    /// Streaming started (first frame received)
    Streaming,
    /// Streaming paused (no frames for a while)
    Paused,
    /// Video frame received
    FrameReceived {
        size: usize,
        timestamp_ms: u64,
    },
    /// Error occurred
    Error {
        message: String,
    },
}

/// A received video frame
#[derive(Debug, Clone)]
pub struct VideoFrame {
    /// Raw JPEG data
    pub data: Vec<u8>,
    /// Timestamp when frame was received (Unix millis)
    pub timestamp_ms: u64,
}

/// WebSocket Camera Server compatible with Arduino IoT Companion App
pub struct CameraServer {
    /// Secret for BPP authentication/encryption
    secret: String,
    /// Whether to use encryption (true) or just signing (false)
    use_encryption: bool,
    /// Server port
    port: u16,
    /// Current status
    status: Arc<RwLock<CameraStatus>>,
    /// Connected client name
    client_name: Arc<RwLock<String>>,
    /// Event broadcaster
    event_tx: broadcast::Sender<CameraEvent>,
    /// Frame channel sender (for consumers)
    frame_tx: mpsc::Sender<VideoFrame>,
    /// Frame channel receiver
    frame_rx: Arc<Mutex<mpsc::Receiver<VideoFrame>>>,
    /// Local IP address
    local_ip: Option<String>,
}

impl CameraServer {
    /// Create a new camera server with the given secret
    ///
    /// # Arguments
    /// * `secret` - 6-digit numeric secret for BPP authentication
    /// * `use_encryption` - Use ChaCha20-Poly1305 encryption (true) or HMAC-SHA256 signing (false)
    pub fn new(secret: &str, use_encryption: bool) -> Self {
        let (event_tx, _) = broadcast::channel(100);
        let (frame_tx, frame_rx) = mpsc::channel(10);

        Self {
            secret: secret.to_string(),
            use_encryption,
            port: DEFAULT_CAMERA_PORT,
            status: Arc::new(RwLock::new(CameraStatus::Disconnected)),
            client_name: Arc::new(RwLock::new(String::new())),
            event_tx,
            frame_tx,
            frame_rx: Arc::new(Mutex::new(frame_rx)),
            local_ip: None,
        }
    }

    /// Set the server port (default: 8080)
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the local IP address for QR code generation
    pub fn with_local_ip(mut self, ip: &str) -> Self {
        self.local_ip = Some(ip.to_string());
        self
    }

    /// Get the server port
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the secret
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Get the protocol string for QR code ("ws" or "wss")
    pub fn protocol(&self) -> &str {
        "ws" // TLS would be "wss"
    }

    /// Get the local IP address
    pub fn ip(&self) -> String {
        self.local_ip
            .clone()
            .or_else(|| local_ip_address::local_ip().ok().map(|ip| ip.to_string()))
            .unwrap_or_else(|| "0.0.0.0".to_string())
    }

    /// Get the current connection status
    pub async fn status(&self) -> CameraStatus {
        *self.status.read().await
    }

    /// Get the connected client name
    pub async fn client_name(&self) -> String {
        self.client_name.read().await.clone()
    }

    /// Get the security mode description
    pub fn security_mode(&self) -> SecurityMode {
        if self.use_encryption {
            SecurityMode::Encrypt
        } else {
            SecurityMode::Sign
        }
    }

    /// Subscribe to camera events
    pub fn subscribe(&self) -> broadcast::Receiver<CameraEvent> {
        self.event_tx.subscribe()
    }

    /// Take the frame receiver (can only be called once effectively)
    pub async fn take_frame_receiver(&self) -> mpsc::Receiver<VideoFrame> {
        let mut guard = self.frame_rx.lock().await;
        let (_, new_rx) = mpsc::channel(1);
        std::mem::replace(&mut *guard, new_rx)
    }

    /// Generate a welcome message to send to connected clients
    fn welcome_message(&self) -> serde_json::Value {
        serde_json::json!({
            "status": "connected",
            "message": "Connected to camera server",
            "security_mode": self.security_mode().to_string(),
            "resolution": [640, 480],
            "fps": 10
        })
    }

    /// Run the camera server
    pub async fn run(&self, bind_addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| RemoteIotError::BindError {
                address: bind_addr.to_string(),
                source: e,
            })?;

        log::info!(
            "Camera server listening on ws://{}:{} (security: {})",
            bind_addr.ip(),
            bind_addr.port(),
            self.security_mode()
        );

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    // Check if we already have a client
                    let current_status = *self.status.read().await;
                    if current_status != CameraStatus::Disconnected {
                        log::warn!(
                            "Rejecting connection from {} - already have a client",
                            peer_addr
                        );
                        // Could send rejection message here
                        continue;
                    }

                    log::info!("New camera client from {}", peer_addr);

                    // Create BPP codec for this connection
                    let codec = if self.use_encryption {
                        BppCodec::new_encrypted(&self.secret)
                    } else {
                        BppCodec::new_signed(&self.secret)
                    };

                    let status = self.status.clone();
                    let client_name = self.client_name.clone();
                    let event_tx = self.event_tx.clone();
                    let frame_tx = self.frame_tx.clone();
                    let welcome = self.welcome_message();

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_client(
                            stream,
                            peer_addr,
                            codec,
                            status,
                            client_name,
                            event_tx,
                            frame_tx,
                            welcome,
                        )
                        .await
                        {
                            log::error!("Client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    log::error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_client(
        stream: TcpStream,
        peer_addr: SocketAddr,
        mut codec: BppCodec,
        status: Arc<RwLock<CameraStatus>>,
        client_name_store: Arc<RwLock<String>>,
        event_tx: broadcast::Sender<CameraEvent>,
        frame_tx: mpsc::Sender<VideoFrame>,
        welcome: serde_json::Value,
    ) -> Result<()> {
        let ws_stream = accept_async(stream).await?;
        let (mut write, mut read) = ws_stream.split();

        // Extract client name from URL query params if available
        let client_name = "Arduino IoT Remote".to_string(); // Default name
        let client_addr = peer_addr.to_string();

        // Update state
        {
            *status.write().await = CameraStatus::Connected;
            *client_name_store.write().await = client_name.clone();
        }

        let _ = event_tx.send(CameraEvent::Connected {
            client_address: client_addr.clone(),
            client_name: client_name.clone(),
        });

        // Send welcome message (encoded with BPP)
        let welcome_json = serde_json::to_vec(&welcome).unwrap_or_default();
        if let Ok(encoded) = codec.encode(&welcome_json) {
            let _ = write.send(Message::Binary(encoded.into())).await;
        }

        let mut frame_count = 0u64;
        let mut streaming_started = false;

        // Process incoming messages
        while let Some(msg_result) = read.next().await {
            let msg = match msg_result {
                Ok(m) => m,
                Err(e) => {
                    log::warn!("WebSocket error: {}", e);
                    break;
                }
            };

            match msg {
                Message::Binary(data) => {
                    // Log first few bytes for debugging
                    if data.len() >= 14 {
                        log::debug!(
                            "Received binary message: {} bytes, header: {:02X?}, mode byte: {}",
                            data.len(),
                            &data[..14],
                            data[1]
                        );
                    }

                    // Decode BPP message
                    match codec.decode(&data) {
                        Ok(payload) => {
                            // Check if it's a JPEG frame (starts with FFD8)
                            if payload.len() >= 2 && payload[0] == 0xFF && payload[1] == 0xD8 {
                                frame_count += 1;

                                if !streaming_started {
                                    streaming_started = true;
                                    *status.write().await = CameraStatus::Streaming;
                                    let _ = event_tx.send(CameraEvent::Streaming);
                                }

                                let timestamp_ms = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_millis() as u64)
                                    .unwrap_or(0);

                                let frame = VideoFrame {
                                    data: payload,
                                    timestamp_ms,
                                };

                                let size = frame.data.len();

                                // Try to send frame, drop if channel full
                                let _ = frame_tx.try_send(frame);

                                let _ = event_tx.send(CameraEvent::FrameReceived {
                                    size,
                                    timestamp_ms,
                                });

                                if frame_count % 30 == 0 {
                                    log::debug!(
                                        "Received {} frames (last: {} bytes)",
                                        frame_count,
                                        size
                                    );
                                }
                            } else {
                                // Might be a control message (JSON)
                                if let Ok(text) = std::str::from_utf8(&payload) {
                                    log::debug!("Received text message: {}", text);
                                }
                            }
                        }
                        Err(e) => {
                            log::warn!("BPP decode error: {}", e);
                            let _ = event_tx.send(CameraEvent::Error {
                                message: format!("BPP decode error: {}", e),
                            });
                        }
                    }
                }
                Message::Text(text) => {
                    // Text messages might be base64-encoded BPP or plain JSON
                    log::debug!("Received text: {}", text);
                    
                    // Try to decode as base64 BPP
                    if let Ok(payload) = codec.decode_text(&text) {
                        if let Ok(json_str) = std::str::from_utf8(&payload) {
                            log::debug!("Decoded BPP text message: {}", json_str);
                        }
                    }
                }
                Message::Ping(data) => {
                    let _ = write.send(Message::Pong(data)).await;
                }
                Message::Close(_) => {
                    log::info!("Client {} requested close", peer_addr);
                    break;
                }
                _ => {}
            }
        }

        // Cleanup
        {
            *status.write().await = CameraStatus::Disconnected;
            *client_name_store.write().await = String::new();
        }

        let _ = event_tx.send(CameraEvent::Disconnected {
            client_address: client_addr,
            client_name,
        });

        Ok(())
    }
}

/// Generate a random 6-digit numeric secret
pub fn generate_secret() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let num: u32 = rng.random_range(0..1_000_000);
    format!("{:06}", num)
}

/// Builder for CameraServer
pub struct CameraServerBuilder {
    secret: Option<String>,
    use_encryption: bool,
    port: u16,
    local_ip: Option<String>,
}

impl Default for CameraServerBuilder {
    fn default() -> Self {
        Self {
            secret: None,
            use_encryption: true, // Default to encrypted
            port: DEFAULT_CAMERA_PORT,
            local_ip: None,
        }
    }
}

impl CameraServerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the secret (generates random if not set)
    pub fn secret(mut self, secret: &str) -> Self {
        self.secret = Some(secret.to_string());
        self
    }

    /// Use encryption (ChaCha20-Poly1305) - default: true
    pub fn use_encryption(mut self, enable: bool) -> Self {
        self.use_encryption = enable;
        self
    }

    /// Set the server port (default: 8080)
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Set the local IP for QR code generation
    pub fn local_ip(mut self, ip: &str) -> Self {
        self.local_ip = Some(ip.to_string());
        self
    }

    /// Build the camera server
    pub fn build(self) -> CameraServer {
        let secret = self.secret.unwrap_or_else(generate_secret);
        let mut server = CameraServer::new(&secret, self.use_encryption).with_port(self.port);
        
        if let Some(ip) = self.local_ip {
            server = server.with_local_ip(&ip);
        }
        
        server
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secret() {
        let secret = generate_secret();
        assert_eq!(secret.len(), 6);
        assert!(secret.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_camera_server_builder() {
        let server = CameraServerBuilder::new()
            .secret("123456")
            .use_encryption(true)
            .port(9000)
            .build();

        assert_eq!(server.secret(), "123456");
        assert_eq!(server.port(), 9000);
        assert_eq!(server.security_mode(), SecurityMode::Encrypt);
    }
}
