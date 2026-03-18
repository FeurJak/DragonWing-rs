// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Main RemoteServer that orchestrates QR generation, WebSocket, and HTTP servers

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

use crate::error::{RemoteIotError, Result};
use crate::http::{HttpEvent, HttpServer};
use crate::otp::Otp;
use crate::protocol::ConnectionState;
use crate::qr::QrGenerator;
use crate::websocket::{WsEvent, WsServer};
use crate::DEFAULT_DATA_PORT;

/// Configuration for the RemoteServer
#[derive(Debug, Clone)]
pub struct RemoteServerConfig {
    /// Local IP address to bind to (auto-detected if None)
    pub local_ip: Option<IpAddr>,
    /// WebSocket port (0 = auto-assign)
    pub websocket_port: u16,
    /// HTTP data port (default: 4912)
    pub data_port: u16,
    /// OTP timeout in seconds
    pub otp_timeout_secs: u64,
    /// Whether to print QR code to terminal on start
    pub print_qr: bool,
}

impl Default for RemoteServerConfig {
    fn default() -> Self {
        Self {
            local_ip: None,
            websocket_port: 0, // Auto-assign
            data_port: DEFAULT_DATA_PORT,
            otp_timeout_secs: 30,
            print_qr: true,
        }
    }
}

/// Events from the RemoteServer
#[derive(Debug, Clone)]
pub enum RemoteEvent {
    /// Server started
    ServerStarted {
        local_ip: IpAddr,
        websocket_port: u16,
        data_port: u16,
    },
    /// OTP generated/regenerated
    OtpGenerated { otp: String },
    /// Phone connected
    PhoneConnected,
    /// Phone authenticated
    PhoneAuthenticated,
    /// Phone ready to stream
    PhoneReady { capabilities: Vec<String> },
    /// Phone disconnected
    PhoneDisconnected,
    /// Video frame received
    VideoFrameReceived { size: usize },
    /// IMU data received
    ImuDataReceived,
    /// Error occurred
    Error { message: String },
}

/// The main Remote IoT server.
///
/// Manages the complete lifecycle of connecting a phone via the Arduino IoT
/// Companion App and streaming data.
///
/// # Example
///
/// ```no_run
/// use dragonwing_remote_iot::{RemoteServer, RemoteServerConfig};
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let config = RemoteServerConfig::default();
///     let mut server = RemoteServer::new(config);
///     
///     // Subscribe to events
///     let mut events = server.subscribe();
///     tokio::spawn(async move {
///         while let Ok(event) = events.recv().await {
///             println!("Event: {:?}", event);
///         }
///     });
///
///     // Run the server (blocks)
///     server.run().await?;
///     Ok(())
/// }
/// ```
pub struct RemoteServer {
    config: RemoteServerConfig,
    otp: Arc<Mutex<Option<Otp>>>,
    ws_server: Option<Arc<WsServer>>,
    http_server: Option<Arc<HttpServer>>,
    event_tx: broadcast::Sender<RemoteEvent>,
    /// Actual ports after binding (may differ from config if 0 was specified)
    actual_ws_port: Arc<Mutex<u16>>,
    actual_local_ip: Arc<Mutex<Option<IpAddr>>>,
}

impl RemoteServer {
    /// Create a new RemoteServer with the given configuration
    pub fn new(config: RemoteServerConfig) -> Self {
        let (event_tx, _) = broadcast::channel(100);
        Self {
            config,
            otp: Arc::new(Mutex::new(None)),
            ws_server: None,
            http_server: None,
            event_tx,
            actual_ws_port: Arc::new(Mutex::new(0)),
            actual_local_ip: Arc::new(Mutex::new(None)),
        }
    }

    /// Subscribe to server events
    pub fn subscribe(&self) -> broadcast::Receiver<RemoteEvent> {
        self.event_tx.subscribe()
    }

    /// Get the current OTP (if any)
    pub async fn current_otp(&self) -> Option<String> {
        self.otp.lock().await.as_ref().map(|o| o.value().to_string())
    }

    /// Get the current connection state
    pub async fn connection_state(&self) -> ConnectionState {
        if let Some(ws) = &self.ws_server {
            ws.state().await
        } else {
            ConnectionState::WaitingForConnection
        }
    }

    /// Regenerate the OTP and optionally display new QR code
    pub async fn regenerate_otp(&self) -> Result<String> {
        let otp = Otp::generate_with_timeout(
            std::time::Duration::from_secs(self.config.otp_timeout_secs)
        );
        let otp_value = otp.value().to_string();
        
        // Update stored OTP
        *self.otp.lock().await = Some(otp.clone());
        
        // Update WebSocket server if running
        if let Some(ws) = &self.ws_server {
            ws.update_otp(otp.clone()).await;
        }

        // Emit event
        let _ = self.event_tx.send(RemoteEvent::OtpGenerated { otp: otp_value.clone() });

        // Print QR if configured
        if self.config.print_qr {
            let local_ip = self.actual_local_ip.lock().await;
            let ws_port = *self.actual_ws_port.lock().await;
            if let Some(ip) = *local_ip {
                let display = QrGenerator::generate_pairing_display(
                    &otp,
                    &ip.to_string(),
                    ws_port,
                    self.config.data_port,
                );
                println!("{}", display);
            }
        }

        Ok(otp_value)
    }

    /// Detect the local IP address
    fn detect_local_ip() -> Result<IpAddr> {
        local_ip_address::local_ip().map_err(|_| RemoteIotError::NoLocalIp)
    }

    /// Run the server (blocks until shutdown)
    pub async fn run(&mut self) -> Result<()> {
        // Determine local IP
        let local_ip = match self.config.local_ip {
            Some(ip) => ip,
            None => Self::detect_local_ip()?,
        };
        *self.actual_local_ip.lock().await = Some(local_ip);

        // Generate initial OTP
        let otp = Otp::generate_with_timeout(
            std::time::Duration::from_secs(self.config.otp_timeout_secs)
        );
        *self.otp.lock().await = Some(otp.clone());
        let _ = self.event_tx.send(RemoteEvent::OtpGenerated { 
            otp: otp.value().to_string() 
        });

        // Bind WebSocket server to get actual port
        let ws_bind_addr: SocketAddr = format!("{}:{}", local_ip, self.config.websocket_port)
            .parse()
            .unwrap();
        
        let ws_listener = tokio::net::TcpListener::bind(ws_bind_addr)
            .await
            .map_err(|e| RemoteIotError::BindError {
                address: ws_bind_addr.to_string(),
                source: e,
            })?;
        
        let actual_ws_port = ws_listener.local_addr()?.port();
        *self.actual_ws_port.lock().await = actual_ws_port;

        log::info!(
            "RemoteServer starting: IP={}, WS port={}, Data port={}",
            local_ip, actual_ws_port, self.config.data_port
        );

        // Create servers
        let ws_server = Arc::new(WsServer::new(otp.clone(), self.config.data_port));
        let http_server = Arc::new(HttpServer::new());
        
        self.ws_server = Some(ws_server.clone());
        self.http_server = Some(http_server.clone());

        // Emit started event
        let _ = self.event_tx.send(RemoteEvent::ServerStarted {
            local_ip,
            websocket_port: actual_ws_port,
            data_port: self.config.data_port,
        });

        // Print QR code
        if self.config.print_qr {
            let display = QrGenerator::generate_pairing_display(
                &otp,
                &local_ip.to_string(),
                actual_ws_port,
                self.config.data_port,
            );
            println!("{}", display);
        }

        // Subscribe to WebSocket events and forward them
        let event_tx = self.event_tx.clone();
        let mut ws_events = ws_server.subscribe();
        tokio::spawn(async move {
            while let Ok(event) = ws_events.recv().await {
                let remote_event = match event {
                    WsEvent::ClientConnected { .. } => Some(RemoteEvent::PhoneConnected),
                    WsEvent::ClientAuthenticated { .. } => Some(RemoteEvent::PhoneAuthenticated),
                    WsEvent::ClientReady { capabilities, .. } => {
                        Some(RemoteEvent::PhoneReady { capabilities })
                    }
                    WsEvent::ClientDisconnected { .. } => Some(RemoteEvent::PhoneDisconnected),
                    WsEvent::ClientError { error, .. } => {
                        Some(RemoteEvent::Error { message: error })
                    }
                };
                if let Some(e) = remote_event {
                    let _ = event_tx.send(e);
                }
            }
        });

        // Subscribe to HTTP events and forward them
        let event_tx = self.event_tx.clone();
        let mut http_events = http_server.subscribe().await;
        tokio::spawn(async move {
            while let Ok(event) = http_events.recv().await {
                let remote_event = match event {
                    HttpEvent::VideoFrameReceived { size, .. } => {
                        Some(RemoteEvent::VideoFrameReceived { size })
                    }
                    HttpEvent::ImuDataReceived => Some(RemoteEvent::ImuDataReceived),
                    _ => None,
                };
                if let Some(e) = remote_event {
                    let _ = event_tx.send(e);
                }
            }
        });

        // HTTP server address
        let http_addr: SocketAddr = format!("{}:{}", local_ip, self.config.data_port)
            .parse()
            .unwrap();

        // Run both servers concurrently
        // Note: We need to use the listener we already created for WS
        let ws_addr = ws_listener.local_addr()?;
        drop(ws_listener); // Drop it so the WsServer can bind again
        
        tokio::select! {
            result = ws_server.run(ws_addr) => {
                log::error!("WebSocket server stopped: {:?}", result);
                result
            }
            result = http_server.run(http_addr) => {
                log::error!("HTTP server stopped: {:?}", result);
                result
            }
        }
    }
}

/// Builder for RemoteServer
pub struct RemoteServerBuilder {
    config: RemoteServerConfig,
}

impl Default for RemoteServerBuilder {
    fn default() -> Self {
        Self {
            config: RemoteServerConfig::default(),
        }
    }
}

impl RemoteServerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the local IP address (auto-detect if not set)
    pub fn local_ip(mut self, ip: IpAddr) -> Self {
        self.config.local_ip = Some(ip);
        self
    }

    /// Set the WebSocket port (0 = auto-assign)
    pub fn websocket_port(mut self, port: u16) -> Self {
        self.config.websocket_port = port;
        self
    }

    /// Set the HTTP data port
    pub fn data_port(mut self, port: u16) -> Self {
        self.config.data_port = port;
        self
    }

    /// Set OTP timeout in seconds
    pub fn otp_timeout(mut self, secs: u64) -> Self {
        self.config.otp_timeout_secs = secs;
        self
    }

    /// Enable/disable QR code printing
    pub fn print_qr(mut self, enabled: bool) -> Self {
        self.config.print_qr = enabled;
        self
    }

    /// Build the RemoteServer
    pub fn build(self) -> RemoteServer {
        RemoteServer::new(self.config)
    }
}
