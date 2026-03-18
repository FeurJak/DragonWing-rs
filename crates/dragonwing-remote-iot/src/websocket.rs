// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// WebSocket server for Arduino IoT Companion App control channel

use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_tungstenite::{accept_async, tungstenite::Message};

use crate::error::{RemoteIotError, Result};
use crate::otp::Otp;
use crate::protocol::{ConnectionState, ControlMessage};
use crate::DEFAULT_DATA_PORT;

/// Events emitted by the WebSocket server
#[derive(Debug, Clone)]
pub enum WsEvent {
    /// A client connected
    ClientConnected { addr: SocketAddr },
    /// A client authenticated successfully
    ClientAuthenticated { addr: SocketAddr },
    /// A client is ready to stream
    ClientReady { addr: SocketAddr, capabilities: Vec<String> },
    /// A client disconnected
    ClientDisconnected { addr: SocketAddr },
    /// An error occurred with a client
    ClientError { addr: SocketAddr, error: String },
}

/// WebSocket server for handling control connections from the IoT app
pub struct WsServer {
    /// The OTP for authenticating connections
    otp: Arc<Mutex<Otp>>,
    /// Current connection state
    state: Arc<Mutex<ConnectionState>>,
    /// Data port to tell clients
    data_port: u16,
    /// Event sender for notifying about connection events
    event_tx: broadcast::Sender<WsEvent>,
    /// Sender to connected client (if any)
    client_tx: Arc<Mutex<Option<mpsc::Sender<ControlMessage>>>>,
}

impl WsServer {
    /// Create a new WebSocket server
    pub fn new(otp: Otp, data_port: u16) -> Self {
        let (event_tx, _) = broadcast::channel(100);
        Self {
            otp: Arc::new(Mutex::new(otp)),
            state: Arc::new(Mutex::new(ConnectionState::WaitingForConnection)),
            data_port,
            event_tx,
            client_tx: Arc::new(Mutex::new(None)),
        }
    }

    /// Subscribe to server events
    pub fn subscribe(&self) -> broadcast::Receiver<WsEvent> {
        self.event_tx.subscribe()
    }

    /// Get current connection state
    pub async fn state(&self) -> ConnectionState {
        *self.state.lock().await
    }

    /// Update the OTP (e.g., to regenerate after expiration)
    pub async fn update_otp(&self, otp: Otp) {
        *self.otp.lock().await = otp;
    }

    /// Send a control message to the connected client
    pub async fn send_to_client(&self, msg: ControlMessage) -> Result<()> {
        let tx = self.client_tx.lock().await;
        if let Some(tx) = tx.as_ref() {
            tx.send(msg).await.map_err(|_| RemoteIotError::ClientDisconnected)?;
            Ok(())
        } else {
            Err(RemoteIotError::InvalidState("No client connected".to_string()))
        }
    }

    /// Run the WebSocket server on the given address
    pub async fn run(&self, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await.map_err(|e| RemoteIotError::BindError {
            address: addr.to_string(),
            source: e,
        })?;

        log::info!("WebSocket server listening on ws://{}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    log::info!("New WebSocket connection from {}", peer_addr);
                    
                    // Only allow one client at a time
                    {
                        let state = self.state.lock().await;
                        if *state != ConnectionState::WaitingForConnection 
                            && *state != ConnectionState::Disconnected 
                        {
                            log::warn!("Rejecting connection from {} - already have a client", peer_addr);
                            continue;
                        }
                    }

                    let otp = self.otp.clone();
                    let state = self.state.clone();
                    let event_tx = self.event_tx.clone();
                    let client_tx = self.client_tx.clone();
                    let data_port = self.data_port;

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(
                            stream, 
                            peer_addr, 
                            otp, 
                            state, 
                            event_tx.clone(),
                            client_tx,
                            data_port,
                        ).await {
                            log::error!("Connection error from {}: {}", peer_addr, e);
                            let _ = event_tx.send(WsEvent::ClientError {
                                addr: peer_addr,
                                error: e.to_string(),
                            });
                        }
                    });
                }
                Err(e) => {
                    log::error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_connection(
        stream: TcpStream,
        addr: SocketAddr,
        otp: Arc<Mutex<Otp>>,
        state: Arc<Mutex<ConnectionState>>,
        event_tx: broadcast::Sender<WsEvent>,
        client_tx: Arc<Mutex<Option<mpsc::Sender<ControlMessage>>>>,
        data_port: u16,
    ) -> Result<()> {
        let ws_stream = accept_async(stream).await?;
        let (mut write, mut read) = ws_stream.split();

        // Update state
        {
            *state.lock().await = ConnectionState::WaitingForAuth;
        }
        let _ = event_tx.send(WsEvent::ClientConnected { addr });

        // Create channel for sending messages to client
        let (tx, mut rx) = mpsc::channel::<ControlMessage>(32);
        {
            *client_tx.lock().await = Some(tx);
        }

        // Spawn task to forward messages from channel to WebSocket
        let write_handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let json = serde_json::to_string(&msg).unwrap();
                if write.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
        });

        // Process incoming messages
        let result = Self::process_messages(
            &mut read,
            addr,
            otp,
            state.clone(),
            event_tx.clone(),
            client_tx.clone(),
            data_port,
        ).await;

        // Cleanup
        write_handle.abort();
        {
            *client_tx.lock().await = None;
            *state.lock().await = ConnectionState::Disconnected;
        }
        let _ = event_tx.send(WsEvent::ClientDisconnected { addr });

        result
    }

    async fn process_messages(
        read: &mut futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<TcpStream>
        >,
        addr: SocketAddr,
        otp: Arc<Mutex<Otp>>,
        state: Arc<Mutex<ConnectionState>>,
        event_tx: broadcast::Sender<WsEvent>,
        client_tx: Arc<Mutex<Option<mpsc::Sender<ControlMessage>>>>,
        data_port: u16,
    ) -> Result<()> {
        while let Some(msg) = read.next().await {
            let msg = msg?;

            match msg {
                Message::Text(text) => {
                    let control_msg: ControlMessage = serde_json::from_str(&text)?;
                    
                    Self::handle_control_message(
                        control_msg,
                        addr,
                        &otp,
                        &state,
                        &event_tx,
                        &client_tx,
                        data_port,
                    ).await?;
                }
                Message::Binary(_) => {
                    log::warn!("Received unexpected binary message from {}", addr);
                }
                Message::Ping(data) => {
                    // Pong is handled automatically by tungstenite
                    log::debug!("Received ping from {}", addr);
                    let _ = data; // Suppress unused warning
                }
                Message::Pong(_) => {
                    log::debug!("Received pong from {}", addr);
                }
                Message::Close(_) => {
                    log::info!("Client {} requested close", addr);
                    break;
                }
                Message::Frame(_) => {}
            }
        }

        Ok(())
    }

    async fn handle_control_message(
        msg: ControlMessage,
        addr: SocketAddr,
        otp: &Arc<Mutex<Otp>>,
        state: &Arc<Mutex<ConnectionState>>,
        event_tx: &broadcast::Sender<WsEvent>,
        client_tx: &Arc<Mutex<Option<mpsc::Sender<ControlMessage>>>>,
        data_port: u16,
    ) -> Result<()> {
        match msg {
            ControlMessage::Auth { otp: provided_otp } => {
                let current_state = *state.lock().await;
                if current_state != ConnectionState::WaitingForAuth {
                    log::warn!("Received auth in wrong state: {:?}", current_state);
                    return Self::send_error(client_tx, 1, "Already authenticated").await;
                }

                let stored_otp = otp.lock().await;
                let response = match stored_otp.validate(&provided_otp) {
                    Ok(()) => {
                        *state.lock().await = ConnectionState::Authenticated;
                        let _ = event_tx.send(WsEvent::ClientAuthenticated { addr });
                        log::info!("Client {} authenticated successfully", addr);
                        ControlMessage::AuthResponse {
                            success: true,
                            message: "Authentication successful".to_string(),
                        }
                    }
                    Err(e) => {
                        log::warn!("Authentication failed for {}: {}", addr, e);
                        ControlMessage::AuthResponse {
                            success: false,
                            message: e.to_string(),
                        }
                    }
                };

                Self::send_message(client_tx, response).await?;
            }

            ControlMessage::Ready { capabilities } => {
                let current_state = *state.lock().await;
                if current_state != ConnectionState::Authenticated {
                    log::warn!("Received ready in wrong state: {:?}", current_state);
                    return Self::send_error(client_tx, 2, "Not authenticated").await;
                }

                *state.lock().await = ConnectionState::Ready;
                let _ = event_tx.send(WsEvent::ClientReady { 
                    addr, 
                    capabilities: capabilities.clone(),
                });
                log::info!("Client {} ready with capabilities: {:?}", addr, capabilities);

                Self::send_message(client_tx, ControlMessage::ReadyAck { data_port }).await?;
            }

            ControlMessage::Ping => {
                Self::send_message(client_tx, ControlMessage::Pong).await?;
            }

            ControlMessage::Disconnect => {
                log::info!("Client {} disconnecting gracefully", addr);
                return Err(RemoteIotError::ClientDisconnected);
            }

            _ => {
                log::debug!("Received message: {:?}", msg);
            }
        }

        Ok(())
    }

    async fn send_message(
        client_tx: &Arc<Mutex<Option<mpsc::Sender<ControlMessage>>>>,
        msg: ControlMessage,
    ) -> Result<()> {
        let tx = client_tx.lock().await;
        if let Some(tx) = tx.as_ref() {
            tx.send(msg).await.map_err(|_| RemoteIotError::ClientDisconnected)?;
        }
        Ok(())
    }

    async fn send_error(
        client_tx: &Arc<Mutex<Option<mpsc::Sender<ControlMessage>>>>,
        code: u32,
        message: &str,
    ) -> Result<()> {
        Self::send_message(client_tx, ControlMessage::Error {
            code,
            message: message.to_string(),
        }).await
    }
}

/// Builder for creating WebSocket servers
pub struct WsServerBuilder {
    data_port: u16,
}

impl Default for WsServerBuilder {
    fn default() -> Self {
        Self {
            data_port: DEFAULT_DATA_PORT,
        }
    }
}

impl WsServerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn data_port(mut self, port: u16) -> Self {
        self.data_port = port;
        self
    }

    pub fn build(self, otp: Otp) -> WsServer {
        WsServer::new(otp, self.data_port)
    }
}
