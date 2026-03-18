// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// MPU Client - Async RPC client for QRB2210 Linux (std)
//
// This module provides the MPU-side RPC client for communicating
// with the MCU via Unix socket connection to the SPI router.

#![cfg(feature = "mpu")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::UnixStream;
use tokio::sync::{oneshot, Mutex};

use thiserror::Error;

/// RPC client errors
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Connection error: {0}")]
    Connection(#[from] std::io::Error),

    #[error("Encoding error: {0}")]
    Encode(String),

    #[error("Decoding error: {0}")]
    Decode(String),

    #[error("RPC error ({code}): {message}")]
    Rpc { code: i32, message: String },

    #[error("Timeout")]
    Timeout,

    #[error("Channel closed")]
    ChannelClosed,
}

/// RPC response
pub type RpcResult<T> = Result<T, RpcError>;

/// Async RPC client for communicating with Arduino Uno Q MCU
///
/// Connects to the SPI router via Unix socket and provides
/// methods to call MCU functions.
pub struct RpcClient {
    writer: Arc<Mutex<WriteHalf<UnixStream>>>,
    next_id: AtomicU32,
    pending: Arc<Mutex<HashMap<u32, oneshot::Sender<RpcResult<rmpv::Value>>>>>,
    _reader_handle: tokio::task::JoinHandle<()>,
}

impl RpcClient {
    /// Connect to the SPI router
    pub async fn connect(socket_path: &str) -> RpcResult<Self> {
        let stream = UnixStream::connect(socket_path).await?;

        // Split the stream into read and write halves to avoid deadlock
        let (reader, writer) = tokio::io::split(stream);
        let writer = Arc::new(Mutex::new(writer));

        let pending: Arc<Mutex<HashMap<u32, oneshot::Sender<RpcResult<rmpv::Value>>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Clone for reader task
        let pending_clone = Arc::clone(&pending);

        // Spawn reader task with its own read half
        let reader_handle = tokio::spawn(async move {
            let mut reader = reader;
            let mut buffer = vec![0u8; 4096];
            loop {
                let n = match reader.read(&mut buffer).await {
                    Ok(0) => break, // Connection closed
                    Ok(n) => n,
                    Err(_) => break,
                };

                // Try to decode response
                if let Ok(response) = Self::decode_response(&buffer[..n]) {
                    let mut pending = pending_clone.lock().await;
                    if let Some(sender) = pending.remove(&response.0) {
                        let _ = sender.send(response.1);
                    }
                }
            }
        });

        Ok(Self {
            writer,
            next_id: AtomicU32::new(1),
            pending,
            _reader_handle: reader_handle,
        })
    }

    /// Call an RPC method on the MCU
    pub async fn call(&self, method: &str, params: Vec<rmpv::Value>) -> RpcResult<rmpv::Value> {
        self.call_timeout(method, params, Duration::from_secs(5))
            .await
    }

    /// Call an RPC method with custom timeout
    pub async fn call_timeout(
        &self,
        method: &str,
        params: Vec<rmpv::Value>,
        timeout: Duration,
    ) -> RpcResult<rmpv::Value> {
        let msg_id = self.next_id.fetch_add(1, Ordering::SeqCst);

        // Encode request
        let request = Self::encode_request(msg_id, method, params)?;

        // Create response channel
        let (tx, rx) = oneshot::channel();

        // Register pending request
        {
            let mut pending = self.pending.lock().await;
            pending.insert(msg_id, tx);
        }

        // Send request
        {
            let mut writer = self.writer.lock().await;
            writer.write_all(&request).await?;
        }

        // Wait for response with timeout
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(RpcError::ChannelClosed),
            Err(_) => {
                // Remove pending request on timeout
                let mut pending = self.pending.lock().await;
                pending.remove(&msg_id);
                Err(RpcError::Timeout)
            }
        }
    }

    /// Send a notification (fire-and-forget)
    pub async fn notify(&self, method: &str, params: Vec<rmpv::Value>) -> RpcResult<()> {
        let notification = Self::encode_notification(method, params)?;

        let mut writer = self.writer.lock().await;
        writer.write_all(&notification).await?;

        Ok(())
    }

    /// Encode an RPC request
    fn encode_request(msg_id: u32, method: &str, params: Vec<rmpv::Value>) -> RpcResult<Vec<u8>> {
        // [0, msgid, method, params]
        let request = (0u8, msg_id, method, params);
        rmp_serde::to_vec(&request).map_err(|e| RpcError::Encode(e.to_string()))
    }

    /// Encode an RPC notification
    fn encode_notification(method: &str, params: Vec<rmpv::Value>) -> RpcResult<Vec<u8>> {
        // [2, method, params]
        let notification = (2u8, method, params);
        rmp_serde::to_vec(&notification).map_err(|e| RpcError::Encode(e.to_string()))
    }

    /// Decode an RPC response
    fn decode_response(data: &[u8]) -> Result<(u32, RpcResult<rmpv::Value>), ()> {
        let value: rmpv::Value = rmp_serde::from_slice(data).map_err(|_| ())?;
        let arr = value.as_array().ok_or(())?;

        if arr.len() < 4 {
            return Err(());
        }

        let msg_type = arr[0].as_u64().ok_or(())? as u8;
        if msg_type != 1 {
            return Err(()); // Not a response
        }

        let msg_id = arr[1].as_u64().ok_or(())? as u32;

        // Check for error
        if !arr[2].is_nil() {
            if let Some(err) = arr[2].as_map() {
                let code = err
                    .iter()
                    .find(|(k, _)| k.as_str() == Some("code"))
                    .and_then(|(_, v)| v.as_i64())
                    .unwrap_or(-1) as i32;
                let message = err
                    .iter()
                    .find(|(k, _)| k.as_str() == Some("message"))
                    .and_then(|(_, v)| v.as_str())
                    .unwrap_or("Unknown error")
                    .to_string();
                return Ok((msg_id, Err(RpcError::Rpc { code, message })));
            }
        }

        Ok((msg_id, Ok(arr[3].clone())))
    }
}

/// Synchronous RPC client wrapper
pub struct RpcClientSync {
    runtime: tokio::runtime::Runtime,
    client: RpcClient,
}

impl RpcClientSync {
    /// Connect to the SPI router (blocking)
    pub fn connect(socket_path: &str) -> RpcResult<Self> {
        // Use multi-threaded runtime to ensure reader task can run
        // while main thread is blocked waiting for response
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| RpcError::Connection(e.into()))?;

        let client = runtime.block_on(RpcClient::connect(socket_path))?;

        Ok(Self { runtime, client })
    }

    /// Call an RPC method (blocking)
    pub fn call(&self, method: &str, params: Vec<rmpv::Value>) -> RpcResult<rmpv::Value> {
        self.runtime.block_on(self.client.call(method, params))
    }

    /// Call an RPC method with custom timeout (blocking)
    pub fn call_timeout(
        &self,
        method: &str,
        params: Vec<rmpv::Value>,
        timeout: Duration,
    ) -> RpcResult<rmpv::Value> {
        self.runtime
            .block_on(self.client.call_timeout(method, params, timeout))
    }

    /// Send a notification (blocking)
    pub fn notify(&self, method: &str, params: Vec<rmpv::Value>) -> RpcResult<()> {
        self.runtime.block_on(self.client.notify(method, params))
    }
}

/// Convenience trait for LED matrix control
pub trait LedMatrixClient {
    /// Initialize the LED matrix
    fn led_matrix_begin(&self) -> RpcResult<()>;

    /// Clear the LED matrix
    fn led_matrix_clear(&self) -> RpcResult<()>;

    /// Set a single pixel
    fn led_matrix_set_pixel(&self, row: u8, col: u8, on: bool) -> RpcResult<()>;

    /// Load a 104-bit frame
    fn led_matrix_load_frame(&self, data: &[u32; 4]) -> RpcResult<()>;

    /// Set grayscale brightness
    fn led_matrix_set_brightness(&self, level: u8) -> RpcResult<()>;
}

impl LedMatrixClient for RpcClientSync {
    fn led_matrix_begin(&self) -> RpcResult<()> {
        self.call("led_matrix.begin", vec![])?;
        Ok(())
    }

    fn led_matrix_clear(&self) -> RpcResult<()> {
        self.call("led_matrix.clear", vec![])?;
        Ok(())
    }

    fn led_matrix_set_pixel(&self, row: u8, col: u8, on: bool) -> RpcResult<()> {
        self.call(
            "led_matrix.set_pixel",
            vec![
                rmpv::Value::Integer(row.into()),
                rmpv::Value::Integer(col.into()),
                rmpv::Value::Boolean(on),
            ],
        )?;
        Ok(())
    }

    fn led_matrix_load_frame(&self, data: &[u32; 4]) -> RpcResult<()> {
        let arr: Vec<rmpv::Value> = data
            .iter()
            .map(|&v| rmpv::Value::Integer(v.into()))
            .collect();
        self.call("led_matrix.load_frame", vec![rmpv::Value::Array(arr)])?;
        Ok(())
    }

    fn led_matrix_set_brightness(&self, level: u8) -> RpcResult<()> {
        self.call(
            "led_matrix.set_brightness",
            vec![rmpv::Value::Integer(level.into())],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_request() {
        let encoded =
            RpcClient::encode_request(1, "ping", vec![rmpv::Value::Integer(42.into())]).unwrap();
        assert!(!encoded.is_empty());
    }
}
