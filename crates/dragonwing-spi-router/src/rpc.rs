// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// MessagePack-RPC protocol implementation
//
// This module implements the MessagePack-RPC protocol for communication
// between the SPI router and the MCU.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// RPC message types (MessagePack-RPC spec)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Request = 0,
    Response = 1,
    Notification = 2,
}

/// RPC Request message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub msg_type: u8,             // Always 0 for request
    pub msg_id: u32,              // Unique message ID
    pub method: String,           // Method name
    pub params: Vec<rmpv::Value>, // Parameters
}

/// RPC Response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub msg_type: u8,                // Always 1 for response
    pub msg_id: u32,                 // Same as request msg_id
    pub error: Option<RpcError>,     // Error if any
    pub result: Option<rmpv::Value>, // Result if successful
}

/// RPC Error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

/// RPC Notification (no response expected)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcNotification {
    pub msg_type: u8,             // Always 2 for notification
    pub method: String,           // Method name
    pub params: Vec<rmpv::Value>, // Parameters
}

/// Decoded RPC message
#[derive(Debug, Clone)]
pub enum RpcMessage {
    Request(RpcRequest),
    Response(RpcResponse),
    Notification(RpcNotification),
}

impl RpcRequest {
    pub fn new(msg_id: u32, method: &str, params: Vec<rmpv::Value>) -> Self {
        Self {
            msg_type: 0,
            msg_id,
            method: method.to_string(),
            params,
        }
    }

    /// Encode request to MessagePack bytes
    pub fn encode(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        // MessagePack-RPC request: [type, msgid, method, params]
        let msg: (u8, u32, &str, &[rmpv::Value]) =
            (self.msg_type, self.msg_id, &self.method, &self.params);
        rmp_serde::to_vec(&msg)
    }
}

impl RpcResponse {
    pub fn success(msg_id: u32, result: rmpv::Value) -> Self {
        Self {
            msg_type: 1,
            msg_id,
            error: None,
            result: Some(result),
        }
    }

    pub fn error(msg_id: u32, code: i32, message: &str) -> Self {
        Self {
            msg_type: 1,
            msg_id,
            error: Some(RpcError {
                code,
                message: message.to_string(),
            }),
            result: None,
        }
    }

    /// Encode response to MessagePack bytes
    pub fn encode(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        // MessagePack-RPC response: [type, msgid, error, result]
        let error = self
            .error
            .as_ref()
            .map(|e| {
                let mut map = HashMap::new();
                map.insert("code".to_string(), rmpv::Value::Integer(e.code.into()));
                map.insert(
                    "message".to_string(),
                    rmpv::Value::String(e.message.clone().into()),
                );
                rmpv::Value::Map(
                    map.into_iter()
                        .map(|(k, v)| (rmpv::Value::String(k.into()), v))
                        .collect(),
                )
            })
            .unwrap_or(rmpv::Value::Nil);

        let result = self.result.clone().unwrap_or(rmpv::Value::Nil);
        let msg: (u8, u32, rmpv::Value, rmpv::Value) = (self.msg_type, self.msg_id, error, result);
        rmp_serde::to_vec(&msg)
    }
}

impl RpcNotification {
    pub fn new(method: &str, params: Vec<rmpv::Value>) -> Self {
        Self {
            msg_type: 2,
            method: method.to_string(),
            params,
        }
    }

    /// Encode notification to MessagePack bytes
    pub fn encode(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        // MessagePack-RPC notification: [type, method, params]
        let msg: (u8, &str, &[rmpv::Value]) = (self.msg_type, &self.method, &self.params);
        rmp_serde::to_vec(&msg)
    }
}

/// Decode a MessagePack-RPC message from bytes
pub fn decode_message(data: &[u8]) -> Result<RpcMessage, String> {
    // First, try to decode as a generic array
    let value: rmpv::Value =
        rmp_serde::from_slice(data).map_err(|e| format!("Failed to decode MessagePack: {}", e))?;

    let arr = value.as_array().ok_or("Message is not an array")?;

    if arr.is_empty() {
        return Err("Empty message array".to_string());
    }

    let msg_type = arr[0].as_u64().ok_or("Invalid message type")? as u8;

    match msg_type {
        0 => {
            // Request: [0, msgid, method, params]
            if arr.len() < 4 {
                return Err("Invalid request format".to_string());
            }
            let msg_id = arr[1].as_u64().ok_or("Invalid msgid")? as u32;
            let method = arr[2].as_str().ok_or("Invalid method")?.to_string();
            let params = arr[3].as_array().cloned().unwrap_or_default();

            Ok(RpcMessage::Request(RpcRequest {
                msg_type: 0,
                msg_id,
                method,
                params,
            }))
        }
        1 => {
            // Response: [1, msgid, error, result]
            if arr.len() < 4 {
                return Err("Invalid response format".to_string());
            }
            let msg_id = arr[1].as_u64().ok_or("Invalid msgid")? as u32;

            let error = if arr[2].is_nil() {
                None
            } else if let Some(map) = arr[2].as_map() {
                let code = map
                    .iter()
                    .find(|(k, _)| k.as_str() == Some("code"))
                    .and_then(|(_, v)| v.as_i64())
                    .unwrap_or(0) as i32;
                let message = map
                    .iter()
                    .find(|(k, _)| k.as_str() == Some("message"))
                    .and_then(|(_, v)| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Some(RpcError { code, message })
            } else {
                None
            };

            let result = if arr[3].is_nil() {
                None
            } else {
                Some(arr[3].clone())
            };

            Ok(RpcMessage::Response(RpcResponse {
                msg_type: 1,
                msg_id,
                error,
                result,
            }))
        }
        2 => {
            // Notification: [2, method, params]
            if arr.len() < 3 {
                return Err("Invalid notification format".to_string());
            }
            let method = arr[1].as_str().ok_or("Invalid method")?.to_string();
            let params = arr[2].as_array().cloned().unwrap_or_default();

            Ok(RpcMessage::Notification(RpcNotification {
                msg_type: 2,
                method,
                params,
            }))
        }
        _ => Err(format!("Unknown message type: {}", msg_type)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_request() {
        let req = RpcRequest::new(1, "test", vec![rmpv::Value::Integer(42.into())]);
        let encoded = req.encode().unwrap();

        let decoded = decode_message(&encoded).unwrap();
        if let RpcMessage::Request(r) = decoded {
            assert_eq!(r.msg_id, 1);
            assert_eq!(r.method, "test");
            assert_eq!(r.params.len(), 1);
        } else {
            panic!("Expected Request");
        }
    }

    #[test]
    fn test_encode_decode_response() {
        let resp = RpcResponse::success(1, rmpv::Value::String("ok".into()));
        let encoded = resp.encode().unwrap();

        let decoded = decode_message(&encoded).unwrap();
        if let RpcMessage::Response(r) = decoded {
            assert_eq!(r.msg_id, 1);
            assert!(r.error.is_none());
            assert!(r.result.is_some());
        } else {
            panic!("Expected Response");
        }
    }
}
