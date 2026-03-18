// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// DragonWing RPC - Cross-platform MessagePack-RPC for Arduino Uno Q
//
// This crate provides RPC communication between the STM32U585 MCU and
// QRB2210 Linux MPU on the Arduino Uno Q board.
//
// # Features
//
// - `mcu`: Enables no_std server/bridge for STM32U585 (Zephyr RTOS)
// - `mpu`: Enables std async client for QRB2210 Linux (requires tokio)
//
// # Architecture
//
// ```text
// ┌─────────────────────┐         ┌─────────────────────┐
// │   STM32U585 MCU     │         │  QRB2210 Linux MPU  │
// │   (Zephyr RTOS)     │         │                     │
// │                     │  UART   │                     │
// │  ┌───────────────┐  │◄───────►│  ┌───────────────┐  │
// │  │ Bridge/Server │  │ Serial1 │  │ RpcClient     │  │
// │  │ (mcu feature) │  │ 115200  │  │ (mpu feature) │  │
// │  └───────────────┘  │         │  └───────────────┘  │
// └─────────────────────┘         └─────────────────────┘
// ```
//
// # Protocol
//
// Uses MessagePack-RPC format:
// - Request: [type=0, msgid, method, params]
// - Response: [type=1, msgid, error, result]
// - Notification: [type=2, method, params]

// Conditionally enable no_std for MCU builds
#![cfg_attr(all(feature = "mcu", not(feature = "std")), no_std)]

// Module declarations
pub mod protocol;

#[cfg(feature = "mcu")]
pub mod bridge;

#[cfg(feature = "mpu")]
pub mod client;

// Re-export protocol types (always available)
pub use protocol::{
    RpcErrorCode, RpcMessageType, DECODER_BUFFER_SIZE, DEFAULT_BAUD_RATE, DEFAULT_RPC_BUFFER_SIZE,
    MAX_METHOD_NAME_LEN, MAX_STRING_LEN, MIN_RPC_BYTES,
};

// Re-export MCU types when mcu feature is enabled
#[cfg(feature = "mcu")]
pub use bridge::{
    // Bridge API
    Bridge,
    // MessagePack types
    MsgPackPacker,
    MsgPackUnpacker,
    MsgPackValue,
    // RPC types
    RpcClient as McuRpcClient,
    RpcDecoder,
    RpcHandler,
    RpcRequest,
    RpcResponse,
    RpcResult,
    RpcServer,
    RpcValue,
    // Transport
    SpiTransport,
    Transport,
    UartTransport,
    // Server
    MAX_HANDLERS,
    MAX_PARAMS,
    PARAMS,
    // SPI constants
    FRAME_MAGIC,
    FRAME_HEADER_SIZE,
    MAX_PAYLOAD_SIZE,
    SPI_BUFFER_SIZE,
};

#[cfg(feature = "mcu")]
pub use protocol::mcu::{RpcError as McuRpcError, StrBuf};

// Re-export MPU types when mpu feature is enabled
#[cfg(feature = "mpu")]
pub use client::{
    LedMatrixClient, RpcClient, RpcClientSync, RpcError, RpcResult as MpuRpcResult,
};
