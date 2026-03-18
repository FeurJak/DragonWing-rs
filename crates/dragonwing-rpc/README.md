# dragonwing-rpc

Cross-platform MessagePack-RPC library for Arduino Uno Q.

## Overview

This crate provides RPC communication between the STM32U585 MCU and QRB2210 Linux MPU on the Arduino Uno Q board. It supports both sides of the communication through feature flags.

## Features

- **`mcu`**: Enables `no_std` server/bridge for STM32U585 (Zephyr RTOS)
- **`mpu`**: Enables `std` async client for QRB2210 Linux (requires tokio)

## Usage

### MCU Side (STM32U585)

```toml
[dependencies]
dragonwing-rpc = { version = "0.1", features = ["mcu"] }
```

```rust
use dragonwing_rpc::{Bridge, MsgPackValue};

let mut bridge = Bridge::new();
bridge.begin();

// Make RPC calls to Linux
let result = bridge.call_int("multiply", &[
    MsgPackValue::Int(5),
    MsgPackValue::Int(7),
]);
```

### MPU Side (QRB2210 Linux)

```toml
[dependencies]
dragonwing-rpc = { version = "0.1", features = ["mpu"] }
```

```rust
use dragonwing_rpc::RpcClient;

let client = RpcClient::connect("/run/arduino-spi-router.sock").await?;
let result = client.call("ping", vec![]).await?;
```

## Protocol

Uses MessagePack-RPC format:
- Request: `[0, msgid, method, params]`
- Response: `[1, msgid, error, result]`
- Notification: `[2, method, params]`
