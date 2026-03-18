# dragonwing-zcbor

Rust wrapper for Zephyr's zcbor CBOR library.

## MCU-Only

This crate is `no_std` and requires Zephyr's zcbor C library to be linked. It is intended for use on microcontrollers running Zephyr RTOS.

## Features

- `cose` - Enable COSE_Sign1 support (requires `dragonwing-crypto`)

## Requirements

Enable zcbor in your Zephyr `prj.conf`:

```
CONFIG_ZCBOR=y
```
