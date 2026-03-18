# SPDX-License-Identifier: Apache-2.0 OR MIT
# RPC Demo Application for Arduino Uno Q

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(rpc_demo)

# Add the RPC UART C driver (demo-specific, uses UART instead of SPI)
target_sources(app PRIVATE src/c/rpc_uart.c)

# Build the Rust application
rust_cargo_application()
