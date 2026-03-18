# SPDX-License-Identifier: Apache-2.0 OR MIT
# SPI Test Application for Arduino Uno Q

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(spi_test)

# Add the SPI peripheral C driver from dragonwing-spi crate
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../crates/dragonwing-spi/c/spi_peripheral.c)

# Build the Rust application
rust_cargo_application()
