# SPDX-License-Identifier: Apache-2.0 OR MIT
# ML-KEM Demo Application for Arduino Uno Q

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(mlkem_demo)

# Add the SPI peripheral C driver from dragonwing-spi crate
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../crates/dragonwing-spi/c/spi_peripheral.c)

# Add the LED matrix C driver from dragonwing-led-matrix crate
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../crates/dragonwing-led-matrix/c/matrix.c)

# Build the Rust application
rust_cargo_application()
