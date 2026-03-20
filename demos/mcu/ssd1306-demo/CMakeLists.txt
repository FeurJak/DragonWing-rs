# SPDX-License-Identifier: Apache-2.0 OR MIT
# SSD1306 OLED Display Demo for Arduino Uno Q

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ssd1306_demo)

# Add the I2C C driver from dragonwing-i2c crate
# Path is relative to the build directory structure created by the Makefile
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/dragonwing-i2c/c/i2c.c)

# Build the Rust application
rust_cargo_application()
