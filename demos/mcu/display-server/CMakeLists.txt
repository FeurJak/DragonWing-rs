# SPDX-License-Identifier: Apache-2.0 OR MIT
# Display Server for Arduino Uno Q
# Controls SSD1306 OLED (I2C) and LED Matrix via SPI RPC

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(display_server)

# Add the I2C C driver from dragonwing-i2c crate
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/dragonwing-i2c/c/i2c.c)

# Add the LED Matrix C driver from dragonwing-led-matrix crate
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/dragonwing-led-matrix/c/matrix.c)

# Add the SPI peripheral C driver from dragonwing-spi crate
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/dragonwing-spi/c/spi_peripheral.c)

# Build the Rust application
rust_cargo_application()
