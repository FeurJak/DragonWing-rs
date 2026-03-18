# SPDX-License-Identifier: Apache-2.0 OR MIT
# PQC Demo Application for Arduino Uno Q (ML-KEM + ML-DSA)

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(pqc_demo)

# Add the SPI peripheral C driver from dragonwing-spi crate
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../crates/dragonwing-spi/c/spi_peripheral.c)

# Add the LED matrix C driver from dragonwing-led-matrix crate
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../crates/dragonwing-led-matrix/c/matrix.c)

# Add the hardware RNG wrapper from dragonwing-crypto crate
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../crates/dragonwing-crypto/c/hwrng.c)

# Add Ed25519 implementation (classical cryptography)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../crates/dragonwing-crypto/c/ed25519.c)

# Add X25519 implementation (for X-Wing hybrid KEM)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../crates/dragonwing-crypto/c/x25519.c)

# Add XChaCha20-Poly1305 implementation (uses mbedTLS ChaCha20-Poly1305)
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../crates/dragonwing-crypto/c/xchacha20poly1305.c)

# Add PSA Secure Storage wrapper for Rust FFI
# Provides ITS (Internal Trusted Storage) and Crypto key management
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../crates/dragonwing-crypto/c/psa_wrapper.c)

# Build the Rust application
rust_cargo_application()
