# Dockerfile for Arduino Libraries Rust Development
# 
# This container provides a complete build environment for Rust applications
# targeting the STM32U585 MCU on the Arduino Uno Q board via Zephyr RTOS.
#
# Build stages:
#   1. base: Ubuntu with system dependencies
#   2. zephyr-sdk: Installs Zephyr SDK (ARM toolchain)
#   3. rust: Installs Rust with embedded targets
#   4. zephyr: Clones and sets up Zephyr workspace with Rust support
#   5. final: Production image with all tools

FROM ubuntu:24.04 AS base

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Build essentials
    build-essential \
    cmake \
    ninja-build \
    # Python for West and Zephyr scripts
    python3 \
    python3-pip \
    python3-venv \
    # Git for cloning repositories
    git \
    # Device tree compiler
    device-tree-compiler \
    # For bindgen (Rust FFI generation)
    clang \
    libclang-dev \
    # Utilities
    wget \
    curl \
    xz-utils \
    file \
    # ADB for flashing (optional, for local dev)
    adb \
    # Cleanup
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# Stage 2: Install Zephyr SDK
# -----------------------------------------------------------------------------
FROM base AS zephyr-sdk

ARG ZEPHYR_SDK_VERSION=1.0.0
ARG ZEPHYR_SDK_INSTALL_DIR=/opt/zephyr-sdk

# Download and install Zephyr SDK (minimal - just ARM toolchain)
# Detect architecture and download the correct SDK variant
RUN mkdir -p ${ZEPHYR_SDK_INSTALL_DIR} && \
    cd /tmp && \
    ARCH=$(uname -m) && \
    if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        SDK_ARCH="linux-aarch64"; \
    else \
        SDK_ARCH="linux-x86_64"; \
    fi && \
    echo "Downloading Zephyr SDK for ${SDK_ARCH}..." && \
    wget -q https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v${ZEPHYR_SDK_VERSION}/zephyr-sdk-${ZEPHYR_SDK_VERSION}_${SDK_ARCH}_minimal.tar.xz && \
    tar -xf zephyr-sdk-${ZEPHYR_SDK_VERSION}_${SDK_ARCH}_minimal.tar.xz && \
    mv zephyr-sdk-${ZEPHYR_SDK_VERSION} /opt/zephyr-sdk-${ZEPHYR_SDK_VERSION} && \
    cd /opt/zephyr-sdk-${ZEPHYR_SDK_VERSION} && \
    ./setup.sh -t arm-zephyr-eabi -h -c && \
    rm /tmp/zephyr-sdk-${ZEPHYR_SDK_VERSION}_${SDK_ARCH}_minimal.tar.xz

ENV ZEPHYR_SDK_INSTALL_DIR=/opt/zephyr-sdk-1.0.0

# -----------------------------------------------------------------------------
# Stage 3: Install Rust
# -----------------------------------------------------------------------------
FROM zephyr-sdk AS rust

# Install Rust
ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
ENV PATH="${CARGO_HOME}/bin:${PATH}"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --profile minimal && \
    # Add ARM Cortex-M33 targets
    rustup target add thumbv8m.main-none-eabi && \
    rustup target add thumbv8m.main-none-eabihf

# -----------------------------------------------------------------------------
# Stage 4: Setup Zephyr workspace
# -----------------------------------------------------------------------------
FROM rust AS zephyr

# Create workspace directory
WORKDIR /workspace

# Create Python virtual environment and install West
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

RUN pip install --no-cache-dir west

# Initialize Zephyr workspace
# 1. Init with Zephyr as the manifest repository
# 2. Clone the Rust language support module
# 3. Update all modules
RUN west init && \
    west update && \
    git clone https://github.com/zephyrproject-rtos/zephyr-lang-rust.git && \
    west zephyr-export

# Install Zephyr Python dependencies
RUN pip install --no-cache-dir -r /workspace/zephyr/scripts/requirements.txt

# Set environment variables for Zephyr
ENV ZEPHYR_BASE=/workspace/zephyr
ENV ZEPHYR_EXTRA_MODULES=/workspace/zephyr-lang-rust

# -----------------------------------------------------------------------------
# Stage 5: Final production image
# -----------------------------------------------------------------------------
FROM zephyr AS final

# Create workspace directory for mounting source code
RUN mkdir -p /workspace

# Create output directory for build artifacts
RUN mkdir -p /output

# Set working directory
WORKDIR /workspace

# Default command - show help
CMD ["echo", "Use 'make build' or 'make flash' from the host"]
