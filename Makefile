# ==============================================================================
# DragonWing-rs Makefile
# ==============================================================================
#
# Unified build system for Arduino Uno Q development
#
# The Arduino Uno Q has two processors:
#   - STM32U585 MCU: Cortex-M33 running Zephyr RTOS (Rust, no_std)
#   - QRB2210 MPU: Qualcomm Adreno running Linux (Rust, std)
#
# Quick Start:
#   make build-mcu DEMO=pqc-demo    # Build MCU firmware
#   make flash                       # Flash to board
#   make build-mpu APP=pqc-client   # Build MPU app
#   make deploy APP=pqc-client      # Deploy to board
#   make run DEMO=pqc/psa           # Run demo
#
# ==============================================================================

# Configuration
IMAGE_NAME := dragonwing-builder
DOCKER_DIR := docker
OUTPUT_DIR := output

# Board connection settings (set via environment variables or .env file)
# Example: export BOARD_IP=192.168.1.100 BOARD_USER=arduino BOARD_PASS=yourpassword
BOARD_IP ?= $(error BOARD_IP is not set. Set via environment variable or create .env file)
BOARD_USER ?= arduino
BOARD_PASS ?= $(error BOARD_PASS is not set. Set via environment variable or create .env file)

# Linux cross-compilation target
LINUX_TARGET := aarch64-unknown-linux-gnu

# Zephyr board name
BOARD := arduino_uno_q

# OpenOCD paths on the Arduino Uno Q board
OPENOCD_BIN := /opt/openocd/bin/openocd
OPENOCD_SCRIPTS := /opt/openocd/share/openocd/scripts
OPENOCD_CFG_DIR := /opt/openocd
SWD_CFG := /home/arduino/QRB2210_swd.cfg
STM32_CFG := /opt/openocd/stm32u5x.cfg
REMOTE_ELF := /home/arduino/zephyr.elf

# Colors for output
CYAN := \033[0;36m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m

.PHONY: all help build-mcu flash build-mpu deploy run demo demo-list \
        docker-build docker-shell clean serial ssh ping version setup-spi-router

# ==============================================================================
# Help
# ==============================================================================

help:
	@echo "$(CYAN)DragonWing-rs - Arduino Uno Q Development$(NC)"
	@echo ""
	@echo "$(GREEN)Quick Start:$(NC)"
	@echo "  make build-mcu DEMO=pqc-demo  - Build MCU firmware"
	@echo "  make flash                     - Flash MCU firmware"
	@echo "  make build-mpu APP=pqc-client - Build MPU application"
	@echo "  make deploy APP=pqc-client    - Deploy to board"
	@echo "  make run DEMO=pqc/psa         - Run a demo"
	@echo ""
	@echo "$(GREEN)MCU Demos (STM32U585, Zephyr RTOS):$(NC)"
	@echo "  pqc-demo        - Post-quantum cryptography showcase"
	@echo "  led-matrix-demo - LED matrix animations"
	@echo "  rpc-demo        - Basic RPC communication"
	@echo "  rpc-server      - RPC server with LED matrix"
	@echo "  mlkem-demo      - ML-KEM 768 demo"
	@echo "  spi-test        - SPI communication test"
	@echo ""
	@echo "$(GREEN)MPU Apps (QRB2210, Linux):$(NC)"
	@echo "  pqc-client      - PQC demo client"
	@echo "  mlkem-client    - ML-KEM client"
	@echo "  weather-display - Weather on LED matrix"
	@echo "  spi-router      - SPI router daemon"
	@echo ""
	@echo "$(GREEN)Run Targets (after flashing):$(NC)"
	@echo "  make run DEMO=pqc/psa         - PSA Secure Storage"
	@echo "  make run DEMO=pqc/persistence - SAGA + X-Wing persistence"
	@echo "  make run DEMO=pqc/xwing       - X-Wing hybrid KEM"
	@echo "  make run DEMO=pqc/saga        - SAGA anonymous credentials"
	@echo "  make run DEMO=pqc/mlkem       - ML-KEM 768"
	@echo "  make run DEMO=pqc/ed25519     - Ed25519 signatures"
	@echo "  make run DEMO=pqc/x25519      - X25519 key exchange"
	@echo "  make run DEMO=pqc/xchacha20   - XChaCha20-Poly1305 AEAD"
	@echo ""
	@echo "$(GREEN)Utility Commands:$(NC)"
	@echo "  make serial                   - Open serial console"
	@echo "  make ssh                      - SSH to board"
	@echo "  make ping                     - Ping MCU"
	@echo "  make docker-shell             - Open Docker shell"
	@echo "  make clean                    - Clean build artifacts"
	@echo ""
	@echo "$(GREEN)Setup Commands:$(NC)"
	@echo "  make docker-build             - Build Docker image"
	@echo "  make setup-spi-router         - Install SPI router service"

# ==============================================================================
# Docker Commands
# ==============================================================================

# Check if Docker is available
check-docker:
	@command -v docker >/dev/null 2>&1 || { echo "$(RED)Error: Docker is not installed$(NC)"; exit 1; }

# Build the Docker image
docker-build: check-docker
	@echo "$(CYAN)Building Docker image...$(NC)"
	docker build -t $(IMAGE_NAME) -f $(DOCKER_DIR)/Dockerfile $(DOCKER_DIR)
	@echo "$(GREEN)Docker image built successfully$(NC)"

# Ensure Docker image exists
.docker-image-built: $(DOCKER_DIR)/Dockerfile
	@$(MAKE) docker-build
	@touch .docker-image-built

# Open a shell in the Docker container
docker-shell: check-docker .docker-image-built
	@echo "$(CYAN)Opening shell in Docker container...$(NC)"
	docker run --rm -it \
		-v "$$(pwd):/workspace" \
		-v "$$(pwd)/$(OUTPUT_DIR):/output" \
		$(IMAGE_NAME) \
		/bin/bash

# ==============================================================================
# MCU Build Commands (STM32U585)
# ==============================================================================

# Default demo
DEMO ?= pqc-demo

# Build MCU firmware
# Usage: make build-mcu DEMO=pqc-demo
build-mcu: check-docker .docker-image-built
	@echo "$(CYAN)Building MCU demo: $(DEMO)...$(NC)"
	@mkdir -p $(OUTPUT_DIR)
	docker run --rm \
		-v "$$(pwd)/crates/dragonwing-crypto:/lib-crypto:ro" \
		-v "$$(pwd)/crates/dragonwing-led-matrix:/lib-led-matrix:ro" \
		-v "$$(pwd)/crates/dragonwing-rpc:/lib-rpc:ro" \
		-v "$$(pwd)/crates/dragonwing-spi:/lib-spi:ro" \
		-v "$$(pwd)/crates/dragonwing-zcbor:/lib-zcbor:ro" \
		-v "$$(pwd)/demos/mcu/$(DEMO):/app:ro" \
		-v "$$(pwd)/$(OUTPUT_DIR):/output" \
		$(IMAGE_NAME) \
		/bin/bash -c '\
			set -e && \
			echo "Copying demo source..." && \
			cp -r /app /tmp/app && \
			echo "Copying libraries..." && \
			mkdir -p /tmp/app/dragonwing-crypto && \
			mkdir -p /tmp/app/dragonwing-led-matrix && \
			mkdir -p /tmp/app/dragonwing-rpc && \
			mkdir -p /tmp/app/dragonwing-spi && \
			mkdir -p /tmp/app/dragonwing-zcbor && \
			cp -r /lib-crypto/* /tmp/app/dragonwing-crypto/ 2>/dev/null || true && \
			cp -r /lib-led-matrix/* /tmp/app/dragonwing-led-matrix/ 2>/dev/null || true && \
			cp -r /lib-rpc/* /tmp/app/dragonwing-rpc/ 2>/dev/null || true && \
			cp -r /lib-spi/* /tmp/app/dragonwing-spi/ 2>/dev/null || true && \
			cp -r /lib-zcbor/* /tmp/app/dragonwing-zcbor/ 2>/dev/null || true && \
			sed -i "s|path = \"../../crates/dragonwing-crypto\"|path = \"dragonwing-crypto\"|g" /tmp/app/Cargo.toml 2>/dev/null || true && \
			sed -i "s|path = \"../../crates/dragonwing-led-matrix\"|path = \"dragonwing-led-matrix\"|g" /tmp/app/Cargo.toml 2>/dev/null || true && \
			sed -i "s|path = \"../../crates/dragonwing-rpc\"|path = \"dragonwing-rpc\"|g" /tmp/app/Cargo.toml 2>/dev/null || true && \
			sed -i "s|path = \"../../crates/dragonwing-spi\"|path = \"dragonwing-spi\"|g" /tmp/app/Cargo.toml 2>/dev/null || true && \
			sed -i "s|path = \"../../crates/dragonwing-zcbor\"|path = \"dragonwing-zcbor\"|g" /tmp/app/Cargo.toml 2>/dev/null || true && \
			echo "Configuring build..." && \
			west build -p auto -b $(BOARD) /tmp/app -d /tmp/build && \
			echo "Copying artifacts..." && \
			cp /tmp/build/zephyr/zephyr.elf /output/ && \
			cp /tmp/build/zephyr/zephyr.bin /output/ 2>/dev/null || true && \
			cp /tmp/build/zephyr/zephyr.hex /output/ 2>/dev/null || true && \
			echo "Build artifacts:" && \
			ls -la /output/ \
		'
	@echo "$(GREEN)Build complete! Artifacts in $(OUTPUT_DIR)/$(NC)"

# Check if ADB is available
check-adb:
	@command -v adb >/dev/null 2>&1 || { echo "$(RED)Error: ADB is not installed. Install via: brew install android-platform-tools$(NC)"; exit 1; }
	@adb devices | grep -q "device$$" || { echo "$(RED)Error: No ADB device found. Connect the Arduino Uno Q via USB.$(NC)"; exit 1; }

# Flash the MCU firmware
# Usage: make flash
flash: check-adb
	@echo "$(CYAN)Flashing MCU firmware...$(NC)"
	@test -f $(OUTPUT_DIR)/zephyr.elf || { echo "$(RED)Error: No firmware found. Run 'make build-mcu' first.$(NC)"; exit 1; }
	@echo "Pushing firmware to board..."
	adb push $(OUTPUT_DIR)/zephyr.elf $(REMOTE_ELF)
	@echo "Flashing via OpenOCD..."
	adb shell "$(OPENOCD_BIN) \
		-s $(OPENOCD_SCRIPTS) \
		-s $(OPENOCD_CFG_DIR) \
		-f $(SWD_CFG) \
		-f $(STM32_CFG) \
		-c 'program $(REMOTE_ELF) verify reset exit'"
	@echo "$(GREEN)Flash complete!$(NC)"

# ==============================================================================
# MPU Build Commands (QRB2210 Linux)
# ==============================================================================

# Default app
APP ?= pqc-client

# Check if cargo-zigbuild is available
check-zigbuild:
	@command -v cargo-zigbuild >/dev/null 2>&1 || { echo "$(RED)Error: cargo-zigbuild is not installed. Install via: cargo install cargo-zigbuild$(NC)"; exit 1; }

# Check if sshpass is available
check-ssh:
	@command -v sshpass >/dev/null 2>&1 || { echo "$(RED)Error: sshpass is not installed. Install via: brew install hudochenkov/sshpass/sshpass$(NC)"; exit 1; }

# Build MPU application
# Usage: make build-mpu APP=pqc-client
build-mpu: check-zigbuild
	@echo "$(CYAN)Building MPU app: $(APP)...$(NC)"
ifeq ($(APP),spi-router)
	cd crates/dragonwing-spi-router && cargo zigbuild --target $(LINUX_TARGET) --release
	@echo "$(GREEN)Build complete: crates/dragonwing-spi-router/target/$(LINUX_TARGET)/release/dragonwing-spi-router$(NC)"
else
	cd demos/mpu/$(APP) && cargo zigbuild --target $(LINUX_TARGET) --release
	@echo "$(GREEN)Build complete: demos/mpu/$(APP)/target/$(LINUX_TARGET)/release/$(APP)$(NC)"
endif

# Deploy MPU application to board
# Usage: make deploy APP=pqc-client
deploy: check-ssh
	@echo "$(CYAN)Deploying $(APP) to board...$(NC)"
ifeq ($(APP),spi-router)
	@test -f crates/dragonwing-spi-router/target/$(LINUX_TARGET)/release/dragonwing-spi-router || { echo "$(RED)Error: Binary not found. Run 'make build-mpu APP=spi-router' first.$(NC)"; exit 1; }
	sshpass -p '$(BOARD_PASS)' scp crates/dragonwing-spi-router/target/$(LINUX_TARGET)/release/dragonwing-spi-router $(BOARD_USER)@$(BOARD_IP):/home/$(BOARD_USER)/spi-router
	@echo "$(GREEN)Deployed to /home/$(BOARD_USER)/spi-router$(NC)"
else
	@test -f demos/mpu/$(APP)/target/$(LINUX_TARGET)/release/$(APP) || { echo "$(RED)Error: Binary not found. Run 'make build-mpu APP=$(APP)' first.$(NC)"; exit 1; }
	sshpass -p '$(BOARD_PASS)' scp demos/mpu/$(APP)/target/$(LINUX_TARGET)/release/$(APP) $(BOARD_USER)@$(BOARD_IP):/home/$(BOARD_USER)/
	@echo "$(GREEN)Deployed to /home/$(BOARD_USER)/$(APP)$(NC)"
endif

# ==============================================================================
# Demo Commands
# ==============================================================================

# Run a specific demo
# Usage: make run DEMO=pqc/psa
#        make run DEMO=pqc/persistence
run: check-ssh
	@echo "$(CYAN)Running demo: $(DEMO)...$(NC)"
	@echo "Watch the LED matrix for status indicators!"
	@echo ""
	$(eval DEMO_FLAG := $(shell echo $(DEMO) | sed 's|pqc/||' | sed 's|/|-|g'))
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "/home/$(BOARD_USER)/pqc-client --$(DEMO_FLAG)-demo"

# Full demo workflow: build MCU, flash, build MPU client, deploy, run
# Usage: make demo DEMO=pqc/psa
demo:
	@echo "$(CYAN)Running full demo workflow...$(NC)"
	$(MAKE) build-mcu DEMO=pqc-demo
	$(MAKE) flash
	$(MAKE) build-mpu APP=pqc-client
	$(MAKE) deploy APP=pqc-client
	$(MAKE) run DEMO=$(DEMO)

# List available demos
demo-list:
	@echo "$(CYAN)Available Demos:$(NC)"
	@echo ""
	@echo "$(GREEN)MCU Demos (DEMO=):$(NC)"
	@echo "  pqc-demo        - Post-quantum cryptography (full)"
	@echo "  led-matrix-demo - LED matrix animations"
	@echo "  rpc-demo        - Basic RPC communication"
	@echo "  rpc-server      - RPC server with LED matrix"
	@echo "  mlkem-demo      - ML-KEM 768 standalone"
	@echo "  spi-test        - SPI communication test"
	@echo ""
	@echo "$(GREEN)MPU Apps (APP=):$(NC)"
	@echo "  pqc-client      - PQC demo client"
	@echo "  mlkem-client    - ML-KEM client"
	@echo "  weather-display - Weather on LED matrix"
	@echo "  spi-router      - SPI router daemon"
	@echo ""
	@echo "$(GREEN)Run Targets (after flash):$(NC)"
	@echo "  make run DEMO=pqc/psa         - PSA Secure Storage"
	@echo "  make run DEMO=pqc/persistence - SAGA + X-Wing persistence"
	@echo "  make run DEMO=pqc/xwing       - X-Wing hybrid KEM"
	@echo "  make run DEMO=pqc/saga        - SAGA anonymous credentials"
	@echo "  make run DEMO=pqc/saga-xwing  - SAGA + X-Wing combined"
	@echo "  make run DEMO=pqc/mlkem       - ML-KEM 768"
	@echo "  make run DEMO=pqc/mldsa       - ML-DSA 65 (slow!)"
	@echo "  make run DEMO=pqc/ed25519     - Ed25519 signatures"
	@echo "  make run DEMO=pqc/x25519      - X25519 key exchange"
	@echo "  make run DEMO=pqc/xchacha20   - XChaCha20-Poly1305 AEAD"

# ==============================================================================
# Utility Commands
# ==============================================================================

# Open serial console to MCU
serial: check-ssh
	@echo "$(CYAN)Opening serial console to MCU (Ctrl+A then X to exit)...$(NC)"
	sshpass -p '$(BOARD_PASS)' ssh -t $(BOARD_USER)@$(BOARD_IP) "picocom -b 115200 /dev/ttyACM0"

# SSH to board
ssh: check-ssh
	@echo "$(CYAN)SSH to Arduino Uno Q...$(NC)"
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP)

# Ping the MCU
ping: check-ssh
	@sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "/home/$(BOARD_USER)/pqc-client --ping"

# Get MCU version
version: check-ssh
	@sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "/home/$(BOARD_USER)/pqc-client --version"

# Setup SPI router as systemd service
setup-spi-router: check-zigbuild check-ssh
	@echo "$(CYAN)Setting up SPI router...$(NC)"
	$(MAKE) build-mpu APP=spi-router
	$(MAKE) deploy APP=spi-router
	@echo "Installing systemd service..."
	sshpass -p '$(BOARD_PASS)' scp config/dragonwing-spi-router.service $(BOARD_USER)@$(BOARD_IP):/tmp/
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "\
		echo '$(BOARD_PASS)' | sudo -S cp /tmp/dragonwing-spi-router.service /etc/systemd/system/ && \
		echo '$(BOARD_PASS)' | sudo -S systemctl daemon-reload && \
		echo '$(BOARD_PASS)' | sudo -S systemctl enable dragonwing-spi-router && \
		echo '$(BOARD_PASS)' | sudo -S systemctl restart dragonwing-spi-router && \
		sleep 2 && \
		systemctl status dragonwing-spi-router --no-pager"
	@echo "$(GREEN)SPI router service installed and started$(NC)"

# Setup SWD configuration on board (first-time setup)
setup-swd: check-adb
	@echo "$(CYAN)Setting up SWD configuration on board...$(NC)"
	adb push config/QRB2210_swd.cfg /home/arduino/
	@echo "$(GREEN)SWD configuration uploaded$(NC)"

# ==============================================================================
# Clean
# ==============================================================================

clean:
	@echo "$(CYAN)Cleaning build artifacts...$(NC)"
	rm -rf $(OUTPUT_DIR)
	rm -f .docker-image-built
	find demos -name "target" -type d -exec rm -rf {} + 2>/dev/null || true
	find crates -name "target" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)Clean complete$(NC)"

# Clean everything including Docker image
distclean: clean
	@echo "$(CYAN)Removing Docker image...$(NC)"
	-docker rmi $(IMAGE_NAME) 2>/dev/null || true
	@echo "$(GREEN)Distclean complete$(NC)"
