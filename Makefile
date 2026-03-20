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
        docker-build docker-shell clean serial ssh ping version setup-spi-router setup-ble-bridge \
        sync-to-board remote-build-mpu remote-install remote-start remote-setup

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
	@echo "  secure-access   - Secure Access responder (SAGA+X-Wing)"
	@echo ""
	@echo "$(GREEN)MPU Apps (QRB2210, Linux):$(NC)"
	@echo "  pqc-client      - PQC demo client"
	@echo "  mlkem-client    - ML-KEM client"
	@echo "  weather-display - Weather on LED matrix"
	@echo "  spi-router      - SPI router daemon"
	@echo "  ble-bridge      - BLE bridge for Secure Access"
	@echo "  remote-iot      - Phone camera streaming"
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
	@echo "  make setup-ble-bridge         - Install BLE bridge service (cross-compiled)"
	@echo ""
	@echo "$(GREEN)Remote Build (native compilation on board):$(NC)"
	@echo "  make sync-to-board            - Sync project to board"
	@echo "  make remote-build-mpu APP=x   - Build app on board"
	@echo "  make remote-build-mpu APP=x FEATURES=y - Build with features"
	@echo "  make remote-install APP=x     - Install built binary"
	@echo "  make remote-start APP=x       - Start/restart systemd service"
	@echo "  make remote-setup APP=x       - Full workflow: sync+build+install+start"
	@echo ""
	@echo "$(YELLOW)Example (BLE bridge with BlueZ):$(NC)"
	@echo "  make setup-ble-bridge-native  - One command setup"
	@echo "  # Or step by step:"
	@echo "  make remote-build-mpu APP=ble-bridge FEATURES=bluez"
	@echo "  make remote-install APP=ble-bridge"
	@echo "  make remote-start APP=ble-bridge"

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
		-v "$$(pwd)/crates/dragonwing-i2c:/lib-i2c:ro" \
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
			mkdir -p /tmp/app/dragonwing-i2c && \
			mkdir -p /tmp/app/dragonwing-led-matrix && \
			mkdir -p /tmp/app/dragonwing-rpc && \
			mkdir -p /tmp/app/dragonwing-spi && \
			mkdir -p /tmp/app/dragonwing-zcbor && \
			cp -r /lib-crypto/* /tmp/app/dragonwing-crypto/ 2>/dev/null || true && \
			cp -r /lib-i2c/* /tmp/app/dragonwing-i2c/ 2>/dev/null || true && \
			cp -r /lib-led-matrix/* /tmp/app/dragonwing-led-matrix/ 2>/dev/null || true && \
			cp -r /lib-rpc/* /tmp/app/dragonwing-rpc/ 2>/dev/null || true && \
			cp -r /lib-spi/* /tmp/app/dragonwing-spi/ 2>/dev/null || true && \
			cp -r /lib-zcbor/* /tmp/app/dragonwing-zcbor/ 2>/dev/null || true && \
			echo "Creating workspace Cargo.toml for standalone build..." && \
			printf "[workspace]\nmembers = [\".\", \"dragonwing-crypto\", \"dragonwing-i2c\", \"dragonwing-led-matrix\", \"dragonwing-rpc\", \"dragonwing-spi\", \"dragonwing-zcbor\"]\nresolver = \"2\"\n\n[workspace.package]\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = \"Apache-2.0 OR MIT\"\nrepository = \"https://github.com/FeurJak/DragonWing-rs\"\n\n[workspace.dependencies]\nlibcrux-iot-ml-kem = { git = \"https://github.com/FeurJak/libcrux-iot\", rev = \"e223df3b37aa76298716c02d77b4d8af96fd2111\", default-features = false }\nlibcrux-iot-ml-dsa = { git = \"https://github.com/FeurJak/libcrux-iot\", rev = \"e223df3b37aa76298716c02d77b4d8af96fd2111\", default-features = false }\nlibcrux-iot-sha3 = { git = \"https://github.com/FeurJak/libcrux-iot\", rev = \"e223df3b37aa76298716c02d77b4d8af96fd2111\" }\nlibcrux-secrets = \"0.0.5\"\ncurve25519-dalek = { version = \"4\", default-features = false, features = [\"alloc\", \"zeroize\"] }\nsha2 = { version = \"0.10\", default-features = false }\nrand_core = { version = \"0.6\", default-features = false }\nrmp-serde = \"1.3\"\nrmpv = { version = \"1.3\", features = [\"with-serde\"] }\nserde = { version = \"1.0\", default-features = false, features = [\"derive\"] }\nheapless = \"0.8\"\nlog = \"0.4\"\nthiserror = \"2.0\"\nanyhow = \"1.0\"\ntokio = { version = \"1\", features = [\"full\"] }\nclap = { version = \"4\", features = [\"derive\"] }\nenv_logger = \"0.11\"\nembedded-hal = \"1.0\"\ndragonwing-zcbor = { path = \"dragonwing-zcbor\" }\ndragonwing-spi = { path = \"dragonwing-spi\" }\ndragonwing-crypto = { path = \"dragonwing-crypto\" }\ndragonwing-i2c = { path = \"dragonwing-i2c\" }\ndragonwing-led-matrix = { path = \"dragonwing-led-matrix\" }\ndragonwing-rpc = { path = \"dragonwing-rpc\" }\n\n" > /tmp/app/Cargo.toml.workspace && \
			head -n 1 /tmp/app/Cargo.toml > /tmp/app/Cargo.toml.new && \
			cat /tmp/app/Cargo.toml.workspace >> /tmp/app/Cargo.toml.new && \
			tail -n +2 /tmp/app/Cargo.toml >> /tmp/app/Cargo.toml.new && \
			mv /tmp/app/Cargo.toml.new /tmp/app/Cargo.toml && \
			sed -i "s|path = \"../../crates/dragonwing-crypto\"|path = \"dragonwing-crypto\"|g" /tmp/app/Cargo.toml 2>/dev/null || true && \
			sed -i "s|path = \"../../crates/dragonwing-i2c\"|path = \"dragonwing-i2c\"|g" /tmp/app/Cargo.toml 2>/dev/null || true && \
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

# Open serial console to MCU (interactive - run from terminal)
# Note: Serial port is managed by arduino-router, use 'monitor' target instead
serial: check-ssh
	@echo "$(CYAN)Opening serial console to MCU (Ctrl+A then Z for menu)...$(NC)"
	@echo "$(YELLOW)Note: If port is busy, stop arduino-router first: sudo systemctl stop arduino-router$(NC)"
	sshpass -p '$(BOARD_PASS)' ssh -t $(BOARD_USER)@$(BOARD_IP) "minicom -D /dev/ttyHS1 -b 115200"

# Monitor MCU via arduino-cli (uses arduino-router)
monitor: check-ssh
	@echo "$(CYAN)Opening MCU monitor via arduino-cli (Ctrl+C to stop)...$(NC)"
	sshpass -p '$(BOARD_PASS)' ssh -t $(BOARD_USER)@$(BOARD_IP) "arduino-cli monitor -p /dev/ttyHS1 --config 115200"

# Read MCU logs from journalctl
logs: check-ssh
	@echo "$(CYAN)Streaming arduino-router logs (Ctrl+C to stop)...$(NC)"
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "journalctl -f -u arduino-router --no-pager"

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

# Setup BLE bridge as systemd service
# Note: Cross-compiled version doesn't have BlueZ support.
# For full BLE functionality, use setup-ble-bridge-native which builds on the board.
setup-ble-bridge: check-zigbuild check-ssh
	@echo "$(CYAN)Setting up BLE bridge (cross-compiled, no BlueZ)...$(NC)"
	@echo "$(YELLOW)Note: For full BLE support, use 'make setup-ble-bridge-native'$(NC)"
	$(MAKE) build-mpu APP=ble-bridge
	$(MAKE) deploy APP=ble-bridge
	@echo "Installing systemd service..."
	sshpass -p '$(BOARD_PASS)' scp config/dragonwing-ble-bridge.service $(BOARD_USER)@$(BOARD_IP):/tmp/
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "\
		echo '$(BOARD_PASS)' | sudo -S cp /tmp/dragonwing-ble-bridge.service /etc/systemd/system/ && \
		echo '$(BOARD_PASS)' | sudo -S systemctl daemon-reload && \
		echo '$(BOARD_PASS)' | sudo -S systemctl enable dragonwing-ble-bridge"
	@echo "$(GREEN)BLE bridge installed (without BlueZ support)$(NC)"

# Remote build directory on board
REMOTE_BUILD_DIR := /home/$(BOARD_USER)/dragonwing-rs

# Sync project to board (excludes target directories and git)
sync-to-board: check-ssh
	@echo "$(CYAN)Syncing project to board...$(NC)"
	@command -v rsync >/dev/null 2>&1 || { echo "$(RED)Error: rsync is not installed$(NC)"; exit 1; }
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "mkdir -p $(REMOTE_BUILD_DIR)"
	sshpass -p '$(BOARD_PASS)' rsync -avz --delete \
		--exclude 'target' \
		--exclude '.git' \
		--exclude 'output' \
		--exclude '.docker-image-built' \
		--exclude '*.elf' \
		--exclude '*.bin' \
		--exclude '*.hex' \
		. $(BOARD_USER)@$(BOARD_IP):$(REMOTE_BUILD_DIR)/
	@echo "$(GREEN)Project synced to $(REMOTE_BUILD_DIR)$(NC)"

# Build MPU application remotely on the board (native compilation)
# Usage: make remote-build-mpu APP=ble-bridge FEATURES=bluez
# This is required for apps with native dependencies (like BlueZ/D-Bus)
FEATURES ?=
remote-build-mpu: check-ssh sync-to-board
	@echo "$(CYAN)Building $(APP) remotely on board...$(NC)"
ifeq ($(APP),spi-router)
	@echo "Building crates/dragonwing-spi-router..."
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "\
		source ~/.cargo/env && \
		cd $(REMOTE_BUILD_DIR)/crates/dragonwing-spi-router && \
		cargo build --release $(if $(FEATURES),--features $(FEATURES),)"
	@echo "$(GREEN)Build complete: $(REMOTE_BUILD_DIR)/crates/dragonwing-spi-router/target/release/dragonwing-spi-router$(NC)"
else
	@echo "Building demos/mpu/$(APP)..."
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "\
		source ~/.cargo/env && \
		cd $(REMOTE_BUILD_DIR)/demos/mpu/$(APP) && \
		cargo build --release $(if $(FEATURES),--features $(FEATURES),)"
	@echo "$(GREEN)Build complete: $(REMOTE_BUILD_DIR)/demos/mpu/$(APP)/target/release/$(APP)$(NC)"
endif

# Install remotely-built app as systemd service
# Usage: make remote-install APP=ble-bridge
# Note: Workspace builds go to the root target/ directory
remote-install: check-ssh
	@echo "$(CYAN)Installing $(APP)...$(NC)"
ifeq ($(APP),spi-router)
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "\
		cp $(REMOTE_BUILD_DIR)/target/release/dragonwing-spi-router /home/$(BOARD_USER)/spi-router"
	@test -f config/dragonwing-spi-router.service && \
		sshpass -p '$(BOARD_PASS)' scp config/dragonwing-spi-router.service $(BOARD_USER)@$(BOARD_IP):/tmp/ && \
		sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "\
			echo '$(BOARD_PASS)' | sudo -S cp /tmp/dragonwing-spi-router.service /etc/systemd/system/ && \
			echo '$(BOARD_PASS)' | sudo -S systemctl daemon-reload && \
			echo '$(BOARD_PASS)' | sudo -S systemctl enable dragonwing-spi-router" || true
	@echo "$(GREEN)$(APP) installed to /home/$(BOARD_USER)/spi-router$(NC)"
else ifeq ($(APP),ble-bridge)
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "\
		cp $(REMOTE_BUILD_DIR)/target/release/ble-bridge /home/$(BOARD_USER)/ble-bridge"
	@test -f config/dragonwing-ble-bridge.service && \
		sshpass -p '$(BOARD_PASS)' scp config/dragonwing-ble-bridge.service $(BOARD_USER)@$(BOARD_IP):/tmp/ && \
		sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "\
			echo '$(BOARD_PASS)' | sudo -S cp /tmp/dragonwing-ble-bridge.service /etc/systemd/system/ && \
			echo '$(BOARD_PASS)' | sudo -S systemctl daemon-reload && \
			echo '$(BOARD_PASS)' | sudo -S systemctl enable dragonwing-ble-bridge" || true
	@echo "$(GREEN)$(APP) installed to /home/$(BOARD_USER)/ble-bridge$(NC)"
else
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "\
		cp $(REMOTE_BUILD_DIR)/target/release/$(APP) /home/$(BOARD_USER)/$(APP)"
	@echo "$(GREEN)$(APP) installed to /home/$(BOARD_USER)/$(APP)$(NC)"
endif

# Start/restart a systemd service
# Usage: make remote-start APP=ble-bridge
remote-start: check-ssh
	@echo "$(CYAN)Starting $(APP)...$(NC)"
ifeq ($(APP),spi-router)
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "\
		echo '$(BOARD_PASS)' | sudo -S systemctl restart dragonwing-spi-router && \
		sleep 2 && \
		systemctl status dragonwing-spi-router --no-pager"
else ifeq ($(APP),ble-bridge)
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "\
		echo '$(BOARD_PASS)' | sudo -S systemctl restart dragonwing-ble-bridge && \
		sleep 2 && \
		systemctl status dragonwing-ble-bridge --no-pager"
else
	@echo "$(YELLOW)No systemd service configured for $(APP). Run manually on board.$(NC)"
endif

# Full remote setup: sync, build with features, install, start
# Usage: make remote-setup APP=ble-bridge FEATURES=bluez
remote-setup: remote-build-mpu remote-install remote-start
	@echo "$(GREEN)$(APP) setup complete!$(NC)"

# Setup BLE bridge with native compilation on the board (full BlueZ support)
# This requires Rust to be installed on the Arduino board
setup-ble-bridge-native: check-ssh
	@echo "$(CYAN)Setting up BLE bridge with native BlueZ support...$(NC)"
	@echo "Installing BlueZ development dependencies..."
	sshpass -p '$(BOARD_PASS)' ssh $(BOARD_USER)@$(BOARD_IP) "\
		echo '$(BOARD_PASS)' | sudo -S apt-get update && \
		echo '$(BOARD_PASS)' | sudo -S apt-get install -y libdbus-1-dev pkg-config"
	$(MAKE) remote-setup APP=ble-bridge FEATURES=bluez
	@echo "$(GREEN)BLE bridge service installed with BlueZ support$(NC)"

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
