# Contributing to Arduino Libraries Rust

Thank you for your interest in contributing to Arduino Libraries Rust! This project provides Rust libraries and examples for the Arduino Uno Q board.

## Getting Started

### Prerequisites

- **Rust toolchain**: Install via [rustup](https://rustup.rs/)
- **Docker**: For building MCU firmware
- **cargo-zigbuild**: For cross-compiling Linux apps (`cargo install cargo-zigbuild`)
- **ADB**: For flashing (`brew install android-platform-tools` on macOS)
- **sshpass**: For SSH deployment (`brew install hudochenkov/sshpass/sshpass` on macOS)

### Setting Up Development Environment

1. Clone the repository:
   ```bash
   git clone https://github.com/FeurJak/arduino-libraries-rust.git
   cd arduino-libraries-rust
   ```

2. Build the Docker image (first time only):
   ```bash
   make docker-build
   ```

3. Connect your Arduino Uno Q via USB-C

4. Verify connection:
   ```bash
   adb devices
   ```

## Project Structure

```
arduino-libraries-rust/
├── arduino-led-matrix/      # MCU library: LED matrix control
├── arduino-rpc-bridge/      # MCU library: RPC server/client
├── arduino-cryptography/    # MCU library: Post-quantum crypto
├── arduino-spi-router/      # Linux daemon: SPI-to-socket bridge
├── arduino-rpc-client/      # Linux library: RPC client
├── examples/
│   ├── led-matrix-demo/     # MCU: LED matrix demo
│   ├── rpc-server/          # MCU: RPC server example
│   ├── mlkem-demo/          # MCU: Post-quantum crypto demo
│   ├── weather-display/     # Linux: Weather on LED matrix
│   └── mlkem-client/        # Linux: ML-KEM client
├── docker/                  # Build environment
└── Makefile                 # Build automation
```

## How to Contribute

### Reporting Issues

- Use GitHub Issues to report bugs or request features
- Include:
  - Clear description of the issue
  - Steps to reproduce
  - Expected vs actual behavior
  - Hardware/software versions

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Make your changes
4. Test your changes:
   ```bash
   # For MCU code
   make build APP=<app-name>
   make flash
   
   # For Linux code
   make build-linux APP=<app-name>
   ```
5. Commit with a clear message:
   ```bash
   git commit -m "Add feature: description of changes"
   ```
6. Push and create a Pull Request

### Code Style

- Follow Rust standard formatting (`cargo fmt`)
- Use `cargo clippy` for linting
- Add documentation comments for public APIs
- Include SPDX license headers in new files:
  ```rust
  // SPDX-License-Identifier: Apache-2.0 OR MIT
  ```

### Testing

- Test MCU code on actual hardware when possible
- Test Linux code both natively and on the board
- Add tests for new functionality when applicable

## Areas for Contribution

### Good First Issues

- Documentation improvements
- Code cleanup and refactoring
- Adding examples

### Advanced Contributions

- New hardware peripheral support
- Performance optimizations
- Additional cryptographic algorithms
- Protocol enhancements

## Building and Testing

### MCU Firmware

```bash
# Build
make build APP=rpc-server

# Flash
make flash

# Open Docker shell for debugging
make shell
```

### Linux Applications

```bash
# Build
make build-linux APP=weather-display

# Deploy
make deploy-linux APP=weather-display

# Run
make run-linux APP=weather-display
```

## Communication

- **GitHub Issues**: Bug reports and feature requests
- **Pull Requests**: Code contributions and discussions

## License

By contributing, you agree that your contributions will be licensed under the same dual license as the project: Apache-2.0 OR MIT.

## Code of Conduct

Please be respectful and inclusive in all interactions. We aim to create a welcoming environment for all contributors.

---

Thank you for contributing to Arduino Libraries Rust!
