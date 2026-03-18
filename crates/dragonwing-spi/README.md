# dragonwing-spi

Cross-platform SPI communication library for Arduino Uno Q.

## Target

- **MCU** (feature = `mcu`): STM32U585 as SPI peripheral (slave), no_std
- **MPU** (feature = `mpu`): QRB2210 Linux as SPI controller (master), std

## Features

- Framed protocol with magic header and length fields
- 512-byte transfer buffers
- MCU: Zephyr SPI peripheral driver (C FFI)
- MPU: Linux spidev interface

## Quick Start

### MCU (peripheral/slave)

```toml
[dependencies]
dragonwing-spi = { version = "0.1", features = ["mcu"] }
```

### MPU (controller/master)

```toml
[dependencies]
dragonwing-spi = { version = "0.1", features = ["mpu"] }
```

## Frame Format

```text
+--------+--------+--------+--------+------------------+
| Magic (0xAA55)  |    Length      |     Payload      |
|   2 bytes       |    2 bytes     |   0-508 bytes    |
+--------+--------+--------+--------+------------------+
```

## Documentation

See [docs/rpc-protocol.md](../../docs/rpc-protocol.md) for protocol details.

## License

Apache-2.0 OR MIT
