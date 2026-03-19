# dragonwing-spi

Cross-platform SPI communication library for Arduino Uno Q.

## Target

- **MCU** (feature = `mcu`): STM32U585 as SPI peripheral (slave), no_std
- **MPU** (feature = `mpu`): QRB2210 Linux as SPI controller (master), std

## Features

- Framed protocol with magic header and length fields
- Configurable transfer buffers (default: 16KB for camera streaming)
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
|   2 bytes       |    2 bytes     |  0-16380 bytes   |
+--------+--------+--------+--------+------------------+
```

## Linux SPI Buffer Configuration

The Linux spidev driver has a default buffer size limit of **4096 bytes**. For applications 
that need larger transfers (e.g., camera JPEG frames which are typically 5-15KB), you must 
increase this limit.

### Check Current Buffer Size

```bash
cat /sys/module/spidev/parameters/bufsiz
# Default: 4096
```

### Configure Larger Buffer (Persistent)

On Arduino Uno Q (systemd-boot), add the kernel parameter to increase the buffer:

1. Edit `/etc/kernel/cmdline`:
   ```bash
   sudo nano /etc/kernel/cmdline
   ```

2. Add `spidev.bufsiz=16384` to the existing parameters:
   ```
   root=UUID=... clk_ignore_unused pd_ignore_unused audit=0 deferred_probe_timeout=30 spidev.bufsiz=16384
   ```

3. Regenerate boot entry:
   ```bash
   sudo kernel-install add $(uname -r) /boot/vmlinuz-$(uname -r) /boot/initrd.img-$(uname -r)
   ```

4. Reboot and verify:
   ```bash
   sudo reboot
   # After reboot:
   cat /sys/module/spidev/parameters/bufsiz
   # Should show: 16384
   ```

### Automated Setup

Use the provided setup script:

```bash
./scripts/setup-spi-buffer.sh 16384
```

### Why 16KB?

- Camera JPEG frames: typically 5-15KB
- With 4-byte header overhead, 16KB buffer supports frames up to ~16380 bytes
- Larger buffers increase memory usage but reduce fragmentation overhead

## Documentation

See [docs/rpc-protocol.md](../../docs/rpc-protocol.md) for protocol details.

## License

Apache-2.0 OR MIT
