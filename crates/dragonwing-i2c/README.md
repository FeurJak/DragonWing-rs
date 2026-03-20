# dragonwing-i2c

I2C (Wire) driver for Arduino Uno Q using Zephyr RTOS.

## Overview

This crate provides I2C master functionality for the Arduino Uno Q board, implementing the `embedded-hal` I2C traits for compatibility with the embedded Rust ecosystem.

## Hardware

The Arduino Uno Q has two I2C buses:

| Bus | Zephyr | Arduino | Pins | Description |
|-----|--------|---------|------|-------------|
| Wire | I2C2 | Bus 0 | SDA=PB11 (D20), SCL=PB10 (D21) | Arduino header pins |
| Wire1 | I2C4 | Bus 1 | SDA=PD13, SCL=PD12 | Camera/internal connector |

## Features

- **embedded-hal 1.0 compatible**: Works with drivers like `ssd1306`, `bme280`, etc.
- **Multiple bus support**: Wire (I2C2) and Wire1 (I2C4)
- **Configurable speed**: Standard (100kHz), Fast (400kHz), Fast Plus (1MHz)
- **Bus scanning**: Find devices on the bus
- **no_std**: Works in embedded environments

## Usage

```rust
use dragonwing_i2c::{I2c, I2cBus, I2cSpeed};
use embedded_hal::i2c::I2c as I2cTrait;

// Create and initialize I2C on Wire bus
let mut i2c = I2c::new(I2cBus::Wire);
i2c.init().unwrap();
i2c.set_speed(I2cSpeed::Fast).unwrap();

// Scan for devices
let devices = i2c.scan();
for addr in devices.iter() {
    println!("Found device at 0x{:02X}", addr);
}

// Use with ssd1306 display driver
use ssd1306::{prelude::*, I2CDisplayInterface, Ssd1306};

let interface = I2CDisplayInterface::new(i2c);
let mut display = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate0)
    .into_buffered_graphics_mode();
display.init().unwrap();
```

## Zephyr Configuration

Enable I2C in your `prj.conf`:

```
CONFIG_I2C=y
```

Enable the I2C bus in your board overlay:

```dts
&i2c2 {
    status = "okay";
    clock-frequency = <I2C_BITRATE_FAST>;
};
```

## Building

The dragonwing-i2c crate requires Zephyr RTOS. Build MCU demos with:

```bash
make build-mcu DEMO=ssd1306-demo
```

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
