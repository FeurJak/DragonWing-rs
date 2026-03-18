# dragonwing-led-matrix

8x13 LED matrix driver for the Arduino Uno Q.

## Requirements

- **MCU only** - This crate runs on the STM32U585 microcontroller
- **no_std** - No standard library support
- **Zephyr RTOS** - Requires Zephyr kernel and GPIO drivers

## Hardware

The Arduino Uno Q features a 104-LED charlieplexed matrix (8 rows x 13 columns)
driven through GPIO port F (PF0-PF10) using only 11 pins.

## Usage

```rust
use dragonwing_led_matrix::{LedMatrix, Frame};

let mut matrix = LedMatrix::new();
matrix.begin();

// Display a binary frame
let frame = Frame::new([0x12345678, 0x9ABCDEF0, 0x11223344, 0x55667788]);
matrix.load_frame(&frame);

// Or use grayscale (8 brightness levels)
matrix.set_grayscale_bits(3);
```

## C Driver

The `c/matrix.c` file contains the low-level charlieplexing driver that must
be compiled with your Zephyr application. It provides the FFI functions called
by this Rust crate.

## License

Apache-2.0 OR MIT
