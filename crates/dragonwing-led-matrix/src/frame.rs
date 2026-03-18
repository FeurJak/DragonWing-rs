// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Frame types for the LED matrix.

use crate::{MATRIX_COLS, MATRIX_ROWS, NUM_LEDS};

/// A binary (on/off) frame for the LED matrix.
///
/// The frame data is packed as 4 x 32-bit words (128 bits total),
/// where each bit represents one LED. Only the first 104 bits are used.
///
/// # Bit Layout
///
/// The bits are arranged in row-major order:
/// - Word 0: LEDs 0-31 (rows 0-2, partial row 3)
/// - Word 1: LEDs 32-63 (partial row 3, rows 4-5, partial row 6)
/// - Word 2: LEDs 64-95 (partial row 6, rows 7, and remaining)
/// - Word 3: LEDs 96-103 (only lower 8 bits used)
///
/// # Example
///
/// ```
/// use dragonwing_led_matrix::Frame;
///
/// // Create a frame with all LEDs off
/// let frame = Frame::new([0, 0, 0, 0]);
///
/// // Create a frame with all LEDs on
/// let frame = Frame::all_on();
///
/// // Create a frame from a bitmap
/// let bitmap: [[u8; 13]; 8] = [[0; 13]; 8];
/// let frame = Frame::from_bitmap(&bitmap);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Frame {
    /// Packed LED data (4 x 32-bit words)
    pub data: [u32; 4],
}

impl Frame {
    /// Create a new frame from raw packed data.
    ///
    /// # Arguments
    ///
    /// * `data` - Array of 4 x 32-bit words containing packed LED states
    pub const fn new(data: [u32; 4]) -> Self {
        Self { data }
    }

    /// Create a frame with all LEDs off.
    pub const fn all_off() -> Self {
        Self { data: [0, 0, 0, 0] }
    }

    /// Create a frame with all LEDs on.
    pub const fn all_on() -> Self {
        Self {
            data: [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x000000FF],
        }
    }

    /// Create a frame from an 8x13 bitmap.
    ///
    /// # Arguments
    ///
    /// * `bitmap` - 8 rows x 13 columns, where non-zero values mean LED on
    ///
    /// # Example
    ///
    /// ```
    /// use dragonwing_led_matrix::Frame;
    ///
    /// let mut bitmap = [[0u8; 13]; 8];
    /// // Draw a diagonal line
    /// for i in 0..8 {
    ///     bitmap[i][i] = 1;
    /// }
    /// let frame = Frame::from_bitmap(&bitmap);
    /// ```
    pub fn from_bitmap(bitmap: &[[u8; MATRIX_COLS]; MATRIX_ROWS]) -> Self {
        let mut data = [0u32; 4];
        let mut bit_index = 0usize;

        for row in 0..MATRIX_ROWS {
            for col in 0..MATRIX_COLS {
                if bitmap[row][col] != 0 {
                    let word_index = bit_index / 32;
                    let bit_offset = bit_index % 32;
                    data[word_index] |= 1 << (31 - bit_offset);
                }
                bit_index += 1;
            }
        }

        Self { data }
    }

    /// Get the state of a specific LED.
    ///
    /// # Arguments
    ///
    /// * `row` - Row index (0-7)
    /// * `col` - Column index (0-12)
    ///
    /// # Returns
    ///
    /// `true` if the LED is on, `false` if off
    pub fn get(&self, row: usize, col: usize) -> bool {
        if row >= MATRIX_ROWS || col >= MATRIX_COLS {
            return false;
        }

        let bit_index = row * MATRIX_COLS + col;
        let word_index = bit_index / 32;
        let bit_offset = bit_index % 32;

        (self.data[word_index] & (1 << (31 - bit_offset))) != 0
    }

    /// Set the state of a specific LED.
    ///
    /// # Arguments
    ///
    /// * `row` - Row index (0-7)
    /// * `col` - Column index (0-12)
    /// * `on` - `true` to turn LED on, `false` to turn off
    pub fn set(&mut self, row: usize, col: usize, on: bool) {
        if row >= MATRIX_ROWS || col >= MATRIX_COLS {
            return;
        }

        let bit_index = row * MATRIX_COLS + col;
        let word_index = bit_index / 32;
        let bit_offset = bit_index % 32;

        if on {
            self.data[word_index] |= 1 << (31 - bit_offset);
        } else {
            self.data[word_index] &= !(1 << (31 - bit_offset));
        }
    }

    /// Clear the frame (turn off all LEDs).
    pub fn clear(&mut self) {
        self.data = [0, 0, 0, 0];
    }

    /// Fill the frame (turn on all LEDs).
    pub fn fill(&mut self) {
        self.data = [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x000000FF];
    }
}

impl Default for Frame {
    fn default() -> Self {
        Self::all_off()
    }
}

/// A grayscale frame for the LED matrix.
///
/// Each LED has an independent brightness value. The range depends on
/// the grayscale bits setting (typically 0-7 for 3 bits or 0-255 for 8 bits).
///
/// # Example
///
/// ```
/// use dragonwing_led_matrix::GrayscaleFrame;
///
/// // Create a frame with all LEDs at half brightness (for 3-bit mode)
/// let frame = GrayscaleFrame::new([4; 104]);
///
/// // Create a gradient
/// let mut frame = GrayscaleFrame::default();
/// for row in 0..8 {
///     for col in 0..13 {
///         frame.set(row, col, row as u8);
///     }
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct GrayscaleFrame {
    /// Brightness value for each LED (104 values)
    pub data: [u8; NUM_LEDS],
}

impl GrayscaleFrame {
    /// Create a new grayscale frame from raw data.
    ///
    /// # Arguments
    ///
    /// * `data` - Array of 104 brightness values
    pub const fn new(data: [u8; NUM_LEDS]) -> Self {
        Self { data }
    }

    /// Create a frame with all LEDs off (brightness 0).
    pub const fn all_off() -> Self {
        Self {
            data: [0; NUM_LEDS],
        }
    }

    /// Create a frame with all LEDs at maximum brightness.
    ///
    /// Note: The actual brightness depends on the grayscale bits setting.
    /// For 3-bit mode, use `all_on_3bit()` instead.
    pub const fn all_on() -> Self {
        Self {
            data: [255; NUM_LEDS],
        }
    }

    /// Create a frame with all LEDs at maximum brightness for 3-bit mode (value 7).
    pub const fn all_on_3bit() -> Self {
        Self {
            data: [7; NUM_LEDS],
        }
    }

    /// Get the brightness of a specific LED.
    ///
    /// # Arguments
    ///
    /// * `row` - Row index (0-7)
    /// * `col` - Column index (0-12)
    ///
    /// # Returns
    ///
    /// The brightness value of the LED
    pub fn get(&self, row: usize, col: usize) -> u8 {
        if row >= MATRIX_ROWS || col >= MATRIX_COLS {
            return 0;
        }
        self.data[row * MATRIX_COLS + col]
    }

    /// Set the brightness of a specific LED.
    ///
    /// # Arguments
    ///
    /// * `row` - Row index (0-7)
    /// * `col` - Column index (0-12)
    /// * `brightness` - Brightness value (range depends on grayscale bits)
    pub fn set(&mut self, row: usize, col: usize, brightness: u8) {
        if row >= MATRIX_ROWS || col >= MATRIX_COLS {
            return;
        }
        self.data[row * MATRIX_COLS + col] = brightness;
    }

    /// Clear the frame (set all LEDs to brightness 0).
    pub fn clear(&mut self) {
        self.data = [0; NUM_LEDS];
    }

    /// Fill the frame with a uniform brightness.
    ///
    /// # Arguments
    ///
    /// * `brightness` - Brightness value for all LEDs
    pub fn fill(&mut self, brightness: u8) {
        self.data = [brightness; NUM_LEDS];
    }

    /// Create a grayscale frame from an 8x13 bitmap.
    ///
    /// # Arguments
    ///
    /// * `bitmap` - 8 rows x 13 columns of brightness values
    pub fn from_bitmap(bitmap: &[[u8; MATRIX_COLS]; MATRIX_ROWS]) -> Self {
        let mut data = [0u8; NUM_LEDS];

        for row in 0..MATRIX_ROWS {
            for col in 0..MATRIX_COLS {
                data[row * MATRIX_COLS + col] = bitmap[row][col];
            }
        }

        Self { data }
    }
}

impl Default for GrayscaleFrame {
    fn default() -> Self {
        Self::all_off()
    }
}

/// Convert a binary frame to a grayscale frame.
///
/// On LEDs become the specified brightness, off LEDs become 0.
impl From<&Frame> for GrayscaleFrame {
    fn from(frame: &Frame) -> Self {
        let mut data = [0u8; NUM_LEDS];

        for i in 0..NUM_LEDS {
            let word_index = i / 32;
            let bit_offset = i % 32;
            if (frame.data[word_index] & (1 << (31 - bit_offset))) != 0 {
                data[i] = 7; // Max brightness for 3-bit mode
            }
        }

        Self { data }
    }
}
