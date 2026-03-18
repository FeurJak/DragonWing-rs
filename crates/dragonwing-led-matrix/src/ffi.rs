// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// FFI bindings to the Zephyr LED matrix C functions.
//
// These functions are implemented in c/matrix.c and provide
// low-level access to the charlieplexed LED matrix hardware.

extern "C" {
    /// Initialize the LED matrix driver.
    ///
    /// This starts the TIM17 counter that drives the charlieplexing
    /// multiplexer at a high frequency.
    pub fn matrixBegin();

    /// Stop the LED matrix driver.
    ///
    /// This stops the timer and turns off all LEDs.
    pub fn matrixEnd();

    /// Set the maximum grayscale bits.
    ///
    /// # Arguments
    ///
    /// * `max` - The number of bits used for grayscale values.
    ///           Typically 3 (0-7) or 8 (0-255).
    pub fn matrixSetGrayscaleBits(max: u8);

    /// Write a grayscale frame to the matrix.
    ///
    /// # Arguments
    ///
    /// * `buf` - Pointer to 104 bytes, one per LED (brightness value)
    pub fn matrixGrayscaleWrite(buf: *const u8);

    /// Write a binary (on/off) frame to the matrix.
    ///
    /// # Arguments
    ///
    /// * `buf` - Pointer to 4 x u32 (128 bits), packed LED states
    pub fn matrixWrite(buf: *const u32);

    /// Play a grayscale video sequence.
    ///
    /// # Arguments
    ///
    /// * `buf` - Pointer to video data (multiple 104-byte frames)
    /// * `len` - Total length in bytes
    pub fn matrixPlay(buf: *const u8, len: u32);
}
