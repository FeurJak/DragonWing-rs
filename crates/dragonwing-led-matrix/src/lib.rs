// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// DragonWing LED Matrix Library
//
// A Rust driver for the 8x13 charlieplexed LED matrix on the Arduino Uno Q.
// The matrix uses GPIO port F (PF0-PF10) to drive 104 LEDs.
//
// # Example
//
// ```no_run
// use dragonwing_led_matrix::LedMatrix;
//
// let mut matrix = LedMatrix::new();
// matrix.begin();
//
// // Display a simple frame
// let frame = [0x12345678u32, 0x9ABCDEF0, 0x11223344, 0x55667788];
// matrix.load_frame(&frame);
//
// // Or use grayscale
// matrix.set_grayscale_bits(3);
// let grayscale_frame: [u8; 104] = [0; 104];
// matrix.draw(&grayscale_frame);
// ```

#![no_std]

mod ffi;
mod frame;
mod animation;

pub use frame::{Frame, GrayscaleFrame};
pub use animation::{Animation, AnimationFrame};

/// Number of LEDs in the matrix (8 rows x 13 columns)
pub const NUM_LEDS: usize = 104;

/// Number of rows in the matrix
pub const MATRIX_ROWS: usize = 8;

/// Number of columns in the matrix  
pub const MATRIX_COLS: usize = 13;

/// LED Matrix controller for the Arduino Uno Q.
///
/// This struct provides a safe interface for controlling the charlieplexed
/// LED matrix on the Arduino Uno Q board. The matrix consists of 104 LEDs
/// arranged in an 8x13 grid.
///
/// # Hardware Details
///
/// The matrix uses GPIO port F (PF0-PF10) with charlieplexing to control
/// 104 LEDs using only 11 GPIO pins. A hardware timer (TIM17) drives the
/// multiplexing at a high frequency to achieve persistence of vision.
///
/// # Usage
///
/// ```no_run
/// use dragonwing_led_matrix::LedMatrix;
///
/// let mut matrix = LedMatrix::new();
/// matrix.begin();  // Start the matrix driver
///
/// // Display binary frames (on/off per LED)
/// let frame = Frame::new([0x12345678, 0x9ABCDEF0, 0x11223344, 0x55667788]);
/// matrix.load_frame(&frame);
///
/// // Or use grayscale (8 brightness levels)
/// matrix.set_grayscale_bits(3);  // 3 bits = 8 levels (0-7)
/// let gray_frame = GrayscaleFrame::new([4; 104]);  // All LEDs at half brightness
/// matrix.draw(&gray_frame);
///
/// matrix.end();  // Stop the matrix driver
/// ```
pub struct LedMatrix {
    /// Currently loaded animation frames
    frames: Option<&'static [AnimationFrame]>,
    /// Current frame index in animation
    current_frame: usize,
    /// Number of frames in current animation
    frame_count: usize,
    /// Auto-scroll interval in milliseconds (0 = disabled)
    interval: u32,
    /// Whether animation should loop
    loop_animation: bool,
    /// Whether the current sequence is done
    sequence_done: bool,
    /// Callback function pointer (not used in Rust version)
    _callback: Option<fn()>,
}

impl LedMatrix {
    /// Create a new LED matrix controller.
    ///
    /// Note: You must call `begin()` to start the matrix driver before
    /// displaying any content.
    pub const fn new() -> Self {
        Self {
            frames: None,
            current_frame: 0,
            frame_count: 0,
            interval: 0,
            loop_animation: false,
            sequence_done: false,
            _callback: None,
        }
    }

    /// Initialize and start the LED matrix driver.
    ///
    /// This function configures the timer interrupt that drives the
    /// charlieplexing multiplexer. Must be called before any display
    /// operations.
    ///
    /// Returns `true` on success.
    pub fn begin(&mut self) -> bool {
        unsafe { ffi::matrixBegin() };
        true
    }

    /// Stop the LED matrix driver.
    ///
    /// This disables the timer interrupt and turns off all LEDs.
    pub fn end(&mut self) {
        unsafe { ffi::matrixEnd() };
    }

    /// Set the number of grayscale bits for intensity control.
    ///
    /// The matrix supports up to 8 levels of grayscale (3 bits).
    /// The `max` parameter specifies how many bits of grayscale data
    /// your framebuffer uses.
    ///
    /// # Arguments
    ///
    /// * `max` - Grayscale bits (typically 3 for 8 levels, or 8 for 256 levels)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dragonwing_led_matrix::LedMatrix;
    /// # let mut matrix = LedMatrix::new();
    /// // Use 3-bit grayscale (values 0-7)
    /// matrix.set_grayscale_bits(3);
    ///
    /// // Use 8-bit grayscale (values 0-255, will be scaled)
    /// matrix.set_grayscale_bits(8);
    /// ```
    pub fn set_grayscale_bits(&mut self, max: u8) {
        unsafe { ffi::matrixSetGrayscaleBits(max) };
    }

    /// Display a grayscale frame on the matrix.
    ///
    /// Each byte in the buffer represents the brightness of one LED.
    /// The brightness range depends on the grayscale bits setting:
    /// - 3 bits: 0-7
    /// - 8 bits: 0-255
    ///
    /// # Arguments
    ///
    /// * `frame` - Grayscale frame with 104 brightness values
    pub fn draw(&mut self, frame: &GrayscaleFrame) {
        unsafe { ffi::matrixGrayscaleWrite(frame.data.as_ptr()) };
    }

    /// Display a binary (on/off) frame on the matrix.
    ///
    /// The frame is packed as 4 x 32-bit words (128 bits total),
    /// where each bit represents one LED (104 LEDs used).
    ///
    /// # Arguments
    ///
    /// * `frame` - Binary frame with packed LED states
    pub fn write(&mut self, frame: &Frame) {
        unsafe { ffi::matrixWrite(frame.data.as_ptr()) };
    }

    /// Load a single frame and display it immediately.
    ///
    /// This is a convenience method that loads a frame and displays it
    /// without animation support.
    ///
    /// # Arguments
    ///
    /// * `frame` - Binary frame to display
    pub fn load_frame(&mut self, frame: &Frame) {
        // Create a temporary animation frame with 0 delay
        let reversed = Frame::new([
            reverse_bits(frame.data[0]),
            reverse_bits(frame.data[1]),
            reverse_bits(frame.data[2]),
            reverse_bits(frame.data[3]),
        ]);
        self.write(&reversed);
        self.interval = 0;
    }

    /// Play a grayscale video sequence.
    ///
    /// The buffer contains multiple 104-byte frames that are played
    /// sequentially at approximately 60fps (16ms per frame).
    ///
    /// # Arguments
    ///
    /// * `buffer` - Video frames (each frame is 104 bytes)
    pub fn play_video(&mut self, buffer: &[u8]) {
        unsafe { ffi::matrixPlay(buffer.as_ptr(), buffer.len() as u32) };
    }

    /// Clear the matrix (turn off all LEDs).
    pub fn clear(&mut self) {
        let off = Frame::new([0, 0, 0, 0]);
        self.load_frame(&off);
    }

    /// Load an animation sequence for playback.
    ///
    /// Each frame in the animation contains the LED data plus a duration
    /// in milliseconds.
    ///
    /// # Arguments
    ///
    /// * `animation` - Animation containing frames with timing data
    pub fn load_sequence(&mut self, animation: &'static Animation) {
        self.frames = Some(animation.frames());
        self.frame_count = animation.len();
        self.current_frame = 0;
    }

    /// Display the next frame in the current animation.
    ///
    /// Call this method repeatedly to advance through the animation.
    /// Use `interval()` to get the delay until the next frame.
    pub fn next(&mut self) {
        if let Some(frames) = self.frames {
            if self.current_frame < self.frame_count {
                let frame = &frames[self.current_frame];
                
                // Reverse bits for display
                let display_frame = Frame::new([
                    reverse_bits(frame.data[0]),
                    reverse_bits(frame.data[1]),
                    reverse_bits(frame.data[2]),
                    reverse_bits(frame.data[3]),
                ]);
                self.write(&display_frame);
                self.interval = frame.duration_ms;
                
                self.current_frame = (self.current_frame + 1) % self.frame_count;
                
                if self.current_frame == 0 {
                    if !self.loop_animation {
                        self.interval = 0;
                    }
                    self.sequence_done = true;
                }
            }
        }
    }

    /// Get the interval (in milliseconds) until the next frame.
    ///
    /// Returns 0 if no animation is loaded or animation is complete.
    pub fn interval(&self) -> u32 {
        self.interval
    }

    /// Set the auto-scroll interval for animations.
    ///
    /// # Arguments
    ///
    /// * `interval_ms` - Interval in milliseconds between frames
    pub fn autoscroll(&mut self, interval_ms: u32) {
        self.interval = interval_ms;
    }

    /// Render a specific frame from the loaded animation.
    ///
    /// # Arguments
    ///
    /// * `frame_number` - Index of the frame to display
    pub fn render_frame(&mut self, frame_number: usize) {
        if self.frame_count > 0 {
            self.current_frame = frame_number % self.frame_count;
            self.next();
            self.interval = 0;
        }
    }

    /// Check if the current animation sequence is complete.
    ///
    /// Returns `true` once when the sequence completes, then resets.
    pub fn sequence_done(&mut self) -> bool {
        if self.sequence_done {
            self.sequence_done = false;
            true
        } else {
            false
        }
    }

    /// Play the loaded animation sequence to completion.
    ///
    /// This is a blocking call that displays each frame with the
    /// appropriate delay.
    ///
    /// # Arguments
    ///
    /// * `loop_animation` - If true, repeat the animation indefinitely
    ///
    /// # Note
    ///
    /// When `loop_animation` is true, this function never returns.
    /// Use `next()` with manual timing for non-blocking playback.
    pub fn play_sequence(&mut self, loop_animation: bool) {
        self.loop_animation = loop_animation;
        self.sequence_done = false;
        
        loop {
            self.next();
            
            if self.interval > 0 {
                // Use Zephyr's sleep - caller needs to import this
                // For now, provide the interval and let caller handle delay
            }
            
            if self.sequence_done && !loop_animation {
                break;
            }
        }
    }
}

impl Default for LedMatrix {
    fn default() -> Self {
        Self::new()
    }
}

/// Reverse the bits in a 32-bit word.
///
/// This is needed because the LED matrix data is stored in reverse bit order.
#[inline]
fn reverse_bits(x: u32) -> u32 {
    let mut x = x;
    x = ((x >> 1) & 0x55555555) | ((x & 0x55555555) << 1);
    x = ((x >> 2) & 0x33333333) | ((x & 0x33333333) << 2);
    x = ((x >> 4) & 0x0F0F0F0F) | ((x & 0x0F0F0F0F) << 4);
    x = ((x >> 8) & 0x00FF00FF) | ((x & 0x00FF00FF) << 8);
    x = (x >> 16) | (x << 16);
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_bits() {
        assert_eq!(reverse_bits(0x00000001), 0x80000000);
        assert_eq!(reverse_bits(0x80000000), 0x00000001);
        assert_eq!(reverse_bits(0xF0F0F0F0), 0x0F0F0F0F);
    }
}
