// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Animation support for the LED matrix.

use crate::Frame;

/// A single frame in an animation sequence.
///
/// Each frame contains the LED data (4 x u32 packed bits) plus a duration
/// in milliseconds indicating how long to display this frame.
///
/// # Example
///
/// ```
/// use dragonwing_led_matrix::AnimationFrame;
///
/// // A frame that displays for 100ms
/// let frame = AnimationFrame {
///     data: [0x12345678, 0x9ABCDEF0, 0x11223344, 0x55667788],
///     duration_ms: 100,
/// };
/// ```
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct AnimationFrame {
    /// Packed LED data (same format as Frame)
    pub data: [u32; 4],
    /// Duration to display this frame in milliseconds
    pub duration_ms: u32,
}

impl AnimationFrame {
    /// Create a new animation frame.
    ///
    /// # Arguments
    ///
    /// * `data` - Packed LED data (4 x u32)
    /// * `duration_ms` - How long to display this frame
    pub const fn new(data: [u32; 4], duration_ms: u32) -> Self {
        Self { data, duration_ms }
    }

    /// Create an animation frame from a Frame with specified duration.
    pub const fn from_frame(frame: Frame, duration_ms: u32) -> Self {
        Self {
            data: frame.data,
            duration_ms,
        }
    }

    /// Get this frame's LED data as a Frame.
    pub const fn to_frame(&self) -> Frame {
        Frame::new(self.data)
    }
}

/// An animation sequence containing multiple frames.
///
/// Animations are typically defined as static data and loaded with
/// `LedMatrix::load_sequence()`.
///
/// # Example
///
/// ```
/// use dragonwing_led_matrix::{Animation, AnimationFrame};
///
/// // Define a simple 2-frame animation
/// static MY_ANIMATION: Animation = Animation::new(&[
///     AnimationFrame::new([0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x000000FF], 500),
///     AnimationFrame::new([0x00000000, 0x00000000, 0x00000000, 0x00000000], 500),
/// ]);
/// ```
pub struct Animation {
    frames: &'static [AnimationFrame],
}

impl Animation {
    /// Create a new animation from a slice of frames.
    ///
    /// # Arguments
    ///
    /// * `frames` - Static slice of animation frames
    pub const fn new(frames: &'static [AnimationFrame]) -> Self {
        Self { frames }
    }

    /// Get the number of frames in this animation.
    pub const fn len(&self) -> usize {
        self.frames.len()
    }

    /// Check if the animation is empty.
    pub const fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Get the frames in this animation.
    pub const fn frames(&self) -> &'static [AnimationFrame] {
        self.frames
    }

    /// Get a specific frame by index.
    ///
    /// Returns `None` if the index is out of bounds.
    pub fn get(&self, index: usize) -> Option<&AnimationFrame> {
        self.frames.get(index)
    }

    /// Calculate the total duration of the animation in milliseconds.
    pub fn total_duration_ms(&self) -> u32 {
        self.frames.iter().map(|f| f.duration_ms).sum()
    }
}

/// Macro to define an animation from raw frame data.
///
/// This macro provides a convenient way to define animations using the
/// same format as the Arduino C library (arrays of 5 u32 values where
/// the 5th value is the duration).
///
/// # Example
///
/// ```
/// use dragonwing_led_matrix::animation;
///
/// animation!(MY_ANIMATION, [
///     [0x38022020, 0x810408a0, 0x2200e800, 0x20000000, 66],
///     [0x1c011010, 0x40820450, 0x11007400, 0x10000000, 66],
///     [0x0e008808, 0x20410228, 0x08803a00, 0x08000000, 66],
/// ]);
/// ```
#[macro_export]
macro_rules! animation {
    ($name:ident, [ $( [$d0:expr, $d1:expr, $d2:expr, $d3:expr, $dur:expr] ),* $(,)? ]) => {
        static $name: $crate::Animation = $crate::Animation::new(&[
            $(
                $crate::AnimationFrame::new([$d0, $d1, $d2, $d3], $dur),
            )*
        ]);
    };
}

/// Pre-defined animations and patterns.
pub mod patterns {
    use super::{Animation, AnimationFrame};

    /// A simple blink animation (all on, then all off).
    pub static BLINK: Animation = Animation::new(&[
        AnimationFrame::new([0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x000000FF], 500),
        AnimationFrame::new([0x00000000, 0x00000000, 0x00000000, 0x00000000], 500),
    ]);

    /// A scrolling line animation.
    pub static SCROLL_LINE: Animation = Animation::new(&[
        AnimationFrame::new([0x00010001, 0x00010001, 0x00010001, 0x00010001], 100),
        AnimationFrame::new([0x00020002, 0x00020002, 0x00020002, 0x00020002], 100),
        AnimationFrame::new([0x00040004, 0x00040004, 0x00040004, 0x00040004], 100),
        AnimationFrame::new([0x00080008, 0x00080008, 0x00080008, 0x00080008], 100),
        AnimationFrame::new([0x00100010, 0x00100010, 0x00100010, 0x00100010], 100),
        AnimationFrame::new([0x00200020, 0x00200020, 0x00200020, 0x00200020], 100),
        AnimationFrame::new([0x00400040, 0x00400040, 0x00400040, 0x00400040], 100),
        AnimationFrame::new([0x00800080, 0x00800080, 0x00800080, 0x00800080], 100),
    ]);

    /// A heart shape (static frame, 0ms duration for display only).
    pub static HEART: Animation = Animation::new(&[AnimationFrame::new(
        [0x00000630, 0x0F90108, 0x20040088, 0x01100000],
        0,
    )]);

    /// A smiley face (static frame).
    pub static SMILEY: Animation = Animation::new(&[AnimationFrame::new(
        [0x00000000, 0x24000024, 0x00000000, 0x42003C00],
        0,
    )]);
}
