// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// DragonWing zcbor - Rust wrapper for Zephyr's zcbor CBOR library
//
// This library provides safe Rust bindings to zcbor, a low-footprint
// CBOR encoder/decoder designed for microcontrollers.
//
// # Features
//
// - Zero-copy decoding (strings point directly into payload)
// - Low memory footprint
// - Full CBOR support (integers, strings, arrays, maps, tags)
// - Optional COSE_Sign1 support with ML-DSA
//
// # Example
//
// ```rust,no_run
// use dragonwing_zcbor::{Encoder, Decoder};
//
// // Encoding
// let mut buf = [0u8; 64];
// let mut enc = Encoder::new(&mut buf);
// enc.array(3).unwrap();
// enc.u32(1).unwrap();
// enc.u32(2).unwrap();
// enc.str("hello").unwrap();
// let encoded = enc.finish();
//
// // Decoding
// let mut dec = Decoder::new(encoded);
// let len = dec.array().unwrap();
// let a = dec.u32().unwrap();
// let b = dec.u32().unwrap();
// let s = dec.str().unwrap();
// ```
//
// # Setup
//
// Enable zcbor in your `prj.conf`:
// ```
// CONFIG_ZCBOR=y
// ```

#![no_std]
#![allow(unexpected_cfgs)]

mod ffi;

#[cfg(feature = "cose")]
pub mod cose;

use core::mem::MaybeUninit;

/// Error type for zcbor operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No more space in output buffer
    NoPayload,
    /// Payload not fully consumed
    PayloadNotConsumed,
    /// Wrong CBOR type
    WrongType,
    /// Wrong value
    WrongValue,
    /// Value out of range
    WrongRange,
    /// Integer too large for target type
    IntSize,
    /// Unknown zcbor error
    Unknown(i32),
}

impl From<i32> for Error {
    fn from(code: i32) -> Self {
        match code {
            ffi::ZCBOR_SUCCESS => panic!("Cannot convert success to error"),
            ffi::ZCBOR_ERR_NO_PAYLOAD => Error::NoPayload,
            ffi::ZCBOR_ERR_PAYLOAD_NOT_CONSUMED => Error::PayloadNotConsumed,
            ffi::ZCBOR_ERR_WRONG_TYPE => Error::WrongType,
            ffi::ZCBOR_ERR_WRONG_VALUE => Error::WrongValue,
            ffi::ZCBOR_ERR_WRONG_RANGE => Error::WrongRange,
            ffi::ZCBOR_ERR_INT_SIZE => Error::IntSize,
            code => Error::Unknown(code),
        }
    }
}

/// Result type for zcbor operations
pub type Result<T> = core::result::Result<T, Error>;

/// Number of backup states to allocate
const NUM_BACKUPS: usize = 4;

/// Total states needed (backups + 2 for state + constant_state)
const TOTAL_STATES: usize = NUM_BACKUPS + 2;

/// CBOR Encoder
///
/// Encodes Rust values to CBOR format using zcbor.
pub struct Encoder<'a> {
    states: [MaybeUninit<ffi::ZcborState>; TOTAL_STATES],
    buf: &'a mut [u8],
    start: *const u8,
}

impl<'a> Encoder<'a> {
    /// Create a new encoder writing to the provided buffer
    pub fn new(buf: &'a mut [u8]) -> Self {
        let mut encoder = Self {
            states: unsafe { MaybeUninit::uninit().assume_init() },
            start: buf.as_ptr(),
            buf,
        };

        unsafe {
            ffi::zcbor_new_encode_state(
                encoder.states[0].as_mut_ptr(),
                TOTAL_STATES,
                encoder.buf.as_mut_ptr(),
                encoder.buf.len(),
                1, // elem_count
            );
        }

        encoder
    }

    /// Get pointer to state
    fn state(&mut self) -> *mut ffi::ZcborState {
        self.states[0].as_mut_ptr()
    }

    /// Pop and clear the error from state (inline implementation of zcbor_pop_error)
    fn pop_error(&mut self) -> i32 {
        unsafe {
            let state = &mut *self.state();
            if state.constant_state.is_null() {
                return ffi::ZCBOR_SUCCESS;
            }
            let cs = &mut *state.constant_state;
            let err = cs.error;
            cs.error = ffi::ZCBOR_SUCCESS;
            err
        }
    }

    /// Check for errors after an operation
    fn check(&mut self, ok: bool) -> Result<()> {
        if ok {
            Ok(())
        } else {
            let err = self.pop_error();
            Err(Error::from(err))
        }
    }

    /// Encode a signed 32-bit integer
    pub fn i32(&mut self, value: i32) -> Result<()> {
        let ok = unsafe { ffi::zcbor_int32_put(self.state(), value) };
        self.check(ok)
    }

    /// Encode an unsigned 32-bit integer
    pub fn u32(&mut self, value: u32) -> Result<()> {
        let ok = unsafe { ffi::zcbor_uint32_put(self.state(), value) };
        self.check(ok)
    }

    /// Encode a signed 64-bit integer
    pub fn i64(&mut self, value: i64) -> Result<()> {
        let ok = unsafe { ffi::zcbor_int64_put(self.state(), value) };
        self.check(ok)
    }

    /// Encode an unsigned 64-bit integer
    pub fn u64(&mut self, value: u64) -> Result<()> {
        let ok = unsafe { ffi::zcbor_uint64_put(self.state(), value) };
        self.check(ok)
    }

    /// Encode a boolean
    pub fn bool(&mut self, value: bool) -> Result<()> {
        let ok = unsafe { ffi::zcbor_bool_put(self.state(), value) };
        self.check(ok)
    }

    /// Encode null
    pub fn null(&mut self) -> Result<()> {
        let ok = unsafe { ffi::zcbor_nil_put(self.state(), core::ptr::null()) };
        self.check(ok)
    }

    /// Encode a byte string
    pub fn bytes(&mut self, value: &[u8]) -> Result<()> {
        let ok = unsafe { ffi::zcbor_bstr_encode_ptr(self.state(), value.as_ptr(), value.len()) };
        self.check(ok)
    }

    /// Encode a text string
    pub fn str(&mut self, value: &str) -> Result<()> {
        let ok = unsafe { ffi::zcbor_tstr_encode_ptr(self.state(), value.as_ptr(), value.len()) };
        self.check(ok)
    }

    /// Start encoding an array with the given maximum number of elements
    pub fn array(&mut self, max_len: usize) -> Result<()> {
        let ok = unsafe { ffi::zcbor_list_start_encode(self.state(), max_len) };
        self.check(ok)
    }

    /// End encoding an array
    pub fn end_array(&mut self, max_len: usize) -> Result<()> {
        let ok = unsafe { ffi::zcbor_list_end_encode(self.state(), max_len) };
        self.check(ok)
    }

    /// Start encoding a map with the given maximum number of key-value pairs
    pub fn map(&mut self, max_len: usize) -> Result<()> {
        let ok = unsafe { ffi::zcbor_map_start_encode(self.state(), max_len) };
        self.check(ok)
    }

    /// End encoding a map
    pub fn end_map(&mut self, max_len: usize) -> Result<()> {
        let ok = unsafe { ffi::zcbor_map_end_encode(self.state(), max_len) };
        self.check(ok)
    }

    /// Encode a CBOR tag
    pub fn tag(&mut self, tag: u32) -> Result<()> {
        let ok = unsafe { ffi::zcbor_tag_put(self.state(), tag) };
        self.check(ok)
    }

    /// Finish encoding and return the encoded bytes
    pub fn finish(self) -> &'a [u8] {
        let state = unsafe { &*self.states[0].as_ptr() };
        let len = state.payload as usize - self.start as usize;
        &self.buf[..len]
    }

    /// Get the number of bytes written so far
    pub fn bytes_written(&self) -> usize {
        let state = unsafe { &*self.states[0].as_ptr() };
        state.payload as usize - self.start as usize
    }
}

/// CBOR Decoder
///
/// Decodes CBOR data to Rust values using zcbor.
pub struct Decoder<'a> {
    states: [MaybeUninit<ffi::ZcborState>; TOTAL_STATES],
    _phantom: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> Decoder<'a> {
    /// Create a new decoder for the provided CBOR data
    pub fn new(data: &'a [u8]) -> Self {
        let mut decoder = Self {
            states: unsafe { MaybeUninit::uninit().assume_init() },
            _phantom: core::marker::PhantomData,
        };

        unsafe {
            ffi::zcbor_new_decode_state(
                decoder.states[0].as_mut_ptr(),
                TOTAL_STATES,
                data.as_ptr(),
                data.len(),
                1,                     // elem_count
                core::ptr::null_mut(), // elem_state
                0,                     // elem_state_bytes
            );
        }

        decoder
    }

    /// Get pointer to state
    fn state(&mut self) -> *mut ffi::ZcborState {
        self.states[0].as_mut_ptr()
    }

    /// Pop and clear the error from state (inline implementation of zcbor_pop_error)
    fn pop_error(&mut self) -> i32 {
        unsafe {
            let state = &mut *self.state();
            if state.constant_state.is_null() {
                return ffi::ZCBOR_SUCCESS;
            }
            let cs = &mut *state.constant_state;
            let err = cs.error;
            cs.error = ffi::ZCBOR_SUCCESS;
            err
        }
    }

    /// Check for errors after an operation
    fn check<T>(&mut self, ok: bool, value: T) -> Result<T> {
        if ok {
            Ok(value)
        } else {
            let err = self.pop_error();
            Err(Error::from(err))
        }
    }

    /// Decode a signed 32-bit integer
    pub fn i32(&mut self) -> Result<i32> {
        let mut value = 0i32;
        let ok = unsafe { ffi::zcbor_int32_decode(self.state(), &mut value) };
        self.check(ok, value)
    }

    /// Decode an unsigned 32-bit integer
    pub fn u32(&mut self) -> Result<u32> {
        let mut value = 0u32;
        let ok = unsafe { ffi::zcbor_uint32_decode(self.state(), &mut value) };
        self.check(ok, value)
    }

    /// Decode a signed 64-bit integer
    pub fn i64(&mut self) -> Result<i64> {
        let mut value = 0i64;
        let ok = unsafe { ffi::zcbor_int64_decode(self.state(), &mut value) };
        self.check(ok, value)
    }

    /// Decode an unsigned 64-bit integer
    pub fn u64(&mut self) -> Result<u64> {
        let mut value = 0u64;
        let ok = unsafe { ffi::zcbor_uint64_decode(self.state(), &mut value) };
        self.check(ok, value)
    }

    /// Decode a boolean
    pub fn bool(&mut self) -> Result<bool> {
        let mut value = false;
        let ok = unsafe { ffi::zcbor_bool_decode(self.state(), &mut value) };
        self.check(ok, value)
    }

    /// Decode a byte string (zero-copy, returns slice into input)
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let mut zstr = ffi::ZcborString::default();
        let ok = unsafe { ffi::zcbor_bstr_decode(self.state(), &mut zstr) };
        if ok {
            let slice = unsafe { core::slice::from_raw_parts(zstr.value, zstr.len) };
            Ok(slice)
        } else {
            let err = self.pop_error();
            Err(Error::from(err))
        }
    }

    /// Decode a text string (zero-copy, returns slice into input)
    pub fn str(&mut self) -> Result<&'a str> {
        let mut zstr = ffi::ZcborString::default();
        let ok = unsafe { ffi::zcbor_tstr_decode(self.state(), &mut zstr) };
        if ok {
            let slice = unsafe { core::slice::from_raw_parts(zstr.value, zstr.len) };
            // Note: zcbor doesn't validate UTF-8, so we trust the input
            let s = unsafe { core::str::from_utf8_unchecked(slice) };
            Ok(s)
        } else {
            let err = self.pop_error();
            Err(Error::from(err))
        }
    }

    /// Start decoding an array, returns the number of elements
    pub fn array(&mut self) -> Result<Option<usize>> {
        let ok = unsafe { ffi::zcbor_list_start_decode(self.state()) };
        if ok {
            let state = unsafe { &*self.states[0].as_ptr() };
            // elem_count holds the number of elements
            if state.decode_state.indefinite_length_array {
                Ok(None) // Indefinite length
            } else {
                Ok(Some(state.elem_count))
            }
        } else {
            let err = self.pop_error();
            Err(Error::from(err))
        }
    }

    /// End decoding an array
    pub fn end_array(&mut self) -> Result<()> {
        let ok = unsafe { ffi::zcbor_list_end_decode(self.state()) };
        self.check(ok, ())
    }

    /// Start decoding a map, returns the number of key-value pairs
    pub fn map(&mut self) -> Result<Option<usize>> {
        let ok = unsafe { ffi::zcbor_map_start_decode(self.state()) };
        if ok {
            let state = unsafe { &*self.states[0].as_ptr() };
            if state.decode_state.indefinite_length_array {
                Ok(None)
            } else {
                Ok(Some(state.elem_count / 2)) // Map has key+value pairs
            }
        } else {
            let err = self.pop_error();
            Err(Error::from(err))
        }
    }

    /// End decoding a map
    pub fn end_map(&mut self) -> Result<()> {
        let ok = unsafe { ffi::zcbor_map_end_decode(self.state()) };
        self.check(ok, ())
    }

    /// Decode a CBOR tag
    pub fn tag(&mut self) -> Result<u32> {
        let mut value = 0u32;
        let ok = unsafe { ffi::zcbor_tag_decode(self.state(), &mut value) };
        self.check(ok, value)
    }

    /// Skip the next element (any type)
    pub fn skip(&mut self) -> Result<()> {
        let ok = unsafe { ffi::zcbor_any_skip(self.state(), core::ptr::null_mut()) };
        self.check(ok, ())
    }

    /// Check if at the end of the current array/map
    pub fn at_end(&mut self) -> bool {
        unsafe { ffi::zcbor_array_at_end(self.state()) }
    }
}
