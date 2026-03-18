// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// FFI bindings to Zephyr's zcbor library
//
// These are the raw C function bindings. Use the safe wrappers in the parent module.

use core::ffi::c_void;

/// zcbor string type - points directly into payload without copying
#[repr(C)]
pub struct ZcborString {
    pub value: *const u8,
    pub len: usize,
}

impl Default for ZcborString {
    fn default() -> Self {
        Self {
            value: core::ptr::null(),
            len: 0,
        }
    }
}

/// zcbor state constant - shared between all states
#[repr(C)]
pub struct ZcborStateConstant {
    pub backup_list: *mut ZcborState,
    pub current_backup: usize,
    pub num_backups: usize,
    pub error: i32,
    pub enforce_canonical: bool,
    pub manually_process_elem: bool,
}

/// Decode state portion of zcbor_state_t
#[repr(C)]
pub struct ZcborDecodeState {
    pub indefinite_length_array: bool,
    pub counting_map_elems: bool,
    pub map_elems_processed: usize,
    pub map_elem_count: usize,
}

/// zcbor state - used for both encoding and decoding
#[repr(C)]
pub struct ZcborState {
    pub payload: *mut u8,
    pub payload_bak: *const u8,
    pub elem_count: usize,
    pub payload_end: *const u8,
    pub payload_moved: bool,
    pub decode_state: ZcborDecodeState,
    pub constant_state: *mut ZcborStateConstant,
}

// Error codes
pub const ZCBOR_SUCCESS: i32 = 0;
pub const ZCBOR_ERR_NO_BACKUP_MEM: i32 = 1;
pub const ZCBOR_ERR_NO_BACKUP_ACTIVE: i32 = 2;
pub const ZCBOR_ERR_LOW_ELEM_COUNT: i32 = 3;
pub const ZCBOR_ERR_HIGH_ELEM_COUNT: i32 = 4;
pub const ZCBOR_ERR_INT_SIZE: i32 = 5;
pub const ZCBOR_ERR_FLOAT_SIZE: i32 = 6;
pub const ZCBOR_ERR_ADDITIONAL_INVAL: i32 = 7;
pub const ZCBOR_ERR_NO_PAYLOAD: i32 = 8;
pub const ZCBOR_ERR_PAYLOAD_NOT_CONSUMED: i32 = 9;
pub const ZCBOR_ERR_WRONG_TYPE: i32 = 10;
pub const ZCBOR_ERR_WRONG_VALUE: i32 = 11;
pub const ZCBOR_ERR_WRONG_RANGE: i32 = 12;
pub const ZCBOR_ERR_ITERATIONS: i32 = 13;
pub const ZCBOR_ERR_ASSERTION: i32 = 14;

extern "C" {
    // === State initialization ===

    /// Initialize encoding state
    pub fn zcbor_new_encode_state(
        state_array: *mut ZcborState,
        n_states: usize,
        payload: *mut u8,
        payload_len: usize,
        elem_count: usize,
    );

    /// Initialize decoding state
    pub fn zcbor_new_decode_state(
        state_array: *mut ZcborState,
        n_states: usize,
        payload: *const u8,
        payload_len: usize,
        elem_count: usize,
        elem_state: *mut u8,
        elem_state_bytes: usize,
    );

    // === Encoding functions ===

    /// Encode a signed 32-bit integer
    pub fn zcbor_int32_put(state: *mut ZcborState, input: i32) -> bool;

    /// Encode a signed 64-bit integer
    pub fn zcbor_int64_put(state: *mut ZcborState, input: i64) -> bool;

    /// Encode an unsigned 32-bit integer
    pub fn zcbor_uint32_put(state: *mut ZcborState, input: u32) -> bool;

    /// Encode an unsigned 64-bit integer
    pub fn zcbor_uint64_put(state: *mut ZcborState, input: u64) -> bool;

    /// Encode a boolean
    pub fn zcbor_bool_put(state: *mut ZcborState, input: bool) -> bool;

    /// Encode nil
    pub fn zcbor_nil_put(state: *mut ZcborState, unused: *const c_void) -> bool;

    /// Encode a byte string
    pub fn zcbor_bstr_encode(state: *mut ZcborState, input: *const ZcborString) -> bool;

    /// Encode a text string
    pub fn zcbor_tstr_encode(state: *mut ZcborState, input: *const ZcborString) -> bool;

    /// Encode a byte string from pointer and length
    pub fn zcbor_bstr_encode_ptr(state: *mut ZcborState, str: *const u8, len: usize) -> bool;

    /// Encode a text string from pointer and length
    pub fn zcbor_tstr_encode_ptr(state: *mut ZcborState, str: *const u8, len: usize) -> bool;

    /// Start encoding a list
    pub fn zcbor_list_start_encode(state: *mut ZcborState, max_num: usize) -> bool;

    /// End encoding a list
    pub fn zcbor_list_end_encode(state: *mut ZcborState, max_num: usize) -> bool;

    /// Start encoding a map
    pub fn zcbor_map_start_encode(state: *mut ZcborState, max_num: usize) -> bool;

    /// End encoding a map
    pub fn zcbor_map_end_encode(state: *mut ZcborState, max_num: usize) -> bool;

    /// Encode a CBOR tag
    pub fn zcbor_tag_put(state: *mut ZcborState, tag: u32) -> bool;

    // === Decoding functions ===

    /// Decode a signed 32-bit integer
    pub fn zcbor_int32_decode(state: *mut ZcborState, result: *mut i32) -> bool;

    /// Decode a signed 64-bit integer
    pub fn zcbor_int64_decode(state: *mut ZcborState, result: *mut i64) -> bool;

    /// Decode an unsigned 32-bit integer
    pub fn zcbor_uint32_decode(state: *mut ZcborState, result: *mut u32) -> bool;

    /// Decode an unsigned 64-bit integer
    pub fn zcbor_uint64_decode(state: *mut ZcborState, result: *mut u64) -> bool;

    /// Decode a boolean
    pub fn zcbor_bool_decode(state: *mut ZcborState, result: *mut bool) -> bool;

    /// Decode a byte string
    pub fn zcbor_bstr_decode(state: *mut ZcborState, result: *mut ZcborString) -> bool;

    /// Decode a text string
    pub fn zcbor_tstr_decode(state: *mut ZcborState, result: *mut ZcborString) -> bool;

    /// Start decoding a list
    pub fn zcbor_list_start_decode(state: *mut ZcborState) -> bool;

    /// End decoding a list
    pub fn zcbor_list_end_decode(state: *mut ZcborState) -> bool;

    /// Start decoding a map
    pub fn zcbor_map_start_decode(state: *mut ZcborState) -> bool;

    /// End decoding a map
    pub fn zcbor_map_end_decode(state: *mut ZcborState) -> bool;

    /// Decode a CBOR tag
    pub fn zcbor_tag_decode(state: *mut ZcborState, result: *mut u32) -> bool;

    /// Skip any element
    pub fn zcbor_any_skip(state: *mut ZcborState, unused: *mut c_void) -> bool;

    /// Check if at end of array/map
    pub fn zcbor_array_at_end(state: *mut ZcborState) -> bool;

}
