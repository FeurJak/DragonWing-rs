// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Chunking Protocol for PQ-Ratchet Messages
//!
//! This module provides chunking and reassembly for large PQ-Ratchet messages,
//! enabling reliable transport over size-limited channels like SPI.
//!
//! # Overview
//!
//! PQ-Ratchet messages can be large (up to ~2.5KB with KEM ratchet), and payloads
//! can be even larger (camera frames up to 64KB). This module splits messages
//! into chunks for transmission and reassembles them at the receiver.
//!
//! # Chunk Format
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Chunk Header (16 bytes)                                        │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  [0..2]   Magic (0x4451 = "DQ" for DragonWing Quantum)          │
//! │  [2]      Version (0x01)                                        │
//! │  [3]      Flags:                                                │
//! │             0x01 = first chunk of stream                        │
//! │             0x02 = last chunk of stream                         │
//! │             0x04 = retransmit request                           │
//! │             0x08 = reserved (future: RS-encoded)                │
//! │             0x10 = reserved (future: compressed)                │
//! │  [4..8]   Stream ID (u32 BE) - groups chunks of same message    │
//! │  [8..10]  Chunk Index (u16 BE) - position in stream             │
//! │  [10..12] Total Chunks (u16 BE) - for reassembly                │
//! │  [12..14] Payload Length (u16 BE) - actual data in this chunk   │
//! │  [14..16] CRC-16 (CCITT) of header bytes [0..14]                │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Chunk Payload (up to MAX_CHUNK_PAYLOAD bytes)                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use dragonwing_crypto::experimental::pq_ratchet::chunking::*;
//!
//! // Chunking a large message
//! let mut chunker = Chunker::new();
//! let data = vec![0u8; 5000]; // 5KB payload
//! let chunks = chunker.chunk(&data);
//! assert!(chunks.len() > 1);
//!
//! // Reassembling on the receiver
//! let mut reassembler = Reassembler::new();
//! for chunk in chunks {
//!     match reassembler.add_chunk(&chunk) {
//!         ReassemblyStatus::Complete => {
//!             let data = reassembler.take_data().unwrap();
//!             // Process complete message
//!         }
//!         ReassemblyStatus::NeedMore => continue,
//!         ReassemblyStatus::Error(_) => panic!("Reassembly error"),
//!     }
//! }
//! ```

#[cfg(feature = "std")]
extern crate alloc;

#[cfg(feature = "std")]
use alloc::vec;
#[cfg(feature = "std")]
use alloc::vec::Vec;

// ============================================================================
// Constants
// ============================================================================

/// Magic bytes identifying a DragonWing chunk
pub const CHUNK_MAGIC: [u8; 2] = [0x44, 0x51]; // "DQ"

/// Current chunk format version
pub const CHUNK_VERSION: u8 = 0x01;

/// Size of chunk header in bytes
pub const CHUNK_HEADER_SIZE: usize = 16;

/// Maximum chunk payload size (optimized for SPI: 2048 buffer - 16 header - 32 margin)
pub const MAX_CHUNK_PAYLOAD: usize = 2000;

/// Maximum total chunk size (header + payload)
pub const MAX_CHUNK_SIZE: usize = CHUNK_HEADER_SIZE + MAX_CHUNK_PAYLOAD;

/// Maximum number of chunks per stream (u16 limit)
pub const MAX_CHUNKS_PER_STREAM: usize = 65535;

/// Default maximum chunks for reassembler (memory-constrained)
pub const DEFAULT_MAX_REASSEMBLY_CHUNKS: usize = 64;

// ============================================================================
// Chunk Flags
// ============================================================================

/// Flag indicating this is the first chunk of a stream
pub const FLAG_FIRST_CHUNK: u8 = 0x01;

/// Flag indicating this is the last chunk of a stream
pub const FLAG_LAST_CHUNK: u8 = 0x02;

/// Flag indicating a retransmit request
pub const FLAG_RETRANSMIT: u8 = 0x04;

// Reserved flags for future use
// pub const FLAG_RS_ENCODED: u8 = 0x08;
// pub const FLAG_COMPRESSED: u8 = 0x10;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during chunking/reassembly
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkError {
    /// Invalid magic bytes
    InvalidMagic,
    /// Unsupported version
    UnsupportedVersion,
    /// Header CRC mismatch
    HeaderCrcMismatch,
    /// Chunk too large
    ChunkTooLarge,
    /// Invalid chunk index (out of bounds)
    InvalidChunkIndex,
    /// Stream ID mismatch during reassembly
    StreamIdMismatch,
    /// Duplicate chunk received
    DuplicateChunk,
    /// Reassembly buffer full
    BufferFull,
    /// Data too large to chunk
    DataTooLarge,
    /// Missing chunks for reassembly
    IncompleteStream,
    /// Payload length exceeds chunk size
    PayloadLengthMismatch,
}

/// Status returned by reassembler
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassemblyStatus {
    /// Need more chunks to complete reassembly
    NeedMore,
    /// Reassembly complete, data ready
    Complete,
    /// Error occurred
    Error(ChunkError),
}

// ============================================================================
// CRC-16 CCITT
// ============================================================================

/// CRC-16 CCITT polynomial (used by many protocols including X.25, HDLC)
const CRC16_POLY: u16 = 0x1021;
const CRC16_INIT: u16 = 0xFFFF;

/// Compute CRC-16 CCITT over data
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc = CRC16_INIT;
    for byte in data {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ CRC16_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ============================================================================
// Chunk Header
// ============================================================================

/// Chunk header structure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    /// Chunk flags
    pub flags: u8,
    /// Stream identifier (groups chunks of same message)
    pub stream_id: u32,
    /// Index of this chunk within the stream (0-based)
    pub chunk_index: u16,
    /// Total number of chunks in the stream
    pub total_chunks: u16,
    /// Length of payload in this chunk
    pub payload_length: u16,
}

impl ChunkHeader {
    /// Create a new chunk header
    pub fn new(
        stream_id: u32,
        chunk_index: u16,
        total_chunks: u16,
        payload_length: u16,
        is_first: bool,
        is_last: bool,
    ) -> Self {
        let mut flags = 0u8;
        if is_first {
            flags |= FLAG_FIRST_CHUNK;
        }
        if is_last {
            flags |= FLAG_LAST_CHUNK;
        }

        Self {
            flags,
            stream_id,
            chunk_index,
            total_chunks,
            payload_length,
        }
    }

    /// Check if this is the first chunk
    pub fn is_first(&self) -> bool {
        self.flags & FLAG_FIRST_CHUNK != 0
    }

    /// Check if this is the last chunk
    pub fn is_last(&self) -> bool {
        self.flags & FLAG_LAST_CHUNK != 0
    }

    /// Check if this is a retransmit request
    pub fn is_retransmit(&self) -> bool {
        self.flags & FLAG_RETRANSMIT != 0
    }

    /// Encode header to bytes (including CRC)
    pub fn encode(&self) -> [u8; CHUNK_HEADER_SIZE] {
        let mut buf = [0u8; CHUNK_HEADER_SIZE];

        // Magic
        buf[0..2].copy_from_slice(&CHUNK_MAGIC);

        // Version
        buf[2] = CHUNK_VERSION;

        // Flags
        buf[3] = self.flags;

        // Stream ID
        buf[4..8].copy_from_slice(&self.stream_id.to_be_bytes());

        // Chunk index
        buf[8..10].copy_from_slice(&self.chunk_index.to_be_bytes());

        // Total chunks
        buf[10..12].copy_from_slice(&self.total_chunks.to_be_bytes());

        // Payload length
        buf[12..14].copy_from_slice(&self.payload_length.to_be_bytes());

        // CRC over bytes 0..14
        let crc = crc16_ccitt(&buf[0..14]);
        buf[14..16].copy_from_slice(&crc.to_be_bytes());

        buf
    }

    /// Decode header from bytes (validates magic, version, and CRC)
    pub fn decode(buf: &[u8]) -> Result<Self, ChunkError> {
        if buf.len() < CHUNK_HEADER_SIZE {
            return Err(ChunkError::ChunkTooLarge);
        }

        // Check magic
        if buf[0..2] != CHUNK_MAGIC {
            return Err(ChunkError::InvalidMagic);
        }

        // Check version
        if buf[2] != CHUNK_VERSION {
            return Err(ChunkError::UnsupportedVersion);
        }

        // Verify CRC
        let stored_crc = u16::from_be_bytes([buf[14], buf[15]]);
        let computed_crc = crc16_ccitt(&buf[0..14]);
        if stored_crc != computed_crc {
            return Err(ChunkError::HeaderCrcMismatch);
        }

        Ok(Self {
            flags: buf[3],
            stream_id: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            chunk_index: u16::from_be_bytes([buf[8], buf[9]]),
            total_chunks: u16::from_be_bytes([buf[10], buf[11]]),
            payload_length: u16::from_be_bytes([buf[12], buf[13]]),
        })
    }
}

// ============================================================================
// Chunk (Header + Payload)
// ============================================================================

/// A complete chunk with header and payload
#[derive(Clone)]
pub struct Chunk {
    /// Chunk header
    pub header: ChunkHeader,
    /// Chunk payload (up to MAX_CHUNK_PAYLOAD bytes)
    payload: [u8; MAX_CHUNK_PAYLOAD],
}

impl Chunk {
    /// Create a new chunk with given header and payload
    pub fn new(header: ChunkHeader, payload: &[u8]) -> Result<Self, ChunkError> {
        if payload.len() > MAX_CHUNK_PAYLOAD {
            return Err(ChunkError::ChunkTooLarge);
        }
        if payload.len() != header.payload_length as usize {
            return Err(ChunkError::PayloadLengthMismatch);
        }

        let mut chunk = Self {
            header,
            payload: [0u8; MAX_CHUNK_PAYLOAD],
        };
        chunk.payload[..payload.len()].copy_from_slice(payload);
        Ok(chunk)
    }

    /// Get the payload bytes
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.header.payload_length as usize]
    }

    /// Encode the complete chunk to bytes
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, ChunkError> {
        let total_size = CHUNK_HEADER_SIZE + self.header.payload_length as usize;
        if buf.len() < total_size {
            return Err(ChunkError::ChunkTooLarge);
        }

        buf[..CHUNK_HEADER_SIZE].copy_from_slice(&self.header.encode());
        buf[CHUNK_HEADER_SIZE..total_size].copy_from_slice(self.payload());
        Ok(total_size)
    }

    /// Decode a chunk from bytes
    pub fn decode(buf: &[u8]) -> Result<Self, ChunkError> {
        if buf.len() < CHUNK_HEADER_SIZE {
            return Err(ChunkError::ChunkTooLarge);
        }

        let header = ChunkHeader::decode(buf)?;
        let payload_end = CHUNK_HEADER_SIZE + header.payload_length as usize;

        if buf.len() < payload_end {
            return Err(ChunkError::PayloadLengthMismatch);
        }

        Self::new(header, &buf[CHUNK_HEADER_SIZE..payload_end])
    }

    /// Get total encoded size
    pub fn encoded_size(&self) -> usize {
        CHUNK_HEADER_SIZE + self.header.payload_length as usize
    }
}

impl core::fmt::Debug for Chunk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Chunk")
            .field("header", &self.header)
            .field("payload_len", &self.header.payload_length)
            .finish()
    }
}

// ============================================================================
// Chunker
// ============================================================================

/// Splits large data into chunks for transmission
pub struct Chunker {
    /// Next stream ID to use
    next_stream_id: u32,
}

impl Chunker {
    /// Create a new chunker
    pub fn new() -> Self {
        Self { next_stream_id: 0 }
    }

    /// Create a new chunker with a specific starting stream ID
    pub fn with_stream_id(stream_id: u32) -> Self {
        Self {
            next_stream_id: stream_id,
        }
    }

    /// Get the current stream ID (without incrementing)
    pub fn current_stream_id(&self) -> u32 {
        self.next_stream_id
    }

    /// Calculate number of chunks needed for data of given length
    pub fn chunks_needed(data_len: usize) -> usize {
        if data_len == 0 {
            1 // Empty data still needs one chunk
        } else {
            (data_len + MAX_CHUNK_PAYLOAD - 1) / MAX_CHUNK_PAYLOAD
        }
    }

    /// Check if data can be chunked (not too large)
    pub fn can_chunk(data_len: usize) -> bool {
        Self::chunks_needed(data_len) <= MAX_CHUNKS_PER_STREAM
    }

    /// Chunk data into a vector of chunks
    ///
    /// # Arguments
    /// * `data` - The data to chunk
    ///
    /// # Returns
    /// Vector of chunks, or error if data is too large
    #[cfg(feature = "std")]
    pub fn chunk(&mut self, data: &[u8]) -> Result<Vec<Chunk>, ChunkError> {
        let num_chunks = Self::chunks_needed(data.len());
        if num_chunks > MAX_CHUNKS_PER_STREAM {
            return Err(ChunkError::DataTooLarge);
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1);

        let mut chunks = Vec::with_capacity(num_chunks);
        let total_chunks = num_chunks as u16;

        for i in 0..num_chunks {
            let start = i * MAX_CHUNK_PAYLOAD;
            let end = core::cmp::min(start + MAX_CHUNK_PAYLOAD, data.len());
            let payload = &data[start..end];

            let header = ChunkHeader::new(
                stream_id,
                i as u16,
                total_chunks,
                payload.len() as u16,
                i == 0,
                i == num_chunks - 1,
            );

            chunks.push(Chunk::new(header, payload)?);
        }

        Ok(chunks)
    }

    /// Chunk data into a fixed-size array (for no_std)
    ///
    /// # Arguments
    /// * `data` - The data to chunk
    /// * `output` - Array to store chunks
    ///
    /// # Returns
    /// Number of chunks written, or error
    pub fn chunk_into<const N: usize>(
        &mut self,
        data: &[u8],
        output: &mut [Chunk; N],
    ) -> Result<usize, ChunkError> {
        let num_chunks = Self::chunks_needed(data.len());
        if num_chunks > N {
            return Err(ChunkError::BufferFull);
        }
        if num_chunks > MAX_CHUNKS_PER_STREAM {
            return Err(ChunkError::DataTooLarge);
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1);

        let total_chunks = num_chunks as u16;

        for i in 0..num_chunks {
            let start = i * MAX_CHUNK_PAYLOAD;
            let end = core::cmp::min(start + MAX_CHUNK_PAYLOAD, data.len());
            let payload = &data[start..end];

            let header = ChunkHeader::new(
                stream_id,
                i as u16,
                total_chunks,
                payload.len() as u16,
                i == 0,
                i == num_chunks - 1,
            );

            output[i] = Chunk::new(header, payload)?;
        }

        Ok(num_chunks)
    }
}

impl Default for Chunker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Reassembler (no_std compatible with fixed buffer)
// ============================================================================

/// Status of a chunk slot in the reassembler
#[derive(Clone, Copy, PartialEq, Eq)]
enum ChunkSlotStatus {
    Empty,
    Received,
}

/// Reassembles chunks back into complete data.
///
/// This implementation uses a fixed-size buffer suitable for no_std/MCU environments.
/// The maximum message size is `MAX_CHUNKS * MAX_CHUNK_PAYLOAD`.
pub struct Reassembler<const MAX_CHUNKS: usize = DEFAULT_MAX_REASSEMBLY_CHUNKS> {
    /// Current stream ID being reassembled
    stream_id: Option<u32>,
    /// Expected total number of chunks
    total_chunks: u16,
    /// Number of chunks received so far
    received_count: u16,
    /// Status of each chunk slot
    slot_status: [ChunkSlotStatus; MAX_CHUNKS],
    /// Length of payload in each chunk slot
    payload_lengths: [u16; MAX_CHUNKS],
    /// Data buffer for reassembly
    data: [[u8; MAX_CHUNK_PAYLOAD]; MAX_CHUNKS],
}

impl<const MAX_CHUNKS: usize> Reassembler<MAX_CHUNKS> {
    /// Maximum data size this reassembler can handle
    pub const MAX_DATA_SIZE: usize = MAX_CHUNKS * MAX_CHUNK_PAYLOAD;

    /// Create a new reassembler
    pub fn new() -> Self {
        Self {
            stream_id: None,
            total_chunks: 0,
            received_count: 0,
            slot_status: [ChunkSlotStatus::Empty; MAX_CHUNKS],
            payload_lengths: [0; MAX_CHUNKS],
            data: [[0u8; MAX_CHUNK_PAYLOAD]; MAX_CHUNKS],
        }
    }

    /// Reset the reassembler for a new stream
    pub fn reset(&mut self) {
        self.stream_id = None;
        self.total_chunks = 0;
        self.received_count = 0;
        for status in &mut self.slot_status {
            *status = ChunkSlotStatus::Empty;
        }
    }

    /// Get the current stream ID (if any)
    pub fn current_stream_id(&self) -> Option<u32> {
        self.stream_id
    }

    /// Check if reassembly is complete
    pub fn is_complete(&self) -> bool {
        self.stream_id.is_some()
            && self.total_chunks > 0
            && self.received_count == self.total_chunks
    }

    /// Get number of chunks received
    pub fn received_count(&self) -> u16 {
        self.received_count
    }

    /// Get total chunks expected (0 if not yet known)
    pub fn total_chunks(&self) -> u16 {
        self.total_chunks
    }

    /// Add a chunk to the reassembler
    ///
    /// Returns the reassembly status after adding this chunk.
    pub fn add_chunk(&mut self, chunk: &Chunk) -> ReassemblyStatus {
        let header = &chunk.header;

        // Validate chunk index
        if header.chunk_index >= header.total_chunks {
            return ReassemblyStatus::Error(ChunkError::InvalidChunkIndex);
        }

        // Check if this chunk fits in our buffer
        if header.chunk_index as usize >= MAX_CHUNKS || header.total_chunks as usize > MAX_CHUNKS {
            return ReassemblyStatus::Error(ChunkError::BufferFull);
        }

        // Handle stream ID
        match self.stream_id {
            None => {
                // First chunk, initialize stream
                self.stream_id = Some(header.stream_id);
                self.total_chunks = header.total_chunks;
            }
            Some(sid) => {
                // Check stream ID matches
                if sid != header.stream_id {
                    // New stream, reset and start over
                    self.reset();
                    self.stream_id = Some(header.stream_id);
                    self.total_chunks = header.total_chunks;
                }
            }
        }

        let idx = header.chunk_index as usize;

        // Check for duplicate
        if self.slot_status[idx] == ChunkSlotStatus::Received {
            return ReassemblyStatus::Error(ChunkError::DuplicateChunk);
        }

        // Store chunk data
        let payload = chunk.payload();
        self.data[idx][..payload.len()].copy_from_slice(payload);
        self.payload_lengths[idx] = header.payload_length;
        self.slot_status[idx] = ChunkSlotStatus::Received;
        self.received_count += 1;

        // Check if complete
        if self.is_complete() {
            ReassemblyStatus::Complete
        } else {
            ReassemblyStatus::NeedMore
        }
    }

    /// Get the total reassembled data length
    pub fn data_length(&self) -> usize {
        if !self.is_complete() {
            return 0;
        }

        let mut total = 0;
        for i in 0..self.total_chunks as usize {
            total += self.payload_lengths[i] as usize;
        }
        total
    }

    /// Copy reassembled data to buffer
    ///
    /// Returns the number of bytes copied, or error if incomplete.
    pub fn copy_to(&self, buf: &mut [u8]) -> Result<usize, ChunkError> {
        if !self.is_complete() {
            return Err(ChunkError::IncompleteStream);
        }

        let total_len = self.data_length();
        if buf.len() < total_len {
            return Err(ChunkError::BufferFull);
        }

        let mut offset = 0;
        for i in 0..self.total_chunks as usize {
            let len = self.payload_lengths[i] as usize;
            buf[offset..offset + len].copy_from_slice(&self.data[i][..len]);
            offset += len;
        }

        Ok(offset)
    }

    /// Take reassembled data as a Vec (requires std)
    #[cfg(feature = "std")]
    pub fn take_data(&mut self) -> Result<Vec<u8>, ChunkError> {
        if !self.is_complete() {
            return Err(ChunkError::IncompleteStream);
        }

        let total_len = self.data_length();
        let mut result = vec![0u8; total_len];
        self.copy_to(&mut result)?;
        self.reset();
        Ok(result)
    }

    /// Get missing chunk indices (for retransmit requests)
    pub fn missing_chunks(&self) -> impl Iterator<Item = u16> + '_ {
        (0..self.total_chunks).filter(move |&i| {
            let idx = i as usize;
            idx < MAX_CHUNKS && self.slot_status[idx] == ChunkSlotStatus::Empty
        })
    }
}

impl<const MAX_CHUNKS: usize> Default for Reassembler<MAX_CHUNKS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_CHUNKS: usize> core::fmt::Debug for Reassembler<MAX_CHUNKS> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reassembler")
            .field("stream_id", &self.stream_id)
            .field("total_chunks", &self.total_chunks)
            .field("received_count", &self.received_count)
            .field("max_chunks", &MAX_CHUNKS)
            .finish()
    }
}

// ============================================================================
// Retransmit Request
// ============================================================================

/// Create a retransmit request chunk for a missing chunk
pub fn create_retransmit_request(stream_id: u32, chunk_index: u16, total_chunks: u16) -> Chunk {
    let header = ChunkHeader {
        flags: FLAG_RETRANSMIT,
        stream_id,
        chunk_index,
        total_chunks,
        payload_length: 0,
    };

    // Safe: empty payload always succeeds
    Chunk::new(header, &[]).unwrap()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    extern crate alloc;
    #[cfg(feature = "std")]
    use alloc::vec;
    #[cfg(feature = "std")]
    use alloc::vec::Vec;

    #[test]
    fn test_crc16() {
        // Known CRC-16 CCITT test vectors
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
        assert_eq!(crc16_ccitt(b""), 0xFFFF);
        assert_eq!(crc16_ccitt(b"A"), 0xB915);
    }

    #[test]
    fn test_chunk_header_encode_decode() {
        let header = ChunkHeader::new(12345, 5, 10, 1500, false, false);
        let encoded = header.encode();
        let decoded = ChunkHeader::decode(&encoded).unwrap();

        assert_eq!(decoded.stream_id, 12345);
        assert_eq!(decoded.chunk_index, 5);
        assert_eq!(decoded.total_chunks, 10);
        assert_eq!(decoded.payload_length, 1500);
        assert!(!decoded.is_first());
        assert!(!decoded.is_last());
    }

    #[test]
    fn test_chunk_header_first_last_flags() {
        let first = ChunkHeader::new(1, 0, 3, 100, true, false);
        assert!(first.is_first());
        assert!(!first.is_last());

        let last = ChunkHeader::new(1, 2, 3, 50, false, true);
        assert!(!last.is_first());
        assert!(last.is_last());

        let only = ChunkHeader::new(1, 0, 1, 100, true, true);
        assert!(only.is_first());
        assert!(only.is_last());
    }

    #[test]
    fn test_chunk_header_invalid_magic() {
        let mut encoded = ChunkHeader::new(1, 0, 1, 100, true, true).encode();
        encoded[0] = 0xFF; // Corrupt magic
        assert_eq!(ChunkHeader::decode(&encoded), Err(ChunkError::InvalidMagic));
    }

    #[test]
    fn test_chunk_header_invalid_crc() {
        let mut encoded = ChunkHeader::new(1, 0, 1, 100, true, true).encode();
        encoded[14] ^= 0xFF; // Corrupt CRC
        assert_eq!(
            ChunkHeader::decode(&encoded),
            Err(ChunkError::HeaderCrcMismatch)
        );
    }

    #[test]
    fn test_chunk_encode_decode() {
        let header = ChunkHeader::new(42, 0, 1, 5, true, true);
        let payload = b"hello";
        let chunk = Chunk::new(header, payload).unwrap();

        let mut buf = [0u8; MAX_CHUNK_SIZE];
        let size = chunk.encode(&mut buf).unwrap();

        let decoded = Chunk::decode(&buf[..size]).unwrap();
        assert_eq!(decoded.header.stream_id, 42);
        assert_eq!(decoded.payload(), b"hello");
    }

    #[test]
    fn test_chunker_small_data() {
        let mut chunker = Chunker::new();
        let data = b"small data";
        let chunks = chunker.chunk(data).unwrap();

        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].header.is_first());
        assert!(chunks[0].header.is_last());
        assert_eq!(chunks[0].payload(), data.as_slice());
    }

    #[test]
    fn test_chunker_large_data() {
        let mut chunker = Chunker::new();
        let data = vec![0xABu8; 5000]; // 5KB, needs 3 chunks
        let chunks = chunker.chunk(&data).unwrap();

        assert_eq!(chunks.len(), 3);
        assert_eq!(Chunker::chunks_needed(5000), 3);

        assert!(chunks[0].header.is_first());
        assert!(!chunks[0].header.is_last());
        assert_eq!(chunks[0].header.payload_length, MAX_CHUNK_PAYLOAD as u16);

        assert!(!chunks[1].header.is_first());
        assert!(!chunks[1].header.is_last());

        assert!(!chunks[2].header.is_first());
        assert!(chunks[2].header.is_last());
        assert_eq!(chunks[2].header.payload_length, 1000); // 5000 - 2*2000
    }

    #[test]
    fn test_chunker_stream_id_increment() {
        let mut chunker = Chunker::new();
        assert_eq!(chunker.current_stream_id(), 0);

        let _ = chunker.chunk(b"test1").unwrap();
        assert_eq!(chunker.current_stream_id(), 1);

        let _ = chunker.chunk(b"test2").unwrap();
        assert_eq!(chunker.current_stream_id(), 2);
    }

    #[test]
    fn test_reassembler_single_chunk() {
        let mut chunker = Chunker::new();
        let mut reassembler = Reassembler::<64>::new();

        let data = b"single chunk data";
        let chunks = chunker.chunk(data).unwrap();
        assert_eq!(chunks.len(), 1);

        let status = reassembler.add_chunk(&chunks[0]);
        assert_eq!(status, ReassemblyStatus::Complete);

        let result = reassembler.take_data().unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_reassembler_multiple_chunks() {
        let mut chunker = Chunker::new();
        let mut reassembler = Reassembler::<64>::new();

        let data = vec![0xCDu8; 5000];
        let chunks = chunker.chunk(&data).unwrap();
        assert_eq!(chunks.len(), 3);

        assert_eq!(
            reassembler.add_chunk(&chunks[0]),
            ReassemblyStatus::NeedMore
        );
        assert_eq!(
            reassembler.add_chunk(&chunks[1]),
            ReassemblyStatus::NeedMore
        );
        assert_eq!(
            reassembler.add_chunk(&chunks[2]),
            ReassemblyStatus::Complete
        );

        let result = reassembler.take_data().unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_reassembler_out_of_order() {
        let mut chunker = Chunker::new();
        let mut reassembler = Reassembler::<64>::new();

        let data = vec![0xEFu8; 5000];
        let chunks = chunker.chunk(&data).unwrap();

        // Add chunks in reverse order
        assert_eq!(
            reassembler.add_chunk(&chunks[2]),
            ReassemblyStatus::NeedMore
        );
        assert_eq!(
            reassembler.add_chunk(&chunks[0]),
            ReassemblyStatus::NeedMore
        );
        assert_eq!(
            reassembler.add_chunk(&chunks[1]),
            ReassemblyStatus::Complete
        );

        let result = reassembler.take_data().unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_reassembler_duplicate_chunk() {
        let mut chunker = Chunker::new();
        let mut reassembler = Reassembler::<64>::new();

        let data = b"test data";
        let chunks = chunker.chunk(data).unwrap();

        reassembler.add_chunk(&chunks[0]);

        // Try to add same chunk again
        let status = reassembler.add_chunk(&chunks[0]);
        assert_eq!(status, ReassemblyStatus::Error(ChunkError::DuplicateChunk));
    }

    #[test]
    fn test_reassembler_new_stream_resets() {
        let mut chunker = Chunker::new();
        let mut reassembler = Reassembler::<64>::new();

        let data1 = b"first message";
        let chunks1 = chunker.chunk(data1).unwrap();

        let data2 = b"second message";
        let chunks2 = chunker.chunk(data2).unwrap();

        // Start first stream
        reassembler.add_chunk(&chunks1[0]);
        assert_eq!(reassembler.current_stream_id(), Some(0));

        // Add chunk from different stream - should reset
        let status = reassembler.add_chunk(&chunks2[0]);
        assert_eq!(status, ReassemblyStatus::Complete);
        assert_eq!(reassembler.current_stream_id(), Some(1));

        let result = reassembler.take_data().unwrap();
        assert_eq!(result, data2);
    }

    #[test]
    fn test_reassembler_missing_chunks() {
        let mut chunker = Chunker::new();
        let mut reassembler = Reassembler::<64>::new();

        let data = vec![0u8; 5000];
        let chunks = chunker.chunk(&data).unwrap();

        // Only add first and last chunks
        reassembler.add_chunk(&chunks[0]);
        reassembler.add_chunk(&chunks[2]);

        let missing: Vec<_> = reassembler.missing_chunks().collect();
        assert_eq!(missing, vec![1]);
    }

    #[test]
    fn test_retransmit_request() {
        let req = create_retransmit_request(42, 5, 10);
        assert!(req.header.is_retransmit());
        assert_eq!(req.header.stream_id, 42);
        assert_eq!(req.header.chunk_index, 5);
        assert_eq!(req.header.payload_length, 0);
    }

    #[test]
    fn test_max_chunk_sizes() {
        assert_eq!(CHUNK_HEADER_SIZE, 16);
        assert_eq!(MAX_CHUNK_PAYLOAD, 2000);
        assert_eq!(MAX_CHUNK_SIZE, 2016);
    }

    #[test]
    fn test_chunks_needed_calculation() {
        assert_eq!(Chunker::chunks_needed(0), 1);
        assert_eq!(Chunker::chunks_needed(1), 1);
        assert_eq!(Chunker::chunks_needed(2000), 1);
        assert_eq!(Chunker::chunks_needed(2001), 2);
        assert_eq!(Chunker::chunks_needed(4000), 2);
        assert_eq!(Chunker::chunks_needed(4001), 3);
    }
}
