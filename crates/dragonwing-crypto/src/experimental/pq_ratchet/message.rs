// SPDX-License-Identifier: Apache-2.0 OR MIT
//
//! Message Encoding/Decoding for PQ-Ratchet
//!
//! This module defines the wire format for PQ-Ratchet messages. The format
//! is designed to be:
//! - Compact for typical messages (no KEM ratchet)
//! - Self-describing (version and flags)
//! - Authenticated (header MAC before decryption)
//! - Compatible with chunking (fixed header positions)
//!
//! # Wire Format
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Header (14-2354 bytes depending on flags)                      │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  [0]       Version (0x01)                                       │
//! │  [1]       Flags                                                │
//! │  [2..10]   Epoch (u64 BE)                                       │
//! │  [10..14]  Message Number (u32 BE)                              │
//! │  [14..18]  Previous Chain Length (u32 BE) - if FLAG_HAS_NEW_PK  │
//! │  [18..]    New X-Wing Public Key (1216 bytes) - if FLAG_HAS_NEW_PK
//! │  [..]      X-Wing Ciphertext (1120 bytes) - if FLAG_HAS_CIPHERTEXT
//! ├─────────────────────────────────────────────────────────────────┤
//! │  [H..H+32] Header MAC (HMAC-SHA256)                             │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Encrypted Payload:                                             │
//! │  [M..M+24] Nonce (24 bytes)                                     │
//! │  [M+24..]  Ciphertext + Tag (16 bytes)                          │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use super::kdf::{KEY_SIZE, NONCE_SIZE};
use super::state::{XWING_CIPHERTEXT_SIZE, XWING_PUBLIC_KEY_SIZE};

// ============================================================================
// Constants
// ============================================================================

/// Current protocol version
pub const VERSION: u8 = 0x01;

/// Flag: Sender is including a new X-Wing public key (KEM ratchet)
pub const FLAG_HAS_NEW_PK: u8 = 0x01;

/// Flag: Message is a response to a new public key (includes ciphertext)
pub const FLAG_IS_RESPONSE: u8 = 0x02;

/// Flag: Message includes X-Wing ciphertext
pub const FLAG_HAS_CIPHERTEXT: u8 = 0x04;

/// Minimum header size (no KEM material)
pub const MIN_HEADER_SIZE: usize = 14; // version + flags + epoch + msg_num

/// Header size with new public key
pub const HEADER_SIZE_WITH_PK: usize = MIN_HEADER_SIZE + 4 + XWING_PUBLIC_KEY_SIZE; // + prev_chain_len + pk

/// Header size with ciphertext
pub const HEADER_SIZE_WITH_CT: usize = MIN_HEADER_SIZE + XWING_CIPHERTEXT_SIZE;

/// Header size with both public key and ciphertext
pub const HEADER_SIZE_WITH_PK_AND_CT: usize =
    MIN_HEADER_SIZE + 4 + XWING_PUBLIC_KEY_SIZE + XWING_CIPHERTEXT_SIZE;

/// MAC size (HMAC-SHA256)
pub const MAC_SIZE: usize = KEY_SIZE;

/// AEAD tag size (Poly1305)
pub const TAG_SIZE: usize = 16;

/// Maximum message size (header + MAC + nonce + max payload + tag)
/// Allows for ~64KB payload which is typical for camera frames
pub const MAX_MESSAGE_SIZE: usize =
    HEADER_SIZE_WITH_PK_AND_CT + MAC_SIZE + NONCE_SIZE + 65536 + TAG_SIZE;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during message encoding/decoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// Message is too short to contain required fields
    TooShort,
    /// Invalid protocol version
    InvalidVersion,
    /// Invalid flags combination
    InvalidFlags,
    /// Message is too long
    TooLong,
    /// Buffer is too small for encoding
    BufferTooSmall,
    /// Header MAC verification failed
    MacVerificationFailed,
    /// Decryption failed (invalid ciphertext or tag)
    DecryptionFailed,
    /// Invalid message structure
    InvalidStructure,
}

/// Result type for message operations
pub type Result<T> = core::result::Result<T, MessageError>;

// ============================================================================
// Message Header
// ============================================================================

/// Parsed message header (without MAC or payload)
#[derive(Debug, Clone)]
pub struct MessageHeader {
    /// Protocol version
    pub version: u8,
    /// Message flags
    pub flags: u8,
    /// Epoch number
    pub epoch: u64,
    /// Message number within epoch
    pub message_num: u32,
    /// Previous send chain length (only if FLAG_HAS_NEW_PK)
    pub prev_chain_len: Option<u32>,
    /// New X-Wing public key (only if FLAG_HAS_NEW_PK)
    pub new_public_key: Option<[u8; XWING_PUBLIC_KEY_SIZE]>,
    /// X-Wing ciphertext (only if FLAG_HAS_CIPHERTEXT)
    pub ciphertext: Option<[u8; XWING_CIPHERTEXT_SIZE]>,
}

impl MessageHeader {
    /// Create a new header for a regular message (no KEM ratchet)
    pub fn new(epoch: u64, message_num: u32) -> Self {
        Self {
            version: VERSION,
            flags: 0,
            epoch,
            message_num,
            prev_chain_len: None,
            new_public_key: None,
            ciphertext: None,
        }
    }

    /// Create a header with a new public key (initiating KEM ratchet)
    pub fn with_new_pk(
        epoch: u64,
        message_num: u32,
        prev_chain_len: u32,
        new_public_key: [u8; XWING_PUBLIC_KEY_SIZE],
    ) -> Self {
        Self {
            version: VERSION,
            flags: FLAG_HAS_NEW_PK,
            epoch,
            message_num,
            prev_chain_len: Some(prev_chain_len),
            new_public_key: Some(new_public_key),
            ciphertext: None,
        }
    }

    /// Create a header responding to a new public key (with ciphertext)
    pub fn with_response(
        epoch: u64,
        message_num: u32,
        ciphertext: [u8; XWING_CIPHERTEXT_SIZE],
    ) -> Self {
        Self {
            version: VERSION,
            flags: FLAG_IS_RESPONSE | FLAG_HAS_CIPHERTEXT,
            epoch,
            message_num,
            prev_chain_len: None,
            new_public_key: None,
            ciphertext: Some(ciphertext),
        }
    }

    /// Check if this header includes a new public key
    pub fn has_new_pk(&self) -> bool {
        self.flags & FLAG_HAS_NEW_PK != 0
    }

    /// Check if this header is a response (includes ciphertext)
    pub fn is_response(&self) -> bool {
        self.flags & FLAG_IS_RESPONSE != 0
    }

    /// Check if this header has ciphertext
    pub fn has_ciphertext(&self) -> bool {
        self.flags & FLAG_HAS_CIPHERTEXT != 0
    }

    /// Calculate the encoded size of this header
    pub fn encoded_size(&self) -> usize {
        let mut size = MIN_HEADER_SIZE;
        if self.has_new_pk() {
            size += 4 + XWING_PUBLIC_KEY_SIZE; // prev_chain_len + pk
        }
        if self.has_ciphertext() {
            size += XWING_CIPHERTEXT_SIZE;
        }
        size
    }

    /// Encode the header into a buffer
    ///
    /// # Returns
    /// The number of bytes written
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let size = self.encoded_size();
        if buf.len() < size {
            return Err(MessageError::BufferTooSmall);
        }

        let mut offset = 0;

        // Version
        buf[offset] = self.version;
        offset += 1;

        // Flags
        buf[offset] = self.flags;
        offset += 1;

        // Epoch (u64 BE)
        buf[offset..offset + 8].copy_from_slice(&self.epoch.to_be_bytes());
        offset += 8;

        // Message number (u32 BE)
        buf[offset..offset + 4].copy_from_slice(&self.message_num.to_be_bytes());
        offset += 4;

        // Previous chain length (if FLAG_HAS_NEW_PK)
        if self.has_new_pk() {
            let pcl = self.prev_chain_len.unwrap_or(0);
            buf[offset..offset + 4].copy_from_slice(&pcl.to_be_bytes());
            offset += 4;

            // New public key
            if let Some(ref pk) = self.new_public_key {
                buf[offset..offset + XWING_PUBLIC_KEY_SIZE].copy_from_slice(pk);
                offset += XWING_PUBLIC_KEY_SIZE;
            }
        }

        // Ciphertext (if FLAG_HAS_CIPHERTEXT)
        if self.has_ciphertext() {
            if let Some(ref ct) = self.ciphertext {
                buf[offset..offset + XWING_CIPHERTEXT_SIZE].copy_from_slice(ct);
                offset += XWING_CIPHERTEXT_SIZE;
            }
        }

        Ok(offset)
    }

    /// Decode a header from a buffer
    ///
    /// # Returns
    /// The header and the number of bytes consumed
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < MIN_HEADER_SIZE {
            return Err(MessageError::TooShort);
        }

        let mut offset = 0;

        // Version
        let version = buf[offset];
        if version != VERSION {
            return Err(MessageError::InvalidVersion);
        }
        offset += 1;

        // Flags
        let flags = buf[offset];
        offset += 1;

        // Epoch
        let epoch = u64::from_be_bytes(buf[offset..offset + 8].try_into().unwrap());
        offset += 8;

        // Message number
        let message_num = u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap());
        offset += 4;

        // Previous chain length and public key (if FLAG_HAS_NEW_PK)
        let (prev_chain_len, new_public_key) = if flags & FLAG_HAS_NEW_PK != 0 {
            if buf.len() < offset + 4 + XWING_PUBLIC_KEY_SIZE {
                return Err(MessageError::TooShort);
            }
            let pcl = u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap());
            offset += 4;

            let mut pk = [0u8; XWING_PUBLIC_KEY_SIZE];
            pk.copy_from_slice(&buf[offset..offset + XWING_PUBLIC_KEY_SIZE]);
            offset += XWING_PUBLIC_KEY_SIZE;

            (Some(pcl), Some(pk))
        } else {
            (None, None)
        };

        // Ciphertext (if FLAG_HAS_CIPHERTEXT)
        let ciphertext = if flags & FLAG_HAS_CIPHERTEXT != 0 {
            if buf.len() < offset + XWING_CIPHERTEXT_SIZE {
                return Err(MessageError::TooShort);
            }
            let mut ct = [0u8; XWING_CIPHERTEXT_SIZE];
            ct.copy_from_slice(&buf[offset..offset + XWING_CIPHERTEXT_SIZE]);
            offset += XWING_CIPHERTEXT_SIZE;
            Some(ct)
        } else {
            None
        };

        Ok((
            Self {
                version,
                flags,
                epoch,
                message_num,
                prev_chain_len,
                new_public_key,
                ciphertext,
            },
            offset,
        ))
    }
}

// ============================================================================
// Complete Ratchet Message
// ============================================================================

/// A complete PQ-Ratchet message with header, MAC, and encrypted payload
#[derive(Clone)]
pub struct RatchetMessage {
    /// Message header
    pub header: MessageHeader,
    /// Header MAC (32 bytes)
    pub header_mac: [u8; MAC_SIZE],
    /// Nonce for payload encryption (24 bytes)
    pub nonce: [u8; NONCE_SIZE],
    /// Encrypted payload with authentication tag
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    /// Create a new ratchet message
    pub fn new(
        header: MessageHeader,
        header_mac: [u8; MAC_SIZE],
        nonce: [u8; NONCE_SIZE],
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            header,
            header_mac,
            nonce,
            ciphertext,
        }
    }

    /// Calculate the total encoded size
    pub fn encoded_size(&self) -> usize {
        self.header.encoded_size() + MAC_SIZE + NONCE_SIZE + self.ciphertext.len()
    }

    /// Encode the complete message into a buffer
    ///
    /// # Returns
    /// The number of bytes written
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let total_size = self.encoded_size();
        if buf.len() < total_size {
            return Err(MessageError::BufferTooSmall);
        }

        let mut offset = 0;

        // Encode header
        let header_size = self.header.encode(&mut buf[offset..])?;
        offset += header_size;

        // Header MAC
        buf[offset..offset + MAC_SIZE].copy_from_slice(&self.header_mac);
        offset += MAC_SIZE;

        // Nonce
        buf[offset..offset + NONCE_SIZE].copy_from_slice(&self.nonce);
        offset += NONCE_SIZE;

        // Ciphertext
        buf[offset..offset + self.ciphertext.len()].copy_from_slice(&self.ciphertext);
        offset += self.ciphertext.len();

        Ok(offset)
    }

    /// Encode the complete message into a new Vec
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.encoded_size()];
        self.encode(&mut buf).expect("buffer size is correct");
        buf
    }

    /// Decode a complete message from a buffer
    pub fn decode(buf: &[u8]) -> Result<Self> {
        // Decode header
        let (header, header_size) = MessageHeader::decode(buf)?;

        let mut offset = header_size;

        // Minimum remaining: MAC + nonce + at least 1 byte ciphertext + tag
        if buf.len() < offset + MAC_SIZE + NONCE_SIZE + TAG_SIZE {
            return Err(MessageError::TooShort);
        }

        // Header MAC
        let mut header_mac = [0u8; MAC_SIZE];
        header_mac.copy_from_slice(&buf[offset..offset + MAC_SIZE]);
        offset += MAC_SIZE;

        // Nonce
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&buf[offset..offset + NONCE_SIZE]);
        offset += NONCE_SIZE;

        // Ciphertext (rest of buffer)
        let ciphertext = buf[offset..].to_vec();

        Ok(Self {
            header,
            header_mac,
            nonce,
            ciphertext,
        })
    }

    /// Get the header bytes for MAC verification
    pub fn header_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.header.encoded_size()];
        self.header
            .encode(&mut buf)
            .expect("buffer size is correct");
        buf
    }
}

impl core::fmt::Debug for RatchetMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RatchetMessage")
            .field("header", &self.header)
            .field("header_mac", &"[...]")
            .field("nonce", &"[...]")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

// ============================================================================
// No-std Compatible Message (fixed-size buffer)
// ============================================================================

/// Maximum payload size for no_std environments
pub const MAX_PAYLOAD_SIZE: usize = 2048;

/// A ratchet message with fixed-size buffer for no_std environments
#[derive(Debug)]
pub struct RatchetMessageFixed {
    /// Message header
    pub header: MessageHeader,
    /// Header MAC (32 bytes)
    pub header_mac: [u8; MAC_SIZE],
    /// Nonce for payload encryption (24 bytes)
    pub nonce: [u8; NONCE_SIZE],
    /// Encrypted payload buffer
    pub ciphertext: [u8; MAX_PAYLOAD_SIZE + TAG_SIZE],
    /// Actual ciphertext length
    pub ciphertext_len: usize,
}

impl RatchetMessageFixed {
    /// Create a new fixed-size ratchet message
    pub fn new(
        header: MessageHeader,
        header_mac: [u8; MAC_SIZE],
        nonce: [u8; NONCE_SIZE],
        ciphertext: &[u8],
    ) -> Result<Self> {
        if ciphertext.len() > MAX_PAYLOAD_SIZE + TAG_SIZE {
            return Err(MessageError::TooLong);
        }

        let mut ct_buf = [0u8; MAX_PAYLOAD_SIZE + TAG_SIZE];
        ct_buf[..ciphertext.len()].copy_from_slice(ciphertext);

        Ok(Self {
            header,
            header_mac,
            nonce,
            ciphertext: ct_buf,
            ciphertext_len: ciphertext.len(),
        })
    }

    /// Get the ciphertext slice
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext[..self.ciphertext_len]
    }

    /// Calculate the total encoded size
    pub fn encoded_size(&self) -> usize {
        self.header.encoded_size() + MAC_SIZE + NONCE_SIZE + self.ciphertext_len
    }

    /// Encode into a buffer
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let total_size = self.encoded_size();
        if buf.len() < total_size {
            return Err(MessageError::BufferTooSmall);
        }

        let mut offset = 0;

        // Encode header
        let header_size = self.header.encode(&mut buf[offset..])?;
        offset += header_size;

        // Header MAC
        buf[offset..offset + MAC_SIZE].copy_from_slice(&self.header_mac);
        offset += MAC_SIZE;

        // Nonce
        buf[offset..offset + NONCE_SIZE].copy_from_slice(&self.nonce);
        offset += NONCE_SIZE;

        // Ciphertext
        buf[offset..offset + self.ciphertext_len].copy_from_slice(self.ciphertext());
        offset += self.ciphertext_len;

        Ok(offset)
    }

    /// Decode from a buffer
    pub fn decode(buf: &[u8]) -> Result<Self> {
        // Decode header
        let (header, header_size) = MessageHeader::decode(buf)?;

        let mut offset = header_size;

        // Minimum remaining: MAC + nonce + tag
        if buf.len() < offset + MAC_SIZE + NONCE_SIZE + TAG_SIZE {
            return Err(MessageError::TooShort);
        }

        // Header MAC
        let mut header_mac = [0u8; MAC_SIZE];
        header_mac.copy_from_slice(&buf[offset..offset + MAC_SIZE]);
        offset += MAC_SIZE;

        // Nonce
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&buf[offset..offset + NONCE_SIZE]);
        offset += NONCE_SIZE;

        // Ciphertext (rest of buffer)
        let ct_slice = &buf[offset..];
        if ct_slice.len() > MAX_PAYLOAD_SIZE + TAG_SIZE {
            return Err(MessageError::TooLong);
        }

        let mut ciphertext = [0u8; MAX_PAYLOAD_SIZE + TAG_SIZE];
        ciphertext[..ct_slice.len()].copy_from_slice(ct_slice);

        Ok(Self {
            header,
            header_mac,
            nonce,
            ciphertext,
            ciphertext_len: ct_slice.len(),
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_basic_encode_decode() {
        let header = MessageHeader::new(42, 7);

        let mut buf = [0u8; 256];
        let size = header.encode(&mut buf).unwrap();

        assert_eq!(size, MIN_HEADER_SIZE);

        let (decoded, decoded_size) = MessageHeader::decode(&buf[..size]).unwrap();

        assert_eq!(decoded_size, size);
        assert_eq!(decoded.version, VERSION);
        assert_eq!(decoded.epoch, 42);
        assert_eq!(decoded.message_num, 7);
        assert!(!decoded.has_new_pk());
        assert!(!decoded.has_ciphertext());
    }

    #[test]
    fn test_header_with_new_pk() {
        let pk = [0xAB; XWING_PUBLIC_KEY_SIZE];
        let header = MessageHeader::with_new_pk(100, 0, 50, pk);

        assert!(header.has_new_pk());
        assert!(!header.has_ciphertext());
        assert_eq!(header.encoded_size(), HEADER_SIZE_WITH_PK);

        let mut buf = [0u8; 2048];
        let size = header.encode(&mut buf).unwrap();

        let (decoded, _) = MessageHeader::decode(&buf[..size]).unwrap();

        assert!(decoded.has_new_pk());
        assert_eq!(decoded.prev_chain_len, Some(50));
        assert_eq!(decoded.new_public_key.as_ref().unwrap(), &pk);
    }

    #[test]
    fn test_header_with_ciphertext() {
        let ct = [0xCD; XWING_CIPHERTEXT_SIZE];
        let header = MessageHeader::with_response(200, 5, ct);

        assert!(!header.has_new_pk());
        assert!(header.has_ciphertext());
        assert!(header.is_response());
        assert_eq!(header.encoded_size(), HEADER_SIZE_WITH_CT);

        let mut buf = [0u8; 2048];
        let size = header.encode(&mut buf).unwrap();

        let (decoded, _) = MessageHeader::decode(&buf[..size]).unwrap();

        assert!(decoded.has_ciphertext());
        assert!(decoded.is_response());
        assert_eq!(decoded.ciphertext.as_ref().unwrap(), &ct);
    }

    #[test]
    fn test_header_decode_too_short() {
        let buf = [0u8; 5]; // Too short
        let result = MessageHeader::decode(&buf);
        assert_eq!(result.unwrap_err(), MessageError::TooShort);
    }

    #[test]
    fn test_header_decode_invalid_version() {
        let mut buf = [0u8; MIN_HEADER_SIZE];
        buf[0] = 0xFF; // Invalid version
        let result = MessageHeader::decode(&buf);
        assert_eq!(result.unwrap_err(), MessageError::InvalidVersion);
    }

    #[test]
    fn test_ratchet_message_encode_decode() {
        let header = MessageHeader::new(1, 2);
        let header_mac = [0x11; MAC_SIZE];
        let nonce = [0x22; NONCE_SIZE];
        let ciphertext = vec![0x33; 100];

        let msg = RatchetMessage::new(header, header_mac, nonce, ciphertext.clone());

        let encoded = msg.encode_to_vec();
        let decoded = RatchetMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.header.epoch, 1);
        assert_eq!(decoded.header.message_num, 2);
        assert_eq!(decoded.header_mac, header_mac);
        assert_eq!(decoded.nonce, nonce);
        assert_eq!(decoded.ciphertext, ciphertext);
    }

    #[test]
    fn test_ratchet_message_fixed_encode_decode() {
        let header = MessageHeader::new(5, 10);
        let header_mac = [0xAA; MAC_SIZE];
        let nonce = [0xBB; NONCE_SIZE];
        let ciphertext = [0xCC; 50];

        let msg = RatchetMessageFixed::new(header, header_mac, nonce, &ciphertext).unwrap();

        let mut buf = [0u8; 4096];
        let size = msg.encode(&mut buf).unwrap();

        let decoded = RatchetMessageFixed::decode(&buf[..size]).unwrap();

        assert_eq!(decoded.header.epoch, 5);
        assert_eq!(decoded.header.message_num, 10);
        assert_eq!(decoded.ciphertext(), &ciphertext[..]);
    }

    #[test]
    fn test_ratchet_message_fixed_too_long() {
        let header = MessageHeader::new(0, 0);
        let header_mac = [0; MAC_SIZE];
        let nonce = [0; NONCE_SIZE];
        let ciphertext = [0; MAX_PAYLOAD_SIZE + TAG_SIZE + 1]; // Too long

        let result = RatchetMessageFixed::new(header, header_mac, nonce, &ciphertext);
        assert_eq!(result.unwrap_err(), MessageError::TooLong);
    }

    #[test]
    fn test_message_sizes() {
        // Verify size calculations match
        assert_eq!(MIN_HEADER_SIZE, 14);
        assert_eq!(HEADER_SIZE_WITH_PK, 14 + 4 + 1216);
        assert_eq!(HEADER_SIZE_WITH_CT, 14 + 1120);
        assert_eq!(HEADER_SIZE_WITH_PK_AND_CT, 14 + 4 + 1216 + 1120);
    }
}
