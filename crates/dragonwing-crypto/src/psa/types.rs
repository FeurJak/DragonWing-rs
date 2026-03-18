// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// PSA Secure Storage - Common Types
//
// This module defines the common types used by the PSA Secure Storage API,
// following the PSA Certified Secure Storage API specification.

use core::fmt;

/// Unique identifier for stored data entries.
///
/// UIDs are 32-bit by default (or 64-bit with `CONFIG_SECURE_STORAGE_64_BIT_UID`).
/// Applications should define their own UID allocation strategy.
///
/// # Example UID Allocation Strategy
///
/// ```text
/// 0x0000_0000          - Reserved (invalid)
/// 0x0000_0001-0x0000_00FF - System/internal use
/// 0x0000_0100-0x0000_0FFF - PSA Crypto key storage (managed by mbedTLS)
/// 0x0000_1000-0x0FFF_FFFF - Application-defined
/// ```
pub type StorageUid = u32;

/// Flags indicating the properties of a storage entry.
///
/// These flags are specified when creating an entry and affect how
/// the entry can be accessed and modified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StorageFlags(pub u32);

impl StorageFlags {
    /// No special flags - entry can be read, written, and deleted.
    pub const NONE: Self = Self(0);

    /// The entry cannot be modified or deleted after creation.
    /// Use this for immutable data like device certificates or root keys.
    pub const WRITE_ONCE: Self = Self(1 << 0);

    /// The entry is public and only requires integrity protection, not confidentiality.
    /// The data will be authenticated but not encrypted.
    pub const NO_CONFIDENTIALITY: Self = Self(1 << 1);

    /// The entry does not require replay protection.
    /// This may improve performance but reduces security guarantees.
    pub const NO_REPLAY_PROTECTION: Self = Self(1 << 2);

    /// Combine multiple flags using bitwise OR.
    #[inline]
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Check if a flag is set.
    #[inline]
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }
}

impl core::ops::BitOr for StorageFlags {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Metadata about a stored entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct StorageInfo {
    /// The allocated capacity of the storage associated with the entry.
    pub capacity: usize,
    /// The current size of the entry's data in bytes.
    pub size: usize,
    /// The flags that were used when the entry was created.
    pub flags: StorageFlags,
}

impl fmt::Display for StorageInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "StorageInfo {{ capacity: {}, size: {}, flags: 0x{:08x} }}",
            self.capacity, self.size, self.flags.0
        )
    }
}

// ============================================================================
// PSA Crypto Types
// ============================================================================

/// Key identifier for persistent keys.
///
/// Key IDs in the range `0x0001_0000` to `0x0001_FFFF` are reserved for
/// application use. IDs outside this range may be used by the system.
pub type KeyId = u32;

/// Key ID ranges defined by PSA/Zephyr
pub mod key_id {
    use super::KeyId;

    /// Start of the application key ID range
    pub const APPLICATION_MIN: KeyId = 0x0001_0000;
    /// End of the application key ID range
    pub const APPLICATION_MAX: KeyId = 0x0001_FFFF;

    /// Check if a key ID is in the valid application range
    #[inline]
    pub const fn is_valid_application_id(id: KeyId) -> bool {
        id >= APPLICATION_MIN && id <= APPLICATION_MAX
    }
}

/// Key type identifiers.
///
/// These identify the type of cryptographic key (algorithm family and key structure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyType {
    /// Raw data (not a cryptographic key)
    RawData = 0x1001,
    /// HMAC key
    Hmac = 0x1100,
    /// AES key (128, 192, or 256 bits)
    Aes = 0x2400,
    /// ChaCha20 key (256 bits)
    ChaCha20 = 0x2004,
    /// RSA key pair
    RsaKeyPair = 0x7001,
    /// RSA public key
    RsaPublicKey = 0x4001,
    /// Elliptic curve key pair (generic)
    EccKeyPair = 0x7100,
    /// Elliptic curve public key (generic)
    EccPublicKey = 0x4100,
}

impl KeyType {
    /// Get the raw PSA key type value
    #[inline]
    pub const fn as_raw(self) -> u32 {
        self as u32
    }
}

/// Algorithm identifiers for key operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Algorithm {
    /// No algorithm (for raw data keys)
    None = 0,
    /// AES-CTR mode
    AesCtr = 0x04c01000,
    /// AES-GCM authenticated encryption
    AesGcm = 0x05500100,
    /// ChaCha20-Poly1305 authenticated encryption
    ChaCha20Poly1305 = 0x05100500,
    /// HMAC with SHA-256
    HmacSha256 = 0x03800009,
    /// ECDSA with SHA-256
    EcdsaSha256 = 0x06000609,
    /// ECDH key agreement
    Ecdh = 0x09020000,
}

impl Algorithm {
    /// Get the raw PSA algorithm value
    #[inline]
    pub const fn as_raw(self) -> u32 {
        self as u32
    }
}

/// Key usage flags indicating what operations are permitted with a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyUsageFlags(pub u32);

impl KeyUsageFlags {
    /// No usage flags - key cannot be used for any operation
    pub const NONE: Self = Self(0);
    /// Key can be exported
    pub const EXPORT: Self = Self(1 << 0);
    /// Key can be copied
    pub const COPY: Self = Self(1 << 1);
    /// Key can be used for encryption
    pub const ENCRYPT: Self = Self(1 << 8);
    /// Key can be used for decryption
    pub const DECRYPT: Self = Self(1 << 9);
    /// Key can be used for signing (message or hash)
    pub const SIGN_MESSAGE: Self = Self(1 << 10);
    /// Key can be used for verifying signatures
    pub const VERIFY_MESSAGE: Self = Self(1 << 11);
    /// Key can be used for signing hashes
    pub const SIGN_HASH: Self = Self(1 << 12);
    /// Key can be used for verifying hash signatures
    pub const VERIFY_HASH: Self = Self(1 << 13);
    /// Key can be used for key derivation
    pub const DERIVE: Self = Self(1 << 14);

    /// Combine multiple flags
    #[inline]
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Check if a flag is set
    #[inline]
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }
}

impl core::ops::BitOr for KeyUsageFlags {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Key lifetime - volatile or persistent
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KeyLifetime {
    /// Key is stored in volatile memory and lost on reset
    Volatile = 0x00000000,
    /// Key is stored in persistent storage and survives reset
    Persistent = 0x00000001,
}

impl Default for KeyLifetime {
    fn default() -> Self {
        Self::Volatile
    }
}

/// Key attributes builder for creating keys with specific properties.
///
/// # Example
///
/// ```rust,no_run
/// use dragonwing_crypto::psa::{KeyAttributes, KeyType, Algorithm, KeyUsageFlags, KeyLifetime};
///
/// let attrs = KeyAttributes::new()
///     .with_type(KeyType::Aes)
///     .with_bits(256)
///     .with_algorithm(Algorithm::AesGcm)
///     .with_usage(KeyUsageFlags::ENCRYPT | KeyUsageFlags::DECRYPT)
///     .with_lifetime(KeyLifetime::Persistent)
///     .with_id(0x0001_0001);
/// ```
#[derive(Debug, Clone, Default)]
pub struct KeyAttributes {
    /// Key type
    pub key_type: Option<KeyType>,
    /// Key size in bits
    pub bits: usize,
    /// Permitted algorithm
    pub algorithm: Option<Algorithm>,
    /// Usage flags
    pub usage: KeyUsageFlags,
    /// Lifetime (volatile or persistent)
    pub lifetime: KeyLifetime,
    /// Key ID (for persistent keys)
    pub id: Option<KeyId>,
}

impl KeyAttributes {
    /// Create a new key attributes builder with default values.
    #[inline]
    pub const fn new() -> Self {
        Self {
            key_type: None,
            bits: 0,
            algorithm: None,
            usage: KeyUsageFlags::NONE,
            lifetime: KeyLifetime::Volatile,
            id: None,
        }
    }

    /// Set the key type.
    #[inline]
    pub const fn with_type(mut self, key_type: KeyType) -> Self {
        self.key_type = Some(key_type);
        self
    }

    /// Set the key size in bits.
    #[inline]
    pub const fn with_bits(mut self, bits: usize) -> Self {
        self.bits = bits;
        self
    }

    /// Set the permitted algorithm.
    #[inline]
    pub const fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Set the usage flags.
    #[inline]
    pub const fn with_usage(mut self, usage: KeyUsageFlags) -> Self {
        self.usage = usage;
        self
    }

    /// Set the key lifetime.
    #[inline]
    pub const fn with_lifetime(mut self, lifetime: KeyLifetime) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Set the key ID (makes the key persistent).
    #[inline]
    pub const fn with_id(mut self, id: KeyId) -> Self {
        self.id = Some(id);
        self.lifetime = KeyLifetime::Persistent;
        self
    }

    /// Make the key persistent with the specified ID.
    #[inline]
    pub const fn persistent(self, id: KeyId) -> Self {
        self.with_id(id)
    }

    /// Make the key volatile (default).
    #[inline]
    pub const fn volatile(mut self) -> Self {
        self.lifetime = KeyLifetime::Volatile;
        self.id = None;
        self
    }
}
