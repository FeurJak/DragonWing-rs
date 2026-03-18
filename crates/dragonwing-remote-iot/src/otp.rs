// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// OTP (One-Time Password) generation and validation

use rand::Rng;
use std::time::{Duration, Instant};

use crate::error::{RemoteIotError, Result};
use crate::DEFAULT_OTP_TIMEOUT_SECS;

/// A one-time password for authenticating phone connections.
///
/// The OTP is a 6-digit numeric code that the phone must provide
/// via WebSocket to complete the pairing process.
#[derive(Debug, Clone)]
pub struct Otp {
    /// The 6-digit OTP value
    value: String,
    /// When this OTP was created
    created_at: Instant,
    /// How long this OTP is valid for
    timeout: Duration,
}

impl Otp {
    /// Generate a new random 6-digit OTP
    pub fn generate() -> Self {
        Self::generate_with_timeout(Duration::from_secs(DEFAULT_OTP_TIMEOUT_SECS))
    }

    /// Generate a new OTP with a custom timeout
    pub fn generate_with_timeout(timeout: Duration) -> Self {
        let mut rng = rand::rng();
        let value: u32 = rng.random_range(0..1_000_000);
        Self {
            value: format!("{:06}", value),
            created_at: Instant::now(),
            timeout,
        }
    }

    /// Create an OTP with a specific value (for testing)
    #[cfg(test)]
    pub fn from_value(value: &str) -> Self {
        Self {
            value: value.to_string(),
            created_at: Instant::now(),
            timeout: Duration::from_secs(DEFAULT_OTP_TIMEOUT_SECS),
        }
    }

    /// Get the OTP value as a string
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Check if the OTP has expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.timeout
    }

    /// Get remaining time before expiration
    pub fn remaining_time(&self) -> Option<Duration> {
        let elapsed = self.created_at.elapsed();
        if elapsed > self.timeout {
            None
        } else {
            Some(self.timeout - elapsed)
        }
    }

    /// Validate a provided OTP value
    pub fn validate(&self, provided: &str) -> Result<()> {
        if self.is_expired() {
            return Err(RemoteIotError::OtpExpired {
                timeout_secs: self.timeout.as_secs(),
            });
        }

        if self.value != provided {
            return Err(RemoteIotError::InvalidOtp {
                expected: self.value.clone(),
                received: provided.to_string(),
            });
        }

        Ok(())
    }
}

impl std::fmt::Display for Otp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_otp_generation() {
        let otp = Otp::generate();
        assert_eq!(otp.value().len(), 6);
        assert!(otp.value().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_otp_validation() {
        let otp = Otp::from_value("123456");
        assert!(otp.validate("123456").is_ok());
        assert!(otp.validate("000000").is_err());
    }

    #[test]
    fn test_otp_expiration() {
        let otp = Otp::generate_with_timeout(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(10));
        assert!(otp.is_expired());
        assert!(otp.validate("000000").is_err());
    }
}
