//! Random number utilities using cryptographic-quality PRNG.
//!
//! These functions replace time-based pseudo-random generation with
//! proper random number generation suitable for security-sensitive
//! identifiers like SSRC, Call-ID, and session IDs.

use rand::Rng;

/// Generate a cryptographically random u16.
///
/// Used for RTP sequence number initialization.
#[inline]
pub fn random_u16() -> u16 {
    rand::thread_rng().gen()
}

/// Generate a cryptographically random u32.
///
/// Used for RTP SSRC values and other identifiers.
#[inline]
pub fn random_u32() -> u32 {
    rand::thread_rng().gen()
}

/// Generate a cryptographically random u64.
///
/// Used for SDP session IDs.
#[inline]
pub fn random_u64() -> u64 {
    rand::thread_rng().gen()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_random_u16_distribution() {
        // Generate multiple values and verify they're different
        let values: HashSet<u16> = (0..100).map(|_| random_u16()).collect();
        // With 100 random u16 values, we should have at least 90 unique
        assert!(values.len() >= 90, "Random values should be distributed");
    }

    #[test]
    fn test_random_u32_distribution() {
        let values: HashSet<u32> = (0..100).map(|_| random_u32()).collect();
        // With 100 random u32 values, we should have 100 unique (collision extremely unlikely)
        assert_eq!(values.len(), 100, "All u32 values should be unique");
    }

    #[test]
    fn test_random_u64_distribution() {
        let values: HashSet<u64> = (0..100).map(|_| random_u64()).collect();
        assert_eq!(values.len(), 100, "All u64 values should be unique");
    }
}
