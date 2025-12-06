//! SRTP Key Derivation Function (RFC 3711 Section 4.3).
//!
//! Derives session keys from master key and salt.

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// SRTP crypto suite identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoSuite {
    /// AES-CM-128, HMAC-SHA1 with 80-bit auth tag.
    AesCm128HmacSha1_80,
    /// AES-CM-128, HMAC-SHA1 with 32-bit auth tag.
    AesCm128HmacSha1_32,
}

impl CryptoSuite {
    /// Parse crypto suite from string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "AES_CM_128_HMAC_SHA1_80" => Some(Self::AesCm128HmacSha1_80),
            "AES_CM_128_HMAC_SHA1_32" => Some(Self::AesCm128HmacSha1_32),
            _ => None,
        }
    }

    /// Get the authentication tag length in bytes.
    pub fn auth_tag_len(&self) -> usize {
        match self {
            Self::AesCm128HmacSha1_80 => 10, // 80 bits
            Self::AesCm128HmacSha1_32 => 4,  // 32 bits
        }
    }

    /// Get the master key length in bytes.
    pub fn master_key_len(&self) -> usize {
        16 // 128 bits for AES-128
    }

    /// Get the master salt length in bytes.
    pub fn master_salt_len(&self) -> usize {
        14 // 112 bits
    }

    /// Get the session key length in bytes.
    pub fn session_key_len(&self) -> usize {
        16 // 128 bits
    }

    /// Get the session salt length in bytes.
    pub fn session_salt_len(&self) -> usize {
        14 // 112 bits
    }

    /// Get the session auth key length in bytes.
    pub fn session_auth_key_len(&self) -> usize {
        20 // 160 bits for HMAC-SHA1
    }

    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AesCm128HmacSha1_80 => "AES_CM_128_HMAC_SHA1_80",
            Self::AesCm128HmacSha1_32 => "AES_CM_128_HMAC_SHA1_32",
        }
    }
}

impl std::fmt::Display for CryptoSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Key derivation labels from RFC 3711 Section 4.3.1.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Label {
    /// SRTP encryption key (0x00).
    SrtpEncryption = 0x00,
    /// SRTP authentication key (0x01).
    SrtpAuthentication = 0x01,
    /// SRTP salt (0x02).
    SrtpSalt = 0x02,
    /// SRTCP encryption key (0x03).
    SrtcpEncryption = 0x03,
    /// SRTCP authentication key (0x04).
    SrtcpAuthentication = 0x04,
    /// SRTCP salt (0x05).
    SrtcpSalt = 0x05,
}

/// Session keys derived from master key.
#[derive(Clone)]
pub struct SessionKeys {
    /// SRTP encryption key.
    pub srtp_enc_key: Vec<u8>,
    /// SRTP authentication key.
    pub srtp_auth_key: Vec<u8>,
    /// SRTP salt.
    pub srtp_salt: Vec<u8>,
    /// SRTCP encryption key.
    pub srtcp_enc_key: Vec<u8>,
    /// SRTCP authentication key.
    pub srtcp_auth_key: Vec<u8>,
    /// SRTCP salt.
    pub srtcp_salt: Vec<u8>,
}

impl SessionKeys {
    /// Derive session keys from master key and salt.
    ///
    /// Uses the PRF (Pseudo-Random Function) defined in RFC 3711 Section 4.3.
    pub fn derive(
        suite: CryptoSuite,
        master_key: &[u8],
        master_salt: &[u8],
    ) -> Result<Self, String> {
        // Validate input lengths
        if master_key.len() != suite.master_key_len() {
            return Err(format!(
                "Invalid master key length: {} (expected {})",
                master_key.len(),
                suite.master_key_len()
            ));
        }
        if master_salt.len() != suite.master_salt_len() {
            return Err(format!(
                "Invalid master salt length: {} (expected {})",
                master_salt.len(),
                suite.master_salt_len()
            ));
        }

        // Derive each session key
        let srtp_enc_key = derive_key(
            master_key,
            master_salt,
            Label::SrtpEncryption,
            0,
            suite.session_key_len(),
        )?;

        let srtp_auth_key = derive_key(
            master_key,
            master_salt,
            Label::SrtpAuthentication,
            0,
            suite.session_auth_key_len(),
        )?;

        let srtp_salt = derive_key(
            master_key,
            master_salt,
            Label::SrtpSalt,
            0,
            suite.session_salt_len(),
        )?;

        let srtcp_enc_key = derive_key(
            master_key,
            master_salt,
            Label::SrtcpEncryption,
            0,
            suite.session_key_len(),
        )?;

        let srtcp_auth_key = derive_key(
            master_key,
            master_salt,
            Label::SrtcpAuthentication,
            0,
            suite.session_auth_key_len(),
        )?;

        let srtcp_salt = derive_key(
            master_key,
            master_salt,
            Label::SrtcpSalt,
            0,
            suite.session_salt_len(),
        )?;

        Ok(Self {
            srtp_enc_key,
            srtp_auth_key,
            srtp_salt,
            srtcp_enc_key,
            srtcp_auth_key,
            srtcp_salt,
        })
    }
}

/// Derive a key using the SRTP PRF.
///
/// PRF is defined as AES-CM with the master key.
fn derive_key(
    master_key: &[u8],
    master_salt: &[u8],
    label: Label,
    index: u64,
    len: usize,
) -> Result<Vec<u8>, String> {
    // Build the 128-bit "x" value: salt XOR (label || r)
    // Where r is the key_derivation_rate (0 for our use case, meaning use index 0)
    let mut x = [0u8; 16];

    // Copy master salt (14 bytes) into x[0..14]
    x[..master_salt.len()].copy_from_slice(master_salt);

    // XOR with label at position 7 (RFC 3711 Appendix B)
    x[7] ^= label as u8;

    // XOR with 48-bit index at positions 8-13 (for key derivation rate = 0)
    // The index is always 0 for our simplified implementation
    let _ = index; // We ignore index for default key derivation rate

    // Use AES-CM with x as IV to generate key material
    // We need enough blocks to generate 'len' bytes
    let mut key_stream = vec![0u8; len.div_ceil(16) * 16];

    // Create AES-CTR cipher with master key and x as IV
    let mut iv = [0u8; 16];
    iv[..16].copy_from_slice(&x);

    let mut cipher = Aes128Ctr::new(master_key.into(), &iv.into());
    cipher.apply_keystream(&mut key_stream);

    // Return only the requested length
    key_stream.truncate(len);
    Ok(key_stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_suite_parse() {
        assert_eq!(
            CryptoSuite::parse("AES_CM_128_HMAC_SHA1_80"),
            Some(CryptoSuite::AesCm128HmacSha1_80)
        );
        assert_eq!(
            CryptoSuite::parse("AES_CM_128_HMAC_SHA1_32"),
            Some(CryptoSuite::AesCm128HmacSha1_32)
        );
        assert_eq!(
            CryptoSuite::parse("aes_cm_128_hmac_sha1_80"),
            Some(CryptoSuite::AesCm128HmacSha1_80)
        );
        assert_eq!(CryptoSuite::parse("UNKNOWN"), None);
    }

    #[test]
    fn test_crypto_suite_auth_tag_len() {
        assert_eq!(CryptoSuite::AesCm128HmacSha1_80.auth_tag_len(), 10);
        assert_eq!(CryptoSuite::AesCm128HmacSha1_32.auth_tag_len(), 4);
    }

    #[test]
    fn test_derive_session_keys() {
        let master_key = [0u8; 16];
        let master_salt = [0u8; 14];

        let keys = SessionKeys::derive(
            CryptoSuite::AesCm128HmacSha1_80,
            &master_key,
            &master_salt,
        )
        .unwrap();

        // Check key lengths
        assert_eq!(keys.srtp_enc_key.len(), 16);
        assert_eq!(keys.srtp_auth_key.len(), 20);
        assert_eq!(keys.srtp_salt.len(), 14);
        assert_eq!(keys.srtcp_enc_key.len(), 16);
        assert_eq!(keys.srtcp_auth_key.len(), 20);
        assert_eq!(keys.srtcp_salt.len(), 14);

        // Keys should be different
        assert_ne!(keys.srtp_enc_key, keys.srtcp_enc_key);
        assert_ne!(keys.srtp_auth_key, keys.srtcp_auth_key);
    }

    #[test]
    fn test_derive_invalid_key_length() {
        let master_key = [0u8; 8]; // Too short
        let master_salt = [0u8; 14];

        let result = SessionKeys::derive(
            CryptoSuite::AesCm128HmacSha1_80,
            &master_key,
            &master_salt,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_invalid_salt_length() {
        let master_key = [0u8; 16];
        let master_salt = [0u8; 8]; // Too short

        let result = SessionKeys::derive(
            CryptoSuite::AesCm128HmacSha1_80,
            &master_key,
            &master_salt,
        );
        assert!(result.is_err());
    }
}
