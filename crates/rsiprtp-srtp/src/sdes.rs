//! SDES (SDP Security Descriptions) parsing (RFC 4568).
//!
//! Parses a=crypto attributes for SRTP key exchange.

use crate::kdf::CryptoSuite;

/// SDES crypto attribute.
///
/// Represents a parsed `a=crypto:` line from SDP.
#[derive(Debug, Clone)]
pub struct SdesAttribute {
    /// Tag number (unique identifier within the SDP).
    pub tag: u32,
    /// Crypto suite.
    pub crypto_suite: CryptoSuite,
    /// Master key (16 bytes for AES-128).
    pub master_key: Vec<u8>,
    /// Master salt (14 bytes).
    pub master_salt: Vec<u8>,
    /// Optional lifetime (2^n packets).
    pub lifetime: Option<u64>,
    /// Optional MKI (Master Key Identifier).
    pub mki: Option<(u32, u8)>, // (value, length in bytes)
}

impl SdesAttribute {
    /// Parse an SDES attribute from a string.
    ///
    /// Format: `<tag> <crypto-suite> <key-params> [session-params]`
    ///
    /// Key params format: `inline:<base64-key>[|lifetime][|MKI:value:length]`
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() < 3 {
            return Err("Invalid SDES attribute format".into());
        }

        // Parse tag
        let tag: u32 = parts[0].parse().map_err(|_| "Invalid tag number")?;

        // Parse crypto suite
        let crypto_suite = CryptoSuite::parse(parts[1])
            .ok_or_else(|| format!("Unknown crypto suite: {}", parts[1]))?;

        // Parse key params
        let key_params = parts[2];
        if !key_params.starts_with("inline:") {
            return Err("Key params must start with 'inline:'".into());
        }

        let key_data = &key_params[7..]; // Skip "inline:"
        let parsed = parse_key_params(key_data)?;

        Ok(Self {
            tag,
            crypto_suite,
            master_key: parsed.master_key,
            master_salt: parsed.master_salt,
            lifetime: parsed.lifetime,
            mki: parsed.mki,
        })
    }

    /// Generate an SDES attribute string.
    pub fn to_sdp(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        // Concatenate master key and salt for base64 encoding
        let mut key_material = self.master_key.clone();
        key_material.extend_from_slice(&self.master_salt);
        let key_b64 = STANDARD.encode(&key_material);

        let mut result = format!("{} {} inline:{}", self.tag, self.crypto_suite, key_b64);

        if let Some(lifetime) = self.lifetime {
            result.push_str(&format!("|2^{}", (lifetime as f64).log2() as u32));
        }

        if let Some((value, len)) = self.mki {
            result.push_str(&format!("|{}:{}", value, len));
        }

        result
    }

    /// Create a new SDES attribute with random key material.
    pub fn new_random(tag: u32, crypto_suite: CryptoSuite) -> Self {
        use rand::RngCore;

        let mut rng = rand::thread_rng();

        let mut master_key = vec![0u8; crypto_suite.master_key_len()];
        rng.fill_bytes(&mut master_key);

        let mut master_salt = vec![0u8; crypto_suite.master_salt_len()];
        rng.fill_bytes(&mut master_salt);

        Self {
            tag,
            crypto_suite,
            master_key,
            master_salt,
            lifetime: None,
            mki: None,
        }
    }
}

/// Parsed key parameters from SDES.
struct ParsedKeyParams {
    master_key: Vec<u8>,
    master_salt: Vec<u8>,
    lifetime: Option<u64>,
    mki: Option<(u32, u8)>,
}

/// Parse key params from base64-encoded string.
fn parse_key_params(s: &str) -> Result<ParsedKeyParams, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    // Split by | for optional lifetime and MKI
    let parts: Vec<&str> = s.split('|').collect();

    // Decode base64 key material (key + salt = 30 bytes for AES-128)
    let key_material = STANDARD
        .decode(parts[0])
        .map_err(|e| format!("Invalid base64: {}", e))?;

    if key_material.len() != 30 {
        return Err(format!(
            "Invalid key material length: {} (expected 30)",
            key_material.len()
        ));
    }

    let master_key = key_material[..16].to_vec();
    let master_salt = key_material[16..].to_vec();

    let mut lifetime = None;
    let mut mki = None;

    // Parse optional parameters
    for part in parts.iter().skip(1) {
        if let Some(exp_str) = part.strip_prefix("2^") {
            // Lifetime
            let exp: u32 = exp_str.parse().map_err(|_| "Invalid lifetime exponent")?;
            lifetime = Some(1u64 << exp);
        } else if part.contains(':') {
            // MKI
            let mki_parts: Vec<&str> = part.split(':').collect();
            if mki_parts.len() == 2 {
                let value: u32 = mki_parts[0].parse().map_err(|_| "Invalid MKI value")?;
                let len: u8 = mki_parts[1].parse().map_err(|_| "Invalid MKI length")?;
                mki = Some((value, len));
            }
        }
    }

    Ok(ParsedKeyParams {
        master_key,
        master_salt,
        lifetime,
        mki,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sdes_basic() {
        // 30 bytes = 40 base64 chars (no padding needed)
        let sdes = SdesAttribute::parse(
            "1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap();

        assert_eq!(sdes.tag, 1);
        assert_eq!(sdes.crypto_suite, CryptoSuite::AesCm128HmacSha1_80);
        assert_eq!(sdes.master_key.len(), 16);
        assert_eq!(sdes.master_salt.len(), 14);
        assert!(sdes.lifetime.is_none());
        assert!(sdes.mki.is_none());
    }

    #[test]
    fn test_parse_sdes_with_lifetime() {
        let sdes = SdesAttribute::parse(
            "1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|2^31",
        )
        .unwrap();

        assert_eq!(sdes.lifetime, Some(1u64 << 31));
    }

    #[test]
    fn test_parse_sdes_with_mki() {
        let sdes = SdesAttribute::parse(
            "1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|1:4",
        )
        .unwrap();

        assert_eq!(sdes.mki, Some((1, 4)));
    }

    #[test]
    fn test_parse_sdes_with_invalid_mki_format() {
        let sdes = SdesAttribute::parse(
            "1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|1:2:3",
        )
        .unwrap();

        assert!(sdes.mki.is_none());
    }

    #[test]
    fn test_parse_sdes_with_unknown_param() {
        let sdes = SdesAttribute::parse(
            "1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|foo",
        )
        .unwrap();

        assert!(sdes.lifetime.is_none());
        assert!(sdes.mki.is_none());
    }

    #[test]
    fn test_parse_sdes_invalid_suite() {
        let result = SdesAttribute::parse(
            "1 UNKNOWN_SUITE inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sdes_to_sdp() {
        let sdes = SdesAttribute {
            tag: 1,
            crypto_suite: CryptoSuite::AesCm128HmacSha1_80,
            master_key: vec![0u8; 16],
            master_salt: vec![0u8; 14],
            lifetime: None,
            mki: None,
        };

        let sdp = sdes.to_sdp();
        assert!(sdp.contains("AES_CM_128_HMAC_SHA1_80"));
        assert!(sdp.contains("inline:"));
    }

    #[test]
    fn test_new_random() {
        let sdes = SdesAttribute::new_random(1, CryptoSuite::AesCm128HmacSha1_80);

        assert_eq!(sdes.tag, 1);
        assert_eq!(sdes.master_key.len(), 16);
        assert_eq!(sdes.master_salt.len(), 14);

        // Verify key is not all zeros (extremely unlikely for random)
        assert!(!sdes.master_key.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_roundtrip() {
        let original = SdesAttribute::new_random(2, CryptoSuite::AesCm128HmacSha1_32);
        let sdp = original.to_sdp();
        let parsed = SdesAttribute::parse(&sdp).unwrap();

        assert_eq!(parsed.tag, original.tag);
        assert_eq!(parsed.crypto_suite, original.crypto_suite);
        assert_eq!(parsed.master_key, original.master_key);
        assert_eq!(parsed.master_salt, original.master_salt);
    }

    // Additional tests for better coverage

    #[test]
    fn test_parse_too_few_parts() {
        let result = SdesAttribute::parse("1 AES_CM_128_HMAC_SHA1_80");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid SDES attribute format"));
    }

    #[test]
    fn test_parse_invalid_tag() {
        let result = SdesAttribute::parse(
            "notanumber AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid tag"));
    }

    #[test]
    fn test_parse_no_inline_prefix() {
        let result = SdesAttribute::parse(
            "1 AES_CM_128_HMAC_SHA1_80 noprefix:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("inline:"));
    }

    #[test]
    fn test_parse_invalid_base64() {
        let result = SdesAttribute::parse("1 AES_CM_128_HMAC_SHA1_80 inline:!!!notvalidbase64!!!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid base64"));
    }

    #[test]
    fn test_parse_wrong_key_length() {
        // Too short key material (only 10 bytes encoded)
        let result = SdesAttribute::parse("1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAA==");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid key material length"));
    }

    #[test]
    fn test_to_sdp_with_lifetime() {
        let sdes = SdesAttribute {
            tag: 1,
            crypto_suite: CryptoSuite::AesCm128HmacSha1_80,
            master_key: vec![0u8; 16],
            master_salt: vec![0u8; 14],
            lifetime: Some(1u64 << 31),
            mki: None,
        };

        let sdp = sdes.to_sdp();
        assert!(sdp.contains("|2^31"));
    }

    #[test]
    fn test_to_sdp_with_mki() {
        let sdes = SdesAttribute {
            tag: 1,
            crypto_suite: CryptoSuite::AesCm128HmacSha1_80,
            master_key: vec![0u8; 16],
            master_salt: vec![0u8; 14],
            lifetime: None,
            mki: Some((1, 4)),
        };

        let sdp = sdes.to_sdp();
        assert!(sdp.contains("|1:4"));
    }

    #[test]
    fn test_to_sdp_with_lifetime_and_mki() {
        let sdes = SdesAttribute {
            tag: 1,
            crypto_suite: CryptoSuite::AesCm128HmacSha1_80,
            master_key: vec![0u8; 16],
            master_salt: vec![0u8; 14],
            lifetime: Some(1u64 << 48),
            mki: Some((2, 2)),
        };

        let sdp = sdes.to_sdp();
        assert!(sdp.contains("|2^48"));
        assert!(sdp.contains("|2:2"));
    }

    #[test]
    fn test_sdes_attribute_debug() {
        let sdes = SdesAttribute::new_random(1, CryptoSuite::AesCm128HmacSha1_80);
        let debug = format!("{:?}", sdes);
        assert!(debug.contains("SdesAttribute"));
        assert!(debug.contains("tag"));
    }

    #[test]
    fn test_sdes_attribute_clone() {
        let sdes = SdesAttribute::new_random(1, CryptoSuite::AesCm128HmacSha1_80);
        let cloned = sdes.clone();
        assert_eq!(sdes.tag, cloned.tag);
        assert_eq!(sdes.crypto_suite, cloned.crypto_suite);
        assert_eq!(sdes.master_key, cloned.master_key);
        assert_eq!(sdes.master_salt, cloned.master_salt);
    }

    #[test]
    fn test_parse_with_all_optional_params() {
        let sdes = SdesAttribute::parse(
            "1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|2^20|3:2",
        )
        .unwrap();

        assert_eq!(sdes.tag, 1);
        assert_eq!(sdes.lifetime, Some(1u64 << 20));
        assert_eq!(sdes.mki, Some((3, 2)));
    }

    #[test]
    fn test_parse_32_bit_crypto_suite() {
        let sdes = SdesAttribute::parse(
            "1 AES_CM_128_HMAC_SHA1_32 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap();

        assert_eq!(sdes.crypto_suite, CryptoSuite::AesCm128HmacSha1_32);
    }

    #[test]
    fn test_new_random_different_keys() {
        let sdes1 = SdesAttribute::new_random(1, CryptoSuite::AesCm128HmacSha1_80);
        let sdes2 = SdesAttribute::new_random(2, CryptoSuite::AesCm128HmacSha1_80);

        // Keys should be different (with overwhelming probability)
        assert_ne!(sdes1.master_key, sdes2.master_key);
    }

    #[test]
    fn test_roundtrip_with_80_bit_suite() {
        let original = SdesAttribute::new_random(1, CryptoSuite::AesCm128HmacSha1_80);
        let sdp = original.to_sdp();
        let parsed = SdesAttribute::parse(&sdp).unwrap();

        assert_eq!(parsed.crypto_suite, CryptoSuite::AesCm128HmacSha1_80);
    }

    #[test]
    fn test_empty_input() {
        let result = SdesAttribute::parse("");
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_only_input() {
        let result = SdesAttribute::parse("   ");
        assert!(result.is_err());
    }

    #[test]
    fn test_tag_number_ranges() {
        // Tag 0
        let sdes = SdesAttribute::parse(
            "0 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap();
        assert_eq!(sdes.tag, 0);

        // Large tag number
        let sdes = SdesAttribute::parse(
            "999 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .unwrap();
        assert_eq!(sdes.tag, 999);
    }

    #[test]
    fn test_invalid_mki_value() {
        // MKI with invalid value format (not parseable)
        let result = SdesAttribute::parse(
            "1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|abc:4",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_mki_length() {
        let result = SdesAttribute::parse(
            "1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|1:abc",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_lifetime_exponent() {
        let result = SdesAttribute::parse(
            "1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|2^abc",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_lifetime_and_mki() {
        let sdes = SdesAttribute::parse(
            "1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|2^4|1:4",
        )
        .unwrap();
        assert_eq!(sdes.lifetime, Some(1u64 << 4));
        assert_eq!(sdes.mki, Some((1, 4)));
    }

    #[test]
    fn test_mki_with_single_colon() {
        // MKI with only one part after split (should fail to parse as MKI)
        let result = SdesAttribute::parse(
            "1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|singlepart:",
        );
        assert!(result.is_err());
    }
}
