//! DTLS-SRTP key exchange (RFC 5764).
//!
//! This module provides types and utilities for DTLS-SRTP key exchange,
//! including fingerprint handling, role negotiation, and key extraction.
//!
//! # Current Status: Partial Implementation
//!
//! **Note:** This module provides the foundational types for DTLS-SRTP but does NOT
//! include a full DTLS handshake implementation. The actual DTLS transport layer
//! would require integration with a TLS library (e.g., rustls, openssl, or ring).
//!
//! ## What IS implemented:
//! - [`Fingerprint`] - Certificate fingerprint parsing and generation for SDP
//! - [`DtlsRole`] - DTLS client/server role from SDP setup attribute
//! - [`SrtpProfile`] - SRTP protection profile negotiation
//! - [`DtlsSrtpKeys`] - Key material structure for SRTP session creation
//! - [`extract_srtp_keys`] - Extract SRTP keys from exported DTLS material
//! - [`parse_use_srtp_extension`] / [`build_use_srtp_extension`] - DTLS extension handling
//!
//! ## What is NOT implemented (future work):
//! - Full DTLS handshake state machine
//! - Certificate generation and management
//! - TLS record layer for UDP (DTLS)
//! - Retransmission handling for lost handshake messages
//! - Cookie exchange for DoS protection
//!
//! # Implementation Options
//!
//! To add full DTLS support, consider:
//!
//! 1. **rustls + webrtc-rs approach**: Use rustls with custom datagram transport
//! 2. **openssl**: Use the openssl crate's DTLS support
//! 3. **ring**: Lower-level crypto primitives with custom DTLS implementation
//!
//! # For SIP without WebRTC
//!
//! Traditional SIP applications typically use SDES (Session Description Exchange)
//! for SRTP key exchange rather than DTLS. See the [`crate::sdes`] module for
//! SDES-based key exchange which is fully implemented and works with most
//! SIP infrastructure.
//!
//! # SDP Attributes
//!
//! The fingerprint attribute in SDP is used to verify the peer's certificate:
//! ```text
//! a=fingerprint:sha-256 AB:CD:EF:...
//! a=setup:actpass
//! ```
//!
//! # Example (with hypothetical full implementation)
//!
//! ```rust,ignore
//! use mdsiprtp_srtp::dtls::{DtlsRole, Fingerprint, FingerprintHash};
//!
//! // Generate fingerprint for SDP
//! let fingerprint = dtls_context.local_fingerprint();
//! println!("a=fingerprint:{} {}", fingerprint.algorithm, fingerprint.value);
//!
//! // After DTLS handshake
//! let keys = dtls_context.export_keying_material()?;
//! let srtp_ctx = SrtpContext::from_dtls_keys(keys)?;
//! ```

use sha2::{Sha256, Digest};
use thiserror::Error;

/// DTLS-SRTP errors.
#[derive(Debug, Error)]
pub enum DtlsError {
    /// Handshake failed.
    #[error("DTLS handshake failed: {0}")]
    HandshakeFailed(String),

    /// Certificate verification failed.
    #[error("Certificate verification failed: fingerprint mismatch")]
    FingerprintMismatch,

    /// Key export failed.
    #[error("Failed to export keying material: {0}")]
    KeyExportFailed(String),

    /// Invalid state.
    #[error("Invalid DTLS state: {0}")]
    InvalidState(String),

    /// IO error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// OpenSSL error (when dtls feature enabled).
    #[error("OpenSSL error: {0}")]
    OpenSsl(String),
}

/// DTLS connection role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsRole {
    /// Active role (client, initiates handshake).
    Client,
    /// Passive role (server, responds to handshake).
    Server,
    /// Will accept either role based on setup attribute.
    ActPass,
}

impl DtlsRole {
    /// Parse from SDP setup attribute.
    pub fn from_sdp_setup(setup: &str) -> Option<Self> {
        match setup.to_lowercase().as_str() {
            "active" => Some(DtlsRole::Client),
            "passive" => Some(DtlsRole::Server),
            "actpass" => Some(DtlsRole::ActPass),
            _ => None,
        }
    }

    /// Convert to SDP setup attribute.
    pub fn to_sdp_setup(&self) -> &'static str {
        match self {
            DtlsRole::Client => "active",
            DtlsRole::Server => "passive",
            DtlsRole::ActPass => "actpass",
        }
    }
}

/// Hash algorithm for fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintHash {
    /// SHA-256 (recommended).
    Sha256,
    /// SHA-1 (legacy).
    Sha1,
}

impl FingerprintHash {
    /// Parse from SDP.
    pub fn from_sdp(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sha-256" => Some(FingerprintHash::Sha256),
            "sha-1" => Some(FingerprintHash::Sha1),
            _ => None,
        }
    }

    /// Convert to SDP format.
    pub fn to_sdp(&self) -> &'static str {
        match self {
            FingerprintHash::Sha256 => "sha-256",
            FingerprintHash::Sha1 => "sha-1",
        }
    }
}

/// Certificate fingerprint for SDP.
#[derive(Debug, Clone)]
pub struct Fingerprint {
    /// Hash algorithm.
    pub algorithm: FingerprintHash,
    /// Fingerprint bytes.
    pub value: Vec<u8>,
}

impl Fingerprint {
    /// Create fingerprint from certificate DER bytes.
    pub fn from_certificate_der(cert_der: &[u8], algorithm: FingerprintHash) -> Self {
        let value = match algorithm {
            FingerprintHash::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(cert_der);
                hasher.finalize().to_vec()
            }
            FingerprintHash::Sha1 => {
                use sha1::Sha1;
                let mut hasher = Sha1::new();
                hasher.update(cert_der);
                hasher.finalize().to_vec()
            }
        };

        Self { algorithm, value }
    }

    /// Parse fingerprint from SDP attribute.
    ///
    /// Format: `sha-256 AB:CD:EF:...`
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split_whitespace();
        let alg = parts.next()?;
        let hex = parts.next()?;

        let algorithm = FingerprintHash::from_sdp(alg)?;
        let value = hex
            .split(':')
            .filter_map(|h| u8::from_str_radix(h, 16).ok())
            .collect();

        Some(Self { algorithm, value })
    }

    /// Format fingerprint for SDP.
    pub fn to_sdp(&self) -> String {
        let hex = self.value
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":");
        format!("{} {}", self.algorithm.to_sdp(), hex)
    }

    /// Verify against another fingerprint.
    pub fn verify(&self, other: &Fingerprint) -> bool {
        self.algorithm == other.algorithm && self.value == other.value
    }
}

/// SRTP keying material exported from DTLS.
#[derive(Debug, Clone)]
pub struct DtlsSrtpKeys {
    /// Client master key.
    pub client_write_key: Vec<u8>,
    /// Server master key.
    pub server_write_key: Vec<u8>,
    /// Client master salt.
    pub client_write_salt: Vec<u8>,
    /// Server master salt.
    pub server_write_salt: Vec<u8>,
    /// SRTP protection profile.
    pub profile: SrtpProfile,
}

impl DtlsSrtpKeys {
    /// Get local keys based on role.
    pub fn local_keys(&self, role: DtlsRole) -> (&[u8], &[u8]) {
        match role {
            DtlsRole::Client | DtlsRole::ActPass => {
                (&self.client_write_key, &self.client_write_salt)
            }
            DtlsRole::Server => {
                (&self.server_write_key, &self.server_write_salt)
            }
        }
    }

    /// Get remote keys based on role.
    pub fn remote_keys(&self, role: DtlsRole) -> (&[u8], &[u8]) {
        match role {
            DtlsRole::Client | DtlsRole::ActPass => {
                (&self.server_write_key, &self.server_write_salt)
            }
            DtlsRole::Server => {
                (&self.client_write_key, &self.client_write_salt)
            }
        }
    }
}

/// SRTP protection profile (RFC 5764).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpProfile {
    /// AES-128 Counter Mode with 80-bit authentication tag.
    Aes128CmHmacSha1_80,
    /// AES-128 Counter Mode with 32-bit authentication tag.
    Aes128CmHmacSha1_32,
    /// AES-256 Counter Mode with 80-bit authentication tag.
    Aes256CmHmacSha1_80,
    /// AES-256 Counter Mode with 32-bit authentication tag.
    Aes256CmHmacSha1_32,
}

impl SrtpProfile {
    /// Profile ID as used in DTLS extension.
    pub fn id(&self) -> u16 {
        match self {
            SrtpProfile::Aes128CmHmacSha1_80 => 0x0001,
            SrtpProfile::Aes128CmHmacSha1_32 => 0x0002,
            SrtpProfile::Aes256CmHmacSha1_80 => 0x0003,
            SrtpProfile::Aes256CmHmacSha1_32 => 0x0004,
        }
    }

    /// Master key length in bytes.
    pub fn key_length(&self) -> usize {
        match self {
            SrtpProfile::Aes128CmHmacSha1_80 | SrtpProfile::Aes128CmHmacSha1_32 => 16,
            SrtpProfile::Aes256CmHmacSha1_80 | SrtpProfile::Aes256CmHmacSha1_32 => 32,
        }
    }

    /// Master salt length in bytes (always 14).
    pub fn salt_length(&self) -> usize {
        14
    }

    /// Total keying material length.
    pub fn keying_material_length(&self) -> usize {
        // 2 * (key + salt)
        2 * (self.key_length() + self.salt_length())
    }

    /// Parse from profile ID.
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x0001 => Some(SrtpProfile::Aes128CmHmacSha1_80),
            0x0002 => Some(SrtpProfile::Aes128CmHmacSha1_32),
            0x0003 => Some(SrtpProfile::Aes256CmHmacSha1_80),
            0x0004 => Some(SrtpProfile::Aes256CmHmacSha1_32),
            _ => None,
        }
    }
}

/// DTLS connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsState {
    /// Initial state.
    New,
    /// Handshake in progress.
    Connecting,
    /// Handshake complete.
    Connected,
    /// Connection failed.
    Failed,
    /// Connection closed.
    Closed,
}

/// DTLS configuration.
#[derive(Debug, Clone)]
pub struct DtlsConfig {
    /// Connection role.
    pub role: DtlsRole,
    /// SRTP profiles to offer (in preference order).
    pub srtp_profiles: Vec<SrtpProfile>,
    /// Certificate fingerprint hash.
    pub fingerprint_hash: FingerprintHash,
}

impl Default for DtlsConfig {
    fn default() -> Self {
        Self {
            role: DtlsRole::ActPass,
            srtp_profiles: vec![
                SrtpProfile::Aes128CmHmacSha1_80,
                SrtpProfile::Aes128CmHmacSha1_32,
            ],
            fingerprint_hash: FingerprintHash::Sha256,
        }
    }
}

/// Parse use-srtp extension value.
pub fn parse_use_srtp_extension(data: &[u8]) -> Option<SrtpProfile> {
    if data.len() < 4 {
        return None;
    }

    let profile_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + profile_len {
        return None;
    }

    // Return first supported profile
    let mut offset = 2;
    while offset + 2 <= 2 + profile_len {
        let profile_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
        if let Some(profile) = SrtpProfile::from_id(profile_id) {
            return Some(profile);
        }
        offset += 2;
    }

    None
}

/// Build use-srtp extension value.
pub fn build_use_srtp_extension(profiles: &[SrtpProfile]) -> Vec<u8> {
    let mut data = Vec::new();

    // Profile length (2 bytes per profile)
    let len = (profiles.len() * 2) as u16;
    data.extend_from_slice(&len.to_be_bytes());

    // Profiles
    for profile in profiles {
        data.extend_from_slice(&profile.id().to_be_bytes());
    }

    // MKI length (0 = no MKI)
    data.push(0);

    data
}

/// Extract SRTP keying material from exported bytes.
pub fn extract_srtp_keys(exported: &[u8], profile: SrtpProfile) -> Option<DtlsSrtpKeys> {
    let key_len = profile.key_length();
    let salt_len = profile.salt_length();
    let expected_len = 2 * (key_len + salt_len);

    if exported.len() < expected_len {
        return None;
    }

    let mut offset = 0;

    let client_write_key = exported[offset..offset + key_len].to_vec();
    offset += key_len;

    let server_write_key = exported[offset..offset + key_len].to_vec();
    offset += key_len;

    let client_write_salt = exported[offset..offset + salt_len].to_vec();
    offset += salt_len;

    let server_write_salt = exported[offset..offset + salt_len].to_vec();

    Some(DtlsSrtpKeys {
        client_write_key,
        server_write_key,
        client_write_salt,
        server_write_salt,
        profile,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_parse() {
        let s = "sha-256 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
        let fp = Fingerprint::parse(s).unwrap();

        assert_eq!(fp.algorithm, FingerprintHash::Sha256);
        assert_eq!(fp.value.len(), 32);
        assert_eq!(fp.value[0], 0xAB);
        assert_eq!(fp.value[1], 0xCD);
    }

    #[test]
    fn test_fingerprint_to_sdp() {
        let fp = Fingerprint {
            algorithm: FingerprintHash::Sha256,
            value: vec![0xAB, 0xCD, 0xEF],
        };

        let sdp = fp.to_sdp();
        assert!(sdp.starts_with("sha-256"));
        assert!(sdp.contains("AB:CD:EF"));
    }

    #[test]
    fn test_dtls_role_sdp() {
        assert_eq!(
            DtlsRole::from_sdp_setup("active"),
            Some(DtlsRole::Client)
        );
        assert_eq!(
            DtlsRole::from_sdp_setup("passive"),
            Some(DtlsRole::Server)
        );
        assert_eq!(
            DtlsRole::from_sdp_setup("actpass"),
            Some(DtlsRole::ActPass)
        );

        assert_eq!(DtlsRole::Client.to_sdp_setup(), "active");
        assert_eq!(DtlsRole::Server.to_sdp_setup(), "passive");
    }

    #[test]
    fn test_srtp_profile() {
        let profile = SrtpProfile::Aes128CmHmacSha1_80;
        assert_eq!(profile.id(), 0x0001);
        assert_eq!(profile.key_length(), 16);
        assert_eq!(profile.salt_length(), 14);
        assert_eq!(profile.keying_material_length(), 60);

        assert_eq!(SrtpProfile::from_id(0x0001), Some(SrtpProfile::Aes128CmHmacSha1_80));
    }

    #[test]
    fn test_use_srtp_extension() {
        let profiles = vec![
            SrtpProfile::Aes128CmHmacSha1_80,
            SrtpProfile::Aes128CmHmacSha1_32,
        ];

        let ext = build_use_srtp_extension(&profiles);

        // Length (2 bytes) + profiles (4 bytes) + mki length (1 byte) = 7 bytes
        assert_eq!(ext.len(), 7);

        let parsed = parse_use_srtp_extension(&ext);
        assert_eq!(parsed, Some(SrtpProfile::Aes128CmHmacSha1_80));
    }

    #[test]
    fn test_extract_srtp_keys() {
        let profile = SrtpProfile::Aes128CmHmacSha1_80;

        // Create fake exported material
        let mut exported = Vec::new();
        exported.extend_from_slice(&[1u8; 16]); // client key
        exported.extend_from_slice(&[2u8; 16]); // server key
        exported.extend_from_slice(&[3u8; 14]); // client salt
        exported.extend_from_slice(&[4u8; 14]); // server salt

        let keys = extract_srtp_keys(&exported, profile).unwrap();

        assert_eq!(keys.client_write_key, vec![1u8; 16]);
        assert_eq!(keys.server_write_key, vec![2u8; 16]);
        assert_eq!(keys.client_write_salt, vec![3u8; 14]);
        assert_eq!(keys.server_write_salt, vec![4u8; 14]);
    }

    #[test]
    fn test_dtls_keys_by_role() {
        let keys = DtlsSrtpKeys {
            client_write_key: vec![1],
            server_write_key: vec![2],
            client_write_salt: vec![3],
            server_write_salt: vec![4],
            profile: SrtpProfile::Aes128CmHmacSha1_80,
        };

        let (local_key, local_salt) = keys.local_keys(DtlsRole::Client);
        assert_eq!(local_key, &[1]);
        assert_eq!(local_salt, &[3]);

        let (remote_key, remote_salt) = keys.remote_keys(DtlsRole::Client);
        assert_eq!(remote_key, &[2]);
        assert_eq!(remote_salt, &[4]);
    }
}
