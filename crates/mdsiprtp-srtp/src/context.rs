//! SRTP/SRTCP context for encryption and decryption.
//!
//! Implements RFC 3711 packet protection.

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;
use bytes::{Bytes, BytesMut};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::kdf::{CryptoSuite, SessionKeys};

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type HmacSha1 = Hmac<Sha1>;

/// Minimum RTP header size.
const RTP_HEADER_SIZE: usize = 12;

/// SRTP context for encrypting/decrypting RTP packets.
pub struct SrtpContext {
    /// Crypto suite.
    suite: CryptoSuite,
    /// Session keys.
    keys: SessionKeys,
    /// Rollover counter (ROC) for sender.
    sender_roc: u32,
    /// Rollover counter (ROC) for receiver.
    receiver_roc: u32,
    /// Highest sequence number seen.
    highest_seq: u16,
    /// Whether first packet has been received.
    first_packet: bool,
}

impl SrtpContext {
    /// Create a new SRTP context from master key and salt.
    pub fn new(suite: CryptoSuite, master_key: &[u8], master_salt: &[u8]) -> Result<Self, String> {
        let keys = SessionKeys::derive(suite, master_key, master_salt)?;
        Ok(Self {
            suite,
            keys,
            sender_roc: 0,
            receiver_roc: 0,
            highest_seq: 0,
            first_packet: true,
        })
    }

    /// Protect (encrypt + authenticate) an RTP packet.
    ///
    /// Returns the SRTP packet with encrypted payload and authentication tag.
    pub fn protect(&mut self, rtp: &[u8]) -> Result<Bytes, String> {
        if rtp.len() < RTP_HEADER_SIZE {
            return Err("RTP packet too short".into());
        }

        // Parse sequence number
        let seq = u16::from_be_bytes([rtp[2], rtp[3]]);

        // Update sender ROC
        if seq < 0x8000 && self.highest_seq > 0x8000 {
            self.sender_roc = self.sender_roc.wrapping_add(1);
        }
        self.highest_seq = seq;

        // Get SSRC
        let ssrc = u32::from_be_bytes([rtp[8], rtp[9], rtp[10], rtp[11]]);

        // Calculate packet index (48 bits)
        let index = ((self.sender_roc as u64) << 16) | (seq as u64);

        // Build IV for AES-CM
        let iv = build_iv(&self.keys.srtp_salt, ssrc, index);

        // Encrypt payload (leave header unencrypted)
        let header_len = get_rtp_header_len(rtp)?;
        let mut output = BytesMut::with_capacity(rtp.len() + self.suite.auth_tag_len());

        // Copy header unencrypted
        output.extend_from_slice(&rtp[..header_len]);

        // Encrypt payload
        let mut payload = rtp[header_len..].to_vec();
        let mut cipher = Aes128Ctr::new((&self.keys.srtp_enc_key[..]).into(), &iv.into());
        cipher.apply_keystream(&mut payload);
        output.extend_from_slice(&payload);

        // Calculate authentication tag
        let tag = self.compute_auth_tag(&output, self.sender_roc);
        output.extend_from_slice(&tag[..self.suite.auth_tag_len()]);

        Ok(output.freeze())
    }

    /// Unprotect (verify + decrypt) an SRTP packet.
    ///
    /// Returns the original RTP packet.
    pub fn unprotect(&mut self, srtp: &[u8]) -> Result<Bytes, String> {
        let tag_len = self.suite.auth_tag_len();
        if srtp.len() < RTP_HEADER_SIZE + tag_len {
            return Err("SRTP packet too short".into());
        }

        // Split packet and tag
        let packet = &srtp[..srtp.len() - tag_len];
        let received_tag = &srtp[srtp.len() - tag_len..];

        // Parse sequence number
        let seq = u16::from_be_bytes([packet[2], packet[3]]);

        // Estimate ROC based on sequence number
        let roc = if self.first_packet {
            self.first_packet = false;
            self.highest_seq = seq;
            0
        } else {
            estimate_roc(self.receiver_roc, self.highest_seq, seq)
        };

        // Verify authentication tag
        let expected_tag = self.compute_auth_tag(packet, roc);
        if !constant_time_compare(&expected_tag[..tag_len], received_tag) {
            return Err("Authentication failed".into());
        }

        // Update receiver state
        let index = ((roc as u64) << 16) | (seq as u64);
        let current_index = ((self.receiver_roc as u64) << 16) | (self.highest_seq as u64);
        if index > current_index {
            self.receiver_roc = roc;
            self.highest_seq = seq;
        }

        // Get SSRC
        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);

        // Build IV for AES-CM
        let iv = build_iv(&self.keys.srtp_salt, ssrc, index);

        // Decrypt payload
        let header_len = get_rtp_header_len(packet)?;
        let mut output = BytesMut::with_capacity(packet.len());

        // Copy header
        output.extend_from_slice(&packet[..header_len]);

        // Decrypt payload
        let mut payload = packet[header_len..].to_vec();
        let mut cipher = Aes128Ctr::new((&self.keys.srtp_enc_key[..]).into(), &iv.into());
        cipher.apply_keystream(&mut payload);
        output.extend_from_slice(&payload);

        Ok(output.freeze())
    }

    /// Compute authentication tag using HMAC-SHA1.
    fn compute_auth_tag(&self, packet: &[u8], roc: u32) -> [u8; 20] {
        let mut mac =
            HmacSha1::new_from_slice(&self.keys.srtp_auth_key).expect("HMAC key length is valid");

        mac.update(packet);
        mac.update(&roc.to_be_bytes());

        let result = mac.finalize();
        let mut tag = [0u8; 20];
        tag.copy_from_slice(&result.into_bytes());
        tag
    }
}

/// SRTCP context for encrypting/decrypting RTCP packets.
pub struct SrtcpContext {
    /// Crypto suite.
    suite: CryptoSuite,
    /// Session keys.
    keys: SessionKeys,
    /// SRTCP index (31 bits + E flag).
    index: u32,
}

impl SrtcpContext {
    /// Create a new SRTCP context from master key and salt.
    pub fn new(suite: CryptoSuite, master_key: &[u8], master_salt: &[u8]) -> Result<Self, String> {
        let keys = SessionKeys::derive(suite, master_key, master_salt)?;
        Ok(Self {
            suite,
            keys,
            index: 0,
        })
    }

    /// Protect (encrypt + authenticate) an RTCP packet.
    pub fn protect(&mut self, rtcp: &[u8]) -> Result<Bytes, String> {
        if rtcp.len() < 8 {
            return Err("RTCP packet too short".into());
        }

        // Get SSRC (from first RTCP packet in compound)
        let ssrc = u32::from_be_bytes([rtcp[4], rtcp[5], rtcp[6], rtcp[7]]);

        // Set E flag (encryption enabled) and increment index
        let srtcp_index = 0x80000000 | self.index;
        self.index = (self.index + 1) & 0x7FFFFFFF;

        // Build IV
        let iv = build_srtcp_iv(&self.keys.srtcp_salt, ssrc, srtcp_index);

        // Encrypt (skip first 8 bytes: version/padding/count/pt/length/ssrc)
        let mut output = BytesMut::with_capacity(rtcp.len() + 4 + self.suite.auth_tag_len());

        // Copy header unencrypted (8 bytes)
        output.extend_from_slice(&rtcp[..8]);

        // Encrypt payload
        let mut payload = rtcp[8..].to_vec();
        let mut cipher = Aes128Ctr::new((&self.keys.srtcp_enc_key[..]).into(), &iv.into());
        cipher.apply_keystream(&mut payload);
        output.extend_from_slice(&payload);

        // Append SRTCP index
        output.extend_from_slice(&srtcp_index.to_be_bytes());

        // Calculate authentication tag
        let tag = self.compute_auth_tag(&output);
        output.extend_from_slice(&tag[..self.suite.auth_tag_len()]);

        Ok(output.freeze())
    }

    /// Unprotect (verify + decrypt) an SRTCP packet.
    pub fn unprotect(&mut self, srtcp: &[u8]) -> Result<Bytes, String> {
        let tag_len = self.suite.auth_tag_len();
        if srtcp.len() < 8 + 4 + tag_len {
            return Err("SRTCP packet too short".into());
        }

        // Split packet, index, and tag
        let packet_with_index = &srtcp[..srtcp.len() - tag_len];
        let received_tag = &srtcp[srtcp.len() - tag_len..];

        // Verify authentication tag
        let expected_tag = self.compute_auth_tag(packet_with_index);
        if !constant_time_compare(&expected_tag[..tag_len], received_tag) {
            return Err("Authentication failed".into());
        }

        // Extract SRTCP index
        let index_offset = packet_with_index.len() - 4;
        let srtcp_index = u32::from_be_bytes([
            packet_with_index[index_offset],
            packet_with_index[index_offset + 1],
            packet_with_index[index_offset + 2],
            packet_with_index[index_offset + 3],
        ]);

        let is_encrypted = (srtcp_index & 0x80000000) != 0;
        let packet = &packet_with_index[..index_offset];

        if !is_encrypted {
            // Not encrypted, just return the packet
            return Ok(Bytes::copy_from_slice(packet));
        }

        // Get SSRC
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        // Build IV
        let iv = build_srtcp_iv(&self.keys.srtcp_salt, ssrc, srtcp_index);

        // Decrypt payload
        let mut output = BytesMut::with_capacity(packet.len());

        // Copy header
        output.extend_from_slice(&packet[..8]);

        // Decrypt payload
        let mut payload = packet[8..].to_vec();
        let mut cipher = Aes128Ctr::new((&self.keys.srtcp_enc_key[..]).into(), &iv.into());
        cipher.apply_keystream(&mut payload);
        output.extend_from_slice(&payload);

        Ok(output.freeze())
    }

    /// Compute authentication tag using HMAC-SHA1.
    fn compute_auth_tag(&self, packet: &[u8]) -> [u8; 20] {
        let mut mac =
            HmacSha1::new_from_slice(&self.keys.srtcp_auth_key).expect("HMAC key length is valid");

        mac.update(packet);

        let result = mac.finalize();
        let mut tag = [0u8; 20];
        tag.copy_from_slice(&result.into_bytes());
        tag
    }
}

/// Build IV for SRTP encryption.
///
/// IV = salt XOR (SSRC || 0x0000 || index)
fn build_iv(salt: &[u8], ssrc: u32, index: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];

    // Copy salt (14 bytes)
    iv[..salt.len()].copy_from_slice(salt);

    // XOR with SSRC at bytes 4-7
    let ssrc_bytes = ssrc.to_be_bytes();
    iv[4] ^= ssrc_bytes[0];
    iv[5] ^= ssrc_bytes[1];
    iv[6] ^= ssrc_bytes[2];
    iv[7] ^= ssrc_bytes[3];

    // XOR with index (48 bits) at bytes 8-13
    let index_bytes = index.to_be_bytes();
    iv[8] ^= index_bytes[2];
    iv[9] ^= index_bytes[3];
    iv[10] ^= index_bytes[4];
    iv[11] ^= index_bytes[5];
    iv[12] ^= index_bytes[6];
    iv[13] ^= index_bytes[7];

    iv
}

/// Build IV for SRTCP encryption.
fn build_srtcp_iv(salt: &[u8], ssrc: u32, index: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];

    // Copy salt (14 bytes)
    iv[..salt.len()].copy_from_slice(salt);

    // XOR with SSRC at bytes 4-7
    let ssrc_bytes = ssrc.to_be_bytes();
    iv[4] ^= ssrc_bytes[0];
    iv[5] ^= ssrc_bytes[1];
    iv[6] ^= ssrc_bytes[2];
    iv[7] ^= ssrc_bytes[3];

    // XOR with index (31 bits) at bytes 10-13
    let index_bytes = index.to_be_bytes();
    iv[10] ^= index_bytes[0];
    iv[11] ^= index_bytes[1];
    iv[12] ^= index_bytes[2];
    iv[13] ^= index_bytes[3];

    iv
}

/// Get RTP header length including any CSRC and extension.
fn get_rtp_header_len(rtp: &[u8]) -> Result<usize, String> {
    if rtp.len() < RTP_HEADER_SIZE {
        return Err("RTP packet too short".into());
    }

    let cc = (rtp[0] & 0x0F) as usize;
    let has_extension = (rtp[0] & 0x10) != 0;

    let mut header_len = RTP_HEADER_SIZE + cc * 4;

    if has_extension {
        if rtp.len() < header_len + 4 {
            return Err("RTP packet too short for extension".into());
        }

        let ext_len = u16::from_be_bytes([rtp[header_len + 2], rtp[header_len + 3]]) as usize;
        header_len += 4 + ext_len * 4;
    }

    if rtp.len() < header_len {
        return Err("RTP packet too short for header".into());
    }

    Ok(header_len)
}

/// Estimate ROC based on sequence number.
fn estimate_roc(current_roc: u32, highest_seq: u16, new_seq: u16) -> u32 {
    let v = current_roc;
    let s_l = highest_seq;
    let seq = new_seq;

    if s_l < 0x8000 {
        if seq > s_l && seq - s_l > 0x8000 {
            // Wraparound backward
            v.wrapping_sub(1)
        } else {
            v
        }
    } else if seq < s_l && s_l - seq > 0x8000 {
        // Wraparound forward
        v.wrapping_add(1)
    } else {
        v
    }
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::CryptoSuite;

    fn make_test_rtp() -> Vec<u8> {
        let mut rtp = vec![0u8; 172];
        rtp[0] = 0x80; // V=2, no padding, no extension, CC=0
        rtp[1] = 0x00; // PT=0
        rtp[2] = 0x00; // Seq high
        rtp[3] = 0x01; // Seq low = 1
        rtp[4] = 0x00; // Timestamp
        rtp[5] = 0x00;
        rtp[6] = 0x00;
        rtp[7] = 0x00;
        rtp[8] = 0x12; // SSRC
        rtp[9] = 0x34;
        rtp[10] = 0x56;
        rtp[11] = 0x78;
        // Payload
        for i in 12..172 {
            rtp[i] = (i - 12) as u8;
        }
        rtp
    }

    #[test]
    fn test_srtp_protect_unprotect() {
        let master_key = [0u8; 16];
        let master_salt = [0u8; 14];

        let mut ctx_send =
            SrtpContext::new(CryptoSuite::AesCm128HmacSha1_80, &master_key, &master_salt).unwrap();

        let mut ctx_recv =
            SrtpContext::new(CryptoSuite::AesCm128HmacSha1_80, &master_key, &master_salt).unwrap();

        let rtp = make_test_rtp();

        // Protect
        let srtp = ctx_send.protect(&rtp).unwrap();

        // SRTP should be larger (auth tag added)
        assert_eq!(srtp.len(), rtp.len() + 10);

        // Unprotect
        let decrypted = ctx_recv.unprotect(&srtp).unwrap();

        // Should match original
        assert_eq!(&decrypted[..], &rtp[..]);
    }

    #[test]
    fn test_srtp_tamper_detection() {
        let master_key = [0u8; 16];
        let master_salt = [0u8; 14];

        let mut ctx_send =
            SrtpContext::new(CryptoSuite::AesCm128HmacSha1_80, &master_key, &master_salt).unwrap();

        let mut ctx_recv =
            SrtpContext::new(CryptoSuite::AesCm128HmacSha1_80, &master_key, &master_salt).unwrap();

        let rtp = make_test_rtp();
        let mut srtp = ctx_send.protect(&rtp).unwrap().to_vec();

        // Tamper with the payload
        srtp[20] ^= 0xFF;

        // Unprotect should fail
        let result = ctx_recv.unprotect(&srtp);
        assert!(result.is_err());
    }

    #[test]
    fn test_srtp_32bit_tag() {
        let master_key = [0u8; 16];
        let master_salt = [0u8; 14];

        let mut ctx =
            SrtpContext::new(CryptoSuite::AesCm128HmacSha1_32, &master_key, &master_salt).unwrap();

        let rtp = make_test_rtp();
        let srtp = ctx.protect(&rtp).unwrap();

        // 32-bit tag should only add 4 bytes
        assert_eq!(srtp.len(), rtp.len() + 4);
    }

    #[test]
    fn test_srtcp_protect_unprotect() {
        let master_key = [0u8; 16];
        let master_salt = [0u8; 14];

        let mut ctx_send =
            SrtcpContext::new(CryptoSuite::AesCm128HmacSha1_80, &master_key, &master_salt).unwrap();

        let mut ctx_recv =
            SrtcpContext::new(CryptoSuite::AesCm128HmacSha1_80, &master_key, &master_salt).unwrap();

        // Simple RTCP packet (SR)
        let rtcp = vec![
            0x80, 0xC8, 0x00, 0x06, // V=2, PT=200 (SR), length=6
            0x12, 0x34, 0x56, 0x78, // SSRC
            0x00, 0x00, 0x00, 0x00, // NTP timestamp high
            0x00, 0x00, 0x00, 0x00, // NTP timestamp low
            0x00, 0x00, 0x00, 0x00, // RTP timestamp
            0x00, 0x00, 0x00, 0x00, // Sender packet count
            0x00, 0x00, 0x00, 0x00, // Sender octet count
        ];

        // Protect
        let srtcp = ctx_send.protect(&rtcp).unwrap();

        // SRTCP should be larger (index + auth tag)
        assert_eq!(srtcp.len(), rtcp.len() + 4 + 10);

        // Unprotect
        let decrypted = ctx_recv.unprotect(&srtcp).unwrap();

        // Should match original
        assert_eq!(&decrypted[..], &rtcp[..]);
    }

    #[test]
    fn test_get_rtp_header_len() {
        // Basic header (no CSRC, no extension)
        let rtp = vec![0x80; 12];
        assert_eq!(get_rtp_header_len(&rtp).unwrap(), 12);

        // With 2 CSRC entries
        let mut rtp = vec![0x82; 20];
        rtp[0] = 0x82; // CC=2
        assert_eq!(get_rtp_header_len(&rtp).unwrap(), 20);

        // With extension
        let mut rtp = vec![0; 20];
        rtp[0] = 0x90; // X=1, CC=0
        rtp[14] = 0x00; // Extension length high
        rtp[15] = 0x01; // Extension length low = 1 (4 bytes)
        assert_eq!(get_rtp_header_len(&rtp).unwrap(), 20);
    }

    #[test]
    fn test_estimate_roc() {
        // Normal case
        assert_eq!(estimate_roc(0, 100, 101), 0);

        // Wraparound forward
        assert_eq!(estimate_roc(0, 0xFFFF, 0), 1);

        // Wraparound backward
        assert_eq!(estimate_roc(1, 0, 0xFFFF), 0);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
        assert!(!constant_time_compare(&a, &[1, 2, 3])); // Different length
    }

    #[test]
    fn test_estimate_roc_more_cases() {
        // s_l < 0x8000, seq > s_l, difference > 0x8000 (wraparound backward)
        assert_eq!(estimate_roc(5, 0x1000, 0xF000), 4);

        // s_l < 0x8000, normal increment
        assert_eq!(estimate_roc(3, 0x1000, 0x1001), 3);

        // s_l >= 0x8000, seq < s_l, difference > 0x8000 (wraparound forward)
        assert_eq!(estimate_roc(2, 0xFFF0, 0x0010), 3);

        // s_l >= 0x8000, normal case
        assert_eq!(estimate_roc(2, 0x9000, 0x9001), 2);
    }

    #[test]
    fn test_get_rtp_header_len_with_csrc() {
        // RTP with 2 CSRC entries (CC=2)
        let mut rtp = vec![0x82, 0x00, 0x00, 0x01]; // Version 2, CC=2
        rtp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Timestamp
        rtp.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // SSRC
        rtp.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // CSRC 1
        rtp.extend_from_slice(&[0x00, 0x00, 0x00, 0x03]); // CSRC 2
        rtp.extend_from_slice(&[0x00]); // Payload

        let header_len = get_rtp_header_len(&rtp).unwrap();
        assert_eq!(header_len, 12 + 8); // 12 base + 2*4 CSRC
    }

    #[test]
    fn test_get_rtp_header_len_too_short_for_extension() {
        // RTP with extension flag set but not enough data
        let rtp = vec![0x90, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        // Only 12 bytes, needs 4 more for extension header

        let result = get_rtp_header_len(&rtp);
        assert!(result.is_err());
    }

    #[test]
    fn test_srtp_protect_short_packet() {
        let master_key = [0u8; 16];
        let master_salt = [0u8; 14];

        let mut ctx =
            SrtpContext::new(CryptoSuite::AesCm128HmacSha1_80, &master_key, &master_salt).unwrap();

        // Too short packet
        let short_rtp = [0u8; 8];
        assert!(ctx.protect(&short_rtp).is_err());
    }

    #[test]
    fn test_srtp_unprotect_short_packet() {
        let master_key = [0u8; 16];
        let master_salt = [0u8; 14];

        let mut ctx =
            SrtpContext::new(CryptoSuite::AesCm128HmacSha1_80, &master_key, &master_salt).unwrap();

        // Too short packet
        let short_srtp = [0u8; 16];
        assert!(ctx.unprotect(&short_srtp).is_err());
    }

    #[test]
    fn test_srtcp_protect_short_packet() {
        let master_key = [0u8; 16];
        let master_salt = [0u8; 14];

        let mut ctx =
            SrtcpContext::new(CryptoSuite::AesCm128HmacSha1_80, &master_key, &master_salt).unwrap();

        // Too short packet
        let short_rtcp = [0u8; 4];
        assert!(ctx.protect(&short_rtcp).is_err());
    }

    #[test]
    fn test_srtcp_unprotect_short_packet() {
        let master_key = [0u8; 16];
        let master_salt = [0u8; 14];

        let mut ctx =
            SrtcpContext::new(CryptoSuite::AesCm128HmacSha1_80, &master_key, &master_salt).unwrap();

        // Too short packet
        let short_srtcp = [0u8; 10];
        assert!(ctx.unprotect(&short_srtcp).is_err());
    }

    #[test]
    fn test_srtp_auth_failure() {
        let master_key = [0u8; 16];
        let master_salt = [0u8; 14];

        let mut ctx =
            SrtpContext::new(CryptoSuite::AesCm128HmacSha1_80, &master_key, &master_salt).unwrap();

        // Create valid RTP packet
        let rtp = make_test_rtp();

        // Protect it
        let srtp = ctx.protect(&rtp).unwrap();

        // Create new context for unprotect
        let mut ctx2 =
            SrtpContext::new(CryptoSuite::AesCm128HmacSha1_80, &master_key, &master_salt).unwrap();

        // Tamper with the packet
        let mut tampered = srtp.to_vec();
        tampered[12] ^= 0xFF;

        // Should fail auth
        assert!(ctx2.unprotect(&tampered).is_err());
    }
}
