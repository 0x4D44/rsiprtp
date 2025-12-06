//! Configuration types for the mdsiprtp stack.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Main configuration for the SIP/RTP stack.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StackConfig {
    /// Identity configuration (who we are).
    pub identity: IdentityConfig,
    /// Transport configuration (how we communicate).
    pub transport: TransportConfig,
    /// Media configuration (audio settings).
    pub media: MediaConfig,
}

/// Identity configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Display name shown to other parties.
    pub display_name: Option<String>,
    /// SIP URI (e.g., "sip:alice@example.com").
    pub uri: String,
    /// Authentication username (if different from URI user).
    pub auth_username: Option<String>,
    /// Authentication password.
    pub auth_password: Option<String>,
    /// Realm for authentication (usually domain).
    pub realm: Option<String>,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            display_name: None,
            uri: "sip:anonymous@localhost".to_string(),
            auth_username: None,
            auth_password: None,
            realm: None,
        }
    }
}

/// Transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// UDP bind address (None to disable UDP).
    pub udp_bind: Option<SocketAddr>,
    /// TCP bind address (None to disable TCP).
    pub tcp_bind: Option<SocketAddr>,
    /// TLS bind address (None to disable TLS).
    pub tls_bind: Option<SocketAddr>,
    /// TLS certificate file path.
    pub tls_cert_path: Option<PathBuf>,
    /// TLS private key file path.
    pub tls_key_path: Option<PathBuf>,
    /// Outbound proxy URI (optional).
    pub outbound_proxy: Option<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            udp_bind: Some("0.0.0.0:5060".parse().unwrap()),
            tcp_bind: None,
            tls_bind: None,
            tls_cert_path: None,
            tls_key_path: None,
            outbound_proxy: None,
        }
    }
}

/// Media configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaConfig {
    /// RTP port range (start, end).
    pub rtp_port_range: (u16, u16),
    /// Enabled codecs in priority order.
    pub codecs: Vec<CodecConfig>,
    /// Jitter buffer size in milliseconds.
    pub jitter_buffer_ms: u32,
    /// Packet time (ptime) in milliseconds.
    pub ptime_ms: u32,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            rtp_port_range: (10000, 20000),
            codecs: vec![
                CodecConfig::pcmu(),
                CodecConfig::pcma(),
            ],
            jitter_buffer_ms: 60,
            ptime_ms: 20,
        }
    }
}

/// Codec configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodecConfig {
    /// Codec name (e.g., "PCMU", "PCMA", "opus").
    pub name: String,
    /// RTP payload type (0-127).
    pub payload_type: u8,
    /// Clock rate in Hz.
    pub clock_rate: u32,
    /// Number of channels.
    pub channels: u8,
    /// Format-specific parameters (fmtp).
    pub fmtp: Option<String>,
}

impl CodecConfig {
    /// Create G.711 mu-law (PCMU) codec configuration.
    pub fn pcmu() -> Self {
        Self {
            name: "PCMU".to_string(),
            payload_type: 0,
            clock_rate: 8000,
            channels: 1,
            fmtp: None,
        }
    }

    /// Create G.711 A-law (PCMA) codec configuration.
    pub fn pcma() -> Self {
        Self {
            name: "PCMA".to_string(),
            payload_type: 8,
            clock_rate: 8000,
            channels: 1,
            fmtp: None,
        }
    }

    /// Create G.722 wideband codec configuration.
    pub fn g722() -> Self {
        Self {
            name: "G722".to_string(),
            payload_type: 9,
            clock_rate: 8000, // RTP clock rate is 8000 despite 16kHz sampling
            channels: 1,
            fmtp: None,
        }
    }

    /// Create Opus codec configuration.
    pub fn opus() -> Self {
        Self {
            name: "opus".to_string(),
            payload_type: 111, // Dynamic payload type
            clock_rate: 48000,
            channels: 2,
            fmtp: Some("minptime=10;useinbandfec=1".to_string()),
        }
    }

    /// Create telephone-event (DTMF) payload configuration.
    pub fn telephone_event() -> Self {
        Self {
            name: "telephone-event".to_string(),
            payload_type: 101, // Common dynamic PT for DTMF
            clock_rate: 8000,
            channels: 1,
            fmtp: Some("0-16".to_string()),
        }
    }
}

/// SIP timer configuration (RFC 3261).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TimerConfig {
    /// T1: RTT estimate (default 500ms).
    pub t1_ms: u32,
    /// T2: Maximum retransmit interval (default 4000ms).
    pub t2_ms: u32,
    /// T4: Maximum network transit time (default 5000ms).
    pub t4_ms: u32,
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            t1_ms: 500,
            t2_ms: 4000,
            t4_ms: 5000,
        }
    }
}

impl TimerConfig {
    /// Timer B: INVITE transaction timeout (64 * T1).
    pub fn timer_b_ms(&self) -> u32 {
        64 * self.t1_ms
    }

    /// Timer F: Non-INVITE transaction timeout (64 * T1).
    pub fn timer_f_ms(&self) -> u32 {
        64 * self.t1_ms
    }

    /// Timer D: Wait time in Completed state for unreliable transport.
    pub fn timer_d_ms(&self) -> u32 {
        32000 // > 32 seconds
    }

    /// Timer H: Wait for ACK timeout.
    pub fn timer_h_ms(&self) -> u32 {
        64 * self.t1_ms
    }
}
