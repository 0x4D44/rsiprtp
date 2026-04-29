//! Configuration types for the rsiprtp stack.

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
            codecs: vec![CodecConfig::pcmu(), CodecConfig::pcma()],
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

#[cfg(test)]
mod tests {
    use super::*;

    // StackConfig tests
    #[test]
    fn test_stack_config_default() {
        let config = StackConfig::default();
        assert_eq!(config.identity.uri, "sip:anonymous@localhost");
        assert!(config.transport.udp_bind.is_some());
        assert_eq!(config.media.rtp_port_range, (10000, 20000));
    }

    #[test]
    fn test_stack_config_clone() {
        let config = StackConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.identity.uri, config.identity.uri);
    }

    #[test]
    fn test_stack_config_debug() {
        let config = StackConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("StackConfig"));
    }

    // IdentityConfig tests
    #[test]
    fn test_identity_config_default() {
        let config = IdentityConfig::default();
        assert!(config.display_name.is_none());
        assert_eq!(config.uri, "sip:anonymous@localhost");
        assert!(config.auth_username.is_none());
        assert!(config.auth_password.is_none());
        assert!(config.realm.is_none());
    }

    #[test]
    fn test_identity_config_with_values() {
        let config = IdentityConfig {
            display_name: Some("Alice".to_string()),
            uri: "sip:alice@example.com".to_string(),
            auth_username: Some("alice_auth".to_string()),
            auth_password: Some("secret".to_string()),
            realm: Some("example.com".to_string()),
        };
        assert_eq!(config.display_name.as_deref(), Some("Alice"));
        assert_eq!(config.uri, "sip:alice@example.com");
        assert_eq!(config.auth_username.as_deref(), Some("alice_auth"));
        assert_eq!(config.auth_password.as_deref(), Some("secret"));
        assert_eq!(config.realm.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_identity_config_clone() {
        let config = IdentityConfig {
            display_name: Some("Bob".to_string()),
            uri: "sip:bob@test.com".to_string(),
            auth_username: None,
            auth_password: None,
            realm: None,
        };
        let cloned = config.clone();
        assert_eq!(cloned.display_name, config.display_name);
        assert_eq!(cloned.uri, config.uri);
    }

    // TransportConfig tests
    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert!(config.udp_bind.is_some());
        assert_eq!(
            config.udp_bind.unwrap(),
            "0.0.0.0:5060".parse::<SocketAddr>().unwrap()
        );
        assert!(config.tcp_bind.is_none());
        assert!(config.tls_bind.is_none());
        assert!(config.tls_cert_path.is_none());
        assert!(config.tls_key_path.is_none());
        assert!(config.outbound_proxy.is_none());
    }

    #[test]
    fn test_transport_config_with_all_transports() {
        let config = TransportConfig {
            udp_bind: Some("0.0.0.0:5060".parse().unwrap()),
            tcp_bind: Some("0.0.0.0:5060".parse().unwrap()),
            tls_bind: Some("0.0.0.0:5061".parse().unwrap()),
            tls_cert_path: Some(PathBuf::from("/etc/ssl/cert.pem")),
            tls_key_path: Some(PathBuf::from("/etc/ssl/key.pem")),
            outbound_proxy: Some("sip:proxy.example.com".to_string()),
        };
        assert!(config.udp_bind.is_some());
        assert!(config.tcp_bind.is_some());
        assert!(config.tls_bind.is_some());
        assert_eq!(
            config.tls_cert_path.as_ref().unwrap().to_str().unwrap(),
            "/etc/ssl/cert.pem"
        );
        assert_eq!(
            config.outbound_proxy.as_deref(),
            Some("sip:proxy.example.com")
        );
    }

    #[test]
    fn test_transport_config_ipv6() {
        let config = TransportConfig {
            udp_bind: Some("[::]:5060".parse().unwrap()),
            tcp_bind: Some("[::]:5060".parse().unwrap()),
            tls_bind: None,
            tls_cert_path: None,
            tls_key_path: None,
            outbound_proxy: None,
        };
        assert!(config.udp_bind.unwrap().is_ipv6());
        assert!(config.tcp_bind.unwrap().is_ipv6());
    }

    // MediaConfig tests
    #[test]
    fn test_media_config_default() {
        let config = MediaConfig::default();
        assert_eq!(config.rtp_port_range, (10000, 20000));
        assert_eq!(config.codecs.len(), 2);
        assert_eq!(config.codecs[0].name, "PCMU");
        assert_eq!(config.codecs[1].name, "PCMA");
        assert_eq!(config.jitter_buffer_ms, 60);
        assert_eq!(config.ptime_ms, 20);
    }

    #[test]
    fn test_media_config_custom_port_range() {
        let config = MediaConfig {
            rtp_port_range: (16384, 32767),
            codecs: vec![CodecConfig::opus()],
            jitter_buffer_ms: 100,
            ptime_ms: 40,
        };
        assert_eq!(config.rtp_port_range.0, 16384);
        assert_eq!(config.rtp_port_range.1, 32767);
        assert_eq!(config.codecs.len(), 1);
        assert_eq!(config.jitter_buffer_ms, 100);
        assert_eq!(config.ptime_ms, 40);
    }

    // CodecConfig tests
    #[test]
    fn test_codec_pcmu() {
        let codec = CodecConfig::pcmu();
        assert_eq!(codec.name, "PCMU");
        assert_eq!(codec.payload_type, 0);
        assert_eq!(codec.clock_rate, 8000);
        assert_eq!(codec.channels, 1);
        assert!(codec.fmtp.is_none());
    }

    #[test]
    fn test_codec_pcma() {
        let codec = CodecConfig::pcma();
        assert_eq!(codec.name, "PCMA");
        assert_eq!(codec.payload_type, 8);
        assert_eq!(codec.clock_rate, 8000);
        assert_eq!(codec.channels, 1);
        assert!(codec.fmtp.is_none());
    }

    #[test]
    fn test_codec_g722() {
        let codec = CodecConfig::g722();
        assert_eq!(codec.name, "G722");
        assert_eq!(codec.payload_type, 9);
        assert_eq!(codec.clock_rate, 8000); // RTP clock rate
        assert_eq!(codec.channels, 1);
        assert!(codec.fmtp.is_none());
    }

    #[test]
    fn test_codec_opus() {
        let codec = CodecConfig::opus();
        assert_eq!(codec.name, "opus");
        assert_eq!(codec.payload_type, 111);
        assert_eq!(codec.clock_rate, 48000);
        assert_eq!(codec.channels, 2);
        assert!(codec.fmtp.is_some());
        assert!(codec.fmtp.as_ref().unwrap().contains("useinbandfec"));
    }

    #[test]
    fn test_codec_telephone_event() {
        let codec = CodecConfig::telephone_event();
        assert_eq!(codec.name, "telephone-event");
        assert_eq!(codec.payload_type, 101);
        assert_eq!(codec.clock_rate, 8000);
        assert_eq!(codec.channels, 1);
        assert_eq!(codec.fmtp.as_deref(), Some("0-16"));
    }

    #[test]
    fn test_codec_custom() {
        let codec = CodecConfig {
            name: "AMR".to_string(),
            payload_type: 96,
            clock_rate: 8000,
            channels: 1,
            fmtp: Some("octet-align=1".to_string()),
        };
        assert_eq!(codec.name, "AMR");
        assert_eq!(codec.payload_type, 96);
        assert_eq!(codec.fmtp.as_deref(), Some("octet-align=1"));
    }

    // TimerConfig tests
    #[test]
    fn test_timer_config_default() {
        let config = TimerConfig::default();
        assert_eq!(config.t1_ms, 500);
        assert_eq!(config.t2_ms, 4000);
        assert_eq!(config.t4_ms, 5000);
    }

    #[test]
    fn test_timer_b() {
        let config = TimerConfig::default();
        assert_eq!(config.timer_b_ms(), 64 * 500); // 32000ms
    }

    #[test]
    fn test_timer_f() {
        let config = TimerConfig::default();
        assert_eq!(config.timer_f_ms(), 64 * 500); // 32000ms
    }

    #[test]
    fn test_timer_d() {
        let config = TimerConfig::default();
        assert_eq!(config.timer_d_ms(), 32000);
    }

    #[test]
    fn test_timer_h() {
        let config = TimerConfig::default();
        assert_eq!(config.timer_h_ms(), 64 * 500); // 32000ms
    }

    #[test]
    fn test_timer_config_custom_t1() {
        let config = TimerConfig {
            t1_ms: 250,
            t2_ms: 2000,
            t4_ms: 2500,
        };
        assert_eq!(config.timer_b_ms(), 64 * 250); // 16000ms
        assert_eq!(config.timer_f_ms(), 64 * 250); // 16000ms
        assert_eq!(config.timer_h_ms(), 64 * 250); // 16000ms
                                                   // timer_d is fixed
        assert_eq!(config.timer_d_ms(), 32000);
    }

    #[test]
    fn test_timer_config_copy() {
        let config = TimerConfig::default();
        let copied = config; // Copy trait
        assert_eq!(copied.t1_ms, config.t1_ms);
    }

    // Serialization tests
    #[test]
    fn test_stack_config_json_roundtrip() {
        let config = StackConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: StackConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.identity.uri, config.identity.uri);
        assert_eq!(deserialized.media.ptime_ms, config.media.ptime_ms);
    }

    #[test]
    fn test_identity_config_json_roundtrip() {
        let config = IdentityConfig {
            display_name: Some("Test User".to_string()),
            uri: "sip:test@example.com".to_string(),
            auth_username: Some("testuser".to_string()),
            auth_password: Some("password123".to_string()),
            realm: Some("example.com".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: IdentityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.display_name, config.display_name);
        assert_eq!(deserialized.uri, config.uri);
        assert_eq!(deserialized.auth_username, config.auth_username);
    }

    #[test]
    fn test_transport_config_json_roundtrip() {
        let config = TransportConfig {
            udp_bind: Some("192.168.1.100:5060".parse().unwrap()),
            tcp_bind: Some("192.168.1.100:5060".parse().unwrap()),
            tls_bind: None,
            tls_cert_path: Some(PathBuf::from("/path/to/cert.pem")),
            tls_key_path: None,
            outbound_proxy: Some("sip:proxy.local".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TransportConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.udp_bind, config.udp_bind);
        assert_eq!(deserialized.outbound_proxy, config.outbound_proxy);
    }

    #[test]
    fn test_media_config_json_roundtrip() {
        let config = MediaConfig {
            rtp_port_range: (20000, 30000),
            codecs: vec![
                CodecConfig::pcmu(),
                CodecConfig::opus(),
                CodecConfig::telephone_event(),
            ],
            jitter_buffer_ms: 80,
            ptime_ms: 30,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: MediaConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.rtp_port_range, config.rtp_port_range);
        assert_eq!(deserialized.codecs.len(), 3);
        assert_eq!(deserialized.jitter_buffer_ms, config.jitter_buffer_ms);
    }

    #[test]
    fn test_timer_config_json_roundtrip() {
        let config = TimerConfig {
            t1_ms: 1000,
            t2_ms: 8000,
            t4_ms: 10000,
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: TimerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.t1_ms, config.t1_ms);
        assert_eq!(deserialized.t2_ms, config.t2_ms);
        assert_eq!(deserialized.t4_ms, config.t4_ms);
    }

    #[test]
    fn test_codec_config_clone() {
        let codec = CodecConfig::opus();
        let cloned = codec.clone();
        assert_eq!(cloned.name, codec.name);
        assert_eq!(cloned.payload_type, codec.payload_type);
        assert_eq!(cloned.fmtp, codec.fmtp);
    }

    #[test]
    fn test_media_config_empty_codecs() {
        let config = MediaConfig {
            rtp_port_range: (10000, 20000),
            codecs: vec![],
            jitter_buffer_ms: 60,
            ptime_ms: 20,
        };
        assert!(config.codecs.is_empty());
    }
}
