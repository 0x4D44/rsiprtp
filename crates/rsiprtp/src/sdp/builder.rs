//! SDP builder.
//!
//! Builds SDP session descriptions programmatically.

use std::net::IpAddr;

use crate::sdp::parser::{
    Attribute, Connection, Direction, MediaDescription, MediaType, Origin, SessionDescription,
    Timing,
};
use crate::core::random_u64;

/// Builder for SDP session descriptions.
#[derive(Debug, Clone)]
pub struct SdpBuilder {
    /// Origin username.
    username: String,
    /// Session ID.
    session_id: u64,
    /// Session version.
    session_version: u64,
    /// Local IP address.
    local_addr: IpAddr,
    /// Session name.
    session_name: String,
    /// Media descriptions.
    media: Vec<MediaBuilder>,
}

impl SdpBuilder {
    /// Create a new SDP builder.
    pub fn new(local_addr: IpAddr) -> Self {
        Self {
            username: "-".to_string(),
            session_id: random_u64(),
            session_version: 1,
            local_addr,
            session_name: "-".to_string(),
            media: Vec::new(),
        }
    }

    /// Set the username.
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    /// Set the session ID.
    pub fn session_id(mut self, id: u64) -> Self {
        self.session_id = id;
        self
    }

    /// Set the session version.
    pub fn session_version(mut self, version: u64) -> Self {
        self.session_version = version;
        self
    }

    /// Set the session name.
    pub fn session_name(mut self, name: impl Into<String>) -> Self {
        self.session_name = name.into();
        self
    }

    /// Add an audio media description.
    pub fn audio(mut self, port: u16) -> Self {
        self.media.push(MediaBuilder::audio(port));
        self
    }

    /// Add a media builder.
    pub fn add_media(mut self, media: MediaBuilder) -> Self {
        self.media.push(media);
        self
    }

    /// Build the SDP.
    pub fn build(self) -> SessionDescription {
        let addr_type = if self.local_addr.is_ipv4() {
            "IP4"
        } else {
            "IP6"
        };

        let origin = Origin {
            username: self.username,
            session_id: self.session_id.to_string(),
            session_version: self.session_version.to_string(),
            net_type: "IN".to_string(),
            addr_type: addr_type.to_string(),
            unicast_address: self.local_addr.to_string(),
        };

        let connection = Connection {
            net_type: "IN".to_string(),
            addr_type: addr_type.to_string(),
            address: self.local_addr.to_string(),
        };

        let media = self.media.into_iter().map(|m| m.build()).collect();

        SessionDescription {
            version: 0,
            origin,
            session_name: self.session_name,
            session_info: None,
            connection: Some(connection),
            timing: Timing { start: 0, stop: 0 },
            media,
            attributes: Vec::new(),
        }
    }

    /// Build and render to string.
    pub fn build_string(self) -> String {
        self.build().to_string()
    }
}

/// Builder for media descriptions.
#[derive(Debug, Clone)]
pub struct MediaBuilder {
    media_type: MediaType,
    port: u16,
    protocol: String,
    formats: Vec<String>,
    direction: Direction,
    rtpmaps: Vec<(u8, String, u32, Option<u8>)>, // (pt, encoding, rate, channels)
    fmtps: Vec<(u8, String)>,                    // (pt, params)
    ptime: Option<u32>,
}

impl MediaBuilder {
    /// Create an audio media builder.
    pub fn audio(port: u16) -> Self {
        Self {
            media_type: MediaType::Audio,
            port,
            protocol: "RTP/AVP".to_string(),
            formats: Vec::new(),
            direction: Direction::SendRecv,
            rtpmaps: Vec::new(),
            fmtps: Vec::new(),
            ptime: None,
        }
    }

    /// Set the protocol (e.g., "RTP/SAVP" for SRTP).
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocol = protocol.into();
        self
    }

    /// Set the direction.
    pub fn direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// Add PCMU (G.711 mu-law) codec.
    pub fn pcmu(mut self) -> Self {
        self.formats.push("0".to_string());
        self.rtpmaps.push((0, "PCMU".to_string(), 8000, None));
        self
    }

    /// Add PCMA (G.711 A-law) codec.
    pub fn pcma(mut self) -> Self {
        self.formats.push("8".to_string());
        self.rtpmaps.push((8, "PCMA".to_string(), 8000, None));
        self
    }

    /// Add G722 codec.
    pub fn g722(mut self) -> Self {
        self.formats.push("9".to_string());
        self.rtpmaps.push((9, "G722".to_string(), 8000, None)); // Clock rate is 8000 in SDP
        self
    }

    /// Add telephone-event (DTMF).
    pub fn telephone_event(mut self, pt: u8) -> Self {
        self.formats.push(pt.to_string());
        self.rtpmaps
            .push((pt, "telephone-event".to_string(), 8000, None));
        self.fmtps.push((pt, "0-16".to_string()));
        self
    }

    /// Add a dynamic codec.
    pub fn codec(
        mut self,
        pt: u8,
        encoding: impl Into<String>,
        clock_rate: u32,
        channels: Option<u8>,
    ) -> Self {
        self.formats.push(pt.to_string());
        self.rtpmaps
            .push((pt, encoding.into(), clock_rate, channels));
        self
    }

    /// Add format-specific parameters.
    pub fn fmtp(mut self, pt: u8, params: impl Into<String>) -> Self {
        self.fmtps.push((pt, params.into()));
        self
    }

    /// Set ptime.
    pub fn ptime(mut self, ptime: u32) -> Self {
        self.ptime = Some(ptime);
        self
    }

    /// Build the media description.
    pub fn build(self) -> MediaDescription {
        let mut attributes = Vec::new();

        // Add rtpmaps
        for (pt, encoding, rate, channels) in &self.rtpmaps {
            let value = if let Some(ch) = channels {
                format!("{} {}/{}/{}", pt, encoding, rate, ch)
            } else {
                format!("{} {}/{}", pt, encoding, rate)
            };
            attributes.push(Attribute {
                name: "rtpmap".to_string(),
                value: Some(value),
            });
        }

        // Add fmtps
        for (pt, params) in &self.fmtps {
            attributes.push(Attribute {
                name: "fmtp".to_string(),
                value: Some(format!("{} {}", pt, params)),
            });
        }

        // Add ptime
        if let Some(ptime) = self.ptime {
            attributes.push(Attribute {
                name: "ptime".to_string(),
                value: Some(ptime.to_string()),
            });
        }

        // Add direction
        attributes.push(Attribute {
            name: match self.direction {
                Direction::SendRecv => "sendrecv".to_string(),
                Direction::SendOnly => "sendonly".to_string(),
                Direction::RecvOnly => "recvonly".to_string(),
                Direction::Inactive => "inactive".to_string(),
            },
            value: None,
        });

        MediaDescription {
            media_type: self.media_type,
            port: self.port,
            num_ports: None,
            protocol: self.protocol,
            formats: self.formats,
            connection: None,
            bandwidth: Default::default(),
            attributes,
        }
    }
}

impl std::fmt::Display for SessionDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Version
        writeln!(f, "v={}", self.version)?;

        // Origin
        writeln!(
            f,
            "o={} {} {} {} {} {}",
            self.origin.username,
            self.origin.session_id,
            self.origin.session_version,
            self.origin.net_type,
            self.origin.addr_type,
            self.origin.unicast_address
        )?;

        // Session name
        writeln!(f, "s={}", self.session_name)?;

        // Session info
        if let Some(ref info) = self.session_info {
            writeln!(f, "i={}", info)?;
        }

        // Connection (session-level)
        if let Some(ref conn) = self.connection {
            writeln!(f, "c={} {} {}", conn.net_type, conn.addr_type, conn.address)?;
        }

        // Timing
        writeln!(f, "t={} {}", self.timing.start, self.timing.stop)?;

        // Session-level attributes
        for attr in &self.attributes {
            if let Some(ref value) = attr.value {
                writeln!(f, "a={}:{}", attr.name, value)?;
            } else {
                writeln!(f, "a={}", attr.name)?;
            }
        }

        // Media descriptions
        for media in &self.media {
            write_media(f, media)?;
        }

        Ok(())
    }
}

fn write_media(f: &mut std::fmt::Formatter<'_>, media: &MediaDescription) -> std::fmt::Result {
    // Media line
    let media_type = match media.media_type {
        MediaType::Audio => "audio",
        MediaType::Video => "video",
        MediaType::Application => "application",
        MediaType::Message => "message",
        MediaType::Other => "other",
    };

    let mut line = String::new();
    line.push_str("m=");
    line.push_str(media_type);
    line.push(' ');
    line.push_str(&media.port.to_string());
    line.push(' ');
    line.push_str(&media.protocol);
    for fmt in &media.formats {
        line.push(' ');
        line.push_str(fmt);
    }
    writeln!(f, "{}", line)?;

    // Connection (media-level)
    if let Some(ref conn) = media.connection {
        writeln!(f, "c={} {} {}", conn.net_type, conn.addr_type, conn.address)?;
    }

    // Bandwidth
    for (btype, bw) in &media.bandwidth {
        writeln!(f, "b={}:{}", btype, bw)?;
    }

    // Attributes
    for attr in &media.attributes {
        if let Some(ref value) = attr.value {
            writeln!(f, "a={}:{}", attr.name, value)?;
        } else {
            writeln!(f, "a={}", attr.name)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // SdpBuilder tests
    #[test]
    fn test_sdp_builder_new() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let builder = SdpBuilder::new(addr);
        let sdp = builder.build();

        assert_eq!(sdp.version, 0);
        assert_eq!(sdp.origin.username, "-");
        assert_eq!(sdp.session_name, "-");
    }

    #[test]
    fn test_session_description_display() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let sdp = SdpBuilder::new(addr).build();
        let rendered = sdp.to_string();
        assert!(rendered.contains("o="));
    }

    #[test]
    fn test_sdp_builder_username() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let sdp = SdpBuilder::new(addr).username("alice").build();

        assert_eq!(sdp.origin.username, "alice");
    }

    #[test]
    fn test_sdp_builder_session_id() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let sdp = SdpBuilder::new(addr).session_id(123456789).build();

        assert_eq!(sdp.origin.session_id, "123456789");
    }

    #[test]
    fn test_sdp_builder_session_version() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let sdp = SdpBuilder::new(addr).session_version(42).build();

        assert_eq!(sdp.origin.session_version, "42");
    }

    #[test]
    fn test_sdp_builder_session_name() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let sdp = SdpBuilder::new(addr).session_name("My Test Call").build();

        assert_eq!(sdp.session_name, "My Test Call");
    }

    #[test]
    fn test_sdp_builder_audio_shorthand() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let sdp = SdpBuilder::new(addr).audio(49170).build();

        assert_eq!(sdp.media.len(), 1);
        assert_eq!(sdp.media[0].port, 49170);
    }

    #[test]
    fn test_sdp_builder_add_media() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let media = MediaBuilder::audio(5000).pcmu();
        let sdp = SdpBuilder::new(addr).add_media(media).build();

        assert_eq!(sdp.media.len(), 1);
        assert_eq!(sdp.media[0].port, 5000);
    }

    #[test]
    fn test_sdp_builder_multiple_media() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let sdp = SdpBuilder::new(addr)
            .add_media(MediaBuilder::audio(5000).pcmu())
            .add_media(MediaBuilder::audio(5002).pcma())
            .build();

        assert_eq!(sdp.media.len(), 2);
    }

    #[test]
    fn test_sdp_builder_ipv6() {
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let sdp = SdpBuilder::new(addr).build();

        assert_eq!(sdp.origin.addr_type, "IP6");
        assert!(sdp
            .connection
            .as_ref()
            .unwrap()
            .address
            .contains("2001:db8"));
    }

    #[test]
    fn test_sdp_builder_build_string() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let s = SdpBuilder::new(addr).session_id(123).build_string();

        assert!(s.contains("v=0"));
        assert!(s.contains("123"));
    }

    #[test]
    fn test_sdp_builder_media_type_variants() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut sdp = SdpBuilder::new(addr).build();

        sdp.media = vec![
            MediaDescription {
                media_type: MediaType::Video,
                port: 5004,
                num_ports: None,
                protocol: "RTP/AVP".to_string(),
                formats: vec!["96".to_string()],
                connection: None,
                bandwidth: Default::default(),
                attributes: Vec::new(),
            },
            MediaDescription {
                media_type: MediaType::Application,
                port: 6000,
                num_ports: None,
                protocol: "UDP".to_string(),
                formats: vec!["app".to_string()],
                connection: None,
                bandwidth: Default::default(),
                attributes: Vec::new(),
            },
            MediaDescription {
                media_type: MediaType::Message,
                port: 7000,
                num_ports: None,
                protocol: "TCP".to_string(),
                formats: vec!["msg".to_string()],
                connection: None,
                bandwidth: Default::default(),
                attributes: Vec::new(),
            },
            MediaDescription {
                media_type: MediaType::Other,
                port: 8000,
                num_ports: None,
                protocol: "RTP/AVP".to_string(),
                formats: vec!["0".to_string()],
                connection: None,
                bandwidth: Default::default(),
                attributes: Vec::new(),
            },
        ];

        let rendered = sdp.to_string();
        assert!(rendered.contains("m=video"));
        assert!(rendered.contains("m=application"));
        assert!(rendered.contains("m=message"));
        assert!(rendered.contains("m=other"));
    }

    #[test]
    fn test_sdp_builder_debug() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let builder = SdpBuilder::new(addr);
        let debug = format!("{:?}", builder);
        assert!(debug.contains("SdpBuilder"));
    }

    #[test]
    fn test_sdp_builder_clone() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let builder = SdpBuilder::new(addr).session_name("Test");
        let cloned = builder.clone();
        let sdp = cloned.build();
        assert_eq!(sdp.session_name, "Test");
    }

    // MediaBuilder tests
    #[test]
    fn test_media_builder_audio() {
        let media = MediaBuilder::audio(49170).build();
        assert_eq!(media.media_type, MediaType::Audio);
        assert_eq!(media.port, 49170);
        assert_eq!(media.protocol, "RTP/AVP");
    }

    #[test]
    fn test_media_builder_protocol() {
        let media = MediaBuilder::audio(49170).protocol("RTP/SAVP").build();
        assert_eq!(media.protocol, "RTP/SAVP");
    }

    #[test]
    fn test_media_builder_direction() {
        let media = MediaBuilder::audio(49170)
            .direction(Direction::SendOnly)
            .build();

        let has_sendonly = media.attributes.iter().any(|a| a.name == "sendonly");
        assert!(has_sendonly);
    }

    #[test]
    fn test_media_builder_all_directions() {
        // SendRecv
        let media = MediaBuilder::audio(49170)
            .direction(Direction::SendRecv)
            .build();
        assert!(media.attributes.iter().any(|a| a.name == "sendrecv"));

        // RecvOnly
        let media = MediaBuilder::audio(49170)
            .direction(Direction::RecvOnly)
            .build();
        assert!(media.attributes.iter().any(|a| a.name == "recvonly"));

        // Inactive
        let media = MediaBuilder::audio(49170)
            .direction(Direction::Inactive)
            .build();
        assert!(media.attributes.iter().any(|a| a.name == "inactive"));
    }

    #[test]
    fn test_media_builder_pcmu() {
        let media = MediaBuilder::audio(49170).pcmu().build();
        assert!(media.formats.contains(&"0".to_string()));

        let has_rtpmap = media
            .attributes
            .iter()
            .filter(|a| a.name == "rtpmap")
            .any(|a| a.value.as_deref().unwrap_or("").contains("PCMU"));
        assert!(has_rtpmap);
    }

    #[test]
    fn test_media_builder_pcma() {
        let media = MediaBuilder::audio(49170).pcma().build();
        assert!(media.formats.contains(&"8".to_string()));

        let has_rtpmap = media
            .attributes
            .iter()
            .filter(|a| a.name == "rtpmap")
            .any(|a| a.value.as_deref().unwrap_or("").contains("PCMA"));
        assert!(has_rtpmap);
    }

    #[test]
    fn test_media_builder_g722() {
        let media = MediaBuilder::audio(49170).g722().build();
        assert!(media.formats.contains(&"9".to_string()));

        let has_rtpmap = media
            .attributes
            .iter()
            .filter(|a| a.name == "rtpmap")
            .any(|a| a.value.as_deref().unwrap_or("").contains("G722"));
        assert!(has_rtpmap);
    }

    #[test]
    fn test_media_builder_telephone_event() {
        let media = MediaBuilder::audio(49170).telephone_event(101).build();
        assert!(media.formats.contains(&"101".to_string()));

        let has_rtpmap = media
            .attributes
            .iter()
            .filter(|a| a.name == "rtpmap")
            .any(|a| a.value.as_deref().unwrap_or("").contains("telephone-event"));
        assert!(has_rtpmap);

        let has_fmtp = media
            .attributes
            .iter()
            .any(|a| a.name == "fmtp" && a.value.as_ref().is_some_and(|v| v.contains("0-16")));
        assert!(has_fmtp);
    }

    #[test]
    fn test_media_builder_codec() {
        let media = MediaBuilder::audio(49170)
            .codec(96, "opus", 48000, Some(2))
            .build();

        assert!(media.formats.contains(&"96".to_string()));

        let has_rtpmap = media
            .attributes
            .iter()
            .filter(|a| a.name == "rtpmap")
            .any(|a| a.value.as_deref().unwrap_or("").contains("opus/48000/2"));
        assert!(has_rtpmap);
    }

    #[test]
    fn test_media_builder_codec_without_channels() {
        let media = MediaBuilder::audio(49170)
            .codec(97, "iLBC", 8000, None)
            .build();

        // Check that the rtpmap is "97 iLBC/8000" (without channel count)
        let has_rtpmap = media
            .attributes
            .iter()
            .filter(|a| a.name == "rtpmap")
            .any(|a| a.value.as_deref().unwrap_or("") == "97 iLBC/8000");
        assert!(has_rtpmap);
    }

    #[test]
    fn test_media_builder_fmtp() {
        let media = MediaBuilder::audio(49170)
            .codec(96, "opus", 48000, Some(2))
            .fmtp(96, "useinbandfec=1")
            .build();

        let has_fmtp = media.attributes.iter().any(|a| {
            a.name == "fmtp" && a.value.as_ref().is_some_and(|v| v.contains("useinbandfec"))
        });
        assert!(has_fmtp);
    }

    #[test]
    fn test_media_builder_ptime() {
        let media = MediaBuilder::audio(49170).pcmu().ptime(20).build();

        let has_ptime = media
            .attributes
            .iter()
            .any(|a| a.name == "ptime" && a.value == Some("20".to_string()));
        assert!(has_ptime);
    }

    #[test]
    fn test_media_builder_debug() {
        let builder = MediaBuilder::audio(49170);
        let debug = format!("{:?}", builder);
        assert!(debug.contains("MediaBuilder"));
    }

    #[test]
    fn test_media_builder_clone() {
        let builder = MediaBuilder::audio(49170).pcmu();
        let cloned = builder.clone();
        let media = cloned.build();
        assert_eq!(media.port, 49170);
    }

    // SessionDescription Display tests
    #[test]
    fn test_build_basic_sdp() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let sdp = SdpBuilder::new(addr)
            .session_name("Test Call")
            .add_media(MediaBuilder::audio(49170).pcmu().pcma())
            .build();

        assert_eq!(sdp.version, 0);
        assert_eq!(sdp.session_name, "Test Call");

        let audio = sdp.audio_media().unwrap();
        assert_eq!(audio.port, 49170);
        assert_eq!(audio.formats, vec!["0", "8"]);
    }

    #[test]
    fn test_sdp_to_string() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let sdp = SdpBuilder::new(addr)
            .session_id(1234567890)
            .session_version(1)
            .add_media(MediaBuilder::audio(49170).pcmu())
            .build();

        let s = sdp.to_string();
        assert!(s.contains("v=0"));
        assert!(s.contains("o=- 1234567890 1 IN IP4 192.168.1.1"));
        assert!(s.contains("c=IN IP4 192.168.1.1"));
        assert!(s.contains("m=audio 49170 RTP/AVP 0"));
        assert!(s.contains("a=rtpmap:0 PCMU/8000"));
    }

    #[test]
    fn test_sdp_display_with_session_info() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut sdp = SdpBuilder::new(addr).build();
        sdp.session_info = Some("A test session".to_string());

        let s = sdp.to_string();
        assert!(s.contains("i=A test session"));
    }

    #[test]
    fn test_sdp_display_without_connection() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut sdp = SdpBuilder::new(addr).build();
        sdp.connection = None;

        let s = sdp.to_string();
        // Should not have c= line at session level
        assert!(!s.contains("c=IN IP4"));
    }

    #[test]
    fn test_sdp_display_with_session_attributes() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut sdp = SdpBuilder::new(addr).build();
        sdp.attributes.push(Attribute {
            name: "ice-ufrag".to_string(),
            value: Some("abcd1234".to_string()),
        });
        sdp.attributes.push(Attribute {
            name: "rtcp-mux".to_string(),
            value: None,
        });

        let s = sdp.to_string();
        assert!(s.contains("a=ice-ufrag:abcd1234"));
        assert!(s.contains("a=rtcp-mux"));
    }

    #[test]
    fn test_sdp_display_error_paths() {
        struct CountingWriter {
            writes: usize,
        }

        impl std::fmt::Write for CountingWriter {
            fn write_str(&mut self, _s: &str) -> std::fmt::Result {
                self.writes += 1;
                Ok(())
            }
        }

        struct FailingWriter {
            fail_at: usize,
            writes: usize,
        }

        impl FailingWriter {
            fn new(fail_at: usize) -> Self {
                Self { fail_at, writes: 0 }
            }
        }

        impl std::fmt::Write for FailingWriter {
            fn write_str(&mut self, _s: &str) -> std::fmt::Result {
                self.writes += 1;
                if self.writes == self.fail_at {
                    return Err(std::fmt::Error);
                }
                Ok(())
            }
        }

        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut sdp = SdpBuilder::new(addr)
            .session_name("Test Session")
            .add_media(
                MediaBuilder::audio(5000)
                    .pcmu()
                    .pcma()
                    .g722()
                    .telephone_event(101)
                    .ptime(20),
            )
            .build();
        sdp.session_info = Some("Test Info".to_string());
        sdp.connection = Some(Connection {
            net_type: "IN".to_string(),
            addr_type: "IP4".to_string(),
            address: "203.0.113.1".to_string(),
        });
        sdp.attributes.push(Attribute {
            name: "ice-ufrag".to_string(),
            value: Some("abcd1234".to_string()),
        });
        sdp.attributes.push(Attribute {
            name: "rtcp-mux".to_string(),
            value: None,
        });
        sdp.media[0].connection = Some(Connection {
            net_type: "IN".to_string(),
            addr_type: "IP4".to_string(),
            address: "10.0.0.1".to_string(),
        });
        sdp.media[0].bandwidth.insert("AS".to_string(), 64);
        sdp.media[0].attributes.push(Attribute {
            name: "recvonly".to_string(),
            value: None,
        });
        sdp.media[0].attributes.push(Attribute {
            name: "fmtp".to_string(),
            value: Some("101 0-16".to_string()),
        });

        let mut counter = CountingWriter { writes: 0 };
        let _ = write!(&mut counter, "{}", sdp);
        let total_writes = counter.writes;

        for fail_at in 1..=total_writes {
            let mut writer = FailingWriter::new(fail_at);
            let _ = write!(&mut writer, "{}", sdp);
        }
    }

    #[test]
    fn test_sdp_display_media_with_connection() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut sdp = SdpBuilder::new(addr)
            .add_media(MediaBuilder::audio(5000).pcmu())
            .build();

        // Add media-level connection
        sdp.media[0].connection = Some(Connection {
            net_type: "IN".to_string(),
            addr_type: "IP4".to_string(),
            address: "10.0.0.1".to_string(),
        });

        let s = sdp.to_string();
        assert!(s.contains("c=IN IP4 10.0.0.1"));
    }

    #[test]
    fn test_sdp_display_media_with_bandwidth() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut sdp = SdpBuilder::new(addr)
            .add_media(MediaBuilder::audio(5000).pcmu())
            .build();

        // Add bandwidth
        sdp.media[0].bandwidth.insert("AS".to_string(), 64);

        let s = sdp.to_string();
        assert!(s.contains("b=AS:64"));
    }

    #[test]
    fn test_roundtrip() {
        use crate::sdp::parser::SessionDescription as ParsedSdp;

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let sdp = SdpBuilder::new(addr)
            .session_id(999)
            .session_version(1)
            .add_media(MediaBuilder::audio(5000).pcmu().pcma().telephone_event(101))
            .build();

        let sdp_str = sdp.to_string();
        let parsed = ParsedSdp::parse(&sdp_str).unwrap();

        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.origin.session_id, "999");

        let audio = parsed.audio_media().unwrap();
        assert_eq!(audio.port, 5000);
        assert_eq!(audio.formats, vec!["0", "8", "101"]);
    }

    #[test]
    fn test_media_all_directions_in_string() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Test all direction strings in output
        let sdp = SdpBuilder::new(addr)
            .add_media(
                MediaBuilder::audio(5000)
                    .pcmu()
                    .direction(Direction::SendOnly),
            )
            .build();
        let s = sdp.to_string();
        assert!(s.contains("a=sendonly"));

        let sdp = SdpBuilder::new(addr)
            .add_media(
                MediaBuilder::audio(5000)
                    .pcmu()
                    .direction(Direction::RecvOnly),
            )
            .build();
        let s = sdp.to_string();
        assert!(s.contains("a=recvonly"));

        let sdp = SdpBuilder::new(addr)
            .add_media(
                MediaBuilder::audio(5000)
                    .pcmu()
                    .direction(Direction::Inactive),
            )
            .build();
        let s = sdp.to_string();
        assert!(s.contains("a=inactive"));
    }

    #[test]
    fn test_multiple_codecs_roundtrip() {
        use crate::sdp::parser::SessionDescription as ParsedSdp;

        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let sdp = SdpBuilder::new(addr)
            .session_id(1000)
            .add_media(
                MediaBuilder::audio(5000)
                    .pcmu()
                    .pcma()
                    .g722()
                    .codec(96, "opus", 48000, Some(2))
                    .fmtp(96, "useinbandfec=1")
                    .telephone_event(101)
                    .ptime(20),
            )
            .build();

        let sdp_str = sdp.to_string();

        // Verify string content
        assert!(sdp_str.contains("a=rtpmap:0 PCMU/8000"));
        assert!(sdp_str.contains("a=rtpmap:8 PCMA/8000"));
        assert!(sdp_str.contains("a=rtpmap:9 G722/8000"));
        assert!(sdp_str.contains("a=rtpmap:96 opus/48000/2"));
        assert!(sdp_str.contains("a=fmtp:96 useinbandfec=1"));
        assert!(sdp_str.contains("a=ptime:20"));

        // Verify it can be parsed back
        let parsed = ParsedSdp::parse(&sdp_str).unwrap();
        let audio = parsed.audio_media().unwrap();
        assert_eq!(audio.formats, vec!["0", "8", "9", "96", "101"]);
    }

    #[test]
    fn test_chained_builder() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let sdp = SdpBuilder::new(addr)
            .username("user")
            .session_id(123)
            .session_version(1)
            .session_name("Call")
            .audio(5000)
            .build();

        assert_eq!(sdp.origin.username, "user");
        assert_eq!(sdp.origin.session_id, "123");
        assert_eq!(sdp.origin.session_version, "1");
        assert_eq!(sdp.session_name, "Call");
        assert_eq!(sdp.media.len(), 1);
    }
}
