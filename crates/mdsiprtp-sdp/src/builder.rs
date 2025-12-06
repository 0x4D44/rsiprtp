//! SDP builder.
//!
//! Builds SDP session descriptions programmatically.

use std::fmt::Write;
use std::net::IpAddr;

use crate::parser::{
    Attribute, Connection, Direction, MediaDescription, MediaType, Origin,
    SessionDescription, Timing,
};
use mdsiprtp_core::random_u64;

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
        let addr_type = if self.local_addr.is_ipv4() { "IP4" } else { "IP6" };

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
    fmtps: Vec<(u8, String)>,                     // (pt, params)
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
        self.rtpmaps.push((pt, "telephone-event".to_string(), 8000, None));
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
        self.rtpmaps.push((pt, encoding.into(), clock_rate, channels));
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
    write!(&mut line, "m={} {} {}", media_type, media.port, media.protocol)?;
    for fmt in &media.formats {
        write!(&mut line, " {}", fmt)?;
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
    use std::net::Ipv4Addr;

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
    fn test_roundtrip() {
        use crate::parser::SessionDescription as ParsedSdp;

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
}
