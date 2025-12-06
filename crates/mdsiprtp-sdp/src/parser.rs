//! SDP parsing per RFC 4566.
//!
//! Parses SDP session descriptions from text format.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

/// SDP session description.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionDescription {
    /// Protocol version (always 0).
    pub version: u8,
    /// Origin/Session ID.
    pub origin: Origin,
    /// Session name.
    pub session_name: String,
    /// Session information (optional).
    pub session_info: Option<String>,
    /// Connection information (session-level).
    pub connection: Option<Connection>,
    /// Timing information.
    pub timing: Timing,
    /// Media descriptions.
    pub media: Vec<MediaDescription>,
    /// Session-level attributes.
    pub attributes: Vec<Attribute>,
}

impl SessionDescription {
    /// Parse SDP from string.
    pub fn parse(sdp: &str) -> Result<Self, SdpParseError> {
        let mut version = None;
        let mut origin = None;
        let mut session_name = None;
        let mut session_info = None;
        let mut connection = None;
        let mut timing = None;
        let mut attributes = Vec::new();
        let mut media = Vec::new();

        let mut current_media: Option<MediaDescription> = None;

        for line in sdp.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if line.len() < 2 || line.chars().nth(1) != Some('=') {
                continue;
            }

            let type_char = line.chars().next().unwrap();
            let value = &line[2..];

            // If we're in media section, attributes go to media
            if current_media.is_some() && type_char != 'm' {
                if let Some(ref mut m) = current_media {
                    match type_char {
                        'c' => m.connection = Some(Connection::parse(value)?),
                        'b' => {
                            if let Some((btype, bw)) = value.split_once(':') {
                                m.bandwidth.insert(btype.to_string(), bw.parse().unwrap_or(0));
                            }
                        }
                        'a' => m.attributes.push(Attribute::parse(value)),
                        _ => {}
                    }
                    continue;
                }
            }

            // New media description - save previous one
            if type_char == 'm' {
                if let Some(m) = current_media.take() {
                    media.push(m);
                }
                current_media = Some(MediaDescription::parse(value)?);
                continue;
            }

            // Session-level fields
            match type_char {
                'v' => version = Some(value.parse().map_err(|_| SdpParseError::InvalidVersion)?),
                'o' => origin = Some(Origin::parse(value)?),
                's' => session_name = Some(value.to_string()),
                'i' => session_info = Some(value.to_string()),
                'c' => connection = Some(Connection::parse(value)?),
                't' => timing = Some(Timing::parse(value)?),
                'a' => attributes.push(Attribute::parse(value)),
                _ => {} // Ignore unknown fields
            }
        }

        // Don't forget the last media description
        if let Some(m) = current_media {
            media.push(m);
        }

        Ok(SessionDescription {
            version: version.ok_or(SdpParseError::MissingVersion)?,
            origin: origin.ok_or(SdpParseError::MissingOrigin)?,
            session_name: session_name.unwrap_or_else(|| "-".to_string()),
            session_info,
            connection,
            timing: timing.ok_or(SdpParseError::MissingTiming)?,
            media,
            attributes,
        })
    }

    /// Get the first audio media description.
    pub fn audio_media(&self) -> Option<&MediaDescription> {
        self.media.iter().find(|m| m.media_type == MediaType::Audio)
    }

    /// Get audio media mutably.
    pub fn audio_media_mut(&mut self) -> Option<&mut MediaDescription> {
        self.media.iter_mut().find(|m| m.media_type == MediaType::Audio)
    }
}

/// SDP origin field.
#[derive(Debug, Clone, PartialEq)]
pub struct Origin {
    /// Username.
    pub username: String,
    /// Session ID.
    pub session_id: String,
    /// Session version.
    pub session_version: String,
    /// Network type (usually "IN").
    pub net_type: String,
    /// Address type (IP4 or IP6).
    pub addr_type: String,
    /// Unicast address.
    pub unicast_address: String,
}

impl Origin {
    fn parse(value: &str) -> Result<Self, SdpParseError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 6 {
            return Err(SdpParseError::InvalidOrigin);
        }

        Ok(Origin {
            username: parts[0].to_string(),
            session_id: parts[1].to_string(),
            session_version: parts[2].to_string(),
            net_type: parts[3].to_string(),
            addr_type: parts[4].to_string(),
            unicast_address: parts[5].to_string(),
        })
    }
}

/// Connection information.
#[derive(Debug, Clone, PartialEq)]
pub struct Connection {
    /// Network type (usually "IN").
    pub net_type: String,
    /// Address type (IP4 or IP6).
    pub addr_type: String,
    /// Connection address.
    pub address: String,
}

impl Connection {
    fn parse(value: &str) -> Result<Self, SdpParseError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(SdpParseError::InvalidConnection);
        }

        Ok(Connection {
            net_type: parts[0].to_string(),
            addr_type: parts[1].to_string(),
            address: parts[2].to_string(),
        })
    }

    /// Get the IP address.
    pub fn ip_addr(&self) -> Option<IpAddr> {
        // Handle multicast with TTL: 224.0.0.1/127
        let addr = self.address.split('/').next()?;
        IpAddr::from_str(addr).ok()
    }
}

/// Timing information.
#[derive(Debug, Clone, PartialEq)]
pub struct Timing {
    /// Start time (0 for permanent session).
    pub start: u64,
    /// Stop time (0 for permanent session).
    pub stop: u64,
}

impl Timing {
    fn parse(value: &str) -> Result<Self, SdpParseError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(SdpParseError::InvalidTiming);
        }

        Ok(Timing {
            start: parts[0].parse().unwrap_or(0),
            stop: parts[1].parse().unwrap_or(0),
        })
    }
}

/// Media type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    Audio,
    Video,
    Application,
    Message,
    Other,
}

impl From<&str> for MediaType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "audio" => MediaType::Audio,
            "video" => MediaType::Video,
            "application" => MediaType::Application,
            "message" => MediaType::Message,
            _ => MediaType::Other,
        }
    }
}

/// Media direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    /// Send and receive.
    #[default]
    SendRecv,
    /// Send only.
    SendOnly,
    /// Receive only.
    RecvOnly,
    /// Inactive.
    Inactive,
}

/// Media description.
#[derive(Debug, Clone, PartialEq)]
pub struct MediaDescription {
    /// Media type (audio, video, etc.).
    pub media_type: MediaType,
    /// Port number.
    pub port: u16,
    /// Number of ports (for RTP/RTCP pairs).
    pub num_ports: Option<u16>,
    /// Protocol (e.g., "RTP/AVP", "RTP/SAVP").
    pub protocol: String,
    /// Format list (payload types for RTP).
    pub formats: Vec<String>,
    /// Connection information (media-level).
    pub connection: Option<Connection>,
    /// Bandwidth.
    pub bandwidth: HashMap<String, u32>,
    /// Attributes.
    pub attributes: Vec<Attribute>,
}

impl MediaDescription {
    fn parse(value: &str) -> Result<Self, SdpParseError> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(SdpParseError::InvalidMedia);
        }

        let media_type = MediaType::from(parts[0]);

        // Parse port (may include number of ports: 49170/2)
        let (port, num_ports) = if let Some((p, n)) = parts[1].split_once('/') {
            (
                p.parse().map_err(|_| SdpParseError::InvalidMedia)?,
                Some(n.parse().map_err(|_| SdpParseError::InvalidMedia)?),
            )
        } else {
            (
                parts[1].parse().map_err(|_| SdpParseError::InvalidMedia)?,
                None,
            )
        };

        let protocol = parts[2].to_string();
        let formats = parts[3..].iter().map(|s| s.to_string()).collect();

        Ok(MediaDescription {
            media_type,
            port,
            num_ports,
            protocol,
            formats,
            connection: None,
            bandwidth: HashMap::new(),
            attributes: Vec::new(),
        })
    }

    /// Get the direction attribute.
    pub fn direction(&self) -> Direction {
        for attr in &self.attributes {
            match attr.name.as_str() {
                "sendrecv" => return Direction::SendRecv,
                "sendonly" => return Direction::SendOnly,
                "recvonly" => return Direction::RecvOnly,
                "inactive" => return Direction::Inactive,
                _ => {}
            }
        }
        Direction::SendRecv // Default per RFC 3264
    }

    /// Get rtpmap attributes.
    pub fn rtpmaps(&self) -> Vec<RtpMap> {
        self.attributes
            .iter()
            .filter_map(|a| {
                if a.name == "rtpmap" {
                    RtpMap::parse(a.value.as_deref()?)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get fmtp attributes.
    pub fn fmtps(&self) -> Vec<Fmtp> {
        self.attributes
            .iter()
            .filter_map(|a| {
                if a.name == "fmtp" {
                    Fmtp::parse(a.value.as_deref()?)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Check if port is 0 (rejected/disabled media).
    pub fn is_rejected(&self) -> bool {
        self.port == 0
    }
}

/// SDP attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    /// Attribute name.
    pub name: String,
    /// Attribute value (None for flag attributes like "sendrecv").
    pub value: Option<String>,
}

impl Attribute {
    fn parse(value: &str) -> Self {
        if let Some((name, val)) = value.split_once(':') {
            Attribute {
                name: name.to_string(),
                value: Some(val.to_string()),
            }
        } else {
            Attribute {
                name: value.to_string(),
                value: None,
            }
        }
    }
}

/// RTP map attribute (a=rtpmap:96 opus/48000/2).
#[derive(Debug, Clone, PartialEq)]
pub struct RtpMap {
    /// Payload type.
    pub payload_type: u8,
    /// Encoding name.
    pub encoding: String,
    /// Clock rate.
    pub clock_rate: u32,
    /// Encoding parameters (channels for audio).
    pub params: Option<String>,
}

impl RtpMap {
    fn parse(value: &str) -> Option<Self> {
        let (pt_str, rest) = value.split_once(' ')?;
        let payload_type = pt_str.parse().ok()?;

        let parts: Vec<&str> = rest.split('/').collect();
        if parts.is_empty() {
            return None;
        }

        Some(RtpMap {
            payload_type,
            encoding: parts[0].to_string(),
            clock_rate: parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(8000),
            params: parts.get(2).map(|s| s.to_string()),
        })
    }

    /// Get the number of channels (defaults to 1 for audio).
    pub fn channels(&self) -> u8 {
        self.params
            .as_ref()
            .and_then(|p| p.parse().ok())
            .unwrap_or(1)
    }
}

/// Format-specific parameters (a=fmtp:96 mode-set=0,2,4).
#[derive(Debug, Clone, PartialEq)]
pub struct Fmtp {
    /// Payload type.
    pub payload_type: u8,
    /// Parameters string.
    pub params: String,
}

impl Fmtp {
    fn parse(value: &str) -> Option<Self> {
        let (pt_str, params) = value.split_once(' ')?;
        Some(Fmtp {
            payload_type: pt_str.parse().ok()?,
            params: params.to_string(),
        })
    }
}

/// SDP parse error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SdpParseError {
    #[error("Missing version")]
    MissingVersion,
    #[error("Invalid version")]
    InvalidVersion,
    #[error("Missing origin")]
    MissingOrigin,
    #[error("Invalid origin")]
    InvalidOrigin,
    #[error("Invalid connection")]
    InvalidConnection,
    #[error("Missing timing")]
    MissingTiming,
    #[error("Invalid timing")]
    InvalidTiming,
    #[error("Invalid media")]
    InvalidMedia,
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC_SDP: &str = r#"v=0
o=- 1234567890 1 IN IP4 192.168.1.1
s=Test Session
c=IN IP4 192.168.1.1
t=0 0
m=audio 49170 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
"#;

    #[test]
    fn test_parse_basic_sdp() {
        let sdp = SessionDescription::parse(BASIC_SDP).unwrap();

        assert_eq!(sdp.version, 0);
        assert_eq!(sdp.origin.username, "-");
        assert_eq!(sdp.session_name, "Test Session");
        assert!(sdp.connection.is_some());

        let audio = sdp.audio_media().unwrap();
        assert_eq!(audio.port, 49170);
        assert_eq!(audio.protocol, "RTP/AVP");
        assert_eq!(audio.formats, vec!["0", "8"]);
        assert_eq!(audio.direction(), Direction::SendRecv);
    }

    #[test]
    fn test_parse_rtpmap() {
        let sdp = SessionDescription::parse(BASIC_SDP).unwrap();
        let audio = sdp.audio_media().unwrap();
        let rtpmaps = audio.rtpmaps();

        assert_eq!(rtpmaps.len(), 2);
        assert_eq!(rtpmaps[0].payload_type, 0);
        assert_eq!(rtpmaps[0].encoding, "PCMU");
        assert_eq!(rtpmaps[0].clock_rate, 8000);
        assert_eq!(rtpmaps[1].payload_type, 8);
        assert_eq!(rtpmaps[1].encoding, "PCMA");
    }

    #[test]
    fn test_connection_ip() {
        let sdp = SessionDescription::parse(BASIC_SDP).unwrap();
        let conn = sdp.connection.unwrap();
        let ip = conn.ip_addr().unwrap();
        assert_eq!(ip.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_media_direction() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 0 RTP/AVP 0\na=inactive\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        let audio = parsed.audio_media().unwrap();
        assert_eq!(audio.direction(), Direction::Inactive);
        assert!(audio.is_rejected());
    }
}
