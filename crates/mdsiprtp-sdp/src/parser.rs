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
                                m.bandwidth
                                    .insert(btype.to_string(), bw.parse().unwrap_or(0));
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
        self.media
            .iter_mut()
            .find(|m| m.media_type == MediaType::Audio)
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

    // SdpParseError tests
    #[test]
    fn test_sdp_parse_error_debug() {
        let err = SdpParseError::MissingVersion;
        let debug = format!("{:?}", err);
        assert!(debug.contains("MissingVersion"));
    }

    #[test]
    fn test_sdp_parse_error_display() {
        assert_eq!(SdpParseError::MissingVersion.to_string(), "Missing version");
        assert_eq!(SdpParseError::InvalidVersion.to_string(), "Invalid version");
        assert_eq!(SdpParseError::MissingOrigin.to_string(), "Missing origin");
        assert_eq!(SdpParseError::InvalidOrigin.to_string(), "Invalid origin");
        assert_eq!(
            SdpParseError::InvalidConnection.to_string(),
            "Invalid connection"
        );
        assert_eq!(SdpParseError::MissingTiming.to_string(), "Missing timing");
        assert_eq!(SdpParseError::InvalidTiming.to_string(), "Invalid timing");
        assert_eq!(SdpParseError::InvalidMedia.to_string(), "Invalid media");
    }

    #[test]
    fn test_sdp_parse_error_clone() {
        let err = SdpParseError::InvalidOrigin;
        let cloned = err.clone();
        assert!(format!("{:?}", cloned).contains("InvalidOrigin"));
    }

    // SessionDescription tests
    #[test]
    fn test_session_description_eq() {
        let sdp1 = SessionDescription::parse(BASIC_SDP).unwrap();
        let sdp2 = SessionDescription::parse(BASIC_SDP).unwrap();
        assert_eq!(sdp1, sdp2);
    }

    #[test]
    fn test_session_description_clone() {
        let sdp1 = SessionDescription::parse(BASIC_SDP).unwrap();
        let sdp2 = sdp1.clone();
        assert_eq!(sdp1.session_name, sdp2.session_name);
    }

    #[test]
    fn test_parse_missing_version() {
        let sdp = "o=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\n";
        let result = SessionDescription::parse(sdp);
        assert!(matches!(result, Err(SdpParseError::MissingVersion)));
    }

    #[test]
    fn test_parse_missing_origin() {
        let sdp = "v=0\ns=-\nt=0 0\n";
        let result = SessionDescription::parse(sdp);
        assert!(matches!(result, Err(SdpParseError::MissingOrigin)));
    }

    #[test]
    fn test_parse_missing_timing() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\n";
        let result = SessionDescription::parse(sdp);
        assert!(matches!(result, Err(SdpParseError::MissingTiming)));
    }

    #[test]
    fn test_parse_with_session_info() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\ni=Session Info\nt=0 0\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.session_info, Some("Session Info".to_string()));
    }

    #[test]
    fn test_parse_empty_lines() {
        let sdp = "v=0\n\no=- 0 0 IN IP4 0.0.0.0\n\ns=-\nt=0 0\n\n";
        let result = SessionDescription::parse(sdp);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_short_lines_ignored() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nx\nt=0 0\n";
        let result = SessionDescription::parse(sdp);
        assert!(result.is_ok());
    }

    // Origin tests
    #[test]
    fn test_origin_debug() {
        let sdp = SessionDescription::parse(BASIC_SDP).unwrap();
        let debug = format!("{:?}", sdp.origin);
        assert!(debug.contains("Origin"));
    }

    #[test]
    fn test_origin_clone() {
        let sdp = SessionDescription::parse(BASIC_SDP).unwrap();
        let cloned = sdp.origin.clone();
        assert_eq!(cloned.username, sdp.origin.username);
    }

    #[test]
    fn test_origin_eq() {
        let sdp1 = SessionDescription::parse(BASIC_SDP).unwrap();
        let sdp2 = SessionDescription::parse(BASIC_SDP).unwrap();
        assert_eq!(sdp1.origin, sdp2.origin);
    }

    // Connection tests
    #[test]
    fn test_connection_debug() {
        let sdp = SessionDescription::parse(BASIC_SDP).unwrap();
        let conn = sdp.connection.unwrap();
        let debug = format!("{:?}", conn);
        assert!(debug.contains("Connection"));
    }

    #[test]
    fn test_connection_clone() {
        let sdp = SessionDescription::parse(BASIC_SDP).unwrap();
        let conn = sdp.connection.unwrap();
        let cloned = conn.clone();
        assert_eq!(cloned.address, conn.address);
    }

    #[test]
    fn test_connection_eq() {
        let sdp1 = SessionDescription::parse(BASIC_SDP).unwrap();
        let sdp2 = SessionDescription::parse(BASIC_SDP).unwrap();
        assert_eq!(sdp1.connection, sdp2.connection);
    }

    #[test]
    fn test_connection_ipv6() {
        let sdp = "v=0\no=- 0 0 IN IP6 ::1\ns=-\nc=IN IP6 2001:db8::1\nt=0 0\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        let conn = parsed.connection.unwrap();
        assert_eq!(conn.net_type, "IN");
        assert_eq!(conn.addr_type, "IP6");
        let ip = conn.ip_addr().unwrap();
        assert!(ip.is_ipv6());
    }

    #[test]
    fn test_connection_invalid_ip() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nc=IN IP4 not-an-ip\nt=0 0\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        let conn = parsed.connection.unwrap();
        assert!(conn.ip_addr().is_none());
    }

    // Timing tests
    #[test]
    fn test_timing_debug() {
        let sdp = SessionDescription::parse(BASIC_SDP).unwrap();
        let debug = format!("{:?}", sdp.timing);
        assert!(debug.contains("Timing"));
    }

    #[test]
    fn test_timing_clone() {
        let sdp = SessionDescription::parse(BASIC_SDP).unwrap();
        let cloned = sdp.timing.clone();
        assert_eq!(cloned.start, sdp.timing.start);
    }

    #[test]
    fn test_timing_eq() {
        let sdp1 = SessionDescription::parse(BASIC_SDP).unwrap();
        let sdp2 = SessionDescription::parse(BASIC_SDP).unwrap();
        assert_eq!(sdp1.timing, sdp2.timing);
    }

    // MediaType tests
    #[test]
    fn test_media_type_from_str() {
        assert_eq!(MediaType::from("audio"), MediaType::Audio);
        assert_eq!(MediaType::from("AUDIO"), MediaType::Audio);
        assert_eq!(MediaType::from("video"), MediaType::Video);
        assert_eq!(MediaType::from("application"), MediaType::Application);
        assert_eq!(MediaType::from("message"), MediaType::Message);
        assert_eq!(MediaType::from("unknown"), MediaType::Other);
    }

    #[test]
    fn test_media_type_debug() {
        assert!(format!("{:?}", MediaType::Audio).contains("Audio"));
        assert!(format!("{:?}", MediaType::Video).contains("Video"));
    }

    #[test]
    fn test_media_type_clone() {
        let mt = MediaType::Audio;
        let cloned = mt;
        assert_eq!(mt, cloned);
    }

    // Direction tests
    #[test]
    fn test_direction_default() {
        let dir = Direction::default();
        assert_eq!(dir, Direction::SendRecv);
    }

    #[test]
    fn test_direction_debug() {
        assert!(format!("{:?}", Direction::SendRecv).contains("SendRecv"));
        assert!(format!("{:?}", Direction::SendOnly).contains("SendOnly"));
        assert!(format!("{:?}", Direction::RecvOnly).contains("RecvOnly"));
        assert!(format!("{:?}", Direction::Inactive).contains("Inactive"));
    }

    #[test]
    fn test_direction_clone() {
        let dir = Direction::RecvOnly;
        let cloned = dir;
        assert_eq!(dir, cloned);
    }

    // MediaDescription tests
    #[test]
    fn test_media_description_debug() {
        let sdp = SessionDescription::parse(BASIC_SDP).unwrap();
        let audio = sdp.audio_media().unwrap();
        let debug = format!("{:?}", audio);
        assert!(debug.contains("MediaDescription"));
    }

    #[test]
    fn test_media_description_with_port_range() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 49170/2 RTP/AVP 0\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        let audio = parsed.audio_media().unwrap();
        assert_eq!(audio.port, 49170);
        assert_eq!(audio.num_ports, Some(2));
    }

    #[test]
    fn test_media_description_video() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=video 49172 RTP/AVP 96\na=rtpmap:96 H264/90000\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        assert!(parsed.audio_media().is_none());
        assert_eq!(parsed.media[0].media_type, MediaType::Video);
    }

    #[test]
    fn test_media_with_connection() {
        let sdp =
            "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 5000 RTP/AVP 0\nc=IN IP4 10.0.0.1\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        let audio = parsed.audio_media().unwrap();
        let conn = audio.connection.as_ref().unwrap();
        assert_eq!(conn.address, "10.0.0.1");
    }

    #[test]
    fn test_media_with_bandwidth() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 5000 RTP/AVP 0\nb=AS:64\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        let audio = parsed.audio_media().unwrap();
        assert_eq!(audio.bandwidth.get("AS"), Some(&64));
    }

    #[test]
    fn test_media_direction_sendonly() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 5000 RTP/AVP 0\na=sendonly\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        let audio = parsed.audio_media().unwrap();
        assert_eq!(audio.direction(), Direction::SendOnly);
    }

    #[test]
    fn test_media_direction_recvonly() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 5000 RTP/AVP 0\na=recvonly\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        let audio = parsed.audio_media().unwrap();
        assert_eq!(audio.direction(), Direction::RecvOnly);
    }

    #[test]
    fn test_media_direction_default() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 5000 RTP/AVP 0\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        let audio = parsed.audio_media().unwrap();
        assert_eq!(audio.direction(), Direction::SendRecv); // Default
    }

    #[test]
    fn test_is_rejected() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 0 RTP/AVP 0\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        let audio = parsed.audio_media().unwrap();
        assert!(audio.is_rejected());
    }

    #[test]
    fn test_is_not_rejected() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 5000 RTP/AVP 0\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        let audio = parsed.audio_media().unwrap();
        assert!(!audio.is_rejected());
    }

    // Attribute tests
    #[test]
    fn test_attribute_debug() {
        let attr = Attribute {
            name: "test".to_string(),
            value: Some("value".to_string()),
        };
        let debug = format!("{:?}", attr);
        assert!(debug.contains("Attribute"));
    }

    #[test]
    fn test_attribute_clone() {
        let attr = Attribute {
            name: "test".to_string(),
            value: Some("value".to_string()),
        };
        let cloned = attr.clone();
        assert_eq!(cloned.name, attr.name);
    }

    #[test]
    fn test_attribute_eq() {
        let a1 = Attribute {
            name: "test".to_string(),
            value: None,
        };
        let a2 = Attribute {
            name: "test".to_string(),
            value: None,
        };
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_attribute_parse_with_value() {
        let attr = Attribute::parse("rtpmap:0 PCMU/8000");
        assert_eq!(attr.name, "rtpmap");
        assert_eq!(attr.value, Some("0 PCMU/8000".to_string()));
    }

    #[test]
    fn test_attribute_parse_flag() {
        let attr = Attribute::parse("sendrecv");
        assert_eq!(attr.name, "sendrecv");
        assert!(attr.value.is_none());
    }

    // RtpMap tests
    #[test]
    fn test_rtpmap_debug() {
        let rtpmap = RtpMap {
            payload_type: 0,
            encoding: "PCMU".to_string(),
            clock_rate: 8000,
            params: None,
        };
        let debug = format!("{:?}", rtpmap);
        assert!(debug.contains("RtpMap"));
    }

    #[test]
    fn test_rtpmap_clone() {
        let rtpmap = RtpMap {
            payload_type: 0,
            encoding: "PCMU".to_string(),
            clock_rate: 8000,
            params: None,
        };
        let cloned = rtpmap.clone();
        assert_eq!(cloned.encoding, rtpmap.encoding);
    }

    #[test]
    fn test_rtpmap_eq() {
        let r1 = RtpMap {
            payload_type: 0,
            encoding: "PCMU".to_string(),
            clock_rate: 8000,
            params: None,
        };
        let r2 = RtpMap {
            payload_type: 0,
            encoding: "PCMU".to_string(),
            clock_rate: 8000,
            params: None,
        };
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_rtpmap_channels_default() {
        let rtpmap = RtpMap {
            payload_type: 0,
            encoding: "PCMU".to_string(),
            clock_rate: 8000,
            params: None,
        };
        assert_eq!(rtpmap.channels(), 1);
    }

    #[test]
    fn test_rtpmap_channels_stereo() {
        let rtpmap = RtpMap {
            payload_type: 96,
            encoding: "opus".to_string(),
            clock_rate: 48000,
            params: Some("2".to_string()),
        };
        assert_eq!(rtpmap.channels(), 2);
    }

    #[test]
    fn test_rtpmap_parse_with_channels() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 5000 RTP/AVP 96\na=rtpmap:96 opus/48000/2\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        let audio = parsed.audio_media().unwrap();
        let rtpmaps = audio.rtpmaps();
        assert_eq!(rtpmaps[0].channels(), 2);
    }

    // Fmtp tests
    #[test]
    fn test_fmtp_debug() {
        let fmtp = Fmtp {
            payload_type: 101,
            params: "0-16".to_string(),
        };
        let debug = format!("{:?}", fmtp);
        assert!(debug.contains("Fmtp"));
    }

    #[test]
    fn test_fmtp_clone() {
        let fmtp = Fmtp {
            payload_type: 101,
            params: "0-16".to_string(),
        };
        let cloned = fmtp.clone();
        assert_eq!(cloned.params, fmtp.params);
    }

    #[test]
    fn test_fmtp_eq() {
        let f1 = Fmtp {
            payload_type: 101,
            params: "0-16".to_string(),
        };
        let f2 = Fmtp {
            payload_type: 101,
            params: "0-16".to_string(),
        };
        assert_eq!(f1, f2);
    }

    #[test]
    fn test_fmtps() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 5000 RTP/AVP 101\na=rtpmap:101 telephone-event/8000\na=fmtp:101 0-16\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        let audio = parsed.audio_media().unwrap();
        let fmtps = audio.fmtps();
        assert_eq!(fmtps.len(), 1);
        assert_eq!(fmtps[0].payload_type, 101);
        assert_eq!(fmtps[0].params, "0-16");
    }

    // Multiple media streams
    #[test]
    fn test_multiple_media_streams() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\nt=0 0\nm=audio 5000 RTP/AVP 0\nm=video 5002 RTP/AVP 96\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        assert_eq!(parsed.media.len(), 2);
        assert_eq!(parsed.media[0].media_type, MediaType::Audio);
        assert_eq!(parsed.media[1].media_type, MediaType::Video);
    }

    // Session-level attributes
    #[test]
    fn test_session_level_attributes() {
        let sdp = "v=0\no=- 0 0 IN IP4 0.0.0.0\ns=-\na=group:BUNDLE audio video\nt=0 0\nm=audio 5000 RTP/AVP 0\n";
        let parsed = SessionDescription::parse(sdp).unwrap();
        assert!(!parsed.attributes.is_empty());
        assert_eq!(parsed.attributes[0].name, "group");
    }
}
