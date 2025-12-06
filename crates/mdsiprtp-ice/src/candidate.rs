//! ICE candidate types and utilities (RFC 8445).

use std::fmt;
use std::net::SocketAddr;

/// ICE candidate type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateType {
    /// Host candidate (local address).
    Host,
    /// Server reflexive candidate (STUN mapped address).
    ServerReflexive,
    /// Peer reflexive candidate (discovered during checks).
    PeerReflexive,
    /// Relay candidate (TURN allocated address).
    Relay,
}

impl CandidateType {
    /// Get the type preference for priority calculation.
    ///
    /// RFC 8445 Section 5.1.2.1: Recommended values.
    pub fn type_preference(&self) -> u32 {
        match self {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        }
    }

    /// Get the SDP candidate type string.
    pub fn as_str(&self) -> &'static str {
        match self {
            CandidateType::Host => "host",
            CandidateType::ServerReflexive => "srflx",
            CandidateType::PeerReflexive => "prflx",
            CandidateType::Relay => "relay",
        }
    }

    /// Parse from SDP candidate type string.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "host" => Some(CandidateType::Host),
            "srflx" => Some(CandidateType::ServerReflexive),
            "prflx" => Some(CandidateType::PeerReflexive),
            "relay" => Some(CandidateType::Relay),
            _ => None,
        }
    }
}

impl fmt::Display for CandidateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// ICE candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Foundation (identifies similar candidates).
    pub foundation: String,
    /// Component ID (1 for RTP, 2 for RTCP).
    pub component: u8,
    /// Transport protocol.
    pub transport: Transport,
    /// Priority (higher is better).
    pub priority: u32,
    /// Candidate address.
    pub address: SocketAddr,
    /// Candidate type.
    pub candidate_type: CandidateType,
    /// Related address (for srflx/prflx/relay).
    pub related_address: Option<SocketAddr>,
}

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Candidate {
    /// Create a new host candidate.
    pub fn host(address: SocketAddr, component: u8) -> Self {
        let foundation = format!("host{}{}", address.ip(), component);
        let priority = calculate_priority(CandidateType::Host, 65535, component);

        Self {
            foundation,
            component,
            transport: Transport::Udp,
            priority,
            address,
            candidate_type: CandidateType::Host,
            related_address: None,
        }
    }

    /// Create a new server reflexive candidate.
    pub fn server_reflexive(
        address: SocketAddr,
        base: SocketAddr,
        component: u8,
    ) -> Self {
        let foundation = format!("srflx{}{}", base.ip(), component);
        let priority = calculate_priority(CandidateType::ServerReflexive, 65535, component);

        Self {
            foundation,
            component,
            transport: Transport::Udp,
            priority,
            address,
            candidate_type: CandidateType::ServerReflexive,
            related_address: Some(base),
        }
    }

    /// Create a new peer reflexive candidate.
    pub fn peer_reflexive(
        address: SocketAddr,
        base: SocketAddr,
        component: u8,
        priority: u32,
    ) -> Self {
        let foundation = format!("prflx{}{}", base.ip(), component);

        Self {
            foundation,
            component,
            transport: Transport::Udp,
            priority,
            address,
            candidate_type: CandidateType::PeerReflexive,
            related_address: Some(base),
        }
    }

    /// Format as SDP a=candidate attribute value.
    pub fn to_sdp(&self) -> String {
        let mut s = format!(
            "{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.transport,
            self.priority,
            self.address.ip(),
            self.address.port(),
            self.candidate_type
        );

        if let Some(raddr) = self.related_address {
            s.push_str(&format!(" raddr {} rport {}", raddr.ip(), raddr.port()));
        }

        s
    }

    /// Parse from SDP a=candidate attribute value.
    pub fn from_sdp(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() < 8 {
            return None;
        }

        let foundation = parts[0].to_string();
        let component: u8 = parts[1].parse().ok()?;
        let transport = match parts[2].to_uppercase().as_str() {
            "UDP" => Transport::Udp,
            "TCP" => Transport::Tcp,
            _ => return None,
        };
        let priority: u32 = parts[3].parse().ok()?;
        let ip: std::net::IpAddr = parts[4].parse().ok()?;
        let port: u16 = parts[5].parse().ok()?;
        let address = SocketAddr::new(ip, port);

        // parts[6] should be "typ"
        if parts[6] != "typ" {
            return None;
        }

        let candidate_type = CandidateType::parse(parts[7])?;

        // Parse optional raddr/rport
        let mut related_address = None;
        let mut i = 8;
        while i + 1 < parts.len() {
            match parts[i] {
                "raddr" => {
                    if i + 3 < parts.len() && parts[i + 2] == "rport" {
                        let rip: std::net::IpAddr = parts[i + 1].parse().ok()?;
                        let rport: u16 = parts[i + 3].parse().ok()?;
                        related_address = Some(SocketAddr::new(rip, rport));
                        i += 4;
                    } else {
                        i += 1;
                    }
                }
                _ => i += 1,
            }
        }

        Some(Self {
            foundation,
            component,
            transport,
            priority,
            address,
            candidate_type,
            related_address,
        })
    }
}

/// Calculate candidate priority per RFC 8445 Section 5.1.2.1.
///
/// priority = (2^24 * type_preference) + (2^8 * local_preference) + (256 - component)
pub fn calculate_priority(candidate_type: CandidateType, local_preference: u32, component: u8) -> u32 {
    let type_pref = candidate_type.type_preference();
    (type_pref << 24) + (local_preference << 8) + (256 - component as u32)
}

/// Calculate pair priority per RFC 8445 Section 6.1.2.3.
pub fn calculate_pair_priority(controlling: bool, g: u32, d: u32) -> u64 {
    let (g, d) = if controlling { (g, d) } else { (d, g) };
    let min = std::cmp::min(g, d) as u64;
    let max = std::cmp::max(g, d) as u64;
    (1 << 32) * min + 2 * max + if g > d { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_candidate_type_preference() {
        assert!(CandidateType::Host.type_preference() > CandidateType::ServerReflexive.type_preference());
        assert!(CandidateType::ServerReflexive.type_preference() > CandidateType::Relay.type_preference());
    }

    #[test]
    fn test_host_candidate() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let candidate = Candidate::host(addr, 1);

        assert_eq!(candidate.component, 1);
        assert_eq!(candidate.candidate_type, CandidateType::Host);
        assert_eq!(candidate.address, addr);
        assert!(candidate.related_address.is_none());
    }

    #[test]
    fn test_srflx_candidate() {
        let mapped = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 12345);
        let base = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let candidate = Candidate::server_reflexive(mapped, base, 1);

        assert_eq!(candidate.candidate_type, CandidateType::ServerReflexive);
        assert_eq!(candidate.address, mapped);
        assert_eq!(candidate.related_address, Some(base));
    }

    #[test]
    fn test_sdp_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let candidate = Candidate::host(addr, 1);

        let sdp = candidate.to_sdp();
        let parsed = Candidate::from_sdp(&sdp).unwrap();

        assert_eq!(parsed.foundation, candidate.foundation);
        assert_eq!(parsed.component, candidate.component);
        assert_eq!(parsed.priority, candidate.priority);
        assert_eq!(parsed.address, candidate.address);
        assert_eq!(parsed.candidate_type, candidate.candidate_type);
    }

    #[test]
    fn test_sdp_parse_with_raddr() {
        let sdp = "srflx1 1 UDP 1694498815 203.0.113.1 12345 typ srflx raddr 192.168.1.100 rport 5000";
        let candidate = Candidate::from_sdp(sdp).unwrap();

        assert_eq!(candidate.candidate_type, CandidateType::ServerReflexive);
        assert_eq!(candidate.address.port(), 12345);
        assert!(candidate.related_address.is_some());
        assert_eq!(candidate.related_address.unwrap().port(), 5000);
    }

    #[test]
    fn test_priority_calculation() {
        let host_prio = calculate_priority(CandidateType::Host, 65535, 1);
        let srflx_prio = calculate_priority(CandidateType::ServerReflexive, 65535, 1);

        assert!(host_prio > srflx_prio);
    }

    #[test]
    fn test_pair_priority() {
        // For the same pair seen from both agents:
        // Agent A (controlling): local=1000, remote=2000
        // Agent B (controlled): local=2000, remote=1000 (reversed perspective)
        let prio1 = calculate_pair_priority(true, 1000, 2000);
        let prio2 = calculate_pair_priority(false, 2000, 1000);

        // Both agents should compute the same pair priority
        assert_eq!(prio1, prio2);

        // Also verify the formula works for identical priorities
        let prio3 = calculate_pair_priority(true, 1000, 1000);
        let prio4 = calculate_pair_priority(false, 1000, 1000);
        assert_eq!(prio3, prio4);
    }
}
