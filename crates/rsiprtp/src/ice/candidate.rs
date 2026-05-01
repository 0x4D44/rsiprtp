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
    /// User Datagram Protocol — the common case for ICE candidates.
    Udp,
    /// Transmission Control Protocol — used by ICE-TCP (RFC 6544).
    Tcp,
}

impl Transport {
    /// Return the SDP token for this transport (`"UDP"` or `"TCP"`).
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
    pub fn server_reflexive(address: SocketAddr, base: SocketAddr, component: u8) -> Self {
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
pub fn calculate_priority(
    candidate_type: CandidateType,
    local_preference: u32,
    component: u8,
) -> u32 {
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
        assert!(
            CandidateType::Host.type_preference()
                > CandidateType::ServerReflexive.type_preference()
        );
        assert!(
            CandidateType::ServerReflexive.type_preference()
                > CandidateType::Relay.type_preference()
        );
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
        let sdp =
            "srflx1 1 UDP 1694498815 203.0.113.1 12345 typ srflx raddr 192.168.1.100 rport 5000";
        let candidate = Candidate::from_sdp(sdp).unwrap();

        assert_eq!(candidate.candidate_type, CandidateType::ServerReflexive);
        assert_eq!(candidate.address.port(), 12345);
        assert!(candidate.related_address.is_some());
        assert_eq!(candidate.related_address.unwrap().port(), 5000);
    }

    #[test]
    fn test_sdp_parse_invalid_raddr_rport() {
        let sdp =
            "srflx1 1 UDP 1694498815 203.0.113.1 12345 typ srflx raddr 999.999.999.999 rport bad";
        let candidate = Candidate::from_sdp(sdp);
        assert!(candidate.is_none());
    }

    #[test]
    fn test_sdp_parse_invalid_rport_only() {
        let sdp =
            "srflx1 1 UDP 1694498815 203.0.113.1 12345 typ srflx raddr 192.168.1.100 rport bad";
        let candidate = Candidate::from_sdp(sdp);
        assert!(candidate.is_none());
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

    // Additional tests for better coverage

    #[test]
    fn test_candidate_type_debug() {
        assert!(format!("{:?}", CandidateType::Host).contains("Host"));
        assert!(format!("{:?}", CandidateType::ServerReflexive).contains("ServerReflexive"));
        assert!(format!("{:?}", CandidateType::PeerReflexive).contains("PeerReflexive"));
        assert!(format!("{:?}", CandidateType::Relay).contains("Relay"));
    }

    #[test]
    #[allow(clippy::clone_on_copy)] // exercise derived Clone for coverage
    fn test_candidate_type_clone() {
        let ct = CandidateType::Host;
        let cloned = ct.clone();
        assert_eq!(ct, cloned);
    }

    #[test]
    fn test_candidate_type_copy() {
        let ct = CandidateType::Relay;
        let copied: CandidateType = ct;
        assert_eq!(ct, copied);
    }

    #[test]
    fn test_candidate_type_eq() {
        assert_eq!(CandidateType::Host, CandidateType::Host);
        assert_ne!(CandidateType::Host, CandidateType::Relay);
    }

    #[test]
    fn test_candidate_type_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CandidateType::Host);
        set.insert(CandidateType::Relay);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&CandidateType::Host));
    }

    #[test]
    fn test_candidate_type_display() {
        assert_eq!(format!("{}", CandidateType::Host), "host");
        assert_eq!(format!("{}", CandidateType::ServerReflexive), "srflx");
        assert_eq!(format!("{}", CandidateType::PeerReflexive), "prflx");
        assert_eq!(format!("{}", CandidateType::Relay), "relay");
    }

    #[test]
    fn test_candidate_type_as_str() {
        assert_eq!(CandidateType::Host.as_str(), "host");
        assert_eq!(CandidateType::ServerReflexive.as_str(), "srflx");
        assert_eq!(CandidateType::PeerReflexive.as_str(), "prflx");
        assert_eq!(CandidateType::Relay.as_str(), "relay");
    }

    #[test]
    fn test_candidate_type_parse_all() {
        assert_eq!(CandidateType::parse("host"), Some(CandidateType::Host));
        assert_eq!(
            CandidateType::parse("srflx"),
            Some(CandidateType::ServerReflexive)
        );
        assert_eq!(
            CandidateType::parse("prflx"),
            Some(CandidateType::PeerReflexive)
        );
        assert_eq!(CandidateType::parse("relay"), Some(CandidateType::Relay));
        assert_eq!(CandidateType::parse("invalid"), None);
    }

    #[test]
    fn test_transport_debug() {
        assert!(format!("{:?}", Transport::Udp).contains("Udp"));
        assert!(format!("{:?}", Transport::Tcp).contains("Tcp"));
    }

    #[test]
    #[allow(clippy::clone_on_copy)] // exercise derived Clone for coverage
    fn test_transport_clone() {
        let t = Transport::Udp;
        let cloned = t.clone();
        assert_eq!(t, cloned);
    }

    #[test]
    fn test_transport_copy() {
        let t = Transport::Tcp;
        let copied: Transport = t;
        assert_eq!(t, copied);
    }

    #[test]
    fn test_transport_eq() {
        assert_eq!(Transport::Udp, Transport::Udp);
        assert_ne!(Transport::Udp, Transport::Tcp);
    }

    #[test]
    fn test_transport_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Transport::Udp);
        set.insert(Transport::Tcp);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&Transport::Udp));
    }

    #[test]
    fn test_transport_display() {
        assert_eq!(format!("{}", Transport::Udp), "UDP");
        assert_eq!(format!("{}", Transport::Tcp), "TCP");
    }

    #[test]
    fn test_transport_as_str() {
        assert_eq!(Transport::Udp.as_str(), "UDP");
        assert_eq!(Transport::Tcp.as_str(), "TCP");
    }

    #[test]
    fn test_candidate_debug() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let candidate = Candidate::host(addr, 1);
        let debug = format!("{:?}", candidate);
        assert!(debug.contains("Candidate"));
    }

    #[test]
    fn test_candidate_clone() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let candidate = Candidate::host(addr, 1);
        let cloned = candidate.clone();
        assert_eq!(candidate, cloned);
    }

    #[test]
    fn test_candidate_eq() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let c1 = Candidate::host(addr, 1);
        let c2 = Candidate::host(addr, 1);
        let c3 = Candidate::host(addr, 2); // Different component
        assert_eq!(c1, c2);
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_peer_reflexive_candidate() {
        let mapped = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 54321);
        let base = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let candidate = Candidate::peer_reflexive(mapped, base, 1, 1000000);

        assert_eq!(candidate.candidate_type, CandidateType::PeerReflexive);
        assert_eq!(candidate.address, mapped);
        assert_eq!(candidate.related_address, Some(base));
        assert_eq!(candidate.priority, 1000000);
    }

    #[test]
    fn test_sdp_roundtrip_with_related() {
        let mapped = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 12345);
        let base = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let candidate = Candidate::server_reflexive(mapped, base, 1);

        let sdp = candidate.to_sdp();
        assert!(sdp.contains("raddr"));
        assert!(sdp.contains("rport"));

        let parsed = Candidate::from_sdp(&sdp).unwrap();
        assert_eq!(parsed.candidate_type, candidate.candidate_type);
        assert_eq!(parsed.related_address, candidate.related_address);
    }

    #[test]
    fn test_from_sdp_tcp_transport() {
        let sdp = "host1 1 TCP 2130706431 192.168.1.100 5000 typ host";
        let candidate = Candidate::from_sdp(sdp).unwrap();
        assert_eq!(candidate.transport, Transport::Tcp);
    }

    #[test]
    fn test_from_sdp_lowercase_transport() {
        let sdp = "host1 1 udp 2130706431 192.168.1.100 5000 typ host";
        let candidate = Candidate::from_sdp(sdp).unwrap();
        assert_eq!(candidate.transport, Transport::Udp);
    }

    #[test]
    fn test_from_sdp_too_short() {
        let sdp = "host1 1 UDP";
        assert!(Candidate::from_sdp(sdp).is_none());
    }

    #[test]
    fn test_from_sdp_invalid_component() {
        let sdp = "host1 abc UDP 2130706431 192.168.1.100 5000 typ host";
        assert!(Candidate::from_sdp(sdp).is_none());
    }

    #[test]
    fn test_from_sdp_invalid_transport() {
        let sdp = "host1 1 SCTP 2130706431 192.168.1.100 5000 typ host";
        assert!(Candidate::from_sdp(sdp).is_none());
    }

    #[test]
    fn test_from_sdp_invalid_priority() {
        let sdp = "host1 1 UDP notanumber 192.168.1.100 5000 typ host";
        assert!(Candidate::from_sdp(sdp).is_none());
    }

    #[test]
    fn test_from_sdp_invalid_ip() {
        let sdp = "host1 1 UDP 2130706431 notanip 5000 typ host";
        assert!(Candidate::from_sdp(sdp).is_none());
    }

    #[test]
    fn test_from_sdp_invalid_port() {
        let sdp = "host1 1 UDP 2130706431 192.168.1.100 notaport typ host";
        assert!(Candidate::from_sdp(sdp).is_none());
    }

    #[test]
    fn test_from_sdp_missing_typ() {
        let sdp = "host1 1 UDP 2130706431 192.168.1.100 5000 nottyp host";
        assert!(Candidate::from_sdp(sdp).is_none());
    }

    #[test]
    fn test_from_sdp_invalid_candidate_type() {
        let sdp = "host1 1 UDP 2130706431 192.168.1.100 5000 typ invalid";
        assert!(Candidate::from_sdp(sdp).is_none());
    }

    #[test]
    fn test_from_sdp_raddr_without_rport() {
        // raddr without rport should be handled
        let sdp = "srflx1 1 UDP 1694498815 203.0.113.1 12345 typ srflx raddr 192.168.1.100";
        let candidate = Candidate::from_sdp(sdp);
        // Should still parse, just without related_address
        assert!(candidate.is_some());
    }

    #[test]
    fn test_from_sdp_raddr_with_non_rport_param() {
        let sdp = "srflx1 1 UDP 1694498815 203.0.113.1 12345 typ srflx raddr 192.168.1.100 foo bar";
        let candidate = Candidate::from_sdp(sdp).unwrap();
        assert!(candidate.related_address.is_none());
    }

    #[test]
    fn test_priority_calculation_component_2() {
        // RTCP component (2) should have slightly lower priority
        let rtp_prio = calculate_priority(CandidateType::Host, 65535, 1);
        let rtcp_prio = calculate_priority(CandidateType::Host, 65535, 2);
        assert!(rtp_prio > rtcp_prio);
    }

    #[test]
    fn test_all_type_preferences() {
        let host = CandidateType::Host.type_preference();
        let prflx = CandidateType::PeerReflexive.type_preference();
        let srflx = CandidateType::ServerReflexive.type_preference();
        let relay = CandidateType::Relay.type_preference();

        assert!(host > prflx);
        assert!(prflx > srflx);
        assert!(srflx > relay);
    }

    #[test]
    fn test_pair_priority_g_greater() {
        // When g > d, last bit should be 1
        let prio = calculate_pair_priority(true, 2000, 1000);
        assert_eq!(prio % 2, 1);
    }

    #[test]
    fn test_pair_priority_d_greater() {
        // When d > g, last bit should be 0
        let prio = calculate_pair_priority(true, 1000, 2000);
        assert_eq!(prio % 2, 0);
    }
}
