//! ICE agent implementation (RFC 8445).
//!
//! Handles candidate gathering and connectivity checks.

use crate::candidate::{Candidate, CandidateType, calculate_pair_priority};
use crate::stun::StunServer;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// ICE agent errors.
#[derive(Error, Debug)]
pub enum IceError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("STUN error: {0}")]
    Stun(#[from] crate::stun::StunError),

    #[error("No candidates available")]
    NoCandidates,

    #[error("ICE failed: {0}")]
    Failed(String),
}

/// ICE agent role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    /// Controlling agent (makes nomination decisions).
    Controlling,
    /// Controlled agent (follows controlling agent's decisions).
    Controlled,
}

/// ICE agent state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceState {
    /// Not started.
    New,
    /// Gathering candidates.
    Gathering,
    /// Checking connectivity.
    Checking,
    /// At least one valid pair found.
    Connected,
    /// All checks complete, selected pair nominated.
    Completed,
    /// ICE failed.
    Failed,
    /// ICE closed.
    Closed,
}

/// ICE candidate pair.
#[derive(Debug, Clone)]
pub struct CandidatePair {
    /// Local candidate.
    pub local: Candidate,
    /// Remote candidate.
    pub remote: Candidate,
    /// Pair priority.
    pub priority: u64,
    /// Pair state.
    pub state: PairState,
    /// Whether this pair is nominated.
    pub nominated: bool,
}

/// Candidate pair state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    /// Waiting to be checked.
    Waiting,
    /// Check in progress.
    InProgress,
    /// Check succeeded.
    Succeeded,
    /// Check failed.
    Failed,
    /// Pair frozen (waiting for other checks).
    Frozen,
}

/// ICE agent configuration.
#[derive(Debug, Clone)]
pub struct IceConfig {
    /// STUN servers to use for gathering.
    pub stun_servers: Vec<StunServer>,
    /// ICE credentials (ufrag:pwd).
    pub local_ufrag: String,
    pub local_pwd: String,
    /// Gather timeout.
    pub gather_timeout_ms: u64,
    /// Check timeout.
    pub check_timeout_ms: u64,
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            stun_servers: vec![StunServer::GOOGLE],
            local_ufrag: generate_ice_ufrag(),
            local_pwd: generate_ice_pwd(),
            gather_timeout_ms: 5000,
            check_timeout_ms: 3000,
        }
    }
}

/// Generate random ICE ufrag (4-256 chars).
fn generate_ice_ufrag() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: String = (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect();
    chars
}

/// Generate random ICE password (22-256 chars).
fn generate_ice_pwd() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: String = (0..24)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect();
    chars
}

/// ICE agent.
pub struct IceAgent {
    config: IceConfig,
    role: IceRole,
    state: Arc<RwLock<IceState>>,
    local_candidates: Arc<RwLock<Vec<Candidate>>>,
    remote_candidates: Arc<RwLock<Vec<Candidate>>>,
    candidate_pairs: Arc<RwLock<Vec<CandidatePair>>>,
    selected_pair: Arc<RwLock<Option<CandidatePair>>>,
    sockets: Arc<RwLock<HashMap<SocketAddr, Arc<UdpSocket>>>>,
}

impl IceAgent {
    /// Create a new ICE agent.
    pub fn new(config: IceConfig, role: IceRole) -> Self {
        Self {
            config,
            role,
            state: Arc::new(RwLock::new(IceState::New)),
            local_candidates: Arc::new(RwLock::new(Vec::new())),
            remote_candidates: Arc::new(RwLock::new(Vec::new())),
            candidate_pairs: Arc::new(RwLock::new(Vec::new())),
            selected_pair: Arc::new(RwLock::new(None)),
            sockets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the ICE credentials.
    pub fn local_credentials(&self) -> (&str, &str) {
        (&self.config.local_ufrag, &self.config.local_pwd)
    }

    /// Get the current state.
    pub async fn state(&self) -> IceState {
        *self.state.read().await
    }

    /// Get local candidates.
    pub async fn local_candidates(&self) -> Vec<Candidate> {
        self.local_candidates.read().await.clone()
    }

    /// Get the selected candidate pair.
    pub async fn selected_pair(&self) -> Option<CandidatePair> {
        self.selected_pair.read().await.clone()
    }

    /// Gather local candidates.
    ///
    /// Discovers host candidates from local interfaces and
    /// server-reflexive candidates from STUN servers.
    pub async fn gather_candidates(&self) -> Result<Vec<Candidate>, IceError> {
        *self.state.write().await = IceState::Gathering;
        info!("Starting ICE candidate gathering");

        let mut candidates = Vec::new();

        // Gather host candidates from local interfaces
        let host_candidates = self.gather_host_candidates().await?;
        candidates.extend(host_candidates);

        // Gather server-reflexive candidates from STUN
        let srflx_candidates = self.gather_srflx_candidates().await;
        candidates.extend(srflx_candidates);

        // Store candidates
        *self.local_candidates.write().await = candidates.clone();

        info!("Gathered {} candidates", candidates.len());
        Ok(candidates)
    }

    /// Gather host candidates from local interfaces.
    async fn gather_host_candidates(&self) -> Result<Vec<Candidate>, IceError> {
        let mut candidates = Vec::new();

        // Get local addresses
        let addrs = get_local_addresses();

        for addr in addrs {
            // Bind a socket for this address
            let bind_addr = SocketAddr::new(addr, 0);
            match UdpSocket::bind(bind_addr).await {
                Ok(socket) => {
                    let local_addr = socket.local_addr()?;
                    debug!("Bound socket to {}", local_addr);

                    // Create host candidate
                    let candidate = Candidate::host(local_addr, 1);
                    candidates.push(candidate);

                    // Store socket
                    self.sockets.write().await.insert(local_addr, Arc::new(socket));
                }
                Err(e) => {
                    warn!("Failed to bind to {}: {}", bind_addr, e);
                }
            }
        }

        Ok(candidates)
    }

    /// Gather server-reflexive candidates from STUN servers.
    async fn gather_srflx_candidates(&self) -> Vec<Candidate> {
        let mut candidates = Vec::new();

        let sockets = self.sockets.read().await;
        for (base_addr, socket) in sockets.iter() {
            for server in &self.config.stun_servers {
                match self.stun_binding_request(socket, server).await {
                    Ok(mapped_addr) => {
                        if mapped_addr != *base_addr {
                            let candidate = Candidate::server_reflexive(mapped_addr, *base_addr, 1);
                            debug!("Discovered srflx candidate: {} (base: {})", mapped_addr, base_addr);
                            candidates.push(candidate);
                        }
                    }
                    Err(e) => {
                        warn!("STUN request to {} failed: {}", server.name, e);
                    }
                }
            }
        }

        candidates
    }

    /// Send a STUN binding request using an existing socket.
    async fn stun_binding_request(
        &self,
        socket: &UdpSocket,
        server: &StunServer,
    ) -> Result<SocketAddr, crate::stun::StunError> {
        use bytes::{Buf, BufMut, BytesMut};
        use rand::RngCore;
        use std::time::Duration;
        use tokio::time::timeout;

        const MAGIC_COOKIE: u32 = 0x2112A442;
        const BINDING_REQUEST: u16 = 0x0001;
        const BINDING_RESPONSE: u16 = 0x0101;

        // Generate transaction ID
        let mut txn_id = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut txn_id);

        // Build request
        let mut request = BytesMut::with_capacity(20);
        request.put_u16(BINDING_REQUEST);
        request.put_u16(0);
        request.put_u32(MAGIC_COOKIE);
        request.put_slice(&txn_id);

        // Send request
        socket.send_to(&request, server.addr).await?;

        // Wait for response
        let mut buf = vec![0u8; 1024];
        let (len, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
            .await
            .map_err(|_| crate::stun::StunError::Timeout)??;

        // Parse response (simplified)
        let data = &buf[..len];
        if data.len() < 20 {
            return Err(crate::stun::StunError::InvalidResponse("Too short".into()));
        }

        let mut buf = data;
        let msg_type = buf.get_u16();
        if msg_type != BINDING_RESPONSE {
            return Err(crate::stun::StunError::InvalidResponse("Not a response".into()));
        }

        let msg_len = buf.get_u16() as usize;
        let cookie = buf.get_u32();
        if cookie != MAGIC_COOKIE {
            return Err(crate::stun::StunError::InvalidResponse("Bad cookie".into()));
        }

        // Skip transaction ID check for simplicity
        buf.advance(12);

        // Parse attributes to find XOR-MAPPED-ADDRESS
        let mut attrs = &data[20..20 + msg_len];
        while attrs.len() >= 4 {
            let attr_type = attrs.get_u16();
            let attr_len = attrs.get_u16() as usize;

            if attr_type == 0x0020 && attr_len >= 8 {
                // XOR-MAPPED-ADDRESS
                let _reserved = attrs.get_u8();
                let family = attrs.get_u8();
                let port = attrs.get_u16() ^ (MAGIC_COOKIE >> 16) as u16;

                if family == 0x01 {
                    let ip_bytes = [
                        attrs.get_u8() ^ 0x21,
                        attrs.get_u8() ^ 0x12,
                        attrs.get_u8() ^ 0xA4,
                        attrs.get_u8() ^ 0x42,
                    ];
                    return Ok(SocketAddr::new(
                        IpAddr::V4(std::net::Ipv4Addr::from(ip_bytes)),
                        port,
                    ));
                }
            }

            let padded = (attr_len + 3) & !3;
            if attrs.len() >= padded {
                attrs.advance(padded);
            } else {
                break;
            }
        }

        Err(crate::stun::StunError::NoMappedAddress)
    }

    /// Add remote candidates.
    pub async fn add_remote_candidates(&self, candidates: Vec<Candidate>) {
        {
            let mut remote = self.remote_candidates.write().await;
            remote.extend(candidates);
        } // Drop write lock before calling form_candidate_pairs

        // Form new candidate pairs
        self.form_candidate_pairs().await;
    }

    /// Form candidate pairs from local and remote candidates.
    async fn form_candidate_pairs(&self) {
        let local = self.local_candidates.read().await;
        let remote = self.remote_candidates.read().await;
        let mut pairs = self.candidate_pairs.write().await;

        for l in local.iter() {
            for r in remote.iter() {
                // Only pair candidates with same component
                if l.component != r.component {
                    continue;
                }

                // Only pair compatible transports
                if l.transport != r.transport {
                    continue;
                }

                // Check if pair already exists
                let exists = pairs.iter().any(|p| {
                    p.local.address == l.address && p.remote.address == r.address
                });

                if !exists {
                    let is_controlling = self.role == IceRole::Controlling;
                    let priority = calculate_pair_priority(is_controlling, l.priority, r.priority);

                    pairs.push(CandidatePair {
                        local: l.clone(),
                        remote: r.clone(),
                        priority,
                        state: PairState::Frozen,
                        nominated: false,
                    });
                }
            }
        }

        // Sort by priority (highest first)
        pairs.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Unfreeze first pair of each foundation
        let mut seen_foundations = std::collections::HashSet::new();
        for pair in pairs.iter_mut() {
            let key = (&pair.local.foundation, &pair.remote.foundation);
            if !seen_foundations.contains(&key) {
                pair.state = PairState::Waiting;
                seen_foundations.insert(key);
            }
        }

        debug!("Formed {} candidate pairs", pairs.len());
    }

    /// Start connectivity checks.
    pub async fn start_checks(&self) -> Result<(), IceError> {
        *self.state.write().await = IceState::Checking;
        info!("Starting ICE connectivity checks");

        // For now, just select the highest priority pair with matching addresses
        // A full implementation would perform STUN binding requests
        let pairs = self.candidate_pairs.read().await;

        for pair in pairs.iter() {
            if pair.state == PairState::Waiting {
                // In a full implementation, we would:
                // 1. Send STUN binding request to remote candidate
                // 2. Wait for response
                // 3. Mark pair as succeeded/failed

                // For now, assume host-to-host works
                if pair.local.candidate_type == CandidateType::Host
                    && pair.remote.candidate_type == CandidateType::Host
                {
                    let mut selected = self.selected_pair.write().await;
                    *selected = Some(pair.clone());
                    *self.state.write().await = IceState::Connected;
                    info!("Selected candidate pair: {} <-> {}",
                          pair.local.address, pair.remote.address);
                    return Ok(());
                }
            }
        }

        // Try any remaining pair
        if let Some(pair) = pairs.first() {
            let mut selected = self.selected_pair.write().await;
            *selected = Some(pair.clone());
            *self.state.write().await = IceState::Connected;
            return Ok(());
        }

        *self.state.write().await = IceState::Failed;
        Err(IceError::NoCandidates)
    }

    /// Close the ICE agent.
    pub async fn close(&self) {
        *self.state.write().await = IceState::Closed;
        self.sockets.write().await.clear();
    }
}

/// Get local IP addresses suitable for ICE.
fn get_local_addresses() -> Vec<IpAddr> {
    let mut addrs = Vec::new();

    // Try to get addresses by connecting to a public address
    // This finds the default route interface
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = socket.local_addr() {
                addrs.push(local.ip());
            }
        }
    }

    // Also include localhost for testing
    addrs.push(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

    addrs.dedup();
    addrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ufrag() {
        let ufrag = generate_ice_ufrag();
        assert_eq!(ufrag.len(), 8);
        assert!(ufrag.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_pwd() {
        let pwd = generate_ice_pwd();
        assert_eq!(pwd.len(), 24);
        assert!(pwd.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[tokio::test]
    async fn test_ice_agent_creation() {
        let config = IceConfig::default();
        let agent = IceAgent::new(config, IceRole::Controlling);

        assert_eq!(agent.state().await, IceState::New);
    }

    #[tokio::test]
    async fn test_gather_host_candidates() {
        // Use empty STUN servers to avoid network calls
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let candidates = agent.gather_candidates().await.unwrap();

        // Should have at least one host candidate
        assert!(!candidates.is_empty());
        assert!(candidates.iter().any(|c| c.candidate_type == CandidateType::Host));
    }

    #[tokio::test]
    async fn test_form_candidate_pairs() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Directly add local and remote candidates without network
        let local = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        agent.local_candidates.write().await.push(local);

        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            1,
        );
        agent.add_remote_candidates(vec![remote]).await;

        // Check that pairs were formed
        let pairs = agent.candidate_pairs.read().await;
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].state, PairState::Waiting);
    }
}
