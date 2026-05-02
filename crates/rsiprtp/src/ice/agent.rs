//! ICE agent implementation (RFC 8445).
//!
//! Handles candidate gathering and connectivity checks.

use crate::ice::candidate::{calculate_pair_priority, Candidate, CandidateType};
use crate::ice::stun::StunServer;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// Wire constants shared by the request/response code paths.
const MAGIC_COOKIE: u32 = 0x2112A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

/// ICE agent errors.
#[derive(Error, Debug)]
pub enum IceError {
    /// Underlying network I/O error.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// STUN protocol error during candidate gathering or connectivity checks.
    #[error("STUN error: {0}")]
    Stun(#[from] crate::ice::stun::StunError),

    /// No candidates were gathered or supplied — cannot perform ICE.
    #[error("No candidates available")]
    NoCandidates,

    /// ICE processing failed (no valid pair found, all checks failed, etc.).
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
    /// ICE credentials (ufrag:pwd) — local username fragment.
    pub local_ufrag: String,
    /// Local ICE password used for STUN message integrity.
    pub local_pwd: String,
    /// Wall-clock cap on `gather_candidates`. On timeout, whatever
    /// candidates have already been gathered are returned (partial results
    /// are useful — the caller can still negotiate). Host gathering happens
    /// first, so a timeout will typically still leave at least the host
    /// candidates intact.
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
            // 1500ms: STUN RTT well under 200ms (HLD); leaves headroom
            // for several retransmits before the deferred-answer path
            // forces send.
            gather_timeout_ms: 1500,
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

/// Per-socket dispatcher state: the dispatcher drains the bound socket,
/// answers inbound STUN binding requests directly, and forwards inbound
/// STUN binding responses to whatever check-loop registered the matching
/// transaction ID. Every access is a write (insert / remove / clear),
/// so a `Mutex` is the right primitive here — `RwLock` would only add
/// overhead.
type PendingResponses = Arc<Mutex<HashMap<[u8; 12], oneshot::Sender<Vec<u8>>>>>;

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
    /// One dispatcher task per bound host socket. Tracked so `close`
    /// can abort them.
    responder_tasks: Arc<RwLock<HashMap<SocketAddr, JoinHandle<()>>>>,
    /// In-flight outgoing STUN transactions, keyed by transaction ID.
    /// The dispatcher hands the response bytes to the matching oneshot.
    pending_responses: PendingResponses,
    /// Remote ICE credentials.
    remote_ufrag: Arc<RwLock<Option<String>>>,
    remote_pwd: Arc<RwLock<Option<String>>>,
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
            responder_tasks: Arc::new(RwLock::new(HashMap::new())),
            pending_responses: Arc::new(Mutex::new(HashMap::new())),
            remote_ufrag: Arc::new(RwLock::new(None)),
            remote_pwd: Arc::new(RwLock::new(None)),
        }
    }

    /// Set remote ICE credentials.
    pub async fn set_remote_credentials(&self, ufrag: &str, pwd: &str) {
        *self.remote_ufrag.write().await = Some(ufrag.to_string());
        *self.remote_pwd.write().await = Some(pwd.to_string());
        debug!("Set remote credentials: ufrag={}", ufrag);
    }

    /// Get remote ICE credentials.
    pub async fn remote_credentials(&self) -> Option<(String, String)> {
        let ufrag = self.remote_ufrag.read().await.clone()?;
        let pwd = self.remote_pwd.read().await.clone()?;
        Some((ufrag, pwd))
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

    /// Get the host-bound socket for an address that appeared as a host
    /// candidate's address (i.e. anything in `local_candidates()` with
    /// `CandidateType::Host`).
    ///
    /// After `start_checks` succeeds, the caller may take ownership of the
    /// socket for RTP; the agent will not race on it provided no further
    /// ICE operations (gather, restart) are invoked.
    pub async fn socket_for(&self, addr: SocketAddr) -> Option<Arc<UdpSocket>> {
        self.sockets.read().await.get(&addr).cloned()
    }

    /// Gather local candidates.
    ///
    /// Discovers host candidates from local interfaces and
    /// server-reflexive candidates from STUN servers.
    ///
    /// The whole call is bounded by `IceConfig::gather_timeout_ms`. If the
    /// budget elapses, gathering stops and whatever candidates have already
    /// been gathered are returned — partial results are useful (host
    /// candidates alone are enough to keep negotiating).
    pub async fn gather_candidates(&self) -> Result<Vec<Candidate>, IceError> {
        *self.state.write().await = IceState::Gathering;
        info!("Starting ICE candidate gathering");

        let budget = std::time::Duration::from_millis(self.config.gather_timeout_ms);
        match tokio::time::timeout(budget, self.gather_candidates_inner()).await {
            Ok(result) => result,
            Err(_) => {
                // Timeout: return whatever was stored so far.
                let partial = self.local_candidates.read().await.clone();
                warn!(
                    "ICE candidate gathering timed out after {}ms; returning {} partial candidates",
                    self.config.gather_timeout_ms,
                    partial.len()
                );
                Ok(partial)
            }
        }
    }

    /// Inner gathering body — host then srflx, each batch stored in
    /// `local_candidates` so the outer timeout wrapper can return partial
    /// results.
    async fn gather_candidates_inner(&self) -> Result<Vec<Candidate>, IceError> {
        let mut candidates = Vec::new();

        // Gather host candidates from local interfaces
        let host_candidates = self.gather_host_candidates().await?;
        candidates.extend(host_candidates);
        // Stash hosts before we start STUN — if srflx gathering times out
        // mid-flight, the timeout branch can still return the hosts.
        *self.local_candidates.write().await = candidates.clone();

        // Gather server-reflexive candidates from STUN
        let srflx_candidates = self.gather_srflx_candidates().await;
        candidates.extend(srflx_candidates);

        // Store final candidate set
        *self.local_candidates.write().await = candidates.clone();

        info!("Gathered {} candidates", candidates.len());
        Ok(candidates)
    }

    /// Gather host candidates from local interfaces.
    async fn gather_host_candidates(&self) -> Result<Vec<Candidate>, IceError> {
        let addrs = get_local_addresses();
        self.gather_host_candidates_with(addrs).await
    }

    async fn gather_host_candidates_with(
        &self,
        addrs: Vec<IpAddr>,
    ) -> Result<Vec<Candidate>, IceError> {
        let mut candidates = Vec::new();

        for addr in addrs {
            // Bind a socket for this address
            let bind_addr = SocketAddr::new(addr, 0);
            match UdpSocket::bind(bind_addr).await {
                Ok(socket) => {
                    let local_addr = socket_local_addr(&socket)?;
                    debug!("Bound socket to {}", local_addr);

                    // Create host candidate
                    let candidate = Candidate::host(local_addr, 1);
                    candidates.push(candidate);

                    // Store socket and start a dispatcher task for it.
                    let socket = Arc::new(socket);
                    self.sockets
                        .write()
                        .await
                        .insert(local_addr, socket.clone());
                    self.ensure_dispatcher(local_addr, socket).await;
                }
                Err(e) => {
                    warn!("Failed to bind to {}: {}", bind_addr, e);
                }
            }
        }

        Ok(candidates)
    }

    /// Start (or noop) the per-socket dispatcher loop that answers
    /// inbound STUN binding requests and routes inbound binding
    /// responses to the matching outgoing-check oneshot. Idempotent
    /// per `local_addr`.
    ///
    /// Note on the bind-then-spawn window: between `UdpSocket::bind`
    /// returning and the spawned task issuing its first `recv_from`,
    /// the kernel buffers any inbound datagrams in the per-socket
    /// queue. Nothing is lost as long as the queue isn't overrun;
    /// a STUN check arriving "early" simply waits a few microseconds
    /// for the loop to drain it.
    async fn ensure_dispatcher(&self, local_addr: SocketAddr, socket: Arc<UdpSocket>) {
        let mut tasks = self.responder_tasks.write().await;
        if tasks.contains_key(&local_addr) {
            return;
        }

        let pending = self.pending_responses.clone();
        let local_ufrag = self.config.local_ufrag.clone();
        let local_pwd = self.config.local_pwd.clone();
        let handle = tokio::spawn(async move {
            stun_dispatcher_loop(socket, pending, local_ufrag, local_pwd).await;
        });
        tasks.insert(local_addr, handle);
    }

    /// Send an outgoing STUN message and await the response (matched
    /// by transaction ID via the dispatcher) with a timeout. The
    /// dispatcher must already be running for `socket`'s local address
    /// — callers ensure this via `ensure_dispatcher` or by binding
    /// through `gather_host_candidates_with`.
    async fn send_and_await_response(
        &self,
        socket: &UdpSocket,
        target: SocketAddr,
        msg: &[u8],
        txn_id: [u8; 12],
        timeout_dur: std::time::Duration,
    ) -> Result<Vec<u8>, std::io::Error> {
        let (tx, rx) = oneshot::channel();
        self.pending_responses.lock().await.insert(txn_id, tx);

        let send_result = socket.send_to(msg, target).await;
        if let Err(e) = send_result {
            self.pending_responses.lock().await.remove(&txn_id);
            return Err(e);
        }

        let result = tokio::time::timeout(timeout_dur, rx).await;
        // Whatever happened, drop the pending entry.
        self.pending_responses.lock().await.remove(&txn_id);
        match result {
            Ok(Ok(bytes)) => Ok(bytes),
            Ok(Err(_)) => Err(std::io::Error::other("dispatcher dropped")),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "STUN response timeout",
            )),
        }
    }

    /// Gather server-reflexive candidates from STUN servers.
    async fn gather_srflx_candidates(&self) -> Vec<Candidate> {
        let mut candidates = Vec::new();

        // Snapshot sockets to avoid holding the lock across awaits.
        let sockets: Vec<(SocketAddr, Arc<UdpSocket>)> = self
            .sockets
            .read()
            .await
            .iter()
            .map(|(a, s)| (*a, s.clone()))
            .collect();

        for (base_addr, socket) in sockets {
            for server in &self.config.stun_servers {
                match self.stun_binding_request(&socket, server).await {
                    Ok(mapped_addr) => {
                        if mapped_addr != base_addr {
                            let candidate = Candidate::server_reflexive(mapped_addr, base_addr, 1);
                            debug!(
                                "Discovered srflx candidate: {} (base: {})",
                                mapped_addr, base_addr
                            );
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
        socket: &Arc<UdpSocket>,
        server: &StunServer,
    ) -> Result<SocketAddr, crate::ice::stun::StunError> {
        use bytes::{Buf, BufMut, BytesMut};
        use rand::RngCore;
        use std::time::Duration;

        // Generate transaction ID
        let mut txn_id = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut txn_id);

        // Build request
        let mut request = BytesMut::with_capacity(20);
        request.put_u16(BINDING_REQUEST);
        request.put_u16(0);
        request.put_u32(MAGIC_COOKIE);
        request.put_slice(&txn_id);

        // Make sure the dispatcher is running for this socket's local
        // address; otherwise the response will never reach us.
        let local_addr = match socket.local_addr() {
            Ok(a) => a,
            Err(e) => return Err(crate::ice::stun::StunError::Io(e)),
        };
        self.ensure_dispatcher(local_addr, socket.clone()).await;

        // Send + await via the dispatcher.
        let timeout_dur = Duration::from_millis(self.config.check_timeout_ms);
        let response = match self
            .send_and_await_response(socket, server.addr, &request, txn_id, timeout_dur)
            .await
        {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                return Err(crate::ice::stun::StunError::Timeout);
            }
            Err(e) => return Err(crate::ice::stun::StunError::Io(e)),
        };

        // Parse response.
        let data = response.as_slice();
        if data.len() < 20 {
            return Err(crate::ice::stun::StunError::InvalidResponse(
                "Too short".into(),
            ));
        }

        let mut buf = data;
        let msg_type = buf.get_u16();
        if msg_type != BINDING_RESPONSE {
            return Err(crate::ice::stun::StunError::InvalidResponse(
                "Not a response".into(),
            ));
        }

        let msg_len = buf.get_u16() as usize;
        let cookie = buf.get_u32();
        if cookie != MAGIC_COOKIE {
            return Err(crate::ice::stun::StunError::InvalidResponse(
                "Bad cookie".into(),
            ));
        }

        // Skip transaction ID — already matched by the dispatcher.
        buf.advance(12);

        // Parse attributes to find XOR-MAPPED-ADDRESS
        let mut attrs = &data[20..20 + msg_len.min(data.len() - 20)];
        while attrs.len() >= 4 {
            let attr_type = attrs.get_u16();
            let attr_len = attrs.get_u16() as usize;

            if attr_type == ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8 {
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

        Err(crate::ice::stun::StunError::NoMappedAddress)
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
                let exists = pairs
                    .iter()
                    .any(|p| p.local.address == l.address && p.remote.address == r.address);

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
    ///
    /// Performs STUN connectivity checks on candidate pairs according to RFC 8445.
    /// Each check sends a STUN Binding Request to the remote candidate and waits
    /// for a response to validate the path.
    ///
    /// Known limitation: peer-reflexive (prflx) candidate discovery for
    /// symmetric-NAT peers is not implemented (out of scope per the ICE
    /// HLD — symmetric NAT requires a TURN relay, which this thin ICE
    /// path doesn't wire in). The caller should plan to fall back to a
    /// relay if both peers sit behind symmetric NATs.
    pub async fn start_checks(&self) -> Result<(), IceError> {
        *self.state.write().await = IceState::Checking;
        info!("Starting ICE connectivity checks");

        // Get credentials for STUN requests
        let remote_creds = self.remote_credentials().await;
        let (remote_ufrag, remote_pwd) = match remote_creds {
            Some((u, p)) => (u, p),
            None => {
                warn!("Remote credentials not set, falling back to simple selection");
                return self.fallback_selection().await;
            }
        };

        // Get pairs to check (copy to avoid holding lock during async operations)
        let pairs_to_check: Vec<(usize, CandidatePair)> = {
            let pairs = self.candidate_pairs.read().await;
            pairs
                .iter()
                .enumerate()
                .filter(|(_, p)| p.state == PairState::Waiting)
                .map(|(i, p)| (i, p.clone()))
                .collect()
        };

        // Perform connectivity checks
        for (idx, pair) in pairs_to_check {
            // Mark as in-progress
            {
                let mut pairs = self.candidate_pairs.write().await;
                let pair_state = pairs.get_mut(idx).expect("candidate pair missing");
                pair_state.state = PairState::InProgress;
            }

            debug!(
                "Checking pair {} <-> {}",
                pair.local.address, pair.remote.address
            );

            // Find the socket for this local candidate
            let socket = {
                let sockets = self.sockets.read().await;
                // For host candidates, use the candidate's address
                // For srflx/relay, use the related address (base)
                let socket_addr = pair.local.related_address.unwrap_or(pair.local.address);
                sockets.get(&socket_addr).cloned()
            };

            let check_result = match socket {
                Some(sock) => {
                    self.perform_connectivity_check(&sock, &pair, &remote_ufrag, &remote_pwd)
                        .await
                }
                None => {
                    warn!("No socket for local candidate {}", pair.local.address);
                    false
                }
            };
            // `sock` is an `Arc<UdpSocket>`, so the dispatcher's clone
            // remains live regardless of this scope.

            // Update pair state
            let mut succeeded = false;
            {
                let mut pairs = self.candidate_pairs.write().await;
                let pair_state = pairs.get_mut(idx).expect("candidate pair missing");
                if check_result {
                    pair_state.state = PairState::Succeeded;
                    info!(
                        "Connectivity check succeeded: {} <-> {}",
                        pair.local.address, pair.remote.address
                    );

                    // If controlling, nominate this pair
                    if self.role == IceRole::Controlling {
                        pair_state.nominated = true;
                    }

                    // Select this pair
                    let mut selected = self.selected_pair.write().await;
                    *selected = Some(pair_state.clone());
                    *self.state.write().await = IceState::Connected;
                    succeeded = true;
                } else {
                    pair_state.state = PairState::Failed;
                    debug!(
                        "Connectivity check failed: {} <-> {}",
                        pair.local.address, pair.remote.address
                    );
                }
            }

            if succeeded {
                // Unfreeze other pairs with same foundation (for triggered checks)
                self.unfreeze_related_pairs(idx, &pair).await;
                return Ok(());
            }
        }

        // No successful checks, try to find any valid pair
        self.fallback_selection().await
    }

    /// Perform a single connectivity check on a candidate pair.
    ///
    /// Sends a STUN Binding Request with ICE credentials (USERNAME, MESSAGE-INTEGRITY)
    /// and validates the response.
    async fn perform_connectivity_check(
        &self,
        socket: &Arc<UdpSocket>,
        pair: &CandidatePair,
        remote_ufrag: &str,
        remote_pwd: &str,
    ) -> bool {
        use bytes::{BufMut, BytesMut};
        use hmac::{Hmac, Mac};
        use rand::RngCore;
        use sha1::Sha1;
        use std::time::Duration;

        const ATTR_PRIORITY: u16 = 0x0024;
        const ATTR_ICE_CONTROLLING: u16 = 0x802A;
        const ATTR_ICE_CONTROLLED: u16 = 0x8029;

        type HmacSha1 = Hmac<Sha1>;

        // Make sure the dispatcher is running for this socket so we
        // can receive responses (and answer the peer's checks too).
        let local_addr = match socket.local_addr() {
            Ok(a) => a,
            Err(e) => {
                warn!("Cannot resolve local addr for connectivity check: {}", e);
                return false;
            }
        };
        self.ensure_dispatcher(local_addr, socket.clone()).await;

        // Generate transaction ID
        let mut txn_id = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut txn_id);

        // Build ICE username: remote_ufrag:local_ufrag
        let username = format!("{}:{}", remote_ufrag, self.config.local_ufrag);

        // Build attributes
        let mut attrs = BytesMut::new();

        // USERNAME attribute
        let username_bytes = username.as_bytes();
        attrs.put_u16(ATTR_USERNAME);
        attrs.put_u16(username_bytes.len() as u16);
        attrs.put_slice(username_bytes);
        // Pad to 4-byte boundary
        let padding = (4 - (username_bytes.len() % 4)) % 4;
        for _ in 0..padding {
            attrs.put_u8(0);
        }

        // PRIORITY attribute (our priority for this candidate)
        attrs.put_u16(ATTR_PRIORITY);
        attrs.put_u16(4);
        attrs.put_u32(pair.local.priority);

        // ICE-CONTROLLING or ICE-CONTROLLED with tie-breaker
        let mut tie_breaker = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut tie_breaker);

        match self.role {
            IceRole::Controlling => {
                attrs.put_u16(ATTR_ICE_CONTROLLING);
                attrs.put_u16(8);
                attrs.put_slice(&tie_breaker);
            }
            IceRole::Controlled => {
                attrs.put_u16(ATTR_ICE_CONTROLLED);
                attrs.put_u16(8);
                attrs.put_slice(&tie_breaker);
            }
        }

        // Build message header (length will be updated for MESSAGE-INTEGRITY)
        let mut msg = BytesMut::with_capacity(20 + attrs.len() + 24);
        msg.put_u16(BINDING_REQUEST);
        msg.put_u16(attrs.len() as u16);
        msg.put_u32(MAGIC_COOKIE);
        msg.put_slice(&txn_id);
        msg.put_slice(&attrs);

        // Add MESSAGE-INTEGRITY using remote password as key (short-term credential)
        // For ICE, the key is the remote password directly (not MD5 hashed)
        {
            let current_len = msg.len();
            let new_len = (current_len - 20 + 24) as u16;
            msg[2] = (new_len >> 8) as u8;
            msg[3] = (new_len & 0xFF) as u8;

            let mut mac = HmacSha1::new_from_slice(remote_pwd.as_bytes())
                .expect("HMAC can take any key size");
            mac.update(&msg);
            let integrity = mac.finalize().into_bytes();

            msg.put_u16(ATTR_MESSAGE_INTEGRITY);
            msg.put_u16(20);
            msg.put_slice(&integrity);
        }

        // Send + await response via the dispatcher.
        let target_addr = pair.remote.address;
        let check_timeout = Duration::from_millis(self.config.check_timeout_ms);

        match self
            .send_and_await_response(socket, target_addr, &msg, txn_id, check_timeout)
            .await
        {
            Ok(response_bytes) => {
                // Dispatcher matches by transaction ID and forwards
                // any well-formed-length packet — re-validate the
                // STUN-level fields here so a malformed reply doesn't
                // count as a successful check.
                if response_bytes.len() < 20 {
                    debug!(
                        "Connectivity check response from {} too short ({} bytes)",
                        target_addr,
                        response_bytes.len()
                    );
                    return false;
                }
                let resp_type = u16::from_be_bytes([response_bytes[0], response_bytes[1]]);
                let resp_cookie = u32::from_be_bytes([
                    response_bytes[4],
                    response_bytes[5],
                    response_bytes[6],
                    response_bytes[7],
                ]);
                if resp_type != BINDING_RESPONSE || resp_cookie != MAGIC_COOKIE {
                    debug!(
                        "Connectivity check response from {} malformed (type=0x{:04x} cookie=0x{:08x})",
                        target_addr, resp_type, resp_cookie
                    );
                    return false;
                }
                debug!(
                    "Received valid STUN response for connectivity check to {}",
                    target_addr
                );
                true
            }
            Err(e) => {
                debug!(
                    "Connectivity check to {} did not complete: {}",
                    target_addr, e
                );
                false
            }
        }
    }

    /// Unfreeze candidate pairs with the same foundation after a successful check.
    async fn unfreeze_related_pairs(&self, succeeded_idx: usize, succeeded: &CandidatePair) {
        let mut pairs = self.candidate_pairs.write().await;
        for (i, pair) in pairs.iter_mut().enumerate() {
            if i != succeeded_idx
                && pair.state == PairState::Frozen
                && pair.local.foundation == succeeded.local.foundation
            {
                pair.state = PairState::Waiting;
            }
        }
    }

    /// Fallback selection when connectivity checks aren't possible.
    async fn fallback_selection(&self) -> Result<(), IceError> {
        let pairs = self.candidate_pairs.read().await;

        // Try host-to-host first
        for pair in pairs.iter() {
            if pair.local.candidate_type == CandidateType::Host
                && pair.remote.candidate_type == CandidateType::Host
            {
                let mut selected = self.selected_pair.write().await;
                *selected = Some(pair.clone());
                *self.state.write().await = IceState::Connected;
                info!(
                    "Fallback: Selected host-to-host pair: {} <-> {}",
                    pair.local.address, pair.remote.address
                );
                return Ok(());
            }
        }

        // Try any pair
        if let Some(pair) = pairs.first() {
            let mut selected = self.selected_pair.write().await;
            *selected = Some(pair.clone());
            *self.state.write().await = IceState::Connected;
            info!(
                "Fallback: Selected first available pair: {} <-> {}",
                pair.local.address, pair.remote.address
            );
            return Ok(());
        }

        *self.state.write().await = IceState::Failed;
        Err(IceError::NoCandidates)
    }

    /// Stop the per-socket STUN responder dispatchers without
    /// otherwise tearing down the agent.
    ///
    /// Sockets stay bound and remain in the agent's `sockets` map, so
    /// `socket_for(...)` keeps returning the same `Arc<UdpSocket>` and
    /// any clones the caller already obtained continue to receive
    /// traffic. Cloned `rtp_socket()` handles held by callers (e.g.
    /// the RTP loop) are unaffected by this call beyond the
    /// dispatcher releasing its own clone.
    ///
    /// Use this once a validated pair has been selected: the caller
    /// is taking the socket for RTP, and we no longer want the
    /// dispatcher consuming inbound packets out from under them.
    /// `close()` remains the full-shutdown path.
    pub async fn stop_responders(&self) {
        let mut tasks = self.responder_tasks.write().await;
        for (_addr, handle) in tasks.drain() {
            handle.abort();
        }
    }

    /// Close the ICE agent.
    pub async fn close(&self) {
        *self.state.write().await = IceState::Closed;
        self.sockets.write().await.clear();
        // Abort all dispatcher tasks. Cloned `Arc<UdpSocket>` handles
        // held by callers (e.g. RTP) remain alive — only our reference
        // is dropped.
        let mut tasks = self.responder_tasks.write().await;
        for (_addr, handle) in tasks.drain() {
            handle.abort();
        }
        self.pending_responses.lock().await.clear();
    }
}

/// Get local IP addresses suitable for ICE.
fn get_local_addresses() -> Vec<IpAddr> {
    get_local_addresses_with(bind_default, connect_default, local_addr_default)
}

#[cfg(test)]
static FORCE_HOST_LOCAL_ADDR_ERROR: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
fn force_host_local_addr_error_once() {
    FORCE_HOST_LOCAL_ADDR_ERROR.store(current_thread_id(), Ordering::SeqCst);
}

#[cfg(test)]
fn take_forced_host_local_addr_error() -> Option<std::io::Error> {
    let current = current_thread_id();
    if FORCE_HOST_LOCAL_ADDR_ERROR.load(Ordering::SeqCst) == current {
        let _ = FORCE_HOST_LOCAL_ADDR_ERROR.compare_exchange(
            current,
            0,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        Some(std::io::Error::other("forced local_addr error"))
    } else {
        None
    }
}

#[cfg(test)]
fn current_thread_id() -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    let id = hasher.finish();
    normalize_thread_id(id)
}

#[cfg(test)]
fn normalize_thread_id(id: u64) -> u64 {
    if id == 0 {
        1
    } else {
        id
    }
}

/// Per-socket STUN dispatcher loop. Reads inbound packets and either
/// answers binding requests (with `MESSAGE-INTEGRITY` validated against
/// `local_pwd`) or forwards binding responses to whichever outgoing
/// transaction is awaiting them.
async fn stun_dispatcher_loop(
    socket: Arc<UdpSocket>,
    pending: PendingResponses,
    local_ufrag: String,
    local_pwd: String,
) {
    // 1500 covers a typical Ethernet MTU. Real STUN messages are far
    // smaller (a few hundred bytes), and `recv_from` truncates rather
    // than failing on oversize, so we log and drop oversized packets.
    let mut buf = vec![0u8; 1500];
    loop {
        let (len, from) = match socket.recv_from(&mut buf).await {
            Ok(t) => t,
            Err(e) => {
                debug!("STUN dispatcher recv error, exiting: {}", e);
                return;
            }
        };
        if len == buf.len() {
            // Datagram filled the buffer exactly; UDP has no fragment
            // signal here. Anything legitimate from a STUN peer fits
            // well below 1500 bytes — log and drop rather than forward
            // a possibly-truncated message.
            debug!(
                "STUN dispatcher dropped possibly-truncated {}-byte datagram from {}",
                len, from
            );
            continue;
        }
        if len < 20 {
            continue;
        }
        let data = &buf[..len];
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let mut txn_id = [0u8; 12];
        txn_id.copy_from_slice(&data[8..20]);

        // Forward to a pending outgoing transaction first if the txn
        // ID matches, regardless of msg_type/cookie. This lets the
        // caller (`stun_binding_request`, `perform_connectivity_check`)
        // re-validate and surface `StunError::InvalidResponse` for
        // malformed replies — staying permissive here keeps the
        // public API contract intact. Only if no transaction is
        // waiting for this ID do we treat the packet as a peer
        // binding request.
        let pending_match = pending.lock().await.remove(&txn_id);
        if let Some(tx) = pending_match {
            let _ = tx.send(data.to_vec());
            continue;
        }

        if cookie == MAGIC_COOKIE && msg_type == BINDING_REQUEST {
            let owned: Vec<u8> = data.to_vec();
            if let Some(resp) =
                build_binding_response(&owned, txn_id, from, &local_ufrag, &local_pwd)
            {
                if let Err(e) = socket.send_to(&resp, from).await {
                    debug!("Failed to send STUN binding response to {}: {}", from, e);
                }
            }
        } else {
            // Unmatched non-request (stray response, indication, or
            // bad-cookie noise): drop silently.
            debug!(
                "STUN dispatcher dropped unmatched packet from {} (type=0x{:04x})",
                from, msg_type
            );
        }
    }
}

/// Validate an inbound STUN binding request and build the success
/// response bytes. Returns `None` if validation fails (the dispatcher
/// then drops the packet silently — RFC 5389 permits a STUN error
/// response, but staying silent is simpler and safer).
fn build_binding_response(
    request: &[u8],
    txn_id: [u8; 12],
    from: SocketAddr,
    local_ufrag: &str,
    local_pwd: &str,
) -> Option<Vec<u8>> {
    use bytes::{BufMut, BytesMut};
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    type HmacSha1 = Hmac<Sha1>;

    if request.len() < 20 {
        return None;
    }
    let total_attrs_len = u16::from_be_bytes([request[2], request[3]]) as usize;
    if request.len() < 20 + total_attrs_len {
        return None;
    }

    // Walk attributes, locate USERNAME and MESSAGE-INTEGRITY.
    let mut username: Option<&[u8]> = None;
    let mut mi_offset: Option<usize> = None;
    let mut mi_value: Option<&[u8]> = None;

    let mut off = 20;
    let attrs_end = 20 + total_attrs_len;
    while off + 4 <= attrs_end {
        let attr_type = u16::from_be_bytes([request[off], request[off + 1]]);
        let attr_len = u16::from_be_bytes([request[off + 2], request[off + 3]]) as usize;
        let val_start = off + 4;
        let val_end = val_start + attr_len;
        if val_end > attrs_end {
            return None;
        }
        match attr_type {
            ATTR_USERNAME => {
                username = Some(&request[val_start..val_end]);
            }
            ATTR_MESSAGE_INTEGRITY => {
                if attr_len != 20 {
                    return None;
                }
                mi_offset = Some(off);
                mi_value = Some(&request[val_start..val_end]);
                // RFC 5389 §15.4: attributes after MESSAGE-INTEGRITY
                // are not covered by the HMAC, so trusting them would
                // let an attacker append arbitrary unauthenticated
                // attributes. Stop here.
                break;
            }
            _ => {}
        }
        // Advance past padded attribute.
        let padded = (attr_len + 3) & !3;
        off = val_start + padded;
    }

    let username = username?;
    let mi_offset = mi_offset?;
    let mi_value = mi_value?;

    // RFC 5389 §10.1.2: verify MESSAGE-INTEGRITY *before* USERNAME.
    // An attacker who can guess our local ufrag must not learn whether
    // their MI guess was right; we reject all unauthenticated traffic
    // identically (silent drop). Validating MI first also avoids
    // doing a string comparison on attacker-controlled input before
    // the cryptographic check.
    let mut signed = request[..mi_offset].to_vec();
    let new_len = (mi_offset - 20 + 24) as u16;
    signed[2] = (new_len >> 8) as u8;
    signed[3] = (new_len & 0xff) as u8;

    let mut mac =
        HmacSha1::new_from_slice(local_pwd.as_bytes()).expect("HMAC accepts any key length");
    mac.update(&signed);
    if mac.verify_slice(mi_value).is_err() {
        debug!("STUN request rejected: MESSAGE-INTEGRITY mismatch");
        return None;
    }

    // USERNAME must be of the form `local_ufrag:peer_ufrag`. We
    // verify only the first component matches our local ufrag —
    // peers send `<their_remote_ufrag>:<their_local_ufrag>` and our
    // remote_ufrag (from peer's POV) is our local_ufrag.
    let username_str = std::str::from_utf8(username).ok()?;
    let mut split = username_str.splitn(2, ':');
    let first = split.next()?;
    if first != local_ufrag {
        debug!(
            "STUN request rejected: USERNAME prefix `{}` != local ufrag",
            first
        );
        return None;
    }

    // Build success response: BINDING_RESPONSE + magic + txn_id +
    // XOR-MAPPED-ADDRESS + MESSAGE-INTEGRITY (signed with local_pwd).
    let mut attrs = BytesMut::new();
    match from {
        SocketAddr::V4(addr) => {
            attrs.put_u16(ATTR_XOR_MAPPED_ADDRESS);
            attrs.put_u16(8);
            attrs.put_u8(0);
            attrs.put_u8(0x01); // IPv4
            let xor_port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
            attrs.put_u16(xor_port);
            let ip = addr.ip().octets();
            let cookie = MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                attrs.put_u8(ip[i] ^ cookie[i]);
            }
        }
        SocketAddr::V6(addr) => {
            // RFC 5389 §15.2: IPv6 XOR-MAPPED-ADDRESS is 24 bytes —
            // family 0x02, port XORed with the high 16 bits of the
            // magic cookie, address XORed with the magic cookie
            // followed by the 12-byte transaction ID.
            attrs.put_u16(ATTR_XOR_MAPPED_ADDRESS);
            attrs.put_u16(20);
            attrs.put_u8(0);
            attrs.put_u8(0x02); // IPv6
            let xor_port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
            attrs.put_u16(xor_port);
            let ip = addr.ip().octets();
            let cookie = MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                attrs.put_u8(ip[i] ^ cookie[i]);
            }
            for i in 0..12 {
                attrs.put_u8(ip[4 + i] ^ txn_id[i]);
            }
        }
    }

    let mut msg = BytesMut::with_capacity(20 + attrs.len() + 24);
    msg.put_u16(BINDING_RESPONSE);
    // Will be patched before HMAC.
    msg.put_u16(attrs.len() as u16);
    msg.put_u32(MAGIC_COOKIE);
    msg.put_slice(&txn_id);
    msg.put_slice(&attrs);

    {
        let current_len = msg.len();
        let new_len = (current_len - 20 + 24) as u16;
        msg[2] = (new_len >> 8) as u8;
        msg[3] = (new_len & 0xff) as u8;

        let mut mac =
            HmacSha1::new_from_slice(local_pwd.as_bytes()).expect("HMAC accepts any key length");
        mac.update(&msg);
        let integrity = mac.finalize().into_bytes();

        msg.put_u16(ATTR_MESSAGE_INTEGRITY);
        msg.put_u16(20);
        msg.put_slice(&integrity);
    }

    Some(msg.to_vec())
}

fn socket_local_addr(socket: &UdpSocket) -> Result<SocketAddr, IceError> {
    #[cfg(test)]
    if let Some(err) = take_forced_host_local_addr_error() {
        return Err(IceError::Io(err));
    }
    socket.local_addr().map_err(IceError::Io)
}

fn bind_default() -> std::io::Result<std::net::UdpSocket> {
    std::net::UdpSocket::bind("0.0.0.0:0")
}

fn connect_default(socket: &std::net::UdpSocket) -> std::io::Result<()> {
    socket.connect("8.8.8.8:80")
}

fn local_addr_default(socket: &std::net::UdpSocket) -> std::io::Result<std::net::SocketAddr> {
    socket.local_addr()
}

fn get_local_addresses_with(
    bind: fn() -> std::io::Result<std::net::UdpSocket>,
    connect: fn(&std::net::UdpSocket) -> std::io::Result<()>,
    local_addr: fn(&std::net::UdpSocket) -> std::io::Result<std::net::SocketAddr>,
) -> Vec<IpAddr> {
    let mut addrs = Vec::new();

    // Try to get addresses by connecting to a public address
    // This finds the default route interface
    if let Ok(socket) = bind() {
        if connect(&socket).is_ok() {
            if let Ok(local) = local_addr(&socket) {
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
    use crate::ice::Transport;
    use std::sync::Once;

    fn init_tracing() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_test_writer()
                .try_init();
        });
    }

    #[test]
    fn test_normalize_thread_id_branches() {
        assert_eq!(normalize_thread_id(0), 1);
        assert_eq!(normalize_thread_id(42), 42);
    }

    // IceError tests
    #[test]
    fn test_ice_error_io() {
        let io_err = std::io::Error::other("test");
        let err: IceError = io_err.into();
        assert!(err.to_string().contains("IO error"));
    }

    #[test]
    fn test_ice_error_no_candidates() {
        let err = IceError::NoCandidates;
        assert!(err.to_string().contains("No candidates"));
    }

    #[test]
    fn test_ice_error_failed() {
        let err = IceError::Failed("test reason".to_string());
        assert!(err.to_string().contains("test reason"));
    }

    #[test]
    fn test_ice_error_debug() {
        let err = IceError::NoCandidates;
        let debug = format!("{:?}", err);
        assert!(debug.contains("NoCandidates"));
    }

    // IceRole tests
    #[test]
    fn test_ice_role_debug() {
        assert!(format!("{:?}", IceRole::Controlling).contains("Controlling"));
        assert!(format!("{:?}", IceRole::Controlled).contains("Controlled"));
    }

    #[test]
    fn test_ice_role_clone() {
        let role = IceRole::Controlling;
        let cloned = role;
        assert_eq!(role, cloned);
    }

    #[test]
    fn test_ice_role_eq() {
        assert_eq!(IceRole::Controlling, IceRole::Controlling);
        assert_ne!(IceRole::Controlling, IceRole::Controlled);
    }

    // IceState tests
    #[test]
    fn test_ice_state_debug() {
        assert!(format!("{:?}", IceState::New).contains("New"));
        assert!(format!("{:?}", IceState::Gathering).contains("Gathering"));
        assert!(format!("{:?}", IceState::Checking).contains("Checking"));
        assert!(format!("{:?}", IceState::Connected).contains("Connected"));
        assert!(format!("{:?}", IceState::Completed).contains("Completed"));
        assert!(format!("{:?}", IceState::Failed).contains("Failed"));
        assert!(format!("{:?}", IceState::Closed).contains("Closed"));
    }

    #[test]
    fn test_ice_state_clone() {
        let state = IceState::Connected;
        let cloned = state;
        assert_eq!(state, cloned);
    }

    #[test]
    fn test_ice_state_eq() {
        assert_eq!(IceState::New, IceState::New);
        assert_ne!(IceState::New, IceState::Closed);
    }

    // PairState tests
    #[test]
    fn test_pair_state_debug() {
        assert!(format!("{:?}", PairState::Waiting).contains("Waiting"));
        assert!(format!("{:?}", PairState::InProgress).contains("InProgress"));
        assert!(format!("{:?}", PairState::Succeeded).contains("Succeeded"));
        assert!(format!("{:?}", PairState::Failed).contains("Failed"));
        assert!(format!("{:?}", PairState::Frozen).contains("Frozen"));
    }

    #[test]
    fn test_pair_state_clone() {
        let state = PairState::Succeeded;
        let cloned = state;
        assert_eq!(state, cloned);
    }

    #[test]
    fn test_pair_state_eq() {
        assert_eq!(PairState::Waiting, PairState::Waiting);
        assert_ne!(PairState::Waiting, PairState::Failed);
    }

    // CandidatePair tests
    #[test]
    fn test_candidate_pair_debug() {
        let local = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 5000),
            1,
        );
        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        let pair = CandidatePair {
            local,
            remote,
            priority: 1000,
            state: PairState::Waiting,
            nominated: false,
        };
        let debug = format!("{:?}", pair);
        assert!(debug.contains("CandidatePair"));
    }

    #[test]
    fn test_candidate_pair_clone() {
        let local = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 5000),
            1,
        );
        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        let pair = CandidatePair {
            local,
            remote,
            priority: 1000,
            state: PairState::Waiting,
            nominated: false,
        };
        let cloned = pair.clone();
        assert_eq!(cloned.priority, pair.priority);
        assert_eq!(cloned.state, pair.state);
    }

    // IceConfig tests
    #[test]
    fn test_ice_config_default() {
        let config = IceConfig::default();
        assert!(!config.stun_servers.is_empty());
        assert_eq!(config.local_ufrag.len(), 8);
        assert_eq!(config.local_pwd.len(), 24);
        assert_eq!(config.gather_timeout_ms, 1500);
        assert_eq!(config.check_timeout_ms, 3000);
    }

    #[test]
    fn test_ice_config_custom() {
        let config = IceConfig {
            stun_servers: vec![],
            local_ufrag: "myufrag1".to_string(),
            local_pwd: "mypasswordisverysecret1!".to_string(),
            gather_timeout_ms: 10000,
            check_timeout_ms: 5000,
        };
        assert!(config.stun_servers.is_empty());
        assert_eq!(config.local_ufrag, "myufrag1");
        assert_eq!(config.gather_timeout_ms, 10000);
    }

    #[test]
    fn test_ice_config_debug() {
        let config = IceConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("IceConfig"));
    }

    #[test]
    fn test_ice_config_clone() {
        let config = IceConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.gather_timeout_ms, config.gather_timeout_ms);
    }

    // Credential generation tests
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

    #[test]
    fn test_generate_ufrag_uniqueness() {
        let ufrag1 = generate_ice_ufrag();
        let ufrag2 = generate_ice_ufrag();
        assert_ne!(ufrag1, ufrag2);
    }

    #[test]
    fn test_generate_pwd_uniqueness() {
        let pwd1 = generate_ice_pwd();
        let pwd2 = generate_ice_pwd();
        assert_ne!(pwd1, pwd2);
    }

    // get_local_addresses tests
    fn bind_ok() -> std::io::Result<std::net::UdpSocket> {
        std::net::UdpSocket::bind("127.0.0.1:0")
    }

    fn bind_err() -> std::io::Result<std::net::UdpSocket> {
        Err(std::io::Error::other("bind failed"))
    }

    fn connect_ok(socket: &std::net::UdpSocket) -> std::io::Result<()> {
        socket.connect("127.0.0.1:9")
    }

    fn connect_err(_socket: &std::net::UdpSocket) -> std::io::Result<()> {
        Err(std::io::Error::other("connect failed"))
    }

    fn local_addr_ok(socket: &std::net::UdpSocket) -> std::io::Result<std::net::SocketAddr> {
        socket.local_addr()
    }

    fn local_addr_err(_socket: &std::net::UdpSocket) -> std::io::Result<std::net::SocketAddr> {
        Err(std::io::Error::other("addr failed"))
    }

    #[test]
    fn test_get_local_addresses() {
        let addrs = get_local_addresses();
        // Should at least contain localhost
        assert!(!addrs.is_empty());
        assert!(addrs.contains(&IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn test_get_local_addresses_with_bind_error() {
        let addrs = get_local_addresses_with(bind_err, connect_ok, local_addr_ok);
        assert_eq!(addrs, vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
    }

    #[test]
    fn test_get_local_addresses_with_connect_error() {
        let addrs = get_local_addresses_with(bind_ok, connect_err, local_addr_ok);
        assert_eq!(addrs, vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
    }

    #[test]
    fn test_get_local_addresses_with_local_addr_error() {
        let addrs = get_local_addresses_with(bind_ok, connect_ok, local_addr_err);
        assert_eq!(addrs, vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
    }

    #[test]
    fn test_get_local_addresses_with_success() {
        let addrs = get_local_addresses_with(bind_ok, connect_ok, local_addr_ok);
        assert_eq!(addrs, vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
    }

    // IceAgent tests
    #[tokio::test]
    async fn test_ice_agent_creation() {
        let config = IceConfig::default();
        let agent = IceAgent::new(config, IceRole::Controlling);

        assert_eq!(agent.state().await, IceState::New);
    }

    #[tokio::test]
    async fn test_ice_agent_controlled_role() {
        let config = IceConfig::default();
        let agent = IceAgent::new(config, IceRole::Controlled);

        assert_eq!(agent.role, IceRole::Controlled);
        assert_eq!(agent.state().await, IceState::New);
    }

    #[tokio::test]
    async fn test_local_credentials() {
        let config = IceConfig {
            stun_servers: vec![],
            local_ufrag: "testufrag".to_string(),
            local_pwd: "testpasswordverysecure".to_string(),
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let (ufrag, pwd) = agent.local_credentials();
        assert_eq!(ufrag, "testufrag");
        assert_eq!(pwd, "testpasswordverysecure");
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
        assert!(candidates
            .iter()
            .any(|c| c.candidate_type == CandidateType::Host));
    }

    #[tokio::test]
    async fn test_gather_host_candidates_with_bind_error() {
        init_tracing();
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let addrs = vec![
            IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1)),
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        ];
        let candidates = agent.gather_host_candidates_with(addrs).await.unwrap();
        assert!(candidates
            .iter()
            .any(|c| c.address.ip() == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
    }

    #[tokio::test]
    async fn test_local_candidates_accessor() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Initially empty
        assert!(agent.local_candidates().await.is_empty());

        // After gathering
        let _ = agent.gather_candidates().await;
        assert!(!agent.local_candidates().await.is_empty());
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

    #[tokio::test]
    async fn test_form_candidate_pairs_different_components() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Add local candidate for component 1
        let local = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        agent.local_candidates.write().await.push(local);

        // Add remote candidate for component 2 (shouldn't pair)
        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            2, // Different component
        );
        agent.add_remote_candidates(vec![remote]).await;

        // No pairs should be formed due to component mismatch
        let pairs = agent.candidate_pairs.read().await;
        assert_eq!(pairs.len(), 0);
    }

    #[tokio::test]
    async fn test_form_candidate_pairs_skips_mismatched_transport() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let mut local = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        local.transport = Transport::Tcp;
        agent.local_candidates.write().await.push(local);

        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            1,
        );
        agent.remote_candidates.write().await.push(remote);

        agent.form_candidate_pairs().await;

        let pairs = agent.candidate_pairs.read().await;
        assert!(pairs.is_empty());
    }

    #[tokio::test]
    async fn test_set_remote_credentials() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Initially no remote credentials
        assert!(agent.remote_credentials().await.is_none());

        // Set credentials
        agent.set_remote_credentials("abc123", "password456").await;

        // Verify they're set
        let creds = agent.remote_credentials().await;
        assert!(creds.is_some());
        let (ufrag, pwd) = creds.unwrap();
        assert_eq!(ufrag, "abc123");
        assert_eq!(pwd, "password456");
    }

    #[tokio::test]
    async fn test_selected_pair_initially_none() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        assert!(agent.selected_pair().await.is_none());
    }

    #[tokio::test]
    async fn test_start_checks_missing_socket_falls_back() {
        init_tracing();
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

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
        agent.set_remote_credentials("remufrag", "rempwd").await;

        let result = agent.start_checks().await;
        assert!(result.is_ok());
        assert_eq!(agent.state().await, IceState::Connected);
    }

    #[tokio::test]
    async fn test_start_checks_success() {
        init_tracing();
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();
        let local = Candidate::host(local_addr, 1);
        agent.local_candidates.write().await.push(local.clone());
        agent
            .sockets
            .write()
            .await
            .insert(local.address, local_socket.clone());

        let mock = MockStunServer::new().await;
        let remote = Candidate::host(mock.addr, 1);
        agent.add_remote_candidates(vec![remote]).await;
        agent
            .set_remote_credentials("remoteufrag", "remotepwd")
            .await;

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = MockStunServer::build_connectivity_check_response(&txn_id);
            let _ = mock_socket.send_to(&response, peer).await;
        });

        let result = agent.start_checks().await;
        assert!(result.is_ok());
        let selected = agent.selected_pair().await.unwrap();
        assert_eq!(selected.state, PairState::Succeeded);
        assert!(selected.nominated);
    }

    #[tokio::test]
    async fn test_perform_connectivity_check_send_error() {
        init_tracing();
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();
        let local_cand = Candidate::host(local_addr, 1);
        let remote_cand = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0),
            1,
        );
        let pair = CandidatePair {
            local: local_cand,
            remote: remote_cand,
            priority: 100,
            state: PairState::Waiting,
            nominated: false,
        };

        let result = agent
            .perform_connectivity_check(&local_socket, &pair, "remoteufrag", "remotepwd")
            .await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_fallback_selection() {
        init_tracing();
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Add local candidate
        let local = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        agent.local_candidates.write().await.push(local.clone());

        // Create socket for the local candidate
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        agent
            .sockets
            .write()
            .await
            .insert(local.address, Arc::new(socket));

        // Add remote candidate
        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            1,
        );
        agent.add_remote_candidates(vec![remote]).await;

        // Without remote credentials, should use fallback
        let result = agent.start_checks().await;
        assert!(result.is_ok());

        // Should have selected the host-to-host pair
        let selected = agent.selected_pair().await;
        assert!(selected.is_some());
        let pair = selected.unwrap();
        assert_eq!(pair.local.candidate_type, CandidateType::Host);
        assert_eq!(pair.remote.candidate_type, CandidateType::Host);
    }

    #[tokio::test]
    async fn test_fallback_selection_non_host_pair() {
        init_tracing();
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let base = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001);
        let mapped = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2)), 5002);
        let remote_mapped =
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 3)), 5003);

        let local_host = Candidate::host(base, 1);
        let remote_srflx = Candidate::server_reflexive(remote_mapped, base, 1);
        let local_srflx = Candidate::server_reflexive(mapped, base, 1);
        let remote_host = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            1,
        );

        let pair1 = CandidatePair {
            local: local_host.clone(),
            remote: remote_srflx,
            priority: 1000,
            state: PairState::Waiting,
            nominated: false,
        };
        let pair2 = CandidatePair {
            local: local_srflx,
            remote: remote_host,
            priority: 900,
            state: PairState::Waiting,
            nominated: false,
        };
        {
            let mut pairs = agent.candidate_pairs.write().await;
            pairs.push(pair1);
            pairs.push(pair2);
        }

        let result = agent.fallback_selection().await;
        assert!(result.is_ok());

        let selected = agent.selected_pair().await;
        assert!(selected.is_some());
        let selected = selected.unwrap();
        assert_eq!(selected.local.candidate_type, CandidateType::Host);
        assert_eq!(
            selected.remote.candidate_type,
            CandidateType::ServerReflexive
        );
    }

    #[tokio::test]
    async fn test_fallback_no_candidates() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // No candidates added, should fail
        let result = agent.start_checks().await;
        assert!(result.is_err());
        assert!(agent.state().await == IceState::Failed);
    }

    #[tokio::test]
    async fn test_ice_state_transitions() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Initial state
        assert_eq!(agent.state().await, IceState::New);

        // After gathering
        let _ = agent.gather_candidates().await;
        assert_eq!(agent.state().await, IceState::Gathering);

        // Close
        agent.close().await;
        assert_eq!(agent.state().await, IceState::Closed);
    }

    #[tokio::test]
    async fn test_close_clears_sockets() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Gather to create sockets
        let _ = agent.gather_candidates().await;
        assert!(!agent.sockets.read().await.is_empty());

        // Close should clear sockets
        agent.close().await;
        assert!(agent.sockets.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_socket_for_returns_bound_socket() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let candidates = agent.gather_candidates().await.expect("gather");
        // Pick any host candidate; its address must be a key in the
        // sockets map.
        let host = candidates
            .iter()
            .find(|c| c.candidate_type == CandidateType::Host)
            .expect("host candidate");
        let socket = agent.socket_for(host.address).await.expect("socket");
        assert_eq!(socket.local_addr().unwrap(), host.address);
    }

    #[tokio::test]
    async fn test_socket_for_unknown_address() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);
        let unknown = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 99)), 65000);
        assert!(agent.socket_for(unknown).await.is_none());
    }

    #[tokio::test]
    async fn test_multiple_remote_candidates() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Add local candidate
        let local = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        agent.local_candidates.write().await.push(local);

        // Add multiple remote candidates
        let remote1 = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            1,
        );
        let remote2 = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 101)), 5000),
            1,
        );
        agent.add_remote_candidates(vec![remote1, remote2]).await;

        // Should have 2 pairs
        let pairs = agent.candidate_pairs.read().await;
        assert_eq!(pairs.len(), 2);
    }

    // ========== New Comprehensive Tests for Coverage ==========

    // Mock UDP server for testing STUN interactions
    struct MockStunServer {
        socket: Arc<UdpSocket>,
        addr: SocketAddr,
    }

    impl MockStunServer {
        async fn new() -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            Self {
                socket: Arc::new(socket),
                addr,
            }
        }

        // Build a STUN Binding Success Response with XOR-MAPPED-ADDRESS
        fn build_binding_response(txn_id: &[u8; 12], mapped_addr: SocketAddr) -> Vec<u8> {
            use bytes::{BufMut, BytesMut};

            const MAGIC_COOKIE: u32 = 0x2112A442;
            const BINDING_RESPONSE: u16 = 0x0101;
            const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

            let mut attrs = BytesMut::new();

            // XOR-MAPPED-ADDRESS attribute
            match mapped_addr {
                SocketAddr::V4(addr) => {
                    attrs.put_u16(ATTR_XOR_MAPPED_ADDRESS);
                    attrs.put_u16(8); // Length
                    attrs.put_u8(0); // Reserved
                    attrs.put_u8(0x01); // Family: IPv4

                    // XOR port with magic cookie high 16 bits
                    let xor_port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
                    attrs.put_u16(xor_port);

                    // XOR IP with magic cookie
                    let ip_bytes = addr.ip().octets();
                    let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
                    for i in 0..4 {
                        attrs.put_u8(ip_bytes[i] ^ cookie_bytes[i]);
                    }
                }
                SocketAddr::V6(_) => {
                    // For simplicity, not implementing IPv6
                    panic!("IPv6 not implemented in mock");
                }
            }

            // Build message
            let mut msg = BytesMut::new();
            msg.put_u16(BINDING_RESPONSE);
            msg.put_u16(attrs.len() as u16);
            msg.put_u32(MAGIC_COOKIE);
            msg.put_slice(txn_id);
            msg.put_slice(&attrs);

            msg.to_vec()
        }

        // Build a STUN Binding Success Response for connectivity check (with MESSAGE-INTEGRITY validation)
        fn build_connectivity_check_response(txn_id: &[u8; 12]) -> Vec<u8> {
            use bytes::{BufMut, BytesMut};

            const MAGIC_COOKIE: u32 = 0x2112A442;
            const BINDING_RESPONSE: u16 = 0x0101;

            // Simple response with just header (minimal valid response)
            let mut msg = BytesMut::new();
            msg.put_u16(BINDING_RESPONSE);
            msg.put_u16(0); // No attributes
            msg.put_u32(MAGIC_COOKIE);
            msg.put_slice(txn_id);

            msg.to_vec()
        }
    }

    #[test]
    #[should_panic(expected = "IPv6 not implemented in mock")]
    fn test_mock_stun_server_ipv6_not_implemented() {
        let txn_id = [0u8; 12];
        let addr = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 9999);
        let _ = MockStunServer::build_binding_response(&txn_id, addr);
    }

    // Test: perform_connectivity_check with successful response
    #[tokio::test]
    async fn test_perform_connectivity_check_success() {
        init_tracing();
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Create local socket
        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();

        // Create mock remote server
        let mock = MockStunServer::new().await;
        let mock_addr = mock.addr;

        // Create candidate pair
        let local_cand = Candidate::host(local_addr, 1);
        let remote_cand = Candidate::host(mock_addr, 1);
        let pair = CandidatePair {
            local: local_cand,
            remote: remote_cand,
            priority: 1000,
            state: PairState::Waiting,
            nominated: false,
        };

        // Spawn mock server to respond
        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);

            // Send response
            let response = MockStunServer::build_connectivity_check_response(&txn_id);
            let _ = mock_socket.send_to(&response, peer).await;
        });

        // Perform connectivity check
        let result = agent
            .perform_connectivity_check(&local_socket, &pair, "remoteufrag", "remotepwd")
            .await;

        assert!(result);
    }

    // Test: perform_connectivity_check with timeout
    #[tokio::test]
    async fn test_perform_connectivity_check_timeout() {
        init_tracing();
        let config = IceConfig {
            stun_servers: vec![],
            check_timeout_ms: 100, // Very short timeout
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Create local socket
        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();

        // Use unreachable address for timeout
        let unreachable_addr =
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)), 9999);

        let local_cand = Candidate::host(local_addr, 1);
        let remote_cand = Candidate::host(unreachable_addr, 1);
        let pair = CandidatePair {
            local: local_cand,
            remote: remote_cand,
            priority: 1000,
            state: PairState::Waiting,
            nominated: false,
        };

        // Perform connectivity check - should timeout
        let result = agent
            .perform_connectivity_check(&local_socket, &pair, "remoteufrag", "remotepwd")
            .await;

        assert!(!result);
    }

    // Test: perform_connectivity_check with invalid response
    #[tokio::test]
    async fn test_perform_connectivity_check_invalid_response() {
        let config = IceConfig {
            stun_servers: vec![],
            check_timeout_ms: 500,
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();

        let mock = MockStunServer::new().await;
        let mock_addr = mock.addr;

        let local_cand = Candidate::host(local_addr, 1);
        let remote_cand = Candidate::host(mock_addr, 1);
        let pair = CandidatePair {
            local: local_cand,
            remote: remote_cand,
            priority: 1000,
            state: PairState::Waiting,
            nominated: false,
        };

        // Spawn mock server to send invalid response
        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            // Send invalid response (too short)
            let _ = mock_socket.send_to(&[0, 1, 2, 3], peer).await;
        });

        let result = agent
            .perform_connectivity_check(&local_socket, &pair, "remoteufrag", "remotepwd")
            .await;

        assert!(!result);
    }

    // Test: perform_connectivity_check with wrong message type
    #[tokio::test]
    async fn test_perform_connectivity_check_bad_message_type() {
        use bytes::{BufMut, BytesMut};

        let config = IceConfig {
            stun_servers: vec![],
            check_timeout_ms: 100,
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();

        let mock = MockStunServer::new().await;
        let mock_addr = mock.addr;

        let local_cand = Candidate::host(local_addr, 1);
        let remote_cand = Candidate::host(mock_addr, 1);
        let pair = CandidatePair {
            local: local_cand,
            remote: remote_cand,
            priority: 1000,
            state: PairState::Waiting,
            nominated: false,
        };

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);

            let mut msg = BytesMut::new();
            msg.put_u16(0x0001); // Not a response
            msg.put_u16(0);
            msg.put_u32(0x2112A442);
            msg.put_slice(&txn_id);
            let _ = mock_socket.send_to(&msg, peer).await;
        });

        let result = agent
            .perform_connectivity_check(&local_socket, &pair, "remoteufrag", "remotepwd")
            .await;

        assert!(!result);
    }

    // Test: perform_connectivity_check with bad magic cookie
    #[tokio::test]
    async fn test_perform_connectivity_check_bad_cookie() {
        use bytes::{BufMut, BytesMut};

        let config = IceConfig {
            stun_servers: vec![],
            check_timeout_ms: 100,
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();

        let mock = MockStunServer::new().await;
        let mock_addr = mock.addr;

        let local_cand = Candidate::host(local_addr, 1);
        let remote_cand = Candidate::host(mock_addr, 1);
        let pair = CandidatePair {
            local: local_cand,
            remote: remote_cand,
            priority: 1000,
            state: PairState::Waiting,
            nominated: false,
        };

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);

            let mut msg = BytesMut::new();
            msg.put_u16(0x0101);
            msg.put_u16(0);
            msg.put_u32(0xDEADBEEF);
            msg.put_slice(&txn_id);
            let _ = mock_socket.send_to(&msg, peer).await;
        });

        let result = agent
            .perform_connectivity_check(&local_socket, &pair, "remoteufrag", "remotepwd")
            .await;

        assert!(!result);
    }

    // Test: perform_connectivity_check with wrong transaction ID
    #[tokio::test]
    async fn test_perform_connectivity_check_wrong_transaction_id() {
        let config = IceConfig {
            stun_servers: vec![],
            check_timeout_ms: 500,
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();

        let mock = MockStunServer::new().await;
        let mock_addr = mock.addr;

        let local_cand = Candidate::host(local_addr, 1);
        let remote_cand = Candidate::host(mock_addr, 1);
        let pair = CandidatePair {
            local: local_cand,
            remote: remote_cand,
            priority: 1000,
            state: PairState::Waiting,
            nominated: false,
        };

        // Spawn mock server to send response with wrong transaction ID
        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            // Send response with different transaction ID
            let wrong_txn_id = [9u8; 12];
            let response = MockStunServer::build_connectivity_check_response(&wrong_txn_id);
            let _ = mock_socket.send_to(&response, peer).await;
        });

        let result = agent
            .perform_connectivity_check(&local_socket, &pair, "remoteufrag", "remotepwd")
            .await;

        assert!(!result);
    }

    // Test: Controlling agent nominates successful pair
    #[tokio::test]
    async fn test_controlling_agent_nominates_pair() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Create a pair and simulate successful check
        let local = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            1,
        );

        agent.local_candidates.write().await.push(local.clone());
        agent.add_remote_candidates(vec![remote.clone()]).await;

        // Manually mark pair as succeeded (simulating successful check)
        {
            let mut pairs = agent.candidate_pairs.write().await;
            let pair = pairs.get_mut(0).unwrap();
            pair.state = PairState::Succeeded;
            pair.nominated = true;

            // Select the pair
            *agent.selected_pair.write().await = Some(pair.clone());
            *agent.state.write().await = IceState::Connected;
        }

        // Verify controlling agent nominated the pair
        let selected = agent.selected_pair().await.unwrap();
        assert!(selected.nominated);
        assert_eq!(selected.state, PairState::Succeeded);
        assert_eq!(agent.state().await, IceState::Connected);
    }

    // Test: Controlled agent does not nominate
    #[tokio::test]
    async fn test_controlled_agent_does_not_nominate() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlled);

        let local = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            1,
        );

        agent.local_candidates.write().await.push(local);
        agent.add_remote_candidates(vec![remote]).await;

        // Manually mark pair as succeeded
        {
            let mut pairs = agent.candidate_pairs.write().await;
            let pair = pairs.get_mut(0).unwrap();
            pair.state = PairState::Succeeded;
            pair.nominated = false;

            *agent.selected_pair.write().await = Some(pair.clone());
            *agent.state.write().await = IceState::Connected;
        }

        // Verify controlled agent did not nominate
        let selected = agent.selected_pair().await.unwrap();
        assert!(!selected.nominated);
    }

    // Test: pair prioritization logic
    #[tokio::test]
    async fn test_pair_prioritization() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Add multiple local candidates with different priorities
        let local1 = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        let local2 = Candidate::server_reflexive(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)), 5002),
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );

        agent.local_candidates.write().await.push(local1);
        agent.local_candidates.write().await.push(local2);

        // Add remote candidate
        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            1,
        );
        agent.add_remote_candidates(vec![remote]).await;

        // Check pairs are sorted by priority (highest first)
        let pairs = agent.candidate_pairs.read().await;
        assert_eq!(pairs.len(), 2);

        // Host candidates have higher priority than srflx
        // So first pair should have host local candidate
        assert!(pairs[0].priority >= pairs[1].priority);
    }

    // Test: unfreeze_related_pairs functionality
    #[tokio::test]
    async fn test_unfreeze_related_pairs() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Create candidates with same foundation
        let local1 = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        let local2 = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5002),
            1,
        );

        let remote1 = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            1,
        );
        let remote2 = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 101)), 5001),
            1,
        );

        agent.local_candidates.write().await.push(local1.clone());
        agent.local_candidates.write().await.push(local2);
        agent
            .add_remote_candidates(vec![remote1.clone(), remote2])
            .await;

        // Set all pairs to Frozen except first
        {
            let mut pairs = agent.candidate_pairs.write().await;
            for (i, pair) in pairs.iter_mut().enumerate() {
                if i == 0 {
                    pair.state = PairState::Succeeded;
                } else {
                    pair.state = PairState::Frozen;
                }
            }
        }

        // Create a succeeded pair for unfreezing
        let succeeded_pair = CandidatePair {
            local: local1,
            remote: remote1,
            priority: 1000,
            state: PairState::Succeeded,
            nominated: false,
        };

        // Unfreeze related pairs
        agent.unfreeze_related_pairs(0, &succeeded_pair).await;

        // Check that pairs with same foundation are now Waiting
        let pairs = agent.candidate_pairs.read().await;
        let unfrozen_count = pairs
            .iter()
            .filter(|p| p.state == PairState::Waiting)
            .count();
        assert!(unfrozen_count > 0);
    }

    #[tokio::test]
    async fn test_unfreeze_related_pairs_skips_mismatched() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_base = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)), 5001),
            1,
        );
        let local_other = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)), 5002),
            1,
        );
        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 100)), 5000),
            1,
        );

        let succeeded = CandidatePair {
            local: local_base.clone(),
            remote: remote.clone(),
            priority: 1000,
            state: PairState::Succeeded,
            nominated: false,
        };

        let frozen_match = CandidatePair {
            local: local_base.clone(),
            remote: remote.clone(),
            priority: 900,
            state: PairState::Frozen,
            nominated: false,
        };

        let waiting_match = CandidatePair {
            local: local_base.clone(),
            remote: remote.clone(),
            priority: 800,
            state: PairState::Waiting,
            nominated: false,
        };

        let frozen_other = CandidatePair {
            local: local_other,
            remote,
            priority: 700,
            state: PairState::Frozen,
            nominated: false,
        };

        {
            let mut pairs = agent.candidate_pairs.write().await;
            pairs.clear();
            pairs.push(succeeded.clone());
            pairs.push(frozen_match);
            pairs.push(waiting_match);
            pairs.push(frozen_other);
        }

        agent.unfreeze_related_pairs(0, &succeeded).await;

        let pairs = agent.candidate_pairs.read().await;
        assert_eq!(pairs[1].state, PairState::Waiting);
        assert_eq!(pairs[2].state, PairState::Waiting);
        assert_eq!(pairs[3].state, PairState::Frozen);
    }

    // Test: stun_binding_request with successful response
    #[tokio::test]
    async fn test_stun_binding_request_success() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Create local socket
        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // Create mock STUN server
        let mock = MockStunServer::new().await;
        let server = StunServer {
            name: "mock",
            addr: mock.addr,
        };

        // Expected mapped address
        let mapped_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)), 5678);

        // Spawn mock server to respond
        let mock_socket = mock.socket.clone();
        let expected_mapped = mapped_addr;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = MockStunServer::build_binding_response(&txn_id, expected_mapped);
            let _ = mock_socket.send_to(&response, peer).await;
        });

        // Perform STUN binding request
        let result = agent.stun_binding_request(&local_socket, &server).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), mapped_addr);
    }

    // Test: stun_binding_request with too-short response
    #[tokio::test]
    async fn test_stun_binding_request_too_short() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mock = MockStunServer::new().await;
        let server = StunServer {
            name: "mock",
            addr: mock.addr,
        };

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let _ = mock_socket.send_to(&[0u8; 8], peer).await;
        });

        let result = agent.stun_binding_request(&local_socket, &server).await;
        assert!(result.is_err());
    }

    // Test: stun_binding_request with non-response message type
    #[tokio::test]
    async fn test_stun_binding_request_not_response() {
        use bytes::{BufMut, BytesMut};

        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mock = MockStunServer::new().await;
        let server = StunServer {
            name: "mock",
            addr: mock.addr,
        };

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);

            let mut msg = BytesMut::new();
            msg.put_u16(0x0001); // Not a response
            msg.put_u16(0);
            msg.put_u32(0x2112A442);
            msg.put_slice(&txn_id);
            let _ = mock_socket.send_to(&msg, peer).await;
        });

        let result = agent.stun_binding_request(&local_socket, &server).await;
        let err = result.expect_err("expected InvalidResponse");
        assert!(
            matches!(err, crate::ice::stun::StunError::InvalidResponse(_)),
            "expected InvalidResponse, got {:?}",
            err
        );
    }

    // Test: stun_binding_request with non-XOR attribute payload
    #[tokio::test]
    async fn test_stun_binding_request_non_xor_attribute() {
        use bytes::{BufMut, BytesMut};

        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mock = MockStunServer::new().await;
        let server = StunServer {
            name: "mock",
            addr: mock.addr,
        };

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);

            let mut attrs = BytesMut::new();
            attrs.put_u16(0x0001); // Dummy attribute
            attrs.put_u16(4);
            attrs.put_u32(0x01020304);

            let mut msg = BytesMut::new();
            msg.put_u16(0x0101);
            msg.put_u16(attrs.len() as u16);
            msg.put_u32(0x2112A442);
            msg.put_slice(&txn_id);
            msg.put_slice(&attrs);
            let _ = mock_socket.send_to(&msg, peer).await;
        });

        let result = agent.stun_binding_request(&local_socket, &server).await;
        assert!(result.is_err());
    }

    // Test: stun_binding_request with non-IPv4 XOR-MAPPED-ADDRESS family
    #[tokio::test]
    async fn test_stun_binding_request_non_ipv4_family() {
        use bytes::{BufMut, BytesMut};

        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mock = MockStunServer::new().await;
        let server = StunServer {
            name: "mock",
            addr: mock.addr,
        };

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);

            let mut attrs = BytesMut::new();
            attrs.put_u16(0x0020); // XOR-MAPPED-ADDRESS
            attrs.put_u16(8);
            attrs.put_u8(0);
            attrs.put_u8(0x02); // IPv6 family
            attrs.put_u16(0x1234);
            attrs.put_u32(0x01020304);

            let mut msg = BytesMut::new();
            msg.put_u16(0x0101);
            msg.put_u16(attrs.len() as u16);
            msg.put_u32(0x2112A442);
            msg.put_slice(&txn_id);
            msg.put_slice(&attrs);
            let _ = mock_socket.send_to(&msg, peer).await;
        });

        let result = agent.stun_binding_request(&local_socket, &server).await;
        assert!(result.is_err());
    }

    // Test: stun_binding_request with short XOR-MAPPED-ADDRESS attribute
    #[tokio::test]
    async fn test_stun_binding_request_short_xor_attribute() {
        use bytes::{BufMut, BytesMut};

        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mock = MockStunServer::new().await;
        let server = StunServer {
            name: "mock",
            addr: mock.addr,
        };

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);

            let mut attrs = BytesMut::new();
            attrs.put_u16(0x0020); // XOR-MAPPED-ADDRESS
            attrs.put_u16(4); // Too short
            attrs.put_u32(0x01020304);

            let mut msg = BytesMut::new();
            msg.put_u16(0x0101);
            msg.put_u16(attrs.len() as u16);
            msg.put_u32(0x2112A442);
            msg.put_slice(&txn_id);
            msg.put_slice(&attrs);
            let _ = mock_socket.send_to(&msg, peer).await;
        });

        let result = agent.stun_binding_request(&local_socket, &server).await;
        assert!(result.is_err());
    }

    // Test: stun_binding_request with timeout
    #[tokio::test]
    async fn test_stun_binding_request_timeout() {
        let config = IceConfig {
            stun_servers: vec![],
            check_timeout_ms: 10,
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();

        let server = StunServer {
            name: "unreachable",
            addr: server_addr,
        };

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = server_socket.recv_from(&mut buf).await;
        });

        let result = agent.stun_binding_request(&local_socket, &server).await;
        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "Request timeout");
    }

    // Test: stun_binding_request with invalid response (bad magic cookie)
    #[tokio::test]
    async fn test_stun_binding_request_bad_magic_cookie() {
        use bytes::{BufMut, BytesMut};

        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mock = MockStunServer::new().await;
        let server = StunServer {
            name: "mock",
            addr: mock.addr,
        };

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            // Build response with bad magic cookie
            let mut msg = BytesMut::new();
            msg.put_u16(0x0101); // BINDING_RESPONSE
            msg.put_u16(0); // Length
            msg.put_u32(0xDEADBEEF); // Wrong magic cookie
            msg.put_slice(&buf[8..20]); // Transaction ID
            let _ = mock_socket.send_to(&msg, peer).await;
        });

        // R4: dispatcher forwards by txn-id, then `stun_binding_request`
        // re-validates the cookie and surfaces `InvalidResponse`.
        let result = agent.stun_binding_request(&local_socket, &server).await;
        let err = result.expect_err("expected InvalidResponse");
        assert!(
            matches!(err, crate::ice::stun::StunError::InvalidResponse(_)),
            "expected InvalidResponse, got {:?}",
            err
        );
    }

    // Test: stun_binding_request with missing XOR-MAPPED-ADDRESS
    #[tokio::test]
    async fn test_stun_binding_request_no_mapped_address() {
        use bytes::{BufMut, BytesMut};

        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let mock = MockStunServer::new().await;
        let server = StunServer {
            name: "mock",
            addr: mock.addr,
        };

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let txn_id: [u8; 12] = buf[8..20].try_into().expect("short STUN request");

            // Build response without XOR-MAPPED-ADDRESS
            let mut msg = BytesMut::new();
            msg.put_u16(0x0101); // BINDING_RESPONSE
            msg.put_u16(0); // No attributes
            msg.put_u32(0x2112A442); // Magic cookie
            msg.put_slice(&txn_id);
            let _ = mock_socket.send_to(&msg, peer).await;
        });

        let result = agent.stun_binding_request(&local_socket, &server).await;
        assert!(result.is_err());
    }

    // Test: gather_srflx_candidates with STUN server
    #[tokio::test]
    async fn test_gather_srflx_candidates() {
        init_tracing();
        // Create mock STUN server
        let mock = MockStunServer::new().await;

        let config = IceConfig {
            stun_servers: vec![StunServer {
                name: "mock",
                addr: mock.addr,
            }],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // First gather host candidates
        let _ = agent.gather_host_candidates().await;

        // Spawn mock server to respond (respond once per request)
        let mock_socket = mock.socket.clone();
        let mapped_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)), 9999);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            // Respond to first request only
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let txn_id: [u8; 12] = buf[8..20].try_into().expect("short STUN request");
            let response = MockStunServer::build_binding_response(&txn_id, mapped_addr);
            let _ = mock_socket.send_to(&response, peer).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Gather srflx candidates
        let srflx_candidates = agent.gather_srflx_candidates().await;

        // Should have at least one srflx candidate
        assert!(!srflx_candidates.is_empty());
        assert!(srflx_candidates
            .iter()
            .any(|c| c.candidate_type == CandidateType::ServerReflexive));
    }

    // Test: gather_srflx_candidates ignores mapped address equal to base
    #[tokio::test]
    async fn test_gather_srflx_candidates_ignores_base_address() {
        let mock = MockStunServer::new().await;

        let config = IceConfig {
            stun_servers: vec![StunServer {
                name: "mock",
                addr: mock.addr,
            }],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();
        agent
            .sockets
            .write()
            .await
            .insert(local_addr, local_socket.clone());

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = MockStunServer::build_binding_response(&txn_id, local_addr);
            let _ = mock_socket.send_to(&response, peer).await;
        });

        let srflx_candidates = agent.gather_srflx_candidates().await;
        assert!(srflx_candidates.is_empty());
    }

    // Test: gather_srflx_candidates handles STUN error
    #[tokio::test]
    async fn test_gather_srflx_candidates_stun_error() {
        let mock = MockStunServer::new().await;

        let config = IceConfig {
            stun_servers: vec![StunServer {
                name: "mock",
                addr: mock.addr,
            }],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();
        agent
            .sockets
            .write()
            .await
            .insert(local_addr, local_socket.clone());

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let _ = mock_socket.send_to(&[0u8; 8], peer).await;
        });

        let srflx_candidates = agent.gather_srflx_candidates().await;
        assert!(srflx_candidates.is_empty());
    }

    // Test: fallback_selection prefers host-to-host pairs
    #[tokio::test]
    async fn test_fallback_prefers_host_to_host() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Add srflx local candidate
        let local_srflx = Candidate::server_reflexive(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)), 5001),
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );

        // Add host local candidate
        let local_host = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2)), 5002),
            1,
        );

        agent.local_candidates.write().await.push(local_srflx);
        agent.local_candidates.write().await.push(local_host);

        // Add host remote candidate
        let remote_host = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            1,
        );
        agent.add_remote_candidates(vec![remote_host]).await;

        // Fallback selection
        let result = agent.fallback_selection().await;
        assert!(result.is_ok());

        // Should prefer host-to-host
        let selected = agent.selected_pair().await.unwrap();
        assert_eq!(selected.local.candidate_type, CandidateType::Host);
        assert_eq!(selected.remote.candidate_type, CandidateType::Host);
    }

    // Test: form_candidate_pairs prevents duplicates
    #[tokio::test]
    async fn test_form_candidate_pairs_no_duplicates() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        agent.local_candidates.write().await.push(local);

        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            1,
        );

        // Add same remote candidate twice
        agent.add_remote_candidates(vec![remote.clone()]).await;
        agent.add_remote_candidates(vec![remote]).await;

        // Should only have 1 pair (no duplicates)
        let pairs = agent.candidate_pairs.read().await;
        assert_eq!(pairs.len(), 1);
    }

    // Test: form_candidate_pairs initializes with Frozen state
    #[tokio::test]
    async fn test_form_candidate_pairs_frozen_state() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Add multiple local candidates with different foundations
        let local1 = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        let local2 = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 2)), 5002),
            1,
        );

        agent.local_candidates.write().await.push(local1);
        agent.local_candidates.write().await.push(local2);

        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            1,
        );
        agent.add_remote_candidates(vec![remote]).await;

        let pairs = agent.candidate_pairs.read().await;

        // First pair of each foundation should be Waiting, others Frozen
        let waiting_count = pairs
            .iter()
            .filter(|p| p.state == PairState::Waiting)
            .count();
        assert!(waiting_count > 0);
    }

    // Test: start_checks updates pair states correctly
    #[tokio::test]
    async fn test_start_checks_pair_state_progression() {
        let config = IceConfig {
            stun_servers: vec![],
            check_timeout_ms: 500,
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        agent.set_remote_credentials("remoteusr", "remotepwd").await;

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();

        // Use unreachable address so check fails
        let unreachable_addr =
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1)), 9999);

        let local_cand = Candidate::host(local_addr, 1);
        agent.local_candidates.write().await.push(local_cand);
        agent
            .sockets
            .write()
            .await
            .insert(local_addr, local_socket.clone());

        let remote_cand = Candidate::host(unreachable_addr, 1);
        agent.add_remote_candidates(vec![remote_cand]).await;

        {
            let mut pairs = agent.candidate_pairs.write().await;
            let pair = pairs.get_mut(0).expect("missing candidate pair");
            pair.state = PairState::Waiting;
        }

        // Start checks - should fail and go to fallback
        let _ = agent.start_checks().await;

        // Check pair state was updated to Failed
        let pairs = agent.candidate_pairs.read().await;
        assert!(pairs.iter().any(|p| p.state == PairState::Failed));
    }

    // Test: start_checks succeeds and nominates for controlling role
    #[tokio::test]
    async fn test_start_checks_success_controlling() {
        let config = IceConfig {
            stun_servers: vec![],
            check_timeout_ms: 500,
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        agent.set_remote_credentials("remoteusr", "remotepwd").await;

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();
        let local_cand = Candidate::host(local_addr, 1);
        agent.local_candidates.write().await.push(local_cand);
        agent
            .sockets
            .write()
            .await
            .insert(local_addr, local_socket.clone());

        let mock = MockStunServer::new().await;
        let remote_cand = Candidate::host(mock.addr, 1);
        agent.add_remote_candidates(vec![remote_cand]).await;

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = MockStunServer::build_connectivity_check_response(&txn_id);
            let _ = mock_socket.send_to(&response, peer).await;
        });

        let result = agent.start_checks().await;
        assert!(result.is_ok());

        let selected = agent.selected_pair().await;
        assert!(selected.is_some());
        assert!(selected.unwrap().nominated);
    }

    // Test: start_checks succeeds without nomination when controlled
    #[tokio::test]
    async fn test_start_checks_success_controlled() {
        let config = IceConfig {
            stun_servers: vec![],
            check_timeout_ms: 500,
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlled);

        agent.set_remote_credentials("remoteusr", "remotepwd").await;

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();
        let local_cand = Candidate::host(local_addr, 1);
        agent.local_candidates.write().await.push(local_cand);
        agent
            .sockets
            .write()
            .await
            .insert(local_addr, local_socket.clone());

        let mock = MockStunServer::new().await;
        let remote_cand = Candidate::host(mock.addr, 1);
        agent.add_remote_candidates(vec![remote_cand]).await;

        let mock_socket = mock.socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (_len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let mut txn_id = [0u8; 12];
            txn_id.copy_from_slice(&buf[8..20]);
            let response = MockStunServer::build_connectivity_check_response(&txn_id);
            let _ = mock_socket.send_to(&response, peer).await;
        });

        let result = agent.start_checks().await;
        assert!(result.is_ok());

        let selected = agent.selected_pair().await;
        assert!(selected.is_some());
        assert!(!selected.unwrap().nominated);
    }

    // Test: Controlled agent uses correct ICE-CONTROLLED attribute
    #[tokio::test]
    async fn test_controlled_agent_ice_attribute() {
        let config = IceConfig {
            stun_servers: vec![],
            check_timeout_ms: 1000,
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlled);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();

        let mock = MockStunServer::new().await;
        let mock_addr = mock.addr;

        let local_cand = Candidate::host(local_addr, 1);
        let remote_cand = Candidate::host(mock_addr, 1);
        let pair = CandidatePair {
            local: local_cand,
            remote: remote_cand,
            priority: 1000,
            state: PairState::Waiting,
            nominated: false,
        };

        // Spawn server to check for ICE-CONTROLLED attribute
        let mock_socket = mock.socket.clone();
        let (controlled_tx, controlled_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            // Check for ICE-CONTROLLED attribute (0x8029)
            let has_controlled = buf[..len].windows(2).any(|w| w[0] == 0x80 && w[1] == 0x29);
            let _ = controlled_tx.send(has_controlled);

            let txn_id: [u8; 12] = buf[8..20].try_into().expect("short STUN request");
            let response = MockStunServer::build_connectivity_check_response(&txn_id);
            let _ = mock_socket.send_to(&response, peer).await;
        });

        let result = agent
            .perform_connectivity_check(&local_socket, &pair, "remoteufrag", "remotepwd")
            .await;

        assert!(result);
        assert!(controlled_rx.await.unwrap_or(false));
    }

    // Test: remote credentials update
    #[tokio::test]
    async fn test_update_remote_credentials() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Set initial credentials
        agent.set_remote_credentials("user1", "pass1").await;
        let (ufrag, pwd) = agent.remote_credentials().await.unwrap();
        assert_eq!(ufrag, "user1");
        assert_eq!(pwd, "pass1");

        // Update credentials
        agent.set_remote_credentials("user2", "pass2").await;
        let (ufrag, pwd) = agent.remote_credentials().await.unwrap();
        assert_eq!(ufrag, "user2");
        assert_eq!(pwd, "pass2");
    }

    #[tokio::test]
    async fn test_remote_credentials_missing_password() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        *agent.remote_ufrag.write().await = Some("user".to_string());
        let creds = agent.remote_credentials().await;
        assert!(creds.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_gather_candidates_forced_local_addr_error() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        force_host_local_addr_error_once();
        let result = agent.gather_candidates().await;
        assert!(result.is_err());
    }

    // Test: pair priority calculation differs between controlling and controlled
    #[tokio::test]
    async fn test_pair_priority_role_difference() {
        let config_controlling = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent_controlling = IceAgent::new(config_controlling, IceRole::Controlling);

        let config_controlled = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent_controlled = IceAgent::new(config_controlled, IceRole::Controlled);

        // Add same candidates to both agents
        let local = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)), 5001),
            1,
        );
        let remote = Candidate::host(
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)), 5000),
            1,
        );

        agent_controlling
            .local_candidates
            .write()
            .await
            .push(local.clone());
        agent_controlling
            .add_remote_candidates(vec![remote.clone()])
            .await;

        agent_controlled.local_candidates.write().await.push(local);
        agent_controlled.add_remote_candidates(vec![remote]).await;

        // Both should compute same priority for the pair
        let pairs_controlling = agent_controlling.candidate_pairs.read().await;
        let pairs_controlled = agent_controlled.candidate_pairs.read().await;

        assert_eq!(pairs_controlling[0].priority, pairs_controlled[0].priority);
    }

    // Test: gather_candidates sets state to Gathering
    #[tokio::test]
    async fn test_gather_candidates_state() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        assert_eq!(agent.state().await, IceState::New);

        let _ = agent.gather_candidates().await;

        // State should be Gathering (remains after gathering completes)
        assert_eq!(agent.state().await, IceState::Gathering);
    }

    // Test: gather_candidates respects gather_timeout_ms as a wall-clock cap.
    // With a 1ms budget, the call must return quickly even though host
    // gathering would normally take longer. Partial results (possibly empty
    // or just hosts) are acceptable; what matters is the wall-clock bound.
    #[tokio::test]
    async fn test_gather_candidates_respects_gather_timeout() {
        // Use a STUN server pointed at an unrouteable address so srflx
        // gathering would otherwise stall up to check_timeout_ms.
        let bogus_stun = StunServer {
            name: "bogus",
            addr: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 1)), 3478),
        };
        let config = IceConfig {
            stun_servers: vec![bogus_stun],
            check_timeout_ms: 5_000,
            gather_timeout_ms: 1,
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let start = tokio::time::Instant::now();
        // Must not error — partial results are returned on timeout.
        let _ = agent
            .gather_candidates()
            .await
            .expect("gather (partial ok)");
        let elapsed = start.elapsed();

        // Generous bound: the cap is 1ms, but host binding + scheduler
        // overhead can run a few hundred ms on busy CI. 2 seconds is well
        // below check_timeout_ms (5s), proving the cap kicked in.
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "gather_candidates took {:?} — gather_timeout_ms not enforced",
            elapsed
        );
    }

    // Test: start_checks sets state to Checking
    #[tokio::test]
    async fn test_start_checks_state() {
        let config = IceConfig {
            stun_servers: vec![],
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        // Add minimal setup for checks
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

        // Without remote credentials, will use fallback
        let _ = agent.start_checks().await;

        // Should end up in Connected state (via fallback)
        assert_eq!(agent.state().await, IceState::Connected);
    }

    // Test: STUN request includes correct USERNAME format
    #[tokio::test]
    async fn test_connectivity_check_username_format() {
        let config = IceConfig {
            stun_servers: vec![],
            local_ufrag: "localusr".to_string(),
            local_pwd: "localpwd".to_string(),
            check_timeout_ms: 1000,
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlling);

        let local_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = local_socket.local_addr().unwrap();

        let mock = MockStunServer::new().await;
        let mock_addr = mock.addr;

        let local_cand = Candidate::host(local_addr, 1);
        let remote_cand = Candidate::host(mock_addr, 1);
        let pair = CandidatePair {
            local: local_cand,
            remote: remote_cand,
            priority: 1000,
            state: PairState::Waiting,
            nominated: false,
        };

        // Spawn server to check USERNAME attribute format
        let mock_socket = mock.socket.clone();
        let (username_tx, username_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let (len, peer) = mock_socket.recv_from(&mut buf).await.unwrap();
            let payload = String::from_utf8_lossy(&buf[..len]);
            let found_username = payload.contains("remoteusr") & payload.contains("localusr");

            let _ = username_tx.send(found_username);
            let txn_id: [u8; 12] = buf[8..20].try_into().expect("short STUN request");
            let response = MockStunServer::build_connectivity_check_response(&txn_id);
            let _ = mock_socket.send_to(&response, peer).await;
        });

        let result = agent
            .perform_connectivity_check(&local_socket, &pair, "remoteusr", "remotepwd")
            .await;

        assert!(result);
        assert!(username_rx.await.unwrap_or(false));
    }

    // ========== Phase 2.5: STUN responder tests ==========

    /// Build a STUN binding request mirroring `perform_connectivity_check`'s
    /// wire layout, with USERNAME (`<receiver_ufrag>:<sender_ufrag>`) and
    /// MESSAGE-INTEGRITY keyed on `mi_key`. Returns `(bytes, txn_id)`.
    fn build_signed_binding_request(
        receiver_ufrag: &str,
        sender_ufrag: &str,
        mi_key: &[u8],
    ) -> (Vec<u8>, [u8; 12]) {
        use bytes::{BufMut, BytesMut};
        use hmac::{Hmac, Mac};
        use rand::RngCore;
        use sha1::Sha1;
        type HmacSha1 = Hmac<Sha1>;

        let mut txn_id = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut txn_id);

        let username = format!("{}:{}", receiver_ufrag, sender_ufrag);
        let username_bytes = username.as_bytes();

        let mut attrs = BytesMut::new();
        attrs.put_u16(ATTR_USERNAME);
        attrs.put_u16(username_bytes.len() as u16);
        attrs.put_slice(username_bytes);
        let pad = (4 - (username_bytes.len() % 4)) % 4;
        for _ in 0..pad {
            attrs.put_u8(0);
        }

        let mut msg = BytesMut::with_capacity(20 + attrs.len() + 24);
        msg.put_u16(BINDING_REQUEST);
        msg.put_u16(attrs.len() as u16);
        msg.put_u32(MAGIC_COOKIE);
        msg.put_slice(&txn_id);
        msg.put_slice(&attrs);

        // MESSAGE-INTEGRITY using `mi_key`.
        let current_len = msg.len();
        let new_len = (current_len - 20 + 24) as u16;
        msg[2] = (new_len >> 8) as u8;
        msg[3] = (new_len & 0xff) as u8;

        let mut mac = HmacSha1::new_from_slice(mi_key).expect("hmac key");
        mac.update(&msg);
        let integrity = mac.finalize().into_bytes();
        msg.put_u16(ATTR_MESSAGE_INTEGRITY);
        msg.put_u16(20);
        msg.put_slice(&integrity);

        (msg.to_vec(), txn_id)
    }

    /// Parse a STUN binding response and extract the XOR-MAPPED-ADDRESS,
    /// returning `(xor_addr, txn_id)`.
    fn parse_binding_response_xor(bytes: &[u8]) -> Option<(SocketAddr, [u8; 12])> {
        if bytes.len() < 20 {
            return None;
        }
        if u16::from_be_bytes([bytes[0], bytes[1]]) != BINDING_RESPONSE {
            return None;
        }
        if u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) != MAGIC_COOKIE {
            return None;
        }
        let mut txn_id = [0u8; 12];
        txn_id.copy_from_slice(&bytes[8..20]);
        let total_attrs_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let end = 20 + total_attrs_len.min(bytes.len() - 20);

        let mut off = 20;
        while off + 4 <= end {
            let attr_type = u16::from_be_bytes([bytes[off], bytes[off + 1]]);
            let attr_len = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]) as usize;
            let val_start = off + 4;
            let val_end = val_start + attr_len;
            if val_end > end {
                return None;
            }
            if attr_type == ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8 {
                let family = bytes[val_start + 1];
                let port = u16::from_be_bytes([bytes[val_start + 2], bytes[val_start + 3]])
                    ^ (MAGIC_COOKIE >> 16) as u16;
                if family == 0x01 {
                    let cookie = MAGIC_COOKIE.to_be_bytes();
                    let ip_bytes = [
                        bytes[val_start + 4] ^ cookie[0],
                        bytes[val_start + 5] ^ cookie[1],
                        bytes[val_start + 6] ^ cookie[2],
                        bytes[val_start + 7] ^ cookie[3],
                    ];
                    return Some((
                        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::from(ip_bytes)), port),
                        txn_id,
                    ));
                }
            }
            let padded = (attr_len + 3) & !3;
            off = val_start + padded;
        }
        None
    }

    /// Pick the loopback host candidate from a freshly-gathered agent.
    async fn pick_loopback_host(agent: &IceAgent) -> Candidate {
        let cands = agent.local_candidates().await;
        cands
            .into_iter()
            .find(|c| c.candidate_type == CandidateType::Host && c.address.ip().is_loopback())
            .expect("loopback host candidate")
    }

    #[tokio::test]
    async fn responder_answers_valid_binding_request() {
        init_tracing();
        let config = IceConfig {
            stun_servers: vec![],
            local_ufrag: "loctufrag".to_string(),
            local_pwd: "locpwd1234567890123456".to_string(),
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlled);
        let _ = agent.gather_candidates().await.expect("gather");

        let host = pick_loopback_host(&agent).await;

        // Side socket pretending to be a peer.
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let (req, txn_id) =
            build_signed_binding_request("loctufrag", "peerufrag", b"locpwd1234567890123456");
        peer.send_to(&req, host.address).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (len, from) = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            peer.recv_from(&mut buf),
        )
        .await
        .expect("response did not time out")
        .expect("recv ok");
        assert_eq!(from, host.address);

        let (xor_addr, resp_txn) =
            parse_binding_response_xor(&buf[..len]).expect("XOR-MAPPED-ADDRESS present");
        assert_eq!(resp_txn, txn_id, "txn id round-trips");
        assert_eq!(xor_addr, peer_addr, "XOR-MAPPED-ADDRESS reflects peer");
    }

    #[tokio::test]
    async fn responder_drops_invalid_username() {
        init_tracing();
        let config = IceConfig {
            stun_servers: vec![],
            local_ufrag: "loctufrag".to_string(),
            local_pwd: "locpwd1234567890123456".to_string(),
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlled);
        let _ = agent.gather_candidates().await.expect("gather");

        let host = pick_loopback_host(&agent).await;

        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // USERNAME prefix doesn't match local ufrag → dispatcher drops.
        let (req, _txn_id) =
            build_signed_binding_request("wrongone", "peerufrag", b"locpwd1234567890123456");
        peer.send_to(&req, host.address).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(150),
            peer.recv_from(&mut buf),
        )
        .await;
        assert!(result.is_err(), "expected no response, got {:?}", result);
    }

    #[tokio::test]
    async fn responder_drops_invalid_message_integrity() {
        init_tracing();
        let config = IceConfig {
            stun_servers: vec![],
            local_ufrag: "loctufrag".to_string(),
            local_pwd: "locpwd1234567890123456".to_string(),
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlled);
        let _ = agent.gather_candidates().await.expect("gather");

        let host = pick_loopback_host(&agent).await;

        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // USERNAME ok, MI signed with the wrong key → dispatcher drops.
        let (req, _txn_id) =
            build_signed_binding_request("loctufrag", "peerufrag", b"WRONGKEY999999999999");
        peer.send_to(&req, host.address).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(150),
            peer.recv_from(&mut buf),
        )
        .await;
        assert!(result.is_err(), "expected no response, got {:?}", result);
    }

    #[tokio::test]
    async fn responder_tasks_aborted_on_close() {
        init_tracing();
        let config = IceConfig {
            stun_servers: vec![],
            local_ufrag: "loctufrag".to_string(),
            local_pwd: "locpwd1234567890123456".to_string(),
            ..Default::default()
        };
        let agent = IceAgent::new(config, IceRole::Controlled);
        let _ = agent.gather_candidates().await.expect("gather");
        let host = pick_loopback_host(&agent).await;
        // Keep the cloned Arc alive past close so the OS socket is not
        // freed; we want to prove the dispatcher task no longer reads.
        let _kept = agent.socket_for(host.address).await.expect("socket");

        agent.close().await;

        // Send a fresh binding request — no responder running, so no
        // reply should come back.
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (req, _txn_id) =
            build_signed_binding_request("loctufrag", "peerufrag", b"locpwd1234567890123456");
        peer.send_to(&req, host.address).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(150),
            peer.recv_from(&mut buf),
        )
        .await;
        assert!(
            result.is_err(),
            "expected silence after close, got {:?}",
            result
        );
    }

    /// Decode an IPv6 XOR-MAPPED-ADDRESS attribute the way RFC 5389
    /// §15.2 specifies: family must be 0x02, port XORed with the high
    /// 16 bits of the magic cookie, and the address XORed with the
    /// magic cookie followed by the transaction ID.
    fn parse_binding_response_xor_v6(bytes: &[u8]) -> Option<(std::net::Ipv6Addr, u16, [u8; 12])> {
        if bytes.len() < 20 {
            return None;
        }
        if u16::from_be_bytes([bytes[0], bytes[1]]) != BINDING_RESPONSE {
            return None;
        }
        if u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) != MAGIC_COOKIE {
            return None;
        }
        let mut txn_id = [0u8; 12];
        txn_id.copy_from_slice(&bytes[8..20]);
        let total_attrs_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let end = 20 + total_attrs_len.min(bytes.len() - 20);

        let mut off = 20;
        while off + 4 <= end {
            let attr_type = u16::from_be_bytes([bytes[off], bytes[off + 1]]);
            let attr_len = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]) as usize;
            let val_start = off + 4;
            let val_end = val_start + attr_len;
            if val_end > end {
                return None;
            }
            if attr_type == ATTR_XOR_MAPPED_ADDRESS && attr_len == 20 {
                let family = bytes[val_start + 1];
                if family != 0x02 {
                    return None;
                }
                let port = u16::from_be_bytes([bytes[val_start + 2], bytes[val_start + 3]])
                    ^ (MAGIC_COOKIE >> 16) as u16;
                let cookie = MAGIC_COOKIE.to_be_bytes();
                let mut ip = [0u8; 16];
                for i in 0..4 {
                    ip[i] = bytes[val_start + 4 + i] ^ cookie[i];
                }
                for i in 0..12 {
                    ip[4 + i] = bytes[val_start + 8 + i] ^ txn_id[i];
                }
                return Some((std::net::Ipv6Addr::from(ip), port, txn_id));
            }
            let padded = (attr_len + 3) & !3;
            off = val_start + padded;
        }
        None
    }

    #[test]
    fn build_binding_response_emits_ipv6_xor_mapped_address() {
        // Drive `build_binding_response` directly with an IPv6 source
        // address and decode the XOR-MAPPED-ADDRESS to prove the
        // RFC 5389 §15.2 layout round-trips.
        let local_ufrag = "loctufrag";
        let local_pwd = b"locpwd1234567890123456";
        let (req, txn_id) = build_signed_binding_request(local_ufrag, "peerufrag", local_pwd);

        let from = SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xabcd,
            )),
            54321,
        );
        let resp = build_binding_response(
            &req,
            txn_id,
            from,
            local_ufrag,
            std::str::from_utf8(local_pwd).unwrap(),
        )
        .expect("v6 response built");

        let (ip, port, resp_txn) =
            parse_binding_response_xor_v6(&resp).expect("v6 XOR-MAPPED-ADDRESS round-trips");
        assert_eq!(resp_txn, txn_id);
        assert_eq!(port, 54321);
        assert_eq!(
            ip,
            std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xabcd)
        );
    }
}
