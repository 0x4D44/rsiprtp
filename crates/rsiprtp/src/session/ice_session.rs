//! Async ICE helper that lives next to `CallManager`.
//!
//! `CallManager` is Sans-IO and owns no sockets. ICE needs to bind sockets
//! and run STUN exchanges, so it sits beside the manager rather than
//! inside it. The application drives both in parallel: gather candidates,
//! send the offer, run checks once the answer arrives, then hand the
//! winning socket to the RTP loop.

use crate::ice::{
    Candidate, CandidateType, IceAgent, IceConfig, IceError, IceRole, PairState, StunServer,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Local ICE parameters: credentials and gathered candidates.
#[derive(Debug, Clone)]
pub struct IceLocalParams {
    /// Local username fragment (`a=ice-ufrag`).
    pub ufrag: String,
    /// Local password (`a=ice-pwd`).
    pub pwd: String,
    /// Gathered local candidates.
    pub candidates: Vec<Candidate>,
}

/// Remote ICE parameters parsed from the peer's SDP.
#[derive(Debug, Clone)]
pub struct IceRemoteParams {
    /// Remote username fragment.
    pub ufrag: String,
    /// Remote password.
    pub pwd: String,
    /// Remote candidates.
    pub candidates: Vec<Candidate>,
}

/// Single-component (RTP only, rtcp-mux required) ICE session driven by
/// the application alongside `CallManager`.
pub struct IceSession {
    agent: IceAgent,
    local: IceLocalParams,
    socket: Option<Arc<UdpSocket>>,
    peer: Option<SocketAddr>,
}

impl IceSession {
    /// Create a session and gather host + srflx candidates.
    ///
    /// Pass an empty `stun_servers` for host-only gathering (no network
    /// I/O beyond local interface enumeration). `gather_timeout` bounds
    /// the whole gather phase; partial results are kept on timeout.
    /// `check_timeout` bounds each individual STUN connectivity check
    /// during `run_checks` (per-pair, applied sequentially).
    pub async fn gather(
        role: IceRole,
        stun_servers: Vec<StunServer>,
        gather_timeout: Duration,
        check_timeout: Duration,
    ) -> Result<Self, IceError> {
        let config = IceConfig {
            stun_servers,
            gather_timeout_ms: gather_timeout.as_millis() as u64,
            check_timeout_ms: check_timeout.as_millis() as u64,
            ..Default::default()
        };
        let (ufrag, pwd) = (config.local_ufrag.clone(), config.local_pwd.clone());

        let agent = IceAgent::new(config, role);
        let candidates = agent.gather_candidates().await?;

        Ok(Self {
            agent,
            local: IceLocalParams {
                ufrag,
                pwd,
                candidates,
            },
            socket: None,
            peer: None,
        })
    }

    /// Local credentials and candidates to advertise in our SDP.
    pub fn local(&self) -> &IceLocalParams {
        &self.local
    }

    /// Default candidate for the SDP `c=` line and `m=` port.
    ///
    /// Selection policy (RFC 8839 §4.2.1: `c=`/`m=` should be reachable
    /// for non-ICE peers):
    /// 1. First non-loopback host candidate (externally reachable).
    /// 2. First host candidate of any kind (loopback fallback — useful
    ///    for local testing).
    /// 3. First local candidate of any type.
    /// 4. `None` only if we have no local candidates at all.
    pub fn default_candidate(&self) -> Option<&Candidate> {
        let hosts = || {
            self.local
                .candidates
                .iter()
                .filter(|c| c.candidate_type == CandidateType::Host)
        };

        hosts()
            .find(|c| !c.address.ip().is_loopback())
            .or_else(|| hosts().next())
            .or_else(|| self.local.candidates.first())
    }

    /// Apply the peer's credentials and candidates, run connectivity
    /// checks, and stash the winning socket and peer address.
    ///
    /// Returns the selected peer `SocketAddr` on success.
    ///
    /// This call enforces a *validated* candidate pair: the underlying
    /// `IceAgent` may fall back to picking an unchecked host-host pair
    /// when no STUN check has been completed (best-effort behaviour for
    /// other consumers); `IceSession` rejects that fallback and surfaces
    /// it as `IceError::Failed`. Call sites that need RTP must have a
    /// pair that genuinely passed a connectivity check.
    ///
    /// Call once per `IceSession`. Calling again after success has
    /// undefined behaviour: the underlying agent's pair list is not
    /// reset.
    ///
    /// On success, the agent's STUN responders stop reading from the
    /// bound sockets; the caller takes ownership of the selected
    /// socket for RTP via [`rtp_socket`](Self::rtp_socket). ICE
    /// consent-freshness keepalives (RFC 7675) are out of scope (see
    /// HLD).
    ///
    /// Symmetric-NAT peer-reflexive (prflx) candidate discovery is also
    /// out of scope: the HLD calls for a thin ICE that handles host +
    /// srflx pairs only. A symmetric-NAT peer would need a relay (TURN)
    /// to traverse, which is not wired in for Phase 2.5.
    pub async fn run_checks(&mut self, remote: IceRemoteParams) -> Result<SocketAddr, IceError> {
        self.agent
            .set_remote_credentials(&remote.ufrag, &remote.pwd)
            .await;
        self.agent.add_remote_candidates(remote.candidates).await;
        self.agent.start_checks().await?;

        let pair = self
            .agent
            .selected_pair()
            .await
            .ok_or_else(|| IceError::Failed("no nominated pair".to_string()))?;

        // Reject the agent's fallback pick: a `Frozen`/`Waiting`/`Failed`
        // selected pair means no STUN check actually validated it. Only
        // `Succeeded` proves the path works.
        if pair.state != PairState::Succeeded {
            return Err(IceError::Failed(
                "no validated candidate pair (all connectivity checks failed)".to_string(),
            ));
        }

        let local_addr = pair.local.related_address.unwrap_or(pair.local.address);
        let socket = self.agent.socket_for(local_addr).await.ok_or_else(|| {
            IceError::Failed(format!("no socket for selected local {}", local_addr))
        })?;

        // R3: hand the bound socket back cleanly. The dispatcher tasks
        // would otherwise keep draining it and steal RTP. Sockets stay
        // bound; only the responder loops stop. (Symmetric-NAT prflx
        // is out of scope per HLD — covered above.)
        self.agent.stop_responders().await;

        let peer = pair.remote.address;
        self.socket = Some(socket);
        self.peer = Some(peer);
        Ok(peer)
    }

    /// Socket the application should use for RTP after `run_checks`.
    pub fn rtp_socket(&self) -> Option<Arc<UdpSocket>> {
        self.socket.clone()
    }

    /// Peer address the application should send RTP to.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Release the agent's sockets. Cloned `rtp_socket()` Arcs remain
    /// valid for the caller after `close`.
    pub async fn close(self) {
        self.agent.close().await;
    }
}

#[cfg(test)]
impl IceSession {
    /// Build an `IceSession` from hand-rolled local params, without
    /// actually gathering. Test-only seam for deterministic
    /// `default_candidate` tests; do not call from production code.
    /// Already gated on `#[cfg(test)]`, so this is just clarification
    /// for readers — the symbol is not part of the crate API.
    fn from_local_for_test(role: IceRole, local: IceLocalParams) -> Self {
        let config = IceConfig {
            stun_servers: vec![],
            local_ufrag: local.ufrag.clone(),
            local_pwd: local.pwd.clone(),
            ..Default::default()
        };
        Self {
            agent: IceAgent::new(config, role),
            local,
            socket: None,
            peer: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ice::Transport;
    use std::net::{IpAddr, Ipv4Addr};

    fn short_timeout() -> Duration {
        Duration::from_millis(500)
    }

    fn host_candidate(ip: Ipv4Addr, port: u16) -> Candidate {
        Candidate::host(SocketAddr::new(IpAddr::V4(ip), port), 1)
    }

    #[tokio::test]
    async fn gather_host_only_returns_at_least_one_host() {
        let session = IceSession::gather(
            IceRole::Controlling,
            vec![],
            short_timeout(),
            short_timeout(),
        )
        .await
        .expect("gather succeeds with no STUN servers");

        assert!(
            session
                .local()
                .candidates
                .iter()
                .any(|c| c.candidate_type == CandidateType::Host),
            "expected at least one host candidate from local interfaces"
        );
        assert!(!session.local().ufrag.is_empty());
        assert!(!session.local().pwd.is_empty());
    }

    #[tokio::test]
    async fn default_candidate_prefers_non_loopback_host() {
        // Hand-roll local params with one loopback and one non-loopback
        // host (TEST-NET-1 192.0.2.0/24 is reserved for documentation
        // examples, RFC 5737 — never reachable).
        let loopback = host_candidate(Ipv4Addr::new(127, 0, 0, 1), 12345);
        let routable = host_candidate(Ipv4Addr::new(192, 0, 2, 1), 12345);

        // Insert loopback first so position-based selection would have
        // picked it; the non-loopback preference must override that.
        let local = IceLocalParams {
            ufrag: "ufragxxxx".to_string(),
            pwd: "pwdpwdpwdpwdpwdpwdpwdpwd".to_string(),
            candidates: vec![loopback, routable.clone()],
        };

        let session = IceSession::from_local_for_test(IceRole::Controlling, local);

        let chosen = session.default_candidate().expect("at least one candidate");
        assert_eq!(chosen.address, routable.address);
        assert!(!chosen.address.ip().is_loopback());
    }

    #[tokio::test]
    async fn default_candidate_falls_back_to_loopback_only() {
        // Loopback-only set (e.g. test sandbox with no external NIC) —
        // still return *some* host candidate rather than `None`.
        let loopback = host_candidate(Ipv4Addr::new(127, 0, 0, 1), 12345);
        let local = IceLocalParams {
            ufrag: "ufragxxxx".to_string(),
            pwd: "pwdpwdpwdpwdpwdpwdpwdpwd".to_string(),
            candidates: vec![loopback.clone()],
        };

        let session = IceSession::from_local_for_test(IceRole::Controlling, local);

        let chosen = session.default_candidate().expect("loopback fallback");
        assert_eq!(chosen.address, loopback.address);
        assert!(chosen.address.ip().is_loopback());
    }

    /// Gather two `IceSession`s on loopback, exchange their local
    /// params, and run real connectivity checks against each other.
    /// Returns the two sessions after both `run_checks` calls have
    /// returned `Ok`.
    async fn validated_session_pair() -> (IceSession, IceSession) {
        let mut a = IceSession::gather(
            IceRole::Controlling,
            vec![],
            short_timeout(),
            short_timeout(),
        )
        .await
        .expect("gather A");
        let mut b = IceSession::gather(
            IceRole::Controlled,
            vec![],
            short_timeout(),
            short_timeout(),
        )
        .await
        .expect("gather B");

        let local_a = a.local().clone();
        let local_b = b.local().clone();

        let remote_for_a = IceRemoteParams {
            ufrag: local_b.ufrag.clone(),
            pwd: local_b.pwd.clone(),
            candidates: local_b.candidates.clone(),
        };
        let remote_for_b = IceRemoteParams {
            ufrag: local_a.ufrag.clone(),
            pwd: local_a.pwd.clone(),
            candidates: local_a.candidates.clone(),
        };

        // Run both check loops concurrently — each one's check is the
        // oracle for the other's responder.
        let (peer_a, peer_b) = tokio::join!(a.run_checks(remote_for_a), b.run_checks(remote_for_b));
        peer_a.expect("A run_checks ok");
        peer_b.expect("B run_checks ok");
        (a, b)
    }

    #[tokio::test]
    async fn rtp_socket_and_peer_addr_carry_real_traffic() {
        // R3: prove that the `Arc<UdpSocket>` from `rtp_socket()` and
        // the address from `peer_addr()` actually carry packets to the
        // peer. Drives two real `IceSession`s on loopback through real
        // STUN connectivity checks (the agent's responder answers).
        //
        // The probe goes through the live, post-validation socket —
        // no `close()` call here. `run_checks` is required to stop the
        // dispatchers internally so the caller's RTP traffic isn't
        // stolen by the STUN responder loop.
        let (a, b) = validated_session_pair().await;

        let socket_a = a.rtp_socket().expect("A has a socket after validation");
        let socket_b = b.rtp_socket().expect("B has a socket after validation");
        let peer_a = a.peer_addr().expect("A has a peer after validation");
        let peer_b = b.peer_addr().expect("B has a peer after validation");
        assert_eq!(peer_a, socket_b.local_addr().unwrap());
        assert_eq!(peer_b, socket_a.local_addr().unwrap());

        let probe = b"ping";
        socket_a
            .send_to(probe, peer_a)
            .await
            .expect("send probe A->B");

        let mut buf = [0u8; 64];
        let (n, _from) =
            tokio::time::timeout(Duration::from_millis(500), socket_b.recv_from(&mut buf))
                .await
                .expect("recv on B did not time out")
                .expect("recv on B ok");
        assert_eq!(&buf[..n], probe, "probe bytes match");
    }

    #[tokio::test]
    async fn close_keeps_cloned_socket_alive() {
        // S1: cloned `rtp_socket()` Arcs must outlive the session.
        let (a, b) = validated_session_pair().await;

        let socket_a = a.rtp_socket().unwrap();
        let socket_b = b.rtp_socket().unwrap();
        let peer_a = a.peer_addr().unwrap();

        // Drop both sessions — only the cloned Arcs keep the sockets
        // alive. Closing also shuts down the dispatcher that would
        // otherwise drain the socket out from under the test.
        a.close().await;
        b.close().await;

        socket_a
            .send_to(b"after-close", peer_a)
            .await
            .expect("retained socket still sends after close");

        let mut buf = [0u8; 64];
        let (n, _from) =
            tokio::time::timeout(Duration::from_millis(500), socket_b.recv_from(&mut buf))
                .await
                .expect("recv on retained B did not time out")
                .expect("recv on retained B ok");
        assert_eq!(&buf[..n], b"after-close");
    }

    #[tokio::test]
    async fn run_checks_fails_when_all_checks_time_out() {
        // Pairs DO form (UDP transport, well-formed addresses) — but
        // the remote candidate points at TEST-NET-3 (RFC 5737), which
        // is reserved for documentation and unreachable. The agent's
        // STUN check will time out, no pair reaches `Succeeded`, and
        // the agent's fallback would normally pick the unchecked
        // host-host pair. `IceSession::run_checks` must reject that
        // fallback as "not validated".
        let check_timeout = Duration::from_millis(200);
        let mut session =
            IceSession::gather(IceRole::Controlling, vec![], short_timeout(), check_timeout)
                .await
                .unwrap();

        let bogus = Candidate {
            foundation: "bogus1".to_string(),
            component: 1,
            transport: Transport::Udp,
            priority: 1,
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)), 54321),
            candidate_type: CandidateType::Host,
            related_address: None,
        };

        let res = session
            .run_checks(IceRemoteParams {
                ufrag: "remoteufrag".to_string(),
                pwd: "remotepasswordverysecure".to_string(),
                candidates: vec![bogus],
            })
            .await;

        let err = res.expect_err("expected run_checks to fail when no pair validates");
        let msg = format!("{}", err);
        assert!(
            msg.contains("validated") || msg.contains("checks failed"),
            "expected error to mention validation failure, got: {}",
            msg
        );
        assert!(session.rtp_socket().is_none());
        assert!(session.peer_addr().is_none());
    }
}
