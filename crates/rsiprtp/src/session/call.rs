//! Call abstraction.
//!
//! A Call represents a single SIP call session including signaling and media.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::core::random_u32;
use crate::dialog::DialogId;
use crate::media::{Bitrate, JitterBuffer, JitterBufferConfig, OpusConfig, PlayoutDecision};
use crate::rtp::rtcp::{RtcpCompound, RtcpPacket};
use crate::rtp::session::CongestionController;
use crate::rtp::{RtpPacket, RtpSession};
use crate::sdp::negotiation::{Codec, NegotiatedMedia};
use crate::sdp::parser::SessionDescription;

use crate::session::bitrate_bridge::BitrateBridge;
use crate::session::session_codec::SessionCodec;

/// Simplified dialog info for call tracking.
///
/// This is a lightweight representation used by the session layer to track
/// which SIP dialog a call belongs to, without containing the full dialog
/// state machine (which is managed by the dialog layer).
#[derive(Debug, Clone)]
pub struct Dialog {
    /// Dialog identifier.
    id: DialogId,
    /// Local URI.
    local_uri: String,
    /// Remote URI.
    remote_uri: String,
    /// Local CSeq.
    local_cseq: u32,
}

impl Dialog {
    /// Create a new dialog for a UAC (caller).
    pub fn new_uac(
        call_id: String,
        from_tag: String,
        to_tag: String,
        local_uri: String,
        remote_uri: String,
        cseq: u32,
    ) -> Self {
        Self {
            id: DialogId::new(&call_id, &from_tag, &to_tag),
            local_uri,
            remote_uri,
            local_cseq: cseq,
        }
    }

    /// Create a new dialog for a UAS (callee).
    pub fn new_uas(
        call_id: String,
        from_tag: String,
        to_tag: String,
        local_uri: String,
        remote_uri: String,
        cseq: u32,
    ) -> Self {
        // For UAS, from/to tags are swapped in the DialogId
        Self {
            id: DialogId::new(&call_id, &to_tag, &from_tag),
            local_uri,
            remote_uri,
            local_cseq: cseq,
        }
    }

    /// Get the dialog ID.
    pub fn id(&self) -> &DialogId {
        &self.id
    }

    /// Get the local URI.
    pub fn local_uri(&self) -> &str {
        &self.local_uri
    }

    /// Get the remote URI.
    pub fn remote_uri(&self) -> &str {
        &self.remote_uri
    }

    /// Get the local CSeq.
    pub fn local_cseq(&self) -> u32 {
        self.local_cseq
    }

    /// Increment and return the next CSeq.
    pub fn next_cseq(&mut self) -> u32 {
        self.local_cseq += 1;
        self.local_cseq
    }
}

/// Call state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// Initial state before any signaling.
    Idle,
    /// INVITE sent, waiting for response.
    Inviting,
    /// 18x received, ringing.
    Ringing,
    /// Early media established (18x with SDP).
    EarlyMedia,
    /// 200 OK received, call established.
    Established,
    /// BYE sent or received, terminating.
    Terminating,
    /// Call ended.
    Terminated,
}

/// Direction of the call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallDirection {
    /// We originated the call (UAC).
    Outbound,
    /// We received the call (UAS).
    Inbound,
}

/// Call configuration.
#[derive(Debug, Clone)]
pub struct CallConfig {
    /// Local SIP URI (sip:user@host).
    pub local_uri: String,
    /// Local display name.
    pub local_name: Option<String>,
    /// Supported codecs.
    pub codecs: Vec<Codec>,
    /// RTP port range start.
    pub rtp_port_start: u16,
    /// RTP port range end.
    pub rtp_port_end: u16,
}

impl Default for CallConfig {
    fn default() -> Self {
        Self {
            local_uri: "sip:user@127.0.0.1".to_string(),
            local_name: None,
            codecs: vec![Codec::pcmu(), Codec::pcma()],
            rtp_port_start: 10000,
            rtp_port_end: 20000,
        }
    }
}

/// Events emitted by a call.
#[derive(Debug, Clone)]
pub enum CallEvent {
    /// Call state changed.
    StateChanged(CallState),
    /// Remote is ringing.
    Ringing,
    /// Early media available.
    EarlyMedia,
    /// Call answered and media ready.
    Answered,
    /// Call ended.
    Ended(CallEndReason),
    /// Audio samples received.
    AudioReceived(Vec<i16>),
    /// DTMF digit received.
    DtmfReceived(char),
}

/// Reason for call ending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallEndReason {
    /// Normal hangup.
    NormalClearing,
    /// Remote rejected.
    Rejected,
    /// Remote busy.
    Busy,
    /// No answer timeout.
    NoAnswer,
    /// Network error.
    NetworkError,
    /// Call canceled.
    Canceled,
    /// Other error.
    Error,
}

/// Call identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallId(pub String);

impl CallId {
    /// Create a new unique call ID.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl Default for CallId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for CallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Internal pairing of a `CongestionController` with the
/// `BitrateBridge` that drives an adaptive codec from its target.
///
/// Constructed only for codec variants that actually adapt their
/// encoder rate at runtime (today: Opus). G.711 / G.722 sessions
/// leave `MediaSession::adaptive` as `None` — RTCP is still parsed
/// for them but no adaptation runs.
struct AdaptiveCongestion {
    /// Congestion controller (initial / min / max bps).
    cc: CongestionController,
    /// Hysteresis filter feeding the codec.
    bridge: BitrateBridge,
}

impl std::fmt::Debug for AdaptiveCongestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdaptiveCongestion")
            .field("target_bitrate", &self.cc.target_bitrate())
            .finish()
    }
}

/// Media session for a call.
pub struct MediaSession {
    /// RTP session for sending/receiving.
    rtp_session: RtpSession,
    /// Jitter buffer for received audio.
    jitter_buffer: JitterBuffer,
    /// Audio codec selected during SDP negotiation.
    codec: SessionCodec,
    /// Adaptive congestion + bridge pair, present only for adaptive codecs.
    adaptive: Option<AdaptiveCongestion>,
    /// Remote RTP address.
    remote_addr: Option<SocketAddr>,
    /// Local RTP port.
    local_port: u16,
    /// Whether media is active.
    active: bool,
}

impl std::fmt::Debug for MediaSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaSession")
            .field("rtp_session", &self.rtp_session)
            .field("jitter_buffer", &self.jitter_buffer)
            .field("adaptive", &self.adaptive)
            .field("remote_addr", &self.remote_addr)
            .field("local_port", &self.local_port)
            .field("active", &self.active)
            .finish()
    }
}

impl MediaSession {
    /// Create a new media session for an SDP-negotiated codec entry.
    ///
    /// For adaptive codecs (Opus today) a `CongestionController` and
    /// `BitrateBridge` are constructed and stored together. Fixed-rate
    /// codecs (G.711 / G.722) get `adaptive = None`; their `handle_rtcp`
    /// and `tick` paths are no-ops apart from parsing.
    ///
    /// Returns `Err` if the codec encoding is unsupported by
    /// [`SessionCodec::for_negotiated`].
    pub fn for_negotiated(ssrc: u32, negotiated: &Codec, local_port: u16) -> Result<Self, String> {
        let mut codec = SessionCodec::for_negotiated(negotiated)?;

        // Adaptive codecs get a CC + bridge sized to the codec's range.
        // Min / max bounds (6 / 128 kbps) are deliberately static — see the
        // bridge HLD's "Risks / open items" entry on per-deployment tuning.
        // The initial bitrate is sourced from the same `OpusConfig` helper
        // `SessionCodec::for_negotiated` uses, so the two stay in lockstep
        // if anyone retunes the codec's starting rate.
        let adaptive = if codec.as_adaptive_mut().is_some() {
            let initial_bps: u64 = match OpusConfig::fullband_speech().bitrate {
                Bitrate::Bits(b) => u64::from(b),
                // `fullband_speech` is currently always `Bits(_)`. Fall back
                // defensively so a future helper change can't panic the path.
                _ => 32_000,
            };
            // SDP-negotiated Opus parameters (clock rate / channels) are
            // currently ignored — the codec is always built at 48 kHz / 1 ch
            // via `OpusConfig::fullband_speech()`. Threading the SDP-derived
            // values into the codec config is a follow-up pinned by the HLD;
            // for now we log when they would have differed so the mismatch
            // is visible in operator output.
            if negotiated.clock_rate != 48_000 || negotiated.channels != 1 {
                tracing::warn!(
                    sdp_clock_rate = negotiated.clock_rate,
                    sdp_channels = negotiated.channels,
                    "SDP-negotiated Opus parameters ignored; codec built at 48 kHz / 1 ch (HLD v1 limitation)"
                );
            }
            Some(AdaptiveCongestion {
                cc: CongestionController::new(initial_bps, 6_000, 128_000),
                bridge: BitrateBridge::new(),
            })
        } else {
            None
        };

        // Match the jitter buffer to the negotiated codec's clock rate
        // and frame size so packet-pacing math stays in step.
        let samples_per_packet = codec.samples_per_frame() as u32;
        let mut jb_config = JitterBufferConfig {
            clock_rate: negotiated.clock_rate,
            samples_per_packet,
            ..JitterBufferConfig::default()
        };
        // Preserve the existing G.711 timing for the 8 kHz / 160-sample
        // path so existing tests and behaviour stay stable.
        if negotiated.clock_rate == 8000 && samples_per_packet == 160 {
            jb_config = JitterBufferConfig::g711();
        }

        Ok(Self {
            rtp_session: RtpSession::new(ssrc, negotiated.payload_type, negotiated.clock_rate),
            jitter_buffer: JitterBuffer::new(jb_config),
            codec,
            adaptive,
            remote_addr: None,
            local_port,
            active: false,
        })
    }

    /// Set the remote RTP address.
    pub fn set_remote(&mut self, addr: SocketAddr) {
        self.remote_addr = Some(addr);
        self.active = true;
    }

    /// Create an RTP packet from PCM samples.
    ///
    /// Returns `Err` if the codec rejects the encode (Opus / G.722).
    /// G.711 is infallible at the codec level; the wrapper preserves
    /// `Result` for a uniform surface.
    pub fn encode_audio(&mut self, samples: &[i16], marker: bool) -> Result<RtpPacket, String> {
        let encoded = self.codec.encode(samples)?;
        Ok(self
            .rtp_session
            .create_packet(encoded, samples.len() as u32, marker))
    }

    /// Process a received RTP packet and get decoded audio.
    pub fn receive_rtp(&mut self, packet: &RtpPacket) -> Option<(PlayoutDecision, Vec<i16>)> {
        // Update RTP session statistics
        self.rtp_session.receive_packet(packet);

        // Decode the audio. A decode failure (corrupt payload, etc.) drops
        // the packet — same fail-open posture as the RTP layer; logged at
        // warn so the operator sees the bad input but the call continues.
        let decoded = match self.codec.decode(&packet.payload) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "codec decode failed; dropping packet");
                return None;
            }
        };

        // Push into jitter buffer
        self.jitter_buffer
            .push(packet.sequence_number, packet.timestamp, decoded);

        // Try to get audio for playout
        if self.jitter_buffer.is_primed() {
            let (decision, samples) = self.jitter_buffer.pop();
            Some((decision, samples))
        } else {
            None
        }
    }

    /// Hand an inbound RTCP compound packet to the session.
    ///
    /// Parses the bytes and routes feedback (currently REMB only) into
    /// the `CongestionController` when the active codec is adaptive.
    /// Errors only on malformed input; unknown / non-actionable RTCP
    /// types are silently ignored per RFC 3550 § 6.1's receiver-leniency
    /// guidance.
    ///
    /// Note: NACK and RTT routing are deferred per HLD § "Risks / open
    /// items" — they each need their own dispatch from RR / SR (loss
    /// fraction; LSR / DLSR for RTT).
    pub fn handle_rtcp(&mut self, bytes: &[u8]) -> Result<(), String> {
        let compound = RtcpCompound::parse(bytes)?;
        let Some(adapt) = self.adaptive.as_mut() else {
            // Fixed-rate codec: no consumer for feedback yet. Parsing
            // still ran — that's the cheap forward-compat for future
            // SR/RR telemetry.
            return Ok(());
        };
        for packet in &compound.packets {
            if let RtcpPacket::Remb(remb) = packet {
                adapt.cc.on_remb(remb.bitrate);
            }
            // SR / RR / NACK / RTT — deferred per HLD; intentionally
            // not routed in v1.
        }
        Ok(())
    }

    /// Periodic tick. Caller invokes ~every 100 ms.
    ///
    /// Drives `CongestionController::update()` and `BitrateBridge::poll()`.
    /// A codec rejection from the bridge is logged at warn and swallowed —
    /// it must not fail the call.
    pub fn tick(&mut self, now: Instant) {
        let Some(adapt) = self.adaptive.as_mut() else {
            return;
        };
        adapt.cc.update();
        let target = adapt.cc.target_bitrate();
        if let Some(adaptive_codec) = self.codec.as_adaptive_mut() {
            if let Err(e) = adapt.bridge.poll(target, adaptive_codec, now) {
                tracing::warn!(error = %e, "BitrateBridge::poll rejected by codec");
            }
        }
    }

    /// Get next frame of audio (call periodically at ptime interval).
    pub fn get_audio_frame(&mut self) -> (PlayoutDecision, Vec<i16>) {
        self.jitter_buffer.pop()
    }

    /// Get the local RTP port.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Get the remote address.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// Check if media is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get RTP session for statistics.
    pub fn rtp_session(&self) -> &RtpSession {
        &self.rtp_session
    }

    /// Get jitter buffer statistics.
    pub fn jitter_stats(&self) -> &crate::media::JitterStats {
        self.jitter_buffer.stats()
    }
}

/// Cached state for an inbound call awaiting a deferred SDP answer.
///
/// Populated by `CallManager::accept_inbound_invite` when codec
/// negotiation succeeds, and consumed by `CallManager::build_answer_for`
/// once the application has finished gathering ICE candidates. We cache
/// **both** the parsed offer and the `NegotiatedMedia` so the answer can
/// be rebuilt with the real ICE port without re-running `create_answer`:
///
/// * `offer` — the original offer SDP. Cloned and patched into the answer
///   skeleton (origin, session-level connection, media slot ordering all
///   come from here). Without it we'd have no `o=`/`s=`/`t=` to rebuild
///   the session frame.
/// * `negotiated` — the result of the single negotiation pass. Used to
///   drive the answer's `m=` formats, rtpmap/fmtp/direction attrs, and
///   to wire the `MediaSession` once the port is known. Without it we'd
///   have to redo offer/answer matching just to reach the same outcome.
///
/// Holding both costs one extra `SessionDescription` clone per inbound
/// ICE call but eliminates a second `create_answer` invocation (which
/// would otherwise allocate a port-zero throwaway answer just to feed
/// `apply_default_candidate`).
#[derive(Debug)]
pub(crate) struct PendingAnswer {
    pub(crate) offer: SessionDescription,
    pub(crate) negotiated: NegotiatedMedia,
}

/// A SIP call.
#[derive(Debug)]
pub struct Call {
    /// Unique call identifier.
    id: CallId,
    /// Call state.
    state: CallState,
    /// Call direction.
    direction: CallDirection,
    /// Configuration.
    config: Arc<CallConfig>,
    /// Remote URI.
    remote_uri: String,
    /// Dialog (once established).
    dialog: Option<Dialog>,
    /// Negotiated media.
    negotiated_media: Option<NegotiatedMedia>,
    /// Media session.
    media: Option<MediaSession>,
    /// Cached offer + negotiated media for the deferred-answer path.
    /// `Some` only on inbound calls created via
    /// `CallManager::accept_inbound_invite`; cleared once
    /// `build_answer_for` consumes it (single-use per call). Invariant:
    /// `media.is_some()` XOR `pending_answer.is_some()` for inbound
    /// calls before the answer is built — they represent two stages of
    /// the same handoff.
    pending_answer: Option<PendingAnswer>,
    /// Pending events.
    events: Vec<CallEvent>,
}

impl Call {
    /// Create a new outbound call.
    pub fn new_outbound(config: Arc<CallConfig>, remote_uri: String) -> Self {
        Self {
            id: CallId::new(),
            state: CallState::Idle,
            direction: CallDirection::Outbound,
            config,
            remote_uri,
            dialog: None,
            negotiated_media: None,
            media: None,
            pending_answer: None,
            events: Vec::new(),
        }
    }

    /// Create a new inbound call.
    pub fn new_inbound(config: Arc<CallConfig>, remote_uri: String, dialog: Dialog) -> Self {
        Self {
            id: CallId::new(),
            state: CallState::Ringing,
            direction: CallDirection::Inbound,
            config,
            remote_uri,
            dialog: Some(dialog),
            negotiated_media: None,
            media: None,
            pending_answer: None,
            events: vec![CallEvent::StateChanged(CallState::Ringing)],
        }
    }

    /// Create a new inbound call with a deferred answer pending.
    ///
    /// Used by `CallManager::accept_inbound_invite`: codec negotiation
    /// has run against the offer, but the SDP answer (and the
    /// `MediaSession`) won't be built until the application's ICE
    /// gather completes and `build_answer_for` runs. The cached state
    /// is consumed via `take_pending_answer`.
    pub(crate) fn new_inbound_pending(
        config: Arc<CallConfig>,
        remote_uri: String,
        dialog: Dialog,
        pending: PendingAnswer,
    ) -> Self {
        Self {
            id: CallId::new(),
            state: CallState::Ringing,
            direction: CallDirection::Inbound,
            config,
            remote_uri,
            dialog: Some(dialog),
            negotiated_media: None,
            media: None,
            pending_answer: Some(pending),
            events: vec![CallEvent::StateChanged(CallState::Ringing)],
        }
    }

    /// Get the call ID.
    pub fn id(&self) -> &CallId {
        &self.id
    }

    /// Get the call state.
    pub fn state(&self) -> CallState {
        self.state
    }

    /// Get the call direction.
    pub fn direction(&self) -> CallDirection {
        self.direction
    }

    /// Get the remote URI.
    pub fn remote_uri(&self) -> &str {
        &self.remote_uri
    }

    /// Get the call configuration.
    pub fn config(&self) -> &CallConfig {
        &self.config
    }

    /// Get the dialog ID (if established).
    pub fn dialog_id(&self) -> Option<&DialogId> {
        self.dialog.as_ref().map(|d| d.id())
    }

    /// Set the dialog for this call.
    pub fn set_dialog(&mut self, dialog: Dialog) {
        self.dialog = Some(dialog);
    }

    /// Set the negotiated media.
    ///
    /// Returns `Err` if the negotiated codec is unsupported by
    /// `MediaSession::for_negotiated`. Caller should surface the error
    /// rather than swallowing — reject the call if no media session can
    /// be built.
    pub fn set_negotiated_media(
        &mut self,
        media: NegotiatedMedia,
        local_port: u16,
    ) -> Result<(), String> {
        // Generate random SSRC
        let ssrc = random_u32();

        let mut session = MediaSession::for_negotiated(ssrc, &media.codec, local_port)?;

        // Set remote address if available
        if let Some(ref addr) = media.remote_addr {
            if let Ok(ip) = addr.parse() {
                session.set_remote(SocketAddr::new(ip, media.remote_port));
            }
        }

        self.negotiated_media = Some(media);
        self.media = Some(session);
        Ok(())
    }

    /// Transition to a new state.
    pub fn set_state(&mut self, state: CallState) {
        if self.state != state {
            self.state = state;
            self.events.push(CallEvent::StateChanged(state));
        }
    }

    /// Handle 18x response (ringing/progress).
    pub fn handle_provisional(&mut self, has_sdp: bool) {
        if has_sdp {
            self.set_state(CallState::EarlyMedia);
            self.events.push(CallEvent::EarlyMedia);
        } else {
            self.set_state(CallState::Ringing);
            self.events.push(CallEvent::Ringing);
        }
    }

    /// Handle 200 OK (call answered).
    pub fn handle_answer(&mut self) {
        self.set_state(CallState::Established);
        self.events.push(CallEvent::Answered);
    }

    /// Handle call ended.
    pub fn handle_ended(&mut self, reason: CallEndReason) {
        self.set_state(CallState::Terminated);
        self.events.push(CallEvent::Ended(reason));
        if let Some(ref mut media) = self.media {
            media.active = false;
        }
    }

    /// Drain pending events.
    pub fn drain_events(&mut self) -> Vec<CallEvent> {
        std::mem::take(&mut self.events)
    }

    /// Get the media session.
    pub fn media(&self) -> Option<&MediaSession> {
        self.media.as_ref()
    }

    /// Get mutable media session.
    pub fn media_mut(&mut self) -> Option<&mut MediaSession> {
        self.media.as_mut()
    }

    /// Get the negotiated codec.
    pub fn codec(&self) -> Option<&Codec> {
        self.negotiated_media.as_ref().map(|m| &m.codec)
    }

    /// Get the dialog.
    pub fn dialog(&self) -> Option<&Dialog> {
        self.dialog.as_ref()
    }

    /// Get mutable dialog.
    pub fn dialog_mut(&mut self) -> Option<&mut Dialog> {
        self.dialog.as_mut()
    }

    /// Check if call is active (established and not terminated).
    pub fn is_active(&self) -> bool {
        self.state == CallState::Established
    }

    /// Check if call can receive media.
    pub fn can_receive_media(&self) -> bool {
        matches!(self.state, CallState::EarlyMedia | CallState::Established)
    }

    /// True if this call was accepted via `accept_inbound_invite` and
    /// is still awaiting `build_answer_for` (or `reject_inbound_invite`).
    pub(crate) fn has_pending_answer(&self) -> bool {
        self.pending_answer.is_some()
    }

    /// Take the cached offer + negotiated media, clearing it from the call.
    /// Single-use: subsequent calls return `None`.
    pub(crate) fn take_pending_answer(&mut self) -> Option<PendingAnswer> {
        self.pending_answer.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_id() {
        let id1 = CallId::new();
        let id2 = CallId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_new_outbound_call() {
        let config = Arc::new(CallConfig::default());
        let call = Call::new_outbound(config, "sip:bob@example.com".to_string());

        assert_eq!(call.state(), CallState::Idle);
        assert_eq!(call.direction(), CallDirection::Outbound);
        assert_eq!(call.remote_uri(), "sip:bob@example.com");
    }

    #[test]
    fn test_call_state_transitions() {
        let config = Arc::new(CallConfig::default());
        let mut call = Call::new_outbound(config, "sip:bob@example.com".to_string());

        call.set_state(CallState::Inviting);
        assert_eq!(call.state(), CallState::Inviting);

        call.handle_provisional(false);
        assert_eq!(call.state(), CallState::Ringing);

        call.handle_answer();
        assert_eq!(call.state(), CallState::Established);
        assert!(call.is_active());

        call.handle_ended(CallEndReason::NormalClearing);
        assert_eq!(call.state(), CallState::Terminated);
        assert!(!call.is_active());
    }

    #[test]
    fn test_call_events() {
        let config = Arc::new(CallConfig::default());
        let mut call = Call::new_outbound(config, "sip:bob@example.com".to_string());

        call.handle_provisional(false);
        call.handle_answer();

        let events = call.drain_events();
        assert!(events.len() >= 2);

        // Events should be drained
        let events2 = call.drain_events();
        assert!(events2.is_empty());
    }

    /// Helper: build a PCMU MediaSession the way the old `MediaSession::new`
    /// did. Used by tests that want a fixed-rate session and don't care
    /// about codec dispatch.
    fn pcmu_session(ssrc: u32, local_port: u16) -> MediaSession {
        MediaSession::for_negotiated(ssrc, &Codec::pcmu(), local_port).expect("PCMU MediaSession")
    }

    #[test]
    fn test_media_session() {
        let mut session = pcmu_session(12345, 5000);

        assert_eq!(session.local_port(), 5000);
        assert!(!session.is_active());

        session.set_remote("10.0.0.1:6000".parse().unwrap());
        assert!(session.is_active());
        assert_eq!(
            session.remote_addr(),
            Some("10.0.0.1:6000".parse().unwrap())
        );
    }

    #[test]
    fn test_media_encode() {
        let mut session = pcmu_session(12345, 5000);

        let samples = vec![0i16; 160];
        let packet = session.encode_audio(&samples, true).expect("PCMU encode");

        assert!(packet.marker);
        assert_eq!(packet.payload_type, 0);
        assert_eq!(packet.ssrc, 12345);
        assert_eq!(packet.payload.len(), 160);
    }

    #[test]
    fn test_set_negotiated_media() {
        let config = Arc::new(CallConfig::default());
        let mut call = Call::new_outbound(config, "sip:bob@example.com".to_string());

        let media = NegotiatedMedia {
            codec: Codec::pcmu(),
            remote_port: 6000,
            remote_addr: Some("10.0.0.1".to_string()),
            direction: crate::sdp::parser::Direction::SendRecv,
        };

        call.set_negotiated_media(media, 5000)
            .expect("PCMU media setup");

        assert!(call.media().is_some());
        assert_eq!(call.codec().map(|c| c.encoding.as_str()), Some("PCMU"));
    }

    // Dialog tests
    #[test]
    fn test_dialog_new_uac() {
        let dialog = Dialog::new_uac(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        assert_eq!(dialog.local_uri(), "sip:alice@example.com");
        assert_eq!(dialog.remote_uri(), "sip:bob@example.com");
        assert_eq!(dialog.local_cseq(), 1);
    }

    #[test]
    fn test_dialog_new_uas() {
        let dialog = Dialog::new_uas(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:bob@example.com".to_string(),
            "sip:alice@example.com".to_string(),
            1,
        );

        assert_eq!(dialog.local_uri(), "sip:bob@example.com");
        assert_eq!(dialog.remote_uri(), "sip:alice@example.com");
        assert_eq!(dialog.local_cseq(), 1);
    }

    #[test]
    fn test_dialog_next_cseq() {
        let mut dialog = Dialog::new_uac(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        assert_eq!(dialog.local_cseq(), 1);
        assert_eq!(dialog.next_cseq(), 2);
        assert_eq!(dialog.next_cseq(), 3);
        assert_eq!(dialog.local_cseq(), 3);
    }

    #[test]
    fn test_dialog_id() {
        let dialog = Dialog::new_uac(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let id = dialog.id();
        // Verify id is valid (compare it with itself - DialogId implements PartialEq)
        assert_eq!(id, id);
    }

    #[test]
    fn test_dialog_clone() {
        let dialog = Dialog::new_uac(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );

        let cloned = dialog.clone();
        assert_eq!(cloned.local_uri(), dialog.local_uri());
        assert_eq!(cloned.remote_uri(), dialog.remote_uri());
    }

    // CallState tests
    #[test]
    fn test_call_state_debug() {
        assert!(format!("{:?}", CallState::Idle).contains("Idle"));
        assert!(format!("{:?}", CallState::Inviting).contains("Inviting"));
        assert!(format!("{:?}", CallState::Ringing).contains("Ringing"));
        assert!(format!("{:?}", CallState::EarlyMedia).contains("EarlyMedia"));
        assert!(format!("{:?}", CallState::Established).contains("Established"));
        assert!(format!("{:?}", CallState::Terminating).contains("Terminating"));
        assert!(format!("{:?}", CallState::Terminated).contains("Terminated"));
    }

    #[test]
    fn test_call_state_eq() {
        assert_eq!(CallState::Idle, CallState::Idle);
        assert_ne!(CallState::Idle, CallState::Inviting);
    }

    #[test]
    fn test_call_state_clone() {
        let state = CallState::Established;
        let cloned = state;
        assert_eq!(state, cloned);
    }

    // CallDirection tests
    #[test]
    fn test_call_direction_debug() {
        assert!(format!("{:?}", CallDirection::Outbound).contains("Outbound"));
        assert!(format!("{:?}", CallDirection::Inbound).contains("Inbound"));
    }

    #[test]
    fn test_call_direction_eq() {
        assert_eq!(CallDirection::Outbound, CallDirection::Outbound);
        assert_ne!(CallDirection::Outbound, CallDirection::Inbound);
    }

    // CallConfig tests
    #[test]
    fn test_call_config_default() {
        let config = CallConfig::default();
        assert_eq!(config.local_uri, "sip:user@127.0.0.1");
        assert!(config.local_name.is_none());
        assert!(!config.codecs.is_empty());
        assert_eq!(config.rtp_port_start, 10000);
        assert_eq!(config.rtp_port_end, 20000);
    }

    #[test]
    fn test_call_config_debug() {
        let config = CallConfig::default();
        let debug = format!("{:?}", config);
        assert!(debug.contains("CallConfig"));
    }

    #[test]
    fn test_call_config_clone() {
        let config = CallConfig::default();
        let cloned = config.clone();
        assert_eq!(cloned.local_uri, config.local_uri);
    }

    // CallEvent tests
    #[test]
    fn test_call_event_debug() {
        let event = CallEvent::StateChanged(CallState::Ringing);
        let debug = format!("{:?}", event);
        assert!(debug.contains("StateChanged"));
    }

    #[test]
    fn test_call_event_ringing() {
        let event = CallEvent::Ringing;
        let debug = format!("{:?}", event);
        assert!(debug.contains("Ringing"));
    }

    #[test]
    fn test_call_event_early_media() {
        let event = CallEvent::EarlyMedia;
        let debug = format!("{:?}", event);
        assert!(debug.contains("EarlyMedia"));
    }

    #[test]
    fn test_call_event_answered() {
        let event = CallEvent::Answered;
        let debug = format!("{:?}", event);
        assert!(debug.contains("Answered"));
    }

    #[test]
    fn test_call_event_ended() {
        let event = CallEvent::Ended(CallEndReason::NormalClearing);
        let debug = format!("{:?}", event);
        assert!(debug.contains("Ended"));
    }

    #[test]
    fn test_call_event_audio_received() {
        let event = CallEvent::AudioReceived(vec![0i16; 160]);
        let debug = format!("{:?}", event);
        assert!(debug.contains("AudioReceived"));
    }

    #[test]
    fn test_call_event_dtmf_received() {
        let event = CallEvent::DtmfReceived('5');
        let debug = format!("{:?}", event);
        assert!(debug.contains("DtmfReceived"));
    }

    #[test]
    fn test_call_event_clone() {
        let event = CallEvent::Ringing;
        let cloned = event.clone();
        assert!(format!("{:?}", cloned).contains("Ringing"));
    }

    // CallEndReason tests
    #[test]
    fn test_call_end_reason_debug() {
        assert!(format!("{:?}", CallEndReason::NormalClearing).contains("NormalClearing"));
        assert!(format!("{:?}", CallEndReason::Rejected).contains("Rejected"));
        assert!(format!("{:?}", CallEndReason::Busy).contains("Busy"));
        assert!(format!("{:?}", CallEndReason::NoAnswer).contains("NoAnswer"));
        assert!(format!("{:?}", CallEndReason::NetworkError).contains("NetworkError"));
        assert!(format!("{:?}", CallEndReason::Canceled).contains("Canceled"));
        assert!(format!("{:?}", CallEndReason::Error).contains("Error"));
    }

    #[test]
    fn test_call_end_reason_eq() {
        assert_eq!(CallEndReason::Busy, CallEndReason::Busy);
        assert_ne!(CallEndReason::Busy, CallEndReason::Rejected);
    }

    // CallId tests
    #[test]
    fn test_call_id_default() {
        let id = CallId::default();
        assert!(!id.0.is_empty());
    }

    #[test]
    fn test_call_id_display() {
        let id = CallId::new();
        let display = format!("{}", id);
        assert!(!display.is_empty());
        assert_eq!(display, id.0);
    }

    #[test]
    fn test_call_id_hash() {
        use std::collections::HashSet;
        let id1 = CallId::new();
        let id2 = CallId::new();
        let mut set = HashSet::new();
        set.insert(id1.clone());
        set.insert(id2.clone());
        set.insert(id1.clone()); // duplicate
        assert_eq!(set.len(), 2);
    }

    // Call tests
    #[test]
    fn test_new_inbound_call() {
        let config = Arc::new(CallConfig::default());
        let dialog = Dialog::new_uas(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:bob@example.com".to_string(),
            "sip:alice@example.com".to_string(),
            1,
        );

        let call = Call::new_inbound(config, "sip:alice@example.com".to_string(), dialog);

        assert_eq!(call.state(), CallState::Ringing);
        assert_eq!(call.direction(), CallDirection::Inbound);
        assert!(call.dialog().is_some());
    }

    #[test]
    fn test_call_set_dialog() {
        let config = Arc::new(CallConfig::default());
        let mut call = Call::new_outbound(config, "sip:bob@example.com".to_string());

        assert!(call.dialog().is_none());
        assert!(call.dialog_id().is_none());

        let dialog = Dialog::new_uac(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            1,
        );
        call.set_dialog(dialog);

        assert!(call.dialog().is_some());
        assert!(call.dialog_id().is_some());
    }

    #[test]
    fn test_call_dialog_mut() {
        let config = Arc::new(CallConfig::default());
        let dialog = Dialog::new_uas(
            "call-123".to_string(),
            "from-tag".to_string(),
            "to-tag".to_string(),
            "sip:bob@example.com".to_string(),
            "sip:alice@example.com".to_string(),
            1,
        );
        let mut call = Call::new_inbound(config, "sip:alice@example.com".to_string(), dialog);

        // Modify dialog via mutable reference
        let d = call.dialog_mut().unwrap();
        let _ = d.next_cseq();

        // Verify modification
        assert!(call.dialog().is_some());
    }

    #[test]
    fn test_call_can_receive_media() {
        let config = Arc::new(CallConfig::default());
        let mut call = Call::new_outbound(config, "sip:bob@example.com".to_string());

        // Idle state
        assert!(!call.can_receive_media());

        // Inviting state
        call.set_state(CallState::Inviting);
        assert!(!call.can_receive_media());

        // Ringing state
        call.set_state(CallState::Ringing);
        assert!(!call.can_receive_media());

        // EarlyMedia state
        call.set_state(CallState::EarlyMedia);
        assert!(call.can_receive_media());

        // Established state
        call.set_state(CallState::Established);
        assert!(call.can_receive_media());

        // Terminated state
        call.set_state(CallState::Terminated);
        assert!(!call.can_receive_media());
    }

    #[test]
    fn test_call_handle_early_media() {
        let config = Arc::new(CallConfig::default());
        let mut call = Call::new_outbound(config, "sip:bob@example.com".to_string());

        call.handle_provisional(true);
        assert_eq!(call.state(), CallState::EarlyMedia);

        let events = call.drain_events();
        assert!(events.iter().any(|e| matches!(e, CallEvent::EarlyMedia)));
    }

    #[test]
    fn test_call_handle_ended_with_media() {
        let config = Arc::new(CallConfig::default());
        let mut call = Call::new_outbound(config, "sip:bob@example.com".to_string());

        // Set up media
        let media = NegotiatedMedia {
            codec: Codec::pcmu(),
            remote_port: 6000,
            remote_addr: Some("10.0.0.1".to_string()),
            direction: crate::sdp::parser::Direction::SendRecv,
        };
        call.set_negotiated_media(media, 5000)
            .expect("PCMU media setup");

        assert!(call.media().unwrap().is_active());

        // End call
        call.handle_ended(CallEndReason::NormalClearing);

        assert_eq!(call.state(), CallState::Terminated);
        assert!(!call.media().unwrap().is_active());
    }

    #[test]
    fn test_call_media_mut() {
        let config = Arc::new(CallConfig::default());
        let mut call = Call::new_outbound(config, "sip:bob@example.com".to_string());

        // No media initially
        assert!(call.media_mut().is_none());

        // Set up media
        let media = NegotiatedMedia {
            codec: Codec::pcmu(),
            remote_port: 6000,
            remote_addr: None,
            direction: crate::sdp::parser::Direction::SendRecv,
        };
        call.set_negotiated_media(media, 5000)
            .expect("PCMU media setup");

        // Now has media
        assert!(call.media_mut().is_some());
    }

    #[test]
    fn test_call_config() {
        let config = Arc::new(CallConfig {
            local_uri: "sip:test@host.com".to_string(),
            local_name: Some("Test User".to_string()),
            codecs: vec![Codec::pcma()],
            rtp_port_start: 20000,
            rtp_port_end: 30000,
        });
        let call = Call::new_outbound(config, "sip:bob@example.com".to_string());

        let cfg = call.config();
        assert_eq!(cfg.local_uri, "sip:test@host.com");
        assert_eq!(cfg.local_name.as_deref(), Some("Test User"));
    }

    #[test]
    fn test_call_set_state_no_duplicate_events() {
        let config = Arc::new(CallConfig::default());
        let mut call = Call::new_outbound(config, "sip:bob@example.com".to_string());

        // Set state
        call.set_state(CallState::Established);
        let events1 = call.drain_events();
        assert_eq!(events1.len(), 1);

        // Set same state again - should not emit event
        call.set_state(CallState::Established);
        let events2 = call.drain_events();
        assert!(events2.is_empty());
    }

    // MediaSession tests
    #[test]
    fn test_media_session_alaw() {
        let session =
            MediaSession::for_negotiated(12345, &Codec::pcma(), 5000).expect("PCMA MediaSession");
        assert_eq!(session.local_port(), 5000);
        assert!(!session.is_active());
    }

    #[test]
    fn test_media_session_unknown_payload() {
        // Unsupported codec encodings now surface as Err — previously
        // payload-type 99 silently fell back to mu-law. Asserting the
        // explicit rejection is the correct contract under the new API.
        let unsupported = Codec::new(99, "AMR", 8000);
        assert!(MediaSession::for_negotiated(12345, &unsupported, 5000).is_err());
    }

    #[test]
    fn test_media_session_rtp_session() {
        let session = pcmu_session(12345, 5000);
        let rtp = session.rtp_session();
        assert_eq!(rtp.ssrc(), 12345);
    }

    #[test]
    fn test_media_session_jitter_stats() {
        let session = pcmu_session(12345, 5000);
        let stats = session.jitter_stats();
        assert_eq!(stats.packets_received, 0);
    }

    #[test]
    fn test_media_session_get_audio_frame() {
        use crate::media::PlayoutDecision;
        let mut session = pcmu_session(12345, 5000);

        // Without primed buffer, should get empty samples
        let (decision, samples) = session.get_audio_frame();
        // Empty buffer returns silence
        assert_eq!(decision, PlayoutDecision::Silence);
        assert_eq!(samples.len(), 160);
    }

    #[test]
    fn test_media_session_receive_rtp() {
        let mut session = pcmu_session(12345, 5000);
        session.set_remote("10.0.0.1:6000".parse().unwrap());

        // Use the existing encode method to create a test packet
        // This is cleaner than manually constructing the packet
        let samples = vec![0i16; 160];
        let packet = session.encode_audio(&samples, false).expect("PCMU encode");

        // First packet won't return audio (buffer not primed)
        let result = session.receive_rtp(&packet);
        assert!(result.is_none());
    }

    #[test]
    fn test_media_session_receive_rtp_primes_buffer() {
        let mut session = pcmu_session(12345, 5000);
        session.set_remote("10.0.0.1:6000".parse().unwrap());

        let samples = vec![0i16; 160];
        let mut result = None;

        for _ in 0..3 {
            let packet = session.encode_audio(&samples, false).expect("PCMU encode");
            result = session.receive_rtp(&packet);
        }

        assert!(result.is_some());
    }

    #[test]
    fn test_media_session_debug() {
        let session = pcmu_session(12345, 5000);
        let debug = format!("{:?}", session);
        assert!(debug.contains("MediaSession"));
    }

    #[test]
    fn test_set_negotiated_media_no_remote_addr() {
        let config = Arc::new(CallConfig::default());
        let mut call = Call::new_outbound(config, "sip:bob@example.com".to_string());

        let media = NegotiatedMedia {
            codec: Codec::pcmu(),
            remote_port: 6000,
            remote_addr: None,
            direction: crate::sdp::parser::Direction::SendRecv,
        };

        call.set_negotiated_media(media, 5000)
            .expect("PCMU media setup");

        assert!(call.media().is_some());
        // Media not active because no remote address
        assert!(!call.media().unwrap().is_active());
    }

    #[test]
    fn test_set_negotiated_media_invalid_addr() {
        let config = Arc::new(CallConfig::default());
        let mut call = Call::new_outbound(config, "sip:bob@example.com".to_string());

        let media = NegotiatedMedia {
            codec: Codec::pcmu(),
            remote_port: 6000,
            remote_addr: Some("not-an-ip".to_string()),
            direction: crate::sdp::parser::Direction::SendRecv,
        };

        call.set_negotiated_media(media, 5000)
            .expect("PCMU media setup");

        assert!(call.media().is_some());
        // Media not active because invalid address
        assert!(!call.media().unwrap().is_active());
    }

    #[test]
    fn test_call_debug() {
        let config = Arc::new(CallConfig::default());
        let call = Call::new_outbound(config, "sip:bob@example.com".to_string());
        let debug = format!("{:?}", call);
        assert!(debug.contains("Call"));
    }
}
