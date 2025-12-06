//! Call abstraction.
//!
//! A Call represents a single SIP call session including signaling and media.

use std::net::SocketAddr;
use std::sync::Arc;

use mdsiprtp_core::random_u32;
use mdsiprtp_dialog::DialogId;
use mdsiprtp_media::{G711Codec, G711Variant, JitterBuffer, JitterBufferConfig, PlayoutDecision};
use mdsiprtp_rtp::{RtpPacket, RtpSession};
use mdsiprtp_sdp::negotiation::{Codec, NegotiatedMedia};

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

/// Media session for a call.
#[derive(Debug)]
pub struct MediaSession {
    /// RTP session for sending/receiving.
    rtp_session: RtpSession,
    /// Jitter buffer for received audio.
    jitter_buffer: JitterBuffer,
    /// Audio codec.
    codec: G711Codec,
    /// Remote RTP address.
    remote_addr: Option<SocketAddr>,
    /// Local RTP port.
    local_port: u16,
    /// Whether media is active.
    active: bool,
}

impl MediaSession {
    /// Create a new media session.
    pub fn new(ssrc: u32, payload_type: u8, clock_rate: u32, local_port: u16) -> Self {
        let codec_variant = match payload_type {
            0 => G711Variant::MuLaw,
            8 => G711Variant::ALaw,
            _ => G711Variant::MuLaw, // Default
        };

        Self {
            rtp_session: RtpSession::new(ssrc, payload_type, clock_rate),
            jitter_buffer: JitterBuffer::new(JitterBufferConfig::g711()),
            codec: G711Codec::new(codec_variant),
            remote_addr: None,
            local_port,
            active: false,
        }
    }

    /// Set the remote RTP address.
    pub fn set_remote(&mut self, addr: SocketAddr) {
        self.remote_addr = Some(addr);
        self.active = true;
    }

    /// Create an RTP packet from PCM samples.
    pub fn encode_audio(&mut self, samples: &[i16], marker: bool) -> RtpPacket {
        let encoded = self.codec.encode(samples);
        self.rtp_session
            .create_packet(encoded, samples.len() as u32, marker)
    }

    /// Process a received RTP packet and get decoded audio.
    pub fn receive_rtp(&mut self, packet: &RtpPacket) -> Option<(PlayoutDecision, Vec<i16>)> {
        // Update RTP session statistics
        self.rtp_session.receive_packet(packet);

        // Decode the audio
        let decoded = self.codec.decode(&packet.payload);

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
    pub fn jitter_stats(&self) -> &mdsiprtp_media::JitterStats {
        self.jitter_buffer.stats()
    }
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
    pub fn set_negotiated_media(&mut self, media: NegotiatedMedia, local_port: u16) {
        // Generate random SSRC
        let ssrc = random_u32();

        let mut session = MediaSession::new(
            ssrc,
            media.codec.payload_type,
            media.codec.clock_rate,
            local_port,
        );

        // Set remote address if available
        if let Some(ref addr) = media.remote_addr {
            if let Ok(ip) = addr.parse() {
                session.set_remote(SocketAddr::new(ip, media.remote_port));
            }
        }

        self.negotiated_media = Some(media);
        self.media = Some(session);
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
        matches!(
            self.state,
            CallState::EarlyMedia | CallState::Established
        )
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

    #[test]
    fn test_media_session() {
        let mut session = MediaSession::new(12345, 0, 8000, 5000);

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
        let mut session = MediaSession::new(12345, 0, 8000, 5000);

        let samples = vec![0i16; 160];
        let packet = session.encode_audio(&samples, true);

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
            direction: mdsiprtp_sdp::parser::Direction::SendRecv,
        };

        call.set_negotiated_media(media, 5000);

        assert!(call.media().is_some());
        assert_eq!(call.codec().map(|c| c.encoding.as_str()), Some("PCMU"));
    }
}
