//! Dialog states and identifiers per RFC 3261.
//!
//! A dialog is a peer-to-peer SIP relationship between two UAs that persists
//! for some time. It facilitates sequencing of messages between the UAs and
//! proper routing of requests between both of them.

use mdsiprtp_sip::{SipRequest, SipResponse, Via, RecordRoute as SipRecordRoute};

/// Dialog identifier per RFC 3261.
///
/// A dialog is identified by the combination of Call-ID, local tag, and remote tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialogId {
    /// Call-ID header value.
    pub call_id: String,
    /// Local tag (From tag for UAC, To tag for UAS).
    pub local_tag: String,
    /// Remote tag (To tag for UAC, From tag for UAS).
    pub remote_tag: String,
}

impl DialogId {
    /// Create a new dialog ID.
    pub fn new(call_id: impl Into<String>, local_tag: impl Into<String>, remote_tag: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            local_tag: local_tag.into(),
            remote_tag: remote_tag.into(),
        }
    }

    /// Create a dialog ID from a request (UAC perspective).
    ///
    /// Returns None if the request doesn't have the required tags.
    pub fn from_request_uac(request: &SipRequest, remote_tag: &str) -> Option<Self> {
        let call_id = request.call_id().ok()?;
        let local_tag = request.from_tag().ok()?;

        Some(Self {
            call_id,
            local_tag,
            remote_tag: remote_tag.to_string(),
        })
    }

    /// Create a dialog ID from a response (UAC perspective).
    ///
    /// Returns None if the response doesn't have the required tags.
    pub fn from_response_uac(response: &SipResponse) -> Option<Self> {
        let call_id = response.call_id().ok()?;
        let local_tag = response.from_tag().ok()?;
        let remote_tag = response.to_tag()?;

        Some(Self {
            call_id,
            local_tag,
            remote_tag,
        })
    }

    /// Create a dialog ID from a request (UAS perspective).
    ///
    /// Returns None if the request doesn't have the required tags.
    pub fn from_request_uas(request: &SipRequest, local_tag: &str) -> Option<Self> {
        let call_id = request.call_id().ok()?;
        let remote_tag = request.from_tag().ok()?;

        Some(Self {
            call_id,
            local_tag: local_tag.to_string(),
            remote_tag,
        })
    }
}

/// State of a dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogState {
    /// Early dialog - provisional response received but no final response yet.
    Early,
    /// Confirmed dialog - 2xx response received.
    Confirmed,
    /// Dialog is being terminated.
    Terminating,
    /// Dialog has been terminated.
    Terminated,
}

/// Route set for in-dialog requests (RFC 3261 Section 12.2).
#[derive(Debug, Clone, Default)]
pub struct RouteSet {
    /// List of Route URIs (derived from Record-Route headers).
    routes: Vec<String>,
    /// Whether routes use loose routing (have ;lr parameter).
    loose_routing: bool,
}

impl RouteSet {
    /// Create an empty route set.
    pub fn new() -> Self {
        Self {
            routes: Vec::new(),
            loose_routing: false,
        }
    }

    /// Create a route set from Record-Route header values.
    ///
    /// For UAC (caller), the routes should be reversed (top Record-Route becomes last route).
    /// For UAS (callee), the routes are used in order as received.
    pub fn from_record_route_values(record_route_values: &[String], reverse: bool) -> Self {
        let record_routes = SipRecordRoute::parse_all(record_route_values);

        let mut routes: Vec<String> = record_routes
            .iter()
            .map(|rr| rr.to_header_value())
            .collect();

        if reverse {
            routes.reverse();
        }

        // Check if first route uses loose routing
        let loose_routing = record_routes.first().map(|rr| rr.lr).unwrap_or(false);

        Self { routes, loose_routing }
    }

    /// Get the routes as string values.
    pub fn routes(&self) -> &[String] {
        &self.routes
    }

    /// Check if the route set is empty.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Check if the route set uses loose routing.
    pub fn is_loose_routing(&self) -> bool {
        self.loose_routing
    }

    /// Get the number of routes.
    pub fn len(&self) -> usize {
        self.routes.len()
    }
}

/// Dialog state information.
#[derive(Debug, Clone)]
pub struct DialogInfo {
    /// Dialog ID.
    pub id: DialogId,
    /// Current state.
    pub state: DialogState,
    /// Local sequence number (for outgoing requests).
    pub local_seq: u32,
    /// Remote sequence number (for incoming requests).
    pub remote_seq: Option<u32>,
    /// Local URI.
    pub local_uri: String,
    /// Remote URI.
    pub remote_uri: String,
    /// Remote target (Contact URI from peer).
    pub remote_target: String,
    /// Route set.
    pub route_set: RouteSet,
    /// Whether this is a secure dialog (established over TLS).
    pub secure: bool,
}

impl DialogInfo {
    /// Create dialog info for a UAC from an outgoing INVITE and incoming response.
    pub fn from_invite_response_uac(
        request: &SipRequest,
        response: &SipResponse,
        state: DialogState,
    ) -> Option<Self> {
        let id = DialogId::from_response_uac(response)?;
        let local_uri = request.from_uri().ok()?.to_string();
        let remote_uri = request.to_uri().ok()?.to_string();
        let remote_target = response.contact_uri()?.to_string();
        let local_seq = request.cseq().ok()?;

        // Extract Record-Route headers and reverse for UAC (RFC 3261 Section 12.1.2)
        let record_routes = response.record_routes();
        let route_set = RouteSet::from_record_route_values(&record_routes, true);

        // Detect if dialog is secure from transport (TLS/SIPS)
        let secure = Self::detect_secure_transport(request);

        Some(Self {
            id,
            state,
            local_seq,
            remote_seq: None,
            local_uri,
            remote_uri,
            remote_target,
            route_set,
            secure,
        })
    }

    /// Create dialog info for a UAS from an incoming INVITE.
    pub fn from_invite_uas(
        request: &SipRequest,
        local_tag: &str,
        local_contact: &str,
        state: DialogState,
    ) -> Option<Self> {
        let id = DialogId::from_request_uas(request, local_tag)?;
        let remote_uri = request.from_uri().ok()?.to_string();
        let local_uri = request.to_uri().ok()?.to_string();
        let remote_target = request.contact_uri()?.to_string();
        let remote_seq = request.cseq().ok()?;

        // Extract Record-Route headers (not reversed for UAS per RFC 3261 Section 12.1.1)
        let record_routes = request.record_routes();
        let route_set = RouteSet::from_record_route_values(&record_routes, false);

        // Detect if dialog is secure from transport
        let secure = Self::detect_secure_transport(request);

        let _ = local_contact; // Will be used when sending responses

        Some(Self {
            id,
            state,
            local_seq: 0, // Will be set when sending first in-dialog request
            remote_seq: Some(remote_seq),
            local_uri,
            remote_uri,
            remote_target,
            route_set,
            secure,
        })
    }

    /// Detect if the transport is secure (TLS) from the Via header.
    fn detect_secure_transport(request: &SipRequest) -> bool {
        let via_values = request.via_headers_raw();
        if let Some(first_via) = via_values.first() {
            if let Ok(via) = Via::parse(first_via) {
                return via.protocol.eq_ignore_ascii_case("TLS");
            }
        }
        false
    }

    /// Get the next local CSeq number.
    pub fn next_local_seq(&mut self) -> u32 {
        self.local_seq += 1;
        self.local_seq
    }

    /// Update remote sequence number.
    ///
    /// Returns true if the sequence number is valid (greater than current).
    pub fn update_remote_seq(&mut self, seq: u32) -> bool {
        match self.remote_seq {
            None => {
                self.remote_seq = Some(seq);
                true
            }
            Some(current) if seq > current => {
                self.remote_seq = Some(seq);
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdsiprtp_sip::Method;

    fn create_invite() -> SipRequest {
        SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .contact("sip:alice@192.168.1.1:5060")
            .build()
            .unwrap()
    }

    fn create_response(request: &SipRequest) -> SipResponse {
        SipResponse::builder()
            .status(200, "OK")
            .from_request(request)
            .to_tag("totag")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap()
    }

    #[test]
    fn test_dialog_id_from_response_uac() {
        let invite = create_invite();
        let response = create_response(&invite);
        let id = DialogId::from_response_uac(&response).unwrap();

        assert_eq!(id.call_id, "test@example.com");
        assert_eq!(id.local_tag, "fromtag");
        assert_eq!(id.remote_tag, "totag");
    }

    #[test]
    fn test_dialog_id_from_request_uas() {
        let invite = create_invite();
        let id = DialogId::from_request_uas(&invite, "mytag").unwrap();

        assert_eq!(id.call_id, "test@example.com");
        assert_eq!(id.local_tag, "mytag");
        assert_eq!(id.remote_tag, "fromtag");
    }

    #[test]
    fn test_dialog_info_from_response() {
        let invite = create_invite();
        let response = create_response(&invite);
        let info = DialogInfo::from_invite_response_uac(&invite, &response, DialogState::Confirmed).unwrap();

        assert_eq!(info.state, DialogState::Confirmed);
        assert_eq!(info.local_seq, 1);
        assert!(info.remote_seq.is_none());
    }

    #[test]
    fn test_next_local_seq() {
        let invite = create_invite();
        let response = create_response(&invite);
        let mut info = DialogInfo::from_invite_response_uac(&invite, &response, DialogState::Confirmed).unwrap();

        assert_eq!(info.next_local_seq(), 2);
        assert_eq!(info.next_local_seq(), 3);
    }

    #[test]
    fn test_update_remote_seq() {
        let invite = create_invite();
        let response = create_response(&invite);
        let mut info = DialogInfo::from_invite_response_uac(&invite, &response, DialogState::Confirmed).unwrap();

        assert!(info.update_remote_seq(1));
        assert!(info.update_remote_seq(2));
        assert!(!info.update_remote_seq(1)); // Old seq rejected
        assert!(!info.update_remote_seq(2)); // Same seq rejected
    }
}
