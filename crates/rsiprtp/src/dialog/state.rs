//! Dialog states and identifiers per RFC 3261.
//!
//! A dialog is a peer-to-peer SIP relationship between two UAs that persists
//! for some time. It facilitates sequencing of messages between the UAs and
//! proper routing of requests between both of them.

use crate::sip::{RecordRoute as SipRecordRoute, SipRequest, SipResponse, Via};

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
    pub fn new(
        call_id: impl Into<String>,
        local_tag: impl Into<String>,
        remote_tag: impl Into<String>,
    ) -> Self {
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

        Self {
            routes,
            loose_routing,
        }
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
        let call_id = request.call_id().ok()?;
        let (remote_tag, remote_uri) = request.from_tag_and_uri().ok()?;
        let id = DialogId::new(&call_id, local_tag, &remote_tag);
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
            remote_uri: remote_uri.to_string(),
            remote_target,
            route_set,
            secure,
        })
    }

    /// Detect if the transport is secure (TLS) from the Via header.
    fn detect_secure_transport(request: &SipRequest) -> bool {
        let via_values = request.via_headers_raw();
        if let Some(first_via) = via_values.first() {
            let via_value = first_via
                .trim()
                .strip_prefix("Via:")
                .unwrap_or(first_via)
                .trim();
            if let Ok(via) = Via::parse(via_value) {
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
    use crate::sip::{Method, SipMessage};

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

    fn parse_request(raw: &str) -> SipRequest {
        let msg = SipMessage::parse(raw.as_bytes()).unwrap();
        msg.as_request().unwrap().clone()
    }

    fn parse_response(raw: &str) -> SipResponse {
        let msg = SipMessage::parse(raw.as_bytes()).unwrap();
        msg.as_response().unwrap().clone()
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
    fn test_dialog_id_from_request_uac_missing_call_id() {
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let id = DialogId::from_request_uac(&invite, "remotetag");
        assert!(id.is_none());
    }

    #[test]
    fn test_dialog_id_from_request_uac_missing_from_tag() {
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let id = DialogId::from_request_uac(&invite, "remotetag");
        assert!(id.is_none());
    }

    #[test]
    fn test_dialog_id_from_response_uac_missing_call_id() {
        let response = parse_response(
            "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>;tag=totag\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@192.168.1.2:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let id = DialogId::from_response_uac(&response);
        assert!(id.is_none());
    }

    #[test]
    fn test_dialog_id_from_response_uac_missing_from_tag() {
        let response = parse_response(
            "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>\r\n\
To: <sip:bob@example.com>;tag=totag\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@192.168.1.2:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let id = DialogId::from_response_uac(&response);
        assert!(id.is_none());
    }

    #[test]
    fn test_dialog_id_from_request_uas_missing_call_id() {
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let id = DialogId::from_request_uas(&invite, "localtag");
        assert!(id.is_none());
    }

    #[test]
    fn test_dialog_id_from_request_uas_missing_from_tag() {
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let id = DialogId::from_request_uas(&invite, "mytag");
        assert!(id.is_none());
    }

    #[test]
    fn test_dialog_id_from_request_uac() {
        let invite = create_invite();
        let id = DialogId::from_request_uac(&invite, "remotetag").unwrap();
        assert_eq!(id.call_id, "test@example.com");
        assert_eq!(id.local_tag, "fromtag");
        assert_eq!(id.remote_tag, "remotetag");
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
    fn test_dialog_info_from_invite_uas_option() {
        let invite = create_invite();
        let info = DialogInfo::from_invite_uas(
            &invite,
            "localtag",
            "sip:local@example.com",
            DialogState::Early,
        )
        .unwrap();

        assert_eq!(info.state, DialogState::Early);
        assert_eq!(info.remote_seq, Some(1));
        assert_eq!(info.remote_uri, "sip:alice@example.com");
    }

    #[test]
    fn test_dialog_info_from_response() {
        let invite = create_invite();
        let response = create_response(&invite);
        let info = DialogInfo::from_invite_response_uac(&invite, &response, DialogState::Confirmed)
            .unwrap();

        assert_eq!(info.state, DialogState::Confirmed);
        assert_eq!(info.local_seq, 1);
        assert!(info.remote_seq.is_none());
    }

    #[test]
    fn test_dialog_info_from_response_invalid_from_uri() {
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@[::1>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        assert!(invite.from_uri().is_err());
        let response = parse_response(
            "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>;tag=totag\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@192.168.1.2:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let info = DialogInfo::from_invite_response_uac(&invite, &response, DialogState::Confirmed);
        assert!(info.is_none());
    }

    #[test]
    fn test_dialog_info_from_response_invalid_to_uri() {
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@[::1>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        assert!(invite.to_uri().is_err());
        let response = parse_response(
            "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>;tag=totag\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@192.168.1.2:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let info = DialogInfo::from_invite_response_uac(&invite, &response, DialogState::Confirmed);
        assert!(info.is_none());
    }

    #[test]
    fn test_dialog_info_from_response_missing_contact() {
        let invite = create_invite();
        let response = parse_response(
            "SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>;tag=totag\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let info = DialogInfo::from_invite_response_uac(&invite, &response, DialogState::Confirmed);
        assert!(info.is_none());
    }

    #[test]
    fn test_dialog_info_from_response_invalid_cseq() {
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: abc INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let response = create_response(&invite);
        let info = DialogInfo::from_invite_response_uac(&invite, &response, DialogState::Confirmed);
        assert!(info.is_none());
    }

    #[test]
    fn test_dialog_info_from_invite_uas_invalid_from_uri() {
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@[::1>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        assert!(invite.from_uri().is_err());
        let info = DialogInfo::from_invite_uas(
            &invite,
            "localtag",
            "sip:local@example.com",
            DialogState::Early,
        );
        assert!(info.is_none());
    }

    #[test]
    fn test_dialog_info_from_invite_uas_invalid_to_uri() {
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@[::1>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let info = DialogInfo::from_invite_uas(
            &invite,
            "localtag",
            "sip:local@example.com",
            DialogState::Early,
        );
        assert!(info.is_none());
    }

    #[test]
    fn test_dialog_info_from_invite_uas_invalid_contact() {
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@[::1>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let info = DialogInfo::from_invite_uas(
            &invite,
            "localtag",
            "sip:local@example.com",
            DialogState::Early,
        );
        assert!(info.is_none());
    }

    #[test]
    fn test_dialog_info_from_invite_uas_invalid_cseq() {
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: abc INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let info = DialogInfo::from_invite_uas(
            &invite,
            "localtag",
            "sip:local@example.com",
            DialogState::Early,
        );
        assert!(info.is_none());
    }

    #[test]
    fn test_dialog_info_from_invite_uas_missing_call_id() {
        let invite = parse_request(
            "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n",
        );
        let info = DialogInfo::from_invite_uas(
            &invite,
            "localtag",
            "sip:local@example.com",
            DialogState::Early,
        );
        assert!(info.is_none());
    }

    #[test]
    fn test_detect_secure_transport_prefix_via() {
        let raw = "INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/TLS 192.168.1.1:5061;branch=z9hG4bKtls\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n";
        let invite = parse_request(raw);
        let info = DialogInfo::from_invite_uas(
            &invite,
            "localtag",
            "sip:local@example.com",
            DialogState::Early,
        )
        .unwrap();
        assert!(info.secure);
    }

    #[test]
    fn test_detect_secure_transport_prefix_via_lowercase() {
        let raw = "INVITE sip:bob@example.com SIP/2.0\r\n\
via: SIP/2.0/TLS 192.168.1.1:5061;branch=z9hG4bKtls\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:alice@192.168.1.1:5060>\r\n\
Content-Length: 0\r\n\
\r\n";
        let invite = parse_request(raw);
        let info = DialogInfo::from_invite_uas(
            &invite,
            "localtag",
            "sip:local@example.com",
            DialogState::Early,
        )
        .unwrap();
        assert!(info.secure);
    }

    #[test]
    fn test_next_local_seq() {
        let invite = create_invite();
        let response = create_response(&invite);
        let mut info =
            DialogInfo::from_invite_response_uac(&invite, &response, DialogState::Confirmed)
                .unwrap();

        assert_eq!(info.next_local_seq(), 2);
        assert_eq!(info.next_local_seq(), 3);
    }

    #[test]
    fn test_update_remote_seq() {
        let invite = create_invite();
        let response = create_response(&invite);
        let mut info =
            DialogInfo::from_invite_response_uac(&invite, &response, DialogState::Confirmed)
                .unwrap();

        assert!(info.update_remote_seq(1));
        assert!(info.update_remote_seq(2));
        assert!(!info.update_remote_seq(1)); // Old seq rejected
        assert!(!info.update_remote_seq(2)); // Same seq rejected
    }

    // Additional tests for coverage

    #[test]
    fn test_dialog_id_new() {
        let id = DialogId::new("call123", "local456", "remote789");
        assert_eq!(id.call_id, "call123");
        assert_eq!(id.local_tag, "local456");
        assert_eq!(id.remote_tag, "remote789");
    }

    #[test]
    fn test_dialog_id_clone() {
        let id = DialogId::new("call123", "local456", "remote789");
        let cloned = id.clone();
        assert_eq!(cloned.call_id, id.call_id);
        assert_eq!(cloned.local_tag, id.local_tag);
        assert_eq!(cloned.remote_tag, id.remote_tag);
    }

    #[test]
    fn test_dialog_id_eq() {
        let id1 = DialogId::new("call123", "local456", "remote789");
        let id2 = DialogId::new("call123", "local456", "remote789");
        let id3 = DialogId::new("call999", "local456", "remote789");
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_dialog_id_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DialogId::new("call123", "local456", "remote789"));
        assert!(set.contains(&DialogId::new("call123", "local456", "remote789")));
        assert!(!set.contains(&DialogId::new("call999", "local456", "remote789")));
    }

    #[test]
    fn test_dialog_id_debug() {
        let id = DialogId::new("call123", "local456", "remote789");
        let debug = format!("{:?}", id);
        assert!(debug.contains("call123"));
        assert!(debug.contains("local456"));
        assert!(debug.contains("remote789"));
    }

    #[test]
    fn test_dialog_state_all_variants() {
        let states = [
            DialogState::Early,
            DialogState::Confirmed,
            DialogState::Terminating,
            DialogState::Terminated,
        ];
        for state in states {
            let _ = format!("{:?}", state);
        }
    }

    #[test]
    fn test_dialog_state_clone() {
        let state = DialogState::Early;
        let cloned = state;
        assert_eq!(state, cloned);
    }

    #[test]
    fn test_route_set_new() {
        let route_set = RouteSet::new();
        assert!(route_set.is_empty());
        assert_eq!(route_set.len(), 0);
        assert!(!route_set.is_loose_routing());
    }

    #[test]
    fn test_route_set_default() {
        let route_set = RouteSet::default();
        assert!(route_set.is_empty());
        assert!(!route_set.is_loose_routing());
    }

    #[test]
    fn test_route_set_routes() {
        let routes = RouteSet::new();
        assert!(routes.routes().is_empty());
    }

    #[test]
    fn test_route_set_from_record_route_values() {
        let record_routes = vec![
            "<sip:proxy1.example.com;lr>".to_string(),
            "<sip:proxy2.example.com;lr>".to_string(),
        ];

        let route_set = RouteSet::from_record_route_values(&record_routes, false);
        assert!(!route_set.is_empty());
        assert_eq!(route_set.len(), 2);
        // The lr parameter detection depends on parsing
        // Just check that routes are not empty
    }

    #[test]
    fn test_route_set_from_record_route_values_reversed() {
        let record_routes = vec![
            "<sip:proxy1.example.com;lr>".to_string(),
            "<sip:proxy2.example.com;lr>".to_string(),
        ];

        let route_set = RouteSet::from_record_route_values(&record_routes, true);
        assert!(!route_set.is_empty());
        assert_eq!(route_set.len(), 2);
        // Routes should be reversed
        let routes = route_set.routes();
        assert!(routes[0].contains("proxy2"));
        assert!(routes[1].contains("proxy1"));
    }

    #[test]
    fn test_route_set_from_record_route_values_no_lr() {
        let record_routes = vec!["<sip:proxy1.example.com>".to_string()];

        let route_set = RouteSet::from_record_route_values(&record_routes, false);
        assert!(!route_set.is_empty());
        // No lr parameter
        assert!(!route_set.is_loose_routing());
    }

    #[test]
    fn test_route_set_from_record_route_values_empty() {
        let record_routes: Vec<String> = vec![];
        let route_set = RouteSet::from_record_route_values(&record_routes, false);
        assert!(route_set.is_empty());
        assert!(!route_set.is_loose_routing());
    }

    #[test]
    fn test_route_set_debug() {
        let route_set = RouteSet::new();
        let debug = format!("{:?}", route_set);
        assert!(debug.contains("RouteSet"));
    }

    #[test]
    fn test_route_set_clone() {
        let record_routes = vec!["<sip:proxy.example.com;lr>".to_string()];
        let route_set = RouteSet::from_record_route_values(&record_routes, false);
        let cloned = route_set.clone();
        assert_eq!(cloned.len(), route_set.len());
        assert_eq!(cloned.is_loose_routing(), route_set.is_loose_routing());
    }

    #[test]
    fn test_dialog_info_from_invite_uas() {
        let invite = create_invite();
        let info = DialogInfo::from_invite_uas(
            &invite,
            "mytag",
            "sip:me@192.168.1.2:5060",
            DialogState::Early,
        );

        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.state, DialogState::Early);
        assert_eq!(info.id.local_tag, "mytag");
        assert_eq!(info.id.remote_tag, "fromtag");
        assert_eq!(info.local_seq, 0);
        assert!(info.remote_seq.is_some());
        assert_eq!(info.remote_seq.unwrap(), 1);
    }

    #[test]
    fn test_dialog_id_from_request_uac_option() {
        let invite = create_invite();
        let id = DialogId::from_request_uac(&invite, "remote_tag");

        assert!(id.is_some());
        let id = id.unwrap();
        assert_eq!(id.call_id, "test@example.com");
        assert_eq!(id.local_tag, "fromtag");
        assert_eq!(id.remote_tag, "remote_tag");
    }

    #[test]
    fn test_dialog_info_secure_transport_detection() {
        // Test the detect_secure_transport function indirectly
        // The TLS transport detection checks the Via protocol
        let invite = create_invite(); // Uses UDP
        let is_secure = DialogInfo::detect_secure_transport(&invite);
        assert!(!is_secure); // UDP is not secure
    }

    #[test]
    fn test_dialog_info_secure_transport_tls() {
        let invite = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5061, "TLS", "z9hG4bKtest")
            .from("sip:alice@example.com", "fromtag")
            .to("sip:bob@example.com")
            .call_id("test@example.com")
            .cseq(1)
            .build()
            .unwrap();
        let is_secure = DialogInfo::detect_secure_transport(&invite);
        assert!(is_secure);
    }

    #[test]
    fn test_dialog_info_secure_transport_missing_via() {
        let msg = b"INVITE sip:bob@example.com SIP/2.0\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let parsed = SipMessage::parse(msg).unwrap();
        let invite = parsed.as_request().expect("expected request");
        let is_secure = DialogInfo::detect_secure_transport(invite);
        assert!(!is_secure);
    }

    #[test]
    fn test_dialog_info_secure_transport_invalid_via() {
        let msg = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: INVALID\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let parsed = SipMessage::parse(msg).unwrap();
        let invite = parsed.as_request().expect("expected request");
        let is_secure = DialogInfo::detect_secure_transport(invite);
        assert!(!is_secure);
    }

    #[test]
    fn test_dialog_info_secure_transport_udp() {
        let invite = create_invite(); // Uses UDP
        let info = DialogInfo::from_invite_uas(
            &invite,
            "mytag",
            "sip:me@192.168.1.2:5060",
            DialogState::Early,
        )
        .unwrap();
        assert!(!info.secure);
    }

    #[test]
    fn test_dialog_info_clone() {
        let invite = create_invite();
        let response = create_response(&invite);
        let info = DialogInfo::from_invite_response_uac(&invite, &response, DialogState::Confirmed)
            .unwrap();
        let cloned = info.clone();

        assert_eq!(cloned.id.call_id, info.id.call_id);
        assert_eq!(cloned.state, info.state);
        assert_eq!(cloned.local_seq, info.local_seq);
        assert_eq!(cloned.remote_seq, info.remote_seq);
    }

    #[test]
    fn test_dialog_info_debug() {
        let invite = create_invite();
        let response = create_response(&invite);
        let info = DialogInfo::from_invite_response_uac(&invite, &response, DialogState::Confirmed)
            .unwrap();
        let debug = format!("{:?}", info);
        assert!(debug.contains("DialogInfo"));
    }
}
