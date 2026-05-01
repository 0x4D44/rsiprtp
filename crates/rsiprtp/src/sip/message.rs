//! SIP message types and wrappers.

use bytes::Bytes;
use rsip::prelude::*;
use crate::core::{Result, SipError};
use std::convert::TryFrom;
use std::fmt;

#[cfg(coverage)]
#[inline(always)]
fn cover_none_case() {
    std::hint::black_box(());
}

#[cfg(not(coverage))]
#[inline(always)]
fn cover_none_case() {}

/// SIP message (either request or response).
#[derive(Debug, Clone)]
pub enum SipMessage {
    /// A SIP request (INVITE, REGISTER, BYE, ...).
    Request(SipRequest),
    /// A SIP response (1xx-6xx status).
    Response(SipResponse),
}

impl SipMessage {
    /// Parse a SIP message from bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let msg = rsip::SipMessage::try_from(data).map_err(|e| SipError::Parse(e.to_string()))?;

        match msg {
            rsip::SipMessage::Request(req) => Ok(SipMessage::Request(SipRequest { inner: req })),
            rsip::SipMessage::Response(resp) => {
                Ok(SipMessage::Response(SipResponse { inner: resp }))
            }
        }
    }

    /// Convert to bytes.
    pub fn to_bytes(&self) -> Bytes {
        match self {
            SipMessage::Request(req) => req.to_bytes(),
            SipMessage::Response(resp) => resp.to_bytes(),
        }
    }

    /// Check if this is a request.
    pub fn is_request(&self) -> bool {
        matches!(self, SipMessage::Request(_))
    }

    /// Check if this is a response.
    pub fn is_response(&self) -> bool {
        matches!(self, SipMessage::Response(_))
    }

    /// Get as request if it is one.
    pub fn as_request(&self) -> Option<&SipRequest> {
        match self {
            SipMessage::Request(req) => Some(req),
            _ => None,
        }
    }

    /// Get as response if it is one.
    pub fn as_response(&self) -> Option<&SipResponse> {
        match self {
            SipMessage::Response(resp) => Some(resp),
            _ => None,
        }
    }
}

/// SIP request wrapper.
#[derive(Debug, Clone)]
pub struct SipRequest {
    inner: rsip::Request,
}

impl SipRequest {
    /// Get the request method.
    pub fn method(&self) -> Method {
        Method::from(&self.inner.method)
    }

    /// Get the request URI.
    pub fn uri(&self) -> &rsip::Uri {
        &self.inner.uri
    }

    /// Get the Call-ID header value.
    pub fn call_id(&self) -> Result<String> {
        self.inner
            .call_id_header()
            .map(|h| h.value().to_string())
            .map_err(|_| SipError::MissingHeader("Call-ID".to_string()).into())
    }

    /// Get the From tag.
    pub fn from_tag(&self) -> Result<String> {
        let from = self
            .inner
            .from_header()
            .map_err(|_| SipError::MissingHeader("From".to_string()))?;
        // Convert to typed form to access tag
        let typed_from: rsip::typed::From =
            from.typed().map_err(|e| SipError::Parse(e.to_string()))?;
        let tag = typed_from
            .tag()
            .map(|t| t.to_string())
            .ok_or_else(|| SipError::InvalidHeader("From header missing tag".to_string()))?;
        Ok(tag)
    }

    /// Get the From tag and URI with a single parse.
    pub fn from_tag_and_uri(&self) -> Result<(String, rsip::Uri)> {
        let from = self
            .inner
            .from_header()
            .map_err(|_| SipError::MissingHeader("From".to_string()))?;
        let typed_from: rsip::typed::From =
            from.typed().map_err(|e| SipError::Parse(e.to_string()))?;
        let tag = typed_from
            .tag()
            .map(|t| t.to_string())
            .ok_or_else(|| SipError::InvalidHeader("From header missing tag".to_string()))?;
        Ok((tag, typed_from.uri))
    }

    /// Get the To tag (may not exist in requests).
    pub fn to_tag(&self) -> Option<String> {
        self.inner
            .to_header()
            .ok()
            .and_then(|h| h.typed().ok())
            .and_then(|typed: rsip::typed::To| typed.tag().map(|t| t.to_string()))
    }

    /// Get the Via branch parameter.
    pub fn via_branch(&self) -> Result<String> {
        let via = self
            .inner
            .via_header()
            .map_err(|_| SipError::MissingHeader("Via".to_string()))?;
        let typed_via: rsip::typed::Via =
            via.typed().map_err(|e| SipError::Parse(e.to_string()))?;
        let branch = typed_via
            .branch()
            .map(|b| b.to_string())
            .ok_or_else(|| SipError::InvalidHeader("Via header missing branch".to_string()))?;
        Ok(branch)
    }

    /// Get the CSeq number.
    pub fn cseq(&self) -> Result<u32> {
        let cseq = self
            .inner
            .cseq_header()
            .map_err(|_| SipError::MissingHeader("CSeq".to_string()))?;
        let typed_cseq: rsip::typed::CSeq =
            cseq.typed().map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(typed_cseq.seq)
    }

    /// Get the CSeq method.
    pub fn cseq_method(&self) -> Result<Method> {
        let cseq = self
            .inner
            .cseq_header()
            .map_err(|_| SipError::MissingHeader("CSeq".to_string()))?;
        let typed_cseq: rsip::typed::CSeq =
            cseq.typed().map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(Method::from(&typed_cseq.method))
    }

    /// Get the From URI.
    pub fn from_uri(&self) -> Result<rsip::Uri> {
        let from = self
            .inner
            .from_header()
            .map_err(|_| SipError::MissingHeader("From".to_string()))?;
        let typed_from: rsip::typed::From =
            from.typed().map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(typed_from.uri)
    }

    /// Get the To URI.
    pub fn to_uri(&self) -> Result<rsip::Uri> {
        let to = self
            .inner
            .to_header()
            .map_err(|_| SipError::MissingHeader("To".to_string()))?;
        let typed_to: rsip::typed::To = to.typed().map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(typed_to.uri)
    }

    /// Get the Contact URI if present.
    pub fn contact_uri(&self) -> Option<rsip::Uri> {
        self.inner
            .contact_header()
            .ok()
            .and_then(|h| h.typed().ok())
            .map(|typed: rsip::typed::Contact| typed.uri)
    }

    /// Get the message body.
    pub fn body(&self) -> &[u8] {
        &self.inner.body
    }

    /// Get the Content-Type header.
    pub fn content_type(&self) -> Option<String> {
        // Find Content-Type header in the headers list
        for header in self.inner.headers.iter() {
            if let rsip::Header::ContentType(ct) = header {
                return Some(ct.to_string());
            }
        }
        None
    }

    /// Get Record-Route headers as string values.
    ///
    /// Returns a vector of Record-Route header values for extracting route set.
    pub fn record_routes(&self) -> Vec<String> {
        let mut routes = Vec::new();
        for header in self.inner.headers.iter() {
            if let rsip::Header::RecordRoute(rr) = header {
                routes.push(rr.to_string());
            }
        }
        routes
    }

    /// Get Via headers as string values.
    pub fn via_headers_raw(&self) -> Vec<String> {
        let mut vias = Vec::new();
        for header in self.inner.headers.iter() {
            if let rsip::Header::Via(v) = header {
                vias.push(v.to_string());
            }
        }
        vias
    }

    /// Convert to bytes.
    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(self.inner.to_string())
    }

    /// Get the inner rsip request (for advanced use).
    pub fn inner(&self) -> &rsip::Request {
        &self.inner
    }

    /// Create a builder for a new request.
    pub fn builder() -> SipRequestBuilder {
        SipRequestBuilder::new()
    }
}

/// SIP response wrapper.
#[derive(Debug, Clone)]
pub struct SipResponse {
    inner: rsip::Response,
}

impl SipResponse {
    /// Get the status code.
    pub fn status_code(&self) -> u16 {
        self.inner.status_code.code()
    }

    /// Get the reason phrase.
    pub fn reason(&self) -> String {
        // Extract the reason phrase from the status code Display format
        let s = self.inner.status_code.to_string();
        // Format is "CODE REASON", so split and take the rest
        let reason = s.split_once(' ').map(|(_, reason)| reason).unwrap_or(&s);
        reason.to_string()
    }

    /// Check if this is a provisional response (1xx).
    pub fn is_provisional(&self) -> bool {
        let code = self.status_code();
        (100..200).contains(&code)
    }

    /// Check if this is a success response (2xx).
    pub fn is_success(&self) -> bool {
        let code = self.status_code();
        (200..300).contains(&code)
    }

    /// Check if this is a failure response (3xx-6xx).
    pub fn is_failure(&self) -> bool {
        let code = self.status_code();
        code >= 300
    }

    /// Get the Call-ID header value.
    pub fn call_id(&self) -> Result<String> {
        self.inner
            .call_id_header()
            .map(|h| h.value().to_string())
            .map_err(|_| SipError::MissingHeader("Call-ID".to_string()).into())
    }

    /// Get the From tag.
    pub fn from_tag(&self) -> Result<String> {
        let from = self
            .inner
            .from_header()
            .map_err(|_| SipError::MissingHeader("From".to_string()))?;
        let typed_from: rsip::typed::From =
            from.typed().map_err(|e| SipError::Parse(e.to_string()))?;
        let tag = typed_from
            .tag()
            .map(|t| t.to_string())
            .ok_or_else(|| SipError::InvalidHeader("From header missing tag".to_string()))?;
        Ok(tag)
    }

    /// Get the To tag.
    pub fn to_tag(&self) -> Option<String> {
        self.inner
            .to_header()
            .ok()
            .and_then(|h| h.typed().ok())
            .and_then(|typed: rsip::typed::To| typed.tag().map(|t| t.to_string()))
    }

    /// Get the Via branch parameter.
    pub fn via_branch(&self) -> Result<String> {
        let via = self
            .inner
            .via_header()
            .map_err(|_| SipError::MissingHeader("Via".to_string()))?;
        let typed_via: rsip::typed::Via =
            via.typed().map_err(|e| SipError::Parse(e.to_string()))?;
        let branch = typed_via
            .branch()
            .map(|b| b.to_string())
            .ok_or_else(|| SipError::InvalidHeader("Via header missing branch".to_string()))?;
        Ok(branch)
    }

    /// Get the CSeq number.
    pub fn cseq(&self) -> Result<u32> {
        let cseq = self
            .inner
            .cseq_header()
            .map_err(|_| SipError::MissingHeader("CSeq".to_string()))?;
        let typed_cseq: rsip::typed::CSeq =
            cseq.typed().map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(typed_cseq.seq)
    }

    /// Get the CSeq method.
    pub fn cseq_method(&self) -> Result<Method> {
        let cseq = self
            .inner
            .cseq_header()
            .map_err(|_| SipError::MissingHeader("CSeq".to_string()))?;
        let typed_cseq: rsip::typed::CSeq =
            cseq.typed().map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(Method::from(&typed_cseq.method))
    }

    /// Get the Contact URI if present.
    pub fn contact_uri(&self) -> Option<rsip::Uri> {
        self.inner
            .contact_header()
            .ok()
            .and_then(|h| h.typed().ok())
            .map(|typed: rsip::typed::Contact| typed.uri)
    }

    /// Get the message body.
    pub fn body(&self) -> &[u8] {
        &self.inner.body
    }

    /// Get the Content-Type header.
    pub fn content_type(&self) -> Option<String> {
        for header in self.inner.headers.iter() {
            if let rsip::Header::ContentType(ct) = header {
                return Some(ct.to_string());
            }
        }
        None
    }

    /// Get Record-Route headers as string values.
    ///
    /// Returns a vector of Record-Route header values for extracting route set.
    pub fn record_routes(&self) -> Vec<String> {
        let mut routes = Vec::new();
        for header in self.inner.headers.iter() {
            if let rsip::Header::RecordRoute(rr) = header {
                routes.push(rr.to_string());
            }
        }
        routes
    }

    /// Get Via headers as string values.
    pub fn via_headers_raw(&self) -> Vec<String> {
        let mut vias = Vec::new();
        for header in self.inner.headers.iter() {
            if let rsip::Header::Via(v) = header {
                vias.push(v.to_string());
            }
        }
        vias
    }

    /// Get the WWW-Authenticate header value.
    ///
    /// Used to extract digest authentication challenge from 401 responses.
    pub fn www_authenticate(&self) -> Option<String> {
        for header in self.inner.headers.iter() {
            if let rsip::Header::WwwAuthenticate(auth) = header {
                return Some(auth.value().to_string());
            }
        }
        None
    }

    /// Get the Proxy-Authenticate header value.
    ///
    /// Used to extract digest authentication challenge from 407 responses.
    pub fn proxy_authenticate(&self) -> Option<String> {
        for header in self.inner.headers.iter() {
            if let rsip::Header::ProxyAuthenticate(auth) = header {
                return Some(auth.value().to_string());
            }
        }
        None
    }

    /// Convert to bytes.
    pub fn to_bytes(&self) -> Bytes {
        Bytes::from(self.inner.to_string())
    }

    /// Get the inner rsip response (for advanced use).
    pub fn inner(&self) -> &rsip::Response {
        &self.inner
    }

    /// Create a builder for a new response.
    pub fn builder() -> SipResponseBuilder {
        SipResponseBuilder::new()
    }
}

/// SIP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// INVITE — initiates a session (RFC 3261 §13).
    Invite,
    /// ACK — confirms receipt of a final response to INVITE (RFC 3261 §17).
    Ack,
    /// BYE — terminates an established session (RFC 3261 §15).
    Bye,
    /// CANCEL — cancels an in-flight request (RFC 3261 §9).
    Cancel,
    /// REGISTER — binds a contact address to an address-of-record (RFC 3261 §10).
    Register,
    /// OPTIONS — queries a peer's capabilities (RFC 3261 §11).
    Options,
    /// PRACK — provisional response acknowledgement (RFC 3262).
    Prack,
    /// SUBSCRIBE — requests notification of an event package (RFC 3265/6665).
    Subscribe,
    /// NOTIFY — delivers an event-package notification to a subscriber (RFC 3265/6665).
    Notify,
    /// PUBLISH — publishes event state to a server (RFC 3903).
    Publish,
    /// INFO — sends mid-dialog application information (RFC 6086).
    Info,
    /// REFER — asks the recipient to issue a request to a third party (RFC 3515).
    Refer,
    /// MESSAGE — carries an instant message payload (RFC 3428).
    Message,
    /// UPDATE — modifies session state without affecting dialog state (RFC 3311).
    Update,
}

impl Method {
    /// Convert to rsip method.
    pub fn to_rsip(&self) -> rsip::Method {
        match self {
            Method::Invite => rsip::Method::Invite,
            Method::Ack => rsip::Method::Ack,
            Method::Bye => rsip::Method::Bye,
            Method::Cancel => rsip::Method::Cancel,
            Method::Register => rsip::Method::Register,
            Method::Options => rsip::Method::Options,
            Method::Prack => rsip::Method::PRack,
            Method::Subscribe => rsip::Method::Subscribe,
            Method::Notify => rsip::Method::Notify,
            Method::Publish => rsip::Method::Publish,
            Method::Info => rsip::Method::Info,
            Method::Refer => rsip::Method::Refer,
            Method::Message => rsip::Method::Message,
            Method::Update => rsip::Method::Update,
        }
    }

    /// Check if this method creates a dialog.
    pub fn creates_dialog(&self) -> bool {
        matches!(self, Method::Invite | Method::Subscribe)
    }

    /// Check if this is an INVITE method.
    pub fn is_invite(&self) -> bool {
        matches!(self, Method::Invite)
    }
}

impl From<&rsip::Method> for Method {
    fn from(m: &rsip::Method) -> Self {
        match m {
            rsip::Method::Invite => Method::Invite,
            rsip::Method::Ack => Method::Ack,
            rsip::Method::Bye => Method::Bye,
            rsip::Method::Cancel => Method::Cancel,
            rsip::Method::Register => Method::Register,
            rsip::Method::Options => Method::Options,
            rsip::Method::PRack => Method::Prack,
            rsip::Method::Subscribe => Method::Subscribe,
            rsip::Method::Notify => Method::Notify,
            rsip::Method::Publish => Method::Publish,
            rsip::Method::Info => Method::Info,
            rsip::Method::Refer => Method::Refer,
            rsip::Method::Message => Method::Message,
            rsip::Method::Update => Method::Update,
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Method::Invite => "INVITE",
            Method::Ack => "ACK",
            Method::Bye => "BYE",
            Method::Cancel => "CANCEL",
            Method::Register => "REGISTER",
            Method::Options => "OPTIONS",
            Method::Prack => "PRACK",
            Method::Subscribe => "SUBSCRIBE",
            Method::Notify => "NOTIFY",
            Method::Publish => "PUBLISH",
            Method::Info => "INFO",
            Method::Refer => "REFER",
            Method::Message => "MESSAGE",
            Method::Update => "UPDATE",
        };
        write!(f, "{}", s)
    }
}

/// Builder for SIP requests.
#[derive(Debug, Default)]
pub struct SipRequestBuilder {
    method: Option<rsip::Method>,
    uri: Option<rsip::Uri>,
    uri_error: Option<String>,
    via_branch: Option<String>,
    via_host: Option<String>,
    via_port: Option<u16>,
    via_transport: Option<String>,
    from_uri: Option<rsip::Uri>,
    from_uri_error: Option<String>,
    from_tag: Option<String>,
    from_display: Option<String>,
    to_uri: Option<rsip::Uri>,
    to_uri_error: Option<String>,
    to_tag: Option<String>,
    call_id: Option<String>,
    cseq: Option<u32>,
    contact_uri: Option<rsip::Uri>,
    max_forwards: Option<u32>,
    body: Option<Vec<u8>>,
    content_type: Option<String>,
    authorization: Option<String>,
    proxy_authorization: Option<String>,
    expires: Option<u32>,
}

impl SipRequestBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the method.
    pub fn method(mut self, method: Method) -> Self {
        self.method = Some(method.to_rsip());
        self
    }

    /// Set the request URI.
    ///
    /// The URI should be a valid SIP URI (e.g., "sip:user@host").
    /// If the URI is invalid, an error will be returned when `build()` is called.
    pub fn uri(mut self, uri: &str) -> Self {
        match rsip::Uri::try_from(uri) {
            Ok(u) => {
                self.uri = Some(u);
                self.uri_error = None;
            }
            Err(e) => {
                self.uri_error = Some(format!("Invalid request URI '{}': {}", uri, e));
            }
        }
        self
    }

    /// Set the Via header.
    pub fn via(mut self, host: &str, port: u16, transport: &str, branch: &str) -> Self {
        self.via_host = Some(host.to_string());
        self.via_port = Some(port);
        self.via_transport = Some(transport.to_string());
        self.via_branch = Some(branch.to_string());
        self
    }

    /// Set the From header.
    ///
    /// The URI should be a valid SIP URI (e.g., "sip:user@host").
    pub fn from(mut self, uri: &str, tag: &str) -> Self {
        match rsip::Uri::try_from(uri) {
            Ok(u) => {
                self.from_uri = Some(u);
                self.from_uri_error = None;
            }
            Err(e) => {
                self.from_uri_error = Some(format!("Invalid From URI '{}': {}", uri, e));
            }
        }
        self.from_tag = Some(tag.to_string());
        self
    }

    /// Set the From display name.
    pub fn from_display(mut self, name: &str) -> Self {
        self.from_display = Some(name.to_string());
        self
    }

    /// Set the To header.
    ///
    /// The URI should be a valid SIP URI (e.g., "sip:user@host").
    pub fn to(mut self, uri: &str) -> Self {
        match rsip::Uri::try_from(uri) {
            Ok(u) => {
                self.to_uri = Some(u);
                self.to_uri_error = None;
            }
            Err(e) => {
                self.to_uri_error = Some(format!("Invalid To URI '{}': {}", uri, e));
            }
        }
        self
    }

    /// Set the To tag.
    pub fn to_tag(mut self, tag: &str) -> Self {
        self.to_tag = Some(tag.to_string());
        self
    }

    /// Set the Call-ID.
    pub fn call_id(mut self, call_id: &str) -> Self {
        self.call_id = Some(call_id.to_string());
        self
    }

    /// Set the CSeq.
    pub fn cseq(mut self, seq: u32) -> Self {
        self.cseq = Some(seq);
        self
    }

    /// Set the Contact header.
    pub fn contact(mut self, uri: &str) -> Self {
        if let Ok(u) = rsip::Uri::try_from(uri) {
            self.contact_uri = Some(u);
        }
        self
    }

    /// Set Max-Forwards.
    pub fn max_forwards(mut self, mf: u32) -> Self {
        self.max_forwards = Some(mf);
        self
    }

    /// Set the body.
    pub fn body(mut self, body: Vec<u8>, content_type: &str) -> Self {
        self.body = Some(body);
        self.content_type = Some(content_type.to_string());
        self
    }

    /// Set the Authorization header for digest authentication.
    pub fn authorization(mut self, auth: &str) -> Self {
        self.authorization = Some(auth.to_string());
        self
    }

    /// Set the Proxy-Authorization header for proxy digest authentication.
    pub fn proxy_authorization(mut self, auth: &str) -> Self {
        self.proxy_authorization = Some(auth.to_string());
        self
    }

    /// Set the Expires header (used for REGISTER).
    pub fn expires(mut self, seconds: u32) -> Self {
        self.expires = Some(seconds);
        self
    }

    /// Build the request.
    pub fn build(self) -> Result<SipRequest> {
        // Check for URI parsing errors first (more informative than "Missing URI")
        if let Some(err) = self.uri_error {
            return Err(SipError::InvalidHeader(err).into());
        }
        if let Some(err) = self.from_uri_error {
            return Err(SipError::InvalidHeader(err).into());
        }
        if let Some(err) = self.to_uri_error {
            return Err(SipError::InvalidHeader(err).into());
        }

        let method = self
            .method
            .ok_or_else(|| SipError::InvalidHeader("Missing method".to_string()))?;
        let uri = self
            .uri
            .ok_or_else(|| SipError::InvalidHeader("Missing request URI".to_string()))?;
        let from_uri = self
            .from_uri
            .ok_or_else(|| SipError::InvalidHeader("Missing From URI".to_string()))?;
        let from_tag = self
            .from_tag
            .ok_or_else(|| SipError::InvalidHeader("Missing From tag".to_string()))?;
        let to_uri = self
            .to_uri
            .ok_or_else(|| SipError::InvalidHeader("Missing To URI".to_string()))?;
        let call_id = self
            .call_id
            .ok_or_else(|| SipError::InvalidHeader("Missing Call-ID".to_string()))?;
        let cseq = self
            .cseq
            .ok_or_else(|| SipError::InvalidHeader("Missing CSeq".to_string()))?;
        let via_host = self
            .via_host
            .ok_or_else(|| SipError::InvalidHeader("Missing Via host".to_string()))?;
        let via_branch = self
            .via_branch
            .ok_or_else(|| SipError::InvalidHeader("Missing Via branch".to_string()))?;

        let mut headers = rsip::Headers::default();

        // Via header
        let via_port = self.via_port.unwrap_or(5060);
        let via_transport = self.via_transport.unwrap_or_else(|| "UDP".to_string());
        let via_str = format!(
            "SIP/2.0/{} {}:{};branch={}",
            via_transport, via_host, via_port, via_branch
        );
        headers.push(rsip::Header::Via(rsip::headers::Via::new(via_str)));

        // From header
        let from_str = if let Some(display) = &self.from_display {
            format!("\"{}\" <{}>;tag={}", display, from_uri, from_tag)
        } else {
            format!("<{}>;tag={}", from_uri, from_tag)
        };
        headers.push(rsip::Header::From(rsip::headers::From::new(from_str)));

        // To header
        let to_str = if let Some(tag) = &self.to_tag {
            format!("<{}>;tag={}", to_uri, tag)
        } else {
            format!("<{}>", to_uri)
        };
        headers.push(rsip::Header::To(rsip::headers::To::new(to_str)));

        // Call-ID header
        headers.push(rsip::Header::CallId(rsip::headers::CallId::new(call_id)));

        // CSeq header
        let cseq_str = format!("{} {}", cseq, method);
        headers.push(rsip::Header::CSeq(rsip::headers::CSeq::new(cseq_str)));

        // Max-Forwards
        let mf = self.max_forwards.unwrap_or(70);
        headers.push(rsip::Header::MaxForwards(rsip::headers::MaxForwards::new(
            mf.to_string(),
        )));

        // Contact header
        if let Some(contact) = self.contact_uri {
            let contact_str = format!("<{}>", contact);
            headers.push(rsip::Header::Contact(rsip::headers::Contact::new(
                contact_str,
            )));
        }

        // Authorization header
        if let Some(auth) = self.authorization {
            headers.push(rsip::Header::Authorization(
                rsip::headers::Authorization::new(auth),
            ));
        }

        // Proxy-Authorization header
        if let Some(auth) = self.proxy_authorization {
            headers.push(rsip::Header::ProxyAuthorization(
                rsip::headers::ProxyAuthorization::new(auth),
            ));
        }

        // Expires header
        if let Some(expires) = self.expires {
            headers.push(rsip::Header::Expires(rsip::headers::Expires::new(
                expires.to_string(),
            )));
        }

        // Content-Type and Content-Length
        let body = self.body.unwrap_or_default();
        if !body.is_empty() {
            if let Some(ct) = self.content_type {
                headers.push(rsip::Header::ContentType(rsip::headers::ContentType::new(
                    ct,
                )));
            } else {
                cover_none_case();
            }
        }
        headers.push(rsip::Header::ContentLength(
            rsip::headers::ContentLength::new(body.len().to_string()),
        ));

        let req = rsip::Request {
            method,
            uri,
            version: rsip::Version::V2,
            headers,
            body,
        };

        Ok(SipRequest { inner: req })
    }
}

/// Builder for SIP responses.
#[derive(Debug, Default)]
pub struct SipResponseBuilder {
    status_code: Option<u16>,
    reason: Option<String>,
    via: Vec<String>,
    from: Option<String>,
    to: Option<String>,
    call_id: Option<String>,
    cseq: Option<String>,
    contact_uri: Option<rsip::Uri>,
    body: Option<Vec<u8>>,
    content_type: Option<String>,
}

impl SipResponseBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the status code and reason.
    pub fn status(mut self, code: u16, reason: &str) -> Self {
        self.status_code = Some(code);
        self.reason = Some(reason.to_string());
        self
    }

    /// Copy headers from a request (for building response to request).
    pub fn from_request(mut self, req: &SipRequest) -> Self {
        // Copy Via headers
        for header in req.inner.headers.iter() {
            if let rsip::Header::Via(v) = header {
                if let Ok(typed) = v.typed() {
                    self.via.push(typed.to_string());
                } else {
                    self.via.push(v.to_string());
                }
            }
        }

        // Copy From
        for header in req.inner.headers.iter() {
            if let rsip::Header::From(f) = header {
                self.from = Some(f.to_string());
                break;
            }
        }

        // Copy To
        for header in req.inner.headers.iter() {
            if let rsip::Header::To(t) = header {
                self.to = Some(t.to_string());
                break;
            }
        }

        // Copy Call-ID
        for header in req.inner.headers.iter() {
            if let rsip::Header::CallId(c) = header {
                self.call_id = Some(c.value().to_string());
                break;
            }
        }

        // Copy CSeq
        for header in req.inner.headers.iter() {
            if let rsip::Header::CSeq(c) = header {
                if let (Ok(seq), Ok(method)) = (req.cseq(), req.cseq_method()) {
                    self.cseq = Some(format!("{} {}", seq, method));
                } else {
                    self.cseq = Some(c.to_string());
                }
                break;
            }
        }

        self
    }

    /// Set the To tag.
    pub fn to_tag(mut self, tag: &str) -> Self {
        if let Some(ref mut to) = self.to {
            if !to.contains("tag=") {
                *to = format!("{};tag={}", to, tag);
            }
        } else {
            cover_none_case();
        }
        self
    }

    /// Set the Contact header.
    pub fn contact(mut self, uri: &str) -> Self {
        if let Ok(u) = rsip::Uri::try_from(uri) {
            self.contact_uri = Some(u);
        }
        self
    }

    /// Set the body.
    pub fn body(mut self, body: Vec<u8>, content_type: &str) -> Self {
        self.body = Some(body);
        self.content_type = Some(content_type.to_string());
        self
    }

    /// Build the response.
    pub fn build(self) -> Result<SipResponse> {
        let status_code = self
            .status_code
            .ok_or_else(|| SipError::InvalidHeader("Missing status code".to_string()))?;

        let mut headers = rsip::Headers::default();

        // Via headers (in order)
        for via in &self.via {
            headers.push(rsip::Header::Via(rsip::headers::Via::new(via.clone())));
        }

        // From header
        if let Some(from) = self.from {
            headers.push(rsip::Header::From(rsip::headers::From::new(from)));
        }

        // To header
        if let Some(to) = self.to {
            headers.push(rsip::Header::To(rsip::headers::To::new(to)));
        }

        // Call-ID header
        if let Some(call_id) = self.call_id {
            headers.push(rsip::Header::CallId(rsip::headers::CallId::new(call_id)));
        }

        // CSeq header
        if let Some(cseq) = self.cseq {
            headers.push(rsip::Header::CSeq(rsip::headers::CSeq::new(cseq)));
        }

        // Contact header
        if let Some(contact) = self.contact_uri {
            let contact_str = format!("<{}>", contact);
            headers.push(rsip::Header::Contact(rsip::headers::Contact::new(
                contact_str,
            )));
        }

        // Content-Type and Content-Length
        let body = self.body.unwrap_or_default();
        if !body.is_empty() {
            if let Some(ct) = self.content_type {
                headers.push(rsip::Header::ContentType(rsip::headers::ContentType::new(
                    ct,
                )));
            } else {
                cover_none_case();
            }
        }
        headers.push(rsip::Header::ContentLength(
            rsip::headers::ContentLength::new(body.len().to_string()),
        ));

        let status = rsip::StatusCode::from(status_code);

        let resp = rsip::Response {
            status_code: status,
            version: rsip::Version::V2,
            headers,
            body,
        };

        Ok(SipResponse { inner: resp })
    }
}

/// Generate a unique branch parameter for Via header.
pub fn generate_branch() -> String {
    format!("z9hG4bK{}", uuid::Uuid::new_v4().simple())
}

/// Generate a unique tag for From/To headers.
///
/// Uses 64 bits of OS-seeded randomness via `rand::thread_rng()` so that
/// rapid-fire calls cannot collide. The previous implementation derived the
/// tag purely from `SystemTime::now()`, which produced duplicates on
/// platforms where the wall-clock resolution was coarser than the time
/// between two adjacent calls (observed on macOS).
pub fn generate_tag() -> String {
    use rand::RngCore;
    format!("{:x}", rand::thread_rng().next_u64())
}

/// Generate a unique Call-ID.
pub fn generate_call_id(domain: &str) -> String {
    format!("{}@{}", uuid::Uuid::new_v4().simple(), domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE_MSG: &[u8] = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:alice@pc33.atlanta.com>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 0\r\n\
\r\n";

    const RESPONSE_MSG: &[u8] = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds;received=192.0.2.1\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Contact: <sip:bob@192.0.2.4>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 0\r\n\
\r\n";

    fn replace_header(msg: &[u8], old: &str, new: &str) -> Vec<u8> {
        let msg_str = String::from_utf8_lossy(msg);
        msg_str.replace(old, new).into_bytes()
    }

    // SipMessage tests
    #[test]
    fn test_parse_invite() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        assert!(msg.is_request());

        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Invite);
        assert!(req.call_id().unwrap().contains("a84b4c76e66710"));
        assert_eq!(req.from_tag().unwrap(), "1928301774");
        assert!(req.to_tag().is_none());
        assert_eq!(req.via_branch().unwrap(), "z9hG4bK776asdhds");
        assert_eq!(req.cseq().unwrap(), 314159);
        assert_eq!(req.cseq_method().unwrap(), Method::Invite);
    }

    #[test]
    fn test_parse_response() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        assert!(msg.is_response());

        let resp = msg.as_response().unwrap();
        assert_eq!(resp.status_code(), 200);
        assert!(resp.is_success());
        assert!(!resp.is_provisional());
        assert!(!resp.is_failure());
        assert!(resp.call_id().unwrap().contains("a84b4c76e66710"));
        assert_eq!(resp.from_tag().unwrap(), "1928301774");
        assert_eq!(resp.to_tag(), Some("a6c85cf".to_string()));
        assert_eq!(resp.via_branch().unwrap(), "z9hG4bK776asdhds");
    }

    #[test]
    fn test_sip_message_parse_invalid() {
        let result = SipMessage::parse(b"invalid data");
        assert!(result.is_err());
    }

    #[test]
    fn test_sip_message_is_request_on_response() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        assert!(!msg.is_request());
    }

    #[test]
    fn test_sip_message_is_request_on_request() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        assert!(msg.is_request());
    }

    #[test]
    fn test_sip_message_is_response_on_request() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        assert!(!msg.is_response());
    }

    #[test]
    fn test_sip_message_is_response_on_response() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        assert!(msg.is_response());
    }

    #[test]
    fn test_sip_message_as_request_on_response() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        assert!(msg.as_request().is_none());
    }

    #[test]
    fn test_sip_message_as_response_on_request() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        assert!(msg.as_response().is_none());
    }

    #[test]
    fn test_sip_message_to_bytes_request() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let bytes = msg.to_bytes();
        assert!(!bytes.is_empty());
        assert!(bytes.starts_with(b"INVITE"));
    }

    #[test]
    fn test_sip_message_to_bytes_response() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let bytes = msg.to_bytes();
        assert!(!bytes.is_empty());
        assert!(bytes.starts_with(b"SIP/2.0"));
    }

    #[test]
    fn test_sip_message_clone() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let cloned = msg.clone();
        assert!(cloned.is_request());
    }

    // SipRequest tests
    #[test]
    fn test_request_uri() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let uri = req.uri();
        assert!(uri.to_string().contains("bob@biloxi.com"));
    }

    #[test]
    fn test_request_from_uri() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let uri = req.from_uri().unwrap();
        assert!(uri.to_string().contains("alice@atlanta.com"));
    }

    #[test]
    fn test_request_to_uri() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let uri = req.to_uri().unwrap();
        assert!(uri.to_string().contains("bob@biloxi.com"));
    }

    #[test]
    fn test_request_contact_uri() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let contact = req.contact_uri();
        assert!(contact.is_some());
    }

    #[test]
    fn test_request_body() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.body().is_empty());
    }

    #[test]
    fn test_request_content_type() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let ct = req.content_type();
        assert!(ct.is_some());
        assert!(ct.unwrap().contains("application/sdp"));
    }

    #[test]
    fn test_request_record_routes() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let routes = req.record_routes();
        // INVITE_MSG doesn't have Record-Route headers
        assert!(routes.is_empty());
    }

    #[test]
    fn test_request_via_headers_raw() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let vias = req.via_headers_raw();
        assert!(!vias.is_empty());
        assert!(vias[0].contains("pc33.atlanta.com"));
    }

    #[test]
    fn test_request_from_tag_invalid_header() {
        let msg = replace_header(
            INVITE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "From: <sip:alice@[::1>\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.from_tag().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_request_from_tag_missing_header() {
        let msg = replace_header(
            INVITE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.from_tag().unwrap_err();
        assert!(err.to_string().contains("Missing required header"));
    }

    #[test]
    fn test_request_from_tag_and_uri_success() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let (tag, uri) = req.from_tag_and_uri().unwrap();
        assert_eq!(tag, "1928301774");
        assert_eq!(uri.to_string(), "sip:alice@atlanta.com");
    }

    #[test]
    fn test_request_from_tag_and_uri_invalid_header() {
        let msg = replace_header(
            INVITE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "From: <sip:alice@[::1>\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.from_tag_and_uri().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_request_from_tag_and_uri_missing_header() {
        let msg = replace_header(
            INVITE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.from_tag_and_uri().unwrap_err();
        assert!(err.to_string().contains("Missing required header"));
    }

    #[test]
    fn test_request_from_tag_and_uri_missing_tag() {
        let msg = replace_header(
            INVITE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "From: Alice <sip:alice@atlanta.com>\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.from_tag_and_uri().unwrap_err();
        assert!(err.to_string().to_lowercase().contains("missing tag"));
    }

    #[test]
    fn test_request_from_uri_invalid_header() {
        let msg = replace_header(
            INVITE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "From: <sip:alice@[::1>\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.from_uri().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_request_to_uri_invalid_header() {
        let msg = replace_header(
            INVITE_MSG,
            "To: Bob <sip:bob@biloxi.com>\r\n",
            "To: <sip:bob@[::1>\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.to_uri().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_request_via_branch_invalid_header() {
        let msg = replace_header(
            INVITE_MSG,
            "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n",
            "Via: invalid\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let req = msg.as_request().unwrap();
        let err = req.via_branch().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_request_inner() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let inner = req.inner();
        assert_eq!(inner.method, rsip::Method::Invite);
    }

    // SipResponse tests
    #[test]
    fn test_response_reason() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let reason = resp.reason();
        assert!(reason.contains("OK"));
    }

    #[test]
    fn test_response_is_provisional() {
        let provisional = b"SIP/2.0 180 Ringing\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(provisional).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.is_provisional());
        assert!(!resp.is_success());
        assert!(!resp.is_failure());
    }

    #[test]
    fn test_response_is_failure() {
        let failure = b"SIP/2.0 404 Not Found\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(failure).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.is_failure());
        assert!(!resp.is_success());
        assert!(!resp.is_provisional());
    }

    #[test]
    fn test_response_cseq() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        assert_eq!(resp.cseq().unwrap(), 314159);
    }

    #[test]
    fn test_response_cseq_method() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        assert_eq!(resp.cseq_method().unwrap(), Method::Invite);
    }

    #[test]
    fn test_response_from_tag_invalid_header() {
        let msg = replace_header(
            RESPONSE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "From: <sip:alice@[::1>\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let resp = msg.as_response().unwrap();
        let err = resp.from_tag().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_response_from_tag_missing_header() {
        let msg = replace_header(
            RESPONSE_MSG,
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            "",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let resp = msg.as_response().unwrap();
        let err = resp.from_tag().unwrap_err();
        assert!(err.to_string().contains("Missing required header"));
    }

    #[test]
    fn test_response_via_branch_invalid_header() {
        let msg = replace_header(
            RESPONSE_MSG,
            "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds;received=192.0.2.1\r\n",
            "Via: invalid\r\n",
        );
        let msg = SipMessage::parse(&msg).unwrap();
        let resp = msg.as_response().unwrap();
        let err = resp.via_branch().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_response_cseq_invalid_header() {
        let msg = replace_header(RESPONSE_MSG, "CSeq: 314159 INVITE\r\n", "CSeq: invalid\r\n");
        let msg = SipMessage::parse(&msg).unwrap();
        let resp = msg.as_response().unwrap();
        let err = resp.cseq().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_response_cseq_method_invalid_header() {
        let msg = replace_header(RESPONSE_MSG, "CSeq: 314159 INVITE\r\n", "CSeq: invalid\r\n");
        let msg = SipMessage::parse(&msg).unwrap();
        let resp = msg.as_response().unwrap();
        let err = resp.cseq_method().unwrap_err();
        assert!(err.to_string().contains("Parse error"));
    }

    #[test]
    fn test_response_contact_uri() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let contact = resp.contact_uri();
        assert!(contact.is_some());
    }

    #[test]
    fn test_response_body() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.body().is_empty());
    }

    #[test]
    fn test_response_content_type() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let ct = resp.content_type();
        assert!(ct.is_some());
    }

    #[test]
    fn test_response_record_routes() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let routes = resp.record_routes();
        assert!(routes.is_empty());
    }

    #[test]
    fn test_response_via_headers_raw() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let vias = resp.via_headers_raw();
        assert!(!vias.is_empty());
    }

    #[test]
    fn test_response_www_authenticate_none() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.www_authenticate().is_none());
    }

    #[test]
    fn test_response_proxy_authenticate_none() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.proxy_authenticate().is_none());
    }

    #[test]
    fn test_response_inner() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let inner = resp.inner();
        assert_eq!(inner.status_code.code(), 200);
    }

    // Method tests
    #[test]
    fn test_method_display() {
        assert_eq!(format!("{}", Method::Invite), "INVITE");
        assert_eq!(format!("{}", Method::Ack), "ACK");
        assert_eq!(format!("{}", Method::Register), "REGISTER");
        assert_eq!(format!("{}", Method::Bye), "BYE");
        assert_eq!(format!("{}", Method::Cancel), "CANCEL");
        assert_eq!(format!("{}", Method::Options), "OPTIONS");
        assert_eq!(format!("{}", Method::Prack), "PRACK");
        assert_eq!(format!("{}", Method::Subscribe), "SUBSCRIBE");
        assert_eq!(format!("{}", Method::Notify), "NOTIFY");
        assert_eq!(format!("{}", Method::Publish), "PUBLISH");
        assert_eq!(format!("{}", Method::Info), "INFO");
        assert_eq!(format!("{}", Method::Refer), "REFER");
        assert_eq!(format!("{}", Method::Message), "MESSAGE");
        assert_eq!(format!("{}", Method::Update), "UPDATE");
    }

    #[test]
    fn test_method_creates_dialog() {
        assert!(Method::Invite.creates_dialog());
        assert!(Method::Subscribe.creates_dialog());
        assert!(!Method::Register.creates_dialog());
        assert!(!Method::Options.creates_dialog());
    }

    #[test]
    fn test_method_is_invite() {
        assert!(Method::Invite.is_invite());
        assert!(!Method::Register.is_invite());
        assert!(!Method::Bye.is_invite());
    }

    #[test]
    fn test_method_to_rsip() {
        assert_eq!(Method::Invite.to_rsip(), rsip::Method::Invite);
        assert_eq!(Method::Ack.to_rsip(), rsip::Method::Ack);
        assert_eq!(Method::Bye.to_rsip(), rsip::Method::Bye);
        assert_eq!(Method::Cancel.to_rsip(), rsip::Method::Cancel);
        assert_eq!(Method::Register.to_rsip(), rsip::Method::Register);
        assert_eq!(Method::Options.to_rsip(), rsip::Method::Options);
        assert_eq!(Method::Prack.to_rsip(), rsip::Method::PRack);
        assert_eq!(Method::Subscribe.to_rsip(), rsip::Method::Subscribe);
        assert_eq!(Method::Notify.to_rsip(), rsip::Method::Notify);
        assert_eq!(Method::Publish.to_rsip(), rsip::Method::Publish);
        assert_eq!(Method::Info.to_rsip(), rsip::Method::Info);
        assert_eq!(Method::Refer.to_rsip(), rsip::Method::Refer);
        assert_eq!(Method::Message.to_rsip(), rsip::Method::Message);
        assert_eq!(Method::Update.to_rsip(), rsip::Method::Update);
    }

    #[test]
    fn test_method_from_rsip() {
        assert_eq!(Method::from(&rsip::Method::Invite), Method::Invite);
        assert_eq!(Method::from(&rsip::Method::Ack), Method::Ack);
        assert_eq!(Method::from(&rsip::Method::Bye), Method::Bye);
        assert_eq!(Method::from(&rsip::Method::Cancel), Method::Cancel);
        assert_eq!(Method::from(&rsip::Method::Register), Method::Register);
        assert_eq!(Method::from(&rsip::Method::Options), Method::Options);
        assert_eq!(Method::from(&rsip::Method::PRack), Method::Prack);
        assert_eq!(Method::from(&rsip::Method::Subscribe), Method::Subscribe);
        assert_eq!(Method::from(&rsip::Method::Notify), Method::Notify);
        assert_eq!(Method::from(&rsip::Method::Publish), Method::Publish);
        assert_eq!(Method::from(&rsip::Method::Info), Method::Info);
        assert_eq!(Method::from(&rsip::Method::Refer), Method::Refer);
        assert_eq!(Method::from(&rsip::Method::Message), Method::Message);
        assert_eq!(Method::from(&rsip::Method::Update), Method::Update);
    }

    #[test]
    fn test_method_clone() {
        let m = Method::Invite;
        let cloned = m;
        assert_eq!(m, cloned);
    }

    #[test]
    fn test_method_debug() {
        let m = Method::Invite;
        let debug = format!("{:?}", m);
        assert!(debug.contains("Invite"));
    }

    // Builder tests
    #[test]
    fn test_build_request() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest123")
            .from("sip:alice@example.com", "fromtag1")
            .to("sip:bob@example.com")
            .call_id("testcall@example.com")
            .cseq(1)
            .contact("sip:alice@192.168.1.1:5060")
            .build()
            .unwrap();

        assert_eq!(req.method(), Method::Invite);
        assert!(req.call_id().unwrap().contains("testcall"));
        assert_eq!(req.from_tag().unwrap(), "fromtag1");
        assert_eq!(req.cseq().unwrap(), 1);
    }

    #[test]
    fn test_build_request_with_display_name() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .from_display("Alice")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("\"Alice\""));
    }

    #[test]
    fn test_build_request_with_to_tag() {
        let req = SipRequest::builder()
            .method(Method::Ack)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .to_tag("totag1")
            .call_id("call@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("tag=totag1"));
    }

    #[test]
    fn test_build_request_with_body() {
        let sdp = b"v=0\r\no=- 123 456 IN IP4 192.168.1.1\r\n".to_vec();
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .body(sdp.clone(), "application/sdp")
            .build()
            .unwrap();

        assert_eq!(req.body(), &sdp[..]);
    }

    #[test]
    fn test_build_request_with_authorization() {
        let req = SipRequest::builder()
            .method(Method::Register)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:alice@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .authorization("Digest username=\"alice\"")
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("Authorization"));
    }

    #[test]
    fn test_build_request_with_proxy_authorization() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .proxy_authorization("Digest username=\"alice\"")
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("Proxy-Authorization"));
    }

    #[test]
    fn test_build_request_with_expires() {
        let req = SipRequest::builder()
            .method(Method::Register)
            .uri("sip:example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:alice@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .expires(3600)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("Expires"));
    }

    #[test]
    fn test_build_request_with_max_forwards() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .max_forwards(50)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("Max-Forwards: 50"));
    }

    #[test]
    fn test_build_request_missing_method() {
        let result = SipRequest::builder()
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_missing_uri() {
        // Test when URI is not provided at all
        let result = SipRequest::builder()
            .method(Method::Invite)
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_missing_from() {
        // Test when From URI is not provided
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_missing_to() {
        // Test when To URI is not provided
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_response() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .to_tag("totag123")
            .contact("sip:bob@192.168.1.2:5060")
            .build()
            .unwrap();

        assert_eq!(resp.status_code(), 200);
        assert!(resp.is_success());
        assert!(resp.call_id().unwrap().contains("a84b4c76e66710"));
        assert_eq!(resp.to_tag(), Some("totag123".to_string()));
    }

    #[test]
    fn test_build_response_with_body() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        let sdp = b"v=0\r\n".to_vec();
        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .body(sdp.clone(), "application/sdp")
            .build()
            .unwrap();

        assert_eq!(resp.body(), &sdp[..]);
    }

    #[test]
    fn test_build_response_body_without_content_type() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        let mut builder = SipResponse::builder().status(200, "OK").from_request(req);
        builder.body = Some(b"payload".to_vec());
        builder.content_type = None;

        let resp = builder.build().unwrap();
        assert_eq!(resp.body(), b"payload");
        assert!(resp.content_type().is_none());
    }

    #[test]
    fn test_build_response_invalid_contact_uri() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .contact("sip:alice@[::1")
            .build()
            .unwrap();

        assert!(resp.contact_uri().is_none());
    }

    #[test]
    fn test_build_response_valid_contact_uri() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .to_tag("totag")
            .contact("sip:alice@192.168.1.1:5060")
            .build()
            .unwrap();

        assert!(resp.contact_uri().is_some());
    }

    #[test]
    fn test_response_builder_from_request_invalid_via() {
        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: invalid-via\r\n\
To: <sip:bob@example.com>\r\n\
From: <sip:alice@example.com>;tag=tag1\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(raw).unwrap();
        let req = msg.as_request().unwrap();
        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .build()
            .unwrap();

        let vias: Vec<String> = resp
            .inner
            .headers
            .iter()
            .filter_map(|h| {
                if let rsip::Header::Via(v) = h {
                    Some(v.to_string())
                } else {
                    None
                }
            })
            .collect();
        assert!(vias.iter().any(|via| via.contains("invalid-via")));
    }

    #[test]
    fn test_response_builder_from_request_invalid_cseq() {
        let raw = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: <sip:bob@example.com>\r\n\
From: <sip:alice@example.com>;tag=tag1\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: bad\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(raw).unwrap();
        let req = msg.as_request().unwrap();
        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .build()
            .unwrap();

        let cseq = resp
            .inner
            .headers
            .iter()
            .find_map(|h| {
                if let rsip::Header::CSeq(cseq) = h {
                    Some(cseq.to_string())
                } else {
                    None
                }
            })
            .unwrap();
        assert!(cseq.contains("bad"));
    }

    #[test]
    fn test_build_response_missing_status() {
        let result = SipResponse::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_response_to_tag_without_to_header() {
        let resp = SipResponse::builder()
            .status(200, "OK")
            .to_tag("tag1")
            .build()
            .unwrap();

        assert!(resp.to_tag().is_none());
    }

    #[test]
    fn test_build_response_to_tag_already_present() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        // First add a to_tag, then try to add another
        let resp = SipResponse::builder()
            .status(200, "OK")
            .from_request(req)
            .to_tag("first_tag")
            .to_tag("second_tag") // Should not add another tag
            .build()
            .unwrap();

        let to_tag = resp.to_tag();
        assert!(to_tag.is_some());
    }

    #[test]
    fn test_build_response_to_tag_added_when_missing() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();

        let resp = SipResponse::builder()
            .status(180, "Ringing")
            .from_request(req)
            .to_tag("newtag")
            .build()
            .unwrap();

        assert_eq!(resp.to_tag(), Some("newtag".to_string()));
    }

    #[test]
    fn test_roundtrip() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let bytes = msg.to_bytes();
        let msg2 = SipMessage::parse(&bytes).unwrap();

        let req1 = msg.as_request().unwrap();
        let req2 = msg2.as_request().unwrap();

        assert_eq!(req1.method(), req2.method());
        assert_eq!(req1.call_id().unwrap(), req2.call_id().unwrap());
    }

    // Helper function tests
    #[test]
    fn test_generate_branch() {
        let branch = generate_branch();
        assert!(branch.starts_with("z9hG4bK"));
        assert!(branch.len() > 10);
    }

    #[test]
    fn test_generate_branch_unique() {
        let branch1 = generate_branch();
        let branch2 = generate_branch();
        assert_ne!(branch1, branch2);
    }

    #[test]
    fn test_generate_tag() {
        let tag = generate_tag();
        assert!(!tag.is_empty());
    }

    #[test]
    fn test_generate_tag_unique() {
        let tag1 = generate_tag();
        let tag2 = generate_tag();
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn test_generate_call_id() {
        let call_id = generate_call_id("example.com");
        assert!(call_id.ends_with("@example.com"));
    }

    #[test]
    fn test_generate_call_id_unique() {
        let call_id1 = generate_call_id("example.com");
        let call_id2 = generate_call_id("example.com");
        assert_ne!(call_id1, call_id2);
    }

    #[test]
    fn test_request_builder_default() {
        let builder = SipRequestBuilder::default();
        let debug = format!("{:?}", builder);
        assert!(debug.contains("SipRequestBuilder"));
    }

    #[test]
    fn test_request_builder_missing_from_tag() {
        let mut builder = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com");
        builder.from_uri = Some(rsip::Uri::try_from("sip:alice@example.com").unwrap());
        let err = builder.build().unwrap_err();
        assert!(format!("{err:?}").contains("InvalidHeader"));
    }

    #[test]
    fn test_request_builder_missing_via_branch() {
        let mut builder = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .from("sip:alice@example.com", "tag123")
            .to("sip:bob@example.com")
            .call_id("call-id")
            .cseq(1);
        builder.via_host = Some("example.com".to_string());
        builder.via_port = Some(5060);
        builder.via_transport = Some("UDP".to_string());
        let err = builder.build().unwrap_err();
        assert!(format!("{err:?}").contains("InvalidHeader"));
    }

    #[test]
    fn test_request_builder_default_via_transport() {
        let mut builder = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .from("sip:alice@example.com", "tag123")
            .to("sip:bob@example.com")
            .call_id("call-id")
            .cseq(1);
        builder.via_host = Some("example.com".to_string());
        builder.via_port = Some(5060);
        builder.via_branch = Some("z9hG4bKtest".to_string());
        let request = builder.build().unwrap();
        let bytes = request.to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("SIP/2.0/UDP example.com:5060;branch=z9hG4bKtest"));
    }

    #[test]
    fn test_response_builder_default() {
        let builder = SipResponseBuilder::default();
        let debug = format!("{:?}", builder);
        assert!(debug.contains("SipResponseBuilder"));
    }

    // Display trait tests for SipMessage, SipRequest, and SipResponse
    #[test]
    fn test_sip_message_debug_request() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let debug = format!("{:?}", msg);
        assert!(debug.contains("Request"));
    }

    #[test]
    fn test_sip_message_debug_response() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let debug = format!("{:?}", msg);
        assert!(debug.contains("Response"));
    }

    #[test]
    fn test_sip_request_debug() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let debug = format!("{:?}", req);
        assert!(debug.contains("SipRequest"));
    }

    #[test]
    fn test_sip_request_clone() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let req = msg.as_request().unwrap();
        let cloned = req.clone();
        assert_eq!(cloned.method(), req.method());
        assert_eq!(cloned.call_id().unwrap(), req.call_id().unwrap());
    }

    #[test]
    fn test_sip_response_debug() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let debug = format!("{:?}", resp);
        assert!(debug.contains("SipResponse"));
    }

    #[test]
    fn test_sip_response_clone() {
        let msg = SipMessage::parse(RESPONSE_MSG).unwrap();
        let resp = msg.as_response().unwrap();
        let cloned = resp.clone();
        assert_eq!(cloned.status_code(), resp.status_code());
        assert_eq!(cloned.call_id().unwrap(), resp.call_id().unwrap());
    }

    // Edge case tests for message parsing
    #[test]
    fn test_parse_request_missing_call_id() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.call_id().is_err());
    }

    #[test]
    fn test_parse_request_missing_from() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.from_tag().is_err());
        assert!(req.from_uri().is_err());
    }

    #[test]
    fn test_parse_request_missing_to() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.to_uri().is_err());
    }

    #[test]
    fn test_parse_request_missing_via() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.via_branch().is_err());
    }

    #[test]
    fn test_parse_request_missing_cseq() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
Call-ID: test@example.com\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.cseq().is_err());
        assert!(req.cseq_method().is_err());
    }

    #[test]
    fn test_parse_request_from_missing_tag() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
From: Alice <sip:alice@atlanta.com>\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.from_tag().is_err());
    }

    #[test]
    fn test_parse_request_via_missing_branch() {
        let bad_msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_msg).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.via_branch().is_err());
    }

    #[test]
    fn test_parse_request_no_contact() {
        let msg_no_contact = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(msg_no_contact).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.contact_uri().is_none());
    }

    #[test]
    fn test_parse_request_no_content_type() {
        let msg_no_ct = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(msg_no_ct).unwrap();
        let req = msg.as_request().unwrap();
        assert!(req.content_type().is_none());
    }

    #[test]
    fn test_parse_request_with_record_route() {
        let msg_with_rr = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
Record-Route: <sip:proxy1.example.com;lr>\r\n\
Record-Route: <sip:proxy2.example.com;lr>\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(msg_with_rr).unwrap();
        let req = msg.as_request().unwrap();
        let routes = req.record_routes();
        assert_eq!(routes.len(), 2);
        assert!(routes[0].contains("proxy1.example.com"));
        assert!(routes[1].contains("proxy2.example.com"));
    }

    #[test]
    fn test_parse_request_multiple_via_headers() {
        let msg_multi_via = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP proxy1.example.com;branch=z9hG4bKproxy1\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(msg_multi_via).unwrap();
        let req = msg.as_request().unwrap();
        let vias = req.via_headers_raw();
        assert_eq!(vias.len(), 2);
        assert!(vias[0].contains("proxy1.example.com"));
        assert!(vias[1].contains("pc33.atlanta.com"));
    }

    #[test]
    fn test_parse_request_with_body() {
        let msg_with_body = b"INVITE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 9\r\n\
\r\n\
v=0\r\ntest";
        let msg = SipMessage::parse(msg_with_body).unwrap();
        let req = msg.as_request().unwrap();
        assert!(!req.body().is_empty());
    }

    // Response error handling tests
    #[test]
    fn test_parse_response_missing_call_id() {
        let bad_resp = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_resp).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.call_id().is_err());
    }

    #[test]
    fn test_parse_response_missing_from() {
        let bad_resp = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
Call-ID: test@example.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_resp).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.from_tag().is_err());
    }

    #[test]
    fn test_parse_response_missing_via() {
        let bad_resp = b"SIP/2.0 200 OK\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: test@example.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_resp).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.via_branch().is_err());
    }

    #[test]
    fn test_parse_response_missing_cseq() {
        let bad_resp = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: test@example.com\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_resp).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.cseq().is_err());
        assert!(resp.cseq_method().is_err());
    }

    #[test]
    fn test_parse_response_from_missing_tag() {
        let bad_resp = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>\r\n\
Call-ID: test@example.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_resp).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.from_tag().is_err());
    }

    #[test]
    fn test_parse_response_via_missing_branch() {
        let bad_resp = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: test@example.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(bad_resp).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.via_branch().is_err());
    }

    #[test]
    fn test_parse_response_no_to_tag() {
        let resp_no_tag = b"SIP/2.0 100 Trying\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_no_tag).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.to_tag().is_none());
    }

    #[test]
    fn test_parse_response_no_contact() {
        let resp_no_contact = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_no_contact).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.contact_uri().is_none());
    }

    #[test]
    fn test_parse_response_with_www_authenticate() {
        let resp_with_auth = b"SIP/2.0 401 Unauthorized\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\"\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_with_auth).unwrap();
        let resp = msg.as_response().unwrap();
        let auth = resp.www_authenticate();
        assert!(auth.is_some());
        let auth_str = auth.unwrap();
        assert!(auth_str.contains("Digest"));
        assert!(auth_str.contains("example.com"));
    }

    #[test]
    fn test_parse_response_with_proxy_authenticate() {
        let resp_with_auth = b"SIP/2.0 407 Proxy Authentication Required\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Proxy-Authenticate: Digest realm=\"proxy.example.com\", nonce=\"def456\"\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_with_auth).unwrap();
        let resp = msg.as_response().unwrap();
        let auth = resp.proxy_authenticate();
        assert!(auth.is_some());
        let auth_str = auth.unwrap();
        assert!(auth_str.contains("Digest"));
        assert!(auth_str.contains("proxy.example.com"));
    }

    #[test]
    fn test_parse_response_with_record_route() {
        let resp_with_rr = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Record-Route: <sip:proxy1.example.com;lr>\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_with_rr).unwrap();
        let resp = msg.as_response().unwrap();
        let routes = resp.record_routes();
        assert_eq!(routes.len(), 1);
        assert!(routes[0].contains("proxy1.example.com"));
    }

    #[test]
    fn test_parse_response_multiple_via_headers() {
        let resp_multi_via = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP proxy1.example.com;branch=z9hG4bKproxy1\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_multi_via).unwrap();
        let resp = msg.as_response().unwrap();
        let vias = resp.via_headers_raw();
        assert_eq!(vias.len(), 2);
        assert!(vias[0].contains("proxy1.example.com"));
    }

    #[test]
    fn test_parse_response_3xx_is_failure() {
        let redirect = b"SIP/2.0 302 Moved Temporarily\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(redirect).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.is_failure());
        assert!(!resp.is_success());
        assert!(!resp.is_provisional());
    }

    #[test]
    fn test_parse_response_5xx_is_failure() {
        let server_error = b"SIP/2.0 500 Server Internal Error\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(server_error).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.is_failure());
        assert!(!resp.is_success());
        assert!(!resp.is_provisional());
    }

    #[test]
    fn test_parse_response_6xx_is_failure() {
        let global_failure = b"SIP/2.0 603 Decline\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(global_failure).unwrap();
        let resp = msg.as_response().unwrap();
        assert!(resp.is_failure());
        assert!(!resp.is_success());
        assert!(!resp.is_provisional());
    }

    #[test]
    fn test_response_reason_edge_case() {
        // Test reason parsing - the rsip library has a fixed set of reason phrases
        let resp_long_reason = b"SIP/2.0 488 Not Acceptable Here\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        let msg = SipMessage::parse(resp_long_reason).unwrap();
        let resp = msg.as_response().unwrap();
        assert_eq!(resp.status_code(), 488);
        let reason = resp.reason();
        assert!(!reason.is_empty());
    }

    // Builder edge cases and error paths
    #[test]
    fn test_build_request_with_empty_body() {
        // Test request with empty body doesn't add Content-Type
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .body(vec![], "application/sdp")
            .build()
            .unwrap();

        // Empty body should not have content type added
        let bytes = req.to_bytes();
        let msg_str = String::from_utf8_lossy(&bytes);
        // Content-Length should still be present
        assert!(msg_str.contains("Content-Length: 0"));
    }

    #[test]
    fn test_build_request_with_non_empty_body() {
        // Test request with body adds Content-Type
        let body_data = b"test body".to_vec();
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .body(body_data.clone(), "application/test")
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        let msg_str = String::from_utf8_lossy(&bytes);
        assert!(msg_str.contains("Content-Type: application/test"));
        assert!(msg_str.contains("Content-Length: 9"));
    }

    #[test]
    fn test_build_request_builder_new() {
        // Test that builder can be created via new()
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build()
            .unwrap();

        assert_eq!(req.method(), Method::Invite);
    }

    #[test]
    fn test_build_request_missing_via_host() {
        // Create a builder without calling via()
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_missing_call_id() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .cseq(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_missing_cseq() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_missing_from_tag() {
        // Using empty string for tag
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        // Should succeed even with empty tag (though not recommended)
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_request_invalid_contact_uri() {
        // Contact URI parsing failure should be silently ignored
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .contact("sip:alice@[::1")
            .build()
            .unwrap();

        // Invalid contact URIs are silently ignored by the builder
        assert!(req.contact_uri().is_none());
    }

    #[test]
    fn test_build_request_valid_contact_uri() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .contact("sip:alice@192.168.1.1:5060")
            .build()
            .unwrap();

        assert!(req.contact_uri().is_some());
    }

    #[test]
    fn test_build_request_invalid_uri_error() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("<>invalid<>")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_invalid_from_uri_error() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .from("<>invalid<>", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_invalid_to_uri_error() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .from("sip:alice@example.com", "tag1")
            .to("<>invalid<>")
            .call_id("call@example.com")
            .cseq(1)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn test_build_request_invalid_uri_error_with_required_headers() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:alice@[::1")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid request URI"));
    }

    #[test]
    fn test_build_request_invalid_from_uri_error_with_required_headers() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@[::1", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid From URI"));
    }

    #[test]
    fn test_build_request_invalid_to_uri_error_with_required_headers() {
        let result = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:alice@[::1")
            .call_id("call@example.com")
            .cseq(1)
            .build();

        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid To URI"));
    }

    #[test]
    fn test_build_request_body_without_content_type() {
        let mut builder = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1);

        builder.body = Some(b"payload".to_vec());
        builder.content_type = None;

        let req = builder.build().unwrap();
        assert_eq!(req.body(), b"payload");
        assert!(req.content_type().is_none());
    }

    #[test]
    fn test_build_request_default_via_port() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("192.168.1.1:5060"));
    }

    #[test]
    fn test_build_request_default_max_forwards() {
        let req = SipRequest::builder()
            .method(Method::Invite)
            .uri("sip:bob@example.com")
            .via("192.168.1.1", 5060, "UDP", "z9hG4bKtest")
            .from("sip:alice@example.com", "tag1")
            .to("sip:bob@example.com")
            .call_id("call@example.com")
            .cseq(1)
            .build()
            .unwrap();

        let bytes = req.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("Max-Forwards: 70"));
    }

    #[test]
    fn test_build_response_empty_via() {
        // Test builder with no request (empty via list)
        let resp = SipResponse::builder().status(200, "OK").build().unwrap();

        let vias = resp.via_headers_raw();
        assert!(vias.is_empty());
    }

    // Test different SIP methods
    #[test]
    fn test_parse_register_request() {
        let register = b"REGISTER sip:registrar.example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Alice <sip:alice@atlanta.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 REGISTER\r\n\
Contact: <sip:alice@pc33.atlanta.com>\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(register).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Register);
        assert_eq!(req.cseq_method().unwrap(), Method::Register);
    }

    #[test]
    fn test_parse_bye_request() {
        let bye = b"BYE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314160 BYE\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(bye).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Bye);
        assert_eq!(req.cseq_method().unwrap(), Method::Bye);
    }

    #[test]
    fn test_parse_cancel_request() {
        let cancel = b"CANCEL sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 CANCEL\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(cancel).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Cancel);
        assert_eq!(req.cseq_method().unwrap(), Method::Cancel);
    }

    #[test]
    fn test_parse_options_request() {
        let options = b"OPTIONS sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 OPTIONS\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(options).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Options);
        assert!(!req.method().creates_dialog());
    }

    #[test]
    fn test_parse_subscribe_request() {
        let subscribe = b"SUBSCRIBE sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 SUBSCRIBE\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(subscribe).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Subscribe);
        assert!(req.method().creates_dialog());
    }

    #[test]
    fn test_parse_notify_request() {
        let notify = b"NOTIFY sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 NOTIFY\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(notify).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Notify);
    }

    #[test]
    fn test_parse_ack_request() {
        let ack = b"ACK sip:bob@biloxi.com SIP/2.0\r\n\
Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
CSeq: 314159 ACK\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = SipMessage::parse(ack).unwrap();
        let req = msg.as_request().unwrap();
        assert_eq!(req.method(), Method::Ack);
    }
}
