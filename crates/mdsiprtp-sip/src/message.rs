//! SIP message types and wrappers.

use bytes::Bytes;
use mdsiprtp_core::{SipError, Result};
use rsip::prelude::*;
use std::convert::TryFrom;
use std::fmt;

/// SIP message (either request or response).
#[derive(Debug, Clone)]
pub enum SipMessage {
    Request(SipRequest),
    Response(SipResponse),
}

impl SipMessage {
    /// Parse a SIP message from bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let msg = rsip::SipMessage::try_from(data)
            .map_err(|e| SipError::Parse(e.to_string()))?;

        match msg {
            rsip::SipMessage::Request(req) => Ok(SipMessage::Request(SipRequest { inner: req })),
            rsip::SipMessage::Response(resp) => Ok(SipMessage::Response(SipResponse { inner: resp })),
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
        let from = self.inner
            .from_header()
            .map_err(|_| SipError::MissingHeader("From".to_string()))?;
        // Convert to typed form to access tag
        let typed_from: rsip::typed::From = from.typed()
            .map_err(|e| SipError::Parse(e.to_string()))?;
        typed_from.tag()
            .map(|t| t.to_string())
            .ok_or_else(|| SipError::InvalidHeader("From header missing tag".to_string()).into())
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
        let via = self.inner
            .via_header()
            .map_err(|_| SipError::MissingHeader("Via".to_string()))?;
        let typed_via: rsip::typed::Via = via.typed()
            .map_err(|e| SipError::Parse(e.to_string()))?;
        typed_via.branch()
            .map(|b| b.to_string())
            .ok_or_else(|| SipError::InvalidHeader("Via header missing branch".to_string()).into())
    }

    /// Get the CSeq number.
    pub fn cseq(&self) -> Result<u32> {
        let cseq = self.inner
            .cseq_header()
            .map_err(|_| SipError::MissingHeader("CSeq".to_string()))?;
        let typed_cseq: rsip::typed::CSeq = cseq.typed()
            .map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(typed_cseq.seq)
    }

    /// Get the CSeq method.
    pub fn cseq_method(&self) -> Result<Method> {
        let cseq = self.inner
            .cseq_header()
            .map_err(|_| SipError::MissingHeader("CSeq".to_string()))?;
        let typed_cseq: rsip::typed::CSeq = cseq.typed()
            .map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(Method::from(&typed_cseq.method))
    }

    /// Get the From URI.
    pub fn from_uri(&self) -> Result<rsip::Uri> {
        let from = self.inner
            .from_header()
            .map_err(|_| SipError::MissingHeader("From".to_string()))?;
        let typed_from: rsip::typed::From = from.typed()
            .map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(typed_from.uri)
    }

    /// Get the To URI.
    pub fn to_uri(&self) -> Result<rsip::Uri> {
        let to = self.inner
            .to_header()
            .map_err(|_| SipError::MissingHeader("To".to_string()))?;
        let typed_to: rsip::typed::To = to.typed()
            .map_err(|e| SipError::Parse(e.to_string()))?;
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
        if let Some(pos) = s.find(' ') {
            s[pos + 1..].to_string()
        } else {
            s
        }
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
        let from = self.inner
            .from_header()
            .map_err(|_| SipError::MissingHeader("From".to_string()))?;
        let typed_from: rsip::typed::From = from.typed()
            .map_err(|e| SipError::Parse(e.to_string()))?;
        typed_from.tag()
            .map(|t| t.to_string())
            .ok_or_else(|| SipError::InvalidHeader("From header missing tag".to_string()).into())
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
        let via = self.inner
            .via_header()
            .map_err(|_| SipError::MissingHeader("Via".to_string()))?;
        let typed_via: rsip::typed::Via = via.typed()
            .map_err(|e| SipError::Parse(e.to_string()))?;
        typed_via.branch()
            .map(|b| b.to_string())
            .ok_or_else(|| SipError::InvalidHeader("Via header missing branch".to_string()).into())
    }

    /// Get the CSeq number.
    pub fn cseq(&self) -> Result<u32> {
        let cseq = self.inner
            .cseq_header()
            .map_err(|_| SipError::MissingHeader("CSeq".to_string()))?;
        let typed_cseq: rsip::typed::CSeq = cseq.typed()
            .map_err(|e| SipError::Parse(e.to_string()))?;
        Ok(typed_cseq.seq)
    }

    /// Get the CSeq method.
    pub fn cseq_method(&self) -> Result<Method> {
        let cseq = self.inner
            .cseq_header()
            .map_err(|_| SipError::MissingHeader("CSeq".to_string()))?;
        let typed_cseq: rsip::typed::CSeq = cseq.typed()
            .map_err(|e| SipError::Parse(e.to_string()))?;
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
    Invite,
    Ack,
    Bye,
    Cancel,
    Register,
    Options,
    Prack,
    Subscribe,
    Notify,
    Publish,
    Info,
    Refer,
    Message,
    Update,
    Other,
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
            Method::Other => rsip::Method::Invite, // fallback
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
            Method::Other => "OTHER",
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

        let method = self.method.ok_or_else(|| SipError::InvalidHeader("Missing method".to_string()))?;
        let uri = self.uri.ok_or_else(|| SipError::InvalidHeader("Missing request URI".to_string()))?;
        let from_uri = self.from_uri.ok_or_else(|| SipError::InvalidHeader("Missing From URI".to_string()))?;
        let from_tag = self.from_tag.ok_or_else(|| SipError::InvalidHeader("Missing From tag".to_string()))?;
        let to_uri = self.to_uri.ok_or_else(|| SipError::InvalidHeader("Missing To URI".to_string()))?;
        let call_id = self.call_id.ok_or_else(|| SipError::InvalidHeader("Missing Call-ID".to_string()))?;
        let cseq = self.cseq.ok_or_else(|| SipError::InvalidHeader("Missing CSeq".to_string()))?;
        let via_host = self.via_host.ok_or_else(|| SipError::InvalidHeader("Missing Via host".to_string()))?;
        let via_branch = self.via_branch.ok_or_else(|| SipError::InvalidHeader("Missing Via branch".to_string()))?;

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
        headers.push(rsip::Header::MaxForwards(rsip::headers::MaxForwards::new(mf.to_string())));

        // Contact header
        if let Some(contact) = self.contact_uri {
            let contact_str = format!("<{}>", contact);
            headers.push(rsip::Header::Contact(rsip::headers::Contact::new(contact_str)));
        }

        // Authorization header
        if let Some(auth) = self.authorization {
            headers.push(rsip::Header::Authorization(rsip::headers::Authorization::new(auth)));
        }

        // Proxy-Authorization header
        if let Some(auth) = self.proxy_authorization {
            headers.push(rsip::Header::ProxyAuthorization(rsip::headers::ProxyAuthorization::new(auth)));
        }

        // Expires header
        if let Some(expires) = self.expires {
            headers.push(rsip::Header::Expires(rsip::headers::Expires::new(expires.to_string())));
        }

        // Content-Type and Content-Length
        let body = self.body.unwrap_or_default();
        if !body.is_empty() {
            if let Some(ct) = self.content_type {
                headers.push(rsip::Header::ContentType(rsip::headers::ContentType::new(ct)));
            }
        }
        headers.push(rsip::Header::ContentLength(rsip::headers::ContentLength::new(body.len().to_string())));

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
                self.via.push(v.to_string());
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
                self.cseq = Some(c.to_string());
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
        let status_code = self.status_code.ok_or_else(|| SipError::InvalidHeader("Missing status code".to_string()))?;

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
            headers.push(rsip::Header::Contact(rsip::headers::Contact::new(contact_str)));
        }

        // Content-Type and Content-Length
        let body = self.body.unwrap_or_default();
        if !body.is_empty() {
            if let Some(ct) = self.content_type {
                headers.push(rsip::Header::ContentType(rsip::headers::ContentType::new(ct)));
            }
        }
        headers.push(rsip::Header::ContentLength(rsip::headers::ContentLength::new(body.len().to_string())));

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
pub fn generate_tag() -> String {
    format!("{:x}", rand_u64())
}

/// Generate a unique Call-ID.
pub fn generate_call_id(domain: &str) -> String {
    format!("{}@{}", uuid::Uuid::new_v4().simple(), domain)
}

/// Simple random u64 (not cryptographically secure).
fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    duration.as_nanos() as u64 ^ (duration.as_secs() << 32)
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
    fn test_roundtrip() {
        let msg = SipMessage::parse(INVITE_MSG).unwrap();
        let bytes = msg.to_bytes();
        let msg2 = SipMessage::parse(&bytes).unwrap();

        let req1 = msg.as_request().unwrap();
        let req2 = msg2.as_request().unwrap();

        assert_eq!(req1.method(), req2.method());
        assert_eq!(req1.call_id().unwrap(), req2.call_id().unwrap());
    }

    #[test]
    fn test_method_display() {
        assert_eq!(format!("{}", Method::Invite), "INVITE");
        assert_eq!(format!("{}", Method::Ack), "ACK");
        assert_eq!(format!("{}", Method::Register), "REGISTER");
    }

    #[test]
    fn test_generate_branch() {
        let branch = generate_branch();
        assert!(branch.starts_with("z9hG4bK"));
        assert!(branch.len() > 10);
    }

    #[test]
    fn test_generate_tag() {
        let tag = generate_tag();
        assert!(!tag.is_empty());
    }

    #[test]
    fn test_generate_call_id() {
        let call_id = generate_call_id("example.com");
        assert!(call_id.ends_with("@example.com"));
    }
}
