//! Differential-test harness: rsip vs in-tree parser.
//!
//! Per M2 of the SIP parser rewrite (HLD §"Differential-test harness")
//! we run two parsers over the same bytes and assert their outputs are
//! equivalent under a neutral [`DiffMessage`] representation. Both
//! parsers' typed-header variants are flattened to `(name_lc,
//! value_normalized)` pairs so the 47-vs-19 typed-variant gap doesn't
//! produce false divergences.
//!
//! Equivalence rules:
//! - Both accept ⇒ DiffMessage must be equal.
//! - Both reject ⇒ no further check (errors may differ).
//! - One accepts, one rejects ⇒ panic — investigate as a real
//!   divergence.
//!
//! See `wrk_docs/2026.05.03 - HLD - sip-parser-rewrite.md`.

use rsiprtp::sip::parser::{Header as OurHeader, Message as OurMessage};
use rsiprtp::sip::SipUri;

// M4: typed-form imports for the From/To Tier-2 axis. Our typed
// forms wrap NameAddr; rsip's live under `rsip::typed::*`.
use rsiprtp::sip::parser::typed::{From as OurFrom, To as OurTo};

// M5: typed-form imports for Via, CSeq, Contact.
use rsiprtp::sip::parser::typed::{CSeq as OurCSeq, Contact as OurContact, Via as OurVia};

// ---------------------------------------------------------------
// Neutral representation
// ---------------------------------------------------------------

/// Structurally-normalized URI for diff comparison.
///
/// Per HLD §"Differential-test harness" (point 2): "uri:
/// NormalizedUri (lowercased scheme/host, parameters
/// order-independent)". RFC 3261 §19.1.4 says URI parameters are
/// unordered for equality. We additionally:
/// - lowercase scheme and host (also case-insensitive per
///   §19.1.4),
/// - sort parameters by lowercased key (RFC 3261 §19.1.4 — order
///   does not matter for equality),
/// - sort URI headers by lowercased name (same reasoning, applied
///   conservatively — RFC 3261 doesn't pin URI-header order
///   either).
///
/// Parameter values that are present-with-empty (`;foo=`) are kept
/// distinct from parameter-absent values (`;foo`) — both rsip and
/// our parser distinguish these. We do NOT lowercase param/header
/// values: per RFC 3261 §19.1.4 the values of `user`, `ttl`,
/// `method`, `maddr`, `transport` are case-sensitive (`method` is
/// SHOULD-be-uppercase, `transport` is case-insensitive, but
/// blanket-lowercasing them risks hiding real bugs in either
/// parser).
#[derive(Debug, PartialEq, Eq)]
struct NormalizedUri {
    /// `"sip"`, `"sips"`, or `"tel"` — lowercased.
    scheme: String,
    /// User part (case-sensitive per RFC 3261 §19.1.4 — the user
    /// portion is opaque).
    user: Option<String>,
    /// Host lowercased (RFC 3261 §19.1.4 — host comparison is
    /// case-insensitive).
    host: String,
    /// Port number (None means absent — distinct from default).
    port: Option<u16>,
    /// Sorted by lowercased key.
    params: Vec<(String, Option<String>)>,
    /// Sorted by lowercased name.
    headers: Vec<(String, String)>,
    /// Set if the URI string failed to parse via our `SipUri::parse`
    /// — we fall back to the raw string in that case so the harness
    /// can still compare. A real bug would surface here as one
    /// parser succeeding and the other failing on the same URI.
    raw_fallback: Option<String>,
}

impl NormalizedUri {
    fn from_str(s: &str) -> Self {
        match SipUri::parse(s) {
            Ok(uri) => {
                let mut params: Vec<(String, Option<String>)> = uri
                    .params()
                    .map(|(k, v)| (k.to_ascii_lowercase(), v.map(|s| s.to_string())))
                    .collect();
                params.sort_by(|a, b| a.0.cmp(&b.0));
                let mut headers: Vec<(String, String)> = uri
                    .headers()
                    .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
                    .collect();
                headers.sort_by(|a, b| a.0.cmp(&b.0));
                NormalizedUri {
                    scheme: uri.scheme().to_string(),
                    user: uri.user().map(|u| u.to_string()),
                    host: uri.host().to_ascii_lowercase(),
                    port: uri.port(),
                    params,
                    headers,
                    raw_fallback: None,
                }
            }
            Err(_) => NormalizedUri {
                scheme: String::new(),
                user: None,
                host: String::new(),
                port: None,
                params: Vec::new(),
                headers: Vec::new(),
                raw_fallback: Some(s.to_string()),
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DiffKind {
    Request { method: String, uri: NormalizedUri },
    Response { status: u16 },
}

#[derive(Debug, PartialEq, Eq)]
struct DiffMessage {
    kind: DiffKind,
    headers: Vec<(
        String, /* name_lc */
        String, /* value_normalized */
    )>,
    body: Vec<u8>,
}

// ---------------------------------------------------------------
// Header value normalization (HLD §"Header value normalization")
// ---------------------------------------------------------------

/// Normalize a header value for diff comparison:
///
/// 1. Strip RFC 3261 comments — parenthesized text, including nested
///    parens. Per RFC 3261 §25.1, `\(` and `\)` inside a comment are
///    quoted-pair escapes; we honor them. Comments inside quoted
///    strings are NOT stripped (quoted strings are literal).
/// 2. Collapse runs of whitespace (spaces and tabs) to a single space.
/// 3. Trim leading and trailing whitespace.
///
/// We deliberately do NOT touch parameter ordering, case of values,
/// or quoting beyond strip-of-comment-parens. A real semantic
/// difference (e.g. parameter set differs) MUST surface as a
/// divergence.
fn normalize_value(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    let mut in_quoted = false;
    let mut paren_depth: u32 = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_quoted {
            // Inside a "..." quoted string: pass through verbatim,
            // honoring `\X` quoted-pair escapes (the next char is
            // literal regardless of what it is).
            out.push(b as char);
            if b == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if b == b'"' {
                in_quoted = false;
            }
            i += 1;
            continue;
        }
        if paren_depth > 0 {
            // Inside a comment: skip everything, but still honor
            // `\X` escapes and nested parens.
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'(' {
                paren_depth += 1;
            } else if b == b')' {
                paren_depth -= 1;
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => {
                in_quoted = true;
                out.push('"');
            }
            b'(' => {
                paren_depth = 1;
            }
            b'\\' => {
                // RFC 3261 §25.1: quoted-pair is only valid inside a
                // quoted-string or a comment. Outside both, `\` is a
                // literal byte. Push `\` AND the next byte verbatim
                // (without re-interpreting that next byte as a
                // comment-opener etc.) so callers like `\(literal\)`
                // outside any context don't silently get the `(`
                // treated as a comment-opener and the closing `)`
                // swallowed by quoted-pair handling inside the
                // (unintended) comment.
                out.push('\\');
                if i + 1 < bytes.len() {
                    out.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
            }
            b' ' | b'\t' => {
                // Collapse runs of WS to single space (only emit
                // one if the previous emitted char isn't already a
                // space).
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            _ => out.push(b as char),
        }
        i += 1;
    }
    // Trim leading/trailing ws (collapsing already removed runs but
    // a single leading/trailing space may remain).
    out.trim().to_string()
}

// ---------------------------------------------------------------
// rsip → DiffMessage
// ---------------------------------------------------------------

/// Parse with rsip and project to [`DiffMessage`].
///
/// Each `rsip::Header::*` typed variant exposes its value via
/// `Display` (the Display impl renders `Name: value` for `Other` and
/// just `value` for typed variants — we use the variant-discriminator
/// for the name and re-extract the value from the Display string).
/// Untyped headers (`UntypedHeader::value()`) would also work for the
/// typed variants but the Display path is uniform.
fn rsip_to_diff(bytes: &[u8]) -> Result<DiffMessage, String> {
    use rsip::SipMessage;
    let msg = SipMessage::try_from(bytes).map_err(|e| format!("rsip: {e}"))?;
    let (kind, headers, body) = match msg {
        SipMessage::Request(req) => {
            let method = req.method.to_string();
            let uri = NormalizedUri::from_str(&req.uri.to_string());
            let headers = collect_rsip_headers(&req.headers);
            (DiffKind::Request { method, uri }, headers, req.body.clone())
        }
        SipMessage::Response(resp) => {
            let status: u16 = resp.status_code.clone().into();
            let headers = collect_rsip_headers(&resp.headers);
            (DiffKind::Response { status }, headers, resp.body.clone())
        }
    };
    Ok(DiffMessage {
        kind,
        headers,
        body,
    })
}

fn collect_rsip_headers(hs: &rsip::Headers) -> Vec<(String, String)> {
    hs.iter().map(rsip_header_pair).collect()
}

/// Resolve an RFC 3261 §20 / RFC 3265 §7.2 single-letter compact
/// header name to its long form, lowercased. Anything else is
/// returned lowercased as-is. Used on the rsip side because rsip
/// does NOT resolve compact forms when it falls back to the
/// `Other(name, value)` variant (it stores e.g. `"v"` literally),
/// while our parser normalizes to long form. This is a harness-side
/// normalization, not a spec interpretation difference.
fn resolve_compact_name(name: &str) -> String {
    let lc = name.trim().to_ascii_lowercase();
    if lc.len() != 1 {
        return lc;
    }
    match lc.as_bytes()[0] {
        b'i' => "call-id".into(),
        b'm' => "contact".into(),
        b'f' => "from".into(),
        b't' => "to".into(),
        b'v' => "via".into(),
        b'c' => "content-type".into(),
        b'l' => "content-length".into(),
        b's' => "subject".into(),
        b'k' => "supported".into(),
        b'e' => "content-encoding".into(),
        b'r' => "refer-to".into(),
        b'b' => "referred-by".into(),
        b'd' => "content-disposition".into(),
        b'o' => "event".into(),
        b'u' => "allow-events".into(),
        _ => lc,
    }
}

/// Extract the canonical lowercase name and raw value from an
/// `rsip::Header`. `Other(name, value)` is straightforward; typed
/// variants we mirror via a manual match — simpler than reflecting
/// off Display, and survives any `Display` quirks (rsip's `Display`
/// for some typed headers prepends the canonical `Name: ` prefix
/// which we'd then have to strip).
fn rsip_header_pair(h: &rsip::Header) -> (String, String) {
    use rsip::headers::UntypedHeader;
    use rsip::Header as H;
    match h {
        H::Accept(v) => ("accept".into(), normalize_value(v.value())),
        H::AcceptEncoding(v) => ("accept-encoding".into(), normalize_value(v.value())),
        H::AcceptLanguage(v) => ("accept-language".into(), normalize_value(v.value())),
        H::AlertInfo(v) => ("alert-info".into(), normalize_value(v.value())),
        H::Allow(v) => ("allow".into(), normalize_value(v.value())),
        H::AuthenticationInfo(v) => ("authentication-info".into(), normalize_value(v.value())),
        H::Authorization(v) => ("authorization".into(), normalize_value(v.value())),
        H::CSeq(v) => ("cseq".into(), normalize_value(v.value())),
        H::CallId(v) => ("call-id".into(), normalize_value(v.value())),
        H::CallInfo(v) => ("call-info".into(), normalize_value(v.value())),
        H::Contact(v) => ("contact".into(), normalize_value(v.value())),
        H::ContentDisposition(v) => ("content-disposition".into(), normalize_value(v.value())),
        H::ContentEncoding(v) => ("content-encoding".into(), normalize_value(v.value())),
        H::ContentLanguage(v) => ("content-language".into(), normalize_value(v.value())),
        H::ContentLength(v) => ("content-length".into(), normalize_value(v.value())),
        H::ContentType(v) => ("content-type".into(), normalize_value(v.value())),
        H::Date(v) => ("date".into(), normalize_value(v.value())),
        H::ErrorInfo(v) => ("error-info".into(), normalize_value(v.value())),
        H::Event(v) => ("event".into(), normalize_value(v.value())),
        H::Expires(v) => ("expires".into(), normalize_value(v.value())),
        H::From(v) => ("from".into(), normalize_value(v.value())),
        H::InReplyTo(v) => ("in-reply-to".into(), normalize_value(v.value())),
        H::MaxForwards(v) => ("max-forwards".into(), normalize_value(v.value())),
        H::MimeVersion(v) => ("mime-version".into(), normalize_value(v.value())),
        H::MinExpires(v) => ("min-expires".into(), normalize_value(v.value())),
        H::Organization(v) => ("organization".into(), normalize_value(v.value())),
        H::Other(name, value) => (resolve_compact_name(name), normalize_value(value)),
        H::Priority(v) => ("priority".into(), normalize_value(v.value())),
        H::ProxyAuthenticate(v) => ("proxy-authenticate".into(), normalize_value(v.value())),
        H::ProxyAuthorization(v) => ("proxy-authorization".into(), normalize_value(v.value())),
        H::ProxyRequire(v) => ("proxy-require".into(), normalize_value(v.value())),
        H::RecordRoute(v) => ("record-route".into(), normalize_value(v.value())),
        H::ReplyTo(v) => ("reply-to".into(), normalize_value(v.value())),
        H::Require(v) => ("require".into(), normalize_value(v.value())),
        H::RetryAfter(v) => ("retry-after".into(), normalize_value(v.value())),
        H::Route(v) => ("route".into(), normalize_value(v.value())),
        H::Server(v) => ("server".into(), normalize_value(v.value())),
        H::Subject(v) => ("subject".into(), normalize_value(v.value())),
        H::SubscriptionState(v) => ("subscription-state".into(), normalize_value(v.value())),
        H::Supported(v) => ("supported".into(), normalize_value(v.value())),
        H::Timestamp(v) => ("timestamp".into(), normalize_value(v.value())),
        H::To(v) => ("to".into(), normalize_value(v.value())),
        H::Unsupported(v) => ("unsupported".into(), normalize_value(v.value())),
        H::UserAgent(v) => ("user-agent".into(), normalize_value(v.value())),
        H::Via(v) => ("via".into(), normalize_value(v.value())),
        H::Warning(v) => ("warning".into(), normalize_value(v.value())),
        H::WwwAuthenticate(v) => ("www-authenticate".into(), normalize_value(v.value())),
    }
}

// ---------------------------------------------------------------
// Our parser → DiffMessage
// ---------------------------------------------------------------

fn ours_to_diff(bytes: &[u8]) -> Result<DiffMessage, String> {
    let msg = OurMessage::parse(bytes).map_err(|e| format!("ours: {e}"))?;
    let (kind, headers, body) = match msg {
        OurMessage::Request(req) => {
            let method = req.method.as_str().to_string();
            let uri = NormalizedUri::from_str(&req.uri);
            let headers = collect_our_headers(&req.headers);
            (DiffKind::Request { method, uri }, headers, req.body.clone())
        }
        OurMessage::Response(resp) => {
            let status = resp.status_code.as_u16();
            let headers = collect_our_headers(&resp.headers);
            (DiffKind::Response { status }, headers, resp.body.clone())
        }
    };
    Ok(DiffMessage {
        kind,
        headers,
        body,
    })
}

fn collect_our_headers(hs: &rsiprtp::sip::parser::Headers) -> Vec<(String, String)> {
    hs.iter()
        .map(|h| {
            let name = match h {
                OurHeader::Other(n, _) => n.to_ascii_lowercase(),
                _ => h.name().to_ascii_lowercase(),
            };
            (name, normalize_value(h.value()))
        })
        .collect()
}

// ---------------------------------------------------------------
// Tier-2: typed `From` / `To` diff (M4)
// ---------------------------------------------------------------

/// Neutral Tier-2 representation of a `From` or `To` header value.
///
/// Built from either the rsip or our typed form, then compared
/// field-by-field. Per HLD M4 entry, the goal is "Diff-test green
/// for From/To on golden corpus".
///
/// Normalization choices:
/// - `display_name`: surrounding `"..."` stripped and `\\X`
///   quoted-pair escapes resolved on both sides. rsip stores the
///   display name verbatim (quotes kept); our parser strips quotes
///   at parse time. We normalize the rsip side to match — the data
///   they encode is identical.
/// - `uri`: routed through [`NormalizedUri`] (the same
///   case-insensitive scheme/host + sorted-params normalizer used
///   by Tier-1). Compared structurally.
/// - `parameters`: sorted by lowercased key. Per RFC 3261 §25.1
///   `gen-value = token / host / quoted-string`; multiple params
///   with the same name are theoretically possible but in
///   practice not observed for `From`/`To`. Sort is stable per the
///   wire-order tiebreak, so order-preserving wire fixtures with
///   `;tag=x;foo=y` and `;foo=y;tag=x` compare equal — that is
///   the RFC 3261 §19.1.4 view (URI param order doesn't matter
///   for equality, and §25.1 inherits that for header params).
#[derive(Debug, PartialEq, Eq)]
struct DiffNameAddr {
    display_name: Option<String>,
    uri: NormalizedUri,
    parameters: Vec<(String, Option<String>)>,
}

/// Strip an outer pair of double quotes from a display-name and
/// resolve `\X` quoted-pair escapes inside. If the input is not
/// quoted, returned unchanged. Used to normalize the rsip side to
/// our parser's already-unquoted representation.
fn unquote_display_name(s: &str) -> String {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        // Resolve \X escapes inside.
        let inner = &s[1..s.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let inb = inner.as_bytes();
        let mut i = 0;
        while i < inb.len() {
            if inb[i] == b'\\' && i + 1 < inb.len() {
                out.push(inb[i + 1] as char);
                i += 2;
            } else {
                out.push(inb[i] as char);
                i += 1;
            }
        }
        out
    } else {
        s.to_string()
    }
}

/// Normalize a parameter list: sort by lowercased key (stable),
/// keep value verbatim. The key is lowercased in the output for
/// case-insensitive comparison.
fn normalize_params(params: Vec<(String, Option<String>)>) -> Vec<(String, Option<String>)> {
    let mut out: Vec<(String, Option<String>)> = params
        .into_iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn rsip_from_to_diff(value: &str) -> Result<DiffNameAddr, String> {
    use rsip::headers::untyped::{ToTypedHeader, UntypedHeader};
    let untyped = rsip::headers::From::new(value);
    let typed = untyped.typed().map_err(|e| format!("rsip From: {e}"))?;
    let params = typed
        .params
        .iter()
        .map(rsip_param_to_pair)
        .collect::<Vec<_>>();
    Ok(DiffNameAddr {
        display_name: typed.display_name.as_deref().map(unquote_display_name),
        uri: NormalizedUri::from_str(&typed.uri.to_string()),
        parameters: normalize_params(params),
    })
}

fn rsip_to_to_diff(value: &str) -> Result<DiffNameAddr, String> {
    use rsip::headers::untyped::{ToTypedHeader, UntypedHeader};
    let untyped = rsip::headers::To::new(value);
    let typed = untyped.typed().map_err(|e| format!("rsip To: {e}"))?;
    let params = typed
        .params
        .iter()
        .map(rsip_param_to_pair)
        .collect::<Vec<_>>();
    Ok(DiffNameAddr {
        display_name: typed.display_name.as_deref().map(unquote_display_name),
        uri: NormalizedUri::from_str(&typed.uri.to_string()),
        parameters: normalize_params(params),
    })
}

/// Project a single `rsip::common::uri::Param` to the harness
/// `(name, Option<value>)` pair. We use Display to render the
/// value because rsip's typed param newtypes (`Tag(String)`,
/// `Branch(String)`, etc.) all emit just the raw string via
/// Display. For `Lr` (a flag param) we emit `("lr", None)`. For
/// `Other(name, value)` we keep the name verbatim.
fn rsip_param_to_pair(p: &rsip::common::uri::Param) -> (String, Option<String>) {
    use rsip::common::uri::Param;
    match p {
        Param::Lr => ("lr".to_string(), None),
        Param::Tag(t) => ("tag".to_string(), Some(t.value().to_string())),
        Param::Branch(b) => ("branch".to_string(), Some(b.value().to_string())),
        Param::Received(r) => ("received".to_string(), Some(r.value().to_string())),
        Param::Expires(e) => ("expires".to_string(), Some(e.value().to_string())),
        Param::Q(q) => ("q".to_string(), Some(q.value().to_string())),
        Param::Ttl(t) => ("ttl".to_string(), Some(t.value().to_string())),
        Param::Maddr(m) => ("maddr".to_string(), Some(m.value().to_string())),
        Param::User(u) => ("user".to_string(), Some(u.value().to_string())),
        Param::Method(m) => ("method".to_string(), Some(m.to_string())),
        Param::Transport(t) => ("transport".to_string(), Some(t.to_string())),
        Param::Other(name, Some(v)) => (name.value().to_string(), Some(v.value().to_string())),
        Param::Other(name, None) => (name.value().to_string(), None),
    }
}

fn ours_from_to_diff(value: &str) -> Result<DiffNameAddr, String> {
    let f = OurFrom::parse(value).map_err(|e| format!("ours From: {e}"))?;
    Ok(DiffNameAddr {
        display_name: f.display_name.clone(),
        uri: NormalizedUri::from_str(&f.uri.to_string()),
        parameters: normalize_params(f.params.clone()),
    })
}

fn ours_to_to_diff(value: &str) -> Result<DiffNameAddr, String> {
    let t = OurTo::parse(value).map_err(|e| format!("ours To: {e}"))?;
    Ok(DiffNameAddr {
        display_name: t.display_name.clone(),
        uri: NormalizedUri::from_str(&t.uri.to_string()),
        parameters: normalize_params(t.params.clone()),
    })
}

/// Run the Tier-2 typed-form diff for every `From` and `To` header
/// in `bytes`. Pulls the raw value from each parser's own header
/// list (so each parser sees its own input), then compares.
///
/// If one side accepts the typed-form parse and the other rejects,
/// that is a divergence — panic with both sides for triage. If
/// both reject, accept (mirror Tier-1 policy).
fn assert_typed_from_to_equivalent(bytes: &[u8]) {
    use rsip::SipMessage as RsipMsg;

    // Both parsers need to have already accepted the message at
    // Tier-1; if they didn't, Tier-2 is moot.
    let rs_msg = match RsipMsg::try_from(bytes) {
        Ok(m) => m,
        Err(_) => return,
    };
    let our_msg = match OurMessage::parse(bytes) {
        Ok(m) => m,
        Err(_) => return,
    };

    let rs_headers: &rsip::Headers = match &rs_msg {
        RsipMsg::Request(r) => &r.headers,
        RsipMsg::Response(r) => &r.headers,
    };
    let our_headers = match &our_msg {
        OurMessage::Request(r) => &r.headers,
        OurMessage::Response(r) => &r.headers,
    };

    // From — find the first occurrence on each side. RFC 3261
    // requires exactly one From per message; if either side has
    // more than one we still only diff the first.
    //
    // We use `UntypedHeader::value()` (NOT Display) — Display on
    // an rsip Header emits the full `Name: value` form, while
    // `value()` returns just the value portion, matching what our
    // parser stores in `Header::From(value)`.
    use rsip::headers::untyped::UntypedHeader as _;
    let rsip_from_value = rs_headers.iter().find_map(|h| match h {
        rsip::Header::From(v) => Some(v.value().to_string()),
        _ => None,
    });
    let our_from_value = our_headers.iter().find_map(|h| match h {
        OurHeader::From(v) => Some(v.clone()),
        _ => None,
    });
    if let (Some(rs_v), Some(our_v)) = (rsip_from_value.as_deref(), our_from_value.as_deref()) {
        let rs = rsip_from_to_diff(rs_v);
        let ours = ours_from_to_diff(our_v);
        match (rs, ours) {
            (Ok(a), Ok(b)) => {
                if a != b {
                    panic!(
                        "TYPED-FROM DIVERGENCE.\n\
                         rsip-value: {rs_v:?}\n\
                         our-value:  {our_v:?}\n\
                         rsip:\n{a:#?}\n\
                         ours:\n{b:#?}",
                    );
                }
            }
            (Err(_), Err(_)) => {}
            (Ok(_), Err(e)) => panic!(
                "rsip accepted typed From but ours rejected.\n\
                 value: {our_v:?}\n\
                 ours error: {e}",
            ),
            (Err(e), Ok(_)) => panic!(
                "ours accepted typed From but rsip rejected.\n\
                 value: {rs_v:?}\n\
                 rsip error: {e}",
            ),
        }
    }

    // To — same shape.
    let rsip_to_value = rs_headers.iter().find_map(|h| match h {
        rsip::Header::To(v) => Some(v.value().to_string()),
        _ => None,
    });
    let our_to_value = our_headers.iter().find_map(|h| match h {
        OurHeader::To(v) => Some(v.clone()),
        _ => None,
    });
    if let (Some(rs_v), Some(our_v)) = (rsip_to_value.as_deref(), our_to_value.as_deref()) {
        let rs = rsip_to_to_diff(rs_v);
        let ours = ours_to_to_diff(our_v);
        match (rs, ours) {
            (Ok(a), Ok(b)) => {
                if a != b {
                    panic!(
                        "TYPED-TO DIVERGENCE.\n\
                         rsip-value: {rs_v:?}\n\
                         our-value:  {our_v:?}\n\
                         rsip:\n{a:#?}\n\
                         ours:\n{b:#?}",
                    );
                }
            }
            (Err(_), Err(_)) => {}
            (Ok(_), Err(e)) => panic!(
                "rsip accepted typed To but ours rejected.\n\
                 value: {our_v:?}\n\
                 ours error: {e}",
            ),
            (Err(e), Ok(_)) => panic!(
                "ours accepted typed To but rsip rejected.\n\
                 value: {rs_v:?}\n\
                 rsip error: {e}",
            ),
        }
    }
}

// ---------------------------------------------------------------
// Tier-2: typed `Via` / `CSeq` / `Contact` diff (M5)
// ---------------------------------------------------------------

/// Neutral Tier-2 representation of a single `Via` header value.
///
/// Built from either the rsip or our typed form, then compared
/// field-by-field. Normalization choices:
/// - `protocol`: trimmed, case preserved (`SIP/2.0` is the only
///   thing in the wild; case is the spec).
/// - `transport`: upper-cased — rsip's typed Display emits
///   canonical upper, our parser preserves wire case. Per
///   RFC 3261 §20.42 the transport token is case-insensitive
///   for equality.
/// - `sent_by`: lower-cased — RFC 3261 §19.1.4 / §20.42 host is
///   case-insensitive. Port preserved as text.
/// - `parameters`: same key-sorted, lower-cased-key normalization
///   used elsewhere. We deliberately keep the value verbatim so a
///   real parameter-value divergence surfaces.
#[derive(Debug, PartialEq, Eq)]
struct DiffVia {
    protocol: String,
    transport: String,
    sent_by: String,
    parameters: Vec<(String, Option<String>)>,
}

/// Neutral Tier-2 representation of `CSeq`. Method canonicalized
/// to upper-case (rsip's Display does this; ours via `as_str()`).
#[derive(Debug, PartialEq, Eq)]
struct DiffCSeq {
    seq: u32,
    method: String,
}

/// Neutral Tier-2 representation of `Contact`. The wildcard form
/// is its own variant — rsip's typed::Contact does NOT model the
/// wildcard, so we only assert equivalence on the non-wildcard
/// path (and sanity-check our wildcard handling separately, see
/// `typed_contact_wildcard_*`).
#[derive(Debug, PartialEq, Eq)]
enum DiffContact {
    Wildcard,
    Addr(DiffNameAddr),
}

fn rsip_via_diff(value: &str) -> Result<DiffVia, String> {
    use rsip::headers::untyped::{ToTypedHeader, UntypedHeader};
    let untyped = rsip::headers::Via::new(value);
    let typed = untyped.typed().map_err(|e| format!("rsip Via: {e}"))?;
    let params: Vec<(String, Option<String>)> =
        typed.params.iter().map(rsip_param_to_pair).collect();
    // rsip stores sent-by as a `Uri`. We want the "host[:port]"
    // string only — its Display includes scheme prefix on
    // sip-form URIs but for a Via sent-by tokenized via
    // `Tokenizer::tokenize_without_params` rsip parses the host
    // and (optionally) port without a scheme; Display still
    // emits the scheme (`sip:`) which would mismatch our
    // representation. Build the "host[:port]" form by hand.
    let host = typed.uri.host_with_port.host.to_string();
    let sent_by = match &typed.uri.host_with_port.port {
        Some(p) => format!("{}:{}", host, p),
        None => host,
    };
    Ok(DiffVia {
        protocol: format!("{}", typed.version),
        transport: typed.transport.to_string().to_ascii_uppercase(),
        sent_by: normalize_sent_by(&sent_by),
        parameters: normalize_params(params),
    })
}

fn ours_via_diff(value: &str) -> Result<DiffVia, String> {
    let v = OurVia::parse(value).map_err(|e| format!("ours Via: {e}"))?;
    Ok(DiffVia {
        protocol: v.protocol.clone(),
        transport: v.transport.to_ascii_uppercase(),
        sent_by: normalize_sent_by(&v.sent_by),
        parameters: normalize_params(v.params.clone()),
    })
}

/// Lower-case the host part of a `host[:port]` string, leaving
/// the port (if any) verbatim. IPv6 references stay bracketed.
fn normalize_sent_by(s: &str) -> String {
    // Find a colon outside brackets: IPv6 has internal colons,
    // and `[v6]:port` ends in `]:NNN`. Only the *last* colon
    // outside brackets is the port separator.
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut last_colon: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' => depth += 1,
            b']' => depth -= 1,
            b':' if depth == 0 => last_colon = Some(i),
            _ => {}
        }
    }
    match last_colon {
        Some(idx) => {
            let host = s[..idx].to_ascii_lowercase();
            let port = &s[idx..];
            format!("{}{}", host, port)
        }
        None => s.to_ascii_lowercase(),
    }
}

fn rsip_cseq_diff(value: &str) -> Result<DiffCSeq, String> {
    use rsip::headers::untyped::{ToTypedHeader, UntypedHeader};
    let untyped = rsip::headers::CSeq::new(value);
    let typed = untyped.typed().map_err(|e| format!("rsip CSeq: {e}"))?;
    Ok(DiffCSeq {
        seq: typed.seq,
        method: typed.method.to_string(),
    })
}

fn ours_cseq_diff(value: &str) -> Result<DiffCSeq, String> {
    let c = OurCSeq::parse(value).map_err(|e| format!("ours CSeq: {e}"))?;
    Ok(DiffCSeq {
        seq: c.seq,
        method: c.method.as_str().to_string(),
    })
}

fn rsip_contact_diff(value: &str) -> Result<DiffContact, String> {
    let trimmed = value.trim();
    if trimmed == "*" {
        // rsip's typed Contact does NOT model the wildcard; if we
        // see one, surface it as Wildcard so the Addr-equivalence
        // check skips this header. Our parser produces Wildcard
        // for the same input.
        return Ok(DiffContact::Wildcard);
    }
    use rsip::headers::untyped::{ToTypedHeader, UntypedHeader};
    let untyped = rsip::headers::Contact::new(value);
    let typed = untyped.typed().map_err(|e| format!("rsip Contact: {e}"))?;
    let params: Vec<(String, Option<String>)> =
        typed.params.iter().map(rsip_param_to_pair).collect();
    Ok(DiffContact::Addr(DiffNameAddr {
        display_name: typed.display_name.as_deref().map(unquote_display_name),
        uri: NormalizedUri::from_str(&typed.uri.to_string()),
        parameters: normalize_params(params),
    }))
}

fn ours_contact_diff(value: &str) -> Result<DiffContact, String> {
    let c = OurContact::parse(value).map_err(|e| format!("ours Contact: {e}"))?;
    match c {
        OurContact::Wildcard => Ok(DiffContact::Wildcard),
        OurContact::Addr(a) => Ok(DiffContact::Addr(DiffNameAddr {
            display_name: a.display_name.clone(),
            uri: NormalizedUri::from_str(&a.uri.to_string()),
            parameters: normalize_params(a.params.clone()),
        })),
    }
}

/// Run the Tier-2 typed-form diff for `Via`, `CSeq`, and
/// `Contact` on `bytes`. Each parser's own header list is the
/// source of raw values (so each parser sees its own input),
/// then the typed forms are compared.
///
/// Multiple `Via` headers per message are diffed pairwise in
/// order. CSeq is exactly one per message. Multiple `Contact`
/// headers are diffed pairwise in order.
fn assert_typed_via_cseq_contact_equivalent(bytes: &[u8]) {
    use rsip::headers::untyped::UntypedHeader as _;
    use rsip::SipMessage as RsipMsg;

    let rs_msg = match RsipMsg::try_from(bytes) {
        Ok(m) => m,
        Err(_) => return,
    };
    let our_msg = match OurMessage::parse(bytes) {
        Ok(m) => m,
        Err(_) => return,
    };

    let rs_headers: &rsip::Headers = match &rs_msg {
        RsipMsg::Request(r) => &r.headers,
        RsipMsg::Response(r) => &r.headers,
    };
    let our_headers = match &our_msg {
        OurMessage::Request(r) => &r.headers,
        OurMessage::Response(r) => &r.headers,
    };

    // -- Via (multiple per message possible) --
    //
    // rsip's Header::Via only matches the `Via:` long form. Compact
    // `v: ...` (RFC 3261 §20.42) lands in Header::Other("v", ...)
    // because rsip 0.4 doesn't resolve compact forms before the typed
    // dispatch. Pick up both shapes here so the count and value match
    // our parser (which DOES normalize compact → long-form).
    let rs_vias: Vec<String> = rs_headers
        .iter()
        .filter_map(|h| match h {
            rsip::Header::Via(v) => Some(v.value().to_string()),
            rsip::Header::Other(name, value) if name.eq_ignore_ascii_case("v") => {
                Some(value.clone())
            }
            _ => None,
        })
        .collect();
    let our_vias: Vec<String> = our_headers
        .iter()
        .filter_map(|h| match h {
            OurHeader::Via(v) => Some(v.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        rs_vias.len(),
        our_vias.len(),
        "Via header count differs: rsip {} vs ours {} ({:?} vs {:?})",
        rs_vias.len(),
        our_vias.len(),
        rs_vias,
        our_vias,
    );
    for (rs_v, our_v) in rs_vias.iter().zip(our_vias.iter()) {
        let rs = rsip_via_diff(rs_v);
        let ours = ours_via_diff(our_v);
        match (rs, ours) {
            (Ok(a), Ok(b)) => {
                if a != b {
                    panic!(
                        "TYPED-VIA DIVERGENCE.\n\
                         rsip-value: {rs_v:?}\n\
                         our-value:  {our_v:?}\n\
                         rsip:\n{a:#?}\n\
                         ours:\n{b:#?}",
                    );
                }
            }
            (Err(_), Err(_)) => {}
            (Ok(_), Err(e)) => panic!(
                "rsip accepted typed Via but ours rejected.\n\
                 value: {our_v:?}\n\
                 ours error: {e}",
            ),
            (Err(e), Ok(_)) => panic!(
                "ours accepted typed Via but rsip rejected.\n\
                 value: {rs_v:?}\n\
                 rsip error: {e}",
            ),
        }
    }

    // -- CSeq (exactly one per valid message) --
    let rs_cseq = rs_headers.iter().find_map(|h| match h {
        rsip::Header::CSeq(v) => Some(v.value().to_string()),
        _ => None,
    });
    let our_cseq = our_headers.iter().find_map(|h| match h {
        OurHeader::CSeq(v) => Some(v.clone()),
        _ => None,
    });
    if let (Some(rs_v), Some(our_v)) = (rs_cseq.as_deref(), our_cseq.as_deref()) {
        let rs = rsip_cseq_diff(rs_v);
        let ours = ours_cseq_diff(our_v);
        match (rs, ours) {
            (Ok(a), Ok(b)) => {
                if a != b {
                    panic!(
                        "TYPED-CSEQ DIVERGENCE.\n\
                         rsip-value: {rs_v:?}\n\
                         our-value:  {our_v:?}\n\
                         rsip:\n{a:#?}\n\
                         ours:\n{b:#?}",
                    );
                }
            }
            (Err(_), Err(_)) => {}
            (Ok(_), Err(e)) => panic!(
                "rsip accepted typed CSeq but ours rejected.\n\
                 value: {our_v:?}\n\
                 ours error: {e}",
            ),
            (Err(e), Ok(_)) => panic!(
                "ours accepted typed CSeq but rsip rejected.\n\
                 value: {rs_v:?}\n\
                 rsip error: {e}",
            ),
        }
    }

    // -- Contact (multiple per message possible) --
    //
    // Compact form `m:` falls into rsip's Header::Other (same reason
    // as Via above).
    let rs_contacts: Vec<String> = rs_headers
        .iter()
        .filter_map(|h| match h {
            rsip::Header::Contact(v) => Some(v.value().to_string()),
            rsip::Header::Other(name, value) if name.eq_ignore_ascii_case("m") => {
                Some(value.clone())
            }
            _ => None,
        })
        .collect();
    let our_contacts: Vec<String> = our_headers
        .iter()
        .filter_map(|h| match h {
            OurHeader::Contact(v) => Some(v.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        rs_contacts.len(),
        our_contacts.len(),
        "Contact header count differs: rsip {} vs ours {}",
        rs_contacts.len(),
        our_contacts.len(),
    );
    for (rs_v, our_v) in rs_contacts.iter().zip(our_contacts.iter()) {
        let rs = rsip_contact_diff(rs_v);
        let ours = ours_contact_diff(our_v);
        match (rs, ours) {
            (Ok(a), Ok(b)) => {
                if a != b {
                    panic!(
                        "TYPED-CONTACT DIVERGENCE.\n\
                         rsip-value: {rs_v:?}\n\
                         our-value:  {our_v:?}\n\
                         rsip:\n{a:#?}\n\
                         ours:\n{b:#?}",
                    );
                }
            }
            (Err(_), Err(_)) => {}
            (Ok(_), Err(e)) => panic!(
                "rsip accepted typed Contact but ours rejected.\n\
                 value: {our_v:?}\n\
                 ours error: {e}",
            ),
            (Err(e), Ok(_)) => panic!(
                "ours accepted typed Contact but rsip rejected.\n\
                 value: {rs_v:?}\n\
                 rsip error: {e}",
            ),
        }
    }
}

// ---------------------------------------------------------------
// Equivalence assertion
// ---------------------------------------------------------------

fn assert_equivalent(bytes: &[u8]) {
    let rs = rsip_to_diff(bytes);
    let ours = ours_to_diff(bytes);
    match (rs, ours) {
        (Ok(a), Ok(b)) => {
            if a != b {
                panic!(
                    "DIVERGENCE on parse-success.\n\
                     rsip:\n{a:#?}\n\
                     ours:\n{b:#?}",
                );
            }
        }
        (Err(_), Err(_)) => { /* both rejected — fine, errors may differ */ }
        (Ok(a), Err(e)) => panic!(
            "rsip accepted but ours rejected:\n\
             {a:#?}\n\
             ours error: {e}",
        ),
        (Err(e), Ok(b)) => panic!(
            "ours accepted but rsip rejected:\n\
             {b:#?}\n\
             rsip error: {e}",
        ),
    }
    // Tier-2: typed From/To check (M4). Independent of Tier-1
    // result handling because we want to surface typed-form
    // divergences even where Tier-1 was clean.
    assert_typed_from_to_equivalent(bytes);
    // Tier-2: typed Via/CSeq/Contact check (M5).
    assert_typed_via_cseq_contact_equivalent(bytes);
}

// ---------------------------------------------------------------
// Tests against the mdsiprtp3 fixture corpus
// ---------------------------------------------------------------

#[test]
fn diff_mdsiprtp3_invite_with_via() {
    let bytes = include_bytes!("fixtures/mdsiprtp3/invite_with_via.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_mdsiprtp3_response_200_ok() {
    let bytes = include_bytes!("fixtures/mdsiprtp3/response_200_ok.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_mdsiprtp3_invite_with_body() {
    let bytes = include_bytes!("fixtures/mdsiprtp3/invite_with_body.sip");
    assert_equivalent(bytes);
}

// ---------------------------------------------------------------
// Tests against the hand-curated fixture corpus
// ---------------------------------------------------------------
//
// See `tests/fixtures/handcrafted/README.md` for the catalog. These
// exercise corners not covered by the mdsiprtp3 fixtures: compact-form
// headers, folded headers, multi-`Via`, authentication headers, and
// the REGISTER / ACK / CANCEL methods.

#[test]
fn diff_handcrafted_register_with_contact() {
    let bytes = include_bytes!("fixtures/handcrafted/register_with_contact.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_handcrafted_invite_compact_via() {
    let bytes = include_bytes!("fixtures/handcrafted/invite_compact_via.sip");
    assert_equivalent(bytes);
}

/// rsip 0.4 does NOT accept RFC 3261 §7.3.1 line folding — its
/// tokenizer rejects the SP-led continuation as a malformed header
/// line. Our parser correctly accepts it and merges the fold into a
/// single header value (see `framing::parse_header_block`'s folding
/// path, also covered by the unit test `test_parse_header_block_folding*`).
/// This is a surprising rsip behavior we deliberately differ from;
/// see the brief's triage policy ("mark `#[ignore]` with a comment").
/// When we drop rsip in M10 this test should be unmarked and the
/// equivalence check replaced with a direct on-our-parser assertion.
#[test]
#[ignore = "rsip 0.4 rejects RFC 3261 §7.3.1 line folding; our parser correctly accepts it"]
fn diff_handcrafted_invite_folded_subject() {
    let bytes = include_bytes!("fixtures/handcrafted/invite_folded_subject.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_handcrafted_response_407_with_proxy_authenticate() {
    let bytes = include_bytes!("fixtures/handcrafted/response_407_with_proxy_authenticate.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_handcrafted_ack_for_2xx() {
    let bytes = include_bytes!("fixtures/handcrafted/ack_for_2xx.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_handcrafted_cancel() {
    let bytes = include_bytes!("fixtures/handcrafted/cancel.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_handcrafted_response_with_multi_via() {
    let bytes = include_bytes!("fixtures/handcrafted/response_with_multi_via.sip");
    assert_equivalent(bytes);
}

// ---------------------------------------------------------------
// Tests against the RFC 4475 torture-test corpus (M6)
// ---------------------------------------------------------------
//
// See `tests/fixtures/rfc4475/README.md` for the catalog. These exercise
// the corner cases described in RFC 4475 §3 ("Valid Messages"). Each
// fixture is a representative SIP message constructed per the torture-
// test category — we are testing the same parser corner the RFC §3.1
// paragraph describes, not asserting byte-perfect copies of the RFC's
// own example bodies.

/// §3.1.1 "A short tortuous INVITE": quoted display names with
/// embedded SP / quoted-pairs, parameter-name-only forms, header
/// values broken across lines via line folding, and heavy interior
/// whitespace (e.g. `SIP  /   2.0  /UDP`).
///
/// **Divergence pinned:** rsip 0.4 rejects the entire message at
/// tokenize-version time — the combination of folding + interior
/// whitespace in `Via:` defeats its tokenizer. RFC 3261 §7.3.1
/// (line folding) and §25.1 (LWS in HCOLON / param SEMI / etc.)
/// mandate acceptance of all of these forms, so this is a real
/// rsip-side spec deficiency. Our parser correctly accepts (see
/// `framing::parse_header_block` folding path; `name_addr::*`
/// surrounding-whitespace handling).
///
/// At M10 (rsip dropped from runtime deps), this test should be
/// retargeted to a direct on-our-parser assertion.
#[test]
fn diff_rfc4475_wsinv_rsip_rejects() {
    let bytes: &[u8] = include_bytes!("fixtures/rfc4475/wsinv.sip");
    let rs = rsip::SipMessage::try_from(bytes);
    assert!(
        rs.is_err(),
        "rsip 0.4 rejects RFC 4475 §3.1.1 wsinv torture test; \
         got Ok({rs:?}) — update this test if rsip changed",
    );
    let ours = OurMessage::parse(bytes);
    assert!(
        ours.is_ok(),
        "our parser must accept RFC 4475 §3.1.1 wsinv; got Err({ours:?})",
    );
}

#[test]
fn diff_rfc4475_esc01() {
    // §3.1.2.2 "Valid use of the % escaping": escaped chars in user/
    // contact URIs.
    let bytes = include_bytes!("fixtures/rfc4475/esc01.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_rfc4475_escnull() {
    // §3.1.2.3 "Escaped nulls in URIs": `%00` in user portion.
    let bytes = include_bytes!("fixtures/rfc4475/escnull.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_rfc4475_esc02() {
    // §3.1.2.4 "Use of % when it is not an escape": `%` followed by
    // non-hex inside header values.
    let bytes = include_bytes!("fixtures/rfc4475/esc02.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_rfc4475_lwsdisp() {
    // §3.1.2.5 "No LWS between Display Name and `<`".
    let bytes = include_bytes!("fixtures/rfc4475/lwsdisp.sip");
    assert_equivalent(bytes);
}

#[test]
fn diff_rfc4475_longreq() {
    // §3.1.2.6 "Long values in header fields": exercises size-limit
    // path. Our defense-in-depth caps at 8192 per value; this fixture
    // sits well below that.
    let bytes = include_bytes!("fixtures/rfc4475/longreq.sip");
    assert_equivalent(bytes);
}

/// §3.1.2.7 "Extra trailing octets in a UDP datagram": the first
/// message has `Content-Length: 0` (no body), but the datagram
/// contains a fully-formed second request after that. RFC 4475
/// §3.1.2.7 says: *"Implementations should process the request and
/// ignore the extra bytes."*
///
/// **Divergence pinned:** rsip 0.4 ignores Content-Length and
/// captures the trailing octets as the body of the first request.
/// Our parser correctly truncates the body to Content-Length per
/// RFC 3261 §18.3. Both parse the framing, but produce different
/// `body`. Pin the asymmetry; tighten when rsip is dropped at M10.
#[test]
fn diff_rfc4475_dblreq_rsip_keeps_trailing() {
    let bytes: &[u8] = include_bytes!("fixtures/rfc4475/dblreq.sip");
    let ours = OurMessage::parse(bytes).expect("our parser accepts dblreq");
    let our_body: &Vec<u8> = match &ours {
        OurMessage::Request(r) => &r.body,
        OurMessage::Response(r) => &r.body,
    };
    assert!(
        our_body.is_empty(),
        "ours: Content-Length: 0 → body must be empty; got {} bytes",
        our_body.len(),
    );
    let rs = rsip::SipMessage::try_from(bytes).expect("rsip accepts dblreq framing");
    let rs_body = match &rs {
        rsip::SipMessage::Request(r) => &r.body,
        rsip::SipMessage::Response(r) => &r.body,
    };
    assert!(
        !rs_body.is_empty(),
        "rsip 0.4 captures trailing octets as body; if it now \
         truncates per Content-Length, this pin can be removed.",
    );
}

/// §3.1.2.8 "Semicolons in URI user part": RFC 3261 §25.1
/// `user-unreserved = "&" / "=" / "+" / "$" / "," / ";" / "?" /
/// "/"` — so `;` is a legal user character. The Request-URI
/// `sip:user;par=u%40example.net@example.com` therefore has user
/// `user;par=u%40example.net` (the `;` and `@` decoded inside the
/// user portion) and host `example.com`.
///
/// **Divergence pinned:** rsip 0.4 rejects the entire message —
/// its tokenizer treats `;` as the user/params boundary without
/// honoring the userinfo grammar. Our parser correctly splits at
/// the `@` first per RFC 3261 §19.1.1 (this M6 milestone fixed a
/// bug in our parser where `;` before `@` was ALSO treated as a
/// param separator — see `crates/rsiprtp/src/sip/uri.rs`
/// `parse()`).
#[test]
fn diff_rfc4475_semiuri_rsip_rejects() {
    let bytes: &[u8] = include_bytes!("fixtures/rfc4475/semiuri.sip");
    let ours = OurMessage::parse(bytes).expect("ours accepts semiuri");
    if let OurMessage::Request(r) = &ours {
        // Verify the URI parse produced the right user/host split.
        let uri = SipUri::parse(&r.uri).expect("our URI parses");
        assert_eq!(uri.user(), Some("user;par=u%40example.net"));
        assert_eq!(uri.host(), "example.com");
    } else {
        panic!("expected request");
    }
    let rs = rsip::SipMessage::try_from(bytes);
    assert!(
        rs.is_err(),
        "rsip 0.4 rejects URI with `;` in user part; got Ok({rs:?}) \
         — update this test if rsip changed",
    );
}

/// §3.1.2.9 "Varied and unknown transport types in Via". RFC 3261
/// §20.42 grammar: `transport-param = "transport=" ( "udp" / "tcp"
/// / "sctp" / "tls" / other-transport )` where `other-transport =
/// token`. Unknown but token-shaped transports MUST be accepted at
/// parse time (consumers can route or reject as they see fit).
///
/// **Divergence pinned (typed-Via path only):** rsip 0.4's typed
/// Via parser rejects unknown transport tokens (`TUNA` in our
/// fixture). Tier-1 framing on both sides is fine; the divergence
/// is in `rsip::headers::Via::typed()`. Our parser accepts.
///
/// We assert the message frames cleanly on both sides, then assert
/// rsip's typed-Via specifically rejects the unknown-transport
/// variant. When rsip is dropped at M10 this test is retargeted.
#[test]
fn diff_rfc4475_transports_rsip_rejects_unknown_transport() {
    let bytes: &[u8] = include_bytes!("fixtures/rfc4475/transports.sip");
    // Tier-1 framing is clean on both sides.
    let _ours_msg = OurMessage::parse(bytes).expect("ours frames transports");
    let _rsip_msg = rsip::SipMessage::try_from(bytes).expect("rsip frames transports");
    // Tier-2 typed-Via on the unknown-transport entry: rsip rejects.
    let unknown_via = "SIP/2.0/TUNA t6.example.com;branch=z9hG4bK6";
    let r = rsip_via_diff(unknown_via);
    assert!(
        r.is_err(),
        "rsip 0.4 rejects unknown transport in typed Via; got \
         Ok({r:?}) — update this test if rsip changed",
    );
    let d = ours_via_diff(unknown_via).expect("ours typed-Via accepts unknown transport");
    assert_eq!(d.transport, "TUNA");
}

#[test]
fn diff_rfc4475_unreason() {
    // §3.1.2.10 "Unusual REGISTER request with binding".
    let bytes = include_bytes!("fixtures/rfc4475/unreason.sip");
    assert_equivalent(bytes);
}

// ---------------------------------------------------------------
// RFC 4475 §4 — Invalid Messages: both parsers MUST reject
// ---------------------------------------------------------------
//
// Per RFC 4475 §4 ("Invalid Messages"), each of these is malformed in
// a way that any conformant parser must reject. The harness assertion
// is "both parsers return Err" — if EITHER parser accepts, that's a
// real bug we want to surface.
//
// Fixtures live in `tests/fixtures/rfc4475_invalid/` (separate dir
// from the §3 valid set so the rejection-expectation is structurally
// explicit).

/// Helper for §4 fixtures: assert both rsip 0.4 and our parser return
/// an error. If either accepts, panic with both shapes for triage.
fn assert_both_reject(label: &str, bytes: &[u8]) {
    let rs = rsip::SipMessage::try_from(bytes);
    let ours = OurMessage::parse(bytes);
    match (rs.is_ok(), ours.is_ok()) {
        (false, false) => { /* expected */ }
        (true, false) => panic!(
            "{label}: rsip ACCEPTED but ours rejected — \
             RFC 4475 §4 says this is invalid; rsip is wrong.\n\
             rsip parsed: {:#?}",
            rs.unwrap()
        ),
        (false, true) => panic!(
            "{label}: ours ACCEPTED but rsip rejected — \
             RFC 4475 §4 says this is invalid; we are too lenient.\n\
             ours parsed: {:#?}",
            ours.unwrap()
        ),
        (true, true) => panic!(
            "{label}: BOTH parsers accepted — RFC 4475 §4 says this \
             is invalid; both are too lenient."
        ),
    }
}

#[test]
fn diff_rfc4475_invalid_no_version() {
    // §4-style: request line missing the `SIP/2.0` token.
    let bytes = include_bytes!("fixtures/rfc4475_invalid/badaspec_no_version.sip");
    assert_both_reject("badaspec_no_version", bytes);
}

// NOTE: a "negative Content-Length" fixture was considered (RFC 4475
// §4 ncl) but dropped — both parsers store header values as strings
// and validate digits only when bounding the body, which is a
// typed-form / body-extraction concern rather than tier-1 framing.
// RFC 4475 §4 ncl really exercises tier-2 logic that this harness
// does not cover.

#[test]
fn diff_rfc4475_invalid_garbage_start() {
    // §4-style: start line is neither a valid request nor a valid
    // status line.
    let bytes = include_bytes!("fixtures/rfc4475_invalid/badaspec_garbage_start.sip");
    assert_both_reject("badaspec_garbage_start", bytes);
}

// ---------------------------------------------------------------
// Tests against the rsiprtp fuzz corpus (populated by M11)
// ---------------------------------------------------------------

/// Diff every file in the rsiprtp fuzz corpus, if it exists.
///
/// The corpus directory is created and populated by M11's overnight fuzz
/// campaign. Until then this test is a no-op (vacuously passes). After
/// M11 lands, every fuzz-corpus input becomes a Tier-1 differential
/// assertion against rsip 0.4.
#[test]
fn diff_fuzz_corpus() {
    let corpus_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("sip_message_parse")
        .join("corpus");
    if !corpus_dir.exists() {
        // Corpus not yet populated; M11 owns this. No-op.
        return;
    }
    let entries: Vec<_> = std::fs::read_dir(&corpus_dir)
        .expect("corpus dir exists per check above")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .collect();
    for entry in entries {
        let path = entry.path();
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read fuzz corpus file {:?}: {}", path, e));
        // Wrap each file's assertion in its own panic message so a divergence
        // surfaces the file name, not just the bytes.
        let result = std::panic::catch_unwind(|| assert_equivalent(&bytes));
        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }
}

// ---------------------------------------------------------------
// Sanity tests for the harness itself
// ---------------------------------------------------------------

#[test]
fn normalize_collapses_runs_of_whitespace() {
    assert_eq!(normalize_value("a   b  c"), "a b c");
    assert_eq!(
        normalize_value(" \tleading \t and trailing \t "),
        "leading and trailing"
    );
}

#[test]
fn normalize_strips_comments() {
    assert_eq!(normalize_value("foo (this is a comment) bar"), "foo bar");
    assert_eq!(
        normalize_value("Acme/1.0 (server (nested) detail) baz"),
        "Acme/1.0 baz",
    );
}

#[test]
fn normalize_preserves_quoted_strings() {
    // Parens inside a quoted string are NOT a comment.
    assert_eq!(
        normalize_value(r#""display (name)" <sip:a@b>"#),
        r#""display (name)" <sip:a@b>"#,
    );
}

#[test]
fn normalize_handles_quoted_pair_escapes() {
    // \" inside a quoted string is literal; doesn't end the string.
    assert_eq!(normalize_value(r#""a\"b" trailing"#), r#""a\"b" trailing"#,);
}

// ---------------------------------------------------------------
// Sanity tests for the typed-form (M4) normalization
// ---------------------------------------------------------------
//
// These exercise the DiffNameAddr normalization without needing a
// full SIP message — they construct the value strings inline. Two
// shapes are checked:
//
// 1. Parameter-order independence: `;tag=x;foo=y` should normalize
//    identically to `;foo=y;tag=x`. RFC 3261 §19.1.4 (URI params)
//    and §25.1's `*( SEMI generic-param )` production make this
//    legitimate at equality. Both rsip and our parser should
//    agree.
//
// 2. Quoted vs unquoted display name with a token-only inner: per
//    RFC 3261 §20.10/25.1, `"Alice" <sip:a@b>` and `Alice <sip:a@b>`
//    encode the same display-name "Alice". Our normalizer
//    (`unquote_display_name`) strips the quotes on the rsip side
//    so the two compare equal — this is the right call when the
//    inner content is a bare token (no characters that would
//    require quoting). For inner content that DOES require quoting
//    (e.g. spaces) the two are NOT equivalent — the unquoted form
//    is malformed under §25.1 and rsip and our parser would both
//    reject or interpret differently.

#[test]
fn typed_from_param_order_is_normalized() {
    let v1 = "Alice <sip:alice@example.com>;tag=x;foo=y";
    let v2 = "Alice <sip:alice@example.com>;foo=y;tag=x";
    let d1 = ours_from_to_diff(v1).unwrap();
    let d2 = ours_from_to_diff(v2).unwrap();
    assert_eq!(d1, d2, "param-order normalization failed: {d1:?} vs {d2:?}");
    let r1 = rsip_from_to_diff(v1).unwrap();
    let r2 = rsip_from_to_diff(v2).unwrap();
    assert_eq!(r1, r2);
    assert_eq!(d1, r1);
}

#[test]
fn typed_from_quoted_token_display_normalizes_to_unquoted() {
    // For a *token* inner (no chars requiring quotation) RFC 3261
    // §25.1's `display-name = *(token LWS) / quoted-string` lets
    // either form encode the same name.
    let v_quoted = r#""Alice" <sip:alice@example.com>;tag=t"#;
    let v_token = "Alice <sip:alice@example.com>;tag=t";
    let d_quoted = ours_from_to_diff(v_quoted).unwrap();
    let d_token = ours_from_to_diff(v_token).unwrap();
    assert_eq!(d_quoted, d_token);
    let r_quoted = rsip_from_to_diff(v_quoted).unwrap();
    let r_token = rsip_from_to_diff(v_token).unwrap();
    assert_eq!(r_quoted, r_token);
    assert_eq!(d_quoted, r_quoted);
}

#[test]
fn typed_from_quoted_with_space_preserves_inner() {
    // Inner has a space → MUST be quoted on the wire. The
    // normalized display name is the unquoted "Alice Smith".
    let v = r#""Alice Smith" <sip:a@b>;tag=t"#;
    let d = ours_from_to_diff(v).unwrap();
    let r = rsip_from_to_diff(v).unwrap();
    assert_eq!(d.display_name.as_deref(), Some("Alice Smith"));
    assert_eq!(d, r);
}

#[test]
fn typed_to_no_tag_is_normalized_consistently() {
    // To on initial INVITE has no tag — both parsers should accept.
    let v = "Bob <sip:bob@example.com>";
    let d = ours_to_to_diff(v).unwrap();
    let r = rsip_to_to_diff(v).unwrap();
    assert_eq!(d, r);
    assert_eq!(d.display_name.as_deref(), Some("Bob"));
    assert!(d.parameters.is_empty());
}

#[test]
fn typed_from_bare_addr_spec_normalizes() {
    // No angle brackets, `;tag=` is a header param.
    let v = "sip:bob@example.com;tag=xyz";
    let d = ours_from_to_diff(v).unwrap();
    let r = rsip_from_to_diff(v).unwrap();
    assert_eq!(d, r);
    assert_eq!(d.display_name, None);
    assert_eq!(
        d.parameters,
        vec![("tag".to_string(), Some("xyz".to_string()))]
    );
}

#[test]
fn unquote_display_name_handles_escapes() {
    assert_eq!(unquote_display_name(r#""Alice""#), "Alice");
    assert_eq!(unquote_display_name(r#""Alice Smith""#), "Alice Smith");
    assert_eq!(
        unquote_display_name(r#""He said \"hi\"""#),
        r#"He said "hi""#
    );
    assert_eq!(unquote_display_name("Alice"), "Alice"); // no quotes, pass-through
}

/// M4 follow-up (HLD note): quoted parameter values containing a
/// semicolon. RFC 3261 §25.1 `gen-value = token / host /
/// quoted-string`, so `;name="x;y"` is legal and the inner `;` is
/// NOT a parameter separator.
///
/// Investigation result (DA's flagged divergence): **rsip 0.4
/// rejects the entire input** when a generic-param value is a
/// quoted-string containing a `;`. Its `name_params` tokenizer
/// splits on `;` first, then runs token-only matching on the
/// segments — `name="x` is left over as "trailing input" and
/// fails. Our parser correctly honors the quoted-string boundary
/// (see `name_addr::parse_params`) and accepts the input.
///
/// This is a one-accepts / one-rejects case. Per the HLD's diff
/// triage policy ("spec is explicit (fix the wrong one)") the
/// spec is on our side: §25.1 `gen-value = token / host /
/// quoted-string`. We document the asymmetry here rather than
/// silently masking it. When rsip is dropped at M10 this test
/// becomes a direct on-our-parser assertion (no rsip side).
#[test]
fn typed_from_quoted_param_value_with_semicolon_rsip_rejects() {
    let v = r#"<sip:a@b>;tag=t;name="x;y""#;
    // Our parser accepts and produces two params, with the
    // semicolon-bearing value intact inside the quoted string.
    let d = ours_from_to_diff(v).unwrap();
    assert_eq!(d.parameters.len(), 2, "ours: {:?}", d.parameters);
    let name_value = d
        .parameters
        .iter()
        .find(|(k, _)| k == "name")
        .and_then(|(_, v)| v.as_deref());
    // The value retains its surrounding quotes (matches our
    // NameAddr behavior — see `test_quoted_param_value` there).
    assert_eq!(name_value, Some("\"x;y\""));
    // rsip rejects this. Pin that for documentation; if a future
    // rsip update fixes it the assertion will fire and we can
    // tighten the harness.
    let r = rsip_from_to_diff(v);
    assert!(
        r.is_err(),
        "rsip 0.4 rejects quoted-param-with-semicolon; \
         got Ok({r:?}) — update this test if rsip changed",
    );
}

/// Sister test: a quoted param value WITHOUT a semicolon. rsip
/// 0.4 still rejects this — its `name_params` tokenizer doesn't
/// model `gen-value = quoted-string` *at all* (not just the
/// semicolon-inside subcase). Confirms the divergence is broader
/// than the semicolon case.
///
/// Our parser accepts and stores the value with surrounding
/// quotes preserved; consumers who want the unquoted text apply
/// `unquote_display_name`-style stripping at the call site. We
/// pin both shapes here.
#[test]
fn typed_from_quoted_param_value_rsip_rejects_broadly() {
    let v = r#"<sip:a@b>;tag=t;name="hello""#;
    let d = ours_from_to_diff(v).unwrap();
    // Our parser keeps surrounding quotes verbatim.
    let name_value = d
        .parameters
        .iter()
        .find(|(k, _)| k == "name")
        .and_then(|(_, v)| v.as_deref());
    assert_eq!(name_value, Some("\"hello\""));
    let r = rsip_from_to_diff(v);
    assert!(
        r.is_err(),
        "rsip 0.4 rejects all quoted-string param values; got \
         Ok({r:?}) — update this test if rsip changed",
    );
}

// ---------------------------------------------------------------
// Sanity tests for the typed-form (M5) Via/CSeq/Contact path
// ---------------------------------------------------------------

#[test]
fn typed_via_basic_normalizes() {
    let v = "SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK1";
    let d = ours_via_diff(v).unwrap();
    let r = rsip_via_diff(v).unwrap();
    assert_eq!(d, r);
    assert_eq!(d.protocol, "SIP/2.0");
    assert_eq!(d.transport, "UDP");
    assert_eq!(d.sent_by, "host.example.com:5060");
}

#[test]
fn typed_via_transport_case_normalized_to_upper() {
    let v_upper = "SIP/2.0/UDP host:5060;branch=z";
    let v_lower = "SIP/2.0/udp host:5060;branch=z";
    let d_upper = ours_via_diff(v_upper).unwrap();
    let d_lower = ours_via_diff(v_lower).unwrap();
    assert_eq!(d_upper.transport, d_lower.transport);
}

#[test]
fn typed_via_host_case_normalized_to_lower() {
    let v_lc = "SIP/2.0/UDP host.example.com:5060;branch=z";
    let v_uc = "SIP/2.0/UDP HOST.EXAMPLE.COM:5060;branch=z";
    let d_lc = ours_via_diff(v_lc).unwrap();
    let d_uc = ours_via_diff(v_uc).unwrap();
    assert_eq!(d_lc.sent_by, d_uc.sent_by);
}

/// RFC 3261 §20.42 + RFC 5118 §4.1: Via sent-by may be a bracketed
/// IPv6 reference, e.g. `[2001:db8::1]:5060`. **rsip 0.4 rejects
/// this** — its sent-by tokenizer doesn't model the
/// `IP6reference` production. Our parser accepts it (see
/// `via::test_parse_ipv6_with_port`).
///
/// Like the quoted-param-with-semicolon case, this is a
/// one-accepts/one-rejects divergence where the spec is on our
/// side. Pin the asymmetry; tighten when rsip is dropped at M10.
#[test]
fn typed_via_ipv6_rsip_rejects() {
    let v = "SIP/2.0/UDP [2001:db8::1]:5060;branch=z9hG4bKabc";
    let d = ours_via_diff(v).unwrap();
    assert_eq!(d.sent_by, "[2001:db8::1]:5060");
    let r = rsip_via_diff(v);
    assert!(
        r.is_err(),
        "rsip 0.4 rejects IPv6 sent-by; got Ok({r:?}) — \
         update this test if rsip changed",
    );
}

#[test]
fn typed_via_rport_flag_and_value_both_match_rsip() {
    // rport without value (client request): rsip stores as
    // Other("rport", None); we as ("rport", None).
    let v_flag = "SIP/2.0/UDP host:5060;branch=z;rport";
    let d_flag = ours_via_diff(v_flag).unwrap();
    let r_flag = rsip_via_diff(v_flag).unwrap();
    assert_eq!(d_flag, r_flag);

    // rport with value (server response).
    let v_val = "SIP/2.0/UDP host:5060;branch=z;rport=12345";
    let d_val = ours_via_diff(v_val).unwrap();
    let r_val = rsip_via_diff(v_val).unwrap();
    assert_eq!(d_val, r_val);
}

#[test]
fn typed_cseq_basic_normalizes() {
    let v = "1 INVITE";
    let d = ours_cseq_diff(v).unwrap();
    let r = rsip_cseq_diff(v).unwrap();
    assert_eq!(d, r);
    assert_eq!(d.seq, 1);
    assert_eq!(d.method, "INVITE");
}

#[test]
fn typed_cseq_method_case_normalized() {
    // rsip Display upper-cases; our Method::as_str() also upper.
    let v = "42 invite";
    let d = ours_cseq_diff(v).unwrap();
    let r = rsip_cseq_diff(v).unwrap();
    assert_eq!(d, r);
    assert_eq!(d.method, "INVITE");
}

#[test]
fn typed_cseq_high_seq_numbers() {
    let v = format!("{} BYE", u32::MAX);
    let d = ours_cseq_diff(&v).unwrap();
    let r = rsip_cseq_diff(&v).unwrap();
    assert_eq!(d, r);
    assert_eq!(d.seq, u32::MAX);
}

#[test]
fn typed_contact_simple_normalizes() {
    let v = "<sip:alice@example.com>;expires=3600";
    let d = ours_contact_diff(v).unwrap();
    let r = rsip_contact_diff(v).unwrap();
    assert_eq!(d, r);
    if let DiffContact::Addr(a) = &d {
        assert!(a.display_name.is_none());
    } else {
        panic!("expected Addr");
    }
}

#[test]
fn typed_contact_wildcard_handled_on_both_sides() {
    let v = "*";
    let d = ours_contact_diff(v).unwrap();
    let r = rsip_contact_diff(v).unwrap();
    assert!(matches!(d, DiffContact::Wildcard));
    assert!(matches!(r, DiffContact::Wildcard));
}

#[test]
fn typed_contact_with_quoted_display_normalizes() {
    let v = r#""Alice" <sip:alice@example.com>;expires=300;q=0.7"#;
    let d = ours_contact_diff(v).unwrap();
    let r = rsip_contact_diff(v).unwrap();
    assert_eq!(d, r);
    if let DiffContact::Addr(a) = &d {
        assert_eq!(a.display_name.as_deref(), Some("Alice"));
    } else {
        panic!("expected Addr");
    }
}

#[test]
fn typed_contact_bare_addr_spec_normalizes() {
    let v = "sip:bob@example.com;expires=60";
    let d = ours_contact_diff(v).unwrap();
    let r = rsip_contact_diff(v).unwrap();
    assert_eq!(d, r);
}

#[test]
fn normalize_does_not_apply_quoted_pair_outside_string_or_comment() {
    // RFC 3261 §25.1: quoted-pair only valid inside quoted-string or comment.
    // Outside both, a backslash is a literal byte and the parens are real (not comment-start).
    let input = r"foo \(literal\) bar";
    let out = normalize_value(input);
    // The parens are NOT comments since they're not introduced by an unescaped '(',
    // they're escaped. But our parser doesn't escape; the check is that we don't
    // silently swallow the closing ')'. Concretely: output must contain both '(' and ')'.
    assert!(out.contains('('), "expected '(' preserved, got: {out:?}");
    assert!(out.contains(')'), "expected ')' preserved, got: {out:?}");
}
