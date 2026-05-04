//! SIP message framing — start line + header block + body split.
//!
//! Pure splitting logic. No header *value* parsing happens here; the
//! caller hands header lines to [`Header::parse_line`] via
//! [`parse_header_block`].

use super::header::{Header, Headers, MAX_HEADERS, MAX_HEADER_VALUE_LEN, MAX_START_LINE_LEN};
use super::method::Method;
use super::status::StatusCode;
use crate::core::SipError;
use crate::sip::uri::SipUri;
use std::str::FromStr;

/// Maximum number of fold-continuation lines (RFC 3261 §7.3.1) we
/// accept on a single logical header. The post-fold *length* is
/// already capped indirectly via `MAX_HEADER_VALUE_LEN +
/// MAX_START_LINE_LEN`, but a header with 1000 single-byte fold
/// lines accumulates many small allocations along the way.
/// Pre-M11 fuzz-prep DoS hardening.
pub const MAX_FOLD_LINES_PER_HEADER: usize = 32;

/// Split a SIP message into start line, header block, and body.
///
/// The separator is `\r\n\r\n` per RFC 3261. We tolerate `\n\n` for
/// robustness (matches mdsiprtp3 behavior; real-world stacks vary).
/// Returned slices are views into the input; no allocation.
///
/// `start_line` and `header_block` are returned as `&str` (validated
/// UTF-8). `body` is `&[u8]` — bodies (e.g. SDP) are octets, and a
/// non-UTF-8 body should not fail framing.
pub fn split_message(data: &[u8]) -> Result<(&str, &str, &[u8]), SipError> {
    // Find the header/body separator. Prefer CRLFCRLF; fall back to LFLF.
    let (sep_start, sep_len) = find_separator(data)
        .ok_or_else(|| SipError::Parse("no header/body separator found".to_string()))?;

    let head = &data[..sep_start];
    let body = &data[sep_start + sep_len..];

    let head_str = std::str::from_utf8(head)
        .map_err(|e| SipError::Parse(format!("header section not valid UTF-8: {e}")))?;

    // Split the head into start line + header block on the first
    // line terminator.
    let (start_line, header_block) = split_first_line(head_str);

    if start_line.len() > MAX_START_LINE_LEN {
        return Err(SipError::Parse(format!(
            "start line exceeds {MAX_START_LINE_LEN} bytes",
        )));
    }

    Ok((start_line, header_block, body))
}

/// Locate the header/body separator. Returns `(offset_of_separator,
/// separator_len)` where `separator_len` is 4 for `\r\n\r\n` and 2
/// for `\n\n`. CRLFCRLF takes precedence if both occur.
fn find_separator(data: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = find_subslice(data, b"\r\n\r\n") {
        return Some((pos, 4));
    }
    if let Some(pos) = find_subslice(data, b"\n\n") {
        return Some((pos, 2));
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Split off the first line (terminated by `\r\n` or `\n`) from a
/// header section. Returns `(start_line, rest)`. If no terminator
/// exists, `rest` is empty and the whole input is the start line.
fn split_first_line(head: &str) -> (&str, &str) {
    if let Some(pos) = head.find("\r\n") {
        (&head[..pos], &head[pos + 2..])
    } else if let Some(pos) = head.find('\n') {
        (&head[..pos], &head[pos + 1..])
    } else {
        (head, "")
    }
}

/// Parse a header block (lines after the start line, before the
/// blank line separator) into an ordered [`Headers`] collection.
///
/// Handles RFC 3261 §7.3.1 line folding: a line beginning with SP or
/// HTAB is a continuation of the previous header; whitespace at the
/// fold is collapsed to a single space. Enforces [`MAX_HEADERS`]
/// and [`MAX_HEADER_VALUE_LEN`].
pub fn parse_header_block(block: &str) -> Result<Headers, SipError> {
    let mut headers = Headers::new();
    let mut current: Option<String> = None;
    let mut fold_lines_for_current: usize = 0;

    for raw_line in split_lines(block) {
        // Skip a trailing empty line (the block may end on a newline).
        if raw_line.is_empty() {
            continue;
        }

        // Folded continuation: starts with SP or HTAB.
        let first_byte = raw_line.as_bytes()[0];
        if first_byte == b' ' || first_byte == b'\t' {
            let folded = current.as_mut().ok_or_else(|| {
                SipError::InvalidHeader(format!(
                    "fold continuation with no preceding header line: {raw_line:?}",
                ))
            })?;
            fold_lines_for_current += 1;
            if fold_lines_for_current > MAX_FOLD_LINES_PER_HEADER {
                // Defense-in-depth: a header with thousands of
                // single-byte fold lines accumulates many small
                // allocations even when the post-fold length stays
                // within bounds.
                return Err(SipError::InvalidHeader(format!(
                    "header has more than {MAX_FOLD_LINES_PER_HEADER} fold lines",
                )));
            }
            folded.push(' ');
            folded.push_str(raw_line.trim());
            if folded.len() > MAX_HEADER_VALUE_LEN.saturating_add(MAX_START_LINE_LEN) {
                // Defense-in-depth against folded-overflow attacks.
                return Err(SipError::InvalidHeader(
                    "folded header exceeds size limit".to_string(),
                ));
            }
            continue;
        }

        // Not folded — flush the previous accumulator.
        if let Some(line) = current.take() {
            let header = Header::parse_line(&line)?;
            // MAX_HEADERS is enforced inside Headers::push itself.
            headers.push(header)?;
        }
        current = Some(raw_line.to_string());
        fold_lines_for_current = 0;
    }

    // Flush the last buffered line.
    if let Some(line) = current.take() {
        let header = Header::parse_line(&line)?;
        headers.push(header)?;
    }

    Ok(headers)
}

/// Split on `\r\n` or `\n`, accepting either. Mixed terminators are
/// tolerated. Empty trailing lines are preserved (caller handles
/// them).
fn split_lines(s: &str) -> impl Iterator<Item = &str> {
    // `str::lines` already accepts both; that's what we want.
    s.lines()
}

/// Parse a request line: `METHOD Request-URI SIP-Version`.
///
/// Returns `(method, uri_raw, version)`. The URI is held as a raw
/// `String` for the Tier-1 contract, but is *validated* here by
/// running it through [`SipUri::parse`] and discarding the result.
/// This means any message that survives framing is guaranteed to
/// have a Request-URI that re-parses cleanly downstream — eliminating
/// the attacker-controlled DoS where `SipRequest::uri()` (which calls
/// `SipUri::parse` on the stored string) would panic on a non-SIP
/// URI such as `http://x` that whitespace-only validation would let
/// through.
pub fn parse_request_line(line: &str) -> Result<(Method, String, String), SipError> {
    if line.len() > MAX_START_LINE_LEN {
        return Err(SipError::Parse(format!(
            "request line exceeds {MAX_START_LINE_LEN} bytes",
        )));
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(SipError::Parse(format!(
            "invalid request line (expected 3 whitespace-separated parts): {line:?}",
        )));
    }
    let method = Method::from_str(parts[0])?;
    let uri_str = parts[1];
    let version = parts[2].to_string();
    // RFC 3261 §7.1: version must be exactly "SIP/2.0".
    if version != "SIP/2.0" {
        return Err(SipError::Parse(format!(
            "invalid SIP version in request line: {version}",
        )));
    }
    // Validate the Request-URI shape now so SipRequest::uri() — which
    // re-parses this string via SipUri::parse — cannot be made to
    // panic by a malformed peer. We discard the parsed value: storage
    // remains String per the Tier-1 contract.
    SipUri::parse(uri_str).map_err(|e| SipError::Parse(format!("invalid Request-URI: {e}")))?;
    Ok((method, uri_str.to_string(), version))
}

/// Parse a status line: `SIP-Version Status-Code Reason-Phrase`.
///
/// RFC 3261 §7.2 BNF:
/// `Status-Line = SIP-Version SP Status-Code SP Reason-Phrase CRLF`
/// — *both* SPs are mandatory. The Reason-Phrase itself can be empty
/// (the BNF `Reason-Phrase = *(...)` permits zero-length), but the SP
/// between Status-Code and Reason-Phrase must be present on the wire.
/// Minimum valid status line: `SIP/2.0 200 ` (trailing SP, empty
/// reason). M11 fuzz finding #12 surfaced our previous lenient
/// behavior (silently accepting `SIP/2.0 200`); we now reject to
/// match the BNF strictly.
pub fn parse_status_line(line: &str) -> Result<(String, StatusCode, String), SipError> {
    if line.len() > MAX_START_LINE_LEN {
        return Err(SipError::Parse(format!(
            "status line exceeds {MAX_START_LINE_LEN} bytes",
        )));
    }
    let mut parts = line.splitn(3, ' ');
    let version = parts
        .next()
        .ok_or_else(|| SipError::Parse(format!("empty status line: {line:?}")))?;
    let code_str = parts
        .next()
        .ok_or_else(|| SipError::Parse(format!("status line missing code: {line:?}")))?;
    // Per RFC 3261 §7.2 BNF the SP between Status-Code and
    // Reason-Phrase is mandatory. If `splitn(3, ' ')` yields no third
    // element the input had fewer than 2 SPs — reject. (Empty
    // reason-phrase is fine; a trailing SP after the code produces
    // `Some("")` here.)
    let reason = parts
        .next()
        .ok_or_else(|| SipError::Parse("status line missing SP after status code".to_string()))?;

    // RFC 3261 §7.1: version must be exactly "SIP/2.0".
    if version != "SIP/2.0" {
        return Err(SipError::Parse(format!(
            "invalid SIP version in status line: {version}",
        )));
    }
    let code: u16 = code_str
        .parse()
        .map_err(|_| SipError::Parse(format!("invalid status code: {code_str}")))?;
    // RFC 3261 §7.2: status codes are in [100, 699].
    if !(100..=699).contains(&code) {
        return Err(SipError::Parse(format!("status code out of range: {code}")));
    }
    Ok((
        version.to_string(),
        StatusCode::new(code),
        reason.to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_message_crlf_separator() {
        let msg = b"INVITE sip:bob@x SIP/2.0\r\nVia: x\r\n\r\nBODY";
        let (start, headers, body) = split_message(msg).unwrap();
        assert_eq!(start, "INVITE sip:bob@x SIP/2.0");
        // The final CRLF before the separator is consumed as part of
        // the separator itself; the header block contains just the
        // header lines.
        assert_eq!(headers, "Via: x");
        assert_eq!(body, b"BODY");
    }

    #[test]
    fn test_split_message_lf_only_fallback() {
        let msg = b"INVITE sip:bob@x SIP/2.0\nVia: x\n\nBODY";
        let (start, headers, body) = split_message(msg).unwrap();
        assert_eq!(start, "INVITE sip:bob@x SIP/2.0");
        assert_eq!(headers, "Via: x");
        assert_eq!(body, b"BODY");
    }

    #[test]
    fn test_split_message_no_separator_rejects() {
        let msg = b"INVITE sip:bob@x SIP/2.0\r\nVia: x\r\n";
        let err = split_message(msg).unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    #[test]
    fn test_split_message_empty_body() {
        let msg = b"INVITE sip:bob@x SIP/2.0\r\nVia: x\r\n\r\n";
        let (_, _, body) = split_message(msg).unwrap();
        assert_eq!(body, b"");
    }

    #[test]
    fn test_split_message_oversized_start_line() {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"INVITE ");
        msg.extend(std::iter::repeat_n(b'x', MAX_START_LINE_LEN));
        msg.extend_from_slice(b" SIP/2.0\r\n\r\n");
        let err = split_message(&msg).unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    #[test]
    fn test_split_message_non_utf8_header_rejects() {
        let mut msg = Vec::from(&b"INVITE sip:bob@x SIP/2.0\r\nX-Bad: "[..]);
        msg.push(0xFF);
        msg.extend_from_slice(b"\r\n\r\n");
        let err = split_message(&msg).unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    #[test]
    fn test_split_message_non_utf8_body_ok() {
        let mut msg = Vec::from(&b"INVITE sip:bob@x SIP/2.0\r\n\r\n"[..]);
        msg.push(0xFF);
        msg.push(0xFE);
        let (_, _, body) = split_message(&msg).unwrap();
        assert_eq!(body, &[0xFF, 0xFE]);
    }

    #[test]
    fn test_parse_header_block_simple() {
        let block = "Via: SIP/2.0/UDP h\r\nFrom: <sip:a@b>\r\n";
        let hs = parse_header_block(block).unwrap();
        assert_eq!(hs.len(), 2);
        assert_eq!(hs.get_first_value("Via"), Some("SIP/2.0/UDP h"));
        assert_eq!(hs.get_first_value("From"), Some("<sip:a@b>"));
    }

    #[test]
    fn test_parse_header_block_folding() {
        let block = "Foo: a\r\n bar\r\n";
        let hs = parse_header_block(block).unwrap();
        assert_eq!(hs.len(), 1);
        assert_eq!(hs.get_first_value("Foo"), Some("a bar"));
    }

    #[test]
    fn test_parse_header_block_folding_tab() {
        let block = "Foo: a\r\n\tbar\r\n";
        let hs = parse_header_block(block).unwrap();
        assert_eq!(hs.get_first_value("Foo"), Some("a bar"));
    }

    #[test]
    fn test_parse_header_block_folding_multi_line() {
        let block = "Subject: line1\r\n line2\r\n line3\r\n";
        let hs = parse_header_block(block).unwrap();
        assert_eq!(hs.len(), 1);
        assert_eq!(hs.get_first_value("Subject"), Some("line1 line2 line3"));
    }

    #[test]
    fn test_parse_header_block_fold_without_preceding_rejects() {
        let block = " orphan\r\nFrom: <sip:a@b>\r\n";
        let err = parse_header_block(block).unwrap_err();
        assert!(matches!(err, SipError::InvalidHeader(_)));
    }

    #[test]
    fn test_parse_header_block_max_headers_enforced() {
        let mut block = String::new();
        for _ in 0..(MAX_HEADERS + 1) {
            block.push_str("Via: x\r\n");
        }
        let err = parse_header_block(&block).unwrap_err();
        assert!(matches!(err, SipError::InvalidHeader(_)));
    }

    #[test]
    fn test_parse_header_block_lf_only() {
        let block = "Via: SIP/2.0/UDP h\nFrom: <sip:a@b>\n";
        let hs = parse_header_block(block).unwrap();
        assert_eq!(hs.len(), 2);
    }

    #[test]
    fn test_parse_request_line_invite() {
        let (m, uri, ver) = parse_request_line("INVITE sip:bob@example.com SIP/2.0").unwrap();
        assert_eq!(m, Method::Invite);
        assert_eq!(uri, "sip:bob@example.com");
        assert_eq!(ver, "SIP/2.0");
    }

    #[test]
    fn test_parse_request_line_two_parts_rejects() {
        let err = parse_request_line("INVITE sip:bob@example.com").unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    #[test]
    fn test_parse_request_line_unknown_method_rejects() {
        let err = parse_request_line("BOGUS sip:bob@example.com SIP/2.0").unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    #[test]
    fn test_parse_request_line_bad_version_rejects() {
        let err = parse_request_line("INVITE sip:bob@example.com HTTP/1.1").unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    #[test]
    fn test_parse_request_line_oversized_rejects() {
        let line = "INVITE ".to_string() + &"x".repeat(MAX_START_LINE_LEN) + " SIP/2.0";
        let err = parse_request_line(&line).unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    #[test]
    fn test_request_line_rejects_non_sip_uri() {
        // Per M8 reviewer: INVITE with http:// URI must reject at framing time
        // so SipRequest::uri() never panics.
        let line = "INVITE http://example.com SIP/2.0";
        let result = parse_request_line(line);
        assert!(result.is_err(), "non-sip URI should be rejected");
    }

    #[test]
    fn test_request_line_accepts_tel_uri() {
        let line = "INVITE tel:+12025551234 SIP/2.0";
        let result = parse_request_line(line);
        assert!(result.is_ok(), "tel: URI should be accepted");
    }

    #[test]
    fn test_request_line_accepts_sips_uri() {
        let line = "INVITE sips:bob@example.com SIP/2.0";
        let result = parse_request_line(line);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_status_line_simple() {
        let (ver, code, reason) = parse_status_line("SIP/2.0 200 OK").unwrap();
        assert_eq!(ver, "SIP/2.0");
        assert_eq!(code, StatusCode::OK);
        assert_eq!(reason, "OK");
    }

    #[test]
    fn test_parse_status_line_multi_word_reason() {
        let (ver, code, reason) = parse_status_line("SIP/2.0 486 Busy Here").unwrap();
        assert_eq!(ver, "SIP/2.0");
        assert_eq!(code, StatusCode::BUSY_HERE);
        assert_eq!(reason, "Busy Here");
    }

    #[test]
    fn test_status_line_missing_sp_after_code_rejects() {
        // RFC 3261 §7.2: SP between Status-Code and Reason-Phrase is
        // mandatory. M11 fuzz finding #12 — closed at the framing
        // layer.
        let line = "SIP/2.0 200"; // no second SP, no reason phrase
        assert!(parse_status_line(line).is_err());
    }

    #[test]
    fn test_status_line_empty_reason_phrase_accepts() {
        // RFC 3261 §7.2: `Reason-Phrase = *(...)` — empty is permitted.
        // The SP between Status-Code and Reason-Phrase must still be
        // on the wire. Replaces the old `test_parse_status_line_no_reason`
        // pin which asserted lenient acceptance of the missing-SP form.
        let line = "SIP/2.0 200 "; // trailing SP, empty reason
        let result = parse_status_line(line);
        assert!(result.is_ok(), "empty reason phrase is RFC-legal");
        let (_, code, reason) = result.unwrap();
        assert_eq!(code, StatusCode::OK);
        assert_eq!(reason, "");
    }

    #[test]
    fn test_parse_status_line_bad_version_rejects() {
        let err = parse_status_line("HTTP/1.1 200 OK").unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    #[test]
    fn test_parse_status_line_bad_code_rejects() {
        let err = parse_status_line("SIP/2.0 NOTNUM OK").unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    #[test]
    fn test_parse_status_line_oversized_rejects() {
        let line = "SIP/2.0 200 ".to_string() + &"x".repeat(MAX_START_LINE_LEN);
        let err = parse_status_line(&line).unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    #[test]
    fn test_status_code_zero_rejected() {
        // RFC 3261 §7.2: status codes are 100-699. Per M11 fuzz finding.
        let line = "SIP/2.0 0 OK";
        assert!(parse_status_line(line).is_err());
    }

    #[test]
    fn test_status_code_too_high_rejected() {
        let line = "SIP/2.0 700 ?";
        assert!(parse_status_line(line).is_err());
    }

    #[test]
    fn test_status_code_max_rejected() {
        let line = "SIP/2.0 65535 ?";
        assert!(parse_status_line(line).is_err());
    }

    #[test]
    fn test_status_code_99_rejected() {
        let line = "SIP/2.0 99 ?";
        assert!(parse_status_line(line).is_err());
    }

    #[test]
    fn test_version_sip0_rejected() {
        // RFC 3261 §7.1: version must be exactly SIP/2.0. Per M11 fuzz finding.
        let line = "SIP/0 200 OK";
        assert!(parse_status_line(line).is_err());
    }

    #[test]
    fn test_version_sip3_rejected() {
        let line = "SIP/3.0 200 OK";
        assert!(parse_status_line(line).is_err());
    }

    #[test]
    fn test_request_version_sip0_rejected() {
        let line = "INVITE sip:bob@x SIP/0";
        assert!(parse_request_line(line).is_err());
    }

    #[test]
    fn test_request_version_garbage_rejected() {
        let line = "INVITE sip:bob@x SIP/garbage";
        assert!(parse_request_line(line).is_err());
    }

    /// Per-header fold-count cap (RFC 3261 §7.3.1) — 33 fold
    /// continuation lines is one over the limit and must be
    /// rejected. Pre-M11 fuzz-prep DoS hardening.
    #[test]
    fn test_fold_count_cap_rejects() {
        let mut block = String::from("Subject: x");
        for _ in 0..(MAX_FOLD_LINES_PER_HEADER + 1) {
            block.push_str("\r\n y");
        }
        block.push_str("\r\n");
        let err = parse_header_block(&block).unwrap_err();
        match err {
            SipError::InvalidHeader(msg) => {
                assert!(msg.contains("fold lines"), "got: {msg}");
            }
            other => panic!("expected InvalidHeader, got {other:?}"),
        }
    }

    /// Exactly `MAX_FOLD_LINES_PER_HEADER` fold lines is at the
    /// boundary and must be accepted (cap is "more than").
    #[test]
    fn test_fold_count_at_limit_accepts() {
        let mut block = String::from("Subject: x");
        for _ in 0..MAX_FOLD_LINES_PER_HEADER {
            block.push_str("\r\n y");
        }
        block.push_str("\r\n");
        let hs = parse_header_block(&block).unwrap();
        assert_eq!(hs.len(), 1);
        let v = hs.get_first_value("Subject").unwrap();
        // Each fold appends " y", so the value is "x" + " y" * 32.
        let expected = "x".to_string() + &" y".repeat(MAX_FOLD_LINES_PER_HEADER);
        assert_eq!(v, expected);
    }

    /// Adversarial micro-test: empty input. Must be rejected (no
    /// header/body separator). Pre-M11 fuzz-prep behavior pin.
    #[test]
    fn test_empty_input_rejects() {
        let err = split_message(b"").unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    /// Adversarial micro-test: single byte. Must be rejected (no
    /// separator, certainly no valid start line). Pre-M11 fuzz-prep
    /// behavior pin.
    #[test]
    fn test_single_byte_input_rejects() {
        let err = split_message(b"X").unwrap_err();
        assert!(matches!(err, SipError::Parse(_)));
    }

    /// Adversarial micro-test: only the CRLFCRLF separator.
    /// `split_message` finds the separator at offset 0 — start
    /// line is empty, header block is empty, body is empty. Then
    /// downstream `parse_request_line` / `parse_status_line`
    /// reject the empty start line. Pre-M11 fuzz-prep behavior
    /// pin: confirm the layered rejection is in place.
    #[test]
    fn test_only_crlf_rejects() {
        let res = split_message(b"\r\n\r\n");
        // split_message itself accepts (separator at offset 0).
        assert!(res.is_ok(), "split_message accepts \\r\\n\\r\\n");
        let (start, _hdr, _body) = res.unwrap();
        assert!(start.is_empty(), "start line is empty");
        // Both downstream start-line parsers reject empty input.
        assert!(parse_request_line(start).is_err());
        assert!(parse_status_line(start).is_err());
    }

    /// Adversarial micro-test: header value with embedded NUL
    /// byte. The framer treats the header section as UTF-8; NUL
    /// (0x00) IS valid UTF-8 (a one-byte code point) and IS
    /// preserved by `str::lines()`. Documented behavior: accepted
    /// at framing, value carries the NUL through to typed
    /// parsers. Pre-M11 fuzz-prep behavior pin so a future
    /// stricter rejection is a deliberate change. Defense in depth
    /// (e.g. rejection of non-printable bytes) belongs in a
    /// future hardening pass with an explicit RFC 3261 §25.1
    /// `LWS / TEXT-UTF8 / token` allowlist.
    #[test]
    fn test_header_with_embedded_nul_pinned_accepted() {
        let msg = b"INVITE sip:a@b SIP/2.0\r\nFoo: ba\0r\r\n\r\n";
        let (start, hdr_block, body) = split_message(msg).unwrap();
        assert_eq!(start, "INVITE sip:a@b SIP/2.0");
        assert_eq!(body, b"");
        // The header block contains the literal NUL byte. Header
        // parsing also accepts it today.
        let hs = parse_header_block(hdr_block).unwrap();
        let v = hs.get_first_value("Foo").unwrap();
        assert_eq!(v.as_bytes(), b"ba\0r");
    }
}
