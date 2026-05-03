//! SIP response status code (RFC 3261 §7.2).
//!
//! Ported as-is from `mdsiprtp3/src/sip/status.rs`. The list of associated
//! constants and `reason_phrase()` mapping is already complete.

use std::fmt;

/// SIP response status code per RFC 3261 §7.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusCode(u16);

impl StatusCode {
    // 1xx — Provisional
    pub const TRYING: StatusCode = StatusCode(100);
    pub const RINGING: StatusCode = StatusCode(180);
    pub const CALL_IS_BEING_FORWARDED: StatusCode = StatusCode(181);
    pub const QUEUED: StatusCode = StatusCode(182);
    pub const SESSION_PROGRESS: StatusCode = StatusCode(183);

    // 2xx — Success
    pub const OK: StatusCode = StatusCode(200);
    pub const ACCEPTED: StatusCode = StatusCode(202);

    // 3xx — Redirection
    pub const MULTIPLE_CHOICES: StatusCode = StatusCode(300);
    pub const MOVED_PERMANENTLY: StatusCode = StatusCode(301);
    pub const MOVED_TEMPORARILY: StatusCode = StatusCode(302);
    pub const USE_PROXY: StatusCode = StatusCode(305);
    pub const ALTERNATIVE_SERVICE: StatusCode = StatusCode(380);

    // 4xx — Client Error
    pub const BAD_REQUEST: StatusCode = StatusCode(400);
    pub const UNAUTHORIZED: StatusCode = StatusCode(401);
    pub const PAYMENT_REQUIRED: StatusCode = StatusCode(402);
    pub const FORBIDDEN: StatusCode = StatusCode(403);
    pub const NOT_FOUND: StatusCode = StatusCode(404);
    pub const METHOD_NOT_ALLOWED: StatusCode = StatusCode(405);
    pub const NOT_ACCEPTABLE: StatusCode = StatusCode(406);
    pub const PROXY_AUTHENTICATION_REQUIRED: StatusCode = StatusCode(407);
    pub const REQUEST_TIMEOUT: StatusCode = StatusCode(408);
    pub const GONE: StatusCode = StatusCode(410);
    pub const REQUEST_ENTITY_TOO_LARGE: StatusCode = StatusCode(413);
    pub const REQUEST_URI_TOO_LONG: StatusCode = StatusCode(414);
    pub const UNSUPPORTED_MEDIA_TYPE: StatusCode = StatusCode(415);
    pub const UNSUPPORTED_URI_SCHEME: StatusCode = StatusCode(416);
    pub const BAD_EXTENSION: StatusCode = StatusCode(420);
    pub const EXTENSION_REQUIRED: StatusCode = StatusCode(421);
    pub const INTERVAL_TOO_BRIEF: StatusCode = StatusCode(423);
    pub const TEMPORARILY_UNAVAILABLE: StatusCode = StatusCode(480);
    pub const CALL_DOES_NOT_EXIST: StatusCode = StatusCode(481);
    pub const LOOP_DETECTED: StatusCode = StatusCode(482);
    pub const TOO_MANY_HOPS: StatusCode = StatusCode(483);
    pub const ADDRESS_INCOMPLETE: StatusCode = StatusCode(484);
    pub const AMBIGUOUS: StatusCode = StatusCode(485);
    pub const BUSY_HERE: StatusCode = StatusCode(486);
    pub const REQUEST_TERMINATED: StatusCode = StatusCode(487);
    pub const NOT_ACCEPTABLE_HERE: StatusCode = StatusCode(488);
    pub const REQUEST_PENDING: StatusCode = StatusCode(491);
    pub const UNDECIPHERABLE: StatusCode = StatusCode(493);

    // 5xx — Server Error
    pub const SERVER_INTERNAL_ERROR: StatusCode = StatusCode(500);
    pub const NOT_IMPLEMENTED: StatusCode = StatusCode(501);
    pub const BAD_GATEWAY: StatusCode = StatusCode(502);
    pub const SERVICE_UNAVAILABLE: StatusCode = StatusCode(503);
    pub const SERVER_TIMEOUT: StatusCode = StatusCode(504);
    pub const VERSION_NOT_SUPPORTED: StatusCode = StatusCode(505);
    pub const MESSAGE_TOO_LARGE: StatusCode = StatusCode(513);

    // 6xx — Global Failure
    pub const BUSY_EVERYWHERE: StatusCode = StatusCode(600);
    pub const DECLINE: StatusCode = StatusCode(603);
    pub const DOES_NOT_EXIST_ANYWHERE: StatusCode = StatusCode(604);
    pub const NOT_ACCEPTABLE_GLOBAL: StatusCode = StatusCode(606);

    /// Construct a status code from an arbitrary u16. No validation —
    /// values outside 100–699 are accepted but won't match any class
    /// predicate.
    pub fn new(code: u16) -> Self {
        StatusCode(code)
    }

    /// Numeric status code.
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    /// 1xx — provisional response.
    pub fn is_provisional(&self) -> bool {
        (100..200).contains(&self.0)
    }

    /// 2xx — success.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.0)
    }

    /// 3xx — redirection.
    pub fn is_redirection(&self) -> bool {
        (300..400).contains(&self.0)
    }

    /// 4xx — client error.
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.0)
    }

    /// 5xx — server error.
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.0)
    }

    /// 6xx — global failure.
    pub fn is_global_failure(&self) -> bool {
        (600..700).contains(&self.0)
    }

    /// True for any final response (≥200). False for 1xx provisional.
    pub fn is_final(&self) -> bool {
        self.0 >= 200
    }

    /// Canonical reason phrase for known codes; "Unknown" otherwise.
    pub fn reason_phrase(&self) -> &'static str {
        match self.0 {
            100 => "Trying",
            180 => "Ringing",
            181 => "Call Is Being Forwarded",
            182 => "Queued",
            183 => "Session Progress",
            200 => "OK",
            202 => "Accepted",
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Moved Temporarily",
            305 => "Use Proxy",
            380 => "Alternative Service",
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            410 => "Gone",
            413 => "Request Entity Too Large",
            414 => "Request-URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Unsupported URI Scheme",
            420 => "Bad Extension",
            421 => "Extension Required",
            423 => "Interval Too Brief",
            480 => "Temporarily Unavailable",
            481 => "Call/Transaction Does Not Exist",
            482 => "Loop Detected",
            483 => "Too Many Hops",
            484 => "Address Incomplete",
            485 => "Ambiguous",
            486 => "Busy Here",
            487 => "Request Terminated",
            488 => "Not Acceptable Here",
            491 => "Request Pending",
            493 => "Undecipherable",
            500 => "Server Internal Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Server Time-out",
            505 => "Version Not Supported",
            513 => "Message Too Large",
            600 => "Busy Everywhere",
            603 => "Decline",
            604 => "Does Not Exist Anywhere",
            606 => "Not Acceptable",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.reason_phrase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_categories() {
        assert!(StatusCode::TRYING.is_provisional());
        assert!(StatusCode::OK.is_success());
        assert!(StatusCode::MOVED_PERMANENTLY.is_redirection());
        assert!(StatusCode::NOT_FOUND.is_client_error());
        assert!(StatusCode::SERVER_INTERNAL_ERROR.is_server_error());
        assert!(StatusCode::BUSY_EVERYWHERE.is_global_failure());
    }

    #[test]
    fn test_is_final() {
        assert!(!StatusCode::TRYING.is_final());
        assert!(StatusCode::OK.is_final());
        assert!(StatusCode::NOT_FOUND.is_final());
    }

    #[test]
    fn test_status_code_provisional_vs_final() {
        // Edge case at the 200 boundary. 199 is the last provisional code,
        // 200 is the first final response.
        let one_ninety_nine = StatusCode::new(199);
        assert!(one_ninety_nine.is_provisional());
        assert!(!one_ninety_nine.is_final());

        let two_hundred = StatusCode::new(200);
        assert!(!two_hundred.is_provisional());
        assert!(two_hundred.is_final());
        assert!(two_hundred.is_success());

        // 100 is the lower bound of provisional.
        assert!(StatusCode::new(100).is_provisional());
        // 99 is below the SIP range — neither provisional nor final.
        assert!(!StatusCode::new(99).is_provisional());
        assert!(!StatusCode::new(99).is_final());
    }
}
