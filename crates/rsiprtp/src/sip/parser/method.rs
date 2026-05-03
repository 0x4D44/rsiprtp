//! SIP request method.
//!
//! Seeded from `mdsiprtp3/src/sip/method.rs` with two deliberate changes:
//!
//! - Adds `Publish` (RFC 3903). mdsiprtp3 omits it; rsip supports it.
//! - `FromStr` is case-insensitive. mdsiprtp3's is case-sensitive. RFC 3261
//!   §7.1 declares method names case-sensitive on the wire, but liberal
//!   acceptance on parse is the correct robustness stance and matches
//!   rsip's behavior. Display still emits the canonical uppercase form.
//!
//! Variant naming: `Prack` (lowercase second char) NOT `PRack` — matches
//! rsiprtp's existing public API.

use crate::core::SipError;
use std::fmt;
use std::str::FromStr;

/// SIP request method (RFC 3261 §7.1, plus extensions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// INVITE — initiate a session (RFC 3261).
    Invite,
    /// ACK — acknowledge a final response to INVITE (RFC 3261).
    Ack,
    /// BYE — terminate a session (RFC 3261).
    Bye,
    /// CANCEL — cancel a pending request (RFC 3261).
    Cancel,
    /// REGISTER — register contact information (RFC 3261).
    Register,
    /// OPTIONS — query capabilities (RFC 3261).
    Options,
    /// INFO — mid-session information (RFC 6086).
    Info,
    /// UPDATE — modify session state before a final response (RFC 3311).
    Update,
    /// REFER — call transfer (RFC 3515).
    Refer,
    /// NOTIFY — notify of events (RFC 6665).
    Notify,
    /// SUBSCRIBE — subscribe to events (RFC 6665).
    Subscribe,
    /// PRACK — provisional acknowledgment (RFC 3262).
    Prack,
    /// MESSAGE — instant message (RFC 3428).
    Message,
    /// PUBLISH — event state publication (RFC 3903).
    Publish,
}

impl Method {
    /// Returns the canonical uppercase method token.
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Invite => "INVITE",
            Method::Ack => "ACK",
            Method::Bye => "BYE",
            Method::Cancel => "CANCEL",
            Method::Register => "REGISTER",
            Method::Options => "OPTIONS",
            Method::Info => "INFO",
            Method::Update => "UPDATE",
            Method::Refer => "REFER",
            Method::Notify => "NOTIFY",
            Method::Subscribe => "SUBSCRIBE",
            Method::Prack => "PRACK",
            Method::Message => "MESSAGE",
            Method::Publish => "PUBLISH",
        }
    }

    /// Returns true for methods that establish a dialog.
    ///
    /// RFC 3261 §12: INVITE creates a dialog. RFC 6665 §4.5.1: SUBSCRIBE
    /// creates a subscription dialog. No other method does.
    pub fn creates_dialog(&self) -> bool {
        matches!(self, Method::Invite | Method::Subscribe)
    }

    /// Returns true if this method requires an ACK to complete the
    /// transaction. Only INVITE per RFC 3261 §17.1.1.3.
    pub fn requires_ack(&self) -> bool {
        matches!(self, Method::Invite)
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Method {
    type Err = SipError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Case-insensitive parse — RFC 3261 §7.1 declares method names
        // case-sensitive on the wire, but liberal acceptance on parse is
        // the correct robustness stance and matches rsip's behavior.
        const ALL: &[Method] = &[
            Method::Invite,
            Method::Ack,
            Method::Bye,
            Method::Cancel,
            Method::Register,
            Method::Options,
            Method::Info,
            Method::Update,
            Method::Refer,
            Method::Notify,
            Method::Subscribe,
            Method::Prack,
            Method::Message,
            Method::Publish,
        ];
        for m in ALL {
            if s.eq_ignore_ascii_case(m.as_str()) {
                return Ok(*m);
            }
        }
        Err(SipError::Parse(format!("unknown method: {s}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_from_str_canonical() {
        assert_eq!("INVITE".parse::<Method>().unwrap(), Method::Invite);
        assert_eq!("ACK".parse::<Method>().unwrap(), Method::Ack);
        assert_eq!("BYE".parse::<Method>().unwrap(), Method::Bye);
        assert_eq!("CANCEL".parse::<Method>().unwrap(), Method::Cancel);
        assert_eq!("REGISTER".parse::<Method>().unwrap(), Method::Register);
        assert_eq!("OPTIONS".parse::<Method>().unwrap(), Method::Options);
        assert_eq!("INFO".parse::<Method>().unwrap(), Method::Info);
        assert_eq!("UPDATE".parse::<Method>().unwrap(), Method::Update);
        assert_eq!("REFER".parse::<Method>().unwrap(), Method::Refer);
        assert_eq!("NOTIFY".parse::<Method>().unwrap(), Method::Notify);
        assert_eq!("SUBSCRIBE".parse::<Method>().unwrap(), Method::Subscribe);
        assert_eq!("PRACK".parse::<Method>().unwrap(), Method::Prack);
        assert_eq!("MESSAGE".parse::<Method>().unwrap(), Method::Message);
        assert_eq!("PUBLISH".parse::<Method>().unwrap(), Method::Publish);
    }

    #[test]
    fn test_method_from_str_case_insensitive() {
        assert_eq!("invite".parse::<Method>().unwrap(), Method::Invite);
        assert_eq!("Invite".parse::<Method>().unwrap(), Method::Invite);
        assert_eq!("iNvItE".parse::<Method>().unwrap(), Method::Invite);
        // Spot-check a couple of other variants for case-insensitivity too.
        assert_eq!("bye".parse::<Method>().unwrap(), Method::Bye);
        assert_eq!("Publish".parse::<Method>().unwrap(), Method::Publish);
    }

    #[test]
    fn test_method_from_str_unknown_rejects() {
        assert!("BOGUS".parse::<Method>().is_err());
        assert!("".parse::<Method>().is_err());
        assert!("INVIT".parse::<Method>().is_err());
        assert!("INVITES".parse::<Method>().is_err());
    }

    #[test]
    fn test_method_publish_variant() {
        assert_eq!("PUBLISH".parse::<Method>().unwrap(), Method::Publish);
        assert_eq!(Method::Publish.to_string(), "PUBLISH");
        assert_eq!(Method::Publish.as_str(), "PUBLISH");
    }

    #[test]
    fn test_method_display_uppercase() {
        assert_eq!(Method::Invite.to_string(), "INVITE");
        assert_eq!(Method::Ack.to_string(), "ACK");
        assert_eq!(Method::Subscribe.to_string(), "SUBSCRIBE");
    }

    #[test]
    fn test_method_creates_dialog() {
        assert!(Method::Invite.creates_dialog());
        assert!(Method::Subscribe.creates_dialog());
        assert!(!Method::Ack.creates_dialog());
        assert!(!Method::Bye.creates_dialog());
        assert!(!Method::Cancel.creates_dialog());
        assert!(!Method::Register.creates_dialog());
        assert!(!Method::Options.creates_dialog());
        assert!(!Method::Info.creates_dialog());
        assert!(!Method::Update.creates_dialog());
        assert!(!Method::Refer.creates_dialog());
        assert!(!Method::Notify.creates_dialog());
        assert!(!Method::Prack.creates_dialog());
        assert!(!Method::Message.creates_dialog());
        assert!(!Method::Publish.creates_dialog());
    }

    #[test]
    fn test_method_requires_ack() {
        assert!(Method::Invite.requires_ack());
        assert!(!Method::Ack.requires_ack());
        assert!(!Method::Bye.requires_ack());
        assert!(!Method::Cancel.requires_ack());
        assert!(!Method::Register.requires_ack());
        assert!(!Method::Options.requires_ack());
        assert!(!Method::Info.requires_ack());
        assert!(!Method::Update.requires_ack());
        assert!(!Method::Refer.requires_ack());
        assert!(!Method::Notify.requires_ack());
        assert!(!Method::Subscribe.requires_ack());
        assert!(!Method::Prack.requires_ack());
        assert!(!Method::Message.requires_ack());
        assert!(!Method::Publish.requires_ack());
    }
}
