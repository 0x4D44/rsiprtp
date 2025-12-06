//! SIP Digest Authentication per RFC 2617 and RFC 3261.
//!
//! Provides parsing of WWW-Authenticate/Proxy-Authenticate headers
//! and generation of Authorization/Proxy-Authorization headers.

use rand::Rng;
use std::fmt;
use thiserror::Error;

/// Digest authentication errors.
#[derive(Debug, Error)]
pub enum DigestAuthError {
    /// Missing required field in challenge.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Unsupported algorithm.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Unsupported qop value.
    #[error("unsupported qop: {0}")]
    UnsupportedQop(String),

    /// Parse error.
    #[error("parse error: {0}")]
    ParseError(String),
}

/// Quality of protection options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Qop {
    /// No quality of protection.
    #[default]
    None,
    /// Authentication only.
    Auth,
    /// Authentication with integrity protection.
    AuthInt,
}

impl fmt::Display for Qop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Qop::None => Ok(()),
            Qop::Auth => write!(f, "auth"),
            Qop::AuthInt => write!(f, "auth-int"),
        }
    }
}

/// Digest authentication algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// MD5 algorithm (default for SIP).
    #[default]
    Md5,
    /// MD5-sess algorithm.
    Md5Sess,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::Md5 => write!(f, "MD5"),
            Algorithm::Md5Sess => write!(f, "MD5-sess"),
        }
    }
}

/// Parsed WWW-Authenticate or Proxy-Authenticate challenge.
#[derive(Debug, Clone)]
pub struct DigestChallenge {
    /// Authentication realm.
    pub realm: String,
    /// Server nonce.
    pub nonce: String,
    /// Opaque value (optional, must be returned if present).
    pub opaque: Option<String>,
    /// Stale flag (if true, re-authenticate with new nonce).
    pub stale: bool,
    /// Algorithm to use.
    pub algorithm: Algorithm,
    /// Quality of protection options offered.
    pub qop: Option<Qop>,
    /// Domain of protection (optional).
    pub domain: Option<String>,
}

impl DigestChallenge {
    /// Parse a WWW-Authenticate or Proxy-Authenticate header value.
    ///
    /// Expected format: `Digest realm="...", nonce="...", ...`
    pub fn parse(header_value: &str) -> Result<Self, DigestAuthError> {
        let header_value = header_value.trim();

        // Check for "Digest" scheme
        if !header_value.to_lowercase().starts_with("digest ") {
            return Err(DigestAuthError::ParseError(
                "expected Digest authentication scheme".to_string(),
            ));
        }

        let params_str = &header_value[7..]; // Skip "Digest "
        let params = parse_auth_params(params_str)?;

        let realm = params
            .get("realm")
            .ok_or(DigestAuthError::MissingField("realm"))?
            .clone();

        let nonce = params
            .get("nonce")
            .ok_or(DigestAuthError::MissingField("nonce"))?
            .clone();

        let opaque = params.get("opaque").cloned();
        let domain = params.get("domain").cloned();

        let stale = params
            .get("stale")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));

        let algorithm = match params.get("algorithm").map(|s| s.as_str()) {
            None | Some("MD5") => Algorithm::Md5,
            Some("MD5-sess") => Algorithm::Md5Sess,
            Some(other) => return Err(DigestAuthError::UnsupportedAlgorithm(other.to_string())),
        };

        let qop = params.get("qop").map(|qop_str| {
            // Server may offer multiple qop options, we prefer auth
            if qop_str.contains("auth-int") && !qop_str.contains("auth,") {
                Qop::AuthInt
            } else if qop_str.contains("auth") {
                Qop::Auth
            } else {
                Qop::None
            }
        });

        Ok(DigestChallenge {
            realm,
            nonce,
            opaque,
            stale,
            algorithm,
            qop,
            domain,
        })
    }
}

/// Credentials for digest authentication.
#[derive(Debug, Clone)]
pub struct DigestCredentials {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
}

impl DigestCredentials {
    /// Create new credentials.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

/// Generated Authorization or Proxy-Authorization header.
#[derive(Debug, Clone)]
pub struct DigestResponse {
    /// Username.
    pub username: String,
    /// Realm.
    pub realm: String,
    /// Nonce.
    pub nonce: String,
    /// Request URI.
    pub uri: String,
    /// Response hash.
    pub response: String,
    /// Algorithm used.
    pub algorithm: Algorithm,
    /// Opaque value (if provided in challenge).
    pub opaque: Option<String>,
    /// Quality of protection used.
    pub qop: Option<Qop>,
    /// Client nonce (required if qop is used).
    pub cnonce: Option<String>,
    /// Nonce count (required if qop is used).
    pub nc: Option<u32>,
}

impl DigestResponse {
    /// Create a digest response from a challenge.
    pub fn from_challenge(
        challenge: &DigestChallenge,
        credentials: &DigestCredentials,
        method: &str,
        uri: &str,
        body: Option<&[u8]>,
    ) -> Result<Self, DigestAuthError> {
        let qop = challenge.qop;
        let (cnonce, nc) = if qop.is_some() {
            (Some(generate_cnonce()), Some(1u32))
        } else {
            (None, None)
        };

        let response = compute_digest(
            &credentials.username,
            &credentials.password,
            &challenge.realm,
            method,
            uri,
            &challenge.nonce,
            challenge.algorithm,
            qop,
            cnonce.as_deref(),
            nc,
            body,
        );

        Ok(DigestResponse {
            username: credentials.username.clone(),
            realm: challenge.realm.clone(),
            nonce: challenge.nonce.clone(),
            uri: uri.to_string(),
            response,
            algorithm: challenge.algorithm,
            opaque: challenge.opaque.clone(),
            qop,
            cnonce,
            nc,
        })
    }

    /// Build the Authorization header value.
    pub fn to_header_value(&self) -> String {
        let mut parts = vec![
            format!("Digest username=\"{}\"", self.username),
            format!("realm=\"{}\"", self.realm),
            format!("nonce=\"{}\"", self.nonce),
            format!("uri=\"{}\"", self.uri),
            format!("response=\"{}\"", self.response),
            format!("algorithm={}", self.algorithm),
        ];

        if let Some(ref opaque) = self.opaque {
            parts.push(format!("opaque=\"{}\"", opaque));
        }

        if let Some(qop) = self.qop {
            if qop != Qop::None {
                parts.push(format!("qop={}", qop));
                if let Some(ref cnonce) = self.cnonce {
                    parts.push(format!("cnonce=\"{}\"", cnonce));
                }
                if let Some(nc) = self.nc {
                    parts.push(format!("nc={:08x}", nc));
                }
            }
        }

        parts.join(", ")
    }
}

/// Compute the digest response hash.
#[allow(clippy::too_many_arguments)]
fn compute_digest(
    username: &str,
    password: &str,
    realm: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    algorithm: Algorithm,
    qop: Option<Qop>,
    cnonce: Option<&str>,
    nc: Option<u32>,
    body: Option<&[u8]>,
) -> String {
    // HA1 = MD5(username:realm:password)
    let ha1 = {
        let digest = md5::compute(format!("{}:{}:{}", username, realm, password));
        let ha1_base = hex::encode(digest.0);

        match algorithm {
            Algorithm::Md5 => ha1_base,
            Algorithm::Md5Sess => {
                // HA1 = MD5(MD5(username:realm:password):nonce:cnonce)
                let cnonce = cnonce.unwrap_or("");
                let digest = md5::compute(format!("{}:{}:{}", ha1_base, nonce, cnonce));
                hex::encode(digest.0)
            }
        }
    };

    // HA2 = MD5(method:uri) or MD5(method:uri:MD5(body)) for auth-int
    let ha2 = match qop {
        Some(Qop::AuthInt) => {
            let body_hash = if let Some(body) = body {
                hex::encode(md5::compute(body).0)
            } else {
                hex::encode(md5::compute(b"").0)
            };
            let digest = md5::compute(format!("{}:{}:{}", method, uri, body_hash));
            hex::encode(digest.0)
        }
        _ => {
            let digest = md5::compute(format!("{}:{}", method, uri));
            hex::encode(digest.0)
        }
    };

    // Response = MD5(HA1:nonce:HA2) or MD5(HA1:nonce:nc:cnonce:qop:HA2)
    match qop {
        Some(qop) if qop != Qop::None => {
            let cnonce = cnonce.unwrap_or("");
            let nc = nc.unwrap_or(1);
            let digest = md5::compute(format!(
                "{}:{}:{:08x}:{}:{}:{}",
                ha1, nonce, nc, cnonce, qop, ha2
            ));
            hex::encode(digest.0)
        }
        _ => {
            let digest = md5::compute(format!("{}:{}:{}", ha1, nonce, ha2));
            hex::encode(digest.0)
        }
    }
}

/// Generate a client nonce.
fn generate_cnonce() -> String {
    let random_bytes: [u8; 16] = rand::thread_rng().gen();
    hex::encode(random_bytes)
}

/// Parse authentication parameters from header value.
fn parse_auth_params(params_str: &str) -> Result<std::collections::HashMap<String, String>, DigestAuthError> {
    let mut params = std::collections::HashMap::new();
    let mut remaining = params_str.trim();

    while !remaining.is_empty() {
        // Skip leading whitespace and commas
        remaining = remaining.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
        if remaining.is_empty() {
            break;
        }

        // Find key
        let eq_pos = remaining.find('=').ok_or_else(|| {
            DigestAuthError::ParseError(format!("expected '=' in params: {}", remaining))
        })?;

        let key = remaining[..eq_pos].trim().to_lowercase();
        remaining = remaining[eq_pos + 1..].trim_start();

        // Parse value (quoted or unquoted)
        let value = if remaining.starts_with('"') {
            // Quoted value
            remaining = &remaining[1..];
            let end_quote = remaining.find('"').ok_or_else(|| {
                DigestAuthError::ParseError("unterminated quoted string".to_string())
            })?;
            let value = remaining[..end_quote].to_string();
            remaining = &remaining[end_quote + 1..];
            value
        } else {
            // Unquoted value (ends at comma or end of string)
            let end = remaining
                .find(',')
                .unwrap_or(remaining.len());
            let value = remaining[..end].trim().to_string();
            remaining = &remaining[end..];
            value
        };

        params.insert(key, value);
    }

    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_challenge() {
        let challenge = DigestChallenge::parse(
            r#"Digest realm="asterisk", nonce="1234567890""#
        ).unwrap();

        assert_eq!(challenge.realm, "asterisk");
        assert_eq!(challenge.nonce, "1234567890");
        assert_eq!(challenge.algorithm, Algorithm::Md5);
        assert!(challenge.opaque.is_none());
    }

    #[test]
    fn test_parse_full_challenge() {
        let challenge = DigestChallenge::parse(
            r#"Digest realm="sip.example.com", nonce="abc123", opaque="xyz", algorithm=MD5, qop="auth", stale=true"#
        ).unwrap();

        assert_eq!(challenge.realm, "sip.example.com");
        assert_eq!(challenge.nonce, "abc123");
        assert_eq!(challenge.opaque, Some("xyz".to_string()));
        assert_eq!(challenge.algorithm, Algorithm::Md5);
        assert_eq!(challenge.qop, Some(Qop::Auth));
        assert!(challenge.stale);
    }

    #[test]
    fn test_parse_md5_sess() {
        let challenge = DigestChallenge::parse(
            r#"Digest realm="test", nonce="abc", algorithm=MD5-sess"#
        ).unwrap();

        assert_eq!(challenge.algorithm, Algorithm::Md5Sess);
    }

    #[test]
    fn test_compute_digest_basic() {
        // Test vector from RFC 2617 example
        let response = compute_digest(
            "Mufasa",
            "Circle Of Life",
            "testrealm@host.com",
            "GET",
            "/dir/index.html",
            "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            Algorithm::Md5,
            None,
            None,
            None,
            None,
        );

        // Expected response per RFC 2617
        assert_eq!(response, "670fd8c2df070c60b045671b8b24ff02");
    }

    #[test]
    fn test_compute_digest_with_qop() {
        let response = compute_digest(
            "Mufasa",
            "Circle Of Life",
            "testrealm@host.com",
            "GET",
            "/dir/index.html",
            "dcd98b7102dd2f0e8b11d0f600bfb0c093",
            Algorithm::Md5,
            Some(Qop::Auth),
            Some("0a4f113b"),
            Some(1),
            None,
        );

        // Expected response per RFC 2617 with qop=auth
        assert_eq!(response, "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn test_digest_response_header() {
        let challenge = DigestChallenge {
            realm: "asterisk".to_string(),
            nonce: "abc123".to_string(),
            opaque: None,
            stale: false,
            algorithm: Algorithm::Md5,
            qop: None,
            domain: None,
        };

        let creds = DigestCredentials::new("alice", "secret");
        let response = DigestResponse::from_challenge(
            &challenge,
            &creds,
            "REGISTER",
            "sip:asterisk@192.168.1.1",
            None,
        ).unwrap();

        let header = response.to_header_value();
        assert!(header.starts_with("Digest username=\"alice\""));
        assert!(header.contains("realm=\"asterisk\""));
        assert!(header.contains("nonce=\"abc123\""));
        assert!(header.contains("response=\""));
    }

    #[test]
    fn test_digest_response_with_qop() {
        let challenge = DigestChallenge {
            realm: "asterisk".to_string(),
            nonce: "abc123".to_string(),
            opaque: Some("opaque_value".to_string()),
            stale: false,
            algorithm: Algorithm::Md5,
            qop: Some(Qop::Auth),
            domain: None,
        };

        let creds = DigestCredentials::new("alice", "secret");
        let response = DigestResponse::from_challenge(
            &challenge,
            &creds,
            "REGISTER",
            "sip:asterisk@192.168.1.1",
            None,
        ).unwrap();

        let header = response.to_header_value();
        assert!(header.contains("qop=auth"));
        assert!(header.contains("cnonce=\""));
        assert!(header.contains("nc=00000001"));
        assert!(header.contains("opaque=\"opaque_value\""));
    }

    #[test]
    fn test_missing_digest_scheme() {
        let result = DigestChallenge::parse("Basic realm=\"test\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_realm() {
        let result = DigestChallenge::parse("Digest nonce=\"abc\"");
        assert!(matches!(result, Err(DigestAuthError::MissingField("realm"))));
    }

    #[test]
    fn test_missing_nonce() {
        let result = DigestChallenge::parse("Digest realm=\"test\"");
        assert!(matches!(result, Err(DigestAuthError::MissingField("nonce"))));
    }
}
