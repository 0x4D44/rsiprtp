//! SIP Digest Authentication per RFC 2617, RFC 3261, and RFC 7616.
//!
//! Provides parsing of WWW-Authenticate/Proxy-Authenticate headers
//! and generation of Authorization/Proxy-Authorization headers.
//!
//! Supports MD5 (legacy) and SHA-256 (RFC 7616) algorithms.

use rand::Rng;
use sha2::{Digest, Sha256};
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
    /// SHA-256 algorithm (RFC 7616).
    Sha256,
    /// SHA-256-sess algorithm (RFC 7616).
    Sha256Sess,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::Md5 => write!(f, "MD5"),
            Algorithm::Md5Sess => write!(f, "MD5-sess"),
            Algorithm::Sha256 => write!(f, "SHA-256"),
            Algorithm::Sha256Sess => write!(f, "SHA-256-sess"),
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
            Some("SHA-256") => Algorithm::Sha256,
            Some("SHA-256-sess") => Algorithm::Sha256Sess,
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
        if challenge.realm.is_empty() {
            return Err(DigestAuthError::MissingField("realm"));
        }
        if challenge.nonce.is_empty() {
            return Err(DigestAuthError::MissingField("nonce"));
        }

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

/// Hash a string using MD5.
fn hash_md5(data: &str) -> String {
    hex::encode(md5::compute(data).0)
}

/// Hash bytes using MD5.
fn hash_md5_bytes(data: &[u8]) -> String {
    hex::encode(md5::compute(data).0)
}

/// Hash a string using SHA-256.
fn hash_sha256(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Hash bytes using SHA-256.
fn hash_sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

type HashStrFn = fn(&str) -> String;
type HashBytesFn = fn(&[u8]) -> String;

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
    // Select hash function based on algorithm
    let (hash_str, hash_bytes): (HashStrFn, HashBytesFn) = match algorithm {
        Algorithm::Md5 | Algorithm::Md5Sess => (hash_md5, hash_md5_bytes),
        Algorithm::Sha256 | Algorithm::Sha256Sess => (hash_sha256, hash_sha256_bytes),
    };

    // HA1 = H(username:realm:password)
    let ha1 = {
        let ha1_base = hash_str(&format!("{}:{}:{}", username, realm, password));

        match algorithm {
            Algorithm::Md5 | Algorithm::Sha256 => ha1_base,
            Algorithm::Md5Sess | Algorithm::Sha256Sess => {
                // HA1 = H(H(username:realm:password):nonce:cnonce)
                let cnonce = cnonce.unwrap_or("");
                hash_str(&format!("{}:{}:{}", ha1_base, nonce, cnonce))
            }
        }
    };

    // HA2 = H(method:uri) or H(method:uri:H(body)) for auth-int
    let ha2 = match qop {
        Some(Qop::AuthInt) => {
            let body_hash = if let Some(body) = body {
                hash_bytes(body)
            } else {
                hash_bytes(b"")
            };
            hash_str(&format!("{}:{}:{}", method, uri, body_hash))
        }
        _ => hash_str(&format!("{}:{}", method, uri)),
    };

    // Response = H(HA1:nonce:HA2) or H(HA1:nonce:nc:cnonce:qop:HA2)
    match qop {
        Some(qop) if qop != Qop::None => {
            let cnonce = cnonce.unwrap_or("");
            let nc = nc.unwrap_or(1);
            hash_str(&format!(
                "{}:{}:{:08x}:{}:{}:{}",
                ha1, nonce, nc, cnonce, qop, ha2
            ))
        }
        _ => hash_str(&format!("{}:{}:{}", ha1, nonce, ha2)),
    }
}

/// Generate a client nonce.
fn generate_cnonce() -> String {
    let random_bytes: [u8; 16] = rand::thread_rng().gen();
    hex::encode(random_bytes)
}

/// Parse authentication parameters from header value.
fn parse_auth_params(
    params_str: &str,
) -> Result<std::collections::HashMap<String, String>, DigestAuthError> {
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
            let end = remaining.find(',').unwrap_or(remaining.len());
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
        let challenge =
            DigestChallenge::parse(r#"Digest realm="asterisk", nonce="1234567890""#).unwrap();

        assert_eq!(challenge.realm, "asterisk");
        assert_eq!(challenge.nonce, "1234567890");
        assert_eq!(challenge.algorithm, Algorithm::Md5);
        assert!(challenge.opaque.is_none());
    }

    #[test]
    fn test_parse_auth_params_trailing_commas() {
        let params = parse_auth_params("realm=\"test\", nonce=\"abc\",   , ").unwrap();
        assert_eq!(params.get("realm"), Some(&"test".to_string()));
        assert_eq!(params.get("nonce"), Some(&"abc".to_string()));
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
        let challenge =
            DigestChallenge::parse(r#"Digest realm="test", nonce="abc", algorithm=MD5-sess"#)
                .unwrap();

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
        )
        .unwrap();

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
        )
        .unwrap();

        let header = response.to_header_value();
        assert!(header.contains("qop=auth"));
        assert!(header.contains("cnonce=\""));
        assert!(header.contains("nc=00000001"));
        assert!(header.contains("opaque=\"opaque_value\""));
    }

    #[test]
    fn test_digest_response_with_qop_missing_cnonce_nc() {
        let response = DigestResponse {
            username: "alice".to_string(),
            realm: "asterisk".to_string(),
            nonce: "abc123".to_string(),
            uri: "sip:asterisk@192.168.1.1".to_string(),
            response: "deadbeef".to_string(),
            algorithm: Algorithm::Md5,
            opaque: None,
            qop: Some(Qop::Auth),
            cnonce: None,
            nc: None,
        };

        let header = response.to_header_value();
        assert!(header.contains("qop=auth"));
        assert!(!header.contains("cnonce=\""));
        assert!(!header.contains("nc="));
    }

    #[test]
    fn test_missing_digest_scheme() {
        let result = DigestChallenge::parse("Basic realm=\"test\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_realm() {
        let result = DigestChallenge::parse("Digest nonce=\"abc\"");
        assert!(matches!(
            result,
            Err(DigestAuthError::MissingField("realm"))
        ));
    }

    #[test]
    fn test_missing_nonce() {
        let result = DigestChallenge::parse("Digest realm=\"test\"");
        assert!(matches!(
            result,
            Err(DigestAuthError::MissingField("nonce"))
        ));
    }

    // Additional tests for uncovered code paths

    #[test]
    fn test_qop_display() {
        assert_eq!(format!("{}", Qop::None), "");
        assert_eq!(format!("{}", Qop::Auth), "auth");
        assert_eq!(format!("{}", Qop::AuthInt), "auth-int");
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(format!("{}", Algorithm::Md5), "MD5");
        assert_eq!(format!("{}", Algorithm::Md5Sess), "MD5-sess");
        assert_eq!(format!("{}", Algorithm::Sha256), "SHA-256");
        assert_eq!(format!("{}", Algorithm::Sha256Sess), "SHA-256-sess");
    }

    #[test]
    fn test_parse_sha256_algorithm() {
        let challenge =
            DigestChallenge::parse(r#"Digest realm="test", nonce="abc", algorithm=SHA-256"#)
                .unwrap();
        assert_eq!(challenge.algorithm, Algorithm::Sha256);
    }

    #[test]
    fn test_parse_sha256_sess_algorithm() {
        let challenge =
            DigestChallenge::parse(r#"Digest realm="test", nonce="abc", algorithm=SHA-256-sess"#)
                .unwrap();
        assert_eq!(challenge.algorithm, Algorithm::Sha256Sess);
    }

    #[test]
    fn test_compute_digest_sha256() {
        // SHA-256 should produce a 64-char hex string (256 bits = 32 bytes = 64 hex chars)
        let response = compute_digest(
            "user",
            "password",
            "realm",
            "REGISTER",
            "sip:example.com",
            "servernonce",
            Algorithm::Sha256,
            Some(Qop::Auth),
            Some("clientnonce"),
            Some(1),
            None,
        );

        assert_eq!(response.len(), 64);
        assert!(response.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_digest_sha256_sess() {
        let response = compute_digest(
            "user",
            "password",
            "realm",
            "REGISTER",
            "sip:example.com",
            "servernonce",
            Algorithm::Sha256Sess,
            Some(Qop::Auth),
            Some("clientnonce"),
            Some(1),
            None,
        );

        assert_eq!(response.len(), 64);
        assert!(response.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sha256_response_generation() {
        // Test full response generation with SHA-256
        let challenge = DigestChallenge {
            realm: "sip.example.com".to_string(),
            nonce: "testnonce123".to_string(),
            opaque: None,
            stale: false,
            algorithm: Algorithm::Sha256,
            qop: Some(Qop::Auth),
            domain: None,
        };

        let creds = DigestCredentials::new("testuser", "testpassword");
        let response = DigestResponse::from_challenge(
            &challenge,
            &creds,
            "REGISTER",
            "sip:sip.example.com",
            None,
        )
        .unwrap();

        assert_eq!(response.algorithm, Algorithm::Sha256);
        // SHA-256 response should be 64 hex chars
        assert_eq!(response.response.len(), 64);

        // Verify the header contains algorithm=SHA-256
        let header = response.to_header_value();
        assert!(header.contains("algorithm=SHA-256"));
    }

    #[test]
    fn test_digest_auth_error_display() {
        let err = DigestAuthError::MissingField("realm");
        assert!(err.to_string().contains("realm"));

        let err = DigestAuthError::UnsupportedAlgorithm("SHA512".to_string());
        assert!(err.to_string().contains("SHA512"));

        let err = DigestAuthError::UnsupportedQop("auth-int-256".to_string());
        assert!(err.to_string().contains("auth-int-256"));

        let err = DigestAuthError::ParseError("bad format".to_string());
        assert!(err.to_string().contains("bad format"));
    }

    #[test]
    fn test_parse_unsupported_algorithm() {
        let result =
            DigestChallenge::parse(r#"Digest realm="test", nonce="abc", algorithm=SHA256"#);
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unsupported algorithm"));
    }

    #[test]
    fn test_parse_invalid_params_missing_equals() {
        let result = DigestChallenge::parse(r#"Digest realm"test", nonce="abc""#);
        let err = result.unwrap_err();
        assert!(err.to_string().contains("missing required field: realm"));
    }

    #[test]
    fn test_parse_invalid_params_unterminated_quote() {
        let result = DigestChallenge::parse(r#"Digest realm="test, nonce=abc"#);
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unterminated quoted string"));
    }

    #[test]
    fn test_response_missing_realm() {
        let challenge = DigestChallenge {
            realm: String::new(),
            nonce: "abc".to_string(),
            opaque: None,
            stale: false,
            algorithm: Algorithm::Md5,
            qop: None,
            domain: None,
        };
        let credentials = DigestCredentials::new("user", "pass");
        let err = DigestResponse::from_challenge(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:example.com",
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("missing required field: realm"));
    }

    #[test]
    fn test_response_missing_nonce() {
        let challenge = DigestChallenge {
            realm: "test".to_string(),
            nonce: String::new(),
            opaque: None,
            stale: false,
            algorithm: Algorithm::Md5,
            qop: None,
            domain: None,
        };
        let credentials = DigestCredentials::new("user", "pass");
        let err = DigestResponse::from_challenge(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:example.com",
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("missing required field: nonce"));
    }

    #[test]
    fn test_parse_qop_auth_int() {
        let challenge =
            DigestChallenge::parse(r#"Digest realm="test", nonce="abc", qop="auth-int""#).unwrap();

        assert_eq!(challenge.qop, Some(Qop::AuthInt));
    }

    #[test]
    fn test_parse_qop_multiple_values() {
        // When multiple qop values are offered, prefer "auth"
        let challenge =
            DigestChallenge::parse(r#"Digest realm="test", nonce="abc", qop="auth,auth-int""#)
                .unwrap();

        assert_eq!(challenge.qop, Some(Qop::Auth));
    }

    #[test]
    fn test_parse_qop_unknown() {
        let challenge =
            DigestChallenge::parse(r#"Digest realm="test", nonce="abc", qop="unknown""#).unwrap();

        // Unknown qop values result in Qop::None
        assert_eq!(challenge.qop, Some(Qop::None));
    }

    #[test]
    fn test_parse_stale_false() {
        let challenge =
            DigestChallenge::parse(r#"Digest realm="test", nonce="abc", stale=false"#).unwrap();

        assert!(!challenge.stale);
    }

    #[test]
    fn test_parse_with_domain() {
        let challenge =
            DigestChallenge::parse(r#"Digest realm="test", nonce="abc", domain="sip:example.com""#)
                .unwrap();

        assert_eq!(challenge.domain, Some("sip:example.com".to_string()));
    }

    #[test]
    fn test_compute_digest_md5_sess() {
        // MD5-sess uses a different HA1 calculation
        let response = compute_digest(
            "user",
            "password",
            "realm",
            "REGISTER",
            "sip:example.com",
            "servernonce",
            Algorithm::Md5Sess,
            Some(Qop::Auth),
            Some("clientnonce"),
            Some(1),
            None,
        );

        // Just verify it produces a 32-char hex string
        assert_eq!(response.len(), 32);
        assert!(response.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_digest_auth_int_with_body() {
        let body = b"test body content";
        let response = compute_digest(
            "user",
            "password",
            "realm",
            "INVITE",
            "sip:example.com",
            "nonce123",
            Algorithm::Md5,
            Some(Qop::AuthInt),
            Some("cnonce"),
            Some(1),
            Some(body),
        );

        // Verify it produces a 32-char hex string
        assert_eq!(response.len(), 32);
        assert!(response.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_digest_auth_int_sha256_with_body() {
        let body = b"test body content";
        let response = compute_digest(
            "user",
            "password",
            "realm",
            "INVITE",
            "sip:example.com",
            "nonce123",
            Algorithm::Sha256,
            Some(Qop::AuthInt),
            Some("cnonce"),
            Some(1),
            Some(body),
        );

        assert_eq!(response.len(), 64);
        assert!(response.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_digest_auth_int_without_body() {
        // When auth-int is used without body, empty body is hashed
        let response = compute_digest(
            "user",
            "password",
            "realm",
            "INVITE",
            "sip:example.com",
            "nonce123",
            Algorithm::Md5,
            Some(Qop::AuthInt),
            Some("cnonce"),
            Some(1),
            None,
        );

        assert_eq!(response.len(), 32);
    }

    #[test]
    fn test_compute_digest_md5_sess_empty_cnonce() {
        // MD5-sess with empty cnonce
        let response = compute_digest(
            "user",
            "password",
            "realm",
            "REGISTER",
            "sip:example.com",
            "servernonce",
            Algorithm::Md5Sess,
            None,
            None,
            None,
            None,
        );

        assert_eq!(response.len(), 32);
    }

    #[test]
    fn test_digest_response_with_auth_int() {
        let challenge = DigestChallenge {
            realm: "asterisk".to_string(),
            nonce: "abc123".to_string(),
            opaque: None,
            stale: false,
            algorithm: Algorithm::Md5,
            qop: Some(Qop::AuthInt),
            domain: None,
        };

        let creds = DigestCredentials::new("alice", "secret");
        let body = b"v=0\r\no=- 12345\r\n";
        let response = DigestResponse::from_challenge(
            &challenge,
            &creds,
            "INVITE",
            "sip:bob@example.com",
            Some(body),
        )
        .unwrap();

        let header = response.to_header_value();
        assert!(header.contains("qop=auth-int"));
    }

    #[test]
    fn test_digest_response_with_md5_sess() {
        let challenge = DigestChallenge {
            realm: "asterisk".to_string(),
            nonce: "abc123".to_string(),
            opaque: None,
            stale: false,
            algorithm: Algorithm::Md5Sess,
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
        )
        .unwrap();

        let header = response.to_header_value();
        assert!(header.contains("algorithm=MD5-sess"));
    }

    #[test]
    fn test_parse_auth_params_no_equals() {
        // Test malformed params without equals sign
        let result = parse_auth_params("realm");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_auth_params_unterminated_quote() {
        let result = parse_auth_params("realm=\"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_auth_params_unquoted_value() {
        let result = parse_auth_params("algorithm=MD5").unwrap();
        assert_eq!(result.get("algorithm"), Some(&"MD5".to_string()));
    }

    #[test]
    fn test_parse_challenge_case_insensitive() {
        // "digest" instead of "Digest"
        let challenge = DigestChallenge::parse(r#"digest realm="test", nonce="abc""#).unwrap();
        assert_eq!(challenge.realm, "test");
    }

    #[test]
    fn test_parse_challenge_with_whitespace() {
        let challenge = DigestChallenge::parse(r#"  Digest realm="test", nonce="abc"  "#).unwrap();
        assert_eq!(challenge.realm, "test");
    }

    #[test]
    fn test_digest_credentials_new() {
        let creds = DigestCredentials::new("user", "pass");
        assert_eq!(creds.username, "user");
        assert_eq!(creds.password, "pass");

        // Test with String types
        let creds2 = DigestCredentials::new("user".to_string(), "pass".to_string());
        assert_eq!(creds2.username, "user");
    }

    #[test]
    fn test_qop_default() {
        let qop = Qop::default();
        assert_eq!(qop, Qop::None);
    }

    #[test]
    fn test_algorithm_default() {
        let alg = Algorithm::default();
        assert_eq!(alg, Algorithm::Md5);
    }

    #[test]
    fn test_digest_response_clone() {
        let response = DigestResponse {
            username: "alice".to_string(),
            realm: "test".to_string(),
            nonce: "nonce".to_string(),
            uri: "sip:example.com".to_string(),
            response: "abcd1234".to_string(),
            algorithm: Algorithm::Md5,
            opaque: Some("opaque".to_string()),
            qop: Some(Qop::Auth),
            cnonce: Some("cnonce".to_string()),
            nc: Some(1),
        };

        let cloned = response.clone();
        assert_eq!(cloned.username, "alice");
        assert_eq!(cloned.opaque, Some("opaque".to_string()));
    }

    #[test]
    fn test_digest_challenge_clone() {
        let challenge = DigestChallenge {
            realm: "test".to_string(),
            nonce: "abc".to_string(),
            opaque: Some("xyz".to_string()),
            stale: true,
            algorithm: Algorithm::Md5Sess,
            qop: Some(Qop::AuthInt),
            domain: Some("sip:example.com".to_string()),
        };

        let cloned = challenge.clone();
        assert_eq!(cloned.realm, "test");
        assert_eq!(cloned.algorithm, Algorithm::Md5Sess);
        assert_eq!(cloned.qop, Some(Qop::AuthInt));
    }

    #[test]
    fn test_digest_credentials_clone() {
        let creds = DigestCredentials::new("user", "pass");
        let cloned = creds.clone();
        assert_eq!(cloned.username, "user");
        assert_eq!(cloned.password, "pass");
    }

    #[test]
    fn test_digest_response_no_qop_header() {
        let response = DigestResponse {
            username: "alice".to_string(),
            realm: "test".to_string(),
            nonce: "nonce".to_string(),
            uri: "sip:example.com".to_string(),
            response: "abcd1234".to_string(),
            algorithm: Algorithm::Md5,
            opaque: None,
            qop: Some(Qop::None),
            cnonce: None,
            nc: None,
        };

        let header = response.to_header_value();
        // When qop is None, no qop field should be in header
        assert!(!header.contains("qop="));
    }

    #[test]
    fn test_compute_digest_qop_none_explicit() {
        // When qop is explicitly Qop::None, use simple response format
        let response = compute_digest(
            "user",
            "password",
            "realm",
            "REGISTER",
            "sip:example.com",
            "nonce",
            Algorithm::Md5,
            Some(Qop::None),
            None,
            None,
            None,
        );

        assert_eq!(response.len(), 32);
    }
}
