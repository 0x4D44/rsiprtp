//! SIP registration management.
//!
//! Handles REGISTER requests with digest authentication support
//! and periodic re-registration.

use crate::sip::{
    generate_branch, generate_call_id, generate_tag, DigestChallenge, DigestCredentials,
    DigestResponse, Method, SipRequest, SipResponse,
};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Registration errors.
#[derive(Debug, Error)]
pub enum RegistrationError {
    /// Failed to parse authentication challenge.
    #[error("authentication error: {0}")]
    AuthError(String),

    /// Failed to build request.
    #[error("request error: {0}")]
    RequestError(String),

    /// Registration failed with error response.
    #[error("registration failed: {0} {1}")]
    Failed(u16, String),

    /// Registration timeout.
    #[error("registration timeout")]
    Timeout,
}

/// Registration state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState {
    /// Not registered.
    Unregistered,
    /// Registration in progress (waiting for response).
    Registering,
    /// Successfully registered.
    Registered,
    /// Refreshing registration.
    Refreshing,
    /// Unregistration in progress.
    Unregistering,
    /// Registration failed.
    Failed,
}

/// Configuration for registration.
#[derive(Debug, Clone)]
pub struct RegistrationConfig {
    /// SIP registrar URI (e.g., "sip:registrar.example.com").
    pub registrar: String,
    /// User AoR (Address of Record, e.g., "sip:alice@example.com").
    pub aor: String,
    /// Contact URI (where to receive calls).
    pub contact: String,
    /// Username for authentication.
    pub username: String,
    /// Password for authentication.
    pub password: String,
    /// Registration expiry in seconds.
    pub expires: u32,
    /// Local SIP address (IP:port).
    pub local_addr: String,
    /// Local SIP port.
    pub local_port: u16,
    /// Transport protocol.
    pub transport: String,
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        Self {
            registrar: String::new(),
            aor: String::new(),
            contact: String::new(),
            username: String::new(),
            password: String::new(),
            expires: 3600,
            local_addr: "127.0.0.1".to_string(),
            local_port: 5060,
            transport: "UDP".to_string(),
        }
    }
}

/// SIP registration manager.
///
/// Manages a single registration with a SIP registrar, including
/// authentication challenges and periodic refresh.
#[derive(Debug)]
pub struct RegistrationManager {
    /// Configuration.
    config: RegistrationConfig,
    /// Current state.
    state: RegistrationState,
    /// Current CSeq number.
    cseq: u32,
    /// Call-ID for this registration.
    call_id: String,
    /// From tag.
    from_tag: String,
    /// Registration expiry time.
    expires_at: Option<Instant>,
    /// Last challenge (for retry with auth).
    last_challenge: Option<DigestChallenge>,
    /// Nonce count for auth.
    nc: u32,
}

impl RegistrationManager {
    /// Create a new registration manager.
    pub fn new(config: RegistrationConfig) -> Self {
        let call_id = generate_call_id(&config.local_addr);
        let from_tag = generate_tag();

        Self {
            config,
            state: RegistrationState::Unregistered,
            cseq: 1,
            call_id,
            from_tag,
            expires_at: None,
            last_challenge: None,
            nc: 0,
        }
    }

    /// Get the current registration state.
    pub fn state(&self) -> RegistrationState {
        self.state
    }

    /// Check if currently registered.
    pub fn is_registered(&self) -> bool {
        self.state == RegistrationState::Registered
    }

    /// Check if registration needs refresh.
    pub fn needs_refresh(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            // Refresh when 80% of the time has elapsed.
            //
            // Use `checked_sub` because `Instant` on some platforms (notably
            // Windows, where `Instant` is monotonic since boot) cannot
            // represent times before the platform's epoch. If subtracting
            // the refresh window would underflow, the refresh threshold is
            // logically already in the past, so we report true.
            let now = Instant::now();
            let window = Duration::from_secs((self.config.expires as u64) / 5);
            match expires_at.checked_sub(window) {
                Some(refresh_at) => now >= refresh_at,
                None => true,
            }
        } else {
            false
        }
    }

    /// Create a REGISTER request to initiate or refresh registration.
    pub fn create_register(&mut self) -> Result<SipRequest, RegistrationError> {
        self.state = if self.state == RegistrationState::Registered {
            RegistrationState::Refreshing
        } else {
            RegistrationState::Registering
        };

        self.cseq += 1;
        let branch = generate_branch();

        let builder = SipRequest::builder()
            .method(Method::Register)
            .uri(&self.config.registrar)
            .via(
                &self.config.local_addr,
                self.config.local_port,
                &self.config.transport,
                &branch,
            )
            .from(&self.config.aor, &self.from_tag)
            .to(&self.config.aor)
            .call_id(&self.call_id)
            .cseq(self.cseq)
            .contact(&self.config.contact)
            .expires(self.config.expires);

        builder
            .build()
            .map_err(|e| RegistrationError::RequestError(e.to_string()))
    }

    /// Create a REGISTER request with authentication.
    pub fn create_register_with_auth(
        &mut self,
        challenge: &DigestChallenge,
    ) -> Result<SipRequest, RegistrationError> {
        self.cseq += 1;
        self.nc += 1;
        let branch = generate_branch();

        let credentials = DigestCredentials::new(&self.config.username, &self.config.password);

        let response = DigestResponse::from_challenge(
            challenge,
            &credentials,
            "REGISTER",
            &self.config.registrar,
            None,
        )
        .map_err(|e| RegistrationError::AuthError(e.to_string()))?;

        let auth_value = response.to_header_value();

        let builder = SipRequest::builder()
            .method(Method::Register)
            .uri(&self.config.registrar)
            .via(
                &self.config.local_addr,
                self.config.local_port,
                &self.config.transport,
                &branch,
            )
            .from(&self.config.aor, &self.from_tag)
            .to(&self.config.aor)
            .call_id(&self.call_id)
            .cseq(self.cseq)
            .contact(&self.config.contact)
            .expires(self.config.expires)
            .authorization(&auth_value);

        builder
            .build()
            .map_err(|e| RegistrationError::RequestError(e.to_string()))
    }

    /// Create an unREGISTER request (expires=0).
    pub fn create_unregister(&mut self) -> Result<SipRequest, RegistrationError> {
        self.state = RegistrationState::Unregistering;
        self.cseq += 1;
        let branch = generate_branch();

        let builder = SipRequest::builder()
            .method(Method::Register)
            .uri(&self.config.registrar)
            .via(
                &self.config.local_addr,
                self.config.local_port,
                &self.config.transport,
                &branch,
            )
            .from(&self.config.aor, &self.from_tag)
            .to(&self.config.aor)
            .call_id(&self.call_id)
            .cseq(self.cseq)
            .contact(&self.config.contact)
            .expires(0);

        // If we have a previous challenge, include auth
        if let Some(ref challenge) = self.last_challenge {
            self.nc += 1;
            let credentials = DigestCredentials::new(&self.config.username, &self.config.password);

            let response = DigestResponse::from_challenge(
                challenge,
                &credentials,
                "REGISTER",
                &self.config.registrar,
                None,
            )
            .map_err(|e| RegistrationError::AuthError(e.to_string()))?;

            return SipRequest::builder()
                .method(Method::Register)
                .uri(&self.config.registrar)
                .via(
                    &self.config.local_addr,
                    self.config.local_port,
                    &self.config.transport,
                    &branch,
                )
                .from(&self.config.aor, &self.from_tag)
                .to(&self.config.aor)
                .call_id(&self.call_id)
                .cseq(self.cseq)
                .contact(&self.config.contact)
                .expires(0)
                .authorization(&response.to_header_value())
                .build()
                .map_err(|e| RegistrationError::RequestError(e.to_string()));
        }

        builder
            .build()
            .map_err(|e| RegistrationError::RequestError(e.to_string()))
    }

    /// Handle a response to our REGISTER request.
    ///
    /// Returns:
    /// - `Ok(None)` if registration successful
    /// - `Ok(Some(request))` if we need to retry with authentication
    /// - `Err(error)` if registration failed
    pub fn handle_response(
        &mut self,
        response: &SipResponse,
    ) -> Result<Option<SipRequest>, RegistrationError> {
        let status = response.status_code();

        match status {
            200 => {
                // Success
                if self.state == RegistrationState::Unregistering {
                    self.state = RegistrationState::Unregistered;
                    self.expires_at = None;
                } else {
                    self.state = RegistrationState::Registered;
                    self.expires_at =
                        Some(Instant::now() + Duration::from_secs(self.config.expires as u64));
                }
                Ok(None)
            }
            401 => {
                // Unauthorized - need to retry with auth
                let www_auth = response.www_authenticate().ok_or_else(|| {
                    RegistrationError::AuthError("401 without WWW-Authenticate".to_string())
                })?;

                let challenge = DigestChallenge::parse(&www_auth)
                    .map_err(|e| RegistrationError::AuthError(e.to_string()))?;

                self.last_challenge = Some(challenge.clone());

                let request = self.create_register_with_auth(&challenge)?;
                Ok(Some(request))
            }
            407 => {
                // Proxy authentication required
                let proxy_auth = response.proxy_authenticate().ok_or_else(|| {
                    RegistrationError::AuthError("407 without Proxy-Authenticate".to_string())
                })?;

                let challenge = DigestChallenge::parse(&proxy_auth)
                    .map_err(|e| RegistrationError::AuthError(e.to_string()))?;

                self.last_challenge = Some(challenge.clone());

                // Create request with Proxy-Authorization
                self.cseq += 1;
                self.nc += 1;
                let branch = generate_branch();

                let credentials =
                    DigestCredentials::new(&self.config.username, &self.config.password);

                let response = DigestResponse::from_challenge(
                    &challenge,
                    &credentials,
                    "REGISTER",
                    &self.config.registrar,
                    None,
                )
                .map_err(|e| RegistrationError::AuthError(e.to_string()))?;

                let request = SipRequest::builder()
                    .method(Method::Register)
                    .uri(&self.config.registrar)
                    .via(
                        &self.config.local_addr,
                        self.config.local_port,
                        &self.config.transport,
                        &branch,
                    )
                    .from(&self.config.aor, &self.from_tag)
                    .to(&self.config.aor)
                    .call_id(&self.call_id)
                    .cseq(self.cseq)
                    .contact(&self.config.contact)
                    .expires(self.config.expires)
                    .proxy_authorization(&response.to_header_value())
                    .build()
                    .map_err(|e| RegistrationError::RequestError(e.to_string()))?;

                Ok(Some(request))
            }
            _ if status >= 400 => {
                // Error response
                self.state = RegistrationState::Failed;
                Err(RegistrationError::Failed(status, response.reason()))
            }
            _ => {
                // Provisional responses are ignored
                Ok(None)
            }
        }
    }

    /// Reset the registration state (e.g., after connection loss).
    pub fn reset(&mut self) {
        self.state = RegistrationState::Unregistered;
        self.expires_at = None;
        self.last_challenge = None;
        self.nc = 0;
    }

    /// Get the registration configuration.
    pub fn config(&self) -> &RegistrationConfig {
        &self.config
    }

    /// Get the Call-ID for this registration.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RegistrationConfig {
        RegistrationConfig {
            registrar: "sip:registrar.example.com".to_string(),
            aor: "sip:alice@example.com".to_string(),
            contact: "sip:alice@192.168.1.100:5060".to_string(),
            username: "alice".to_string(),
            password: "secret".to_string(),
            expires: 3600,
            local_addr: "192.168.1.100".to_string(),
            local_port: 5060,
            transport: "UDP".to_string(),
        }
    }

    fn invalid_config() -> RegistrationConfig {
        let mut config = test_config();
        config.registrar = "sip:registrar@[::1".to_string();
        config
    }

    // RegistrationError tests
    #[test]
    fn test_registration_error_auth() {
        let err = RegistrationError::AuthError("test error".to_string());
        assert!(err.to_string().contains("authentication error"));
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_registration_error_request() {
        let err = RegistrationError::RequestError("build failed".to_string());
        assert!(err.to_string().contains("request error"));
    }

    #[test]
    fn test_registration_error_failed() {
        let err = RegistrationError::Failed(403, "Forbidden".to_string());
        assert!(err.to_string().contains("403"));
        assert!(err.to_string().contains("Forbidden"));
    }

    #[test]
    fn test_registration_error_timeout() {
        let err = RegistrationError::Timeout;
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_registration_error_debug() {
        let err = RegistrationError::Timeout;
        let debug = format!("{:?}", err);
        assert!(debug.contains("Timeout"));
    }

    // RegistrationState tests
    #[test]
    fn test_registration_state_eq() {
        assert_eq!(
            RegistrationState::Unregistered,
            RegistrationState::Unregistered
        );
        assert_ne!(
            RegistrationState::Unregistered,
            RegistrationState::Registered
        );
    }

    #[test]
    fn test_registration_state_clone() {
        let state = RegistrationState::Registered;
        let cloned = state;
        assert_eq!(state, cloned);
    }

    #[test]
    fn test_registration_state_debug() {
        let state = RegistrationState::Registering;
        let debug = format!("{:?}", state);
        assert!(debug.contains("Registering"));
    }

    #[test]
    fn test_registration_state_all_variants() {
        let states = [
            RegistrationState::Unregistered,
            RegistrationState::Registering,
            RegistrationState::Registered,
            RegistrationState::Refreshing,
            RegistrationState::Unregistering,
            RegistrationState::Failed,
        ];
        for state in states {
            let _ = format!("{:?}", state);
        }
    }

    // RegistrationConfig tests
    #[test]
    fn test_registration_config_default() {
        let config = RegistrationConfig::default();
        assert!(config.registrar.is_empty());
        assert!(config.aor.is_empty());
        assert!(config.contact.is_empty());
        assert!(config.username.is_empty());
        assert!(config.password.is_empty());
        assert_eq!(config.expires, 3600);
        assert_eq!(config.local_addr, "127.0.0.1");
        assert_eq!(config.local_port, 5060);
        assert_eq!(config.transport, "UDP");
    }

    #[test]
    fn test_registration_config_debug() {
        let config = test_config();
        let debug = format!("{:?}", config);
        assert!(debug.contains("RegistrationConfig"));
    }

    #[test]
    fn test_registration_config_clone() {
        let config = test_config();
        let cloned = config.clone();
        assert_eq!(cloned.registrar, "sip:registrar.example.com");
    }

    // RegistrationManager tests
    #[test]
    fn test_registration_manager_new() {
        let manager = RegistrationManager::new(test_config());
        assert_eq!(manager.state(), RegistrationState::Unregistered);
        assert!(!manager.is_registered());
        assert!(!manager.call_id().is_empty());
    }

    #[test]
    fn test_registration_manager_config() {
        let manager = RegistrationManager::new(test_config());
        let config = manager.config();
        assert_eq!(config.registrar, "sip:registrar.example.com");
    }

    #[test]
    fn test_registration_manager_debug() {
        let manager = RegistrationManager::new(test_config());
        let debug = format!("{:?}", manager);
        assert!(debug.contains("RegistrationManager"));
    }

    #[test]
    fn test_create_register() {
        let mut manager = RegistrationManager::new(test_config());

        assert_eq!(manager.state(), RegistrationState::Unregistered);

        let request = manager.create_register().unwrap();

        assert_eq!(manager.state(), RegistrationState::Registering);

        let bytes = request.to_bytes();
        let msg = String::from_utf8_lossy(&bytes);

        assert!(msg.contains("REGISTER"));
        assert!(msg.contains("sip:registrar.example.com"));
        assert!(msg.contains("alice@example.com"));
        assert!(msg.contains("Expires: 3600"));
    }

    #[test]
    fn test_create_register_invalid_registrar() {
        let mut manager = RegistrationManager::new(invalid_config());
        let err = manager.create_register().unwrap_err();
        assert!(err.to_string().contains("request error"));
    }

    #[test]
    fn test_create_register_with_auth_success() {
        let mut manager = RegistrationManager::new(test_config());
        let challenge = DigestChallenge::parse("Digest realm=\"test\", nonce=\"abc\"").unwrap();
        let request = manager.create_register_with_auth(&challenge).unwrap();
        let bytes = request.to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("Authorization: Digest"));
    }

    #[test]
    fn test_create_register_with_auth_invalid_registrar() {
        let mut manager = RegistrationManager::new(invalid_config());
        let challenge = DigestChallenge::parse("Digest realm=\"test\", nonce=\"abc\"").unwrap();
        let err = manager.create_register_with_auth(&challenge).unwrap_err();
        assert!(err.to_string().contains("request error"));
    }

    #[test]
    fn test_create_register_with_auth_invalid_challenge() {
        let mut manager = RegistrationManager::new(test_config());
        let challenge = DigestChallenge {
            realm: String::new(),
            nonce: "abc".to_string(),
            opaque: None,
            stale: false,
            algorithm: crate::sip::Algorithm::Md5,
            qop: None,
            domain: None,
        };
        let err = manager.create_register_with_auth(&challenge).unwrap_err();
        assert!(err.to_string().contains("authentication error"));
    }

    #[test]
    fn test_create_register_refresh() {
        let mut manager = RegistrationManager::new(test_config());

        // Set to registered state
        manager.state = RegistrationState::Registered;
        manager.expires_at = Some(Instant::now() + Duration::from_secs(100));

        // Create register should set state to Refreshing
        let request = manager.create_register().unwrap();

        assert_eq!(manager.state(), RegistrationState::Refreshing);
        assert!(!request.to_bytes().is_empty());
    }

    #[test]
    fn test_create_unregister() {
        let mut manager = RegistrationManager::new(test_config());

        // First register
        manager.create_register().unwrap();
        manager.state = RegistrationState::Registered;

        // Now unregister
        let request = manager.create_unregister().unwrap();

        assert_eq!(manager.state(), RegistrationState::Unregistering);

        let bytes = request.to_bytes();
        let msg = String::from_utf8_lossy(&bytes);

        assert!(msg.contains("REGISTER"));
        assert!(msg.contains("Expires: 0"));
    }

    #[test]
    fn test_create_unregister_with_previous_challenge() {
        let mut manager = RegistrationManager::new(test_config());

        // First register
        manager.create_register().unwrap();

        // Simulate having received a challenge
        let challenge =
            DigestChallenge::parse("Digest realm=\"asterisk\", nonce=\"abc123\"").unwrap();
        manager.last_challenge = Some(challenge);
        manager.state = RegistrationState::Registered;

        // Now unregister should include auth
        let request = manager.create_unregister().unwrap();

        let bytes = request.to_bytes();
        let msg = String::from_utf8_lossy(&bytes);

        assert!(msg.contains("Expires: 0"));
        assert!(msg.contains("Authorization"));
    }

    #[test]
    fn test_create_unregister_with_last_challenge() {
        let mut manager = RegistrationManager::new(test_config());
        manager.last_challenge =
            Some(DigestChallenge::parse("Digest realm=\"test\", nonce=\"abc\"").unwrap());
        let request = manager.create_unregister().unwrap();
        let bytes = request.to_bytes();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("Authorization: Digest"));
    }

    #[test]
    fn test_create_unregister_with_invalid_challenge() {
        let mut manager = RegistrationManager::new(test_config());
        manager.last_challenge = Some(DigestChallenge {
            realm: String::new(),
            nonce: "abc".to_string(),
            opaque: None,
            stale: false,
            algorithm: crate::sip::Algorithm::Md5,
            qop: None,
            domain: None,
        });
        let err = manager.create_unregister().unwrap_err();
        assert!(err.to_string().contains("authentication error"));
    }

    #[test]
    fn test_create_unregister_with_auth_invalid_registrar() {
        let mut manager = RegistrationManager::new(invalid_config());
        manager.last_challenge =
            Some(DigestChallenge::parse("Digest realm=\"test\", nonce=\"abc\"").unwrap());
        let err = manager.create_unregister().unwrap_err();
        assert!(err.to_string().contains("request error"));
    }

    #[test]
    fn test_create_unregister_invalid_registrar() {
        let mut manager = RegistrationManager::new(invalid_config());
        let err = manager.create_unregister().unwrap_err();
        assert!(err.to_string().contains("request error"));
    }

    #[test]
    fn test_handle_200_ok() {
        let mut manager = RegistrationManager::new(test_config());
        manager.create_register().unwrap();

        // Build a mock 200 OK response
        let response_bytes = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>;tag=totag\r\n\
Call-ID: test@192.168.1.100\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:alice@192.168.1.100:5060>\r\n\
Expires: 3600\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = crate::sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);

        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // No retry needed
        assert_eq!(manager.state(), RegistrationState::Registered);
        assert!(manager.is_registered());
    }

    #[test]
    fn test_handle_200_ok_unregistering() {
        let mut manager = RegistrationManager::new(test_config());
        manager.state = RegistrationState::Unregistering;

        // Build a mock 200 OK response
        let response_bytes = b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>;tag=totag\r\n\
Call-ID: test@192.168.1.100\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = crate::sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);

        assert!(result.is_ok());
        assert_eq!(manager.state(), RegistrationState::Unregistered);
        assert!(manager.expires_at.is_none());
    }

    #[test]
    fn test_handle_401_challenge() {
        let mut manager = RegistrationManager::new(test_config());
        manager.create_register().unwrap();

        // Build a mock 401 response with WWW-Authenticate
        let response_bytes = b"SIP/2.0 401 Unauthorized\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>;tag=totag\r\n\
Call-ID: test@192.168.1.100\r\n\
CSeq: 1 REGISTER\r\n\
WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"abc123\"\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = crate::sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);
        assert!(result.is_ok());
        let retry = result.unwrap();
        assert!(retry.is_some()); // Should retry with auth

        let retry_request = retry.unwrap();
        let bytes = retry_request.to_bytes();
        let msg = String::from_utf8_lossy(&bytes);

        assert!(msg.contains("Authorization: Digest"));
        assert!(msg.contains("username=\"alice\""));
        assert!(msg.contains("realm=\"asterisk\""));
    }

    #[test]
    fn test_handle_401_invalid_challenge() {
        let mut manager = RegistrationManager::new(test_config());
        manager.create_register().unwrap();

        let response_bytes = b"SIP/2.0 401 Unauthorized\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>;tag=totag\r\n\
Call-ID: test@192.168.1.100\r\n\
CSeq: 1 REGISTER\r\n\
WWW-Authenticate: Digest realm=\"asterisk\"\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = crate::sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("authentication error"));
    }

    #[test]
    fn test_handle_401_empty_realm() {
        let mut manager = RegistrationManager::new(test_config());
        manager.create_register().unwrap();

        let response_bytes = b"SIP/2.0 401 Unauthorized\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>;tag=totag\r\n\
Call-ID: test@192.168.1.100\r\n\
CSeq: 1 REGISTER\r\n\
WWW-Authenticate: Digest realm=\"\", nonce=\"abc123\"\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = crate::sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("authentication error"));
    }

    #[test]
    fn test_handle_401_no_www_authenticate() {
        let mut manager = RegistrationManager::new(test_config());
        manager.create_register().unwrap();

        // Build a 401 without WWW-Authenticate
        let response_bytes = b"SIP/2.0 401 Unauthorized\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>;tag=totag\r\n\
Call-ID: test@192.168.1.100\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = crate::sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_407_proxy_auth() {
        let mut manager = RegistrationManager::new(test_config());
        manager.create_register().unwrap();

        // Build a 407 with Proxy-Authenticate
        let response_bytes = b"SIP/2.0 407 Proxy Authentication Required\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>;tag=totag\r\n\
Call-ID: test@192.168.1.100\r\n\
CSeq: 1 REGISTER\r\n\
Proxy-Authenticate: Digest realm=\"proxy\", nonce=\"xyz789\"\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = crate::sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);
        assert!(result.is_ok());
        let retry = result.unwrap();
        assert!(retry.is_some());

        let retry_request = retry.unwrap();
        let bytes = retry_request.to_bytes();
        let msg = String::from_utf8_lossy(&bytes);

        assert!(msg.contains("Proxy-Authorization"));
    }

    #[test]
    fn test_handle_407_invalid_challenge() {
        let mut manager = RegistrationManager::new(test_config());
        manager.create_register().unwrap();

        let response_bytes = b"SIP/2.0 407 Proxy Authentication Required\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>;tag=totag\r\n\
Call-ID: test@192.168.1.100\r\n\
CSeq: 1 REGISTER\r\n\
Proxy-Authenticate: Digest realm=\"proxy\"\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = crate::sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("authentication error"));
    }

    #[test]
    fn test_handle_407_empty_realm() {
        let mut manager = RegistrationManager::new(test_config());
        manager.create_register().unwrap();

        let response_bytes = b"SIP/2.0 407 Proxy Authentication Required\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>;tag=totag\r\n\
Call-ID: test@192.168.1.100\r\n\
CSeq: 1 REGISTER\r\n\
Proxy-Authenticate: Digest realm=\"\", nonce=\"xyz789\"\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = crate::sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("authentication error"));
    }

    #[test]
    fn test_handle_407_invalid_registrar() {
        let mut manager = RegistrationManager::new(invalid_config());
        manager.create_register().unwrap_err();

        let response_bytes = b"SIP/2.0 407 Proxy Authentication Required\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>;tag=totag\r\n\
Call-ID: test@192.168.1.100\r\n\
CSeq: 1 REGISTER\r\n\
Proxy-Authenticate: Digest realm=\"proxy\", nonce=\"xyz789\"\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = crate::sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);
        assert!(result.unwrap_err().to_string().contains("request error"));
    }

    #[test]
    fn test_handle_407_no_proxy_authenticate() {
        let mut manager = RegistrationManager::new(test_config());
        manager.create_register().unwrap();

        // Build a 407 without Proxy-Authenticate
        let response_bytes = b"SIP/2.0 407 Proxy Authentication Required\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>;tag=totag\r\n\
Call-ID: test@192.168.1.100\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = crate::sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_error_response() {
        let mut manager = RegistrationManager::new(test_config());
        manager.create_register().unwrap();

        // Build a 403 Forbidden response
        let response_bytes = b"SIP/2.0 403 Forbidden\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>;tag=totag\r\n\
Call-ID: test@192.168.1.100\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = crate::sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);
        assert!(result.is_err());
        assert_eq!(manager.state(), RegistrationState::Failed);
    }

    #[test]
    fn test_handle_provisional_response() {
        let mut manager = RegistrationManager::new(test_config());
        manager.create_register().unwrap();

        // Build a 100 Trying response
        let response_bytes = b"SIP/2.0 100 Trying\r\n\
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bKtest\r\n\
From: <sip:alice@example.com>;tag=fromtag\r\n\
To: <sip:alice@example.com>;tag=totag\r\n\
Call-ID: test@192.168.1.100\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\
\r\n";

        let msg = crate::sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Provisional is ignored
                                            // State should still be Registering
        assert_eq!(manager.state(), RegistrationState::Registering);
    }

    #[test]
    fn test_needs_refresh() {
        let mut manager = RegistrationManager::new(test_config());

        assert!(!manager.needs_refresh());

        manager.state = RegistrationState::Registered;
        // Set expires_at to now + 10 seconds (less than 20% of 3600)
        manager.expires_at = Some(Instant::now() + Duration::from_secs(10));

        assert!(manager.needs_refresh());
    }

    #[test]
    fn test_needs_refresh_far_future() {
        let mut manager = RegistrationManager::new(test_config());

        manager.state = RegistrationState::Registered;
        // Set expires_at to far future
        manager.expires_at = Some(Instant::now() + Duration::from_secs(7200));

        assert!(!manager.needs_refresh());
    }

    #[test]
    fn test_needs_refresh_underflows_to_true() {
        // Force the `checked_sub` underflow arm: with `expires_at == now`,
        // subtracting the 720s refresh window underflows the `Instant`
        // epoch on every host, regardless of uptime. The function must
        // return `true` (refresh now) without panicking.
        let mut manager = RegistrationManager::new(test_config());

        manager.state = RegistrationState::Registered;
        manager.expires_at = Some(Instant::now());

        assert!(manager.needs_refresh());
    }

    #[test]
    fn test_reset() {
        let mut manager = RegistrationManager::new(test_config());

        manager.state = RegistrationState::Registered;
        manager.expires_at = Some(Instant::now() + Duration::from_secs(3600));
        manager.nc = 5;
        manager.last_challenge =
            Some(DigestChallenge::parse("Digest realm=\"test\", nonce=\"123\"").unwrap());

        manager.reset();

        assert_eq!(manager.state(), RegistrationState::Unregistered);
        assert!(manager.expires_at.is_none());
        assert_eq!(manager.nc, 0);
        assert!(manager.last_challenge.is_none());
    }

    #[test]
    fn test_is_registered() {
        let mut manager = RegistrationManager::new(test_config());
        assert!(!manager.is_registered());

        manager.state = RegistrationState::Registered;
        assert!(manager.is_registered());

        manager.state = RegistrationState::Registering;
        assert!(!manager.is_registered());
    }
}
