//! SIP registration management.
//!
//! Handles REGISTER requests with digest authentication support
//! and periodic re-registration.

use mdsiprtp_sip::{
    DigestChallenge, DigestCredentials, DigestResponse,
    Method, SipRequest, SipResponse,
    generate_branch, generate_call_id, generate_tag,
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
            // Refresh when 80% of the time has elapsed
            let refresh_at = expires_at - Duration::from_secs((self.config.expires as u64) / 5);
            Instant::now() >= refresh_at
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
            .via(&self.config.local_addr, self.config.local_port, &self.config.transport, &branch)
            .from(&self.config.aor, &self.from_tag)
            .to(&self.config.aor)
            .call_id(&self.call_id)
            .cseq(self.cseq)
            .contact(&self.config.contact)
            .expires(self.config.expires);

        builder.build().map_err(|e| RegistrationError::RequestError(e.to_string()))
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
        ).map_err(|e| RegistrationError::AuthError(e.to_string()))?;

        let auth_value = response.to_header_value();

        let builder = SipRequest::builder()
            .method(Method::Register)
            .uri(&self.config.registrar)
            .via(&self.config.local_addr, self.config.local_port, &self.config.transport, &branch)
            .from(&self.config.aor, &self.from_tag)
            .to(&self.config.aor)
            .call_id(&self.call_id)
            .cseq(self.cseq)
            .contact(&self.config.contact)
            .expires(self.config.expires)
            .authorization(&auth_value);

        builder.build().map_err(|e| RegistrationError::RequestError(e.to_string()))
    }

    /// Create an unREGISTER request (expires=0).
    pub fn create_unregister(&mut self) -> Result<SipRequest, RegistrationError> {
        self.state = RegistrationState::Unregistering;
        self.cseq += 1;
        let branch = generate_branch();

        let builder = SipRequest::builder()
            .method(Method::Register)
            .uri(&self.config.registrar)
            .via(&self.config.local_addr, self.config.local_port, &self.config.transport, &branch)
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
            ).map_err(|e| RegistrationError::AuthError(e.to_string()))?;

            return SipRequest::builder()
                .method(Method::Register)
                .uri(&self.config.registrar)
                .via(&self.config.local_addr, self.config.local_port, &self.config.transport, &branch)
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

        builder.build().map_err(|e| RegistrationError::RequestError(e.to_string()))
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
                    self.expires_at = Some(Instant::now() + Duration::from_secs(self.config.expires as u64));
                }
                Ok(None)
            }
            401 => {
                // Unauthorized - need to retry with auth
                let www_auth = response
                    .www_authenticate()
                    .ok_or_else(|| RegistrationError::AuthError("401 without WWW-Authenticate".to_string()))?;

                let challenge = DigestChallenge::parse(&www_auth)
                    .map_err(|e| RegistrationError::AuthError(e.to_string()))?;

                self.last_challenge = Some(challenge.clone());

                let request = self.create_register_with_auth(&challenge)?;
                Ok(Some(request))
            }
            407 => {
                // Proxy authentication required
                let proxy_auth = response
                    .proxy_authenticate()
                    .ok_or_else(|| RegistrationError::AuthError("407 without Proxy-Authenticate".to_string()))?;

                let challenge = DigestChallenge::parse(&proxy_auth)
                    .map_err(|e| RegistrationError::AuthError(e.to_string()))?;

                self.last_challenge = Some(challenge.clone());

                // Create request with Proxy-Authorization
                self.cseq += 1;
                self.nc += 1;
                let branch = generate_branch();

                let credentials = DigestCredentials::new(&self.config.username, &self.config.password);

                let response = DigestResponse::from_challenge(
                    &challenge,
                    &credentials,
                    "REGISTER",
                    &self.config.registrar,
                    None,
                ).map_err(|e| RegistrationError::AuthError(e.to_string()))?;

                let request = SipRequest::builder()
                    .method(Method::Register)
                    .uri(&self.config.registrar)
                    .via(&self.config.local_addr, self.config.local_port, &self.config.transport, &branch)
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

        let msg = mdsiprtp_sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);

        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // No retry needed
        assert_eq!(manager.state(), RegistrationState::Registered);
        assert!(manager.is_registered());
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

        let msg = mdsiprtp_sip::SipMessage::parse(response_bytes).unwrap();
        let response = msg.as_response().unwrap();

        let result = manager.handle_response(response);
        assert!(result.is_ok(), "handle_response failed: {:?}", result.err());
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
    fn test_needs_refresh() {
        let mut manager = RegistrationManager::new(test_config());

        assert!(!manager.needs_refresh());

        manager.state = RegistrationState::Registered;
        // Set expires_at to now + 10 seconds (less than 20% of 3600)
        manager.expires_at = Some(Instant::now() + Duration::from_secs(10));

        assert!(manager.needs_refresh());
    }

    #[test]
    fn test_reset() {
        let mut manager = RegistrationManager::new(test_config());

        manager.state = RegistrationState::Registered;
        manager.expires_at = Some(Instant::now() + Duration::from_secs(3600));
        manager.nc = 5;

        manager.reset();

        assert_eq!(manager.state(), RegistrationState::Unregistered);
        assert!(manager.expires_at.is_none());
        assert_eq!(manager.nc, 0);
    }
}
