//! Test configuration for integration tests.

use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::Duration;

/// Test configuration for a single integration test.
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Local SIP port for rsiprtp endpoint.
    pub local_sip_port: u16,
    /// Local RTP port for rsiprtp endpoint.
    pub local_rtp_port: u16,
    /// Baresip SIP port.
    pub baresip_sip_port: u16,
    /// Baresip RTP port.
    pub baresip_rtp_port: u16,
    /// Baresip control port (for TCP control socket).
    pub baresip_ctrl_port: u16,
    /// Test domain for SIP URIs.
    pub test_domain: String,
    /// Default timeout for test operations.
    pub timeout: Duration,
    /// Path to test fixtures.
    pub fixtures_path: PathBuf,
}

impl TestConfig {
    /// Create a new test configuration with automatically allocated ports.
    pub fn with_available_ports() -> Self {
        let local_sip_port = find_available_port();
        let local_rtp_port = find_available_even_port();
        let baresip_sip_port = find_available_port();
        let baresip_rtp_port = find_available_even_port();
        let baresip_ctrl_port = find_available_port();

        Self {
            local_sip_port,
            local_rtp_port,
            baresip_sip_port,
            baresip_rtp_port,
            baresip_ctrl_port,
            test_domain: "127.0.0.1".to_string(),
            timeout: Duration::from_secs(10),
            fixtures_path: fixtures_path(),
        }
    }

    /// Get local SIP address as string.
    pub fn local_sip_addr(&self) -> String {
        format!("127.0.0.1:{}", self.local_sip_port)
    }

    /// Get local SIP socket address.
    pub fn local_sip_socket_addr(&self) -> SocketAddr {
        format!("127.0.0.1:{}", self.local_sip_port)
            .parse()
            .expect("valid socket addr")
    }

    /// Get local RTP address.
    pub fn local_rtp_addr(&self) -> String {
        format!("127.0.0.1:{}", self.local_rtp_port)
    }

    /// Get baresip SIP address.
    pub fn baresip_sip_addr(&self) -> String {
        format!("127.0.0.1:{}", self.baresip_sip_port)
    }

    /// Get baresip control address.
    pub fn baresip_ctrl_addr(&self) -> String {
        format!("127.0.0.1:{}", self.baresip_ctrl_port)
    }

    /// Generate a SIP URI for the local endpoint.
    pub fn local_uri(&self, user: &str) -> String {
        format!("sip:{}@127.0.0.1:{}", user, self.local_sip_port)
    }

    /// Generate a SIP URI for baresip.
    pub fn baresip_uri(&self, user: &str) -> String {
        format!("sip:{}@127.0.0.1:{}", user, self.baresip_sip_port)
    }

    /// Create a BaresipConfig from this TestConfig.
    pub fn baresip_config(&self) -> BaresipConfig {
        BaresipConfig {
            sip_port: self.baresip_sip_port,
            rtp_port: self.baresip_rtp_port,
            ctrl_port: self.baresip_ctrl_port,
            audio_player: "null".to_string(),
            audio_source: "tone".to_string(),
            supported_codecs: vec!["PCMU".to_string(), "PCMA".to_string()],
        }
    }
}

impl Default for TestConfig {
    fn default() -> Self {
        Self::with_available_ports()
    }
}

/// Baresip-specific configuration.
#[derive(Debug, Clone)]
pub struct BaresipConfig {
    /// SIP listening port.
    pub sip_port: u16,
    /// RTP port.
    pub rtp_port: u16,
    /// Control socket port.
    pub ctrl_port: u16,
    /// Audio player device ("null" for testing).
    pub audio_player: String,
    /// Audio source device ("tone" or "aufile,path").
    pub audio_source: String,
    /// Supported codecs.
    pub supported_codecs: Vec<String>,
}

impl BaresipConfig {
    /// Generate the baresip config file content.
    pub fn to_config_content(&self) -> String {
        format!(
            r#"# Baresip test configuration - auto-generated
poll_method        epoll
sip_listen         127.0.0.1:{}
audio_player       {}
audio_source       {}
audio_alert        null
ausrc_srate        8000
auplay_srate       8000
ausrc_channels     1
auplay_channels    1

# RTP configuration
rtp_ports          {}-{}

# Modules to load
module_path        /usr/lib/baresip/modules

# Core modules
module             stdio.so
module             cons.so

# Audio codecs
module             g711.so

# Control socket for automation
module             ctrl_tcp.so
ctrl_tcp_listen    127.0.0.1:{}
"#,
            self.sip_port,
            self.audio_player,
            self.audio_source,
            self.rtp_port,
            self.rtp_port + 100,
            self.ctrl_port
        )
    }

    /// Generate the baresip accounts file content.
    pub fn to_accounts_content(&self, user: &str) -> String {
        format!("<sip:{}@127.0.0.1:{}>;regint=0\n", user, self.sip_port)
    }
}

/// Find an available UDP port.
fn find_available_port() -> u16 {
    // Bind to port 0 to get an available UDP port from the OS.
    let socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP socket");
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    port
}

/// Find an available even port (for RTP).
fn find_available_even_port() -> u16 {
    loop {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind UDP socket");
        let port = socket.local_addr().unwrap().port();
        drop(socket);

        // RTP uses even ports
        if port.is_multiple_of(2) {
            return port;
        }
    }
}

/// Get the path to the fixtures directory.
fn fixtures_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("tests")
        .join("integration")
        .join("fixtures")
}

/// Check if baresip is installed on the system.
pub fn is_baresip_available() -> bool {
    std::process::Command::new("which")
        .arg("baresip")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Skip test if baresip is not available.
#[macro_export]
macro_rules! skip_if_no_baresip {
    () => {
        if !$crate::framework::config::is_baresip_available() {
            eprintln!("Skipping test: baresip not installed");
            return;
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_with_available_ports() {
        let config = TestConfig::with_available_ports();

        // All ports should be different
        assert_ne!(config.local_sip_port, config.baresip_sip_port);
        assert_ne!(config.local_rtp_port, config.baresip_rtp_port);
        assert_ne!(config.baresip_ctrl_port, config.baresip_sip_port);

        // RTP ports should be even
        assert_eq!(config.local_rtp_port % 2, 0);
        assert_eq!(config.baresip_rtp_port % 2, 0);
    }

    #[test]
    fn test_config_addresses() {
        let config = TestConfig::with_available_ports();

        assert!(config.local_sip_addr().starts_with("127.0.0.1:"));
        assert!(config.baresip_sip_addr().starts_with("127.0.0.1:"));
    }

    #[test]
    fn test_config_uris() {
        let config = TestConfig::with_available_ports();

        let uri = config.local_uri("alice");
        assert!(uri.starts_with("sip:alice@"));

        let uri = config.baresip_uri("bob");
        assert!(uri.starts_with("sip:bob@"));
    }

    #[test]
    fn test_baresip_config_generation() {
        let config = BaresipConfig {
            sip_port: 5060,
            rtp_port: 10000,
            ctrl_port: 5555,
            audio_player: "null".to_string(),
            audio_source: "tone".to_string(),
            supported_codecs: vec!["PCMU".to_string()],
        };

        let content = config.to_config_content();
        assert!(content.contains("sip_listen         127.0.0.1:5060"));
        assert!(content.contains("ctrl_tcp_listen    127.0.0.1:5555"));
        assert!(content.contains("audio_player       null"));
    }

    #[test]
    fn test_baresip_accounts_generation() {
        let config = BaresipConfig {
            sip_port: 5060,
            rtp_port: 10000,
            ctrl_port: 5555,
            audio_player: "null".to_string(),
            audio_source: "tone".to_string(),
            supported_codecs: vec!["PCMU".to_string()],
        };

        let content = config.to_accounts_content("testuser");
        assert!(content.contains("sip:testuser@127.0.0.1:5060"));
        assert!(content.contains("regint=0"));
    }
}
