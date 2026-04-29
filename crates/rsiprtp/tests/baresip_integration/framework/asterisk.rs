//! Asterisk PBX controller for integration testing.
//!
//! This module provides control over an Asterisk PBX instance for testing
//! SIP scenarios that require a registrar, call routing, transfers, and conferences.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

type Result<T> = std::result::Result<T, AsteriskError>;

#[derive(Debug)]
pub enum AsteriskError {
    IoError(std::io::Error),
    ProcessFailed(String),
    AmiError(String),
    Timeout(String),
    NotRunning,
}

impl std::fmt::Display for AsteriskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsteriskError::IoError(e) => write!(f, "IO error: {}", e),
            AsteriskError::ProcessFailed(msg) => write!(f, "Process failed: {}", msg),
            AsteriskError::AmiError(msg) => write!(f, "AMI error: {}", msg),
            AsteriskError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            AsteriskError::NotRunning => write!(f, "Asterisk not running"),
        }
    }
}

impl std::error::Error for AsteriskError {}

impl From<std::io::Error> for AsteriskError {
    fn from(e: std::io::Error) -> Self {
        AsteriskError::IoError(e)
    }
}

/// Asterisk channel state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    Down,
    Reserved,
    OffHook,
    Dialing,
    Ring,
    Ringing,
    Up,
    Busy,
    DialingOffHook,
    PreRing,
    Unknown,
}

/// Asterisk configuration
#[derive(Debug, Clone)]
pub struct AsteriskConfig {
    pub config_dir: PathBuf,
    pub ami_port: u16,
    pub ami_user: String,
    pub ami_secret: String,
    pub sip_port: u16,
    pub rtp_port_start: u16,
    pub rtp_port_end: u16,
}

impl AsteriskConfig {
    /// Create a new Asterisk configuration with test defaults
    pub fn new_test(config_dir: PathBuf, sip_port: u16, ami_port: u16) -> Self {
        Self {
            config_dir,
            ami_port,
            ami_user: "admin".to_string(),
            ami_secret: "secret".to_string(),
            sip_port,
            rtp_port_start: 10000,
            rtp_port_end: 10100,
        }
    }

    /// Generate pjsip.conf configuration file
    pub fn generate_pjsip_conf(&self) -> String {
        format!(
            r#"[transport-udp]
type=transport
protocol=udp
bind=0.0.0.0:{sip_port}

[test-endpoint](!)
type=endpoint
context=test
disallow=all
allow=ulaw
allow=alaw
direct_media=no
rtp_symmetric=yes

[test-auth](!)
type=auth
auth_type=userpass

[test-aor](!)
type=aor
max_contacts=5

; Test user 1001
[1001]
type=endpoint
aors=1001
auth=1001
context=test
disallow=all
allow=ulaw
allow=alaw

[1001]
type=auth
auth_type=userpass
username=1001
password=test1001

[1001]
type=aor
max_contacts=5

; Test user 1002
[1002]
type=endpoint
aors=1002
auth=1002
context=test
disallow=all
allow=ulaw
allow=alaw

[1002]
type=auth
auth_type=userpass
username=1002
password=test1002

[1002]
type=aor
max_contacts=5

; Test user 1003
[1003]
type=endpoint
aors=1003
auth=1003
context=test
disallow=all
allow=ulaw
allow=alaw

[1003]
type=auth
auth_type=userpass
username=1003
password=test1003

[1003]
type=aor
max_contacts=5
"#,
            sip_port = self.sip_port
        )
    }

    /// Generate extensions.conf dialplan
    pub fn generate_extensions_conf(&self) -> String {
        r#"[test]
; Basic call between extensions
exten => _100X,1,NoOp(Calling ${EXTEN})
same => n,Dial(PJSIP/${EXTEN},30)
same => n,Hangup()

; Conference room
exten => 2000,1,NoOp(Conference room)
same => n,ConfBridge(test_conf)
same => n,Hangup()

; Echo test
exten => 8888,1,NoOp(Echo test)
same => n,Answer()
same => n,Echo()
same => n,Hangup()

; Voicemail test
exten => 9999,1,NoOp(Voicemail test)
same => n,Answer()
same => n,Playback(vm-intro)
same => n,Hangup()
"#
        .to_string()
    }

    /// Generate manager.conf for AMI
    pub fn generate_manager_conf(&self) -> String {
        format!(
            r#"[general]
enabled = yes
port = {ami_port}
bindaddr = 0.0.0.0

[{ami_user}]
secret = {ami_secret}
deny=0.0.0.0/0.0.0.0
permit=127.0.0.1/255.255.255.0
read = all
write = all
"#,
            ami_port = self.ami_port,
            ami_user = self.ami_user,
            ami_secret = self.ami_secret
        )
    }

    /// Generate rtp.conf
    pub fn generate_rtp_conf(&self) -> String {
        format!(
            r#"[general]
rtpstart={rtp_start}
rtpend={rtp_end}
"#,
            rtp_start = self.rtp_port_start,
            rtp_end = self.rtp_port_end
        )
    }
}

/// Asterisk PBX instance controller
pub struct AsteriskInstance {
    process: Option<Child>,
    config: AsteriskConfig,
    ami_connection: Option<TcpStream>,
}

impl AsteriskInstance {
    /// Start a new Asterisk instance with the given configuration
    pub fn new(config: AsteriskConfig) -> Result<Self> {
        // Create config directory
        std::fs::create_dir_all(&config.config_dir)?;

        // Write configuration files
        let pjsip_path = config.config_dir.join("pjsip.conf");
        std::fs::write(&pjsip_path, config.generate_pjsip_conf())?;

        let extensions_path = config.config_dir.join("extensions.conf");
        std::fs::write(&extensions_path, config.generate_extensions_conf())?;

        let manager_path = config.config_dir.join("manager.conf");
        std::fs::write(&manager_path, config.generate_manager_conf())?;

        let rtp_path = config.config_dir.join("rtp.conf");
        std::fs::write(&rtp_path, config.generate_rtp_conf())?;

        // Start Asterisk process
        let process = Command::new("asterisk")
            .arg("-C")
            .arg(config.config_dir.join("asterisk.conf").to_str().unwrap())
            .arg("-c") // Console mode
            .arg("-vvv") // Verbose
            .arg("-n") // No fork
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let process = match process {
            Ok(p) => Some(p),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Asterisk not installed, return instance without process
                None
            }
            Err(e) => return Err(e.into()),
        };

        Ok(Self {
            process,
            config,
            ami_connection: None,
        })
    }

    /// Check if Asterisk is available on the system
    pub fn is_available() -> bool {
        Command::new("asterisk")
            .arg("-V")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }

    /// Connect to Asterisk Manager Interface (AMI)
    pub async fn connect_ami(&mut self) -> Result<()> {
        let addr: SocketAddr = format!("127.0.0.1:{}", self.config.ami_port)
            .parse()
            .map_err(|e| AsteriskError::AmiError(format!("Invalid AMI address: {}", e)))?;

        // Try to connect with retries
        let mut stream = None;
        for _ in 0..10 {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        let mut stream = stream.ok_or_else(|| {
            AsteriskError::Timeout(format!(
                "Could not connect to AMI on port {}",
                self.config.ami_port
            ))
        })?;

        // Read welcome banner
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        reader.read_line(&mut line)?;

        // Login to AMI
        let login_cmd = format!(
            "Action: Login\r\nUsername: {}\r\nSecret: {}\r\n\r\n",
            self.config.ami_user, self.config.ami_secret
        );
        stream.write_all(login_cmd.as_bytes())?;
        stream.flush()?;

        // Read login response
        let mut response = String::new();
        loop {
            line.clear();
            reader.read_line(&mut line)?;
            response.push_str(&line);
            if line == "\r\n" {
                break;
            }
        }

        if !response.contains("Success") {
            return Err(AsteriskError::AmiError("Login failed".to_string()));
        }

        self.ami_connection = Some(stream);
        Ok(())
    }

    /// Send AMI action and get response
    pub fn send_ami_action(
        &mut self,
        action: &str,
        params: HashMap<String, String>,
    ) -> Result<AmiResponse> {
        let stream = self
            .ami_connection
            .as_mut()
            .ok_or(AsteriskError::AmiError("Not connected to AMI".to_string()))?;

        // Build action
        let mut cmd = format!("Action: {}\r\n", action);
        for (key, value) in params {
            cmd.push_str(&format!("{}: {}\r\n", key, value));
        }
        cmd.push_str("\r\n");

        // Send command
        stream.write_all(cmd.as_bytes())?;
        stream.flush()?;

        // Read response
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut headers = HashMap::new();
        let mut line = String::new();

        loop {
            line.clear();
            reader.read_line(&mut line)?;
            if line == "\r\n" {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(
                    key.trim().to_string(),
                    value.trim().trim_end_matches("\r\n").to_string(),
                );
            }
        }

        Ok(AmiResponse { headers })
    }

    /// Originate a call via AMI
    pub fn originate(&mut self, channel: &str, extension: &str, context: &str) -> Result<String> {
        let mut params = HashMap::new();
        params.insert("Channel".to_string(), channel.to_string());
        params.insert("Exten".to_string(), extension.to_string());
        params.insert("Context".to_string(), context.to_string());
        params.insert("Priority".to_string(), "1".to_string());
        params.insert("Timeout".to_string(), "30000".to_string());

        let response = self.send_ami_action("Originate", params)?;
        if response.is_success() {
            Ok(response
                .get("ActionID")
                .unwrap_or_else(|| "unknown".to_string()))
        } else {
            Err(AsteriskError::AmiError(format!(
                "Originate failed: {}",
                response
                    .get("Message")
                    .unwrap_or_else(|| "Unknown error".to_string())
            )))
        }
    }

    /// Get channel status
    pub fn channel_status(&mut self, channel: &str) -> Result<ChannelState> {
        let mut params = HashMap::new();
        params.insert("Channel".to_string(), channel.to_string());

        let response = self.send_ami_action("Status", params)?;
        let state_num = response.get("State").and_then(|s| s.parse::<u8>().ok());

        Ok(match state_num {
            Some(0) => ChannelState::Down,
            Some(1) => ChannelState::Reserved,
            Some(2) => ChannelState::OffHook,
            Some(3) => ChannelState::Dialing,
            Some(4) => ChannelState::Ring,
            Some(5) => ChannelState::Ringing,
            Some(6) => ChannelState::Up,
            Some(7) => ChannelState::Busy,
            Some(8) => ChannelState::DialingOffHook,
            Some(9) => ChannelState::PreRing,
            _ => ChannelState::Unknown,
        })
    }

    /// Hangup a channel
    pub fn hangup(&mut self, channel: &str) -> Result<()> {
        let mut params = HashMap::new();
        params.insert("Channel".to_string(), channel.to_string());

        let response = self.send_ami_action("Hangup", params)?;
        if response.is_success() {
            Ok(())
        } else {
            Err(AsteriskError::AmiError("Hangup failed".to_string()))
        }
    }

    /// Get SIP port
    pub fn sip_port(&self) -> u16 {
        self.config.sip_port
    }

    /// Get AMI port
    pub fn ami_port(&self) -> u16 {
        self.config.ami_port
    }
}

impl Drop for AsteriskInstance {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }
}

/// AMI response
#[derive(Debug)]
pub struct AmiResponse {
    headers: HashMap<String, String>,
}

impl AmiResponse {
    /// Check if response indicates success
    pub fn is_success(&self) -> bool {
        self.headers
            .get("Response")
            .map(|r| r == "Success")
            .unwrap_or(false)
    }

    /// Get header value
    pub fn get(&self, key: &str) -> Option<String> {
        self.headers.get(key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asterisk_config_generation() {
        let config = AsteriskConfig::new_test(PathBuf::from("/tmp/ast"), 5060, 5038);

        let pjsip = config.generate_pjsip_conf();
        assert!(pjsip.contains("bind=0.0.0.0:5060"));
        assert!(pjsip.contains("[1001]"));
        assert!(pjsip.contains("[1002]"));

        let extensions = config.generate_extensions_conf();
        assert!(extensions.contains("[test]"));
        assert!(extensions.contains("_100X"));

        let manager = config.generate_manager_conf();
        assert!(manager.contains("port = 5038"));
        assert!(manager.contains("[admin]"));
    }

    #[test]
    fn test_channel_state() {
        assert_eq!(ChannelState::Down, ChannelState::Down);
        assert_ne!(ChannelState::Up, ChannelState::Down);
    }

    #[test]
    fn test_asterisk_available() {
        // Just check this doesn't panic
        let _available = AsteriskInstance::is_available();
    }
}
