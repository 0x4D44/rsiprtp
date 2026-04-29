//! Baresip process controller for integration tests.
//!
//! This module provides functionality to spawn and control baresip as a subprocess
//! for integration testing against our SIP stack.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

use super::config::BaresipConfig;

/// Error type for baresip operations.
#[derive(Debug)]
pub enum BaresipError {
    /// Failed to spawn baresip process.
    SpawnFailed(std::io::Error),
    /// Failed to create config directory.
    ConfigError(std::io::Error),
    /// Failed to connect to control socket.
    ConnectionFailed(std::io::Error),
    /// Command failed.
    CommandFailed(String),
    /// Timeout waiting for event.
    Timeout(String),
    /// Process not running.
    NotRunning,
}

impl std::fmt::Display for BaresipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BaresipError::SpawnFailed(e) => write!(f, "Failed to spawn baresip: {}", e),
            BaresipError::ConfigError(e) => write!(f, "Failed to create config: {}", e),
            BaresipError::ConnectionFailed(e) => write!(f, "Failed to connect: {}", e),
            BaresipError::CommandFailed(msg) => write!(f, "Command failed: {}", msg),
            BaresipError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            BaresipError::NotRunning => write!(f, "Baresip is not running"),
        }
    }
}

impl std::error::Error for BaresipError {}

/// Result type for baresip operations.
pub type Result<T> = std::result::Result<T, BaresipError>;

/// Call state reported by baresip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaresipCallState {
    /// No active call.
    Idle,
    /// Outgoing call in progress.
    Calling,
    /// Incoming call ringing.
    Incoming,
    /// Call is ringing at remote end.
    Ringing,
    /// Call is established.
    Established,
    /// Call on hold.
    OnHold,
    /// Call terminated.
    Terminated,
}

/// A running baresip instance.
pub struct BaresipInstance {
    /// The child process.
    process: Child,
    /// The configuration used.
    config: BaresipConfig,
    /// Temporary directory for config files.
    _config_dir: TempDir,
    /// Receiver for stdout/stderr output.
    output_rx: Receiver<String>,
    /// Collected output lines.
    output_lines: Arc<Mutex<Vec<String>>>,
    /// Control port.
    ctrl_port: u16,
}

impl BaresipInstance {
    /// Spawn a new baresip instance with the given configuration.
    pub fn spawn(config: BaresipConfig) -> Result<Self> {
        // Create temp directory for config
        let config_dir = TempDir::new().map_err(BaresipError::ConfigError)?;
        let config_path = config_dir.path();

        // Write config file
        let config_file = config_path.join("config");
        std::fs::write(&config_file, config.to_config_content())
            .map_err(BaresipError::ConfigError)?;

        // Write accounts file
        let accounts_file = config_path.join("accounts");
        std::fs::write(&accounts_file, config.to_accounts_content("test"))
            .map_err(BaresipError::ConfigError)?;

        // Create empty contacts file
        let contacts_file = config_path.join("contacts");
        std::fs::write(&contacts_file, "").map_err(BaresipError::ConfigError)?;

        let ctrl_port = config.ctrl_port;

        // Spawn baresip process
        let mut process = Command::new("baresip")
            .arg("-f")
            .arg(config_path)
            .arg("-v") // Verbose output for debugging
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(BaresipError::SpawnFailed)?;

        // Set up output capture
        let (output_tx, output_rx) = mpsc::channel();
        let output_lines = Arc::new(Mutex::new(Vec::new()));

        // Capture stdout
        #[allow(clippy::lines_filter_map_ok)]
        if let Some(stdout) = process.stdout.take() {
            let tx = output_tx.clone();
            let lines = Arc::clone(&output_lines);
            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines().flatten() {
                    let _ = tx.send(line.clone());
                    lines.lock().unwrap().push(line);
                }
            });
        }

        // Capture stderr
        #[allow(clippy::lines_filter_map_ok)]
        if let Some(stderr) = process.stderr.take() {
            let tx = output_tx;
            let lines = Arc::clone(&output_lines);
            thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines().flatten() {
                    let _ = tx.send(line.clone());
                    lines.lock().unwrap().push(line);
                }
            });
        }

        let instance = Self {
            process,
            config,
            _config_dir: config_dir,
            output_rx,
            output_lines,
            ctrl_port,
        };

        // Wait for baresip to be ready
        instance.wait_for_ready(Duration::from_secs(10))?;

        Ok(instance)
    }

    /// Wait for baresip to be ready (control socket accepting connections).
    fn wait_for_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        let addr = format!("127.0.0.1:{}", self.ctrl_port);

        while std::time::Instant::now() < deadline {
            // Try to connect to control socket
            if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(100))
                .is_ok()
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }

        Err(BaresipError::Timeout("Baresip failed to start".to_string()))
    }

    /// Send a command via the control socket.
    pub fn command(&self, cmd: &str) -> Result<String> {
        let addr = format!("127.0.0.1:{}", self.ctrl_port);
        let mut stream = TcpStream::connect(&addr).map_err(BaresipError::ConnectionFailed)?;

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(BaresipError::ConnectionFailed)?;

        // Send command
        writeln!(stream, "{}", cmd).map_err(BaresipError::ConnectionFailed)?;

        // Read response
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        let _ = reader.read_line(&mut response);

        Ok(response.trim().to_string())
    }

    /// Dial a SIP URI.
    pub fn dial(&self, uri: &str) -> Result<String> {
        self.command(&format!("/dial {}", uri))
    }

    /// Accept incoming call.
    pub fn accept(&self) -> Result<String> {
        self.command("/accept")
    }

    /// Reject incoming call.
    pub fn reject(&self) -> Result<String> {
        // Baresip uses /hangup for rejecting incoming calls too
        self.command("/hangup")
    }

    /// Hang up current call.
    pub fn hangup(&self) -> Result<String> {
        self.command("/hangup")
    }

    /// Put current call on hold.
    pub fn hold(&self) -> Result<String> {
        self.command("/hold")
    }

    /// Resume held call.
    pub fn resume(&self) -> Result<String> {
        self.command("/resume")
    }

    /// Transfer call to another URI.
    pub fn transfer(&self, target: &str) -> Result<String> {
        self.command(&format!("/transfer {}", target))
    }

    /// Send DTMF digit.
    pub fn send_dtmf(&self, digit: char) -> Result<String> {
        self.command(&format!("/sndcode {}", digit))
    }

    /// Wait for a specific pattern in the output.
    pub fn wait_for_event(&self, pattern: &str, timeout: Duration) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        let pattern_lower = pattern.to_lowercase();

        // Check existing output first
        {
            let lines = self.output_lines.lock().unwrap();
            for line in lines.iter() {
                if line.to_lowercase().contains(&pattern_lower) {
                    return Ok(());
                }
            }
        }

        // Wait for new output
        while std::time::Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            match self.output_rx.recv_timeout(remaining) {
                Ok(line) => {
                    if line.to_lowercase().contains(&pattern_lower) {
                        return Ok(());
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        Err(BaresipError::Timeout(format!(
            "Event '{}' not found",
            pattern
        )))
    }

    /// Get all captured output lines.
    pub fn output(&self) -> Vec<String> {
        self.output_lines.lock().unwrap().clone()
    }

    /// Check if baresip process is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.process.try_wait(), Ok(None))
    }

    /// Get the SIP port.
    pub fn sip_port(&self) -> u16 {
        self.config.sip_port
    }

    /// Get the RTP port.
    pub fn rtp_port(&self) -> u16 {
        self.config.rtp_port
    }

    /// Get the control port.
    pub fn ctrl_port(&self) -> u16 {
        self.ctrl_port
    }

    /// Gracefully shutdown baresip.
    pub fn shutdown(mut self) -> Result<()> {
        // Try to quit gracefully
        let _ = self.command("/quit");

        // Wait a bit for graceful shutdown
        thread::sleep(Duration::from_millis(500));

        // Force kill if still running
        if self.is_running() {
            let _ = self.process.kill();
        }

        // Wait for process to exit
        let _ = self.process.wait();

        Ok(())
    }
}

impl Drop for BaresipInstance {
    fn drop(&mut self) {
        // Kill the process if still running
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Helper struct for spawning multiple baresip instances.
pub struct BaresipPool {
    instances: Vec<BaresipInstance>,
}

impl BaresipPool {
    /// Create a new empty pool.
    pub fn new() -> Self {
        Self {
            instances: Vec::new(),
        }
    }

    /// Spawn a new instance and add it to the pool.
    pub fn spawn(&mut self, config: BaresipConfig) -> Result<usize> {
        let instance = BaresipInstance::spawn(config)?;
        let idx = self.instances.len();
        self.instances.push(instance);
        Ok(idx)
    }

    /// Get an instance by index.
    pub fn get(&self, idx: usize) -> Option<&BaresipInstance> {
        self.instances.get(idx)
    }

    /// Get a mutable instance by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut BaresipInstance> {
        self.instances.get_mut(idx)
    }

    /// Shutdown all instances.
    pub fn shutdown_all(self) {
        for instance in self.instances {
            let _ = instance.shutdown();
        }
    }
}

impl Default for BaresipPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baresip_error_display() {
        let err = BaresipError::NotRunning;
        assert!(err.to_string().contains("not running"));

        let err = BaresipError::Timeout("test".to_string());
        assert!(err.to_string().contains("Timeout"));
    }

    #[test]
    fn test_baresip_call_state() {
        assert_eq!(BaresipCallState::Idle, BaresipCallState::Idle);
        assert_ne!(BaresipCallState::Idle, BaresipCallState::Established);

        let state = BaresipCallState::Established;
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }

    #[test]
    fn test_baresip_pool() {
        let pool = BaresipPool::new();
        assert!(pool.instances.is_empty());
    }
}
