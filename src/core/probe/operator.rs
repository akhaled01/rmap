use regex::Regex;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::parser::{MatchEntry, NmapProbes, ProbeEntry};
use std::fs;

/// Service detection result
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub service: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
    pub hostname: Option<String>,
    pub os_info: Option<String>,
    pub device_type: Option<String>,
    pub cpe: Option<String>,
    pub confidence: u8,
}

/// Port scan result with service detection
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub host: IpAddr,
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<ServiceInfo>,
    pub banner: Option<String>,
}

/// The prober utility is used to perform banner grabbing and detailed service detection
/// for a list of ports on a specified host
pub struct Prober {
    probes: Option<NmapProbes>,
    timeout_ms: u64,
}

impl Prober {
    pub fn new() -> Prober {
        Prober {
            probes: None,
            timeout_ms: 5000,
        }
    }

    /// Load nmap probes from JSON file
    pub fn load_probes(&mut self, path: &str) -> Result<(), Box<dyn Error>> {
        let content = fs::read_to_string(path)?;
        self.probes = Some(serde_json::from_str(&content)?);
        Ok(())
    }

    /// Set connection timeout in milliseconds
    pub fn set_timeout(&mut self, timeout_ms: u64) {
        self.timeout_ms = timeout_ms;
    }

    /// Perform service detection on a single port
    pub async fn probe_port(&self, host: IpAddr, port: u16) -> Result<ProbeResult, Box<dyn Error>> {
        let mut result = ProbeResult {
            host,
            port,
            protocol: "tcp".to_string(),
            state: "unknown".to_string(),
            service: None,
            banner: None,
        };

        // Try to connect to the port
        let socket_addr = SocketAddr::new(host, port);
        let mut stream = match timeout(
            Duration::from_millis(self.timeout_ms),
            TcpStream::connect(socket_addr),
        )
        .await
        {
            Ok(Ok(stream)) => {
                result.state = "open".to_string();
                stream
            }
            Ok(Err(_)) => {
                result.state = "closed".to_string();
                return Ok(result);
            }
            Err(_) => {
                result.state = "filtered".to_string();
                return Ok(result);
            }
        };

        // Perform service detection if probes are loaded
        if let Some(ref probes) = self.probes {
            result.service = self.detect_service(&mut stream, port, probes).await;
        } else {
            // Fallback to simple banner grabbing
            result.banner = self.grab_banner(&mut stream).await;
        }

        Ok(result)
    }

    /// Perform service detection on multiple ports
    pub async fn probe_ports(
        &self,
        host: IpAddr,
        ports: &[u16],
    ) -> Result<Vec<ProbeResult>, Box<dyn Error>> {
        let mut results = Vec::new();

        for &port in ports {
            match self.probe_port(host, port).await {
                Ok(result) => results.push(result),
                Err(e) => eprintln!("Error probing {}:{} - {}", host, port, e),
            }
        }

        Ok(results)
    }

    /// Main execution function
    pub async fn exec(&self) -> Result<(), Box<dyn Error>> {
        println!("Service detection probe ready");
        if self.probes.is_some() {
            println!("Nmap probes loaded successfully");
        } else {
            println!("No probes loaded - using basic banner grabbing");
        }
        Ok(())
    }

    /// Detect service using nmap probes
    async fn detect_service(
        &self,
        stream: &mut TcpStream,
        port: u16,
        probes: &NmapProbes,
    ) -> Option<ServiceInfo> {
        // First try NULL probe (banner grabbing)
        if let Some(null_probe) = probes
            .probes
            .iter()
            .find(|p| p.name == "NULL" && p.protocol == "TCP")
        {
            if let Some(service_info) = self.try_probe(stream, null_probe, port).await {
                return Some(service_info);
            }
        }

        // Try other probes based on port
        let relevant_probes = self.get_relevant_probes(probes, port);
        for probe in relevant_probes {
            if let Some(service_info) = self.try_probe(stream, probe, port).await {
                return Some(service_info);
            }
        }

        None
    }

    /// Try a specific probe against the service
    async fn try_probe(
        &self,
        stream: &mut TcpStream,
        probe: &ProbeEntry,
        _port: u16,
    ) -> Option<ServiceInfo> {
        // Send probe string if not empty
        if !probe.probe_string.is_empty() {
            let probe_data = self.decode_probe_string(&probe.probe_string);
            if let Err(_) = timeout(
                Duration::from_millis(self.timeout_ms),
                stream.write_all(&probe_data),
            )
            .await
            {
                return None;
            }
        }

        // Read response
        let mut buffer = vec![0; 4096];
        let response = match timeout(
            Duration::from_millis(self.timeout_ms),
            stream.read(&mut buffer),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => {
                buffer.truncate(n);
                String::from_utf8_lossy(&buffer).to_string()
            }
            _ => return None,
        };

        // Try to match response against probe patterns
        for match_entry in &probe.matches {
            if let Some(service_info) = self.match_response(&response, match_entry) {
                return Some(service_info);
            }
        }

        // Try soft matches
        for match_entry in &probe.soft_matches {
            if let Some(mut service_info) = self.match_response(&response, match_entry) {
                service_info.confidence = 50; // Lower confidence for soft matches
                return Some(service_info);
            }
        }

        None
    }

    /// Match response against a pattern
    fn match_response(&self, response: &str, match_entry: &MatchEntry) -> Option<ServiceInfo> {
        // Create regex from pattern (simplified - real implementation would handle all nmap regex features)
        let pattern = &match_entry.pattern;
        if let Ok(regex) = Regex::new(pattern) {
            if let Some(captures) = regex.captures(response) {
                let mut service_info = ServiceInfo {
                    service: match_entry.service.clone(),
                    version: None,
                    product: None,
                    extra_info: None,
                    hostname: None,
                    os_info: None,
                    device_type: None,
                    cpe: None,
                    confidence: 90,
                };

                // Extract version information
                for (key, value) in &match_entry.version_info {
                    let processed_value = self.process_version_field(value, &captures);
                    match key.as_str() {
                        "p" => service_info.product = Some(processed_value),
                        "v" => service_info.version = Some(processed_value),
                        "i" => service_info.extra_info = Some(processed_value),
                        "h" => service_info.hostname = Some(processed_value),
                        "o" => service_info.os_info = Some(processed_value),
                        "d" => service_info.device_type = Some(processed_value),
                        "cpe" => service_info.cpe = Some(processed_value),
                        _ => {}
                    }
                }

                return Some(service_info);
            }
        }
        None
    }

    /// Process version field with capture group substitution
    fn process_version_field(&self, value: &str, captures: &regex::Captures) -> String {
        let mut result = value.to_string();

        // Replace $1, $2, etc. with capture groups
        for i in 1..captures.len() {
            if let Some(capture) = captures.get(i) {
                result = result.replace(&format!("${}", i), capture.as_str());
            }
        }

        result
    }

    /// Get probes relevant to a specific port
    fn get_relevant_probes<'a>(&self, probes: &'a NmapProbes, port: u16) -> Vec<&'a ProbeEntry> {
        let mut relevant = Vec::new();

        for probe in &probes.probes {
            if probe.protocol != "TCP" {
                continue;
            }

            // Check if port is in the probe's port list
            let port_str = port.to_string();
            for port_spec in &probe.ports {
                if port_spec.contains(&port_str) || port_spec.contains(&format!("T:{}", port)) {
                    relevant.push(probe);
                    break;
                }
            }
        }

        // If no specific probes found, add some common ones
        if relevant.is_empty() {
            for probe in &probes.probes {
                if probe.protocol == "TCP"
                    && matches!(probe.name.as_str(), "GetRequest" | "GenericLines")
                {
                    relevant.push(probe);
                }
            }
        }

        relevant
    }

    /// Decode probe string (handle escape sequences)
    fn decode_probe_string(&self, probe_string: &str) -> Vec<u8> {
        let mut result = Vec::new();
        let mut chars = probe_string.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '\\' {
                if let Some(&next_ch) = chars.peek() {
                    match next_ch {
                        'n' => {
                            result.push(b'\n');
                            chars.next();
                        }
                        'r' => {
                            result.push(b'\r');
                            chars.next();
                        }
                        't' => {
                            result.push(b'\t');
                            chars.next();
                        }
                        '0' => {
                            result.push(0);
                            chars.next();
                        }
                        '\\' => {
                            result.push(b'\\');
                            chars.next();
                        }
                        'x' => {
                            chars.next(); // consume 'x'
                            let hex1 = chars.next().unwrap_or('0');
                            let hex2 = chars.next().unwrap_or('0');
                            if let Ok(byte) = u8::from_str_radix(&format!("{}{}", hex1, hex2), 16) {
                                result.push(byte);
                            }
                        }
                        _ => result.push(ch as u8),
                    }
                } else {
                    result.push(ch as u8);
                }
            } else {
                result.push(ch as u8);
            }
        }

        result
    }

    /// Simple banner grabbing fallback
    async fn grab_banner(&self, stream: &mut TcpStream) -> Option<String> {
        let mut buffer = vec![0; 1024];

        match timeout(
            Duration::from_millis(self.timeout_ms),
            stream.read(&mut buffer),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => {
                buffer.truncate(n);
                Some(String::from_utf8_lossy(&buffer).trim().to_string())
            }
            _ => None,
        }
    }
}
