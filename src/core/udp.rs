use crate::args::{Config, get_config};
use crate::core::PortState;
use crate::output::OutputHandler;
use crate::utils::valid_ip;
use crate::dns::DNSResolver;
use std::collections::HashMap;
use std::error::Error;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use indicatif::{ProgressBar, ProgressStyle};

pub struct UDPScanner {
    pub config: Config,
    pub dns: DNSResolver,
}

#[derive(Debug, Clone)]
pub enum UdpPortState {
    Open,
    Closed,
}

pub type UDPScanResult = HashMap<u16, UdpPortState>;

impl UDPScanner {
    pub fn new() -> UDPScanner {
        let config = get_config();
        UDPScanner { config, dns: DNSResolver::new() }
    }

    // Parse port ranges and individual ports (similar to TCP scanner)
    fn parse_ports(ports_str: &str) -> Vec<u16> {
        let mut ports = Vec::new();

        for part in ports_str.split(',') {
            let part = part.trim();
            if part.contains('-') {
                // Handle port range
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() == 2 {
                    if let (Ok(start), Ok(end)) =
                        (range_parts[0].parse::<u16>(), range_parts[1].parse::<u16>())
                    {
                        for port in start..=end {
                            ports.push(port);
                        }
                    }
                }
            } else {
                // Handle individual port
                if let Ok(port) = part.parse::<u16>() {
                    ports.push(port);
                }
            }
        }

        ports
    }

    pub async fn fire_and_forget(&self, target: IpAddr, ports: Vec<u16>) -> Result<UDPScanResult, Box<dyn Error>> {
        let mut results = UDPScanResult::new();
        
        // Print scan message
        println!("\x1b[36mrunning UDP scan\x1b[0m");
        
        // Create progress bar
        let pb = ProgressBar::new(ports.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{percent:>3}%|{bar:25.cyan/blue}| {pos}/{len} [{elapsed_precise}<{eta_precise}, {per_sec}]")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏ "),
        );
        
        for port in ports {
            let port_state = self.scan_udp_port(target, port).await;
            results.insert(port, port_state);
            pb.inc(1);
        }
        
        pb.finish_and_clear();
        
        Ok(results)
    }

    async fn scan_udp_port(&self, target: IpAddr, port: u16) -> UdpPortState {
        let timeout_duration = Duration::from_millis(self.config.timeout);
        
        // Create a UDP socket
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(_) => return UdpPortState::Closed,
        };

        let target_addr = format!("{}:{}", target, port);
        
        // Connect to target (this is just for convenience, doesn't actually connect)
        if socket.connect(&target_addr).await.is_err() {
            return UdpPortState::Closed;
        }

        // Send a UDP probe packet
        let probe_data = self.get_probe_data_for_port(port);
        if socket.send(&probe_data).await.is_err() {
            return UdpPortState::Closed;
        }

        // Try to receive a response with timeout
        let mut buffer = [0u8; 1024];
        match timeout(timeout_duration, socket.recv(&mut buffer)).await {
            Ok(Ok(_)) => {
                // Received a response - port is open
                UdpPortState::Open
            }
            Ok(Err(_)) => {
                // Error receiving - port likely closed
                UdpPortState::Closed
            }
            Err(_) => {
                // Timeout - port is likely filtered (open but no response)
                // For UDP, this is typically considered open|filtered
                UdpPortState::Open
            }
        }
    }

    fn get_probe_data_for_port(&self, port: u16) -> Vec<u8> {
        match port {
            53 => {
                // DNS query for "google.com"
                vec![
                    0x12, 0x34, // Transaction ID
                    0x01, 0x00, // Flags: standard query
                    0x00, 0x01, // Questions: 1
                    0x00, 0x00, // Answer RRs: 0
                    0x00, 0x00, // Authority RRs: 0
                    0x00, 0x00, // Additional RRs: 0
                    // Query: google.com
                    0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
                    0x03, 0x63, 0x6f, 0x6d, // "com"
                    0x00, // End of name
                    0x00, 0x01, // Type: A
                    0x00, 0x01, // Class: IN
                ]
            }
            161 => {
                // SNMP GetRequest
                vec![
                    0x30, 0x26, // SEQUENCE
                    0x02, 0x01, 0x00, // version: 1
                    0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // community: "public"
                    0xa0, 0x19, // GetRequest PDU
                    0x02, 0x01, 0x01, // request-id: 1
                    0x02, 0x01, 0x00, // error-status: 0
                    0x02, 0x01, 0x00, // error-index: 0
                    0x30, 0x0e, // variable-bindings
                    0x30, 0x0c, // VarBind
                    0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: 1.3.6.1.2.1.1.1.0
                    0x05, 0x00, // NULL
                ]
            }
            123 => {
                // NTP request
                vec![
                    0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ]
            }
            _ => {
                // Generic UDP probe - empty packet
                vec![]
            }
        }
    }

    async fn udp_scan(&self, targets: Vec<String>, ports: Vec<u16>) -> Result<UDPScanResult, Box<dyn Error>> {
        let mut combined_results = UDPScanResult::new();
        
        for target in targets {
            // Check if target is already an IP address
            let ip_addr = if valid_ip(&target) {
                target.parse::<IpAddr>()?
            } else {
                // Resolve domain name to IP
                let resolved_ip = self.dns.resolve_to_ip(&target).await?;
                // Take the first IP if multiple are returned
                let first_ip = resolved_ip.split(", ").next().unwrap_or(&resolved_ip);
                first_ip.parse::<IpAddr>()?
            };
            
            // Launch fire_and_forget for this resolved IP
            let scan_results = self.fire_and_forget(ip_addr, ports.clone()).await?;
            
            // Merge results into combined results
            for (port, state) in scan_results {
                combined_results.insert(port, state);
            }
        }
        
        Ok(combined_results)
    }

    pub async fn exec(&self) -> Result<(), Box<dyn Error>> {
        let targets = &self.config.target;
        let ports_str = &self.config.ports;
        
        // Parse ports from string format
        let ports = Self::parse_ports(ports_str);
        
        if ports.is_empty() {
            eprintln!("No valid ports specified for UDP scan");
            return Ok(());
        }
        
        // Perform UDP scan on all targets
        let results = self.udp_scan(targets.clone(), ports).await?;
        
        // Display results
        if results.is_empty() {
            println!("No UDP ports found");
        } else {
            let output_handler = OutputHandler::new();
            
            // Convert UDP results to the format expected by OutputHandler
            let mut ports_map = HashMap::new();
            for (port, udp_state) in results {
                let port_state = match udp_state {
                    UdpPortState::Open => PortState::Open,
                    UdpPortState::Closed => PortState::Closed,
                };
                ports_map.insert(port.to_string(), port_state);
            }
            
            // Use the OutputHandler to display results
            let ports_specified = self.config.ports_explicitly_specified;
            output_handler.out_results_with_ports_info(ports_map, "UDP".to_string(), ports_specified);
        }
        
        Ok(())
    }
}
