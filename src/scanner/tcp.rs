use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use std::error::Error;
use std::time::Duration;
use std::sync::Arc;
use std::collections::HashMap;
use crate::args::{get_config, Config};
use crate::dns::DNSResolver;
use crate::utils::valid_ip;
use crate::output::OutputHandler;
use std::io::ErrorKind;
use serde::Serialize;

pub struct TCPScanner {
    /// The configuration for the current scan
    pub config: Config,
    /// A local DNS resolver
    pub dns: DNSResolver,
}

#[derive(Debug, Serialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered, // Likely blocked by firewall
}

#[derive(Debug)]
pub struct PortResult {
    port: String,
    state: PortState,
}

pub struct SynScanResult {
    pub open_ports: Vec<String>,
    pub closed_ports: Vec<String>,
    pub filtered_ports: Vec<String>,
}

impl TCPScanner {
    pub fn new() -> TCPScanner {
        let config = get_config();
        TCPScanner { config, dns: DNSResolver::new() }
    }

    // Parse port ranges and individual ports
    fn parse_ports(ports_str: &str) -> Vec<u16> {
        let mut ports = Vec::new();
        
        for part in ports_str.split(',') {
            let part = part.trim();
            if part.contains('-') {
                // Handle range like "1-1024"
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() == 2 {
                    if let (Ok(start), Ok(end)) = (range_parts[0].parse::<u16>(), range_parts[1].parse::<u16>()) {
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

    // Static version of syn_scan that doesn't require self
    async fn syn_scan(target: &str, ports: &str, timeout: u64, threads: u64) -> Result<SynScanResult, Box<dyn Error + Send + Sync>> {
        let target_owned = target.to_string();
        let mut handles = vec![];
        
        // Parse ports (handles both ranges and individual ports)
        let port_list = Self::parse_ports(ports);
        
        if port_list.is_empty() {
            return Ok(SynScanResult { 
                open_ports: Vec::new(),
                closed_ports: Vec::new(),
                filtered_ports: Vec::new(),
            });
        }
        
        // Create semaphore to limit concurrent port scans per target
        let semaphore = Arc::new(Semaphore::new(threads as usize));
        
        for port in port_list {
            let target_clone = target_owned.clone();
            let port_string = port.to_string();
            let sem_clone = semaphore.clone();
            
            let handle = tokio::spawn(async move {
                // Acquire semaphore permit before scanning
                let _permit = sem_clone.acquire().await.unwrap();
                
                match tokio::time::timeout(
                    Duration::from_millis(timeout),
                    TcpStream::connect((target_clone.as_str(), port))
                ).await {
                    Ok(Ok(stream)) => {
                        // Successfully connected - port is open
                        drop(stream); // Close the connection
                        Some(PortResult {
                            port: port_string,
                            state: PortState::Open,
                        })
                    },
                    Ok(Err(e)) => {
                        // Analyze the connection error to determine port state
                        let state = match e.kind() {
                            ErrorKind::ConnectionRefused => PortState::Closed,
                            ErrorKind::TimedOut => PortState::Filtered,
                            ErrorKind::PermissionDenied => PortState::Filtered,
                            ErrorKind::NetworkUnreachable => PortState::Filtered,
                            ErrorKind::HostUnreachable => PortState::Filtered,
                            _ => {
                                // For unknown errors, try to infer from error message
                                let error_msg = e.to_string().to_lowercase();
                                if error_msg.contains("refused") {
                                    PortState::Closed
                                } else if error_msg.contains("timeout") || 
                                         error_msg.contains("unreachable") ||
                                         error_msg.contains("filtered") {
                                    PortState::Filtered
                                } else {
                                    PortState::Closed // Default to closed for unknown errors
                                }
                            }
                        };
                        Some(PortResult {
                            port: port_string,
                            state,
                        })
                    },
                    Err(_) => {
                        // Timeout from tokio::time::timeout - likely filtered by firewall
                        Some(PortResult {
                            port: port_string,
                            state: PortState::Filtered,
                        })
                    }
                }
                // Permit is automatically released when _permit is dropped
            });
            handles.push(handle);
        }

        let mut open_ports = Vec::new();
        let mut closed_ports = Vec::new();
        let mut filtered_ports = Vec::new();
        
        for handle in handles {
            if let Ok(Some(result)) = handle.await {
                match result.state {
                    PortState::Open => open_ports.push(result.port),
                    PortState::Closed => closed_ports.push(result.port),
                    PortState::Filtered => filtered_ports.push(result.port),
                }
            }
        }

        Ok(SynScanResult { 
            open_ports,
            closed_ports,
            filtered_ports,
        })
    }

    /// Execute the TCP scanner
    ///
    /// Note: For this current iteration, rmap will default to SYN scanning only. Later iterations 
    /// 
    /// will support more scanning techniques.
    ///
    ///
    /// # Arguments
    ///
    /// * `self` - The TCP scanner to execute
    ///
    /// # Returns
    ///
    /// A `Result` containing the scan results, or an error if the scan fails
    pub async fn exec(&self) -> Result<(), Box<dyn Error>> {
        let target = &self.config.target;
        let ports = &self.config.ports;
        let timeout = self.config.timeout;
        let threads = self.config.threads;
        let json_output = &self.config.json;
        let verbose = self.config.verbose;

        if verbose {
            println!("Starting TCP scan with {} threads", threads);
            println!("Target(s): {:?}", target);
            println!("Ports: {}", ports);
            println!("Timeout: {}ms", timeout);
        }

        // resolve targets to IP, and validate them
        let mut targets: Vec<String> = Vec::new();
        for target in target {
            if valid_ip(target) {
                targets.push(target.to_string());
            } else {
                let ips_str = self.dns.resolve_to_ip(target).await?;
                // DNS resolver returns comma-separated IPs, split them
                for ip in ips_str.split(", ") {
                    let ip = ip.trim();
                    if valid_ip(ip) {
                        targets.push(ip.to_string());
                    }
                }
            }
        }
        
        if verbose {
            println!("Resolved targets: {:?}", targets);
        }

        // spawn processes to conduct syn scan with thread limiting
        let mut handles = vec![];
        
        // Create semaphore to limit concurrent target scans
        let target_semaphore = Arc::new(Semaphore::new(std::cmp::min(threads as usize, targets.len())));
        
        for target in &targets {
            let target_clone = target.clone();
            let ports_clone = ports.clone();
            let sem_clone = target_semaphore.clone();
            
            let handle = tokio::spawn(async move {
                // Acquire semaphore permit before scanning target
                let _permit = sem_clone.acquire().await.unwrap();
                
                let result = Self::syn_scan(&target_clone, &ports_clone, timeout, threads).await;
                (target_clone, result)
                // Permit is automatically released when _permit is dropped
            });
            handles.push(handle);
        }

        // Collect and display results
        let output_handler = OutputHandler::new();
        
        for handle in handles {
            if let Ok((target, result)) = handle.await {
                match result {
                    Ok(scan_result) => {
                        // Convert scan results to HashMap format for OutputHandler
                        let mut ports_map = HashMap::new();
                        
                        // Add all ports to the map based on their state
                        for port in scan_result.open_ports {
                            ports_map.insert(port, PortState::Open);
                        }
                        
                        if verbose {
                            // In verbose mode, show closed and filtered ports too
                            for port in scan_result.closed_ports {
                                ports_map.insert(port, PortState::Closed);
                            }
                            for port in scan_result.filtered_ports {
                                ports_map.insert(port, PortState::Filtered);
                            }
                        }
                        
                        // Display results using OutputHandler
                        if !ports_map.is_empty() {
                            // Check if JSON output is requested
                            if let Some(json_file) = json_output {
                                // Output to JSON file
                                if let Err(e) = output_handler.out_json(ports_map, "TCP".to_string(), json_file, &target) {
                                    eprintln!("Error writing JSON output: {}", e);
                                }
                            } else {
                                // Normal table output
                                println!("\nTarget: {}", target);
                                output_handler.out_results(ports_map, "TCP".to_string());
                            }
                        } else {
                            if json_output.is_none() {
                                println!("\nTarget {}: No ports to display", target);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error scanning target {}: {}", target, e);
                    }
                }
            }
        }
        
        Ok(())
    }
}
