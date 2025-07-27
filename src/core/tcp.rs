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
use crate::core::probe::{Prober, ServiceInfo};
use crate::core::lua::{LuaScriptRunner, ScriptResult};
use std::net::IpAddr;

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
    service: Option<ServiceInfo>,
}

pub struct SynScanResult {
    pub open_ports: Vec<PortResult>,
    pub closed_ports: Vec<PortResult>,
    pub filtered_ports: Vec<PortResult>,
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
    async fn syn_scan(target: &str, ports: &str, timeout: u64, semaphore: Arc<Semaphore>, config: &Config) -> Result<SynScanResult, Box<dyn Error + Send + Sync>> {
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
        
        // Initialize prober if service detection is enabled
        let _prober = if config.service_detection {
            let mut prober = Prober::new();
            prober.set_timeout(config.service_timeout);
            
            // Load probes file - use specified file or default to nmap-probes.json
            let probes_file = config.probes_file.as_deref().unwrap_or("assets/nmap-probes.json");
            if let Err(e) = prober.load_probes(probes_file) {
                eprintln!("Warning: Failed to load probes file '{}': {}", probes_file, e);
            }
            
            Some(prober)
        } else {
            None
        };
        
        for port in port_list {
            let target_clone = target_owned.clone();
            let port_string = port.to_string();
            let sem_clone = semaphore.clone();
            let config_clone = config.clone();
            let prober_enabled = config.service_detection;
            
            let handle = tokio::spawn(async move {
                // Acquire semaphore permit before scanning
                let _permit = sem_clone.acquire().await.unwrap();
                
                match tokio::time::timeout(
                    Duration::from_millis(timeout),
                    TcpStream::connect((target_clone.as_str(), port))
                ).await {
                    Ok(Ok(stream)) => {
                        // Successfully connected - port is open
                        let mut service_info = None;
                        
                        // Perform service detection if enabled
                        if prober_enabled {
                            // Parse target IP for service detection
                            if let Ok(ip_addr) = target_clone.parse::<IpAddr>() {
                                // Create a new prober instance for this task
                                let mut task_prober = Prober::new();
                                task_prober.set_timeout(config_clone.service_timeout);
                                
                                // Load probes file - use specified file or default to nmap-probes.json
                                let probes_file = config_clone.probes_file.as_deref().unwrap_or("assets/nmap-probes.json");
                                let _ = task_prober.load_probes(probes_file);
                                
                                // Perform service detection
                                match task_prober.probe_port(ip_addr, port).await {
                                    Ok(probe_result) => {
                                        service_info = probe_result.service;
                                    }
                                    Err(_) => {
                                        // Service detection failed, continue without service info
                                    }
                                }
                            }
                        }
                        
                        drop(stream); // Close the connection
                        
                        Some(PortResult {
                            port: port_string,
                            state: PortState::Open,
                            service: service_info,
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
                            service: None,
                        })
                    },
                    Err(_) => {
                        // Timeout from tokio::time::timeout - likely filtered by firewall
                        Some(PortResult {
                            port: port_string,
                            state: PortState::Filtered,
                            service: None,
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
                    PortState::Open => open_ports.push(result),
                    PortState::Closed => closed_ports.push(result),
                    PortState::Filtered => filtered_ports.push(result),
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
            println!("Starting TCP scan with {} thread{}", threads, if threads == 1 { "" } else { "s" });
            println!("Target(s): {:?}", target);
            println!("Ports: {}", ports);
            println!("Timeout: {}ms", timeout);
        }

        // resolve targets to IP, and validate them
        // Keep track of original target names for display
        let mut target_mapping: HashMap<String, String> = HashMap::new();
        let mut targets: Vec<String> = Vec::new();
        
        for original_target in target {
            if valid_ip(original_target) {
                targets.push(original_target.to_string());
                target_mapping.insert(original_target.to_string(), original_target.to_string());
            } else {
                let ips_str = self.dns.resolve_to_ip(original_target).await?;
                // DNS resolver returns comma-separated IPs, split them
                let resolved_ips: Vec<&str> = ips_str.split(", ").collect();
                
                if resolved_ips.len() == 1 {
                    // Single IP resolution - use original target name
                    let ip = resolved_ips[0].trim();
                    if valid_ip(ip) {
                        targets.push(ip.to_string());
                        target_mapping.insert(ip.to_string(), original_target.to_string());
                    }
                } else {
                    // Multiple IP resolution - use first IP but track all for consolidation
                    let first_ip = resolved_ips[0].trim();
                    if valid_ip(first_ip) {
                        targets.push(first_ip.to_string());
                        target_mapping.insert(first_ip.to_string(), original_target.to_string());
                    }
                }
            }
        }
        
        if verbose {
            println!("Resolved targets: {:?}", targets);
        }

        // spawn processes to conduct syn scan with global thread limiting
        let mut handles = vec![];
        
        // Create global semaphore to limit concurrent connections across all targets and ports
        let global_semaphore = Arc::new(Semaphore::new(threads as usize));
        
        for target in &targets {
            let target_clone = target.clone();
            let ports_clone = ports.clone();
            let sem_clone = global_semaphore.clone();
            
            let config_clone = self.config.clone();
            let handle = tokio::spawn(async move {
                let result = Self::syn_scan(&target_clone, &ports_clone, timeout, sem_clone, &config_clone).await;
                (target_clone, result)
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
                        
                        // Store service information for display
                        let mut service_details = HashMap::new();
                        
                        // Add all ports to the map based on their state
                        for port_result in &scan_result.open_ports {
                            ports_map.insert(port_result.port.clone(), PortState::Open);
                            
                            // Store service information for later display
                            if let Some(service) = &port_result.service {
                                service_details.insert(port_result.port.clone(), service.clone());
                            }
                        }
                        
                        if verbose {
                            // In verbose mode, show closed and filtered ports too
                            for port_result in scan_result.closed_ports {
                                ports_map.insert(port_result.port, PortState::Closed);
                            }
                            for port_result in scan_result.filtered_ports {
                                ports_map.insert(port_result.port, PortState::Filtered);
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
                                // Normal table output - use original target name if available
                                let display_target = target_mapping.get(&target).unwrap_or(&target);
                                println!("\nTarget: {} ({})", display_target, target);
                                output_handler.out_results(ports_map, "TCP".to_string());
                                
                                // Display service detection results if available
                                if self.config.service_detection {
                                    if !service_details.is_empty() {
                                        println!("\nService Detection Results:");
                                        println!("------------------------------------------------------------");
                                    for (port, service) in &service_details {
                                        println!("Port {}: {}", port, service.service);
                                        
                                        if let Some(version) = &service.version {
                                            println!("  Version: {}", version);
                                        }
                                        if let Some(product) = &service.product {
                                            println!("  Product: {}", product);
                                        }
                                        if let Some(extra_info) = &service.extra_info {
                                            println!("  Extra Info: {}", extra_info);
                                        }
                                        if let Some(hostname) = &service.hostname {
                                            println!("  Hostname: {}", hostname);
                                        }
                                        if let Some(os_info) = &service.os_info {
                                            println!("  OS: {}", os_info);
                                        }
                                        if let Some(device_type) = &service.device_type {
                                            println!("  Device Type: {}", device_type);
                                        }
                                        println!("");
                                    }
                                    } else {
                                        println!("\nService Detection: No detailed service information found.");
                                        println!("This may be due to:");
                                        println!("- No probes file loaded (use --probes-file to specify)");
                                        println!("- Services not responding to probes");
                                        println!("- Firewall blocking probe attempts");
                                    }
                                }
                                
                                // Execute Lua scripts if specified
                                if let Some(lua_script) = &self.config.lua_script {
                                    println!("\nExecuting Lua Script: {}", lua_script);
                                    println!("------------------------------------------------------------");
                                    
                                    match LuaScriptRunner::new() {
                                        Ok(script_runner) => {
                                            // Get the original target name for display
                                            let display_target = target_mapping.get(&target).unwrap_or(&target);
                                            
                                            // Execute script against the host
                                            match script_runner.run_script(lua_script, display_target, None).await {
                                                Ok(script_result) => {
                                                    self.display_script_result(&script_result);
                                                }
                                                Err(e) => {
                                                    eprintln!("Error executing script '{}': {}", lua_script, e);
                                                }
                                            }
                                            
                                            // Also execute scripts for each open port
                                            for port_result in &scan_result.open_ports {
                                                if let Ok(port_num) = port_result.port.parse::<u16>() {
                                                    match script_runner.run_script(lua_script, display_target, Some(port_num)).await {
                                                        Ok(script_result) => {
                                                            if script_result.success && (!script_result.output.is_empty() || !script_result.data.is_empty()) {
                                                                println!("\nPort {} Script Results:", port_num);
                                                                self.display_script_result(&script_result);
                                                            }
                                                        }
                                                        Err(e) => {
                                                            eprintln!("Error executing script '{}' on port {}: {}", lua_script, port_num, e);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Error initializing Lua script runner: {}", e);
                                        }
                                    }
                                }
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
    
    /// Display Lua script execution results
    fn display_script_result(&self, result: &ScriptResult) {
        if result.success {
            if !result.output.is_empty() {
                println!("Output: {}", result.output);
            }
            
            if !result.data.is_empty() {
                println!("Data:");
                for (key, value) in &result.data {
                    println!("  {}: {}", key, value);
                }
            }
            
            if result.output.is_empty() && result.data.is_empty() {
                println!("Script executed successfully (no output)");
            }
        } else {
            if let Some(error) = &result.error {
                println!("Script failed: {}", error);
            } else {
                println!("Script failed (unknown error)");
            }
        }
    }
}
