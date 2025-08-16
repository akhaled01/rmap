use crate::args::{Config, get_config};
use crate::core::lua::LuaScriptRunner;
use crate::output::OutputHandler;
use crate::utils::valid_ip;
use crate::dns::DNSResolver;
use std::collections::HashMap;
use std::error::Error;
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;

pub struct TCPScanner {
    /// The configuration for the current scan
    pub config: Config,
    /// A local DNS resolver
    pub dns: DNSResolver,
}

#[derive(Debug, Serialize, Clone)]
pub enum PortState {
    Open,
    Closed,
    Filtered, // Likely blocked by firewall
}

#[derive(Debug)]
pub struct PortResult {
    pub port: String,
    pub state: PortState,
}

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
}

pub struct SynScanResult {
    pub open_ports: Vec<PortResult>,
    pub closed_ports: Vec<PortResult>,
    pub filtered_ports: Vec<PortResult>,
}

impl TCPScanner {
    pub fn new() -> TCPScanner {
        let config = get_config();
        TCPScanner {
            config,
            dns: DNSResolver::new(),
        }
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

    // Static version of syn_scan that doesn't require self
    async fn syn_scan(
        target: &str,
        ports: &str,
        timeout: u64,
        semaphore: Arc<Semaphore>,
        _config: &Config,
    ) -> Result<SynScanResult, Box<dyn Error + Send + Sync>> {
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

        // Print scan message
        println!("\x1b[31mrunning TCP scan\x1b[0m");
        
        // Create progress bar
        let pb = ProgressBar::new(port_list.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{percent:>3}%|{bar:25.red/bright_red}| {pos}/{len} [{elapsed_precise}<{eta_precise}, {per_sec}]")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏ "),
        );

        for port in port_list {
            let target_clone = target_owned.clone();
            let port_string = port.to_string();
            let sem_clone = semaphore.clone();
            let handle = tokio::spawn(async move {
                // Acquire semaphore permit before scanning
                let _permit = sem_clone.acquire().await.unwrap();

                match tokio::time::timeout(
                    Duration::from_millis(timeout),
                    TcpStream::connect((target_clone.as_str(), port)),
                )
                .await
                {
                    Ok(Ok(stream)) => {
                        // Successfully connected - port is open
                        drop(stream); // Close the connection

                        Some(PortResult {
                            port: port_string,
                            state: PortState::Open,
                        })
                    }
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
                                } else if error_msg.contains("timeout")
                                    || error_msg.contains("unreachable")
                                    || error_msg.contains("filtered")
                                {
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
                    }
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
                    PortState::Open => open_ports.push(result),
                    PortState::Closed => closed_ports.push(result),
                    PortState::Filtered => filtered_ports.push(result),
                }
            }
            pb.inc(1);
        }

        pb.finish_and_clear();

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
            println!(
                "Starting TCP scan with {} thread{}",
                threads,
                if threads == 1 { "" } else { "s" }
            );
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

                if resolved_ips.len() > 0 {
                    // Single IP resolution - use original target name
                    let ip = resolved_ips[0].trim();
                    if valid_ip(ip) {
                        targets.push(ip.to_string());
                        target_mapping.insert(ip.to_string(), original_target.to_string());
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
                let result = Self::syn_scan(
                    &target_clone,
                    &ports_clone,
                    timeout,
                    sem_clone,
                    &config_clone,
                )
                .await;
                (target_clone, result)
            });
            handles.push(handle);
        }

        // Collect and display results
        let output_handler = OutputHandler::new();

        for handle in handles {
            if let Ok((target, result)) = handle.await {
                match result {
                    // if scan is ok, output and run scripts
                    Ok(scan_result) => {
                        // Convert scan results to HashMap format for OutputHandler
                        let mut ports_map = HashMap::new();

                        // Process all port results in a single unified approach
                        let all_ports = scan_result
                            .open_ports
                            .iter()
                            .chain(scan_result.closed_ports.iter())
                            .chain(scan_result.filtered_ports.iter());

                        for port_result in all_ports {
                            ports_map.insert(port_result.port.clone(), port_result.state.clone());
                        }

                        // Display results using OutputHandler
                        if !ports_map.is_empty() {
                            // Check if JSON output is requested
                            if let Some(json_file) = json_output {
                                // Output to JSON file
                                if let Err(e) = output_handler.out_json(
                                    ports_map,
                                    "TCP".to_string(),
                                    json_file,
                                    &target,
                                ) {
                                    eprintln!("Error writing JSON output: {}", e);
                                }
                            } else {
                                // Normal table output - use original target name if available
                                let ports_specified = self.config.ports_explicitly_specified;
                                output_handler.out_results_with_ports_info(ports_map, "TCP".to_string(), ports_specified);
                            }
                        } else {
                            if json_output.is_none() {
                                println!("\nTarget {}: No ports to display", target);
                            }
                        }

                        // Execute Lua scripts if specified
                        if let Some(lua_script) = &self.config.lua_script {
                            let display_target = target_mapping.get(&target).unwrap_or(&target);
                            self.execute_lua_scripts(
                                lua_script,
                                display_target,
                                &scan_result,
                                &output_handler,
                            )
                            .await;
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

    /// Execute Lua scripts against a target and its open ports
    async fn execute_lua_scripts(
        &self,
        lua_script: &str,
        display_target: &str,
        scan_result: &SynScanResult,
        output_handler: &OutputHandler,
    ) {
        println!("\nExecuting Lua Script: {}", lua_script);
        println!("------------------------------------------------------------");

        match LuaScriptRunner::new() {
            Ok(script_runner) => {
                // Execute script against the host
                match script_runner
                    .run_script(lua_script, display_target, None)
                    .await
                {
                    Ok(script_result) => {
                        output_handler.out_script_result(&script_result);
                    }
                    Err(e) => {
                        eprintln!("Error executing script '{}': {}", lua_script, e);
                    }
                }

                // Also execute scripts for each open port
                for port_result in &scan_result.open_ports {
                    if let Ok(port_num) = port_result.port.parse::<u16>() {
                        match script_runner
                            .run_script(lua_script, display_target, Some(port_num))
                            .await
                        {
                            Ok(script_result) => {
                                if script_result.success
                                    && (!script_result.output.is_empty()
                                        || !script_result.data.is_empty())
                                {
                                    println!("\nPort {} Script Results:", port_num);
                                    output_handler.out_script_result(&script_result);
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "Error executing script '{}' on port {}: {}",
                                    lua_script, port_num, e
                                );
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
