use crate::core::{PortState, ScriptResult, ServiceInfo};
use std::{collections::HashMap, fs::File, io::Write};
use tabled::{Table, Tabled};

#[derive(Tabled)]
struct PortRow {
    #[tabled(rename = "PORT")]
    port: String,
    #[tabled(rename = "STATE")]
    state: String,
    #[tabled(rename = "SERVICE")]
    service: String,
}

pub struct OutputHandler;

impl OutputHandler {
    pub fn new() -> OutputHandler {
        OutputHandler
    }

    /// Get the most likely service for a given port
    fn get_service_for_port(port: &str) -> &'static str {
        match port {
            "21" => "ftp",
            "22" => "ssh",
            "23" => "telnet",
            "25" => "smtp",
            "53" => "dns",
            "80" => "http",
            "110" => "pop3",
            "115" => "sftp",
            "135" => "rpc",
            "139" => "netbios",
            "143" => "imap",
            "194" => "irc",
            "443" => "https",
            "445" => "smb",
            "993" => "imaps",
            "995" => "pop3s",
            "1433" => "mssql",
            "3306" => "mysql",
            "3389" => "rdp",
            "5432" => "postgresql",
            "5632" => "pcanywhere",
            "5900" => "vnc",
            "25565" => "minecraft",
            "27017" => "mongodb",
            "6379" => "redis",
            "5672" => "rabbitmq",
            "8080" => "http-proxy",
            "8443" => "https-alt",
            "9200" => "elasticsearch",
            "5601" => "kibana",
            "2181" => "zookeeper",
            "9092" => "kafka",
            "11211" => "memcached",
            "1521" => "oracle",
            "5984" => "couchdb",
            "7000" => "cassandra",
            "8086" => "influxdb",
            "9000" => "sonarqube",
            "8888" => "jupyter",
            "3000" => "grafana",
            "9090" => "prometheus",
            "4444" => "selenium",
            "8081" => "nexus",
            "8082" => "sonatype",
            "9999" => "abyss",
            "10000" => "webmin",
            _ => "unknown",
        }
    }

    pub fn out_results(&self, ports: HashMap<String, PortState>, protocol: String) {
        if ports.is_empty() {
            println!("No ports found for {} scan", protocol.to_uppercase());
            return;
        }

        // Sort ports numerically for better display
        let mut sorted_ports: Vec<_> = ports.iter().collect();
        sorted_ports.sort_by(|a, b| {
            let port_a: u16 = a.0.parse().unwrap_or(0);
            let port_b: u16 = b.0.parse().unwrap_or(0);
            port_a.cmp(&port_b)
        });

        // Create table rows
        let rows: Vec<PortRow> = sorted_ports
            .iter()
            .map(|(port, state)| {
                let state_str = match state {
                    PortState::Open => "open",
                    PortState::Closed => "closed",
                    PortState::Filtered => "filtered",
                };

                let service = Self::get_service_for_port(port);

                PortRow {
                    port: port.to_string(),
                    state: state_str.to_string(),
                    service: service.to_string(),
                }
            })
            .collect();

        // Create and display table
        println!("\n{} Scan Results:", protocol.to_uppercase());
        let table = Table::new(rows);
        println!("{}", table);

        // Print summary
        let open_count = ports
            .values()
            .filter(|&s| matches!(s, PortState::Open))
            .count();
        let closed_count = ports
            .values()
            .filter(|&s| matches!(s, PortState::Closed))
            .count();
        let filtered_count = ports
            .values()
            .filter(|&s| matches!(s, PortState::Filtered))
            .count();

        println!(
            "Summary: {} open, {} closed, {} filtered",
            open_count, closed_count, filtered_count
        );
    }

    pub fn out_json(
        &self,
        ports: HashMap<String, PortState>,
        protocol: String,
        file_path: &str,
        host: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::json!({
            "protocol": protocol,
            "ports": ports,
            "host": host
        });

        let mut file = File::create(file_path)?;
        writeln!(file, "{}", serde_json::to_string_pretty(&json)?)?;

        println!("JSON output written to: {}", file_path);
        Ok(())
    }

    pub fn out_service_detection(&self, service_details: &HashMap<String, ServiceInfo>) {
        if !service_details.is_empty() {
            println!("\nService Detection Results:");
            println!("------------------------------------------------------------");
            for (port, service) in service_details {
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

    pub fn out_script_result(&self, result: &ScriptResult) {
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
