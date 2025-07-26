use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use crate::core::PortState;

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
            "143" => "imap",
            "443" => "https",
            "993" => "imaps",
            "995" => "pop3s",
            "3389" => "rdp",
            "5432" => "postgresql",
            "3306" => "mysql",
            "1433" => "mssql",
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
            _ => "unknown"
        }
    }

    pub fn out_results(&self, ports: HashMap<String, PortState>, protocol: String) {
        if ports.is_empty() {
            println!("No ports found for {} scan", protocol.to_uppercase());
            return;
        }

        // Print table header
        println!("\n{} Scan Results:", protocol.to_uppercase());
        println!("{:-<60}", "");
        println!("{:<10} {:<12} {:<20}", "PORT", "STATE", "SERVICE");
        println!("{:-<60}", "");

        // Sort ports numerically for better display
        let mut sorted_ports: Vec<_> = ports.iter().collect();
        sorted_ports.sort_by(|a, b| {
            let port_a: u16 = a.0.parse().unwrap_or(0);
            let port_b: u16 = b.0.parse().unwrap_or(0);
            port_a.cmp(&port_b)
        });

        // Print each port result
        for (port, state) in sorted_ports {
            let state_str = match state {
                PortState::Open => "open",
                PortState::Closed => "closed",
                PortState::Filtered => "filtered",
            };
            
            let service = Self::get_service_for_port(port);
            println!("{:<10} {:<12} {:<20}", port, state_str, service);
        }
        
        println!("{:-<60}", "");
        
        // Print summary
        let open_count = ports.values().filter(|&s| matches!(s, PortState::Open)).count();
        let closed_count = ports.values().filter(|&s| matches!(s, PortState::Closed)).count();
        let filtered_count = ports.values().filter(|&s| matches!(s, PortState::Filtered)).count();
        
        println!("Summary: {} open, {} closed, {} filtered", open_count, closed_count, filtered_count);
    }

    pub fn out_json(&self, ports: HashMap<String, PortState>, protocol: String, file_path: &str, host: &str) -> Result<(), Box<dyn std::error::Error>> {
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
}
    