use std::net::IpAddr;
use std::fs;

pub fn valid_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}

pub fn parse_nmap_probes_json(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let lines = content.lines();
    for line in lines {
        let line = line.trim();
        if line.starts_with("#") || line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
    }
    Ok(())
}