use std::net::IpAddr;
use std::error::Error;
use crate::core::parse_nmap_probes_json;

pub fn valid_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}

// Ensure probes are loaded to JSON
pub fn ensure_probe() -> Result<(), Box<dyn Error>> {
    parse_nmap_probes_json("./assets/nmap-service-probes")?;
    Ok(())
}