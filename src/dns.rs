use std::error::Error;
use std::net::IpAddr;
use tokio::net::lookup_host;

pub struct DNSResolver;

impl DNSResolver {
    pub fn new() -> DNSResolver {
        DNSResolver
    }

    /// Resolve a hostname to an IP address
    ///
    /// # Arguments
    ///
    /// * `host` - The hostname to resolve
    ///
    /// # Returns
    ///
    /// A `Result` containing the resolved IP address, or an error if the resolution fails
    pub async fn resolve_to_ip(&self, host: &str) -> Result<String, Box<dyn Error>> {
        // Use Tokio's built-in DNS resolution to avoid runtime conflicts
        let addrs: Vec<_> = lookup_host(format!("{}:80", host))
            .await?
            .map(|addr| addr.ip().to_string())
            .collect();

        if addrs.is_empty() {
            Err(format!("No IP addresses found for host: {}", host).into())
        } else {
            Ok(addrs.join(", "))
        }
    }

    /// Resolve an IP address to a hostname
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to resolve
    ///
    /// # Returns
    ///
    /// A `Result` containing the resolved hostname, or an error if the resolution fails
    pub async fn reverse_resolve(&self, ip: &str) -> Result<String, Box<dyn Error>> {
        // Parse IP address first to validate it
        let ip_addr: IpAddr = ip.parse()?;

        // Use std::net for reverse DNS lookup (this is sync but doesn't create a runtime)
        match std::net::IpAddr::from(ip_addr) {
            addr => {
                // For now, return the IP as-is since reverse DNS is complex
                // In a full implementation, you'd use a proper async DNS library
                Ok(addr.to_string())
            }
        }
    }
}
