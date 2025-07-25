use std::net::IpAddr;

pub fn valid_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}
