use clap::Parser;
use num_cpus;

#[derive(Parser, Debug)]
#[command(name = "rmap")]
#[command(about = "A fast network port scanner")]
#[command(version)]
pub struct Args {
    /// Configuration file path. Note that CLI arguments override configuration file settings.
    #[arg(long = "config")]
    pub config: Option<String>,

    /// Target IP address, domain, or CIDR range
    #[arg(short = 't', long = "target", required = true)]
    pub target: Vec<String>,

    /// Ports or port ranges (e.g., 80,443,1-1024)
    #[arg(short = 'p', long = "ports", default_value = "1-1024")]
    pub ports: String,

    /// Enable TCP scanning
    #[arg(long = "tcp", default_value = "true")]
    pub tcp: bool,

    /// Enable UDP scanning
    #[arg(long = "udp")]
    pub udp: bool,

    /// Timeout per probe in milliseconds
    #[arg(long = "timeout", default_value = "2000")]
    pub timeout: u64,

    /// Number of concurrent tasks/threads
    #[arg(long = "threads", default_value_t = num_cpus::get())]
    pub threads: usize,

    /// Output results in JSON format
    #[arg(long = "json")]
    pub json: bool,

    /// Output file path (if omitted, prints to stdout)
    #[arg(long = "output")]
    pub output: Option<String>,

    /// Path to Lua script for service detection
    #[arg(long = "lua-script")]
    pub lua_script: Option<String>,

    /// Scan profile (e.g., fast, full, stealth)
    #[arg(long = "scan-profile", default_value = "full")]
    pub scan_profile: String,

    /// Allow scanning of private/local IP ranges
    #[arg(long = "allow-private")]
    pub allow_private: bool,

    /// Enable verbose logging
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}
