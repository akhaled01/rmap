use crate::args::Config;
use std::error::Error;

mod lua;
mod probe;
mod tcp;
mod udp;

pub use lua::{LuaScriptRunner, ScriptResult, new_script_runner};
pub use probe::{ProbeResult, Prober, ServiceInfo, parser::parse_nmap_probes_json};
pub use tcp::PortState;

pub struct Scanner {
    pub config: Config,
}

impl Scanner {
    pub fn new(config: Config) -> Scanner {
        Scanner { config }
    }

    pub async fn exec(&self) -> Result<(), Box<dyn Error>> {
        if self.config.tcp {
            tcp::TCPScanner::new().exec().await?;
        }
        Ok(())
    }
}
