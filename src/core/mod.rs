use crate::args::Config;
use std::error::Error;

mod probe;
mod lua;
mod tcp;
mod udp;

pub use tcp::PortState;
pub use probe::parser::parse_nmap_probes_json;
pub use lua::{LuaScriptRunner, ScriptResult, new_script_runner};
pub use probe::{Prober, ServiceInfo, ProbeResult};

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
