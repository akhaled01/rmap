use crate::args::Config;
use std::error::Error;

mod lua;
mod tcp;
mod udp;
pub mod probe;

pub use lua::{LuaScriptRunner, ScriptResult, new_script_runner};
pub use tcp::{PortState, PortResult, ServiceInfo};
pub use udp::UdpPortState;

pub struct Scanner {
    pub config: Config,
}

impl Scanner {
    pub fn new(config: Config) -> Scanner {
        Scanner { config }
    }

    pub async fn exec(&self) -> Result<(), Box<dyn Error>> {
        if self.config.udp {
            udp::UDPScanner::new().exec().await?;
        } else if self.config.tcp {
            tcp::TCPScanner::new().exec().await?;
        }
        Ok(())
    }
}
