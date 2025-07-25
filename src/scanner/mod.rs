use crate::args::Config;
use std::error::Error;

mod lua;
mod tcp;
mod udp;

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
