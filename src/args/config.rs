use serde_yaml;
use std::fs;
use num_cpus;

#[derive(Debug, serde::Deserialize)]
pub struct Config {
    pub target: Vec<String>,
    pub ports: String,
    pub tcp: bool,
    pub udp: bool,
    pub timeout: u64,
    pub threads: u64,
    pub json: bool,
    pub output: Option<String>,
    pub lua_script: Option<String>,
    pub scan_profile: String,
    pub allow_private: bool,
    pub verbose: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            target: vec![],
            ports: "1-1024".to_string(),
            tcp: true,
            udp: false,
            timeout: 2000,
            threads: num_cpus::get() as u64,
            json: false,
            output: None,
            lua_script: None,
            scan_profile: "full".to_string(),
            allow_private: false,
            verbose: false,
        }
    }
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}