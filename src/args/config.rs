use serde_yaml;
use std::fs;
use num_cpus;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Config {
    pub target: Vec<String>,
    pub ports: String,
    pub tcp: bool,
    pub udp: bool,
    pub timeout: u64,
    pub threads: u64,
    pub json: Option<String>,
    pub lua_script: Option<String>,
    pub verbose: bool,
    pub service_detection: bool,
    pub probes_file: Option<String>,
    pub service_timeout: u64,
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
            json: None,
            lua_script: None,
            verbose: false,
            service_detection: false,
            probes_file: None,
            service_timeout: 5000,
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