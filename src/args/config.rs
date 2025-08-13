use num_cpus;
use serde_yaml;
use std::fs;

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
        }
    }
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;

        // Parse YAML into a partial config that allows missing fields
        let yaml_value: serde_yaml::Value = serde_yaml::from_str(&content)?;

        // Start with default config
        let mut config = Config::default();

        // Merge YAML values over defaults
        if let serde_yaml::Value::Mapping(map) = yaml_value {
            for (key, value) in map {
                if let serde_yaml::Value::String(key_str) = key {
                    match key_str.as_str() {
                        "target" => {
                            if let Ok(targets) = serde_yaml::from_value::<Vec<String>>(value) {
                                config.target = targets;
                            }
                        }
                        "ports" => {
                            if let Ok(ports) = serde_yaml::from_value::<String>(value) {
                                config.ports = ports;
                            }
                        }
                        "tcp" => {
                            if let Ok(tcp) = serde_yaml::from_value::<bool>(value) {
                                config.tcp = tcp;
                            }
                        }
                        "udp" => {
                            if let Ok(udp) = serde_yaml::from_value::<bool>(value) {
                                config.udp = udp;
                            }
                        }
                        "timeout" => {
                            if let Ok(timeout) = serde_yaml::from_value::<u64>(value) {
                                config.timeout = timeout;
                            }
                        }
                        "threads" => {
                            if let Ok(threads) = serde_yaml::from_value::<u64>(value) {
                                config.threads = threads;
                            }
                        }
                        "json" => {
                            if let Ok(json) = serde_yaml::from_value::<Option<String>>(value) {
                                config.json = json;
                            }
                        }
                        "lua_script" => {
                            if let Ok(lua_script) = serde_yaml::from_value::<Option<String>>(value)
                            {
                                config.lua_script = lua_script;
                            }
                        }
                        "verbose" => {
                            if let Ok(verbose) = serde_yaml::from_value::<bool>(value) {
                                config.verbose = verbose;
                            }
                        }

                        _ => {} // Ignore unknown fields
                    }
                }
            }
        }

        Ok(config)
    }
}
