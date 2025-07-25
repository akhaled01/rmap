use clap::Parser;
use num_cpus;

mod cli;
mod config;

pub use config::Config;

pub fn get_config() -> Config {
    let args = cli::Args::parse();
    
    let mut config = if let Some(config_path) = &args.config {
        match Config::from_file(config_path) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Error loading config file '{}': {}", config_path, e);
                std::process::exit(1);
            }
        }
    } else {
        Config::default()
    };
    
    if !args.target.is_empty() {
        config.target = args.target;
    }
    
    // Validate that we have at least one target
    if config.target.is_empty() {
        eprintln!("Error: No target specified. Provide target via --target argument or in config file.");
        std::process::exit(1);
    }
    
    if args.ports != "1-1024" {
        config.ports = args.ports;
    }
    
    if args.tcp != true || args.udp {
        config.tcp = args.tcp;
        config.udp = args.udp;
    }
    
    if args.timeout != 2000 {
        config.timeout = args.timeout;
    }
    
    if args.threads != num_cpus::get() {
        config.threads = args.threads as u64;
    }
    
    if args.json.is_some() {
        config.json = args.json;
    }
    
    if args.lua_script.is_some() {
        config.lua_script = args.lua_script;
    }
    
    if args.verbose {
        config.verbose = args.verbose;
    }
    
    config
}