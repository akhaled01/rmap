use clap::Parser;
use num_cpus;

mod cli;
mod config;

pub fn get_config() -> config::Config {
    let args = cli::Args::parse();
    
    let mut config = if let Some(config_path) = &args.config {
        match config::Config::from_file(config_path) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("Error loading config file '{}': {}", config_path, e);
                std::process::exit(1);
            }
        }
    } else {
        config::Config::default()
    };
    
    if !args.target.is_empty() {
        config.target = args.target;
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
    
    if args.json {
        config.json = args.json;
    }
    
    if args.output.is_some() {
        config.output = args.output;
    }
    
    if args.lua_script.is_some() {
        config.lua_script = args.lua_script;
    }
    
    if args.scan_profile != "full" {
        config.scan_profile = args.scan_profile;
    }
    
    if args.allow_private {
        config.allow_private = args.allow_private;
    }
    
    if args.verbose {
        config.verbose = args.verbose;
    }
    
    config
}