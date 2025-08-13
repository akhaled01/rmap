use mlua::{Lua, Result as LuaResult, Table, Value};
use std::{collections::HashMap, error::Error, fs, path::Path};

/// Lua script execution context for host-based scripts
pub struct LuaScriptRunner {
    lua: Lua,
    scripts_dir: String,
}

/// Result of script execution
#[derive(Debug, Clone)]
pub struct ScriptResult {
    pub script_name: String,
    pub host: String,
    pub port: Option<u16>,
    pub success: bool,
    pub output: String,
    pub error: Option<String>,
    pub data: HashMap<String, String>,
}

impl LuaScriptRunner {
    /// Create a new Lua script runner
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let lua = Lua::new();

        Ok(LuaScriptRunner {
            lua,
            scripts_dir: "scripts".to_string(),
        })
    }

    /// Set the scripts directory
    pub fn set_scripts_dir(&mut self, dir: &str) {
        self.scripts_dir = dir.to_string();
    }

    /// Initialize Lua environment with host scanning functions
    pub fn init_environment(&self, host: &str, port: Option<u16>) -> LuaResult<()> {
        let globals = self.lua.globals();

        // Set host information
        globals.set("HOST", host)?;
        if let Some(p) = port {
            globals.set("PORT", p)?;
        }

        // Create host table with utility functions
        let host_table = self.lua.create_table()?;
        host_table.set("ip", host)?;
        if let Some(p) = port {
            host_table.set("port", p)?;
        }

        // Add utility functions
        let connect_fn = self
            .lua
            .create_function(move |_, (host, port): (String, u16)| {
                // This will be called from Lua to test connectivity
                Ok(format!("connect:{}:{}", host, port))
            })?;
        host_table.set("connect", connect_fn)?;

        let send_fn = self.lua.create_function(|_, data: String| {
            // This will be called from Lua to send data
            Ok(format!("send:{}", data))
        })?;
        host_table.set("send", send_fn)?;

        let recv_fn = self.lua.create_function(|_, timeout_ms: Option<u64>| {
            // This will be called from Lua to receive data
            let timeout = timeout_ms.unwrap_or(5000);
            Ok(format!("recv:{}", timeout))
        })?;
        host_table.set("recv", recv_fn)?;

        globals.set("host", host_table)?;

        // Add logging functions
        let log_fn = self.lua.create_function(|_, msg: String| {
            println!("[SCRIPT] {}", msg);
            Ok(())
        })?;
        globals.set("log", log_fn)?;

        let debug_fn = self.lua.create_function(|_, msg: String| {
            eprintln!("[DEBUG] {}", msg);
            Ok(())
        })?;
        globals.set("debug", debug_fn)?;

        Ok(())
    }

    /// Execute a Lua script against a host
    pub async fn run_script(
        &self,
        script_name: &str,
        host: &str,
        port: Option<u16>,
    ) -> Result<ScriptResult, Box<dyn Error>> {
        let script_path = Path::new(&self.scripts_dir).join(format!("{}.lua", script_name));

        if !script_path.exists() {
            return Ok(ScriptResult {
                script_name: script_name.to_string(),
                host: host.to_string(),
                port,
                success: false,
                output: String::new(),
                error: Some(format!("Script file not found: {}", script_path.display())),
                data: HashMap::new(),
            });
        }

        let script_content = fs::read_to_string(&script_path)?;

        // Initialize environment for this execution
        self.init_environment(host, port)?;

        // Execute the script
        match self.lua.load(&script_content).exec() {
            Ok(_) => {
                // Try to get results from the script
                let globals = self.lua.globals();
                let mut data = HashMap::new();
                let mut output = String::new();

                // Check if script set any result variables
                if let Ok(result_table) = globals.get::<Table>("result") {
                    for pair in result_table.pairs::<String, Value>() {
                        if let Ok((key, value)) = pair {
                            match value {
                                Value::String(s) => {
                                    data.insert(key, s.to_str()?.to_string());
                                }
                                Value::Integer(i) => {
                                    data.insert(key, i.to_string());
                                }
                                Value::Number(n) => {
                                    data.insert(key, n.to_string());
                                }
                                Value::Boolean(b) => {
                                    data.insert(key, b.to_string());
                                }
                                _ => {
                                    data.insert(key, "<complex_value>".to_string());
                                }
                            }
                        }
                    }
                }

                // Check if script set output
                if let Ok(output_str) = globals.get::<String>("output") {
                    output = output_str;
                }

                Ok(ScriptResult {
                    script_name: script_name.to_string(),
                    host: host.to_string(),
                    port,
                    success: true,
                    output,
                    error: None,
                    data,
                })
            }
            Err(e) => Ok(ScriptResult {
                script_name: script_name.to_string(),
                host: host.to_string(),
                port,
                success: false,
                output: String::new(),
                error: Some(e.to_string()),
                data: HashMap::new(),
            }),
        }
    }

    /// List available scripts in the scripts directory
    pub fn list_scripts(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let scripts_path = Path::new(&self.scripts_dir);

        if !scripts_path.exists() {
            return Ok(Vec::new());
        }

        let mut scripts = Vec::new();

        for entry in fs::read_dir(scripts_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && path.extension().map_or(false, |ext| ext == "lua") {
                if let Some(stem) = path.file_stem() {
                    if let Some(name) = stem.to_str() {
                        scripts.push(name.to_string());
                    }
                }
            }
        }

        scripts.sort();
        Ok(scripts)
    }

    /// Execute multiple scripts against a host
    pub async fn run_scripts(
        &self,
        script_names: &[String],
        host: &str,
        port: Option<u16>,
    ) -> Vec<ScriptResult> {
        let mut results = Vec::new();

        for script_name in script_names {
            match self.run_script(script_name, host, port).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    results.push(ScriptResult {
                        script_name: script_name.to_string(),
                        host: host.to_string(),
                        port,
                        success: false,
                        output: String::new(),
                        error: Some(e.to_string()),
                        data: HashMap::new(),
                    });
                }
            }
        }

        results
    }

    /// Execute all available scripts against a host
    pub async fn run_all_scripts(
        &self,
        host: &str,
        port: Option<u16>,
    ) -> Result<Vec<ScriptResult>, Box<dyn Error>> {
        let scripts = self.list_scripts()?;
        Ok(self.run_scripts(&scripts, host, port).await)
    }
}

/// Helper function to create a new script runner
pub fn new_script_runner() -> Result<LuaScriptRunner, Box<dyn Error>> {
    LuaScriptRunner::new()
}
