use std::fs;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::io::Write;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NmapProbes {
    pub excludes: Vec<String>,
    pub probes: Vec<ProbeEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProbeEntry {
    pub protocol: String,
    pub name: String,
    pub probe_string: String,
    pub no_payload: bool,
    pub matches: Vec<MatchEntry>,
    pub soft_matches: Vec<MatchEntry>,
    pub ports: Vec<String>,
    pub ssl_ports: Vec<String>,
    pub total_wait_ms: Option<u32>,
    pub tcp_wrapped_ms: Option<u32>,
    pub rarity: Option<u8>,
    pub fallback: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MatchEntry {
    pub service: String,
    pub pattern: String,
    pub version_info: HashMap<String, String>,
}

pub fn parse_nmap_probes_json(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let mut nmap_probes = NmapProbes {
        excludes: Vec::new(),
        probes: Vec::new(),
    };
    
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    let mut current_probe: Option<ProbeEntry> = None;
    
    while i < lines.len() {
        let line = lines[i].trim();
        i += 1;
        
        // Skip comments and empty lines
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        
        match parts[0] {
            "Exclude" => {
                if parts.len() > 1 {
                    nmap_probes.excludes.push(parts[1..].join(" "));
                }
            },
            "Probe" => {
                // Save previous probe if exists
                if let Some(probe) = current_probe.take() {
                    nmap_probes.probes.push(probe);
                }
                
                if parts.len() >= 4 {
                    let protocol = parts[1].to_string();
                    let name = parts[2].to_string();
                    let probe_string = parse_probe_string(&parts[3..].join(" "));
                    let no_payload = parts.contains(&"no-payload");
                    
                    current_probe = Some(ProbeEntry {
                        protocol,
                        name,
                        probe_string,
                        no_payload,
                        matches: Vec::new(),
                        soft_matches: Vec::new(),
                        ports: Vec::new(),
                        ssl_ports: Vec::new(),
                        total_wait_ms: None,
                        tcp_wrapped_ms: None,
                        rarity: None,
                        fallback: None,
                    });
                }
            },
            "match" => {
                if let Some(ref mut probe) = current_probe {
                    if let Some(match_entry) = parse_match_line(line) {
                        probe.matches.push(match_entry);
                    }
                }
            },
            "softmatch" => {
                if let Some(ref mut probe) = current_probe {
                    if let Some(match_entry) = parse_match_line(line) {
                        probe.soft_matches.push(match_entry);
                    }
                }
            },
            "ports" => {
                if let Some(ref mut probe) = current_probe {
                    if parts.len() > 1 {
                        probe.ports.push(parts[1..].join(" "));
                    }
                }
            },
            "sslports" => {
                if let Some(ref mut probe) = current_probe {
                    if parts.len() > 1 {
                        probe.ssl_ports.push(parts[1..].join(" "));
                    }
                }
            },
            "totalwaitms" => {
                if let Some(ref mut probe) = current_probe {
                    if parts.len() > 1 {
                        if let Ok(ms) = parts[1].parse::<u32>() {
                            probe.total_wait_ms = Some(ms);
                        }
                    }
                }
            },
            "tcpwrappedms" => {
                if let Some(ref mut probe) = current_probe {
                    if parts.len() > 1 {
                        if let Ok(ms) = parts[1].parse::<u32>() {
                            probe.tcp_wrapped_ms = Some(ms);
                        }
                    }
                }
            },
            "rarity" => {
                if let Some(ref mut probe) = current_probe {
                    if parts.len() > 1 {
                        if let Ok(r) = parts[1].parse::<u8>() {
                            probe.rarity = Some(r);
                        }
                    }
                }
            },
            "fallback" => {
                if let Some(ref mut probe) = current_probe {
                    if parts.len() > 1 {
                        probe.fallback = Some(parts[1..].join(" "));
                    }
                }
            },
            _ => {
                // Unknown directive, skip
            }
        }
    }
    
    // Save the last probe if exists
    if let Some(probe) = current_probe {
        nmap_probes.probes.push(probe);
    }
    
    // Write to JSON file
    let json_output = serde_json::to_string_pretty(&nmap_probes)?;
    let mut file = fs::File::create("./assets/nmap-probes.json")?;
    file.write_all(json_output.as_bytes())?;
    
    println!("Successfully parsed {} excludes and {} probes to nmap-probes.json", 
             nmap_probes.excludes.len(), nmap_probes.probes.len());
    
    Ok(())
}

fn parse_probe_string(probe_part: &str) -> String {
    // Handle probe strings like q|GET / HTTP/1.0\r\n\r\n|
    if probe_part.starts_with('q') && probe_part.len() > 2 {
        let mut chars = probe_part.chars();
        chars.next(); // skip 'q'
        if let Some(delimiter) = chars.next() {
            if let Some(start) = probe_part.find(delimiter) {
                if let Some(end) = probe_part.rfind(delimiter) {
                    if start != end {
                        return probe_part[start+delimiter.len_utf8()..end].to_string();
                    }
                }
            }
        }
    }
    probe_part.to_string()
}

fn parse_match_line(line: &str) -> Option<MatchEntry> {
    // Parse lines like: match ftp m/^220.*Welcome to .*Pure-?FTPd (\d\S+\s*)/ p/Pure-FTPd/ v/$1/ cpe:/a:pureftpd:pure-ftpd:$1/
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    
    let service = parts[1].to_string();
    let pattern_part = parts[2].to_string();
    
    // Extract pattern from m/pattern/flags format
    let pattern = if pattern_part.starts_with('m') && pattern_part.len() > 2 {
        let mut chars = pattern_part.chars();
        chars.next(); // skip 'm'
        if let Some(delimiter) = chars.next() {
            if let Some(start) = pattern_part.find(delimiter) {
                if let Some(end) = pattern_part.rfind(delimiter) {
                    if start != end {
                        pattern_part[start+delimiter.len_utf8()..end].to_string()
                    } else {
                        pattern_part
                    }
                } else {
                    pattern_part
                }
            } else {
                pattern_part
            }
        } else {
            pattern_part
        }
    } else {
        pattern_part
    };
    
    // Parse version info fields (p/, v/, i/, h/, o/, d/, cpe:)
    let mut version_info = HashMap::new();
    for part in &parts[3..] {
        if let Some(field_info) = parse_version_field(part) {
            version_info.insert(field_info.0, field_info.1);
        }
    }
    
    Some(MatchEntry {
        service,
        pattern,
        version_info,
    })
}

fn parse_version_field(field: &str) -> Option<(String, String)> {
    // Parse fields like p/Pure-FTPd/, v/$1/, i/protocol $1/, etc.
    if field.len() < 3 {
        return None;
    }
    
    let mut chars = field.chars();
    let field_type = chars.next()?.to_string();
    if !matches!(field_type.as_str(), "p" | "v" | "i" | "h" | "o" | "d") && !field.starts_with("cpe:") {
        return None;
    }
    
    if field.starts_with("cpe:") {
        return Some(("cpe".to_string(), field[4..].to_string()));
    }
    
    let delimiter = chars.next()?;
    if let Some(start) = field.find(delimiter) {
        if let Some(end) = field.rfind(delimiter) {
            if start != end {
                let value = field[start+delimiter.len_utf8()..end].to_string();
                return Some((field_type, value));
            }
        }
    }
    
    None
}