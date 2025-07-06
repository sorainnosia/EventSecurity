// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::Duration;
use chrono::{DateTime, Local, NaiveDateTime};
use regex::Regex;
use tauri::{State, Window, Manager};
use tokio::time;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct EventConfig {
    #[serde(rename = "EventId")]
    event_id: u32,
    #[serde(rename = "EventType")]
    event_type: String,
    #[serde(rename = "Message")]
    message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    #[serde(rename = "Interval")]
    interval: u64,
    #[serde(rename = "Threshold")]
    threshold: u32,
    #[serde(rename = "Configs")]
    configs: HashMap<String, EventConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BlockedIP {
    ip: String,
    datetime: String,
}

type IPCounts = Arc<Mutex<HashMap<String, u32>>>;
type BlockedIPs = Arc<Mutex<Vec<BlockedIP>>>;

impl Default for Config {
    fn default() -> Self {
        let mut configs = HashMap::new();
        configs.insert("RDP".to_string(), EventConfig {
            event_id: 4625,
            event_type: "Security".to_string(),
            message: "An account failed".to_string(),
        });
        configs.insert("MSSQL".to_string(), EventConfig {
            event_id: 18456,
            event_type: "Application".to_string(),
            message: "Login failed for user".to_string(),
        });

        Config {
            interval: 30,
            threshold: 5,
            configs,
        }
    }
}

fn load_or_create_config() -> Config {
    let config_path = "EventSecurity.json";
    
    if Path::new(config_path).exists() {
        match fs::read_to_string(config_path) {
            Ok(content) => {
                match serde_json::from_str::<Config>(&content) {
                    Ok(config) => return config,
                    Err(e) => eprintln!("Error parsing config: {}", e),
                }
            }
            Err(e) => eprintln!("Error reading config file: {}", e),
        }
    }

    let default_config = Config::default();
    match serde_json::to_string_pretty(&default_config) {
        Ok(json) => {
            if let Err(e) = fs::write(config_path, json) {
                eprintln!("Error writing config file: {}", e);
            }
        }
        Err(e) => eprintln!("Error serializing config: {}", e),
    }

    default_config
}

fn extract_ip_from_log(log_content: &str) -> Option<String> {
    let ip_regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
    ip_regex.find(log_content).map(|m| m.as_str().to_string())
}

fn create_hidden_command(program: &str) -> Command {
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

fn check_windows_events(config: &Config) -> HashMap<String, u32> {
    let mut ip_counts = HashMap::new();
    let one_hour_ago = Local::now() - chrono::Duration::hours(1);

    for (name, event_config) in &config.configs {
        println!("Checking {} events (ID: {}, Type: {})", name, event_config.event_id, event_config.event_type);
        
        // Use PowerShell to query Windows Event Log
        let powershell_script = format!(
            r#"
            $StartTime = (Get-Date).AddHours(-1)
            Get-WinEvent -FilterHashtable @{{LogName='{}'; ID={}; StartTime=$StartTime}} -ErrorAction SilentlyContinue | 
            Where-Object {{$_.Message -match '{}'}} | 
            ForEach-Object {{$_.Message}}
            "#,
            event_config.event_type, event_config.event_id, event_config.message
        );

        let output = create_hidden_command("powershell")
            .args(&["-Command", &powershell_script])
            .output();

        match output {
            Ok(result) => {
                let stdout = String::from_utf8_lossy(&result.stdout);
                for line in stdout.lines() {
                    if let Some(ip) = extract_ip_from_log(line) {
                        // Skip local IPs
                        if !ip.starts_with("127.") && !ip.starts_with("192.168.") && !ip.starts_with("10.") {
                            *ip_counts.entry(ip).or_insert(0) += 1;
                        }
                    }
                }
            }
            Err(e) => eprintln!("Error executing PowerShell command: {}", e),
        }
    }

    ip_counts
}

fn is_ip_already_blocked(ip: &str) -> bool {
    let output = create_hidden_command("netsh")
        .args(&["advfirewall", "firewall", "show", "rule", &format!("name=\"Block IP {}\"", ip)])
        .output();

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            stdout.contains("Rule Name:")
        }
        Err(_) => false,
    }
}

fn block_ip_address(ip: &str) -> bool {
    if is_ip_already_blocked(ip) {
        println!("IP {} is already blocked", ip);
        return true;
    }

    let output = create_hidden_command("netsh")
        .args(&[
            "advfirewall", "firewall", "add", "rule",
            &format!("name=\"Block IP {}\"", ip),
            "dir=in", "action=block",
            &format!("remoteip={}", ip)
        ])
        .output();

    match output {
        Ok(result) => {
            if result.status.success() {
                println!("Successfully blocked IP: {}", ip);
                true
            } else {
                eprintln!("Failed to block IP {}: {}", ip, String::from_utf8_lossy(&result.stderr));
                false
            }
        }
        Err(e) => {
            eprintln!("Error executing netsh command: {}", e);
            false
        }
    }
}

fn save_blocked_ip(ip: &str) {
    let now = Local::now();
    let datetime_str = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let entry = format!("{},{}\n", ip, datetime_str);
    
    if let Err(e) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("Blocked.txt")
        .and_then(|mut file| {
            use std::io::Write;
            file.write_all(entry.as_bytes())
        }) {
        eprintln!("Error writing to Blocked.txt: {}", e);
    }
}

fn load_blocked_ips() -> Vec<BlockedIP> {
    match fs::read_to_string("Blocked.txt") {
        Ok(content) => {
            let mut blocked_ips = Vec::new();
            for line in content.lines() {
                if let Some((ip, datetime)) = line.split_once(',') {
                    blocked_ips.push(BlockedIP {
                        ip: ip.to_string(),
                        datetime: datetime.to_string(),
                    });
                }
            }
            // Sort by datetime descending
            blocked_ips.sort_by(|a, b| b.datetime.cmp(&a.datetime));
            blocked_ips
        }
        Err(_) => Vec::new(),
    }
}

async fn monitor_events(config: Config, ip_counts: IPCounts, blocked_ips: BlockedIPs, window: Window) {
    let mut interval = time::interval(Duration::from_secs(config.interval));
    
    loop {
        println!("Checking for security events...");
        let events = check_windows_events(&config);
        
        let mut counts = ip_counts.lock().await;
        let mut blocked_list = blocked_ips.lock().await;
        
        for (ip, count) in events {
            *counts.entry(ip.clone()).or_insert(0) += count;
            
            if counts[&ip] >= config.threshold {
                println!("IP {} exceeded threshold ({}/{})", ip, counts[&ip], config.threshold);
                
                if block_ip_address(&ip) {
                    save_blocked_ip(&ip);
                    let now = Local::now();
                    let datetime_str = now.format("%Y-%m-%d %H:%M:%S").to_string();
                    
                    blocked_list.insert(0, BlockedIP {
                        ip: ip.clone(),
                        datetime: datetime_str,
                    });
                    
                    // Remove the IP from counts as it's now blocked
                    counts.remove(&ip);
                    
                    // Emit event to frontend
                    let _ = window.emit("blocked_ip_updated", &*blocked_list);
                }
            }
        }
        
        interval.tick().await;
    }
}

#[tauri::command]
async fn get_blocked_ips(blocked_ips: State<'_, BlockedIPs>) -> Result<Vec<BlockedIP>, String> {
    let blocked_list = blocked_ips.lock().await;
    Ok(blocked_list.clone())
}

#[tauri::command]
async fn get_blocked_count(blocked_ips: State<'_, BlockedIPs>) -> Result<usize, String> {
    let blocked_list = blocked_ips.lock().await;
    Ok(blocked_list.len())
}

fn main() {
    let config = load_or_create_config();
    let ip_counts: IPCounts = Arc::new(Mutex::new(HashMap::new()));
    let blocked_ips: BlockedIPs = Arc::new(Mutex::new(load_blocked_ips()));

    tauri::Builder::default()
        .manage(ip_counts.clone())
        .manage(blocked_ips.clone())
        .invoke_handler(tauri::generate_handler![get_blocked_ips, get_blocked_count])
        .setup(move |app| {
            let window = app.get_window("main").unwrap();
            let config_clone = config.clone();
            let ip_counts_clone = ip_counts.clone();
            let blocked_ips_clone = blocked_ips.clone();
            let window_clone = window.clone();
            let window_event_clone = window.clone();

            // Start monitoring in background
            tauri::async_runtime::spawn(async move {
                monitor_events(config_clone, ip_counts_clone, blocked_ips_clone, window_clone).await;
            });

            // Prevent closing the app
            window.on_window_event(move |event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window_event_clone.minimize();
                }
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}