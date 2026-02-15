use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use data_encoding::BASE32;

use lxmf_rust::{LXMRouter, LXMessage};
use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::transport::Transport;

fn load_env(path: &PathBuf) -> Result<HashMap<String, String>, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("Failed to read env file: {e}"))?;
    let mut data = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let mut parts = line.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim().trim_matches('"');
        if !key.is_empty() {
            data.insert(key.to_string(), value.to_string());
        }
    }
    Ok(data)
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("Hex string length must be even".to_string());
    }
    let mut bytes = Vec::with_capacity(input.len() / 2);
    let mut chars = input.chars();
    while let (Some(hi), Some(lo)) = (chars.next(), chars.next()) {
        let hi_val = hi.to_digit(16).ok_or("Invalid hex digit")?;
        let lo_val = lo.to_digit(16).ok_or("Invalid hex digit")?;
        bytes.push(((hi_val << 4) | lo_val) as u8);
    }
    Ok(bytes)
}

fn decode_key(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_hexdigit()) && trimmed.len() % 2 == 0 {
        return decode_hex(trimmed);
    }

    let mut padded = trimmed.to_string();
    while padded.len() % 8 != 0 {
        padded.push('=');
    }
    BASE32
        .decode(padded.as_bytes())
        .map_err(|e| format!("Base32 decode failed: {e}"))
}

fn main() -> Result<(), String> {
    let watchdog_timeout = Duration::from_secs(20);
    std::thread::spawn(move || {
        std::thread::sleep(watchdog_timeout);
        eprintln!("Timeout");
        panic!("Timeout");
    });

    let args: Vec<String> = env::args().collect();

    let base_dir = PathBuf::from(env::var("RETICULUM_WORKDIR").unwrap_or_else(|_| "".to_string()));
    let env_path = if let Some(pos) = args.iter().position(|arg| arg == "--env") {
        PathBuf::from(args.get(pos + 1).ok_or("--env requires a path")?)
    } else if base_dir.as_os_str().is_empty() {
        PathBuf::from("cli-tests/cli_constants.env")
    } else {
        base_dir.join("cli-tests/cli_constants.env")
    };

    let config_dir = if let Some(pos) = args.iter().position(|arg| arg == "--config") {
        PathBuf::from(args.get(pos + 1).ok_or("--config requires a path")?)
    } else if base_dir.as_os_str().is_empty() {
        PathBuf::from("cli-tests/rnsd_client_sender")
    } else {
        base_dir.join("cli-tests/rnsd_client_sender")
    };

    let content = if let Some(pos) = args.iter().position(|arg| arg == "--message") {
        args.get(pos + 1).cloned().unwrap_or_else(|| "Hello from Rust".to_string())
    } else {
        "Hello from Rust".to_string()
    };

    let env_map = load_env(&env_path)?;
    let key_value = env_map
        .get("KEY_1")
        .ok_or("KEY_1 not found in env file")?
        .to_string();
    let dest_hash_hex = env_map
        .get("ADDR_2")
        .ok_or("ADDR_2 not found in env file")?
        .to_string();

    let key_bytes = decode_key(&key_value)?;
    let dest_hash = decode_hex(&dest_hash_hex)?;

    eprintln!("[step] init reticulum");
    let init_result = std::panic::catch_unwind(|| {
        Reticulum::init(Some(config_dir.clone()), None, None, None, false, None)
    });
    match init_result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(format!("Reticulum init failed: {err}")),
        Err(panic) => {
            let detail = if let Some(msg) = panic.downcast_ref::<&str>() {
                (*msg).to_string()
            } else if let Some(msg) = panic.downcast_ref::<String>() {
                msg.clone()
            } else {
                "unknown panic".to_string()
            };
            return Err(format!("Reticulum init panicked: {detail}"));
        }
    }
    eprintln!("[step] reticulum init complete");

    let cwd = env::current_dir().map_err(|e| format!("Failed to read current dir: {e}"))?;
    let storage_path = cwd.join("cli-tests/lxmf_storage/sender");

    eprintln!("[step] create router");
    let router = LXMRouter::new(
        None,
        storage_path.to_string_lossy().to_string(),
        None,
        None,
        None,
        None,
        None,
        false,
        false,
        Vec::new(),
        None,
        false,
        LXMRouter::PR_ALL_MESSAGES as u8,
        LXMRouter::PROPAGATION_COST,
        LXMRouter::PROPAGATION_COST_FLEX,
        LXMRouter::PEERING_COST,
        LXMRouter::MAX_PEERING_COST,
        Some("rust-sender".to_string()),
    )?;

    eprintln!("[step] load sender identity");
    let source_identity = Identity::from_bytes(&key_bytes)?;
    eprintln!("[step] register sender destination");
    let source = {
        let mut router_guard = router.lock().map_err(|_| "Router lock poisoned")?;
        router_guard.register_delivery_identity(source_identity, Some("Python Sender".to_string()), None)?
    };

    {
        let mut router_guard = router.lock().map_err(|_| "Router lock poisoned")?;
        eprintln!("[step] announce sender destination");
        router_guard.announce(&source.hash, None);
    }

    let overall_deadline = Instant::now() + Duration::from_secs(30);
    let mut next_log = Instant::now() + Duration::from_secs(10);
    eprintln!("[step] resolve path");
    if !Transport::has_path(&dest_hash) {
        let mut last_request = Instant::now() - Duration::from_secs(10);
        while Instant::now() < overall_deadline && !Transport::has_path(&dest_hash) {
            if last_request.elapsed() >= Duration::from_secs(5) {
                eprintln!("[step] request path");
                Transport::request_path(&dest_hash, None, None, None, None);
                last_request = Instant::now();
            }
            if Instant::now() >= next_log {
                let remaining = overall_deadline.saturating_duration_since(Instant::now());
                eprintln!(
                    "Waiting for path resolution... {}s remaining",
                    remaining.as_secs()
                );
                next_log = Instant::now() + Duration::from_secs(10);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    if Instant::now() >= overall_deadline {
        return Err("Timeout waiting for path resolution".to_string());
    }

    let has_path = Transport::has_path(&dest_hash);
    eprintln!("[step] has_path: {}", has_path);
    eprintln!("[step] recall destination identity");
    let dest_identity = if let Some(identity) = Identity::recall(&dest_hash) {
        identity
    } else {
        return Err("Destination identity not found after path request".to_string());
    };
    eprintln!("[step] create outbound destination");
    let destination = Destination::new_outbound(
        Some(dest_identity),
        DestinationType::Single,
        "lxmf".to_string(),
        vec!["delivery".to_string()],
    )?;

    if !has_path {
        return Err("No path available for direct send".to_string());
    }
    let method = LXMessage::DIRECT;

    eprintln!("[step] build message");
    let message = LXMessage::new(
        Some(destination),
        Some(source),
        Some(content.as_bytes().to_vec()),
        Some(b"Python Test".to_vec()),
        None,
        Some(method),
        None,
        None,
        None,
        true,
    )?;

    let handle = std::sync::Arc::new(std::sync::Mutex::new(message));
    {
        let mut router_guard = router.lock().map_err(|_| "Router lock poisoned")?;
        eprintln!("[step] handle outbound");
        router_guard.handle_outbound(handle.clone());
    }

    let timeout = Instant::now() + Duration::from_secs(20);
    let mut next_state_log = Instant::now() + Duration::from_secs(2);
    while Instant::now() < timeout {
        if let Ok(locked) = handle.lock() {
            if Instant::now() >= next_state_log {
                eprintln!("[step] message state: {}", locked.state);
                next_state_log = Instant::now() + Duration::from_secs(2);
            }
            if locked.state == LXMessage::DELIVERED || locked.state == LXMessage::FAILED {
                println!("Message state: {}", locked.state);
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(200));
    }

    println!("Message send timed out");
    Ok(())
}
